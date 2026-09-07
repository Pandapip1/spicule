// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
//
// spicule.Reentrancy -- catches the classic "returns a pointer into internal
// static storage" hazard: a caller holds onto the pointer a family member
// returned, then makes a second call to the same (or a sibling) family
// member on the same path, which silently invalidates the first result, and
// then reads/dereferences/passes on the now-stale pointer.
//
// Distinct from OwnershipChecker's malloc/free bookkeeping: there's no
// allocation and no free, the "resource" is implicit shared static
// storage, and the bug is a stale pointer read after a same-family call
// invalidated it.
//
// Family grounding (src/string, src/time):
//   strtok    src/string/strtok.c's hidden file-scope `static char *p`
//             threads state across calls with a NULL first argument.
//   (wcstok/strtok_r excluded) both take an explicit `ptr`/`saveptr`
//             argument and keep no static state at all.
//   gmtime/localtime/asctime/ctime/getdate each have their own,
//             independent static buffer in src/time/*.c -- contrary to
//             the usual libc folklore of a shared buffer, grep confirms
//             five separate declarations, one per function, and
//             ctime_r/asctime_r only ever call the _r (explicit-buffer)
//             helpers. So each real family below has exactly one member:
//             only calling that same public function again invalidates
//             its own prior result.
//
//   The checker's mechanism nonetheless supports multi-member families (a
//   call to any member invalidates every other member's result), the
//   shape a future shared-buffer implementation would need. Two
//   synthetic fixture-only names (fake_gmtime/fake_localtime,
//   FixtureShared below) exist purely to exercise that sibling-
//   invalidation path in tools/lint-reentrancy-fixtures/; no real spicule
//   symbol uses them.

#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

#include "llvm/ADT/Twine.h"

#include <cctype>
#include <memory>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

// Monotonically increasing "how many times has this family been called"
// counter, keyed by family id (ReentrantFamily below, cast to unsigned).
// Bumped once per call to any member of the family; a tracked variable's
// remembered generation that no longer equals the family's current
// generation has been invalidated by an intervening call.
REGISTER_MAP_WITH_PROGRAMSTATE(FamilyGeneration, unsigned, unsigned)

// The region a family call's return value points to (or, for a plain
// pointer copy, the region the copied value still points to) -> which
// family produced it. Populated once a call's return value is seen; reused
// unchanged every subsequent bind so `p2 = p1;`-style copies resolve to the
// same family without any separate aliasing analysis.
REGISTER_MAP_WITH_PROGRAMSTATE(PointeeFamily, const MemRegion *, unsigned)

// A tracked local variable's own storage region -> which family its
// current contents came from, and the family generation as of the bind
// that put that value there.
REGISTER_MAP_WITH_PROGRAMSTATE(VarFamily, const MemRegion *, unsigned)
REGISTER_MAP_WITH_PROGRAMSTATE(VarGeneration, const MemRegion *, unsigned)

namespace {

enum class ReentrantFamily : unsigned char {
  Strtok,
  Gmtime,
  Localtime,
  Asctime,
  Ctime,
  Getdate,
  // Fixture-only, see the file header comment above.
  FixtureShared,
};

struct FamilyMember {
  llvm::StringLiteral Name;
  ReentrantFamily Family;
};

constexpr FamilyMember Members[] = {
    {"strtok", ReentrantFamily::Strtok},
    {"gmtime", ReentrantFamily::Gmtime},
    {"localtime", ReentrantFamily::Localtime},
    {"asctime", ReentrantFamily::Asctime},
    {"ctime", ReentrantFamily::Ctime},
    {"getdate", ReentrantFamily::Getdate},
    {"fake_gmtime", ReentrantFamily::FixtureShared},
    {"fake_localtime", ReentrantFamily::FixtureShared},
};

std::optional<ReentrantFamily> familyFor(const CallEvent &Call) {
  const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  if (!Function || !Function->getIdentifier())
    return std::nullopt;
  StringRef Name = Function->getName();
  for (const FamilyMember &Candidate : Members)
    if (Name == Candidate.Name)
      return Candidate.Family;
  return std::nullopt;
}

StringRef familyName(ReentrantFamily Family) {
  for (const FamilyMember &Candidate : Members)
    if (Candidate.Family == Family)
      return Candidate.Name;
  return "unknown";
}

class ReentrancyChecker
    : public Checker<check::PostCall, check::Bind, check::Location> {
  mutable std::unique_ptr<BugType> BT;

  static std::string text(const Stmt *Statement, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    StringRef Raw =
        Lexer::getSourceText(CharSourceRange::getTokenRange(
                                 SM.getSpellingLoc(Statement->getBeginLoc()),
                                 SM.getSpellingLoc(Statement->getEndLoc())),
                             SM, C.getLangOpts());
    std::string Result;
    bool Space = false;
    for (char Character : Raw) {
      if (std::isspace(static_cast<unsigned char>(Character))) {
        Space = !Result.empty();
      } else {
        if (Space)
          Result += ' ';
        Result += Character;
        Space = false;
      }
    }
    return Result.empty() ? Statement->getStmtClassName() : Result;
  }

  static std::string context(CheckerContext &C) {
    const Decl *Current = C.getLocationContext()->getDecl();
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      return Named->getQualifiedNameAsString();
    return Current ? Current->getDeclKindName() : "unknown";
  }

  void report(ReentrantFamily Family, const Stmt *Statement,
              ProgramStateRef State, CheckerContext &C) const {
    if (!Statement)
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Stale reentrant static storage",
                                     categories::MemoryError);
    StringRef Name = familyName(Family);
    const SourceManager &SM = C.getSourceManager();
    std::string Message =
        (llvm::Twine("read of a pointer returned by an earlier '") + Name +
         "' call after a later '" + Name +
         "' call may observe overwritten internal static storage; origin '" +
         SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())) +
         "'; context '" + context(C) + "'; expression '" +
         text(Statement, C) + "'")
            .str();
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

public:
  // A call to a family member invalidates every outstanding pointer any
  // (sibling or the same) member of that family has already handed out,
  // and hands out a fresh one of its own.
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    std::optional<ReentrantFamily> Family = familyFor(Call);
    if (!Family)
      return;
    ProgramStateRef State = C.getState();
    unsigned FamilyId = static_cast<unsigned>(*Family);
    const unsigned *Current = State->get<FamilyGeneration>(FamilyId);
    unsigned Next = Current ? *Current + 1 : 1;
    State = State->set<FamilyGeneration>(FamilyId, Next);

    if (const MemRegion *Region = Call.getReturnValue().getAsRegion())
      State = State->set<PointeeFamily>(Region->getBaseRegion(), FamilyId);

    C.addTransition(State);
  }

  // Track a plain pointer bind (`p = family_call(...)`, or a plain copy
  // `q = p` of an already-tracked pointer) onto a local variable's own
  // storage region, remembering which family's generation it captured.
  // Anything else bound over a previously tracked variable (a fresh
  // unrelated pointer, or the contents of a deep/struct copy -- which does
  // not resolve to a plain region value at all) drops the tracking, which
  // is exactly the "intervening memcpy/deep-copy out" escape hatch.
  void checkBind(SVal Loc, SVal Val, const Stmt *, CheckerContext &C) const {
    const auto *Dest = dyn_cast_or_null<VarRegion>(Loc.getAsRegion());
    if (!Dest)
      return;
    ProgramStateRef State = C.getState();
    const MemRegion *ValRegion = Val.getAsRegion();
    const unsigned *FamilyId =
        ValRegion ? State->get<PointeeFamily>(ValRegion->getBaseRegion())
                  : nullptr;
    if (!FamilyId) {
      if (State->get<VarFamily>(Dest)) {
        State = State->remove<VarFamily>(Dest);
        State = State->remove<VarGeneration>(Dest);
        C.addTransition(State);
      }
      return;
    }
    const unsigned *Generation = State->get<FamilyGeneration>(*FamilyId);
    State = State->set<VarFamily>(Dest, *FamilyId);
    State = State->set<VarGeneration>(Dest, Generation ? *Generation : 0);
    C.addTransition(State);
  }

  // Reading a tracked variable's value -- as a dereference base, an
  // argument, a condition, or anything else that loads it -- after the
  // family it was captured from has moved on to a later call is the bug:
  // the storage the pointer refers to now holds a different call's data.
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *Statement,
                     CheckerContext &C) const {
    if (!IsLoad)
      return;
    const auto *Region = dyn_cast_or_null<VarRegion>(Loc.getAsRegion());
    if (!Region)
      return;
    ProgramStateRef State = C.getState();
    const unsigned *FamilyId = State->get<VarFamily>(Region);
    if (!FamilyId)
      return;
    const unsigned *BoundGeneration = State->get<VarGeneration>(Region);
    const unsigned *CurrentGeneration = State->get<FamilyGeneration>(*FamilyId);
    unsigned Bound = BoundGeneration ? *BoundGeneration : 0;
    unsigned Current = CurrentGeneration ? *CurrentGeneration : 0;
    if (Bound != Current)
      report(static_cast<ReentrantFamily>(*FamilyId), Statement, State, C);
  }
};

} // namespace

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<ReentrancyChecker>(
      "spicule.Reentrancy",
      "Proves a family member's returned static-storage pointer is not read "
      "after a later call to the same or a sibling member invalidates it",
      "");
}
