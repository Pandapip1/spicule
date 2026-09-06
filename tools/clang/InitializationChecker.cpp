// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

#include <cctype>
#include <memory>
#include <string>

using namespace clang;
using namespace ento;

namespace {

class InitializationChecker
    : public Checker<check::Location, check::PostCall> {
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

  static std::string site(const Stmt *Statement, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Statement->getBeginLoc());
    bool Invalid = false;
    StringRef Buffer = SM.getBufferData(SM.getFileID(Location), &Invalid);
    if (Invalid)
      return Statement->getStmtClassName();
    unsigned Offset = SM.getFileOffset(Location);
    size_t Begin = Buffer.rfind('\n', Offset);
    Begin = Begin == StringRef::npos ? 0 : Begin + 1;
    size_t End = Buffer.find('\n', Offset);
    return Buffer.slice(Begin, End == StringRef::npos ? Buffer.size() : End)
        .trim()
        .str();
  }

  static std::string context(CheckerContext &C) {
    const Decl *Current = C.getLocationContext()->getDecl();
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      return Named->getQualifiedNameAsString();
    return Current ? Current->getDeclKindName() : "unknown";
  }

public:
  /* This tree's own raw syscall trampolines (one `static long
   * raw_syscall(long nr, long a1, ..., long a6)` defined per platform
   * file that needs it, always under that exact name -- confirmed by
   * grep across every Linux platform backend file under src) take
   * every argument as a bare `long`, including ones that are really
   * `&local_buffer` or a local array decaying to a pointer, because
   * that is the real Linux syscall ABI: six general-purpose registers,
   * untyped. A real syscall this codebase issues this way, e.g.
   * SYS_socketpair's `int sv[2]` out-parameter
   * (src/socket/linux/plat_socket.c) or SYS_uname's `struct
   * new_utsname` (src/unistd/linux/plat_unistd.c), genuinely does
   * write through that argument in the kernel, but
   * Clang's own default "invalidate a callee's pointer arguments"
   * heuristic never fires here: the parameter type is `long`, not a
   * pointer, so nothing about the call site looks like it could write
   * through that argument at all. Recognising this one, stable,
   * deliberately-named idiom and manually invalidating (clearing the
   * Undef marker on) whatever local storage a `(long)&x` or
   * `(long)arr`-shaped argument actually names is what closes that gap
   * -- the same outcome Clang's own default handling already gives a
   * plain, untyped-through-a-cast pointer argument to any other opaque
   * call, just applied by hand for the one case this tree's own low-
   * level ABI need hides from it. This is deliberately conservative
   * (only a direct `&var` or a bare array-decayed variable, so it
   * cannot itself paper over a real omitted initialization one syntax
   * level away, e.g. through a struct member or an extra indirection)
   * rather than trusting every raw_syscall() argument unconditionally. */
  /* The region a raw_syscall() argument names, if that argument (after
   * stripping the `(long)` cast every real call site here wraps it in)
   * is exactly `&var` or a bare array `var` decaying to a pointer --
   * the two shapes a local out-buffer/out-struct actually takes at
   * these call sites. Resolved directly off the DeclRefExpr's own
   * VarDecl via getLValue() rather than through CheckerContext::getSVal
   * on the (un-decayed, for the array case) sub-expression: that
   * exact Stmt was never separately evaluated by the engine -- only
   * the surrounding cast/decay node was -- so the Environment has no
   * cached binding for it and getSVal comes back empty. */
  static const MemRegion *outArgumentRegion(const Expr *Argument,
                                            CheckerContext &C) {
    const Expr *Stripped = Argument->IgnoreParenCasts();
    const Expr *Base = nullptr;
    if (const auto *Unary = dyn_cast<UnaryOperator>(Stripped)) {
      if (Unary->getOpcode() == UO_AddrOf)
        Base = Unary->getSubExpr()->IgnoreParenCasts();
    } else if (Stripped->getType()->isArrayType()) {
      Base = Stripped;
    }
    const auto *DRE = Base ? dyn_cast<DeclRefExpr>(Base) : nullptr;
    const auto *VD = DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
    if (!VD)
      return nullptr;
    return C.getState()->getLValue(VD, C.getLocationContext()).getAsRegion();
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function || !Function->getIdentifier() ||
        Function->getName() != "raw_syscall")
      return;
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (unsigned I = 0, N = Call.getNumArgs(); I < N; ++I) {
      const Expr *Argument = Call.getArgExpr(I);
      const MemRegion *Region = Argument ? outArgumentRegion(Argument, C) : nullptr;
      if (!Region)
        continue;
      State = State->invalidateRegions(
          Region, Call.getOriginExpr(), C.blockCount(), C.getLocationContext(),
          /*CausesPointerEscape=*/false, /*IdVisited=*/nullptr,
          /*Call=*/&Call, nullptr);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkLocation(SVal Location, bool IsLoad, const Stmt *Statement,
                     CheckerContext &C) const {
    if (!IsLoad || !Statement)
      return;
    std::optional<Loc> Address = Location.getAs<Loc>();
    if (!Address)
      return;
    QualType Type;
    if (const auto *Expression = dyn_cast<Expr>(Statement))
      Type = Expression->getType();
    if (!C.getState()->getSVal(*Address, Type).isUndef())
      return;

    ExplodedNode *Node = C.generateNonFatalErrorNode();
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Uninitialized memory read",
                                     categories::MemoryError);
    const SourceManager &SM = C.getSourceManager();
    std::string Message =
        "memory read is not proven initialized; origin '" +
        SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())).str() +
        "'; context '" + context(C) + "'; expression '" + text(Statement, C) +
        "'; site '" + site(Statement, C) + "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }
};

} // namespace

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<InitializationChecker>(
      "ntlibc.InitializedRead", "Proves that every memory load is initialized",
      "");
}
