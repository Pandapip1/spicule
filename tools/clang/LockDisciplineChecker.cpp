// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "clang/AST/Expr.h"
#include "clang/AST/ParentMap.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "LifecycleAlgebra.h"
#include "LockHandoffContracts.h"

#include <cctype>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

// "Held" is the same must-hold/must-not-double-acquire linear-lifecycle
// question OwnershipChecker.cpp's ConstructMap and AllocationLifetimeChecker.cpp's
// AllocationLifecycle already answer via ntlibc::algebra's shared,
// nominal-state algebra (Live/Released/Absent/Unknown, transitioned by
// applyLifecycleOperation()) -- this checker used to carry its own,
// separately hand-rolled boolean "is this MemRegion held" derivation
// instead of reusing that already-audited machinery. A lock's own
// acquire/release cycle repeats (unlike a one-shot malloc/free or
// construct/destroy), but applyLifecycleOperation()'s Release always
// produces Released rather than Absent, and Released accepts a further
// Acquire cleanly -- so the same three-operation algebra already used for
// one-shot resources composes correctly for a lock's repeated hold/release
// cycles with no extension needed. Read vs write acquisition mode is
// recorded as the lifecycle's own family tag (see readFamily()/
// writeFamily() below), exactly the way OwnershipChecker tags a construct's
// family from its own `construct(name)` annotation -- but, unlike an
// annotated construct/destroy pair, a bare pthread_*_unlock() has no way to
// know in advance whether it is releasing a read or a write acquisition, so
// LifecycleEvent::FamilyMismatch is deliberately never consulted for
// Release/RequireHeld below: this checker has never distinguished read from
// write mode for those two checks, and family-mismatch detection is not a
// discipline this checker claims to enforce.
using ntlibc::algebra::absentLifecycle;
using ntlibc::algebra::applyLifecycleOperation;
using ntlibc::algebra::contains;
using ntlibc::algebra::LifecycleEvent;
using ntlibc::algebra::LifecycleFact;
using ntlibc::algebra::LifecycleFamilyId;
using ntlibc::algebra::LifecycleOperation;
using ntlibc::algebra::LifecycleState;
using ntlibc::algebra::LifecycleTransition;
using ntlibc::algebra::liveLifecycle;
using ntlibc::algebra::observeLifecycleExit;
using ntlibc::algebra::releasedLifecycle;
using ntlibc::algebra::requireNotLive;
using ntlibc::algebra::unknownLifecycle;

REGISTER_MAP_WITH_PROGRAMSTATE(HeldLocks, const MemRegion *, LifecycleState)
REGISTER_MAP_WITH_PROGRAMSTATE(HeldLockFamily, const MemRegion *,
                               const IdentifierInfo *)
REGISTER_MAP_WITH_PROGRAMSTATE(LockAcquirers, const MemRegion *,
                               const StackFrameContext *)
// A region tagged here, for the stack frame that tagged it, is exempt from
// checkEndFunction's "function exits while a lock is held" report:
// ending while holding this lock is a deliberate hand-off (to the
// caller, or, for a pthread_cleanup_push() handler, the cancellation
// machinery). A function opts into this via a
// ntlibc_lock_requires_held_on_entry/ntlibc_lock_acquires_for_caller
// __attribute__((annotate(...))) on its own declaration -- see
// LockHandoffContracts.h and handoffContract() below for the two ways a
// region gets tagged from that annotation.
REGISTER_MAP_WITH_PROGRAMSTATE(HandoffExempt, const MemRegion *,
                               const StackFrameContext *)

namespace {

enum class LockOperation : unsigned char {
  Initialize,
  AcquireRead,
  AcquireWrite,
  Release,
  RequireHeld,
  Destroy
};

struct LockCall {
  LockOperation Operation;
  unsigned Argument;
};

class LockDisciplineChecker
    : public Checker<check::PreCall, check::PostCall, check::EndFunction,
                     check::BeginFunction> {
  mutable std::unique_ptr<BugType> BT;

  static std::optional<LockCall> protocolFor(const CallEvent &Call) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function || !Function->getIdentifier())
      return std::nullopt;
    StringRef Name = Function->getName();
    if (Name == "pthread_mutex_init" || Name == "pthread_rwlock_init" ||
        Name == "pthread_spin_init")
      return LockCall{LockOperation::Initialize, 0};
    if (Name == "pthread_mutex_lock" || Name == "pthread_mutex_trylock" ||
        Name == "pthread_mutex_timedlock" || Name == "pthread_spin_lock" ||
        Name == "pthread_spin_trylock")
      return LockCall{LockOperation::AcquireWrite, 0};
    if (Name == "pthread_rwlock_rdlock" || Name == "pthread_rwlock_tryrdlock" ||
        Name == "pthread_rwlock_timedrdlock")
      return LockCall{LockOperation::AcquireRead, 0};
    if (Name == "pthread_rwlock_wrlock" || Name == "pthread_rwlock_trywrlock" ||
        Name == "pthread_rwlock_timedwrlock")
      return LockCall{LockOperation::AcquireWrite, 0};
    if (Name == "pthread_mutex_unlock" || Name == "pthread_rwlock_unlock" ||
        Name == "pthread_spin_unlock")
      return LockCall{LockOperation::Release, 0};
    if (Name == "pthread_cond_wait" || Name == "pthread_cond_timedwait")
      return LockCall{LockOperation::RequireHeld, 1};
    if (Name == "pthread_mutex_destroy" || Name == "pthread_rwlock_destroy" ||
        Name == "pthread_spin_destroy")
      return LockCall{LockOperation::Destroy, 0};
    return std::nullopt;
  }

  static const MemRegion *regionFor(const CallEvent &Call,
                                    const LockCall &Protocol) {
    if (Protocol.Argument >= Call.getNumArgs())
      return nullptr;
    return Call.getArgSVal(Protocol.Argument).getAsRegion();
  }

  // Mirrors OwnedConstructChecker::familyId() in OwnershipChecker.cpp
  // exactly: an uninterpreted nominal atom's "value" is just its
  // IdentifierInfo's own stable address, reinterpreted as the opaque
  // integer LifecycleFamilyId wraps. Read and write acquisitions get their
  // own fixed, TU-wide identifiers (there is exactly one of each, unlike
  // OwnershipChecker's per-annotation-name families) purely so a held
  // lock's LifecycleFact can still record which mode it was acquired in.
  static LifecycleFamilyId familyId(const IdentifierInfo *Family) {
    return {static_cast<uint64_t>(reinterpret_cast<uintptr_t>(Family))};
  }

  static const IdentifierInfo *readFamily(ASTContext &Ctx) {
    return &Ctx.Idents.get("ntlibc.lock.read");
  }

  static const IdentifierInfo *writeFamily(ASTContext &Ctx) {
    return &Ctx.Idents.get("ntlibc.lock.write");
  }

  // The MemRegion-keyed analogue of AllocationLifetimeChecker.cpp's own
  // lifecycleFor(): reconstructs the canonical LifecycleFact a HeldLocks/
  // HeldLockFamily pair encodes, so every caller reasons about "is this
  // lock held" through the one shared representation instead of an
  // ad hoc boolean. An absent HeldLocks entry is Absent, not Unknown --
  // exactly the prior HeldKind-based code's own convention of reading "no
  // information at all" as "unlocked", for every caller including a
  // pthread_cond_wait() mutex argument this per-function analysis never
  // saw acquired.
  static LifecycleFact heldFact(ProgramStateRef State, const MemRegion *Region) {
    const LifecycleState *Phase = State->get<HeldLocks>(Region);
    if (!Phase)
      return absentLifecycle();
    if (*Phase == LifecycleState::Unknown)
      return unknownLifecycle();
    if (*Phase == LifecycleState::Absent)
      return absentLifecycle();
    const IdentifierInfo *const *Family = State->get<HeldLockFamily>(Region);
    if (!Family)
      return unknownLifecycle();
    LifecycleFamilyId Id = familyId(*Family);
    return *Phase == LifecycleState::Live ? liveLifecycle(Id)
                                          : releasedLifecycle(Id);
  }

  // Function's own ntlibc_lock_requires_held_on_entry/
  // ntlibc_lock_acquires_for_caller annotation, if it (or any of its
  // other redeclarations -- a forward declaration is where these are
  // conventionally attached, e.g. src/thread/pthread_cond.c's
  // cond_wait_cleanup) carries one of the given kind. Real AST
  // inspection of a source-visible attribute, not a name match: see
  // LockHandoffContracts.h.
  static std::optional<ntlibc::LockHandoffContract>
  handoffContract(const FunctionDecl *Function, ntlibc::LockHandoffKind Kind) {
    if (!Function)
      return std::nullopt;
    for (const FunctionDecl *Redeclaration : Function->redecls()) {
      for (const auto *Attribute :
           Redeclaration->specific_attrs<AnnotateAttr>()) {
        std::optional<ntlibc::LockHandoffContract> Contract =
            ntlibc::parseLockHandoff(Attribute->getAnnotation());
        if (Contract && Contract->Kind == Kind)
          return Contract;
      }
    }
    return std::nullopt;
  }

  // True if the function currently being analyzed carries
  // ntlibc_lock_acquires_for_caller.
  static bool acquiresForCaller(CheckerContext &C) {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return handoffContract(Function, ntlibc::LockHandoffKind::AcquiresForCaller)
        .has_value();
  }

  // True if Call's own CallExpr is (modulo enclosing parentheses and
  // implicit casts) the return statement's own operand -- i.e. the
  // surrounding function reads exactly like `return
  // pthread_mutex_unlock(mutex);`, with nothing between the call and the
  // return to swallow the value. See checkPostCall's Failed-branch
  // handling for why this matters: it is the difference between a
  // function silently discarding a release's ambiguous outcome (a real
  // bug the existing unheld-release check catches independently, before
  // this ever runs) and one explicitly propagating that exact outcome to
  // its own caller, which is not a leak this function is responsible
  // for -- the caller receives the same nonzero status a direct call to
  // pthread_mutex_unlock() would have given it, and can react to it
  // exactly as it would have.
  static bool isDirectReturnOperand(const CallEvent &Call, CheckerContext &C) {
    const Stmt *Statement = Call.getOriginExpr();
    if (!Statement)
      return false;
    ParentMap &PM = C.getLocationContext()->getAnalysisDeclContext()->getParentMap();
    const Stmt *Parent = PM.getParentIgnoreParenCasts(Statement);
    return Parent && isa<ReturnStmt>(Parent);
  }

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

  void report(StringRef Reason, const Stmt *Statement, ProgramStateRef State,
              CheckerContext &C) const {
    if (!Statement)
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven lock discipline",
                                     categories::LogicError);
    const SourceManager &SM = C.getSourceManager();
    std::string Message =
        (Reason + "; origin '" +
         SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())) +
         "'; context '" + context(C) + "'; expression '" + text(Statement, C) +
         "'")
            .str();
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    std::optional<LockCall> Protocol = protocolFor(Call);
    if (!Protocol)
      return;
    const MemRegion *Region = regionFor(Call, *Protocol);
    const Stmt *Statement = Call.getOriginExpr();
    if (!Region || !Statement)
      return;
    ProgramStateRef State = C.getState();
    LifecycleFact Fact = heldFact(State, Region);
    switch (Protocol->Operation) {
    case LockOperation::AcquireRead:
    case LockOperation::AcquireWrite: {
      LifecycleFamilyId Family = familyId(
          Protocol->Operation == LockOperation::AcquireRead
              ? readFamily(C.getASTContext())
              : writeFamily(C.getASTContext()));
      LifecycleTransition Transition =
          applyLifecycleOperation(Fact, Family, LifecycleOperation::Acquire);
      if (contains(Transition.Events, LifecycleEvent::AlreadyLive))
        report("lock acquisition is attempted while already held", Statement,
               State, C);
      break;
    }
    case LockOperation::Release: {
      // RequireLive, not Release: checkPreCall only ever proves or
      // disproves the precondition, it never commits a state transition
      // -- checkPostCall is solely responsible for that, gated on the
      // call's own success/failure outcome. See this class's own
      // familyId() doc comment for why FamilyMismatch is not checked
      // here: a bare pthread_*_unlock() carries no read/write mode of
      // its own to mismatch against.
      LifecycleTransition Transition = applyLifecycleOperation(
          Fact, familyId(writeFamily(C.getASTContext())),
          LifecycleOperation::RequireLive);
      if (contains(Transition.Events, LifecycleEvent::MissingLive) ||
          contains(Transition.Events, LifecycleEvent::AlreadyReleased) ||
          contains(Transition.Events, LifecycleEvent::StateUnproven))
        report("lock release is not proven to hold the lock", Statement,
               State, C);
      break;
    }
    case LockOperation::RequireHeld: {
      LifecycleTransition Transition = applyLifecycleOperation(
          Fact, familyId(writeFamily(C.getASTContext())),
          LifecycleOperation::RequireLive);
      if (contains(Transition.Events, LifecycleEvent::MissingLive) ||
          contains(Transition.Events, LifecycleEvent::AlreadyReleased) ||
          contains(Transition.Events, LifecycleEvent::StateUnproven))
        report("condition wait is not proven to hold its mutex", Statement,
               State, C);
      break;
    }
    case LockOperation::Destroy:
      // The photographic negative of the two RequireLive checks above:
      // proves the lock is safe to tear down because nothing currently
      // holds it, rather than proving something does.
      if (contains(requireNotLive(Fact).Events, LifecycleEvent::AlreadyLive))
        report("lock is destroyed while held", Statement, State, C);
      break;
    case LockOperation::Initialize:
      break;
    }
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    std::optional<LockCall> Protocol = protocolFor(Call);
    if (!Protocol || Protocol->Operation == LockOperation::RequireHeld ||
        Protocol->Operation == LockOperation::Destroy)
      return;
    const MemRegion *Region = regionFor(Call, *Protocol);
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Region || !Function)
      return;
    std::optional<DefinedOrUnknownSVal> Return =
        Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
    if (!Return)
      return;
    DefinedOrUnknownSVal Success = C.getSValBuilder().evalEQ(
        C.getState(), *Return,
        C.getSValBuilder().makeZeroVal(Function->getReturnType()));
    auto [Succeeded, Failed] = C.getState()->assume(Success);
    if (Succeeded) {
      bool Acquired = Protocol->Operation == LockOperation::AcquireRead ||
                     Protocol->Operation == LockOperation::AcquireWrite;
      if (Acquired) {
        const IdentifierInfo *Family =
            Protocol->Operation == LockOperation::AcquireRead
                ? readFamily(C.getASTContext())
                : writeFamily(C.getASTContext());
        LifecycleTransition Transition = applyLifecycleOperation(
            heldFact(Succeeded, Region), familyId(Family),
            LifecycleOperation::Acquire);
        Succeeded = Succeeded->set<HeldLocks>(Region, Transition.After.State);
        Succeeded = Succeeded->set<HeldLockFamily>(Region, Family);
        Succeeded = Succeeded->set<LockAcquirers>(Region, C.getStackFrame());
        // See LockHandoffContracts.h's AcquiresForCaller comment:
        // cond_wait_cleanup's pthread_mutex_lock(cleanup->mutex)
        // resolves here to whatever region cleanup->mutex actually
        // names, which is exactly the region this acquisition is
        // tagging -- there is no way to know that region in advance of
        // this call succeeding.
        if (acquiresForCaller(C))
          Succeeded = Succeeded->set<HandoffExempt>(Region, C.getStackFrame());
      } else {
        // Initialize or Release: both leave the lock in a definite
        // not-held state. Released, not Absent -- heldFact() reads
        // either as "not held" identically, and Released additionally
        // keeps a double-release or a wait-after-release distinguishable
        // from a lock nobody ever touched, exactly as
        // applyLifecycleOperation()'s own Release verb intends.
        Succeeded = Succeeded->set<HeldLocks>(Region, LifecycleState::Released);
        Succeeded = Succeeded->set<HeldLockFamily>(
            Region, writeFamily(C.getASTContext()));
        Succeeded = Succeeded->remove<LockAcquirers>(Region);
      }
      C.addTransition(Succeeded);
    }
    if (Failed) {
      // A release whose own return value is (modulo casts) the
      // surrounding function's return value -- `return
      // pthread_mutex_unlock(mutex);` -- propagates whatever ambiguity a
      // nonzero return leaves about the lock's true state straight to
      // its own caller, unchanged, rather than swallowing it. Ordinarily
      // a Release's Failed branch retains the prior held state, because
      // in general a failed unlock's effect on the lock is unknown; here
      // that unknown outcome becomes the caller's problem to interpret,
      // exactly as if the caller had called pthread_mutex_unlock()
      // itself, so this function has nothing left to leak. (A release of
      // a lock this function never actually held in the first place --
      // unsafe.c's unlocked_release fixture -- is unaffected: checkPreCall
      // already reports that at the call site itself, before this
      // success/failure split is even reached.)
      if (Protocol->Operation == LockOperation::Release &&
          isDirectReturnOperand(Call, C)) {
        Failed = Failed->set<HeldLocks>(Region, LifecycleState::Released);
        Failed = Failed->set<HeldLockFamily>(Region,
                                             writeFamily(C.getASTContext()));
        Failed = Failed->remove<LockAcquirers>(Region);
      }
      C.addTransition(Failed);
    }
  }

  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    std::optional<ntlibc::LockHandoffContract> Contract = handoffContract(
        Function, ntlibc::LockHandoffKind::RequiresHeldOnEntry);
    if (!Contract || Contract->Argument >= Function->getNumParams())
      return;
    const ParmVarDecl *Param = Function->getParamDecl(Contract->Argument);
    ProgramStateRef State = C.getState();
    Loc ParamLoc = State->getLValue(Param, C.getLocationContext());
    const MemRegion *Region = State->getSVal(ParamLoc).getAsRegion();
    if (!Region)
      return;
    // Seed the precondition (checkPreCall's Release check needs this to
    // not misread the caller's already-held lock as unheld -- see
    // LockHandoffContracts.h's RequiresHeldOnEntry comment) and tag the
    // region exempt from the end-of-function leak check in the same
    // step: both halves of this function's contract share one region,
    // discovered once, here.
    State = State->set<HeldLocks>(Region, LifecycleState::Live);
    State = State->set<HeldLockFamily>(Region, writeFamily(C.getASTContext()));
    State = State->set<HandoffExempt>(Region, C.getStackFrame());
    C.addTransition(State);
  }

  void checkEndFunction(const ReturnStmt *Return, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    for (const auto &Entry : State->get<HeldLocks>()) {
      // observeLifecycleExit()'s own LiveAtScopeExit event is exactly
      // "function exits while a lock is held" -- the same shared verb
      // AllocationLifetimeChecker.cpp uses for its own end-of-function
      // leak check, applied here to a MemRegion-keyed lock fact instead
      // of a SymbolRef-keyed allocation.
      if (!contains(observeLifecycleExit(heldFact(State, Entry.first)).Events,
                    LifecycleEvent::LiveAtScopeExit))
        continue;
      const StackFrameContext *const *Exempt =
          State->get<HandoffExempt>(Entry.first);
      if (Exempt && *Exempt == C.getStackFrame())
        continue;
      const StackFrameContext *const *Acquirer =
          C.getState()->get<LockAcquirers>(Entry.first);
      if (!Acquirer || *Acquirer != C.getStackFrame())
        continue;
      const auto *Function =
          dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
      const Stmt *Statement = Return;
      if (!Statement && Function && Function->hasBody())
        Statement = Function->getBody();
      report("function exits while a lock is held", Statement, C.getState(), C);
      return;
    }
  }
};

} // namespace

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<LockDisciplineChecker>(
      "ntlibc.LockDiscipline", "Proves mutex, rwlock, and spinlock discipline",
      "");
}
