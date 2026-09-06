// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "LifecycleAlgebra.h"
#include "TokenAlgebra.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"

#include <cctype>
#include <memory>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

REGISTER_MAP_WITH_PROGRAMSTATE(AllocationOrigin, SymbolRef, const Stmt *)
REGISTER_MAP_WITH_PROGRAMSTATE(AllocationFrame, SymbolRef,
                               const StackFrameContext *)
REGISTER_MAP_WITH_PROGRAMSTATE(AllocationFamily, SymbolRef,
                               const IdentifierInfo *)
REGISTER_MAP_WITH_PROGRAMSTATE(AllocationLifecycle, SymbolRef,
                               ntlibc::algebra::LifecycleState)
REGISTER_MAP_WITH_PROGRAMSTATE(FreerObligation, SymbolRef, bool)
REGISTER_MAP_WITH_PROGRAMSTATE(ReplacedBy, SymbolRef, SymbolRef)

namespace {

using ntlibc::algebra::absentLifecycle;
using ntlibc::algebra::applyLifecycleOperation;
using ntlibc::algebra::contains;
using ntlibc::algebra::dischargeLifecycle;
using ntlibc::algebra::excludedSentinel;
using ntlibc::algebra::findTokenSort;
using ntlibc::algebra::hasQualifier;
using ntlibc::algebra::LifecycleEvent;
using ntlibc::algebra::LifecycleFact;
using ntlibc::algebra::LifecycleFamilyId;
using ntlibc::algebra::LifecycleFamilyMorphism;
using ntlibc::algebra::LifecycleMorphismTransition;
using ntlibc::algebra::LifecycleOperation;
using ntlibc::algebra::LifecycleState;
using ntlibc::algebra::LifecycleTransition;
using ntlibc::algebra::liveLifecycle;
using ntlibc::algebra::observeLifecycleExit;
using ntlibc::algebra::replaceLifecycle;
using ntlibc::algebra::ReplacementOutcome;
using ntlibc::algebra::RawTokenImplementation;
using ntlibc::algebra::rawTokenImplementation;
using ntlibc::algebra::retagLifecycle;
using ntlibc::algebra::SentinelSplit;
using ntlibc::algebra::splitOnExcludedSentinel;
using ntlibc::algebra::TokenImplementation;
using ntlibc::algebra::TokenImplementationStatus;
using ntlibc::algebra::tokenImplementation;
using ntlibc::algebra::unknownLifecycle;

struct TokenContract {
  const IdentifierInfo *Family;
  const Attr *Attribute;
};

static const FunctionDecl *functionOf(const CallEvent &Call) {
  return dyn_cast_or_null<FunctionDecl>(Call.getDecl());
}

static bool isDynamicStorageToken(ASTContext &Context, StringRef Name) {
  return hasQualifier(findTokenSort(Context, Name), "qual:dynamic_storage");
}

/* A family with no implemented_by(...) names no further, more-primitive
 * family for its consume(...) site to decompose into -- it IS the leaf of
 * the nominal graph (see include/allocation_tokens.h's terminal
 * platform_heap_allocated/platform_pages_allocated on Linux, or a future
 * locale_opened with no real backing storage). Every consume(...)
 * annotation is already trusted, unconditionally, at every CALL SITE
 * (checkPreCall never re-inspects a callee's body -- it cannot, for an
 * opaque external declaration with no visible body at all). Requiring a
 * terminal family's OWN designated releaser to additionally re-derive its
 * own release from inside its own body demands strictly more proof of
 * that one annotation than any caller anywhere is ever required to
 * produce -- not a real soundness gap, just an inconsistency. A family
 * that DOES declare implemented_by(...) is different: it names a real,
 * further family, and requiring this body to actually reach a release of
 * THAT family (checkPreCall's existing morphism-discharge path) is a
 * genuine, load-bearing proof that catches an annotation that lies about
 * its own implementation (see closedir()/catclose()/iconv_close(), whose
 * families all route to a further heap family this way) -- unaffected by
 * this. Anything other than a clean absent-qualifier (a malformed,
 * conflicting, or otherwise broken implemented_by(...)) is left to the
 * existing contract validation to report instead of being silently
 * treated as terminal. */
static bool isTerminalDynamicStorageFamily(ASTContext &Context,
                                           const IdentifierInfo *Family) {
  if (!Family)
    return false;
  return rawTokenImplementation(findTokenSort(Context, Family->getName()))
             .Status == TokenImplementationStatus::Missing;
}

static const IdentifierInfo *annotationFamily(const Decl *Declaration,
                                              StringRef Prefix) {
  if (!Declaration)
    return nullptr;
  for (const AnnotateAttr *Attribute :
       Declaration->specific_attrs<AnnotateAttr>()) {
    StringRef Text = Attribute->getAnnotation();
    if (Text.consume_front(Prefix) && !Text.empty() && !Text.contains(':') &&
        isDynamicStorageToken(Declaration->getASTContext(), Text))
      return &Declaration->getASTContext().Idents.get(Text);
  }
  return nullptr;
}

static std::optional<TokenContract>
returnsOwnership(const FunctionDecl *Function) {
  if (!Function)
    return std::nullopt;
  for (const AnnotateAttr *Attribute :
       Function->specific_attrs<AnnotateAttr>()) {
    StringRef Text = Attribute->getAnnotation();
    if (Text.consume_front("withtok:") && !Text.empty() &&
        !Text.contains(':') &&
        isDynamicStorageToken(Function->getASTContext(), Text))
      return TokenContract{&Function->getASTContext().Idents.get(Text),
                           Attribute};
  }
  return std::nullopt;
}

/* A reallocation input is consumed only when the returned pointer is nonnull.
 * This remains declaration-driven: the checker contains no allocator names. */
static std::optional<unsigned>
reallocatedArgument(const FunctionDecl *Function) {
  if (!Function)
    return std::nullopt;
  for (unsigned Argument = 0; Argument < Function->getNumParams(); ++Argument)
    if (annotationFamily(Function->getParamDecl(Argument),
                         "consume_if_nonnull_return:"))
      return Argument;
  return std::nullopt;
}

/* Some POSIX interfaces return the caller's buffer when it is nonnull and
 * allocate one only when that argument is null.  The ordinary returns
 * attribute would incorrectly make both results owned. */
static std::optional<unsigned> returnedArgument(const FunctionDecl *Function,
                                                const IdentifierInfo *Family) {
  if (!Function)
    return std::nullopt;
  if (!Family)
    return std::nullopt;
  unsigned Argument = 0;
  for (const ParmVarDecl *Parameter : Function->parameters()) {
    for (const AnnotateAttr *Attribute :
         Parameter->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attribute->getAnnotation();
      if (Text.consume_front("withtok:") && Text == Family->getName())
        return Argument;
    }
    ++Argument;
  }
  return std::nullopt;
}

static std::string sourceText(const Stmt *Statement, CheckerContext &C) {
  if (!Statement)
    return "function exit";
  const SourceManager &SM = C.getSourceManager();
  SourceLocation Begin = SM.getSpellingLoc(Statement->getBeginLoc());
  SourceLocation End = SM.getSpellingLoc(Statement->getEndLoc());
  StringRef Raw = Lexer::getSourceText(
      CharSourceRange::getTokenRange(Begin, End), SM, C.getLangOpts());
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

static std::string contextName(CheckerContext &C) {
  const Decl *Current = C.getLocationContext()->getDecl();
  if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
    return Named->getQualifiedNameAsString();
  return Current ? Current->getDeclKindName() : "unknown";
}

static StringRef implementationStatusName(TokenImplementationStatus Status) {
  switch (Status) {
  case TokenImplementationStatus::Missing:
    return "missing";
  case TokenImplementationStatus::Valid:
    return "valid";
  case TokenImplementationStatus::Malformed:
    return "malformed";
  case TokenImplementationStatus::UnknownFamily:
    return "unknown-family";
  case TokenImplementationStatus::Conflicting:
    return "conflicting";
  case TokenImplementationStatus::Self:
    return "self";
  case TokenImplementationStatus::Cyclic:
    return "cyclic";
  case TokenImplementationStatus::Unsupported:
    return "unsupported";
  }
  return "unsupported";
}

class AllocationLifetimeChecker
    : public Checker<check::ASTDecl<FunctionDecl>,
                     check::ASTDecl<TypedefNameDecl>, check::BeginFunction,
                     check::PreCall, check::PostCall,
                     check::PostStmt<BinaryOperator>, check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

  static LifecycleFamilyId familyId(const IdentifierInfo *Family) {
    return {static_cast<uint64_t>(reinterpret_cast<std::uintptr_t>(Family))};
  }

  static LifecycleFamilyId familyId(const ntlibc::algebra::TokenSort *Family) {
    return familyId(Family ? Family->getIdentifier() : nullptr);
  }

  static std::optional<LifecycleFamilyMorphism>
  implementationMorphism(ASTContext &Context,
                         const IdentifierInfo *External) {
    TokenImplementation Implementation = tokenImplementation(
        Context, findTokenSort(Context, External ? External->getName() : ""));
    if (!Implementation.valid())
      return std::nullopt;
    return LifecycleFamilyMorphism{familyId(Implementation.External),
                                   familyId(Implementation.Internal)};
  }

  static bool hasLifecycleFact(ProgramStateRef State, SymbolRef Symbol) {
    return Symbol && State->get<AllocationLifecycle>(Symbol);
  }

  static LifecycleFact lifecycleFor(ProgramStateRef State, SymbolRef Symbol) {
    if (!Symbol)
      return unknownLifecycle();
    const LifecycleState *Phase = State->get<AllocationLifecycle>(Symbol);
    if (!Phase)
      return unknownLifecycle();
    if (*Phase == LifecycleState::Unknown)
      return unknownLifecycle();
    if (*Phase == LifecycleState::Absent)
      return absentLifecycle();
    const IdentifierInfo *const *Family = State->get<AllocationFamily>(Symbol);
    LifecycleFamilyId Id =
        Family ? familyId(*Family) : ntlibc::algebra::NoLifecycleFamily;
    return {*Phase, Id};
  }

  static ProgramStateRef setLifecycleFact(ProgramStateRef State,
                                          SymbolRef Symbol, LifecycleFact Fact,
                                          const IdentifierInfo *Family) {
    if (!Symbol)
      return State;
    State = State->set<AllocationLifecycle>(Symbol, Fact.State);
    if ((Fact.State == LifecycleState::Live ||
         Fact.State == LifecycleState::Released) &&
        Family)
      return State->set<AllocationFamily>(Symbol, Family);
    if (Fact.State == LifecycleState::Absent)
      return State->remove<AllocationFamily>(Symbol);
    return State;
  }

  static ProgramStateRef forget(ProgramStateRef State, SymbolRef Symbol) {
    if (!Symbol)
      return State;
    return State->remove<AllocationOrigin>(Symbol)
        ->remove<AllocationFrame>(Symbol)
        ->remove<AllocationFamily>(Symbol)
        ->remove<AllocationLifecycle>(Symbol)
        ->remove<FreerObligation>(Symbol)
        ->remove<ReplacedBy>(Symbol);
  }

  static ProgramStateRef track(ProgramStateRef State, SymbolRef Symbol,
                               const Stmt *Origin,
                               const StackFrameContext *Frame,
                               const IdentifierInfo *Family,
                               bool IsFreerObligation) {
    if (!Symbol || !Frame || !Family)
      return State;
    State = State->set<AllocationOrigin>(Symbol, Origin);
    State = State->set<AllocationFrame>(Symbol, Frame);
    State = State->set<AllocationFamily>(Symbol, Family);
    LifecycleTransition Acquired = applyLifecycleOperation(
        absentLifecycle(), familyId(Family), LifecycleOperation::Acquire);
    State = State->set<AllocationLifecycle>(Symbol, Acquired.After.State);
    return State->set<FreerObligation>(Symbol, IsFreerObligation);
  }

  static bool belongsToFrame(ProgramStateRef State, SymbolRef Symbol,
                             const StackFrameContext *Frame) {
    const StackFrameContext *const *Owner = State->get<AllocationFrame>(Symbol);
    return Owner && *Owner == Frame;
  }

  static bool canBeNonNull(ProgramStateRef State, SymbolRef Symbol,
                           CheckerContext &C) {
    DefinedSVal Value = C.getSValBuilder().makeSymbolVal(Symbol);
    return State->assume(Value, true) != nullptr;
  }

  /* `*outParam = allocation` is the ordinary C out-parameter idiom: the
   * caller's slot lives behind one pointer indirection from the callee's
   * own parameter variable.  This is recognized only for a parameter
   * dereferenced directly (not through an intervening local alias, which
   * this checker cannot distinguish from an unrelated pointer), and the
   * same withtok annotation already required of every other destination
   * kind still gates the transfer below -- an unannotated out-parameter
   * is not treated as proof of anything, exactly as an unannotated field
   * or local is not. */
  static const ValueDecl *destinationDeclaration(const Expr *Expression) {
    if (!Expression)
      return nullptr;
    Expression = Expression->IgnoreParenImpCasts();
    if (const auto *Reference = dyn_cast<DeclRefExpr>(Expression))
      return dyn_cast<ValueDecl>(Reference->getDecl());
    if (const auto *Member = dyn_cast<MemberExpr>(Expression))
      return Member->getMemberDecl();
    if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(Expression))
      return destinationDeclaration(Subscript->getBase());
    if (const auto *Unary = dyn_cast<UnaryOperator>(Expression))
      if (Unary->getOpcode() == UO_Deref) {
        const Expr *Pointer = Unary->getSubExpr()->IgnoreParenImpCasts();
        if (const auto *Reference = dyn_cast<DeclRefExpr>(Pointer))
          return dyn_cast<ParmVarDecl>(Reference->getDecl());
      }
    return nullptr;
  }

  static bool replacedOnThisPath(ProgramStateRef State, SymbolRef Symbol,
                                 CheckerContext &C) {
    const SymbolRef *Replacement = State->get<ReplacedBy>(Symbol);
    if (!Replacement)
      return false;
    DefinedSVal Value = C.getSValBuilder().makeSymbolVal(*Replacement);
    return State->assume(Value, false) == nullptr;
  }

  /* Retire both sides of a realloc transition once control flow has proved
   * which side owns storage.  Doing this at the actual release call is
   * important: dead-symbol cleanup may discard the null/non-null constraint
   * before checkEndFunction, but `if (replacement) free(replacement); else
   * free(old);` has the decisive fact available at each of these two calls. */
  static ProgramStateRef retireReallocationPeer(ProgramStateRef State,
                                                SymbolRef Consumed) {
    SymbolRef Current = Consumed;
    for (;;) {
      SymbolRef Predecessor = nullptr;
      for (const auto &Entry : State->get<ReplacedBy>()) {
        if (Entry.second == Current) {
          Predecessor = Entry.first;
          break;
        }
      }
      if (!Predecessor)
        break;
      State = forget(State, Predecessor);
      Current = Predecessor;
    }
    return State;
  }

  void report(StringRef Reason, const Stmt *Statement, ProgramStateRef State,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unreleased dynamic allocation",
                                     categories::MemoryError);
    std::string Message = (Reason + "; context '" + contextName(C) +
                           "'; allocation '" + sourceText(Statement, C) + "'")
                              .str();
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    if (Statement)
      Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  void reportLifecycleEvents(LifecycleEvent Events, const Stmt *Statement,
                             ProgramStateRef State, CheckerContext &C) const {
    if (contains(Events, LifecycleEvent::StateUnproven))
      report("allocation lifecycle state is not proven", Statement, State, C);
    if (contains(Events, LifecycleEvent::MissingLive))
      report("allocation is not proven live", Statement, State, C);
    if (contains(Events, LifecycleEvent::AlreadyLive))
      report("allocation result overwrites a live allocation", Statement, State,
             C);
    if (contains(Events, LifecycleEvent::AlreadyReleased))
      report("allocation is already released", Statement, State, C);
    if (contains(Events, LifecycleEvent::FamilyMismatch))
      report("allocation family does not match operation", Statement, State, C);
    if (contains(Events, LifecycleEvent::MorphismMissing))
      report("allocation family morphism is not proven", Statement, State, C);
    if (contains(Events, LifecycleEvent::MorphismMismatch))
      report("allocation family morphism does not match operation", Statement,
             State, C);
  }

public:
  void checkASTDecl(const TypedefNameDecl *Token, AnalysisManager &,
                    BugReporter &) const {
    RawTokenImplementation Raw = rawTokenImplementation(Token);
    if (Raw.Status == TokenImplementationStatus::Missing)
      return;
    TokenImplementation Implementation =
        tokenImplementation(Token->getASTContext(), Token);
    const SourceManager &SM = Token->getASTContext().getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Token->getLocation());
    StringRef Internal =
        Implementation.Internal ? Implementation.Internal->getName() : Raw.Name;
    llvm::errs() << "ntlibc-allocation-contract: implementation-"
                 << implementationStatusName(Implementation.Status) << '\t'
                 << Token->getName() << '\t'
                 << (Internal.empty() ? StringRef("-") : Internal) << '\t'
                 << SM.getFilename(Location) << '\t'
                 << SM.getSpellingLineNumber(Location) << '\n';
  }

  void checkASTDecl(const FunctionDecl *Function, AnalysisManager &,
                    BugReporter &) const {
    if (!Function->getIdentifier())
      return;
    const SourceManager &SM = Function->getASTContext().getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Function->getLocation());
    std::string Path = SM.getFilename(Location).str();
    unsigned Line = SM.getSpellingLineNumber(Location);
    if (Function->doesThisDeclarationHaveABody())
      llvm::errs() << "ntlibc-allocation-contract: definition\t-\t"
                   << Function->getName() << '\t' << Path << '\t' << Line
                   << '\n';
    for (const AnnotateAttr *Attribute :
         Function->specific_attrs<AnnotateAttr>()) {
      StringRef Family = Attribute->getAnnotation();
      if (!Family.consume_front("withtok:") || Family.empty() ||
          Family.contains(':') ||
          !isDynamicStorageToken(Function->getASTContext(), Family))
        continue;
      StringRef Kind =
          !Function->doesThisDeclarationHaveABody() ? "returns-declaration"
          : Attribute->isInherited() ? "returns-definition-inherited"
                                     : "returns-definition-explicit";
      llvm::errs() << "ntlibc-allocation-contract: " << Kind << '\t' << Family
                   << '\t' << Function->getName() << '\t' << Path << '\t'
                   << Line << '\n';
    }
    unsigned Argument = 1;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      for (const AnnotateAttr *Attribute :
           Parameter->specific_attrs<AnnotateAttr>()) {
        StringRef Family = Attribute->getAnnotation();
        if (!Family.consume_front("consume:") || Family.empty() ||
            Family.contains(':') ||
            !isDynamicStorageToken(Function->getASTContext(), Family))
          continue;
        StringRef Kind =
            !Function->doesThisDeclarationHaveABody() ? "takes-declaration"
            : Attribute->isInherited() ? "takes-definition-inherited"
                                       : "takes-definition-explicit";
        llvm::errs() << "ntlibc-allocation-contract: " << Kind << '\t' << Family
                     << '\t' << Function->getName() << '\t' << Argument << '\t'
                     << Path << '\t' << Line << '\n';
      }
      ++Argument;
    }
  }

  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function)
      return;
    llvm::SmallVector<std::pair<const IdentifierInfo *, const ParmVarDecl *>, 4>
        Inputs;
    for (const ParmVarDecl *Parameter : Function->parameters())
      if (const IdentifierInfo *Family =
              annotationFamily(Parameter, "consume:"))
        Inputs.push_back({Family, Parameter});
    llvm::SmallVector<ProgramStateRef, 4> States{C.getState()};
    bool Changed = false;
    for (const auto &[Family, Parameter] : Inputs) {
      llvm::SmallVector<ProgramStateRef, 4> NextStates;
      for (ProgramStateRef State : States) {
        SVal Value =
            State->getSVal(State->getLValue(Parameter, C.getLocationContext()));
        SymbolRef Symbol = Value.getAsLocSymbol(true);
        std::optional<DefinedOrUnknownSVal> Defined =
            Value.getAs<DefinedOrUnknownSVal>();
        if (!Symbol || !Defined) {
          NextStates.push_back(State);
          continue;
        }
        ProgramStateRef ValueState = State;
        if (std::optional<int64_t> Sentinel = excludedSentinel(
                findTokenSort(Function->getASTContext(), Family->getName()))) {
          SentinelSplit Split = splitOnExcludedSentinel(
              ValueState, *Defined, Parameter->getType(), *Sentinel,
              C.getSValBuilder());
          if (Split.Sentinel)
            NextStates.push_back(Split.Sentinel);
          ValueState = Split.NonSentinel;
          if (!ValueState) {
            Changed = true;
            continue;
          }
        }
        auto [NonNullState, NullState] = ValueState->assume(*Defined);
        if (NullState)
          NextStates.push_back(NullState);
        if (NonNullState)
          NextStates.push_back(track(NonNullState, Symbol, nullptr,
                                     C.getStackFrame(), Family, true));
        Changed = true;
      }
      States = std::move(NextStates);
    }
    if (Changed)
      for (ProgramStateRef State : States)
        C.addTransition(State);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    bool Changed = false;
    const FunctionDecl *Function = functionOf(Call);
    for (unsigned Argument = 0; Argument < Call.getNumArgs(); ++Argument) {
      if (!Function || Argument >= Function->getNumParams())
        continue;
      const IdentifierInfo *Expected =
          annotationFamily(Function->getParamDecl(Argument), "consume:");
      if (!Expected)
        continue;
      SymbolRef Symbol = Call.getArgSVal(Argument).getAsLocSymbol(true);
      if (!hasLifecycleFact(State, Symbol))
        continue;
      const bool *Freer = State->get<FreerObligation>(Symbol);
      const IdentifierInfo *const *Actual =
          State->get<AllocationFamily>(Symbol);
      bool ScopedDischarge =
          Freer && *Freer && belongsToFrame(State, Symbol, C.getStackFrame());
      const auto *CurrentFunction = dyn_cast_or_null<FunctionDecl>(
          C.getLocationContext()->getDecl());
      std::optional<TokenContract> CurrentReturns =
          returnsOwnership(CurrentFunction);
      bool ScopedProducerCleanup =
          (!Freer || !*Freer) && Actual && *Actual != Expected &&
          belongsToFrame(State, Symbol, C.getStackFrame()) && CurrentReturns &&
          CurrentReturns->Family == Expected;
      LifecycleFact After;
      LifecycleEvent Events;
      const IdentifierInfo *ResultFamily = Expected;
      if (ScopedDischarge && Actual && *Actual == Expected) {
        LifecycleTransition Released = applyLifecycleOperation(
            lifecycleFor(State, Symbol), familyId(Expected),
            LifecycleOperation::Release);
        After = Released.After;
        Events = Released.Events;
      } else if (ScopedDischarge) {
        std::optional<LifecycleFamilyMorphism> Permission =
            Actual ? implementationMorphism(C.getASTContext(), *Actual)
                   : std::nullopt;
        LifecycleFamilyMorphism Morphism = Permission.value_or(
            LifecycleFamilyMorphism{ntlibc::algebra::NoLifecycleFamily,
                                     ntlibc::algebra::NoLifecycleFamily});
        LifecycleMorphismTransition Discharged = dischargeLifecycle(
            lifecycleFor(State, Symbol), familyId(Expected), Morphism);
        After = Discharged.After;
        Events = Discharged.Events;
        if (Actual)
          ResultFamily = *Actual;
      } else if (ScopedProducerCleanup) {
        std::optional<LifecycleFamilyMorphism> Permission =
            implementationMorphism(C.getASTContext(), Expected);
        LifecycleFamilyMorphism Morphism = Permission.value_or(
            LifecycleFamilyMorphism{ntlibc::algebra::NoLifecycleFamily,
                                     ntlibc::algebra::NoLifecycleFamily});
        LifecycleMorphismTransition Retagged = retagLifecycle(
            lifecycleFor(State, Symbol), familyId(Expected), Morphism);
        After = Retagged.After;
        Events = Retagged.Events;
        if (Retagged.permitted()) {
          LifecycleTransition Released = applyLifecycleOperation(
              Retagged.After, familyId(Expected), LifecycleOperation::Release);
          After = Released.After;
          Events = Events | Released.Events;
        }
      } else {
        LifecycleTransition Released = applyLifecycleOperation(
            lifecycleFor(State, Symbol), familyId(Expected),
            LifecycleOperation::Release);
        After = Released.After;
        Events = Released.Events;
      }
      if (After.State == LifecycleState::Released)
        State = retireReallocationPeer(State, Symbol);
      State = setLifecycleFact(State, Symbol, After, ResultFamily);
      if (const Stmt *Statement = Call.getOriginExpr())
        reportLifecycleEvents(Events, Statement, State, C);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const FunctionDecl *Function = functionOf(Call);
    std::optional<TokenContract> Returns = returnsOwnership(Function);
    if (!Returns)
      return;
    ProgramStateRef State = C.getState();
    if (std::optional<unsigned> Argument =
            returnedArgument(Function, Returns->Family)) {
      if (*Argument >= Call.getNumArgs())
        return;
      std::optional<DefinedOrUnknownSVal> ArgumentValue =
          Call.getArgSVal(*Argument).getAs<DefinedOrUnknownSVal>();
      if (!ArgumentValue)
        return;
      auto [ArgumentNonNullState, ArgumentNullState] =
          State->assume(*ArgumentValue);
      if (ArgumentNonNullState)
        C.addTransition(ArgumentNonNullState);
      if (!ArgumentNullState)
        return;
      State = ArgumentNullState;
    }
    SVal ReturnValue = Call.getReturnValue();
    SymbolRef Result = ReturnValue.getAsLocSymbol(true);
    if (!Result)
      return;
    std::optional<DefinedOrUnknownSVal> Defined =
        ReturnValue.getAs<DefinedOrUnknownSVal>();
    if (!Defined)
      return;
    if (std::optional<int64_t> Sentinel = excludedSentinel(findTokenSort(
            Function->getASTContext(), Returns->Family->getName()))) {
      SentinelSplit Split = splitOnExcludedSentinel(
          State, *Defined, Function->getReturnType(), *Sentinel,
          C.getSValBuilder());
      if (Split.Sentinel)
        C.addTransition(Split.Sentinel);
      if (!Split.NonSentinel)
        return;
      State = Split.NonSentinel;
    }
    auto [NonNullState, NullState] = State->assume(*Defined);
    std::optional<unsigned> Reallocated = reallocatedArgument(Function);
    SymbolRef Old = Reallocated && *Reallocated < Call.getNumArgs()
                        ? Call.getArgSVal(*Reallocated).getAsLocSymbol(true)
                        : nullptr;
    const IdentifierInfo *Family = Returns->Family;
    if (NullState) {
      if (Old && hasLifecycleFact(NullState, Old)) {
        LifecycleFact Source = lifecycleFor(NullState, Old);
        auto Failed = replaceLifecycle(Source, absentLifecycle(),
                                       ReplacementOutcome::Failed,
                                       {familyId(Family), true});
        NullState =
            setLifecycleFact(NullState, Old, Failed.SourceAfter, Family);
        if (const Stmt *Statement = Call.getOriginExpr())
          reportLifecycleEvents(Failed.Events, Statement, NullState, C);
      }
      C.addTransition(NullState);
    }
    if (!NonNullState)
      return;
    /* An inlined forwarding wrapper (for example reallocarray -> realloc)
     * produces both inner and outer PostCall events for the same successful
     * replacement.  ReplacedBy records that the inner contract already
     * consumed this generation on the current path; applying the lifecycle
     * table a second time would manufacture a double-release event. */
    bool ReplacementAlreadyApplied =
        Old && hasLifecycleFact(NonNullState, Old) &&
        replacedOnThisPath(NonNullState, Old, C);
    if (Reallocated && !ReplacementAlreadyApplied) {
      LifecycleFact Source = Old && hasLifecycleFact(NonNullState, Old)
                                 ? lifecycleFor(NonNullState, Old)
                                 : absentLifecycle();
      auto Succeeded = replaceLifecycle(Source, absentLifecycle(),
                                        ReplacementOutcome::Succeeded,
                                        {familyId(Family), true});
      if (Old && hasLifecycleFact(NonNullState, Old))
        NonNullState =
            setLifecycleFact(NonNullState, Old, Succeeded.SourceAfter, Family);
      if (const Stmt *Statement = Call.getOriginExpr())
        reportLifecycleEvents(Succeeded.Events, Statement, NonNullState, C);
    }
    NonNullState = track(NonNullState, Result, Call.getOriginExpr(),
                         C.getStackFrame(), Family, false);
    if (Old && hasLifecycleFact(NonNullState, Old))
      NonNullState = NonNullState->set<ReplacedBy>(Old, Result);
    C.addTransition(NonNullState);
  }

  /* An annotated destination is an owning slot.  Assignment moves the
   * matching dynamic-storage obligation into that slot; the ordinary
   * ownership-type checker separately enforces that the token classes match
   * and that a linear source is not copied.  This is what lets a composite
   * owner collect children without making every constructor look like it
   * leaked each child at function exit. */
  void checkPostStmt(const BinaryOperator *Statement, CheckerContext &C) const {
    if (!Statement->isAssignmentOp())
      return;
    const ValueDecl *Destination = destinationDeclaration(Statement->getLHS());
    const IdentifierInfo *DestinationFamily =
        annotationFamily(Destination, "withtok:");
    if (!DestinationFamily)
      return;
    SymbolRef Source = C.getSVal(Statement->getRHS()).getAsLocSymbol(true);
    if (!Source)
      return;
    ProgramStateRef State = C.getState();
    const IdentifierInfo *const *SourceFamily =
        State->get<AllocationFamily>(Source);
    if (!SourceFamily || !hasLifecycleFact(State, Source) ||
        !belongsToFrame(State, Source, C.getStackFrame()))
      return;
    LifecycleTransition Transfer = applyLifecycleOperation(
        lifecycleFor(State, Source), familyId(DestinationFamily),
        LifecycleOperation::RequireLive);
    reportLifecycleEvents(Transfer.Events, Statement, State, C);
    if (!Transfer.permitted())
      return;
    C.addTransition(forget(State, Source));
  }

  void checkEndFunction(const ReturnStmt *Return, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    std::optional<TokenContract> Returns = returnsOwnership(Function);
    SymbolRef Returned =
        Return && Return->getRetValue()
            ? C.getSVal(Return->getRetValue()).getAsLocSymbol(true)
            : nullptr;

    if (Returned && belongsToFrame(State, Returned, C.getStackFrame())) {
      const Stmt *const *Origin = State->get<AllocationOrigin>(Returned);
      if (!Returns) {
        report("returned allocation has no dynamic-storage token contract",
               Origin ? *Origin : Return, State, C);
        return;
      }
      const IdentifierInfo *const *Actual =
          State->get<AllocationFamily>(Returned);
      LifecycleFact After;
      LifecycleEvent Events;
      bool Permitted = false;
      if (Actual && *Actual == Returns->Family) {
        LifecycleTransition Transfer = applyLifecycleOperation(
            lifecycleFor(State, Returned), familyId(Returns->Family),
            LifecycleOperation::RequireLive);
        After = Transfer.After;
        Events = Transfer.Events;
        Permitted = Transfer.permitted();
      } else {
        std::optional<LifecycleFamilyMorphism> Permission =
            implementationMorphism(C.getASTContext(), Returns->Family);
        LifecycleFamilyMorphism Morphism = Permission.value_or(
            LifecycleFamilyMorphism{ntlibc::algebra::NoLifecycleFamily,
                                     ntlibc::algebra::NoLifecycleFamily});
        LifecycleMorphismTransition Transfer = retagLifecycle(
            lifecycleFor(State, Returned), familyId(Returns->Family),
            Morphism);
        After = Transfer.After;
        Events = Transfer.Events;
        Permitted = Transfer.permitted();
      }
      if (Permitted) {
        State = forget(State, Returned);
      } else {
        State = setLifecycleFact(State, Returned, After,
                                 Actual ? *Actual : Returns->Family);
      }
      reportLifecycleEvents(Events, Return, State, C);
    }

    for (const auto &Entry : State->get<AllocationLifecycle>()) {
      SymbolRef Symbol = Entry.first;
      if (!belongsToFrame(State, Symbol, C.getStackFrame()) ||
          replacedOnThisPath(State, Symbol, C) ||
          !canBeNonNull(State, Symbol, C))
        continue;
      auto Observation = observeLifecycleExit(lifecycleFor(State, Symbol));
      if (Observation.Events == LifecycleEvent::None)
        continue;
      const bool *Freer = State->get<FreerObligation>(Symbol);
      /* Exempt only a cleanly-untouched terminal-family Freer obligation
       * (nothing in the body ever attempted, and failed, to do anything
       * with it) -- StateUnproven here means some in-body operation DID
       * touch this value and got a real mismatch (wrong family, wrong
       * morphism, ...), which stays a genuine bug regardless of whether
       * the family is terminal. */
      if (!contains(Observation.Events, LifecycleEvent::StateUnproven) &&
          Freer && *Freer) {
        const IdentifierInfo *const *Family =
            State->get<AllocationFamily>(Symbol);
        if (Family &&
            isTerminalDynamicStorageFamily(C.getASTContext(), *Family))
          continue;
      }
      const Stmt *const *Origin = State->get<AllocationOrigin>(Symbol);
      const Stmt *Site = Origin ? *Origin
                                : (Return ? static_cast<const Stmt *>(Return)
                                   : Function ? Function->getBody()
                                              : nullptr);
      if (contains(Observation.Events, LifecycleEvent::StateUnproven))
        report("allocation lifecycle state is not proven", Site, State, C);
      else
        report(Freer && *Freer
                   ? "consume function exits without releasing its argument"
                   : "dynamic allocation is not freed before function exit",
               Site, State, C);
      return;
    }
  }
};

} // namespace

void registerAllocationLifetimeChecker(CheckerRegistry &Registry) {
  Registry.addChecker<AllocationLifetimeChecker>(
      "ntlibc.AllocationLifetime",
      "Proves allocations are freed or transferred through a paired "
      "dynamic-storage token contract",
      "");
}
