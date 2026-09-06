// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "clang/AST/Attr.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/RangedConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "LifecycleAlgebra.h"
#include "TokenAlgebra.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#ifdef NTLIBC_OWNERSHIP_Z3
#include "ExactCScalarSMT.h"
#include "z3++.h"
#endif

#include <cctype>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

enum class OwnershipKind : unsigned char { Owned, Consumed };
REGISTER_MAP_WITH_PROGRAMSTATE(OwnershipMap, SymbolRef, OwnershipKind)

REGISTER_MAP_WITH_PROGRAMSTATE(ConstructMap, const MemRegion *,
                               ntlibc::algebra::LifecycleState)
REGISTER_MAP_WITH_PROGRAMSTATE(ConstructFamilyMap, const MemRegion *,
                               const IdentifierInfo *)

enum class CapabilityKind : unsigned char { Linear, Duplicable };
using CapabilityKey = std::pair<const MemRegion *, const IdentifierInfo *>;
REGISTER_MAP_WITH_PROGRAMSTATE(CapabilityMap, CapabilityKey, CapabilityKind)
using SymbolCapabilityKey = std::pair<SymbolRef, const IdentifierInfo *>;
REGISTER_MAP_WITH_PROGRAMSTATE(SymbolCapabilityMap, SymbolCapabilityKey,
                               CapabilityKind)
enum class CarrierCapabilityKind : unsigned char {
  Unknown,
  Absent,
  Linear,
  Duplicable
};
using CarrierCapabilityKey =
    std::pair<const MemRegion *, const IdentifierInfo *>;
REGISTER_MAP_WITH_PROGRAMSTATE(CarrierCapabilityMap, CarrierCapabilityKey,
                               CarrierCapabilityKind)
using AggregateElementKey =
    std::pair<SymbolRef, const IdentifierInfo *>;
REGISTER_MAP_WITH_PROGRAMSTATE(AggregateElementExtent, AggregateElementKey,
                               SymbolRef)
REGISTER_MAP_WITH_PROGRAMSTATE(ElementTokenOrigin, SymbolCapabilityKey,
                               SymbolRef)
using StrictLoanKey = std::pair<const MemRegion *, const IdentifierInfo *>;
REGISTER_MAP_WITH_PROGRAMSTATE(StrictLoanMap, StrictLoanKey, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(ExpiredStrictLoanSet, const MemRegion *)

REGISTER_MAP_WITH_PROGRAMSTATE(ResourceMap, SymbolRef, unsigned)

namespace {

using ntlibc::algebra::excludedSentinel;
using ntlibc::algebra::ElementTokenRelation;
using ntlibc::algebra::findTokenSort;
using ntlibc::algebra::hasQualifier;
using ntlibc::algebra::LifecycleEvent;
using ntlibc::algebra::LifecycleFact;
using ntlibc::algebra::LifecycleFamilyId;
using ntlibc::algebra::LifecycleOperation;
using ntlibc::algebra::LifecycleState;
using ntlibc::algebra::LifecycleTransition;
using ntlibc::algebra::LinearLoanClass;
using ntlibc::algebra::lookupElementToken;
using ntlibc::algebra::ProofStatus;
using ntlibc::algebra::RelationSupport;
using ntlibc::algebra::TokenEvent;
using ntlibc::algebra::TokenEffect;
using ntlibc::algebra::TokenState;
using ntlibc::algebra::TokenTransfer;
using ntlibc::algebra::transferToken;
using ntlibc::algebra::absentLifecycle;
using ntlibc::algebra::applyLifecycleOperation;
using ntlibc::algebra::contains;
using ntlibc::algebra::liveLifecycle;
using ntlibc::algebra::SentinelSplit;
using ntlibc::algebra::splitOnExcludedSentinel;
using ntlibc::algebra::unknownLifecycle;

struct CapabilityPresence {
  bool Known;
  std::optional<CapabilityKind> Kind;
};

static CarrierCapabilityKey carrierKey(const MemRegion *Carrier,
                                       const IdentifierInfo *Family) {
  return {Carrier, Family};
}

static const MemRegion *carrierRegion(const Expr *Expression,
                                      CheckerContext &C) {
  if (!Expression)
    return nullptr;
  const Expr *Core = Expression->IgnoreParenImpCasts();
  if (const auto *Reference = dyn_cast<DeclRefExpr>(Core))
    if (const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl()))
      return C.getState()
          ->getLValue(Variable, C.getLocationContext())
          .getAsRegion();
  if (const auto *Member = dyn_cast<MemberExpr>(Core)) {
    const auto *Field = dyn_cast<FieldDecl>(Member->getMemberDecl());
    if (!Field)
      return C.getSVal(Core).getAsRegion();
    SVal Base = C.getSVal(Member->getBase());
    if (!Member->isArrow()) {
      const MemRegion *BaseRegion = carrierRegion(Member->getBase(), C);
      if (!BaseRegion)
        return C.getSVal(Core).getAsRegion();
      Base = loc::MemRegionVal(BaseRegion);
    }
    return C.getState()->getLValue(Field, Base).getAsRegion();
  }
  if (const auto *Unary = dyn_cast<UnaryOperator>(Core))
    if (Unary->getOpcode() == UO_AddrOf)
      return C.getSVal(Expression).getAsRegion();
  return nullptr;
}

static const CapabilityKind *underlyingTokenFor(ProgramStateRef State,
                                                SVal Value,
                                                const IdentifierInfo *Family) {
  if (SymbolRef Symbol = Value.getAsSymbol(true))
    if (const CapabilityKind *Kind =
            State->get<SymbolCapabilityMap>({Symbol, Family}))
      return Kind;
  if (const MemRegion *Region = Value.getAsRegion())
    return State->get<CapabilityMap>({Region, Family});
  return nullptr;
}

static ProgramStateRef removeUnderlyingToken(ProgramStateRef State, SVal Value,
                                             const IdentifierInfo *Family) {
  if (SymbolRef Symbol = Value.getAsSymbol(true))
    State = State->remove<SymbolCapabilityMap>({Symbol, Family});
  if (const MemRegion *Region = Value.getAsRegion())
    State = State->remove<CapabilityMap>({Region, Family});
  return State;
}

static ProgramStateRef setUnderlyingToken(ProgramStateRef State, SVal Value,
                                          const IdentifierInfo *Family,
                                          CapabilityKind Kind) {
  if (SymbolRef Symbol = Value.getAsSymbol(true))
    State = State->set<SymbolCapabilityMap>({Symbol, Family}, Kind);
  if (const MemRegion *Region = Value.getAsRegion())
    State = State->set<CapabilityMap>({Region, Family}, Kind);
  return State;
}

static CapabilityPresence capabilityFor(ProgramStateRef State,
                                        const MemRegion *Carrier, SVal Value,
                                        const IdentifierInfo *Family) {
  if (Carrier)
    if (const CarrierCapabilityKind *CarrierKind =
            State->get<CarrierCapabilityMap>(carrierKey(Carrier, Family))) {
      if (*CarrierKind == CarrierCapabilityKind::Unknown)
        return {false, std::nullopt};
      if (*CarrierKind == CarrierCapabilityKind::Absent)
        return {true, std::nullopt};
      return {true, *CarrierKind == CarrierCapabilityKind::Linear
                        ? CapabilityKind::Linear
                        : CapabilityKind::Duplicable};
    }
  if (const CapabilityKind *Underlying =
          underlyingTokenFor(State, Value, Family))
    return {false, *Underlying};
  return {false, std::nullopt};
}

static TokenState tokenState(CapabilityPresence Presence) {
  if (!Presence.Kind)
    return Presence.Known ? TokenState::Absent : TokenState::Unknown;
  return *Presence.Kind == CapabilityKind::Linear ? TokenState::Linear
                                                  : TokenState::Duplicable;
}

static TokenState carrierTokenState(ProgramStateRef State,
                                    const MemRegion *Carrier,
                                    const IdentifierInfo *Family) {
  if (!Carrier)
    return TokenState::Unknown;
  const CarrierCapabilityKind *Kind =
      State->get<CarrierCapabilityMap>(carrierKey(Carrier, Family));
  if (!Kind)
    return TokenState::Absent;
  if (*Kind == CarrierCapabilityKind::Unknown)
    return TokenState::Unknown;
  if (*Kind == CarrierCapabilityKind::Absent)
    return TokenState::Absent;
  return *Kind == CarrierCapabilityKind::Linear ? TokenState::Linear
                                                : TokenState::Duplicable;
}

static ProgramStateRef havocCarrierToken(ProgramStateRef State,
                                         const MemRegion *Carrier,
                                         const IdentifierInfo *Family) {
  return Carrier ? State->set<CarrierCapabilityMap>(
                       carrierKey(Carrier, Family),
                       CarrierCapabilityKind::Unknown)
                 : State;
}

static ProgramStateRef havocOperationToken(ProgramStateRef State,
                                           const MemRegion *Carrier,
                                           SVal Value,
                                           const IdentifierInfo *Family) {
  State = havocCarrierToken(State, Carrier, Family);
  if (const MemRegion *Referent = Value.getAsRegion())
    State = havocCarrierToken(State, Referent, Family);
  return removeUnderlyingToken(State, Value, Family);
}

static std::optional<CapabilityKind> dialectTokenKind(ASTContext &Context,
                                                       StringRef Name) {
  const TypedefNameDecl *Token = findTokenSort(Context, Name);
  if (!Token)
    return std::nullopt;
  return hasQualifier(Token, "qual:l_unlimited")
             ? CapabilityKind::Duplicable
             : CapabilityKind::Linear;
}

static bool dialectTokenPermitsCarrierCopy(const TypedefNameDecl *Token) {
  return Token && hasQualifier(Token, "qual:l_permissive") &&
         !hasQualifier(Token, "qual:l_strict") &&
         !hasQualifier(Token, "qual:l_unlimited");
}

static bool initializedByStringLiteral(const ValueDecl *Declaration) {
  const auto *Variable = dyn_cast_or_null<VarDecl>(Declaration);
  if (!Variable || !Variable->hasInit())
    return false;
  const Expr *Initializer = Variable->getInit()->IgnoreParenImpCasts();
  if (isa<StringLiteral>(Initializer))
    return true;
  if (const auto *List = dyn_cast<InitListExpr>(Initializer))
    return List->getNumInits() == 1 &&
           isa<StringLiteral>(List->getInit(0)->IgnoreParenImpCasts());
  return false;
}

static bool initializedByStringLiteralTable(const ArraySubscriptExpr *Access,
                                            ASTContext &Context) {
  if (!Access || !Access->getType()->isPointerType())
    return false;
  const Expr *Base = Access->getBase()->IgnoreParenImpCasts();
  const auto *Reference = dyn_cast<DeclRefExpr>(Base);
  const auto *Variable =
      Reference ? dyn_cast<VarDecl>(Reference->getDecl()) : nullptr;
  if (!Variable || !Variable->hasInit())
    return false;

  const auto *Array = Context.getAsConstantArrayType(Variable->getType());
  if (!Array || !Array->getElementType().isConstQualified())
    return false;
  const auto *List = dyn_cast<InitListExpr>(
      Variable->getInit()->IgnoreParenImpCasts());
  if (!List)
    return false;
  auto IsLiteral = [](const Expr *Initializer) {
    return isa<StringLiteral>(Initializer->IgnoreParenImpCasts());
  };
  if (std::optional<llvm::APSInt> Index =
          Access->getIdx()->getIntegerConstantExpr(Context)) {
    if (!Index->isNegative() && Index->getActiveBits() <= 64 &&
        Index->getZExtValue() < List->getNumInits() &&
        IsLiteral(List->getInit(Index->getZExtValue())))
      return true;
  }
  if (Array->getSize() == List->getNumInits() && !List->getArrayFiller() &&
      llvm::all_of(List->inits(), IsLiteral))
    return true;

  return false;
}

static bool initializedByStringLiteralMemberTable(const MemberExpr *Member,
                                                  ASTContext &Context) {
  if (!Member || Member->isArrow() || !Member->getType()->isPointerType())
    return false;
  const auto *Field = dyn_cast<FieldDecl>(Member->getMemberDecl());
  const auto *Access = dyn_cast<ArraySubscriptExpr>(
      Member->getBase()->IgnoreParenImpCasts());
  if (!Field || !Access)
    return false;
  const Expr *Base = Access->getBase()->IgnoreParenImpCasts();
  const auto *Reference = dyn_cast<DeclRefExpr>(Base);
  const auto *Variable =
      Reference ? dyn_cast<VarDecl>(Reference->getDecl()) : nullptr;
  if (!Variable || !Variable->hasInit())
    return false;
  const auto *Array = Context.getAsConstantArrayType(Variable->getType());
  if (!Array || !Array->getElementType().isConstQualified())
    return false;
  const auto *Table = dyn_cast<InitListExpr>(
      Variable->getInit()->IgnoreParenImpCasts());
  if (!Table || Array->getSize() != Table->getNumInits() ||
      Table->getArrayFiller())
    return false;

  unsigned FieldIndex = 0;
  for (const FieldDecl *Candidate : Field->getParent()->fields()) {
    if (Candidate == Field)
      break;
    ++FieldIndex;
  }
  return llvm::all_of(Table->inits(), [&](const Expr *Row) {
    const auto *Fields =
        dyn_cast<InitListExpr>(Row->IgnoreParenImpCasts());
    return Fields && FieldIndex < Fields->getNumInits() &&
           isa<StringLiteral>(
               Fields->getInit(FieldIndex)->IgnoreParenImpCasts());
  });
}

static bool expressionProvidesStringLiteralToken(
    const Expr *Expression, const IdentifierInfo *Family, ASTContext &Context) {
  if (!Expression || !Family)
    return false;
  const TypedefNameDecl *Token =
      findTokenSort(Context, Family->getName());
  if (!hasQualifier(Token, "qual:string_literal"))
    return false;
  const Expr *Core = Expression->IgnoreParenImpCasts();
  if (isa<StringLiteral>(Core))
    return true;
  if (const auto *Reference = dyn_cast<DeclRefExpr>(Core))
    return initializedByStringLiteral(Reference->getDecl());
  if (const auto *Access = dyn_cast<ArraySubscriptExpr>(Core))
    return initializedByStringLiteralTable(Access, Context);
  if (const auto *Member = dyn_cast<MemberExpr>(Core))
    return initializedByStringLiteralMemberTable(Member, Context);
  return false;
}

static bool dialectTokenExcludes(const IdentifierInfo *Family,
                                 const Expr *Expression,
                                 ASTContext &Context) {
  if (!Family || !Expression)
    return false;
  std::optional<int64_t> Sentinel = excludedSentinel(
      findTokenSort(Context, Family->getName()));
  if (!Sentinel)
    return false;
  std::optional<llvm::APSInt> Value =
      Expression->IgnoreParenImpCasts()->getIntegerConstantExpr(Context);
  return Value && Value->isSignedIntN(64) &&
         Value->getSExtValue() == *Sentinel;
}

static ProgramStateRef setCarrierToken(ProgramStateRef State,
                                       const MemRegion *Carrier,
                                       const IdentifierInfo *Family,
                                       CapabilityKind Kind) {
  if (!Carrier)
    return State;
  return State->set<CarrierCapabilityMap>(
      carrierKey(Carrier, Family), Kind == CapabilityKind::Linear
                                       ? CarrierCapabilityKind::Linear
                                       : CarrierCapabilityKind::Duplicable);
}

static ProgramStateRef removeCarrierToken(ProgramStateRef State,
                                          const MemRegion *Carrier,
                                          const IdentifierInfo *Family) {
  if (!Carrier)
    return State;
  return State->set<CarrierCapabilityMap>(carrierKey(Carrier, Family),
                                          CarrierCapabilityKind::Absent);
}

static ProgramStateRef setOperationToken(ProgramStateRef State,
                                         const MemRegion *Carrier, SVal Value,
                                         const IdentifierInfo *Family,
                                         CapabilityKind Kind) {
  State = setCarrierToken(State, Carrier, Family, Kind);
  if (const MemRegion *Referent = Value.getAsRegion())
    State = setCarrierToken(State, Referent, Family, Kind);
  return setUnderlyingToken(State, Value, Family, Kind);
}

static ProgramStateRef removeOperationToken(ProgramStateRef State,
                                            const MemRegion *Carrier,
                                            SVal Value,
                                            const IdentifierInfo *Family) {
  State = removeCarrierToken(State, Carrier, Family);
  if (const MemRegion *Referent = Value.getAsRegion())
    State = removeCarrierToken(State, Referent, Family);
  return removeUnderlyingToken(State, Value, Family);
}

static std::string diagnosticText(const Stmt *Statement, CheckerContext &C) {
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

static std::string diagnosticOrigin(const Stmt *Statement, CheckerContext &C) {
  const SourceManager &SM = C.getSourceManager();
  return SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())).str();
}

static std::string diagnosticSite(const Stmt *Statement, CheckerContext &C) {
  const SourceManager &SM = C.getSourceManager();
  SourceLocation Location = SM.getExpansionLoc(Statement->getBeginLoc());
  FileID File = SM.getFileID(Location);
  bool Invalid = false;
  StringRef Buffer = SM.getBufferData(File, &Invalid);
  if (Invalid)
    return Statement->getStmtClassName();
  unsigned Offset = SM.getFileOffset(Location);
  size_t Begin = Buffer.rfind('\n', Offset);
  Begin = Begin == StringRef::npos ? 0 : Begin + 1;
  size_t End = Buffer.find('\n', Offset);
  if (End == StringRef::npos)
    End = Buffer.size();
  StringRef Raw = Buffer.slice(Begin, End);
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
  return Result;
}

static std::string diagnosticContext(CheckerContext &C) {
  const Decl *Current = C.getLocationContext()->getDecl();
  if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
    return Named->getQualifiedNameAsString();
  return Current ? Current->getDeclKindName() : "unknown";
}

static std::string diagnosticMessage(StringRef Reason, const Stmt *Statement,
                                     CheckerContext &C) {
  return (Reason + "; origin '" + diagnosticOrigin(Statement, C) +
          "'; context '" + diagnosticContext(C) + "'; expression '" +
          diagnosticText(Statement, C) + "'; site '" +
          diagnosticSite(Statement, C) + "'")
      .str();
}

static bool insideDynamicStorageConsumer(CheckerContext &C) {
  const auto *Function =
      dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
  if (!Function)
    return false;
  for (const ParmVarDecl *Parameter : Function->parameters())
    for (const AnnotateAttr *Attribute :
         Parameter->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attribute->getAnnotation();
      bool Consumer = Text.consume_front("consume:");
      if (!Consumer) {
        Text = Attribute->getAnnotation();
        Consumer = Text.consume_front("consume_if_nonnull_return:");
      }
      if (Consumer && !Text.empty() &&
          !Text.contains(':') &&
          hasQualifier(findTokenSort(Function->getASTContext(), Text),
                       "qual:dynamic_storage"))
        return true;
    }
  return false;
}

class OwnershipChecker
    : public Checker<check::PreCall, check::PostCall, check::Location> {
  mutable std::unique_ptr<BugType> BT;

  static const FunctionDecl *functionOf(const CallEvent &Call) {
    return dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  }

  static bool returnsOwnership(const CallEvent &Call) {
    const FunctionDecl *Function = functionOf(Call);
    if (!Function)
      return false;
    for (const AnnotateAttr *Attribute :
         Function->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attribute->getAnnotation();
      if (Text.consume_front("withtok:") && !Text.empty() &&
          !Text.contains(':')) {
        const TypedefNameDecl *Token =
            findTokenSort(Function->getASTContext(), Text);
        if (hasQualifier(Token, "qual:dynamic_storage"))
          return true;
      }
    }
    return false;
  }

  static std::optional<unsigned>
  reallocatedArgument(const FunctionDecl *Function) {
    if (!Function)
      return std::nullopt;
    unsigned Argument = 0;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      for (const AnnotateAttr *Attribute :
           Parameter->specific_attrs<AnnotateAttr>()) {
        StringRef Text = Attribute->getAnnotation();
        if (Text.consume_front("consume_if_nonnull_return:") &&
            !Text.empty() && !Text.contains(':') &&
            hasQualifier(findTokenSort(Function->getASTContext(), Text),
                         "qual:dynamic_storage"))
          return Argument;
      }
      ++Argument;
    }
    return std::nullopt;
  }

  static std::optional<unsigned>
  returnedArgument(const FunctionDecl *Function) {
    if (!Function)
      return std::nullopt;
    StringRef ReturnedFamily;
    for (const AnnotateAttr *Attribute :
         Function->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attribute->getAnnotation();
      if (Text.consume_front("withtok:") && !Text.empty() &&
          !Text.contains(':')) {
        ReturnedFamily = Text;
        break;
      }
    }
    if (ReturnedFamily.empty())
      return std::nullopt;
    unsigned Argument = 0;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      for (const AnnotateAttr *Attribute :
           Parameter->specific_attrs<AnnotateAttr>()) {
        StringRef Text = Attribute->getAnnotation();
        if (Text.consume_front("withtok:") && Text == ReturnedFamily)
          return Argument;
      }
      ++Argument;
    }
    return std::nullopt;
  }

  static std::optional<unsigned>
  ownershipTakenArgument(const FunctionDecl *Function) {
    if (!Function)
      return std::nullopt;
    unsigned Argument = 0;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      for (const AnnotateAttr *Attribute :
           Parameter->specific_attrs<AnnotateAttr>()) {
        StringRef Text = Attribute->getAnnotation();
        if (Text.consume_front("consume:") && !Text.empty() &&
            !Text.contains(':') &&
            hasQualifier(findTokenSort(Function->getASTContext(), Text),
                         "qual:dynamic_storage"))
          return Argument;
      }
      ++Argument;
    }
    return std::nullopt;
  }

  static bool hasName(const CallEvent &Call, StringRef Wanted) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    return Function && Function->getIdentifier() &&
           Function->getName() == Wanted;
  }

  static bool isAllocator(const CallEvent &Call) {
    return returnsOwnership(Call);
  }

  // Clang's own dynamic-extent tracking for an allocator's return value
  // only fires for a handful of literally-named standard functions
  // (confirmed empirically against clang 18: `malloc(n)` gets a real,
  // usable dynamic extent; `__malloc(n)` -- the name every allocation
  // inside this tree's OWN code actually goes through, since `malloc`
  // itself is just this codebase's own public wrapper around it -- does
  // not, leaving ValidPointerChecker with nothing but an unconstrained
  // SymbolExtent placeholder for every buffer this codebase allocates
  // through its own internal entry point). isAllocator() above already
  // recognizes this whole family for ownership-tracking purposes and
  // already has the real call in hand, so it can set the region's real
  // dynamic extent itself, straight from the real size argument(s) --
  // exactly the fact clang's own builtin modeling would have recorded had
  // the function been literally named "malloc"/"calloc"/etc. This is not
  // a new assumption layered on top of what the program does: it is the
  // exact byte count the allocator itself is about to hand back, read
  // directly off the arguments of the call that produced it.
  //
  // strdup/strndup are deliberately left alone: their real size depends
  // on the *content* of a string argument (strlen, or a strnlen capped by
  // a second argument), not a value already sitting in a register at the
  // call site the way every other allocator's size is, so there is no
  // argument SVal here that IS the answer the way there is for the rest
  // of this family.
  static std::optional<SVal> allocationSizeInBytes(const CallEvent &Call,
                                                   CheckerContext &C) {
    SValBuilder &Builder = C.getSValBuilder();
    QualType SizeTy = C.getASTContext().getSizeType();
    unsigned NumArgs = Call.getNumArgs();
    auto Arg = [&](unsigned Index) -> SVal {
      return Index < NumArgs ? Call.getArgSVal(Index) : UnknownVal();
    };
    if (hasName(Call, "malloc") || hasName(Call, "__malloc") ||
        hasName(Call, "valloc"))
      return NumArgs >= 1 ? std::optional<SVal>(Arg(0)) : std::nullopt;
    if (hasName(Call, "calloc"))
      return NumArgs >= 2 ? std::optional<SVal>(Builder.evalBinOp(
                                C.getState(), BO_Mul, Arg(0), Arg(1), SizeTy))
                          : std::nullopt;
    if (hasName(Call, "realloc"))
      return NumArgs >= 2 ? std::optional<SVal>(Arg(1)) : std::nullopt;
    if (hasName(Call, "reallocarray"))
      return NumArgs >= 3 ? std::optional<SVal>(Builder.evalBinOp(
                                C.getState(), BO_Mul, Arg(1), Arg(2), SizeTy))
                          : std::nullopt;
    if (hasName(Call, "aligned_alloc") || hasName(Call, "memalign"))
      return NumArgs >= 2 ? std::optional<SVal>(Arg(1)) : std::nullopt;
    return std::nullopt;
  }

  // Nothing in clang's own builtin summaries relates a NUL-terminated
  // string SCAN's return value to the dynamic extent of the pointer it
  // scanned: strlen(s)/wcslen(s) can't return L without having read
  // s[0..L] to find it, so s really does have at least L+1 bytes.
  // strcspn/wcscspn/strspn/wcsspn share the shape: each stops the
  // instant s[L] is a byte it had to inspect (in/absent from the
  // reject/accept set, or the NUL), so the same bound holds regardless
  // of which stopping condition ended the scan.
  //
  // Developed against strsep.c's `end = s + strcspn(s, sep); if (*end)
  // *end++ = 0;`, strtok.c/strtok_r.c's `s += strspn(s, sep); if (!*s)
  // ...`, and catgets.c's `v = lang + strcspn(lang, "_"); if (*v) v++;`
  // -- all three deref the scan's own offset into the pointer just
  // scanned, with no allocator involved, and were false positives
  // before this fix gave them a real extent.
  static bool isScanExtentFunction(const CallEvent &Call) {
    static constexpr llvm::StringLiteral Names[] = {
        "strlen", "strcspn", "strspn", "wcslen", "wcscspn", "wcsspn"};
    for (StringRef Name : Names)
      if (hasName(Call, Name))
        return true;
    return false;
  }

  // Sets the scanned argument's own dynamic extent from the scan's
  // return value, per isScanExtentFunction's comment above.
  //
  // Deliberately narrow, like allocationSizeInBytes: only fires when the
  // scanned argument's region IS the base region already (no offset
  // already applied). A scan of an already-advanced cursor (strtok_r.c's
  // second strcspn() call, on `s` after `s += strspn(...)`) would need
  // that offset composed with this scan's return value, which this
  // doesn't attempt -- left as an unprovable-but-correct residual.
  //
  // Only ever writes an extent that isn't already real: a base region a
  // previous scan/allocation already gave a real (possibly smaller)
  // extent to is left alone, since there's no general way to compare two
  // symbolic bounds. Every scan contract is a true lower bound, so this
  // costs completeness, never soundness.
  //
  // The element width used to convert the scan's return value (always in
  // elements: wcslen() counts wchar_t's) into bytes is read off the
  // argument's real AST-declared pointee type, NOT clang's builtin
  // wchar_t (ASTContext::getWCharType()). This codebase's own wchar_t is
  // deliberately 2 bytes on every arch (its own UTF-16 convention), which
  // differs from clang's builtin default on aarch64 (4 bytes, no
  // --target triple) even though it happens to coincide on the
  // i386/x86_64 mingw32 targets -- using getWCharType() would silently
  // use the wrong byte multiplier on aarch64 and leave wcstok.c's
  // wcsspn() scanner reported there while proving fine elsewhere.
  static void trackScanExtent(const CallEvent &Call, CheckerContext &C) {
    if (Call.getNumArgs() < 1)
      return;
    const MemRegion *Region = Call.getArgSVal(0).getAsRegion();
    if (!Region || Region != Region->getBaseRegion())
      return;
    const Expr *ArgExpr = Call.getArgExpr(0);
    if (!ArgExpr)
      return;
    QualType PointerTy = ArgExpr->IgnoreParenCasts()->getType();
    if (!PointerTy->isPointerType())
      return;
    QualType ElemTy = PointerTy->getPointeeType();
    if (ElemTy.isNull() || ElemTy->isIncompleteType())
      return;
    CharUnits ElemWidth = C.getASTContext().getTypeSizeInChars(ElemTy);
    if (ElemWidth.isZero())
      return;
    ProgramStateRef State = C.getState();
    SValBuilder &Builder = C.getSValBuilder();
    SVal CurrentExtent = getDynamicExtent(State, Region, Builder);
    bool NoRealExtentInfo =
        CurrentExtent.isUnknownOrUndef() ||
        isa_and_nonnull<SymbolExtent>(CurrentExtent.getAsSymbol());
    if (!NoRealExtentInfo)
      return;
    std::optional<DefinedOrUnknownSVal> Scanned =
        Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
    if (!Scanned)
      return;
    QualType SizeTy = C.getASTContext().getSizeType();
    // strlen()/wcslen() (unlike strcspn/strspn and their wide-character
    // counterparts, which can legitimately stop at 0 on a NON-empty
    // string whose very first element already satisfies the stop
    // condition) have a fact none of the other scan-extent functions
    // share: the scan's result is 0 if and only if the scanned buffer's
    // own first element is already 0 -- that is what "length" means for
    // a NUL-terminated string. When this same state already proves the
    // first element nonzero (a preceding `if (!s || !*s) return ...;`-
    // style guard, the shape src/misc/basename.c/dirname.c's `i =
    // strlen(s) - 1;` and src/string/wcsrchr.c's `p = s + wcslen(s);`
    // both follow), the checker can soundly conclude Scanned != 0 too --
    // a real fact about the SAME buffer this scan just read, not a new
    // assumption. Without it, `i = strlen(s) - 1` (and any later re-
    // decrement of it, e.g. a second loop iteration's `i - 1`) has to
    // additionally entertain the symbolically-reachable-but-source-
    // impossible Scanned == 0 branch, which underflows the subtraction
    // to a huge value near SIZE_MAX and defeats the extent proof for
    // every access downstream of it, regardless of how tightly the
    // extent itself is otherwise bounded.
    if (hasName(Call, "strlen") || hasName(Call, "wcslen")) {
      if (const auto *Super = dyn_cast<SubRegion>(Region)) {
        const ElementRegion *FirstElement =
            C.getSValBuilder().getRegionManager().getElementRegion(
                ElemTy, Builder.makeZeroArrayIndex(), Super,
                C.getASTContext());
        SVal FirstValue = State->getSVal(FirstElement);
        SVal FirstIsZero = Builder.evalBinOp(
            State, BO_EQ, FirstValue, Builder.makeZeroVal(ElemTy),
            Builder.getConditionType());
        if (std::optional<DefinedOrUnknownSVal> FirstIsZeroCondition =
                FirstIsZero.getAs<DefinedOrUnknownSVal>()) {
          // The only way to learn "the first element cannot be 0" from
          // a ConstraintManager that only ever narrows ranges (never
          // proves a positive fact outright) is to ask it whether the
          // OPPOSITE assumption is feasible: if assuming "first element
          // == 0" produces no state at all, every path already rules
          // that value out, so it really is provably nonzero here.
          if (!State->assume(*FirstIsZeroCondition, true)) {
            SVal NotEmpty = Builder.evalBinOp(
                State, BO_NE, *Scanned, Builder.makeZeroVal(SizeTy),
                Builder.getConditionType());
            if (std::optional<DefinedOrUnknownSVal> NotEmptyCondition =
                    NotEmpty.getAs<DefinedOrUnknownSVal>())
              if (ProgramStateRef Bounded =
                      State->assume(*NotEmptyCondition, true))
                State = Bounded;
          }
        }
      }
    }
    SVal Elements = Builder.evalBinOp(State, BO_Add, *Scanned,
                                      Builder.makeIntVal(1, SizeTy), SizeTy);
    SVal Bytes =
        ElemWidth.isOne()
            ? Elements
            : Builder.evalBinOp(
                  State, BO_Mul, Elements,
                  Builder.makeIntVal(ElemWidth.getQuantity(), SizeTy), SizeTy);
    std::optional<DefinedOrUnknownSVal> DefinedBytes =
        Bytes.getAs<DefinedOrUnknownSVal>();
    if (!DefinedBytes)
      return;
    C.addTransition(setDynamicExtent(State, Region, *DefinedBytes, Builder));
  }

  static bool insideOwnershipConsumer(CheckerContext &C) {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    return ownershipTakenArgument(Function).has_value() ||
           reallocatedArgument(Function).has_value();
  }

  static std::string sourceText(const Stmt *Statement, CheckerContext &C) {
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

  static std::string sourceOrigin(const Stmt *Statement, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    return SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())).str();
  }

  static std::string sourceSite(const Stmt *Statement, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Statement->getBeginLoc());
    FileID File = SM.getFileID(Location);
    bool Invalid = false;
    StringRef Buffer = SM.getBufferData(File, &Invalid);
    if (Invalid)
      return Statement->getStmtClassName();
    unsigned Offset = SM.getFileOffset(Location);
    size_t Begin = Buffer.rfind('\n', Offset);
    Begin = Begin == StringRef::npos ? 0 : Begin + 1;
    size_t End = Buffer.find('\n', Offset);
    if (End == StringRef::npos)
      End = Buffer.size();
    StringRef Raw = Buffer.slice(Begin, End);
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
    return Result;
  }

  static std::string currentContext(CheckerContext &C) {
    const Decl *Current = C.getLocationContext()->getDecl();
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      return Named->getQualifiedNameAsString();
    return Current ? Current->getDeclKindName() : "unknown";
  }

  void report(StringRef Reason, const Stmt *Statement, ProgramStateRef State,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven pointer ownership",
                                     categories::MemoryError);
    std::string Message =
        (Reason + "; origin '" + sourceOrigin(Statement, C) + "'; context '" +
         currentContext(C) + "'; expression '" + sourceText(Statement, C) +
         "'; site '" + sourceSite(Statement, C) + "'")
            .str();
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  static SymbolRef allocationSymbol(SVal Value) {
    return Value.getAsSymbol(/*IncludeBaseRegions=*/true);
  }

  static SymbolRef accessedOwner(SVal Location) {
    const MemRegion *Region = Location.getAsRegion();
    if (!Region)
      return nullptr;
    const auto *Symbolic = dyn_cast<SymbolicRegion>(Region->getBaseRegion());
    return Symbolic ? Symbolic->getSymbol() : nullptr;
  }

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    if (isScanExtentFunction(Call)) {
      trackScanExtent(Call, C);
      return;
    }
    if (!isAllocator(Call))
      return;
    ProgramStateRef State = C.getState();
    const FunctionDecl *Function = functionOf(Call);
    if (std::optional<unsigned> Argument = returnedArgument(Function)) {
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
    if (std::optional<unsigned> Argument = reallocatedArgument(Function);
        Argument && *Argument < Call.getNumArgs() &&
        State->isNull(ReturnValue).isConstrainedFalse()) {
      SymbolRef Old = allocationSymbol(Call.getArgSVal(*Argument));
      if (Old)
        State = State->set<OwnershipMap>(Old, OwnershipKind::Consumed);
    }
    SymbolRef Symbol = allocationSymbol(ReturnValue);
    if (!Symbol)
      return;
    State = State->set<OwnershipMap>(Symbol, OwnershipKind::Owned);
    if (std::optional<SVal> SizeInBytes = allocationSizeInBytes(Call, C)) {
      if (std::optional<DefinedOrUnknownSVal> DefinedSize =
              SizeInBytes->getAs<DefinedOrUnknownSVal>()) {
        if (const MemRegion *Region = ReturnValue.getAsRegion())
          State = setDynamicExtent(State, Region->getBaseRegion(), *DefinedSize,
                                   C.getSValBuilder());
      }
    }
    C.addTransition(State);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const FunctionDecl *Function = functionOf(Call);
    std::optional<unsigned> Taken = ownershipTakenArgument(Function);
    std::optional<unsigned> Reallocated = reallocatedArgument(Function);
    bool Deallocator = Taken.has_value();
    bool Reallocator = Reallocated.has_value();
    if (!Deallocator && !Reallocator)
      return;
    unsigned ArgumentIndex = Deallocator ? *Taken : *Reallocated;
    if (ArgumentIndex >= Call.getNumArgs())
      return;
    if (insideOwnershipConsumer(C))
      return;
    const Stmt *Statement = Call.getOriginExpr();
    if (!Statement)
      return;

    SVal Argument = Call.getArgSVal(ArgumentIndex);
    ProgramStateRef State = C.getState();
    if (State->isNull(Argument).isConstrainedTrue())
      return;

    SymbolRef Symbol = allocationSymbol(Argument);
    const OwnershipKind *Kind =
        Symbol ? State->get<OwnershipMap>(Symbol) : nullptr;
    if (!Kind) {
      // Symbol == nullptr: the argument is a concrete address (stack-local,
      // global, array, ...) never returned by malloc() -- positive evidence
      // of a real bug, still reported, UNLESS the value is Unknown/Undef
      // (the analyzer itself lost track of it, e.g. a loop variable widened
      // away past clang's max-loop cap), which is the same "no information"
      // case as an untracked symbol below and not a real proof obligation.
      //
      // Symbol != nullptr but absent from OwnershipMap: the pointer's
      // provenance is opaque to this per-function analysis, e.g. a handle
      // received across a call boundary (closedir()'s DIR*, malloc'd inside
      // a different function this analysis never sees). This only trusts
      // the borrow; it still transitions the symbol to Consumed on a real
      // free() so a same-function double-free is still caught below.
      if (!Symbol) {
        if (Argument.isUnknownOrUndef())
          return;
        report(Deallocator ? "deallocator argument is not proven owned"
                           : "reallocator argument is not proven owned",
               Statement, State, C);
        return;
      }
      if (Deallocator)
        C.addTransition(
            State->set<OwnershipMap>(Symbol, OwnershipKind::Consumed));
      return;
    }
    if (*Kind == OwnershipKind::Consumed) {
      report("ownership is already consumed", Statement, State, C);
      return;
    }
    if (Deallocator)
      C.addTransition(
          State->set<OwnershipMap>(Symbol, OwnershipKind::Consumed));
  }

  void checkLocation(SVal Location, bool, const Stmt *Statement,
                     CheckerContext &C) const {
    SymbolRef Symbol = accessedOwner(Location);
    if (!Symbol)
      return;
    const OwnershipKind *Kind = C.getState()->get<OwnershipMap>(Symbol);
    if (Kind && *Kind == OwnershipKind::Consumed &&
        !insideDynamicStorageConsumer(C))
      report("borrow accesses a consumed owner", Statement, C.getState(), C);
  }
};

enum class ConstructOperation : unsigned char { Construct, Destroy, Use };

struct ConstructCall {
  ConstructOperation Operation;
  const IdentifierInfo *Family;
  unsigned Argument;
  bool StaticInitialization;
};

class OwnedConstructChecker : public Checker<check::PreCall, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

  static LifecycleFamilyId familyId(const IdentifierInfo *Family) {
    return {static_cast<uint64_t>(reinterpret_cast<uintptr_t>(Family))};
  }

  static const IdentifierInfo *parameterAnnotation(const FunctionDecl *Function,
                                                   const AnnotateAttr *Attr,
                                                   StringRef Prefix) {
    StringRef Text = Attr->getAnnotation();
    if (!Text.consume_front(Prefix) || Text.empty() || Text.contains(':'))
      return nullptr;
    return &Function->getASTContext().Idents.get(Text);
  }

  static bool hasParameterAnnotation(const FunctionDecl *Function,
                                     const ParmVarDecl *Parameter,
                                     StringRef Prefix,
                                     const IdentifierInfo *Family) {
    for (const AnnotateAttr *Attr : Parameter->specific_attrs<AnnotateAttr>())
      if (parameterAnnotation(Function, Attr, Prefix) == Family)
        return true;
    return false;
  }

  static llvm::SmallVector<ConstructCall, 4>
  protocolsFor(const CallEvent &Call) {
    llvm::SmallVector<ConstructCall, 4> Protocols;
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function)
      return Protocols;
    struct OperationAnnotation {
      llvm::StringLiteral Prefix;
      ConstructOperation Operation;
    };
    static constexpr OperationAnnotation Operations[] = {
        {"construct:", ConstructOperation::Construct},
        {"destroy:", ConstructOperation::Destroy},
        {"handle:", ConstructOperation::Use}};
    unsigned Argument = 0;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      for (const AnnotateAttr *Attr : Parameter->specific_attrs<AnnotateAttr>())
        for (const OperationAnnotation &Candidate : Operations)
          if (const IdentifierInfo *Family =
                  parameterAnnotation(Function, Attr, Candidate.Prefix))
            Protocols.push_back(
                {Candidate.Operation, Family, Argument,
                 hasParameterAnnotation(Function, Parameter,
                                        "static_handle:", Family)});
      ++Argument;
    }
    return Protocols;
  }

  static bool isZeroInitializer(const Expr *Initializer) {
    Initializer = Initializer->IgnoreParenImpCasts();
    if (isa<ImplicitValueInitExpr>(Initializer))
      return true;
    if (const auto *Integer = dyn_cast<IntegerLiteral>(Initializer))
      return Integer->getValue().isZero();
    if (const auto *List = dyn_cast<InitListExpr>(Initializer)) {
      for (const Expr *Element : List->inits())
        if (!isZeroInitializer(Element))
          return false;
      const Expr *Filler = List->getArrayFiller();
      return !Filler || isZeroInitializer(Filler);
    }
    if (const auto *Cast = dyn_cast<CastExpr>(Initializer))
      return isZeroInitializer(Cast->getSubExpr());
    return false;
  }

  static bool hasStaticInitialization(const MemRegion *Region, bool Accepted) {
    if (!Accepted)
      return false;
    const auto *Variable = dyn_cast<VarRegion>(Region);
    if (!Variable)
      return false;
    const VarDecl *Declaration = Variable->getDecl();
    if (!Declaration->hasInit())
      return Declaration->hasGlobalStorage();
    return isZeroInitializer(Declaration->getInit());
  }

  static const MemRegion *argumentRegion(const CallEvent &Call,
                                         unsigned Argument) {
    if (Argument >= Call.getNumArgs())
      return nullptr;
    return Call.getArgSVal(Argument).getAsRegion();
  }

  void report(StringRef Reason, const Stmt *Statement, ProgramStateRef State,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven owned construct",
                                     categories::MemoryError);
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, diagnosticMessage(Reason, Statement, C), Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  // True when Region's identity itself crosses a call boundary this
  // per-function analysis cannot see through -- the exact same "was this
  // value ever visible to my own tracking" gap already fixed for
  // OwnershipChecker::checkPreCall's deallocator argument and
  // ResourceLifecycleChecker::checkResource's liveness proof (see their
  // own comments), just never applied to construct lifecycles. A
  // SymbolicRegion base means this object's address came in as an
  // opaque, borrowed pointer -- overwhelmingly a plain parameter, e.g.
  // pthread_cond_wait's own `mutex`, or sem_timedwait's `sem`, both of
  // which POSIX requires the CALLER to have already initialized, in code
  // this per-function analysis never sees at all (a different TU
  // entirely, in the general case). ConstructMap can only ever gain an
  // entry for a construct by watching THIS analysis's own
  // pthread_*_init()/sem_init() call it directly, so an absent entry for
  // a borrowed object is not evidence it was never initialized, it is
  // simply the ordinary, expected shape of "someone else's problem to
  // have set up". A concrete VarRegion/local or global, by contrast, is
  // an object this analysis DOES see the entire lifetime of within the
  // current function, so an absent entry there remains real, checkable
  // evidence of a genuinely never-initialized on-stack synchronization
  // object -- that case is unchanged and still reported.
  static bool isOpaqueBorrow(const MemRegion *Region) {
    return Region && Region->getSymbolicBase() != nullptr;
  }

  static LifecycleFact constructFact(ProgramStateRef State,
                                     const MemRegion *Region,
                                     const ConstructCall &Protocol,
                                     bool TrustOpaqueBorrow) {
    const LifecycleState *Phase = State->get<ConstructMap>(Region);
    if (!Phase) {
      if (hasStaticInitialization(Region, Protocol.StaticInitialization) ||
          (TrustOpaqueBorrow && isOpaqueBorrow(Region)))
        return liveLifecycle(familyId(Protocol.Family));
      return absentLifecycle();
    }
    if (*Phase == LifecycleState::Unknown)
      return unknownLifecycle();
    if (*Phase == LifecycleState::Absent)
      return absentLifecycle();
    const IdentifierInfo *const *Family =
        State->get<ConstructFamilyMap>(Region);
    if (!Family)
      return unknownLifecycle();
    LifecycleFamilyId Id = familyId(*Family);
    return *Phase == LifecycleState::Live
               ? liveLifecycle(Id)
               : ntlibc::algebra::releasedLifecycle(Id);
  }

  static ProgramStateRef setConstructFact(ProgramStateRef State,
                                          const MemRegion *Region,
                                          LifecycleFact Fact,
                                          const IdentifierInfo *Family) {
    State = State->set<ConstructMap>(Region, Fact.State);
    if (Fact.State == LifecycleState::Live ||
        Fact.State == LifecycleState::Released)
      return State->set<ConstructFamilyMap>(Region, Family);
    return State->remove<ConstructFamilyMap>(Region);
  }

  void reportRequirement(const LifecycleTransition &Transition,
                         ConstructOperation Operation, const Stmt *Statement,
                         ProgramStateRef State, CheckerContext &C) const {
    if (contains(Transition.Events, LifecycleEvent::AlreadyReleased))
      report(Operation == ConstructOperation::Destroy
                 ? "owned construct is already destroyed"
                 : "operation accesses a destroyed owned construct",
             Statement, State, C);
    else if (contains(Transition.Events, LifecycleEvent::FamilyMismatch))
      report("owned construct ownership class does not match operation",
             Statement, State, C);
    else if (contains(Transition.Events, LifecycleEvent::MissingLive) ||
             contains(Transition.Events, LifecycleEvent::StateUnproven))
      report("owned construct is not proven initialized", Statement, State,
             C);
  }

  void requireLive(const CallEvent &Call, const ConstructCall &Protocol,
                   CheckerContext &C) const {
    unsigned Argument = Protocol.Argument;
    const MemRegion *Region = argumentRegion(Call, Argument);
    if (!Region ||
        C.getState()->isNull(Call.getArgSVal(Argument)).isConstrainedTrue())
      return;
    const Stmt *Statement = Call.getOriginExpr();
    if (!Statement)
      return;
    LifecycleTransition Transition = applyLifecycleOperation(
        constructFact(C.getState(), Region, Protocol, true),
        familyId(Protocol.Family), LifecycleOperation::RequireLive);
    reportRequirement(Transition, Protocol.Operation, Statement, C.getState(),
                      C);
  }

public:
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    for (const ConstructCall &Protocol : protocolsFor(Call)) {
      if (Protocol.Operation == ConstructOperation::Use) {
        requireLive(Call, Protocol, C);
        continue;
      }
      const MemRegion *Region = argumentRegion(Call, Protocol.Argument);
      if (!Region)
        continue;
      const Stmt *Statement = Call.getOriginExpr();
      if (!Statement)
        continue;

      if (Protocol.Operation == ConstructOperation::Construct) {
        // Deliberately NOT extended with isOpaqueBorrow here: unlike the
        // "not proven initialized" check below, "no information" must
        // stay "no information" for a double-construct proof specifically
        // -- trusting an opaque borrow as evidence of "definitely already
        // live" would risk hiding a real double pthread_mutex_init() on a
        // borrowed pointer, which is exactly backwards. The acquisition
        // input therefore treats an opaque borrow as Absent, while the
        // RequireLive/Release inputs below may trust it as an externally
        // established live lifetime.
        LifecycleTransition Transition = applyLifecycleOperation(
            constructFact(C.getState(), Region, Protocol, false),
            familyId(Protocol.Family), LifecycleOperation::Acquire);
        if (contains(Transition.Events, LifecycleEvent::AlreadyLive))
          report("owned construct is already initialized", Statement,
                 C.getState(), C);
        continue;
      }
      requireLive(Call, Protocol, C);
    }
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    llvm::SmallVector<ConstructCall, 4> Protocols = protocolsFor(Call);
    if (Protocols.empty())
      return;
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function)
      return;
    if (Function->getReturnType()->isVoidType()) {
      ProgramStateRef State = C.getState();
      for (const ConstructCall &Protocol : Protocols) {
        if (Protocol.Operation == ConstructOperation::Use)
          continue;
        const MemRegion *Region = argumentRegion(Call, Protocol.Argument);
        if (!Region)
          continue;
        LifecycleOperation Operation =
            Protocol.Operation == ConstructOperation::Construct
                ? LifecycleOperation::Acquire
                : LifecycleOperation::Release;
        LifecycleTransition Transition = applyLifecycleOperation(
            constructFact(State, Region, Protocol,
                          Operation == LifecycleOperation::Release),
            familyId(Protocol.Family), Operation);
        State = setConstructFact(State, Region, Transition.After,
                                 Protocol.Family);
      }
      C.addTransition(State);
      return;
    }
    SVal Return = Call.getReturnValue();
    if (Return.isUnknownOrUndef())
      return;
    std::optional<DefinedOrUnknownSVal> DefinedReturn =
        Return.getAs<DefinedOrUnknownSVal>();
    if (!DefinedReturn)
      return;
    SValBuilder &Builder = C.getSValBuilder();
    DefinedOrUnknownSVal Success =
        Builder.evalEQ(C.getState(), *DefinedReturn,
                       Builder.makeZeroVal(Function->getReturnType()));
    auto [Succeeded, Failed] = C.getState()->assume(Success);
    if (Succeeded) {
      for (const ConstructCall &Protocol : Protocols) {
        if (Protocol.Operation == ConstructOperation::Use)
          continue;
        const MemRegion *Region = argumentRegion(Call, Protocol.Argument);
        if (!Region)
          continue;
        LifecycleOperation Operation =
            Protocol.Operation == ConstructOperation::Construct
                ? LifecycleOperation::Acquire
                : LifecycleOperation::Release;
        LifecycleTransition Transition = applyLifecycleOperation(
            constructFact(Succeeded, Region, Protocol,
                          Operation == LifecycleOperation::Release),
            familyId(Protocol.Family), Operation);
        Succeeded = setConstructFact(Succeeded, Region, Transition.After,
                                     Protocol.Family);
      }
      C.addTransition(Succeeded);
    }
    if (Failed)
      C.addTransition(Failed);
  }
};

enum class CapabilityOperation : unsigned char {
  Require,
  RequireAbsent,
  Consume,
  ConsumeAny,
  Drop,
  GrantLinear,
  GrantDuplicable
};

static DefinedOrUnknownSVal protocolSucceeded(const FunctionDecl *Function,
                                              DefinedOrUnknownSVal Return,
                                              SValBuilder &Builder,
                                              ProgramStateRef State) {
  DefinedOrUnknownSVal IsZero = Builder.evalEQ(
      State, Return, Builder.makeZeroVal(Function->getReturnType()));
  if (!Function->getReturnType()->isPointerType())
    return IsZero;
  return Builder.evalBinOp(State, BO_EQ, IsZero,
                           Builder.makeTruthVal(false), Builder.getConditionType())
      .castAs<DefinedOrUnknownSVal>();
}

struct CapabilityProtocol {
  CapabilityOperation Operation;
  const IdentifierInfo *Family;
  unsigned Argument;
  llvm::SmallVector<unsigned, 2> Parameters;
};

class OwnershipContractChecker : public Checker<check::ASTDecl<FunctionDecl>> {
  static bool isHeaderPath(StringRef Path) {
    return Path.ends_with(".h") || Path.ends_with(".hh") ||
           Path.ends_with(".hpp");
  }

  static void emitContract(const FunctionDecl *Function, const Attr *Attribute,
                           StringRef Contract, StringRef Path, unsigned Line) {
    StringRef Kind;
    if (!Function->doesThisDeclarationHaveABody())
      Kind = isHeaderPath(Path) ? "header-declaration" : "source-declaration";
    else
      Kind = Attribute->isInherited() ? "definition-inherited"
                                      : "definition-explicit";
    llvm::errs() << "ownership-contract: " << Kind << '\t' << Contract << '\t'
                 << Function->getQualifiedNameAsString() << '\t' << Path << '\t'
                 << Line << '\n';
  }

  static bool isOwnershipContract(StringRef Annotation) {
    return Annotation.starts_with("withtok:") ||
           Annotation.starts_with("elements_withtok:") ||
           Annotation.starts_with("withouttok:") ||
           Annotation.starts_with("consume:") ||
           Annotation.starts_with("consume_any:") ||
           Annotation.starts_with("drop:") ||
           Annotation.starts_with("grant:") ||
           Annotation.starts_with("consume_if_nonnull_return:") ||
           Annotation.starts_with("construct:") ||
           Annotation.starts_with("destroy:") ||
           Annotation.starts_with("handle:") ||
           Annotation.starts_with("withhandle:") ||
           Annotation.starts_with("static_handle:");
  }

public:
  void checkASTDecl(const FunctionDecl *Function, AnalysisManager &,
                    BugReporter &) const {
    if (!Function->getIdentifier())
      return;
    const SourceManager &SM = Function->getASTContext().getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Function->getLocation());
    StringRef Path = SM.getFilename(Location);
    unsigned Line = SM.getSpellingLineNumber(Location);
    if (Function->doesThisDeclarationHaveABody())
      llvm::errs() << "ownership-contract: definition\t-\t"
                   << Function->getQualifiedNameAsString() << '\t' << Path
                   << '\t' << Line << '\n';
    for (const AnnotateAttr *Attribute :
         Function->specific_attrs<AnnotateAttr>()) {
      StringRef Contract = Attribute->getAnnotation();
      if (isOwnershipContract(Contract))
        emitContract(Function, Attribute, Contract, Path, Line);
    }
    unsigned Argument = 1;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      for (const AnnotateAttr *Attribute :
           Parameter->specific_attrs<AnnotateAttr>()) {
        StringRef Annotation = Attribute->getAnnotation();
        if (!isOwnershipContract(Annotation))
          continue;
        std::string Contract =
            ("parameter:" + llvm::Twine(Argument) + ":" + Annotation).str();
        emitContract(Function, Attribute, Contract, Path, Line);
      }
      ++Argument;
    }
  }
};

static SymbolRef aggregateBaseSymbol(SVal Value) {
  if (const MemRegion *Region = Value.getAsRegion())
    if (const SymbolicRegion *Base = Region->getSymbolicBase())
      return Base->getSymbol();
  return Value.getAsSymbol(true);
}

static SymbolRef aggregateBaseForExpr(const Expr *Expression,
                                      CheckerContext &C) {
  const Expr *Core = Expression ? Expression->IgnoreParenImpCasts() : nullptr;
  if (const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Core))
    if (const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl()))
      return aggregateBaseSymbol(C.getState()->getSVal(
          C.getState()->getLValue(Variable, C.getLocationContext())));
  return Expression ? aggregateBaseSymbol(C.getSVal(Expression)) : nullptr;
}

static bool aggregateIndexProven(const ArraySubscriptExpr *Access,
                                 SymbolRef Upper, ProgramStateRef State,
                                 CheckerContext &C) {
  SVal Index = C.getSVal(Access->getIdx());
  std::optional<DefinedOrUnknownSVal> DefinedIndex =
      Index.getAs<DefinedOrUnknownSVal>();
  if (!DefinedIndex || !Upper)
    return false;
  QualType IndexType = Index.getType(C.getASTContext());
  QualType UpperType = Upper->getType();
  // hasSameType()'s exact canonical-type identity is the wrong tool here:
  // when Index is a concrete integer (e.g. a loop's own "i = 0"
  // initializer, taken on the first-iteration path before i turns
  // symbolic), SVal::getType() cannot recover the index variable's real
  // declared type from a bare width+signedness APSInt -- it reconstructs
  // a representative type for that width/signedness pair instead, which
  // on an LP64 target is "long"/"unsigned long" even when the source
  // variable was declared some OTHER same-width type such as "long
  // long" or its size_t alias (this project's own size_t is `unsigned
  // _Addr`, and _Addr is `long long` on aarch64/x86_64 -- see
  // arch/*/bits/alltypes.h.gen -- a real, distinct canonical type from
  // "unsigned long" despite equal width and signedness). A same-width,
  // same-signedness comparison is exactly what BO_LT below actually
  // needs for a sound bounds check -- the SValBuilder call for two
  // NonLoc integers of matching width/signedness never has to reconcile
  // their nominal C types -- and it is the identical bit-width/signedness
  // representation OwnershipZ3Proof::cType() (above) already uses in
  // place of exact QualType equality for the same reason.
  if (IndexType.isNull() || UpperType.isNull() ||
      !IndexType->isIntegralOrEnumerationType() ||
      !UpperType->isIntegralOrEnumerationType() ||
      C.getASTContext().getIntWidth(IndexType) !=
          C.getASTContext().getIntWidth(UpperType) ||
      IndexType->isUnsignedIntegerOrEnumerationType() !=
          UpperType->isUnsignedIntegerOrEnumerationType())
    return false;
  SValBuilder &Builder = C.getSValBuilder();
  SVal Below = Builder.evalBinOp(State, BO_LT, *DefinedIndex,
                                 nonloc::SymbolVal(Upper),
                                 Builder.getConditionType());
  std::optional<DefinedOrUnknownSVal> BelowCondition =
      Below.getAs<DefinedOrUnknownSVal>();
  if (!BelowCondition || State->assume(*BelowCondition, false))
    return false;
  if (IndexType->isSignedIntegerOrEnumerationType()) {
    SVal NonNegative = Builder.evalBinOp(
        State, BO_GE, *DefinedIndex, Builder.makeIntVal(0, IndexType),
        Builder.getConditionType());
    std::optional<DefinedOrUnknownSVal> Condition =
        NonNegative.getAs<DefinedOrUnknownSVal>();
    if (!Condition || State->assume(*Condition, false))
      return false;
  }
  return true;
}

class AggregateElementTokenChecker
    : public Checker<check::BeginFunction,
                     check::PostStmt<ImplicitCastExpr>, check::Bind,
                     check::PostCall> {

  static ProgramStateRef havocAggregate(ProgramStateRef State,
                                        SymbolRef Aggregate) {
    llvm::SmallVector<AggregateElementKey, 4> Relations;
    for (const auto &Relation : State->get<AggregateElementExtent>())
      if (Relation.first.first == Aggregate)
        Relations.push_back(Relation.first);
    llvm::SmallVector<SymbolCapabilityKey, 8> Elements;
    for (const auto &Element : State->get<ElementTokenOrigin>())
      if (Element.second == Aggregate)
        Elements.push_back(Element.first);
    for (const SymbolCapabilityKey &Element : Elements) {
      State = State->remove<SymbolCapabilityMap>(Element);
      State = State->remove<ElementTokenOrigin>(Element);
    }
    for (const AggregateElementKey &Relation : Relations)
      State = State->remove<AggregateElementExtent>(Relation);
    return State;
  }

  static ProgramStateRef refineExcludedSentinel(
      ProgramStateRef State, SVal Value, const IdentifierInfo *Family,
      CheckerContext &C) {
    std::optional<int64_t> Sentinel = excludedSentinel(
        findTokenSort(C.getASTContext(), Family->getName()));
    if (!Sentinel)
      return State;
    std::optional<DefinedOrUnknownSVal> Defined =
        Value.getAs<DefinedOrUnknownSVal>();
    if (!Defined)
      return nullptr;
    QualType Type = Value.getType(C.getASTContext());
    if (!Type->isPointerType() && !Type->isIntegralOrEnumerationType())
      return nullptr;
    /* This caller only wants the "definitely not the sentinel" half of the
     * split -- the half where the value already carries real ownership --
     * and drops the sentinel-equal half entirely. */
    return splitOnExcludedSentinel(State, *Defined, Type, *Sentinel,
                                   C.getSValBuilder())
        .NonSentinel;
  }

  static bool parameterIsReadOnly(const FunctionDecl *Function,
                                  unsigned Argument) {
    if (!Function || Argument >= Function->getNumParams())
      return false;
    QualType Type = Function->getParamDecl(Argument)->getType();
    bool SawPointer = false;
    while (Type->isPointerType()) {
      SawPointer = true;
      Type = Type->getPointeeType();
      if (!Type.isConstQualified())
        return false;
    }
    return SawPointer;
  }

public:
  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function)
      return;
    ProgramStateRef State = C.getState();
    const LocationContext *LC = C.getLocationContext();
    bool Changed = false;
    for (const ParmVarDecl *Parameter : Function->parameters())
      for (const AnnotateAttr *Attr : Parameter->specific_attrs<AnnotateAttr>()) {
        StringRef Text = Attr->getAnnotation();
        if (!Text.consume_front("elements_withtok:"))
          continue;
        auto [FamilyName, ExtentName] = Text.split(':');
        if (FamilyName.empty() || ExtentName.empty() || ExtentName.contains(':'))
          continue;
        std::optional<CapabilityKind> Kind =
            dialectTokenKind(C.getASTContext(), FamilyName);
        if (!Kind || *Kind != CapabilityKind::Duplicable)
          continue;
        const ParmVarDecl *Extent = nullptr;
        for (const ParmVarDecl *Candidate : Function->parameters())
          if (Candidate->getName() == ExtentName) {
            Extent = Candidate;
            break;
          }
        if (!Extent)
          continue;
        SVal AggregateValue =
            State->getSVal(State->getLValue(Parameter, LC));
        SVal ExtentValue = State->getSVal(State->getLValue(Extent, LC));
        SymbolRef Aggregate = aggregateBaseSymbol(AggregateValue);
        SymbolRef Upper = ExtentValue.getAsSymbol(true);
        if (!Aggregate || !Upper)
          continue;
        const IdentifierInfo *Family =
            &C.getASTContext().Idents.get(FamilyName);
        State = State->set<AggregateElementExtent>({Aggregate, Family}, Upper);
        Changed = true;
      }
    if (Changed)
      C.addTransition(State);
  }

  void checkPostStmt(const ImplicitCastExpr *Cast,
                     CheckerContext &C) const {
    if (Cast->getCastKind() != CK_LValueToRValue)
      return;
    const auto *Access = dyn_cast<ArraySubscriptExpr>(
        Cast->getSubExpr()->IgnoreParenImpCasts());
    if (!Access)
      return;
    SymbolRef Aggregate = aggregateBaseForExpr(Access->getBase(), C);
    if (!Aggregate)
      return;
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (const auto &Relation : State->get<AggregateElementExtent>()) {
      if (Relation.first.first != Aggregate ||
          !aggregateIndexProven(Access, Relation.second, State, C))
        continue;
      const IdentifierInfo *Family = Relation.first.second;
      ElementTokenRelation AlgebraRelation{
          TokenState::Duplicable, RelationSupport::Exact, false,
          excludedSentinel(findTokenSort(C.getASTContext(), Family->getName()))
              .has_value()};
      auto Lookup = lookupElementToken(
          AlgebraRelation, true, ProofStatus::Proved, ProofStatus::Unproved);
      if (!Lookup.proved())
        continue;
      SVal Element = C.getSVal(Cast);
      ProgramStateRef Refined =
          Lookup.ApplyValueRefinement
              ? refineExcludedSentinel(State, Element, Family, C)
              : State;
      if (!Refined)
        continue;
      State = setUnderlyingToken(Refined, Element, Family,
                                 CapabilityKind::Duplicable);
      if (SymbolRef ElementSymbol = Element.getAsSymbol(true))
        State = State->set<ElementTokenOrigin>({ElementSymbol, Family},
                                               Aggregate);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkBind(SVal Location, SVal Value, const Stmt *, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    SymbolRef Written = aggregateBaseSymbol(Location);
    SymbolRef Escaped = aggregateBaseSymbol(Value);
    llvm::SmallVector<SymbolRef, 4> Havoc;
    if (Written)
      for (const auto &Relation : State->get<AggregateElementExtent>())
        if (Relation.first.first == Written)
          Havoc.push_back(Written);
    if (Written)
      for (const auto &Element : State->get<ElementTokenOrigin>())
        if (Element.first.first == Written)
          Havoc.push_back(Element.second);
    const MemRegion *Destination = Location.getAsRegion();
    if (Escaped && Destination && !isa<VarRegion>(Destination))
      for (const auto &Relation : State->get<AggregateElementExtent>())
        if (Relation.first.first == Escaped)
          Havoc.push_back(Escaped);
    for (SymbolRef Aggregate : Havoc)
      State = havocAggregate(State, Aggregate);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    llvm::SmallVector<SymbolRef, 4> Havoc;
    for (unsigned Argument = 0; Argument < Call.getNumArgs(); ++Argument) {
      if (parameterIsReadOnly(Function, Argument))
        continue;
      SymbolRef Passed = aggregateBaseSymbol(Call.getArgSVal(Argument));
      if (!Passed)
        continue;
      for (const auto &Relation : State->get<AggregateElementExtent>())
        if (Relation.first.first == Passed)
          Havoc.push_back(Passed);
      for (const auto &Element : State->get<ElementTokenOrigin>())
        if (Element.first.first == Passed)
          Havoc.push_back(Element.second);
    }
    for (SymbolRef Aggregate : Havoc)
      State = havocAggregate(State, Aggregate);
    if (State != C.getState())
      C.addTransition(State);
  }
};

class CapabilityTokenChecker
    : public Checker<check::BeginFunction, check::PreCall, check::PostCall,
                     check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

  static bool parameterAnnotation(
      const FunctionDecl *Function, const AnnotateAttr *Attr, StringRef Prefix,
      const IdentifierInfo *&Family,
      llvm::SmallVectorImpl<unsigned> &Parameters) {
    StringRef Text = Attr->getAnnotation();
    if (!Text.consume_front(Prefix) || Text.empty() || Text.contains(':'))
      return false;
    StringRef FamilyName = Text;
    StringRef Arguments;
    size_t Open = Text.find('(');
    if (Open != StringRef::npos) {
      if (!Text.ends_with(")"))
        return false;
      FamilyName = Text.take_front(Open).trim();
      Arguments = Text.slice(Open + 1, Text.size() - 1);
    }
    if (FamilyName.empty())
      return false;
    Family = &Function->getASTContext().Idents.get(FamilyName);
    while (!Arguments.empty()) {
      auto [Name, Rest] = Arguments.split(',');
      Name = Name.trim();
      if (Name.empty())
        return false;
      bool Found = false;
      for (unsigned Index = 0; Index < Function->getNumParams(); ++Index)
        if (Function->getParamDecl(Index)->getName() == Name) {
          Parameters.push_back(Index);
          Found = true;
          break;
        }
      if (!Found)
        return false;
      Arguments = Rest;
    }
    return true;
  }

  static const IdentifierInfo *instantiatedFamily(
      const CapabilityProtocol &Protocol, ArrayRef<SVal> Values,
      ASTContext &Context) {
    if (Values.empty())
      return Protocol.Family;
    std::string Name = Protocol.Family->getName().str();
    Name.push_back('(');
    for (unsigned Index = 0; Index < Values.size(); ++Index) {
      if (Index)
        Name.push_back(',');
      const SVal &Value = Values[Index];
      Name += std::to_string(static_cast<unsigned>(Value.getKind()));
      Name.push_back(':');
      if (const MemRegion *Region = Value.getAsRegion())
        Name += std::to_string(reinterpret_cast<uintptr_t>(Region));
      else if (SymbolRef Symbol = Value.getAsSymbol(true))
        Name += std::to_string(reinterpret_cast<uintptr_t>(Symbol));
      else {
        llvm::FoldingSetNodeID Identity;
        Value.Profile(Identity);
        Name += std::to_string(Identity.ComputeHash());
      }
    }
    Name.push_back(')');
    return &Context.Idents.get(Name);
  }

  static const IdentifierInfo *callFamily(const CapabilityProtocol &Protocol,
                                          const CallEvent &Call,
                                          CheckerContext &C) {
    llvm::SmallVector<SVal, 2> Values;
    for (unsigned Parameter : Protocol.Parameters) {
      if (Parameter >= Call.getNumArgs())
        return Protocol.Family;
      Values.push_back(Call.getArgSVal(Parameter));
    }
    return instantiatedFamily(Protocol, Values, C.getASTContext());
  }

  static const IdentifierInfo *functionFamily(
      const CapabilityProtocol &Protocol, const FunctionDecl *Function,
      ProgramStateRef State, const LocationContext *LC) {
    llvm::SmallVector<SVal, 2> Values;
    for (unsigned Parameter : Protocol.Parameters) {
      if (Parameter >= Function->getNumParams())
        return Protocol.Family;
      const ParmVarDecl *Declaration = Function->getParamDecl(Parameter);
      Values.push_back(State->getSVal(State->getLValue(Declaration, LC)));
    }
    return instantiatedFamily(Protocol, Values, Function->getASTContext());
  }

  static const ValueDecl *declarationFor(const Expr *Expression) {
    if (!Expression)
      return nullptr;
    Expression = Expression->IgnoreParenImpCasts();
    if (const auto *Reference = dyn_cast<DeclRefExpr>(Expression))
      return dyn_cast<ValueDecl>(Reference->getDecl());
    if (const auto *Member = dyn_cast<MemberExpr>(Expression))
      return Member->getMemberDecl();
    if (const auto *Unary = dyn_cast<UnaryOperator>(Expression))
      if (Unary->getOpcode() == UO_AddrOf)
        return declarationFor(Unary->getSubExpr());
    return nullptr;
  }

  static std::optional<CapabilityKind>
  declaredTokenFor(const Expr *Expression, const IdentifierInfo *Family) {
    const ValueDecl *Declaration = declarationFor(Expression);
    if (!Declaration)
      return std::nullopt;
    for (const AnnotateAttr *Attr :
         Declaration->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attr->getAnnotation();
      if (Text.consume_front("withtok:") && Text == Family->getName())
        return dialectTokenKind(Declaration->getASTContext(), Text);
    }
    return std::nullopt;
  }

  static llvm::SmallVector<CapabilityProtocol, 6>
  protocolsFor(const FunctionDecl *Function) {
    llvm::SmallVector<CapabilityProtocol, 6> Protocols;
    if (!Function)
      return Protocols;
    struct OperationAnnotation {
      llvm::StringLiteral Prefix;
      CapabilityOperation Operation;
    };
    static constexpr OperationAnnotation Operations[] = {
        {"withtok:", CapabilityOperation::Require},
        {"withouttok:", CapabilityOperation::RequireAbsent},
        {"consume:", CapabilityOperation::Consume},
        {"consume_any:", CapabilityOperation::ConsumeAny},
        {"drop:", CapabilityOperation::Drop},
        {"grant:", CapabilityOperation::GrantLinear}};
    unsigned Argument = 0;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      for (const AnnotateAttr *Attr : Parameter->specific_attrs<AnnotateAttr>())
        for (const OperationAnnotation &Candidate : Operations)
        {
            const IdentifierInfo *Family = nullptr;
            llvm::SmallVector<unsigned, 2> Parameters;
            if (parameterAnnotation(Function, Attr, Candidate.Prefix, Family,
                                    Parameters)) {
              const TypedefNameDecl *Token =
                  findTokenSort(Function->getASTContext(), Family->getName());
              if (hasQualifier(Token, "qual:extent_at_least") ||
                  hasQualifier(Token, "qual:disjoint_extent"))
                continue;
              if ((Candidate.Operation == CapabilityOperation::Require ||
                   Candidate.Operation == CapabilityOperation::Consume) &&
                  hasQualifier(Token, "qual:dynamic_storage"))
                continue;
              CapabilityOperation Operation = Candidate.Operation;
              if (Candidate.Prefix == "grant:") {
                std::optional<CapabilityKind> Kind = dialectTokenKind(
                    Function->getASTContext(), Family->getName());
                if (Kind && *Kind == CapabilityKind::Duplicable)
                  Operation = CapabilityOperation::GrantDuplicable;
              }
              Protocols.push_back(
                  {Operation, Family, Argument, std::move(Parameters)});
            }
          }
      ++Argument;
    }
    return Protocols;
  }

  static bool hasInputProtocol(ArrayRef<CapabilityProtocol> Protocols,
                               const CapabilityProtocol &Output) {
    return llvm::any_of(Protocols, [&](const CapabilityProtocol &Input) {
      return Input.Argument == Output.Argument &&
             Input.Family == Output.Family &&
             Input.Parameters == Output.Parameters &&
             (Input.Operation == CapabilityOperation::Require ||
              Input.Operation == CapabilityOperation::Consume ||
              Input.Operation == CapabilityOperation::ConsumeAny ||
              Input.Operation == CapabilityOperation::Drop);
    });
  }

  static bool acceptsStaticInitialization(const FunctionDecl *Function,
                                          unsigned Argument) {
    if (!Function)
      return false;
    if (Argument >= Function->getNumParams())
      return false;
    const ParmVarDecl *Parameter = Function->getParamDecl(Argument);
    for (const AnnotateAttr *Attr : Parameter->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attr->getAnnotation();
      if (Text.consume_front("static_handle:") && !Text.empty() &&
          !Text.contains(':'))
        return true;
    }
    return false;
  }

  static bool isZeroInitializer(const Expr *Initializer) {
    Initializer = Initializer->IgnoreParenImpCasts();
    if (isa<ImplicitValueInitExpr>(Initializer))
      return true;
    if (const auto *Integer = dyn_cast<IntegerLiteral>(Initializer))
      return Integer->getValue().isZero();
    if (const auto *List = dyn_cast<InitListExpr>(Initializer)) {
      for (const Expr *Element : List->inits())
        if (!isZeroInitializer(Element))
          return false;
      const Expr *Filler = List->getArrayFiller();
      return !Filler || isZeroInitializer(Filler);
    }
    if (const auto *Cast = dyn_cast<CastExpr>(Initializer))
      return isZeroInitializer(Cast->getSubExpr());
    return false;
  }

  static bool hasStaticInitialToken(const FunctionDecl *Function,
                                    const CallEvent &Call, unsigned Argument,
                                    const CapabilityPresence &Existing) {
    if (Existing.Known || !acceptsStaticInitialization(Function, Argument) ||
        Argument >= Call.getNumArgs())
      return false;
    const auto *Variable =
        dyn_cast_or_null<VarRegion>(Call.getArgSVal(Argument).getAsRegion());
    if (!Variable)
      return false;
    const VarDecl *Declaration = Variable->getDecl();
    if (!Declaration->hasInit())
      return Declaration->hasGlobalStorage();
    return isZeroInitializer(Declaration->getInit());
  }

  void report(StringRef Reason, const Stmt *Statement, ProgramStateRef State,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Invalid ownership capability",
                                     categories::MemoryError);
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, diagnosticMessage(Reason, Statement, C), Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  bool preconditionsHold(ProgramStateRef State, const CallEvent &Call,
                         ArrayRef<CapabilityProtocol> Protocols,
                         CheckerContext &C, bool EmitDiagnostics) const {
    const Stmt *Statement = Call.getOriginExpr();
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    bool Valid = true;
    for (const CapabilityProtocol &Protocol : Protocols) {
      if (Protocol.Argument >= Call.getNumArgs())
        continue;
      SVal Value = Call.getArgSVal(Protocol.Argument);
      const IdentifierInfo *StateFamily = callFamily(Protocol, Call, C);
      CapabilityPresence Existing = capabilityFor(
          State, carrierRegion(Call.getArgExpr(Protocol.Argument), C), Value,
          StateFamily);
      if (Protocol.Parameters.empty() && !Existing.Known && !Existing.Kind)
        Existing.Kind =
            declaredTokenFor(Call.getArgExpr(Protocol.Argument),
                             Protocol.Family);
      if (!Existing.Kind && expressionProvidesStringLiteralToken(
                                Call.getArgExpr(Protocol.Argument),
                                Protocol.Family, C.getASTContext()))
        Existing.Kind = CapabilityKind::Duplicable;
      if (!Existing.Kind &&
          hasStaticInitialToken(Function, Call, Protocol.Argument, Existing))
        Existing.Kind = CapabilityKind::Linear;
      if (Protocol.Operation == CapabilityOperation::ConsumeAny)
        continue;
      if ((Protocol.Operation == CapabilityOperation::Require ||
           Protocol.Operation == CapabilityOperation::Consume) &&
          !Existing.Kind) {
        if (EmitDiagnostics && Statement)
          report("required ownership capability token is not held", Statement,
                 State, C);
        Valid = false;
      } else if (Protocol.Operation == CapabilityOperation::RequireAbsent &&
                 Existing.Kind) {
        if (EmitDiagnostics && Statement)
          report(
              "operation is blocked while ownership capability token is held",
              Statement, State, C);
        Valid = false;
      } else if (Protocol.Operation == CapabilityOperation::GrantLinear &&
                 Existing.Kind) {
        if (EmitDiagnostics && Statement)
          report("linear ownership capability token would be duplicated",
                 Statement, State, C);
        Valid = false;
      } else if (Protocol.Operation == CapabilityOperation::GrantDuplicable &&
                 Existing.Kind &&
                 *Existing.Kind != CapabilityKind::Duplicable) {
        if (EmitDiagnostics && Statement)
          report("ownership capability token duplication class does not match",
                 Statement, State, C);
        Valid = false;
      }
    }
    llvm::SmallVector<unsigned, 4> CheckedArguments;
    for (const CapabilityProtocol &Alternative : Protocols) {
      if (Alternative.Operation != CapabilityOperation::ConsumeAny ||
          llvm::is_contained(CheckedArguments, Alternative.Argument))
        continue;
      CheckedArguments.push_back(Alternative.Argument);
      bool Held = false;
      for (const CapabilityProtocol &Candidate : Protocols)
        if (Candidate.Operation == CapabilityOperation::ConsumeAny &&
            Candidate.Argument == Alternative.Argument) {
          CapabilityPresence Existing = capabilityFor(
              State, carrierRegion(Call.getArgExpr(Candidate.Argument), C),
              Call.getArgSVal(Candidate.Argument),
              callFamily(Candidate, Call, C));
          if (Candidate.Parameters.empty() && !Existing.Known && !Existing.Kind)
            Existing.Kind =
                declaredTokenFor(Call.getArgExpr(Candidate.Argument),
                                 Candidate.Family);
          if (!Existing.Kind && expressionProvidesStringLiteralToken(
                                    Call.getArgExpr(Candidate.Argument),
                                    Candidate.Family, C.getASTContext()))
            Existing.Kind = CapabilityKind::Duplicable;
          if (!Existing.Kind &&
              hasStaticInitialToken(Function, Call, Candidate.Argument,
                                    Existing))
            Existing.Kind = CapabilityKind::Linear;
          if (!Existing.Kind)
            continue;
          Held = true;
          break;
        }
      if (!Held) {
        if (EmitDiagnostics && Statement)
          report("none of the required ownership capability tokens is held",
                 Statement, State, C);
        Valid = false;
      }
    }
    return Valid;
  }

  static ProgramStateRef transition(ProgramStateRef State,
                                    const CallEvent &Call,
                                    ArrayRef<CapabilityProtocol> Protocols,
                                    CheckerContext &C) {
    llvm::SmallVector<unsigned, 4> ConsumedArguments;
    for (const CapabilityProtocol &Alternative : Protocols) {
      if (Alternative.Operation != CapabilityOperation::ConsumeAny ||
          llvm::is_contained(ConsumedArguments, Alternative.Argument))
        continue;
      ConsumedArguments.push_back(Alternative.Argument);
      for (const CapabilityProtocol &Candidate : Protocols)
        if (Candidate.Operation == CapabilityOperation::ConsumeAny &&
            Candidate.Argument == Alternative.Argument) {
          SVal Value = Call.getArgSVal(Candidate.Argument);
          const MemRegion *Carrier =
              carrierRegion(Call.getArgExpr(Candidate.Argument), C);
          const IdentifierInfo *StateFamily = callFamily(Candidate, Call, C);
          if (capabilityFor(State, Carrier, Value, StateFamily).Kind) {
            State =
                removeOperationToken(State, Carrier, Value, StateFamily);
            break;
          }
        }
    }
    for (const CapabilityProtocol &Protocol : Protocols) {
      if (Protocol.Argument >= Call.getNumArgs())
        continue;
      SVal Value = Call.getArgSVal(Protocol.Argument);
      const MemRegion *Carrier =
          carrierRegion(Call.getArgExpr(Protocol.Argument), C);
      const IdentifierInfo *StateFamily = callFamily(Protocol, Call, C);
      switch (Protocol.Operation) {
      case CapabilityOperation::Require:
      case CapabilityOperation::RequireAbsent:
        break;
      case CapabilityOperation::Consume:
        State = removeOperationToken(State, Carrier, Value, StateFamily);
        break;
      case CapabilityOperation::ConsumeAny:
        break;
      case CapabilityOperation::Drop:
        State = removeOperationToken(State, Carrier, Value, StateFamily);
        break;
      case CapabilityOperation::GrantLinear:
        State = setOperationToken(State, Carrier, Value, StateFamily,
                                  CapabilityKind::Linear);
        break;
      case CapabilityOperation::GrantDuplicable:
        State = setOperationToken(State, Carrier, Value, StateFamily,
                                  CapabilityKind::Duplicable);
        break;
      }
    }
    return State;
  }

public:
  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function)
      return;
    ProgramStateRef State = C.getState();
    const LocationContext *LC = C.getLocationContext();
    bool Changed = false;
    llvm::SmallVector<CapabilityProtocol, 6> Protocols = protocolsFor(Function);
    for (const CapabilityProtocol &Protocol : Protocols) {
      const ParmVarDecl *Parameter = Function->getParamDecl(Protocol.Argument);
      SVal Value = State->getSVal(State->getLValue(Parameter, LC));
      const MemRegion *Carrier = State->getLValue(Parameter, LC).getAsRegion();
      const IdentifierInfo *StateFamily =
          functionFamily(Protocol, Function, State, LC);
      if (Protocol.Operation == CapabilityOperation::Require ||
          Protocol.Operation == CapabilityOperation::Consume ||
          Protocol.Operation == CapabilityOperation::Drop) {
        CapabilityKind Kind = dialectTokenKind(
                                  Function->getASTContext(),
                                  Protocol.Family->getName())
                                  .value_or(CapabilityKind::Linear);
        State = setOperationToken(State, Carrier, Value, StateFamily,
                                  Kind);
        Changed = true;
      } else if ((Protocol.Operation == CapabilityOperation::GrantLinear ||
                  Protocol.Operation == CapabilityOperation::GrantDuplicable) &&
                 !hasInputProtocol(Protocols, Protocol)) {
        State = removeOperationToken(State, Carrier, Value, StateFamily);
        Changed = true;
      }
    }
    llvm::SmallVector<ProgramStateRef, 4> Alternatives{State};
    llvm::SmallVector<unsigned, 4> ExpandedArguments;
    for (const CapabilityProtocol &Protocol : Protocols) {
      if (Protocol.Operation != CapabilityOperation::ConsumeAny ||
          llvm::is_contained(ExpandedArguments, Protocol.Argument))
        continue;
      ExpandedArguments.push_back(Protocol.Argument);
      const ParmVarDecl *Parameter =
          Function->getParamDecl(Protocol.Argument);
      SVal Value = State->getSVal(State->getLValue(Parameter, LC));
      const MemRegion *Carrier =
          State->getLValue(Parameter, LC).getAsRegion();
      llvm::SmallVector<ProgramStateRef, 4> Expanded;
      for (ProgramStateRef Alternative : Alternatives)
        for (const CapabilityProtocol &Candidate : Protocols) {
          if (Candidate.Operation != CapabilityOperation::ConsumeAny ||
              Candidate.Argument != Protocol.Argument)
            continue;
          CapabilityKind Kind = dialectTokenKind(
                                    Function->getASTContext(),
                                    Candidate.Family->getName())
                                    .value_or(CapabilityKind::Linear);
          Expanded.push_back(setOperationToken(
              Alternative, Carrier, Value,
              functionFamily(Candidate, Function, Alternative, LC), Kind));
        }
      Alternatives = std::move(Expanded);
      Changed = true;
    }
    if (Changed)
      for (ProgramStateRef Alternative : Alternatives)
        C.addTransition(Alternative);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    llvm::SmallVector<CapabilityProtocol, 6> Protocols = protocolsFor(Function);
    if (!Protocols.empty())
      preconditionsHold(C.getState(), Call, Protocols, C, true);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    llvm::SmallVector<CapabilityProtocol, 6> Protocols = protocolsFor(Function);
    if (Protocols.empty() ||
        !preconditionsHold(C.getState(), Call, Protocols, C, false))
      return;

    ProgramStateRef State = C.getState();
    if (Function->getReturnType()->isVoidType()) {
      C.addTransition(transition(State, Call, Protocols, C));
      return;
    }
    std::optional<DefinedOrUnknownSVal> Return =
        Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
    if (!Return)
      return;
    DefinedOrUnknownSVal Success = protocolSucceeded(
        Function, *Return, C.getSValBuilder(), State);
    auto [Succeeded, Failed] = State->assume(Success);
    if (Succeeded)
      C.addTransition(transition(Succeeded, Call, Protocols, C));
    if (Failed)
      C.addTransition(Failed);
  }

  void checkEndFunction(const ReturnStmt *Return, CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function || !Function->doesThisDeclarationHaveABody())
      return;
    ProgramStateRef State = C.getState();
    if (!Function->getReturnType()->isVoidType()) {
      if (!Return || !Return->getRetValue())
        return;
      std::optional<DefinedOrUnknownSVal> Result =
          C.getSVal(Return->getRetValue()).getAs<DefinedOrUnknownSVal>();
      if (!Result)
        return;
      DefinedOrUnknownSVal IsSuccess = protocolSucceeded(
          Function, *Result, C.getSValBuilder(), State);
      State = State->assume(IsSuccess).first;
      if (!State)
        return;
    }
    const Stmt *Site =
        Return ? static_cast<const Stmt *>(Return) : Function->getBody();
    const LocationContext *LC = C.getLocationContext();
    for (const CapabilityProtocol &Protocol : protocolsFor(Function)) {
      if (Protocol.Argument >= Function->getNumParams())
        continue;
      const ParmVarDecl *Parameter = Function->getParamDecl(Protocol.Argument);
      Loc Location = State->getLValue(Parameter, LC);
      SVal Value = State->getSVal(Location);
      const IdentifierInfo *StateFamily =
          functionFamily(Protocol, Function, State, LC);
      CapabilityPresence Present =
          capabilityFor(State, Location.getAsRegion(), Value, StateFamily);
      bool Regranted = llvm::any_of(
          protocolsFor(Function), [&](const CapabilityProtocol &Output) {
            return Output.Argument == Protocol.Argument &&
                   Output.Family == Protocol.Family &&
                   Output.Parameters == Protocol.Parameters &&
                   (Output.Operation == CapabilityOperation::GrantLinear ||
                    Output.Operation ==
                        CapabilityOperation::GrantDuplicable);
          });
      if ((Protocol.Operation == CapabilityOperation::Consume ||
           Protocol.Operation == CapabilityOperation::ConsumeAny ||
           Protocol.Operation == CapabilityOperation::Drop) &&
          Present.Kind && !Regranted) {
        report("declared ownership token drop is not proven by function body",
               Site, State, C);
        return;
      }
      if (Protocol.Operation != CapabilityOperation::GrantLinear &&
          Protocol.Operation != CapabilityOperation::GrantDuplicable)
        continue;
      CapabilityKind Required =
          Protocol.Operation == CapabilityOperation::GrantLinear
              ? CapabilityKind::Linear
              : CapabilityKind::Duplicable;
      if (!Present.Kind || *Present.Kind != Required) {
        report("declared ownership token addition is not proven by function "
               "body",
               Site, State, C);
        return;
      }
    }
  }
};

enum class OwnershipTypeMember : unsigned char {
  Handle,
  LinearToken,
  DuplicableToken
};

struct OwnershipTypeEntry {
  const IdentifierInfo *Family;
  OwnershipTypeMember Member;
};

class OwnershipTypeChecker
    : public Checker<
          check::BeginFunction, check::PreStmt<DeclStmt>,
          check::PostStmt<DeclStmt>, check::PreStmt<BinaryOperator>,
          check::PostStmt<BinaryOperator>, check::PreStmt<UnaryOperator>,
          check::PreStmt<ArraySubscriptExpr>, check::PreStmt<MemberExpr>,
          check::PostStmt<ImplicitCastExpr>, check::PreStmt<ReturnStmt>,
          check::BranchCondition, check::PreCall, check::PostCall,
          check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

  static llvm::SmallVector<OwnershipTypeEntry, 4>
  bundleFor(const ValueDecl *Declaration) {
    llvm::SmallVector<OwnershipTypeEntry, 4> Bundle;
    if (!Declaration)
      return Bundle;
    struct MemberAnnotation {
      llvm::StringLiteral Prefix;
      OwnershipTypeMember Member;
    };
    static constexpr MemberAnnotation Annotations[] = {
        {"withhandle:", OwnershipTypeMember::Handle}};
    for (const AnnotateAttr *Attr :
         Declaration->specific_attrs<AnnotateAttr>()) {
      for (const MemberAnnotation &Candidate : Annotations) {
        StringRef Text = Attr->getAnnotation();
        if (!Text.consume_front(Candidate.Prefix) || Text.empty() ||
            Text.contains(':'))
          continue;
        Bundle.push_back(
            {&Declaration->getASTContext().Idents.get(Text), Candidate.Member});
      }
      StringRef Text = Attr->getAnnotation();
      if (!Text.consume_front("withtok:") || Text.empty() ||
          Text.contains(':'))
        continue;
      std::optional<CapabilityKind> Kind =
          dialectTokenKind(Declaration->getASTContext(), Text);
      if (!Kind)
        continue;
      if (hasQualifier(findTokenSort(Declaration->getASTContext(), Text),
                       "qual:dynamic_storage"))
        continue;
      Bundle.push_back(
          {&Declaration->getASTContext().Idents.get(Text),
           *Kind == CapabilityKind::Duplicable
               ? OwnershipTypeMember::DuplicableToken
               : OwnershipTypeMember::LinearToken});
    }
    return Bundle;
  }

  static const ValueDecl *declarationFor(const Expr *Expression) {
    if (!Expression)
      return nullptr;
    Expression = Expression->IgnoreParenImpCasts();
    if (const auto *Reference = dyn_cast<DeclRefExpr>(Expression))
      return dyn_cast<ValueDecl>(Reference->getDecl());
    if (const auto *Member = dyn_cast<MemberExpr>(Expression))
      return Member->getMemberDecl();
    if (const auto *Call = dyn_cast<CallExpr>(Expression))
      return Call->getDirectCallee();
    if (const auto *Unary = dyn_cast<UnaryOperator>(Expression))
      if (Unary->getOpcode() == UO_AddrOf)
        return declarationFor(Unary->getSubExpr());
    return nullptr;
  }

  static llvm::SmallVector<OwnershipTypeEntry, 4>
  bundleFor(const Expr *Expression) {
    return bundleFor(declarationFor(Expression));
  }

  struct SentinelTrait {
    const IdentifierInfo *Family;
    int64_t Value;
  };

  static llvm::SmallVector<SentinelTrait, 2>
  dialectSentinelTraits(const ValueDecl *Declaration) {
    llvm::SmallVector<SentinelTrait, 2> Traits;
    if (!Declaration)
      return Traits;
    for (const OwnershipTypeEntry &Entry : bundleFor(Declaration)) {
      if (Entry.Member == OwnershipTypeMember::Handle)
        continue;
      const TypedefNameDecl *Token =
          findTokenSort(Declaration->getASTContext(), Entry.Family->getName());
      if (std::optional<int64_t> Sentinel = excludedSentinel(Token))
        Traits.push_back({Entry.Family, *Sentinel});
    }
    return Traits;
  }

  static std::optional<int64_t> integerConstant(const Expr *Expression,
                                                ASTContext &Context) {
    if (!Expression)
      return std::nullopt;
    Expression = Expression->IgnoreParenImpCasts();
    std::optional<llvm::APSInt> Value =
        Expression->getIntegerConstantExpr(Context);
    if (!Value || !Value->isSignedIntN(64))
      return std::nullopt;
    return Value->getSExtValue();
  }

  static bool contains(ArrayRef<OwnershipTypeEntry> Bundle,
                       const OwnershipTypeEntry &Wanted) {
    return llvm::any_of(Bundle, [&](const OwnershipTypeEntry &Entry) {
      return Entry.Family == Wanted.Family && Entry.Member == Wanted.Member;
    });
  }

  void report(StringRef Reason, const Stmt *Statement, ProgramStateRef State,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Mismatched ownership type",
                                     categories::MemoryError);
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, diagnosticMessage(Reason, Statement, C), Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  void requireSameBundle(const ValueDecl *Destination, const Expr *Source,
                         const Stmt *Statement, CheckerContext &C) const {
    if (!Statement)
      return;
    if (Source->isNullPointerConstant(
            C.getASTContext(), Expr::NPC_ValueDependentIsNotNull))
      return;
    llvm::SmallVector<OwnershipTypeEntry, 4> DestinationBundle =
        bundleFor(Destination);
    llvm::SmallVector<OwnershipTypeEntry, 4> SourceBundle = bundleFor(Source);
    ProgramStateRef State = C.getState();
    const MemRegion *SourceCarrier = carrierRegion(Source, C);
    SVal SourceValue = C.getSVal(Source);
    if (SourceCarrier && State->contains<ExpiredStrictLoanSet>(SourceCarrier)) {
      report("borrow accesses a consumed owner", Statement, State, C);
      return;
    }
    for (const OwnershipTypeEntry &Entry : DestinationBundle) {
      if (Entry.Member == OwnershipTypeMember::Handle)
        continue;
      CapabilityPresence Present =
          capabilityFor(State, SourceCarrier, SourceValue, Entry.Family);
      if (!Present.Kind &&
          expressionProvidesStringLiteralToken(Source, Entry.Family,
                                               C.getASTContext()))
        Present.Kind = CapabilityKind::Duplicable;
      if (!Present.Kind) {
        if (dialectTokenExcludes(Entry.Family, Source, C.getASTContext()))
          continue;
        report(contains(SourceBundle, Entry)
                   ? "source ownership token has already moved"
                   : "source ownership type does not provide destination "
                     "token bundle",
               Statement, State, C);
        return;
      }
      CapabilityKind Required = Entry.Member == OwnershipTypeMember::LinearToken
                                    ? CapabilityKind::Linear
                                    : CapabilityKind::Duplicable;
      if (*Present.Kind != Required) {
        report("ownership token duplication class does not match", Statement,
               State, C);
        return;
      }
    }
  }

  static SVal valueForExpression(const Expr *Expression, CheckerContext &C) {
    const Expr *Core = Expression ? Expression->IgnoreParenImpCasts() : nullptr;
    if (const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Core))
      if (const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl())) {
        ProgramStateRef State = C.getState();
        return State->getSVal(
            State->getLValue(Variable, C.getLocationContext()));
      }
    return Expression ? C.getSVal(Expression) : UnknownVal();
  }

  static ProgramStateRef expireStrictLoans(
      ProgramStateRef State, const MemRegion *Owner,
      const IdentifierInfo *Family) {
    if (!Owner || !Family)
      return State;
    for (const auto &Loan : State->get<StrictLoanMap>())
      if (Loan.second == Owner && Loan.first.second == Family)
        State = State->add<ExpiredStrictLoanSet>(Loan.first.first);
    return State;
  }

  static ProgramStateRef copyStrictLoans(ProgramStateRef State,
                                         const MemRegion *Destination,
                                         const MemRegion *Source) {
    if (!Destination || !Source || Destination == Source)
      return State;
    for (const auto &Loan : State->get<StrictLoanMap>())
      if (Loan.first.first == Source)
        State = State->set<StrictLoanMap>(
            {Destination, Loan.first.second}, Loan.second);
    if (State->contains<ExpiredStrictLoanSet>(Source))
      State = State->add<ExpiredStrictLoanSet>(Destination);
    return State;
  }

  void requireDereferenceAllowed(const Expr *Pointer, const Stmt *Statement,
                                 CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    SVal Value = C.getSVal(Pointer);
    const MemRegion *Carrier = carrierRegion(Pointer, C);
    if (Carrier && State->contains<ExpiredStrictLoanSet>(Carrier)) {
      report("borrow accesses a consumed owner", Statement, State, C);
      return;
    }
    for (const OwnershipTypeEntry &Entry : bundleFor(declarationFor(Pointer))) {
      if (Entry.Member == OwnershipTypeMember::Handle)
        continue;
      const TypedefNameDecl *Token =
          findTokenSort(C.getASTContext(), Entry.Family->getName());
      if (hasQualifier(Token, "qual:blocks_dereference") &&
          capabilityFor(State, Carrier, Value, Entry.Family).Kind) {
        report("pointer operation is blocked while unchecked ownership token "
               "is held",
               Statement, State, C);
        return;
      }
    }
  }

  ProgramStateRef transferTokens(const ValueDecl *Destination,
                                 const MemRegion *DestinationCarrier,
                                 const Expr *Source, const Stmt *Statement,
                                 ProgramStateRef State,
                                 CheckerContext &C) const {
    if (!Destination || !Source || !Statement)
      return State;
    llvm::SmallVector<OwnershipTypeEntry, 4> DestinationBundle =
        bundleFor(Destination);
    llvm::SmallVector<OwnershipTypeEntry, 4> SourceBundle = bundleFor(Source);
    const MemRegion *SourceCarrier = carrierRegion(Source, C);
    SVal SourceValue = C.getSVal(Source);
    bool CheckedAssignment = DestinationCarrier &&
                             DestinationCarrier != SourceCarrier &&
                             isa<BinaryOperator>(Statement);

    State = copyStrictLoans(State, DestinationCarrier, SourceCarrier);

    for (const OwnershipTypeEntry &Entry : SourceBundle) {
      if (Entry.Member != OwnershipTypeMember::LinearToken ||
          contains(DestinationBundle, Entry) || !SourceCarrier ||
          !DestinationCarrier || SourceCarrier == DestinationCarrier)
        continue;
      const TypedefNameDecl *Token =
          findTokenSort(C.getASTContext(), Entry.Family->getName());
      if (!dialectTokenPermitsCarrierCopy(Token))
        State = State->set<StrictLoanMap>(
            {DestinationCarrier, Entry.Family}, SourceCarrier);
    }

    if (Source->isNullPointerConstant(
            C.getASTContext(), Expr::NPC_ValueDependentIsNotNull)) {
      for (const OwnershipTypeEntry &Entry : DestinationBundle)
        if (Entry.Member != OwnershipTypeMember::Handle)
          State = removeCarrierToken(State, DestinationCarrier, Entry.Family);
      return State;
    }

    for (const OwnershipTypeEntry &Entry : SourceBundle) {
      if (Entry.Member == OwnershipTypeMember::Handle ||
          contains(DestinationBundle, Entry))
        continue;
      State = removeCarrierToken(State, DestinationCarrier, Entry.Family);
    }

    for (const OwnershipTypeEntry &Entry : DestinationBundle) {
      if (Entry.Member == OwnershipTypeMember::Handle)
        continue;
      if (dialectTokenExcludes(Entry.Family, Source, C.getASTContext())) {
        State = removeCarrierToken(State, DestinationCarrier, Entry.Family);
        continue;
      }
      CapabilityPresence SourceToken =
          capabilityFor(State, SourceCarrier, SourceValue, Entry.Family);
      if (!SourceToken.Kind &&
          expressionProvidesStringLiteralToken(Source, Entry.Family,
                                               C.getASTContext()))
        SourceToken.Kind = CapabilityKind::Duplicable;
      CapabilityKind Required = Entry.Member == OwnershipTypeMember::LinearToken
                                    ? CapabilityKind::Linear
                                    : CapabilityKind::Duplicable;
      std::optional<TokenTransfer> Transfer;
      if (CheckedAssignment) {
        TokenState SourceState = tokenState(SourceToken);
        TokenState DestinationState =
            carrierTokenState(State, DestinationCarrier, Entry.Family);
        const TypedefNameDecl *Token =
            findTokenSort(C.getASTContext(), Entry.Family->getName());
        LinearLoanClass Loans = dialectTokenPermitsCarrierCopy(Token)
                                    ? LinearLoanClass::Permissive
                                    : LinearLoanClass::Strict;
        Transfer = transferToken(
            SourceState, DestinationState,
            {Loans, hasQualifier(Token, "qual:implicit_drop")});
        TokenState RequiredState =
            Required == CapabilityKind::Linear ? TokenState::Linear
                                               : TokenState::Duplicable;
        bool WrongSourceClass =
            (SourceState == TokenState::Linear ||
             SourceState == TokenState::Duplicable) &&
            SourceState != RequiredState;
        if (!Transfer->permitted() || WrongSourceClass) {
          if (ntlibc::algebra::contains(
                  Transfer->Events, TokenEvent::DestinationOccupied))
            report("ownership destination already holds a token", Statement,
                   State, C);
          if (ntlibc::algebra::contains(
                  Transfer->Events,
                  TokenEvent::DuplicationClassMismatch))
            report("ownership token duplication class does not match",
                   Statement, State, C);
          if (DestinationState == TokenState::Unknown)
            report("ownership destination token state is not proven",
                   Statement, State, C);
          State = havocOperationToken(State, SourceCarrier, SourceValue,
                                      Entry.Family);
          State = havocCarrierToken(State, DestinationCarrier, Entry.Family);
          continue;
        }
      }
      if (!SourceToken.Kind)
        continue;
      if (*SourceToken.Kind != Required) {
        continue;
      }
      State =
          setCarrierToken(State, DestinationCarrier, Entry.Family, Required);
      if (Required == CapabilityKind::Linear && SourceCarrier &&
          SourceCarrier != DestinationCarrier) {
        if (CheckedAssignment &&
            Transfer->Effects == TokenEffect::InvalidateStrictLoans)
          State = expireStrictLoans(State, SourceCarrier, Entry.Family);
        else if (!CheckedAssignment) {
          const TypedefNameDecl *Token =
              findTokenSort(C.getASTContext(), Entry.Family->getName());
          if (!dialectTokenPermitsCarrierCopy(Token))
            State = expireStrictLoans(State, SourceCarrier, Entry.Family);
        }
        State = removeCarrierToken(State, SourceCarrier, Entry.Family);
      }
    }
    return State;
  }

public:
  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function)
      return;
    ProgramStateRef State = C.getState();
    const LocationContext *LC = C.getLocationContext();
    bool Changed = false;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      Loc ParameterLocation = State->getLValue(Parameter, LC);
      SVal Value = State->getSVal(ParameterLocation);
      const MemRegion *Carrier = ParameterLocation.getAsRegion();
      for (const OwnershipTypeEntry &Entry : bundleFor(Parameter)) {
        if (Entry.Member == OwnershipTypeMember::Handle)
          continue;
        CapabilityKind Kind = Entry.Member == OwnershipTypeMember::LinearToken
                                  ? CapabilityKind::Linear
                                  : CapabilityKind::Duplicable;
        State = setCarrierToken(State, Carrier, Entry.Family, Kind);
        State = setUnderlyingToken(State, Value, Entry.Family, Kind);
        Changed = true;
      }
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPreStmt(const DeclStmt *Statement, CheckerContext &C) const {
    for (const Decl *Declaration : Statement->decls()) {
      const auto *Variable = dyn_cast<VarDecl>(Declaration);
      if (Variable && Variable->hasInit())
        requireSameBundle(Variable, Variable->getInit(), Statement, C);
    }
  }

  void checkPostStmt(const DeclStmt *Statement, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (const Decl *Declaration : Statement->decls()) {
      const auto *Variable = dyn_cast<VarDecl>(Declaration);
      if (!Variable || !Variable->hasInit())
        continue;
      const MemRegion *DestinationCarrier =
          State->getLValue(Variable, C.getLocationContext()).getAsRegion();
      State = transferTokens(Variable, DestinationCarrier, Variable->getInit(),
                             Statement, State, C);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPreStmt(const BinaryOperator *Statement, CheckerContext &C) const {
    if (!Statement->isAssignmentOp())
      return;
    requireSameBundle(declarationFor(Statement->getLHS()), Statement->getRHS(),
                      Statement, C);
  }

  void consumeEqualityToken(const BinaryOperator *Statement,
                            CheckerContext &C) const {
    if (Statement->getOpcode() != BO_EQ)
      return;
    const Expr *ValueExpression = Statement->getLHS();
    std::optional<int64_t> Sentinel =
        integerConstant(Statement->getRHS(), C.getASTContext());
    if (!Sentinel) {
      ValueExpression = Statement->getRHS();
      Sentinel = integerConstant(Statement->getLHS(), C.getASTContext());
    }
    if (!Sentinel)
      return;
    ProgramStateRef State = C.getState();
    SVal Value = C.getSVal(ValueExpression);
    const MemRegion *Carrier = carrierRegion(ValueExpression, C);
    bool Changed = false;
    llvm::SmallVector<SentinelTrait, 2> Traits =
        dialectSentinelTraits(declarationFor(ValueExpression));
    for (const SentinelTrait &Trait : Traits) {
      if (Trait.Value != *Sentinel ||
          !capabilityFor(State, Carrier, Value, Trait.Family).Kind)
        continue;
      State = removeCarrierToken(State, Carrier, Trait.Family);
      State = removeUnderlyingToken(State, Value, Trait.Family);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPostStmt(const BinaryOperator *Statement, CheckerContext &C) const {
    if (Statement->isAssignmentOp()) {
      const ValueDecl *Destination = declarationFor(Statement->getLHS());
      const MemRegion *DestinationCarrier =
          carrierRegion(Statement->getLHS(), C);
      ProgramStateRef State =
          transferTokens(Destination, DestinationCarrier, Statement->getRHS(),
                         Statement, C.getState(), C);
      C.addTransition(State);
      return;
    }
    consumeEqualityToken(Statement, C);
  }

  void checkBranchCondition(const Stmt *Statement, CheckerContext &C) const {
    if (const auto *Comparison = dyn_cast<BinaryOperator>(Statement))
      consumeEqualityToken(Comparison, C);
  }

  void consumeSwitchToken(const SwitchStmt *Statement,
                          CheckerContext &C) const {
    const Expr *Condition = Statement->getCond();
    ProgramStateRef State = C.getState();
    SVal Value = valueForExpression(Condition, C);
    const MemRegion *Carrier = carrierRegion(Condition, C);
    bool Changed = false;
    llvm::SmallVector<SentinelTrait, 2> Traits =
        dialectSentinelTraits(declarationFor(Condition));
    for (const SentinelTrait &Trait : Traits) {
      bool HasSentinelCase = false;
      for (const SwitchCase *Case = Statement->getSwitchCaseList(); Case;
           Case = Case->getNextSwitchCase()) {
        const auto *ValueCase = dyn_cast<CaseStmt>(Case);
        if (!ValueCase)
          continue;
        std::optional<int64_t> CaseValue =
            integerConstant(ValueCase->getLHS(), C.getASTContext());
        if (CaseValue && *CaseValue == Trait.Value) {
          HasSentinelCase = true;
          break;
        }
      }
      if (!HasSentinelCase ||
          !capabilityFor(State, Carrier, Value, Trait.Family).Kind)
        continue;
      State = removeCarrierToken(State, Carrier, Trait.Family);
      State = removeUnderlyingToken(State, Value, Trait.Family);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPostStmt(const ImplicitCastExpr *Statement,
                     CheckerContext &C) const {
    const Stmt *Current = Statement;
    for (unsigned Depth = 0; Current && Depth != 4; ++Depth) {
      DynTypedNodeList Parents = C.getASTContext().getParents(*Current);
      if (Parents.empty())
        return;
      if (const auto *Switch = Parents[0].get<SwitchStmt>()) {
        consumeSwitchToken(Switch, C);
        return;
      }
      Current = Parents[0].get<Expr>();
    }
  }

  void checkPreStmt(const UnaryOperator *Statement, CheckerContext &C) const {
    if (Statement->getOpcode() == UO_Deref)
      requireDereferenceAllowed(Statement->getSubExpr(), Statement, C);
  }

  void checkPreStmt(const ArraySubscriptExpr *Statement,
                    CheckerContext &C) const {
    requireDereferenceAllowed(Statement->getBase(), Statement, C);
  }

  void checkPreStmt(const MemberExpr *Statement, CheckerContext &C) const {
    if (Statement->isArrow())
      requireDereferenceAllowed(Statement->getBase(), Statement, C);
  }

  void checkPreStmt(const ReturnStmt *Statement, CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (Function && Statement->getRetValue()) {
      requireSameBundle(Function, Statement->getRetValue(), Statement, C);
      ProgramStateRef State =
          transferTokens(Function, nullptr, Statement->getRetValue(), Statement,
                         C.getState(), C);
      C.addTransition(State);
    }
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function)
      return;
    unsigned Count = std::min(Call.getNumArgs(), Function->getNumParams());
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (unsigned Argument = 0; Argument < Count; ++Argument) {
      requireSameBundle(Function->getParamDecl(Argument),
                        Call.getArgExpr(Argument), Call.getOriginExpr(), C);
      State = transferTokens(Function->getParamDecl(Argument), nullptr,
                             Call.getArgExpr(Argument), Call.getOriginExpr(),
                             State, C);
      for (const AnnotateAttr *Attribute :
           Function->getParamDecl(Argument)->specific_attrs<AnnotateAttr>()) {
        StringRef Text = Attribute->getAnnotation();
        if (!Text.consume_front("consume:") || Text.empty() ||
            Text.contains(':'))
          continue;
        const TypedefNameDecl *Token =
            findTokenSort(C.getASTContext(), Text);
        if (!dialectTokenPermitsCarrierCopy(Token))
          State = expireStrictLoans(
              State, carrierRegion(Call.getArgExpr(Argument), C),
              &C.getASTContext().Idents.get(Text));
      }
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function)
      return;
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (const OwnershipTypeEntry &Entry : bundleFor(Function)) {
      if (Entry.Member == OwnershipTypeMember::Handle)
        continue;
      State =
          setUnderlyingToken(State, Call.getReturnValue(), Entry.Family,
                             Entry.Member == OwnershipTypeMember::LinearToken
                                 ? CapabilityKind::Linear
                                 : CapabilityKind::Duplicable);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkEndFunction(const ReturnStmt *Return, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    for (const auto &Entry : State->get<CarrierCapabilityMap>()) {
      if (Entry.second == CarrierCapabilityKind::Absent)
        continue;
      const MemRegion *Carrier = Entry.first.first;
      const IdentifierInfo *Family = Entry.first.second;
      const auto *Variable =
          dyn_cast_or_null<VarRegion>(Carrier ? Carrier->getBaseRegion()
                                              : nullptr);
      if (!Variable || Variable->getStackFrame() != C.getStackFrame())
        continue;
      /* Parameter tokens describe the function boundary: withtok preserves
       * them, while consume/grant postconditions are proved independently by
       * CapabilityTokenChecker.  They are not local values being abandoned
       * at this return site. */
      if (isa<ParmVarDecl>(Variable->getDecl()))
        continue;
      const TypedefNameDecl *Token =
          findTokenSort(C.getASTContext(), Family->getName());
      if (!Token || hasQualifier(Token, "qual:implicit_drop"))
        continue;
      const auto *Function = dyn_cast_or_null<FunctionDecl>(
          C.getLocationContext()->getDecl());
      const Stmt *Site = Return ? static_cast<const Stmt *>(Return)
                                : Function ? Function->getBody() : nullptr;
      if (Site)
        report("ownership token is not implicitly droppable", Site, State, C);
      return;
    }
  }
};

#ifdef NTLIBC_OWNERSHIP_Z3
// A genuine Z3-backed fallback for ValidPointerChecker's own ad hoc
// linear-arithmetic bound prover (collectLinearTerms()/
// linearExtentProvenInBounds()/peelElementWidthFactor() below), used only
// when that prover reports "not proven": it only ever peels a single
// top-level BO_Mul node (never a nested one) off the extent expression,
// and only decomposes an additive (BO_Add/BO_Sub) tree into per-symbol
// coefficients, folding anything else -- including any other BO_Mul it
// meets -- in as one opaque, pointer-identity-only term. This bridge asks
// the exact same "is the access provably within the region's dynamic
// extent" question directly of Z3 instead, via ExactCScalarSMT.h's
// ScalarSMT -- the same shared C-arithmetic algebra TotalityChecker.cpp
// and SizeCastChecker.cpp already trust for width/signedness promotion
// and per-operation overflow/wrap -- so this never reimplements those
// conversion rules itself. Deliberately narrower than SizeCastChecker's
// own ArithmeticZ3Proof translator: an extent/index expression is only
// ever built from BO_Add/BO_Sub/BO_Mul over other such expressions and
// integer literals (never a comparison, a bitwise op, or a call result),
// so only that much of the grammar is implemented here. A SymbolCast is
// handled the same narrow way SizeCastChecker's own CastZ3Proof::translate
// already does (see that function's block comment): trusted only when the
// cast's operand already has the exact same bit width as the cast's own
// type, since that is the one shape where Clang 18's missing accessor for
// a SymbolCast's private source type cannot matter -- no extension or
// truncation happens at all, so the bit pattern is unchanged and
// Algebra.convert() below can soundly reinterpret it under the
// destination's own signedness. A width mismatch -- the one case a folded
// multi-step cast chain could actually make Cast->getOperand()->getType()
// an unsafe substitute for -- still falls through to "not proven".
//
// That SymbolCast case alone is NOT sufficient, though: confirmed
// empirically against line_input_result_bounds_the_buffer
// (tools/lint-ownership-fixtures/pointer-safe.c, a `long length =
// getline(...)` result cast to size_t to build the buffer's extent, where
// `long` and `size_t` are the same width on every target this project
// builds for -- LP64 aarch64/x86_64, ILP32 i386) that Clang's own
// SValBuilder::evalCast does not even emit a SymbolCast node for a
// same-width integer cast -- it silently keeps the operand's own
// pre-cast, now-stale type instead. `(size_t)length + 1` therefore
// reaches translate() as a SymIntExpr whose LHS symbol still reports
// SIGNED `long`, combined with a literal `1` SValBuilder independently
// built as UNSIGNED size_t. literal() and apply() below accept that
// mismatch and settle it the way real C's usual arithmetic conversions
// would (see apply()'s own comment) rather than requiring Clang to have
// already pre-converted both operands into one matching domain, which is
// what the old sameDomain-gated design silently assumed and this
// same-width elision breaks.
//
// Any shape translate() cannot decompose, including a still-rejected
// cast, simply yields "not proven" here too -- exactly like the ad hoc
// prover it backs up -- so this can only ever turn an existing "not
// proven" into "proven", never the reverse: a genuine soundness
// improvement, not a suppression.
class OwnershipZ3Engine {
public:
  z3::context Context;
  z3::solver Solver;

  OwnershipZ3Engine() : Solver(Context) {
    z3::params Parameters(Context);
    // Matches SizeCastChecker's ArithmeticZ3Engine: Z3's deterministic
    // resource counter is the primary query budget, with a generous wall
    // clock only as a pathological safety stop.
    Parameters.set("rlimit", 1000000u);
    Parameters.set("timeout", 2000u);
    Solver.set(Parameters);
  }
};

class OwnershipZ3Proof {
  z3::context &ZCtx;
  z3::solver &Solver;
  ASTContext &AST;
  ntlibc::algebra::ScalarSMT Algebra;

  ntlibc::algebra::CType cType(QualType Type) const {
    return {AST.getIntWidth(Type), AST.getIntWidth(Type),
           Type->isUnsignedIntegerOrEnumerationType()};
  }

  // A SymIntExpr/IntSymExpr literal is trusted in its OWN reported width
  // and signedness -- it is a fresh constant SValBuilder built directly
  // for this one operation (see the two translate() call sites below),
  // never inherited from an earlier, possibly-stale cast the way a
  // symbolic operand's own getType() can be (see apply()'s comment for
  // why that distinction matters here).
  std::optional<ntlibc::algebra::SemanticResult>
  literal(const llvm::APSInt &Value) const {
    ntlibc::algebra::CType Type{Value.getBitWidth(), Value.getBitWidth(),
                                Value.isUnsigned()};
    llvm::SmallString<40> Text;
    Value.toString(Text, 10, false, false);
    return Algebra.input(ZCtx.bv_val(Text.c_str(), Type.Width), Type);
  }

  // Left and Right are each trusted in their OWN reported type, but that
  // type can be STALE: confirmed empirically (a real, minimal getline()
  // repro, matching line_input_result_bounds_the_buffer in
  // tools/lint-ownership-fixtures/pointer-safe.c) that Clang's own
  // SValBuilder::evalCast ELIDES the SymbolCast wrapper entirely for a
  // same-width cast -- `(size_t)length + 1`'s SymIntExpr keeps
  // `length`'s own pre-cast SIGNED `long` type on the symbolic operand,
  // with no SymbolCast node anywhere to see, while the `+ 1` literal is
  // independently built via SValBuilder::makeIntVal(1, SizeTy) --
  // UNSIGNED. Calling straight into ScalarSMT's *Converted entry points
  // (as this used to) would either reject that mismatch outright or --
  // worse, if the mismatch were papered over by forcing one side into
  // the other's type -- perform the addition in the WRONG domain: e.g.
  // computing "length + 1" as SIGNED `long` arithmetic manufactures a
  // signed-overflow obligation at length == LONG_MAX that the real
  // program never has, since the real source casts to size_t (defined,
  // unsigned, no-overflow) *before* adding.  ScalarSMT's own non-
  // Converted add/subtract/multiply already exist to settle exactly this
  // ambiguity the way real C does: usualArithmeticType() picks the
  // correct common domain (same width, mixed signedness converts to
  // UNSIGNED; a genuine width mismatch promotes the narrower side) and
  // convert()s both operands into it before combining them, so the
  // signed-overflow-only-in-the-stale-domain trap above cannot occur, and
  // (unlike the old sameDomain-gated *Converted call) a genuine, honestly
  // different-width pair -- never elided the way a same-width cast is,
  // so each side's own reported type is trustworthy -- can now be
  // combined too, instead of being rejected outright.
  // A relational comparison (BO_LT and friends) is itself an ordinary,
  // int-typed C value -- 0 or 1 -- and RangeConstraintManager tracks it
  // exactly like any other symbol: getConstraintMap(State) can hand back
  // a comparison SymExpr narrowed to the single concrete range {1} (a
  // prior `if (slen < blen) ...`-style guard proved it true) or {0}
  // (proved false). util_basename.c's `if (slen > 0 && slen < blen &&
  // ...) base[blen - slen] = 0;` is exactly this shape: the `slen <
  // blen` guard is a real, already-established path fact, but before
  // this case existed apply() rejected the comparison opcode outright
  // (its default case), so translate() failed for that constraint-map
  // entry and the fact was silently dropped instead of reaching the
  // solver -- indistinguishable, to the rest of this class, from never
  // having been guarded at all.  Building the comparison via
  // ScalarSMT::less() (the same usual-arithmetic-conversions-aware
  // helper CastZ3Proof would use) and re-encoding its boolean result as
  // an ordinary 0/1 bit-vector in the comparison's own reported type
  // lets it flow through the EXISTING translate()/addRange plumbing
  // unchanged: the constructor's addRange call still just asserts "this
  // value lies in the constraint map's range", and a {1}/{0} range now
  // asserts the real relation (or its negation) instead of being
  // silently dropped. A wider range (the comparison's truth value
  // genuinely unknown on this path) still round-trips harmlessly, since
  // "ite(cmp, 1, 0) is in {0, 1}" is a tautology that adds nothing.
  std::optional<ntlibc::algebra::SemanticResult>
  comparisonResult(BinaryOperator::Opcode Op,
                   const ntlibc::algebra::SemanticResult &Left,
                   const ntlibc::algebra::SemanticResult &Right,
                   const ntlibc::algebra::CType &ResultType) const {
    std::optional<z3::expr> Ascending = Algebra.less(Left, Right);
    std::optional<z3::expr> Descending = Algebra.less(Right, Left);
    if (!Ascending || !Descending)
      return std::nullopt;
    // z3::expr has no default constructor, so the switch below must
    // initialize True on every reachable path; BO_LT's own case does
    // that just like every other one, rather than relying on a value
    // set before the switch.
    z3::expr True = ZCtx.bool_val(false);
    switch (Op) {
    case BO_LT:
      True = *Ascending;
      break;
    case BO_GT:
      True = *Descending;
      break;
    case BO_LE:
      True = !*Descending;
      break;
    case BO_GE:
      True = !*Ascending;
      break;
    case BO_EQ:
      True = !*Ascending && !*Descending;
      break;
    case BO_NE:
      True = *Ascending || *Descending;
      break;
    default:
      return std::nullopt;
    }
    z3::expr Value = z3::ite(True, ZCtx.bv_val(1, ResultType.Width),
                             ZCtx.bv_val(0, ResultType.Width));
    return Algebra.input(Value, ResultType);
  }

  std::optional<ntlibc::algebra::SemanticResult>
  apply(BinaryOperator::Opcode Op, const ntlibc::algebra::SemanticResult &Left,
       const ntlibc::algebra::SemanticResult &Right,
       const ntlibc::algebra::CType &ResultType) const {
    switch (Op) {
    case BO_Add:
      return Algebra.add(Left, Right);
    case BO_Sub:
      return Algebra.subtract(Left, Right);
    case BO_Mul:
      return Algebra.multiply(Left, Right);
    case BO_LT:
    case BO_GT:
    case BO_LE:
    case BO_GE:
    case BO_EQ:
    case BO_NE:
      return comparisonResult(Op, Left, Right, ResultType);
    default:
      return std::nullopt;
    }
  }

  std::optional<ntlibc::algebra::SemanticResult>
  translate(SymbolRef Sym, unsigned Depth = 0) {
    if (!Sym || Depth > 24 || Sym->getType().isNull() ||
        !Sym->getType()->isIntegerType())
      return std::nullopt;
    ntlibc::algebra::CType Type = cType(Sym->getType());
    if (const auto *Data = dyn_cast<SymbolData>(Sym)) {
      std::string Name =
          "ntlibc_ownership_bounds_" + std::to_string(Data->getSymbolID());
      return Algebra.input(ZCtx.bv_const(Name.c_str(), Type.Width), Type);
    }
    if (const auto *Cast = dyn_cast<SymbolCast>(Sym)) {
      QualType OperandType = Cast->getOperand()->getType();
      if (OperandType.isNull() || !OperandType->isIntegerType() ||
          AST.getIntWidth(OperandType) != Type.Width)
        return std::nullopt;
      std::optional<ntlibc::algebra::SemanticResult> Operand =
          translate(Cast->getOperand(), Depth + 1);
      if (!Operand)
        return std::nullopt;
      return Algebra.convert(*Operand, Type);
    }
    if (const auto *Binary = dyn_cast<SymIntExpr>(Sym)) {
      std::optional<ntlibc::algebra::SemanticResult> Left =
          translate(Binary->getLHS(), Depth + 1);
      if (!Left)
        return std::nullopt;
      std::optional<ntlibc::algebra::SemanticResult> Right =
          literal(Binary->getRHS());
      if (!Right)
        return std::nullopt;
      return apply(Binary->getOpcode(), *Left, *Right, Type);
    }
    if (const auto *Binary = dyn_cast<IntSymExpr>(Sym)) {
      std::optional<ntlibc::algebra::SemanticResult> Right =
          translate(Binary->getRHS(), Depth + 1);
      if (!Right)
        return std::nullopt;
      std::optional<ntlibc::algebra::SemanticResult> Left =
          literal(Binary->getLHS());
      if (!Left)
        return std::nullopt;
      return apply(Binary->getOpcode(), *Left, *Right, Type);
    }
    if (const auto *Binary = dyn_cast<SymSymExpr>(Sym)) {
      std::optional<ntlibc::algebra::SemanticResult> Left =
          translate(Binary->getLHS(), Depth + 1);
      std::optional<ntlibc::algebra::SemanticResult> Right =
          translate(Binary->getRHS(), Depth + 1);
      if (!Left || !Right)
        return std::nullopt;
      return apply(Binary->getOpcode(), *Left, *Right, Type);
    }
    return std::nullopt;
  }

  // Asserts that Expression (already-translated, in Ranges' own bit
  // width) lies within one of Ranges' disjoint intervals. Mirrors
  // SizeCastChecker.cpp's CastZ3Proof::addRange exactly -- see that
  // function for the reasoning -- adapted only to take a raw z3::expr
  // (this class's translate() wraps it in a SemanticResult; callers pass
  // ->Value) instead of building one from a NonLoc/QualType pair.
  void addRange(const z3::expr &Expression, const RangeSet &Ranges) {
    if (!Expression.is_bv() || Ranges.isEmpty() ||
        Expression.get_sort().bv_size() != Ranges.getBitWidth())
      return;
    std::optional<z3::expr> Union;
    for (const Range &R : Ranges) {
      llvm::SmallString<40> FromText, ToText;
      R.From().toString(FromText, 10, false, false);
      R.To().toString(ToText, 10, false, false);
      z3::expr From = ZCtx.bv_val(FromText.c_str(), Ranges.getBitWidth());
      z3::expr To = ZCtx.bv_val(ToText.c_str(), Ranges.getBitWidth());
      z3::expr Member = R.getConcreteValue()
                            ? Expression == From
                            : Ranges.isUnsigned()
                                  ? z3::ule(From, Expression) &&
                                        z3::ule(Expression, To)
                                  : From <= Expression && Expression <= To;
      Union = Union ? std::optional<z3::expr>(*Union || Member)
                    : std::optional<z3::expr>(Member);
    }
    if (Union && Union->is_bool())
      Solver.add(*Union);
  }

public:
  // State supplies every symbol's own already-established path constraint
  // (a prior `if (n > 0) ...`/`if (len >= cap) return;`-style guard,
  // recorded by Clang's own RangeConstraintManager) -- without it, this
  // class previously had to consider every symbol fully unconstrained
  // across its ENTIRE type range, which is unsound-adjacent in the
  // opposite direction from the ad hoc prover's own bug: it makes Z3
  // *too conservative*, unable to prove access patterns real,
  // already-guarded code relies on (src/util/ed.c's read_line_stdin:
  // `long got = getline(...); if (got > 0 && buf[got - 1] == '\n') ...`
  // is exactly this shape -- `got`'s own state-tracked range already
  // rules out the pathological got == LONG_MIN case a fully-unconstrained
  // symbol would otherwise force this class to entertain). Every symbol
  // getConstraintMap(State) has a range for is fed in exactly the same
  // way SizeCastChecker.cpp's CastZ3Proof already does for its own
  // (differently-scoped) solver.
  OwnershipZ3Proof(OwnershipZ3Engine &Engine, ASTContext &AST,
                   ProgramStateRef State)
      : ZCtx(Engine.Context), Solver(Engine.Solver), AST(AST),
        Algebra(ZCtx, cType(AST.IntTy), cType(AST.UnsignedIntTy)) {
    Solver.reset();
    for (const auto &Entry : getConstraintMap(State))
      if (std::optional<ntlibc::algebra::SemanticResult> Result =
              translate(Entry.first))
        addRange(Result->Value, Entry.second);
  }

  // Proves `index * ElemWidth + Required <= Extent`, in bytes, with every
  // step -- the extent expression, the index expression, and this
  // function's own element-width scale/add -- computed with the exact
  // bit-precise C semantics (including defined unsigned wrap) ScalarSMT
  // already gives every other Z3-backed checker in this tree, and
  // rejected as "not proven" the instant any step's Defined proposition
  // could fail (a genuine UB path, e.g. signed overflow, in the extent or
  // index computation itself makes the resulting bit pattern untrustworthy
  // regardless of what it happens to compute to).
  std::optional<bool> proveOffsetInBounds(SymbolRef ExtentSym,
                                          SymbolRef IndexSym,
                                          CharUnits ElemWidth,
                                          CharUnits Required) {
    std::optional<ntlibc::algebra::SemanticResult> Extent =
        translate(ExtentSym);
    std::optional<ntlibc::algebra::SemanticResult> Index =
        translate(IndexSym);
    if (!Extent || !Index)
      return std::nullopt;
    ntlibc::algebra::CType SizeT = cType(AST.getSizeType());
    std::optional<ntlibc::algebra::SemanticResult> ExtentWide =
        Algebra.convert(*Extent, SizeT);
    std::optional<ntlibc::algebra::SemanticResult> IndexWide =
        Algebra.convert(*Index, SizeT);
    if (!ExtentWide || !IndexWide)
      return std::nullopt;
    std::optional<ntlibc::algebra::SemanticResult> WidthLiteral =
        Algebra.input(
            ZCtx.bv_val(static_cast<uint64_t>(ElemWidth.getQuantity()),
                       SizeT.Width),
            SizeT);
    std::optional<ntlibc::algebra::SemanticResult> RequiredLiteral =
        Algebra.input(
            ZCtx.bv_val(static_cast<uint64_t>(Required.getQuantity()),
                       SizeT.Width),
            SizeT);
    if (!WidthLiteral || !RequiredLiteral)
      return std::nullopt;
    std::optional<ntlibc::algebra::SemanticResult> Scaled =
        Algebra.multiplyConverted(*IndexWide, *WidthLiteral);
    std::optional<ntlibc::algebra::SemanticResult> Access =
        Scaled ? Algebra.addConverted(*Scaled, *RequiredLiteral)
              : std::nullopt;
    if (!Access)
      return std::nullopt;
    z3::expr Sufficient = z3::uge(ExtentWide->Value, Access->Value);
    z3::expr Obligation =
        !(ExtentWide->Defined && Access->Defined && Sufficient);
    Solver.add(Obligation);
    return ntlibc::algebra::provesUnsatisfiable(Solver);
  }
};

static OwnershipZ3Engine &ownershipZ3Engine() {
  // A thread-local context/solver, reused (and reset) across queries,
  // avoids repeated Z3 initialization -- the same rationale as
  // SizeCastChecker's identical arithmeticZ3Engine().
  static thread_local OwnershipZ3Engine Engine;
  return Engine;
}
#endif

class ValidPointerChecker
    : public Checker<check::PreStmt<UnaryOperator>,
                     check::PreStmt<ArraySubscriptExpr>,
                     check::PreStmt<MemberExpr>, check::Location,
                     check::PostCall, check::BeginFunction> {
  mutable std::unique_ptr<BugType> BT;

  // Functions this codebase itself guarantees always return a pointer to
  // real, live storage and never NULL, but whose bodies this checker's
  // cross-TU analysis can't see (their real definitions live in another
  // translation unit), are marked `__attribute__((returns_nonnull))` at
  // their declarations -- errno.h's __errno_location, src/internal/libc.h's
  // __teb, and locale.h's localeconv all do this. This is the standard
  // GCC/Clang return-value counterpart of the `nonnull` parameter
  // attribute checkBeginFunction trusts below. Motivating case: strchr.c's
  // `char *r = strchrnul(s, c); ...` -- strchrnul() is marked
  // `returns_nonnull`, and without honoring it every strchr() call
  // produced an unprovable finding on r. This only trusts a return value
  // the project has itself explicitly annotated.
  static bool isAlwaysNonNull(const CallEvent &Call) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function || !Function->getIdentifier())
      return false;
    return Function->hasAttr<ReturnsNonNullAttr>();
  }

  // The strto* family writes either its input pointer or a pointer later in
  // that same string through endptr.  Consequently, whenever endptr itself
  // is supplied, the value written through it cannot be NULL.  Clang's
  // generic invalidation correctly gives the written value a fresh symbol,
  // but does not attach this library contract to that symbol; every ordinary
  // `strtol(s, &end, 10); if (*end) ...` therefore looked like a possible
  // null dereference even though the conversion call itself established the
  // opposite.  Keep this list literal and limited to the standard narrow and
  // wide conversion families whose second argument is endptr.
  static bool writesNonNullEndPointer(const CallEvent &Call) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function || !Function->getIdentifier())
      return false;
    StringRef Name = Function->getName();
    static constexpr llvm::StringLiteral Names[] = {
        "strtod",  "strtof",   "strtold", "strtol",  "strtoll",
        "strtoul", "strtoull", "wcstod",  "wcstof",  "wcstold",
        "wcstol",  "wcstoll",  "wcstoul", "wcstoull"};
    for (StringRef Candidate : Names)
      if (Name == Candidate)
        return true;
    return false;
  }

  static bool isLineInputFunction(const CallEvent &Call) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function || !Function->getIdentifier())
      return false;
    StringRef Name = Function->getName();
    return Name == "getline" || Name == "getdelim";
  }

  // src/internal/ownership_stubs.h's __ownership_pointer_nonnull(object) is
  // the leaf axiom for exactly the gap this checker's own nonnull proof
  // otherwise cannot close: a struct field or array element (e.g. a
  // `char **` argv slice stashed in a parser context struct, indexed
  // inside that struct's own accessor) that is genuinely always live by
  // construction, but whose read yields a fresh symbolic value under
  // Clang's own core nonnull constraint every time it is evaluated --
  // nothing about *how* that value was constructed (an ordinary
  // MemberExpr/ArraySubscriptExpr read) ever lets isNonNull() prove it.
  //
  // This is recognized BY NAME, the same way isAlwaysNonNull() above
  // recognizes __attribute__((returns_nonnull)) and
  // writesNonNullEndPointer() recognizes the strto* family: a small,
  // fixed set of real per-function contracts this checker cannot derive
  // from first principles, asserted once by a human at the call site
  // where the fact is actually true, the same discipline
  // __ownership_string_terminated() already applies to the NUL-
  // terminated property nearby. It is deliberately NOT routed through
  // this project's own grant()/consume() token-state map the way that
  // sibling axiom is: that map (CapabilityMap/SymbolCapabilityMap, see
  // CapabilityTokenChecker above) is populated only by ntlibc.
  // CapabilityToken, and tools/lint.sh's stage_ownership never loads
  // ntlibc.CapabilityToken in the same clang --analyze invocation as
  // ntlibc.ValidPointer (they are deliberately split into separate
  // passes with separate exploration budgets -- see stage_ownership's
  // own comment on "Keep the high-volume pointer proof search from
  // consuming the exploration budget needed by ownership/lifecycle
  // proofs"), so a token grant recorded by one would never be visible to
  // the other's ProgramState. Directly assuming the argument's own SVal
  // nonnull, right here in the same checker and the same pass that later
  // reads checkPointerExpression's isNonNull() constraint, is the only
  // one of the two designs sketched for this feature that actually
  // reaches the check it exists to satisfy.
  static bool isPointerNonNullAxiom(const CallEvent &Call) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function || !Function->getIdentifier())
      return false;
    return Function->getName() == "__ownership_pointer_nonnull";
  }

  // __peb (src/internal/libc.h: `extern PPEB __peb;`) is a plain global
  // pointer, not a call result, so isAlwaysNonNull's checkPostCall-based
  // mechanism cannot cover it -- it is set exactly once, unconditionally,
  // in crt/crt1.c's __libc_start_main, from __teb()->ProcessEnvironmentBlock
  // (itself always-valid, see isAlwaysNonNull above) before any other
  // code in the program runs, and nothing anywhere in this tree ever
  // reassigns or clears it afterward. That makes every later dereference
  // of __peb (dlfcn.c's __peb->ImageBaseAddress, plat_malloc.c's
  // __peb->ProcessHeap used by every malloc/free/realloc on NT, ...) the
  // exact same "always valid, but not something this per-function
  // analysis can derive from its own tracking" shape as __errno_location,
  // just expressed as a global's identity instead of a call's return
  // value. This is checked structurally (a DeclRefExpr naming this one
  // specific, by-name-identified global) rather than through SVal/region
  // state, because unlike a call result there is no "after this call"
  // point to assume the fact at -- the value already exists in the
  // global's storage by the time any TU's code runs.
  static bool isAlwaysNonNullGlobal(const Expr *PointerExpr) {
    const auto *Ref = dyn_cast<DeclRefExpr>(PointerExpr->IgnoreParenCasts());
    if (!Ref)
      return false;
    const auto *Variable = dyn_cast<VarDecl>(Ref->getDecl());
    if (!Variable || !Variable->getIdentifier() ||
        !Variable->hasGlobalStorage())
      return false;
    StringRef Name = Variable->getName();
    if (Name == "__peb")
      return true;
    // The child table has the same cross-translation-unit invariant as
    // __peb: it starts at the address of the fixed __child_seed array and
    // child_grow() replaces it only after a checked __malloc succeeds.
    // The old allocation is freed before publication of the replacement,
    // but the global itself is never cleared.  Exact-name matching keeps
    // this OS/process-table contract from becoming a general relaxation
    // for arbitrary global pointers.  The name alone is insufficient:
    // require the external-linkage declaration published by libc.h and its
    // canonical `struct __child *` type, so an unrelated file-local or
    // differently-typed variable with the same reserved spelling remains
    // subject to the ordinary proof.
    if (Name != "__children" || !Variable->hasExternalFormalLinkage())
      return false;
    QualType Type = Variable->getType().getCanonicalType();
    if (!Type->isPointerType())
      return false;
    const auto *Record = Type->getPointeeType()->getAs<RecordType>();
    if (!Record)
      return false;
    const auto *Declaration =
        cast<RecordDecl>(Record->getDecl()->getCanonicalDecl());
    return Declaration->isStruct() && Declaration->getIdentifier() &&
           Declaration->getName() == "__child";
  }

  void report(StringRef Reason, const Stmt *Statement, ProgramStateRef State,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven pointer dereference",
                                     categories::MemoryError);
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, diagnosticMessage(Reason, Statement, C), Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  static QualType accessType(const MemRegion *Region, const Stmt *Statement) {
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      QualType Type = Expression->getType();
      if (!Type.isNull() && !Type->isVoidType() && !Type->isFunctionType())
        return Type;
    }
    if (const auto *Typed = dyn_cast_or_null<TypedValueRegion>(Region))
      return Typed->getValueType();
    return QualType();
  }

  // For a[i] into a fixed-size, compile-time-known array `a`, prove the
  // access in-bounds by comparing the index directly against the array's
  // own element count, instead of through the generic byte-extent
  // machinery below. That machinery computes "bytes remaining" as
  // extent_of_a_in_bytes MINUS i*sizeof(element) -- an entirely correct
  // but *compound*, derived symbolic expression -- and then asks the
  // constraint solver whether that compound value can be proven >=
  // sizeof(element). clang's default range-based solver reasons well
  // about a single symbol's own range (exactly what a guard like
  // src/exit/exit.c's atexit() -- `if (nhandlers >= ATEXIT_CAP_) return
  // -1; handlers[nhandlers++] = f;` -- establishes directly: nhandlers
  // < ATEXIT_CAP_) but does not generally re-derive that same fact once
  // it has been folded into a multiplication/subtraction over a fresh
  // symbol -- so a genuinely bounds-checked write into a real, fixed-
  // size array was reported as if the check had never happened. Asking
  // the exact question the guard itself answered (is the raw index
  // symbol below the array's own element count?) is precisely what the
  // solver handles well, so this only helps the shape that is provable
  // by construction, and returns false (falling through to the existing
  // machinery, unchanged) for anything it cannot establish outright --
  // including every heap-allocated "array" (a struct field's calloc'd
  // buffer, whose real capacity was fixed by an argument to a *different*
  // call this per-function analysis cannot see) reached only through a
  // pointer, which has no compile-time array type to compare against at
  // all.
  static bool arrayIndexProvenInBounds(const ElementRegion *Element,
                                       ProgramStateRef State,
                                       CheckerContext &C) {
    const auto *Super = dyn_cast<TypedValueRegion>(Element->getSuperRegion());
    if (!Super)
      return false;
    const ConstantArrayType *ArrayType =
        C.getASTContext().getAsConstantArrayType(Super->getValueType());
    if (!ArrayType)
      return false;
    SVal Index = Element->getIndex();
    std::optional<DefinedOrUnknownSVal> DefinedIndex =
        Index.getAs<DefinedOrUnknownSVal>();
    if (!DefinedIndex)
      return false;
    QualType IndexType = Index.getType(C.getASTContext());
    if (IndexType.isNull() || !IndexType->isIntegralOrEnumerationType())
      return false;
    SValBuilder &Builder = C.getSValBuilder();
    SVal Count =
        Builder.makeIntVal(ArrayType->getSize().getZExtValue(), IndexType);
    SVal Below = Builder.evalBinOp(State, BO_LT, *DefinedIndex, Count,
                                   Builder.getConditionType());
    std::optional<DefinedOrUnknownSVal> BelowCondition =
        Below.getAs<DefinedOrUnknownSVal>();
    if (!BelowCondition)
      return false;
    // If assuming "index is at or past the count" is itself feasible,
    // the bound is not proven -- fall through to the existing machinery
    // rather than claim a fact that is not actually established.
    if (State->assume(*BelowCondition, false))
      return false;
    if (IndexType->isSignedIntegerOrEnumerationType()) {
      SVal NonNegative = Builder.evalBinOp(State, BO_GE, *DefinedIndex,
                                           Builder.makeIntVal(0, IndexType),
                                           Builder.getConditionType());
      std::optional<DefinedOrUnknownSVal> NonNegativeCondition =
          NonNegative.getAs<DefinedOrUnknownSVal>();
      if (!NonNegativeCondition)
        return false;
      if (State->assume(*NonNegativeCondition, false))
        return false;
    }
    return true;
  }

  // Proves `buf[i]` in-bounds for a heap SymbolicRegion whose dynamic
  // extent was set from an allocation's own size argument (e.g.
  // `malloc(n + 1)`), when `i` is that same argument's root symbol:
  // `buf[n]`, the "allocate len+1, write the terminator at len" idiom
  // (strndup.c is the motivating case). Clang's range solver can prove a
  // single symbol's own affine range but cannot fold "(S + K) - S" down
  // to K across two separately-built compound expressions that merely
  // share a root symbol, so this does the cancellation with plain
  // integer arithmetic instead. Deliberately narrow to byte-stride
  // (`char`) elements, where index and size argument are in the same
  // units with no multiplication to peel through (`wchar_t` falls
  // through to the existing machinery unchanged).
  //
  // collectLinearTerms()/linearExtentProvenInBounds() below generalize
  // the original bare-symbol-only match to any number of summed/
  // subtracted symbols, via linear-term cancellation. Neither version
  // recognizes a provably-equal-but-differently-derived symbol: handle_path.c's
  // `r = __malloc((size_t)n + 1); ...; r[n] = 0;` still reports on the
  // `n == 0` branch, where the index concretizes to the literal 0 rather
  // than staying the symbol `n` -- a known remaining gap. A width/
  // signedness cast on one side (`(size_t)n` vs. a raw `long n` index)
  // is handled: stripCasts, called from collectLinearTerms(), sees
  // through it.
  static SymbolRef stripCasts(SymbolRef Symbol) {
    while (const auto *Cast = dyn_cast_or_null<SymbolCast>(Symbol))
      Symbol = Cast->getOperand();
    return Symbol;
  }

  // Generalizes the single-symbol cancellation above (the original
  // shape this was built for was strictly "extent = S + K, index = S")
  // to any number of summed/subtracted symbols on either side, so long
  // as they cancel COMPLETELY: e.g. an allocation sized from the SUM of
  // two independent length symbols, indexed by an expression that reuses
  // ALL of them (linear_combination_extent_cancels's `s[l1 + 1 + l2]` in
  // tools/lint-ownership-fixtures/pointer-safe.c, mirroring src/env/
  // setenv.c's own `s = malloc(l1 + l2 + 2); ...; s[l1 + 1] = value...`-
  // shaped writes) is no different in kind from the S+K case once the
  // shared symbols are identified and cancelled. A genuine LEFTOVER term
  // -- one or more symbols present in the extent but never referenced by
  // the index, so the cancellation leaves a real margin rather than an
  // exact match -- is deliberately NOT trusted by linearExtentProvenInBounds
  // below despite still being "provable" in plain, unbounded integer
  // arithmetic: see that function's own block comment for the confirmed
  // real counterexample (a leftover term does not stay safely ordered
  // once the summed symbols can wrap size_t, which nothing here bounds
  // them away from).
  //
  // collectLinearTerms() walks a SymExpr built purely from BO_Add/BO_Sub
  // over other SymExprs and integer literals -- which is exactly what
  // every size/offset expression in this idiom is built from, since
  // nothing here multiplies two symbolic lengths together -- and reduces
  // it to a normalized "symbol -> net signed coefficient" map plus a net
  // integer constant. A node this cannot decompose (a multiplication, a
  // call result, ...) is folded in as one opaque atomic term instead of
  // being silently dropped, so it can still cancel by pointer identity
  // against the identical opaque subexpression on the other side, but
  // can never be treated as a free pass the way a genuine summed symbol
  // is; ElemWidth stays restricted to a byte stride for the same reason
  // as before (a `wchar_t` buffer's `(n+1) * sizeof(WCHAR)` extent has a
  // BO_Mul node neither this nor the old lemma peels through).
  static void collectLinearTerms(SymbolRef Sym, bool Negate,
                                 llvm::DenseMap<SymbolRef, int> &Terms,
                                 int64_t &Constant) {
    Sym = stripCasts(Sym);
    if (const auto *IntExpr = dyn_cast<SymIntExpr>(Sym)) {
      BinaryOperator::Opcode Op = IntExpr->getOpcode();
      if (Op == BO_Add || Op == BO_Sub) {
        collectLinearTerms(IntExpr->getLHS(), Negate, Terms, Constant);
        int64_t Rhs = IntExpr->getRHS().getExtValue();
        if (Op == BO_Sub)
          Rhs = -Rhs;
        Constant += Negate ? -Rhs : Rhs;
        return;
      }
    } else if (const auto *SymExprB = dyn_cast<SymSymExpr>(Sym)) {
      BinaryOperator::Opcode Op = SymExprB->getOpcode();
      if (Op == BO_Add || Op == BO_Sub) {
        collectLinearTerms(SymExprB->getLHS(), Negate, Terms, Constant);
        collectLinearTerms(SymExprB->getRHS(), Op == BO_Sub ? !Negate : Negate,
                           Terms, Constant);
        return;
      }
    }
    Terms[Sym] += Negate ? -1 : 1;
  }

  // ONLY trusted when EVERY symbol's net coefficient cancels to exactly
  // zero (no leftover term of either sign) AND the leftover Constant
  // exactly equals Required, i.e. Extent and "Index*ElemWidth + Required"
  // reduce to the literal same closed-form bit-vector expression. That
  // exactness requirement is not pedantry: this function's Constant is
  // plain int64_t bookkeeping over the EXACT (unbounded) integer value of
  // each term, but the real access it is standing in for is evaluated as
  // wrapping, modular size_t arithmetic. Two bit-vector values that are
  // EXACTLY EQUAL stay equal under any wraparound (X == X regardless of
  // what X wraps to), so a zero-margin match is safe unconditionally --
  // but two values merely known, in exact arithmetic, to differ by some
  // fixed positive amount are NOT safely ordered once wraparound is
  // possible: X and X+K can independently wrap at different points, so
  // "X+K is the bigger one" is not a bit-vector tautology. Confirmed
  // empirically (both against a real Z3 query and against a hand-picked
  // adversarial value) for exactly the two shapes this function used to
  // trust with a nonzero margin:
  //   - a leftover term (formerly trusted when unsigned with a positive
  //     net coefficient): src/env/setenv.c's `s = malloc(l1 + l2 + 2);
  //     s[l1] = '=';` -- with l1 == SIZE_MAX - 1 and l2 == 0, `l1 + l2 +
  //     2` wraps to 0 (a 0-byte real allocation) while the index `l1`
  //     itself does not wrap, so the write genuinely lands far
  //     out-of-bounds. The old code proved this "safe" unconditionally
  //     from the symbolic shape alone, without ever checking whether l1
  //     or l2 could reach a value where that matters -- a real, if
  //     impractical (both operands would need to be actual in-memory
  //     string lengths near SIZE_MAX/2), false "proven" verdict.
  //   - a nonzero margin with FULL cancellation and no multiplication
  //     involved at all: `d = malloc(n + 2); d[n] = x;` (Constant 2,
  //     Required 1, margin 1) has the identical wraparound counterexample
  //     at n == SIZE_MAX - 1 (extent wraps to 0, index does not).
  //   - a nonzero margin THROUGH an element-width peel (tools/lint-
  //     ownership-fixtures/pointer-unsafe.c's element_width_leftover_
  //     margin_not_provably_bounded, mirroring src/env/setenv.c's `ne =
  //     realloc(__environ, sizeof(char *) * (n + 2)); ne[n] = s;`):
  //     margin 1 element, and Z3 independently confirms n == 2^61 - 2
  //     wraps `sizeof(char *) * (n + 2)` to 0 while `n * sizeof(char *)`
  //     does not -- the same class of counterexample, reached through a
  //     real multiplication this time rather than pure addition.
  // A zero-margin, fully-cancelled case (same_symbol_extent_cancels,
  // linear_combination_extent_cancels's `s[l1 + 1 + l2] = 0`,
  // element_width_is_peeled's `ne[n + 1] = 0`, putenv()'s `putenv_
  // strings[nputenv++] = s`) has no such counterexample: Extent and
  // Access are the same expression, so the comparison is reflexive
  // regardless of wraparound, exactly the "X == X" case above -- and
  // z3ExtentProvenInBounds below proves it too (a trivial query for Z3),
  // so nothing already genuinely safe is lost by this tightening.
  // getDynamicExtent() always answers in BYTES, but a NON-byte element
  // array's own index (`ne[n + 1]`) is naturally expressed in ELEMENTS,
  // not bytes -- so the two are not directly comparable the way the
  // byte-stride case above compares them. This codebase's other
  // extremely common allocation idiom is exactly this mismatch:
  // `realloc(p, sizeof(*p) * (n + K))` growing a POINTER (or struct)
  // array rather than a byte buffer -- src/env/setenv.c's `ne =
  // realloc(__environ, sizeof(char *) * (n + 2)); ...; ne[n + 1] = 0;`
  // and putenv()'s `putenv_strings = realloc(..., sizeof(char *) *
  // (nputenv + 1)); putenv_strings[nputenv++] = s;` are both this shape
  // (both zero-margin: see linearExtentProvenInBounds's own comment for
  // why `ne[n] = s;` on the SAME allocation, one element short of the
  // full extent, is a different, NOT-trusted margin shape). Peeling a
  // top-level `ElemWidth * (...)` factor off the
  // extent expression converts it back to the same element-count units
  // the index is already naturally in, after which the exact same
  // linear-term cancellation below applies unchanged -- the required
  // remaining amount is then simply "at least 1 more element", not "at
  // least Width more bytes". SValBuilder always normalizes a
  // symbol-times-constant product into a SymIntExpr (RHS the literal),
  // regardless of the multiplication's spelling order in the source, so
  // checking only that shape is not an extra restriction here.
  static SymbolRef peelElementWidthFactor(SymbolRef Sym, CharUnits ElemWidth) {
    Sym = stripCasts(Sym);
    const auto *IntExpr = dyn_cast<SymIntExpr>(Sym);
    if (!IntExpr || IntExpr->getOpcode() != BO_Mul)
      return nullptr;
    if (IntExpr->getRHS().getExtValue() != ElemWidth.getQuantity())
      return nullptr;
    return IntExpr->getLHS();
  }

  static bool linearExtentProvenInBounds(const ElementRegion *Element,
                                         SVal BaseExtent, CharUnits Width,
                                         CheckerContext &C) {
    SymbolRef ExtentSym = BaseExtent.getAsSymbol();
    if (!ExtentSym)
      return false;
    CharUnits ElemWidth =
        C.getASTContext().getTypeSizeInChars(Element->getElementType());
    // In bytes for the ElemWidth == 1 case (Width IS the byte count
    // needed); in elements (always exactly 1: "the accessed element
    // itself") once ElemWidth has been peeled off below.
    int64_t Required = Width.getQuantity();
    if (ElemWidth.getQuantity() != 1) {
      SymbolRef Peeled = peelElementWidthFactor(ExtentSym, ElemWidth);
      if (!Peeled)
        return false;
      ExtentSym = Peeled;
      Required = 1;
    }
    SVal Index = Element->getIndex();
    SymbolRef IndexSym = Index.getAsSymbol();
    if (!IndexSym)
      return false;

    llvm::DenseMap<SymbolRef, int> Terms;
    int64_t Constant = 0;
    collectLinearTerms(ExtentSym, false, Terms, Constant);
    collectLinearTerms(IndexSym, true, Terms, Constant);

    // Every symbol must cancel to exactly zero -- see this function's own
    // block comment above for why a leftover term of EITHER sign is a
    // real, confirmed wraparound risk, not just the negative-coefficient
    // case this used to single out.
    for (const auto &Entry : Terms)
      if (Entry.second != 0)
        return false;
    // Zero margin only, for the identical reason: Constant strictly
    // greater than Required is exactly the "X vs X+K" shape that is not
    // safely ordered under wraparound.
    return Constant == Required;
  }

#ifdef NTLIBC_OWNERSHIP_Z3
  // The genuine Z3-backed fallback (OwnershipZ3Proof, above) for exactly
  // the shapes linearExtentProvenInBounds documents it cannot handle:
  // nested multiplication, and a provably-equal-but-differently-derived
  // symbol whose opaque subexpressions do not share pointer identity with
  // anything on the other side. Deliberately queried in raw byte units
  // (unlike linearExtentProvenInBounds, this never peels ElemWidth off
  // the extent first) since OwnershipZ3Proof computes the real, bit-
  // precise `index * ElemWidth` product itself.
  static bool z3ExtentProvenInBounds(const ElementRegion *Element,
                                     SVal BaseExtent, CharUnits Width,
                                     CheckerContext &C) {
    SymbolRef ExtentSym = BaseExtent.getAsSymbol();
    SymbolRef IndexSym = Element->getIndex().getAsSymbol();
    if (!ExtentSym || !IndexSym)
      return false;
    CharUnits ElemWidth =
        C.getASTContext().getTypeSizeInChars(Element->getElementType());
    OwnershipZ3Proof Proof(ownershipZ3Engine(), C.getASTContext(), C.getState());
    std::optional<bool> Proven =
        Proof.proveOffsetInBounds(ExtentSym, IndexSym, ElemWidth, Width);
    return Proven && *Proven;
  }
#endif

  static bool alignmentProven(const MemRegion *Region, QualType Type,
                              ASTContext &Ctx) {
    if (Type.isNull() || Type->isIncompleteType())
      return false;
    uint64_t Required = Ctx.getTypeAlign(Type);
    RegionOffset Offset = Region->getAsOffset();
    if (!Offset.isValid())
      return false;
    if (!Offset.hasSymbolicOffset()) {
      if (Offset.getOffset() < 0 ||
          static_cast<uint64_t>(Offset.getOffset()) % Required)
        return false;
      const MemRegion *Base = Offset.getRegion();
      if (const auto *Variable = dyn_cast_or_null<VarRegion>(Base))
        return static_cast<uint64_t>(
                   Ctx.getDeclAlign(Variable->getDecl()).getQuantity()) *
                   8 >=
               Required;
      if (const auto *Typed = dyn_cast_or_null<TypedValueRegion>(Base)) {
        QualType BaseType = Typed->getValueType();
        return !BaseType.isNull() && !BaseType->isIncompleteType() &&
               Ctx.getTypeAlign(BaseType) >= Required;
      }
      if (const auto *Symbolic = dyn_cast_or_null<SymbolicRegion>(Base)) {
        QualType SymbolType = Symbolic->getSymbol()->getType();
        if (SymbolType->isPointerType()) {
          QualType Pointee = SymbolType->getPointeeType();
          if (!Pointee->isIncompleteType() &&
              Ctx.getTypeAlign(Pointee) >= Required)
            return true;
        }
        // A live pointer's base address carries the alignment promised by
        // the type used for the access. Concrete byte offsets are checked
        // above; this also covers malloc's suitably aligned base address.
        return true;
      }
      return false;
    }
    const auto *Element = dyn_cast<ElementRegion>(Region);
    if (!Element)
      return false;
    QualType ElementType = Element->getElementType();
    return !ElementType->isIncompleteType() &&
           Ctx.getTypeSize(ElementType) % Required == 0 &&
           alignmentProven(Element->getSuperRegion(), Type, Ctx);
  }

public:
  void checkPointerExpression(const Expr *Pointer, const Stmt *Dereference,
                              CheckerContext &C) const {
    if (isAlwaysNonNullGlobal(Pointer))
      return;
    // Reinterpreting an already-nonnull pointer through a pointer-to-
    // pointer cast never turns it into a null one, but evaluating the
    // CAST expression's own SVal loses that fact: printf.c/scanf.c's
    // shared gf() macro dereferences a format cursor `q` as `*(q)` or
    // through `*(const wchar_t *)(const void *)(q)`, and only the cast
    // side was ever flagged "not proven nonnull" even though the same
    // `q` a few lines away, without the cast, was not -- evaluating a
    // BitCast/NoOp pointer-to-pointer CastExpr's SVal doesn't in general
    // preserve the symbolic region identity a nonnull fact was
    // established for.
    //
    // Deliberately narrow: only CK_BitCast/CK_NoOp are looked through,
    // never CK_LValueToRValue (which would evaluate the pointer
    // variable's own storage location instead of the value stored there,
    // trivially "nonnull" the way any local's address is, wrongly
    // proving every unconstrained raw parameter), and only when the
    // sub-expression is itself pointer-typed. A genuinely null or
    // unconstrained pointer behind the cast is still caught, both here
    // and by clang's own core.NullDereference.
    const Expr *EvalExpr = Pointer;
    for (;;) {
      const auto *Cast = dyn_cast<CastExpr>(EvalExpr->IgnoreParens());
      if (!Cast)
        break;
      CastKind Kind = Cast->getCastKind();
      if (Kind != CK_BitCast && Kind != CK_NoOp)
        break;
      if (!Cast->getSubExpr()->getType()->isPointerType())
        break;
      EvalExpr = Cast->getSubExpr();
    }
    SVal Value = C.getSVal(EvalExpr);
    const MemRegion *Region = Value.getAsRegion();
    if (Region && !Region->getSymbolicBase())
      return;
    if (!C.getState()->isNonNull(Value).isConstrainedTrue()) {
      ProgramStateRef NullState = C.getState();
      if (std::optional<DefinedOrUnknownSVal> Defined =
              Value.getAs<DefinedOrUnknownSVal>())
        NullState = C.getState()->assume(*Defined, false);
      report("pointer dereference is not proven nonnull", Dereference,
             NullState ? NullState : C.getState(), C);
    }
  }

  void checkPreStmt(const UnaryOperator *Unary, CheckerContext &C) const {
    if (Unary->getOpcode() == UO_Deref)
      checkPointerExpression(Unary->getSubExpr(), Unary, C);
  }

  void checkPreStmt(const ArraySubscriptExpr *Subscript,
                    CheckerContext &C) const {
    checkPointerExpression(Subscript->getBase(), Subscript, C);
  }

  void checkPreStmt(const MemberExpr *Member, CheckerContext &C) const {
    if (Member->isArrow())
      checkPointerExpression(Member->getBase(), Member, C);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    bool Changed = false;

    // A successful getline/getdelim call returns the number of bytes read,
    // stores a nonnull buffer through lineptr, and places a terminating NUL
    // immediately after those bytes.  Model that lower bound on the success
    // branch while retaining the untouched failure branch.  Without it,
    // idiomatic `if (len >= 0) line[len]` callers can prove neither the
    // pointer nor its extent even though both are the call's contract.
    if (isLineInputFunction(Call) && Call.getNumArgs() > 0) {
      const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
      std::optional<DefinedOrUnknownSVal> Result =
          Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
      if (Function && Result) {
        SValBuilder &Builder = C.getSValBuilder();
        QualType ReturnTy = Function->getReturnType();
        SVal NonNegative = Builder.evalBinOp(State, BO_GE, *Result,
                                             Builder.makeZeroVal(ReturnTy),
                                             Builder.getConditionType());
        if (std::optional<DefinedOrUnknownSVal> Condition =
                NonNegative.getAs<DefinedOrUnknownSVal>()) {
          auto [Succeeded, Failed] = State->assume(*Condition);
          if (Succeeded) {
            const MemRegion *BufferStorage = Call.getArgSVal(0).getAsRegion();
            SVal Buffer = BufferStorage ? Succeeded->getSVal(BufferStorage)
                                        : UnknownVal();
            if (std::optional<DefinedOrUnknownSVal> DefinedBuffer =
                    Buffer.getAs<DefinedOrUnknownSVal>())
              Succeeded = Succeeded->assume(*DefinedBuffer, true);
            if (Succeeded) {
              const MemRegion *BufferRegion = Buffer.getAsRegion();
              QualType SizeTy = C.getASTContext().getSizeType();
              SVal SizeResult = Builder.evalCast(*Result, SizeTy, ReturnTy);
              SVal Extent =
                  Builder.evalBinOp(Succeeded, BO_Add, SizeResult,
                                    Builder.makeIntVal(1, SizeTy), SizeTy);
              if (BufferRegion) {
                if (std::optional<DefinedOrUnknownSVal> DefinedExtent =
                        Extent.getAs<DefinedOrUnknownSVal>())
                  Succeeded = setDynamicExtent(Succeeded, BufferRegion,
                                               *DefinedExtent, Builder);
              }
              C.addTransition(Succeeded);
            }
          }
          if (Failed)
            C.addTransition(Failed);
          return;
        }
      }
    }

    if (writesNonNullEndPointer(Call) && Call.getNumArgs() > 1) {
      const MemRegion *EndStorage = Call.getArgSVal(1).getAsRegion();
      if (EndStorage &&
          !State->isNull(Call.getArgSVal(1)).isConstrainedTrue()) {
        SVal EndValue = State->getSVal(EndStorage);
        if (std::optional<DefinedOrUnknownSVal> Defined =
                EndValue.getAs<DefinedOrUnknownSVal>()) {
          if (ProgramStateRef NonNull = State->assume(*Defined, true)) {
            State = NonNull;
            Changed = true;
          }
        }
      }
    }

    if (isAlwaysNonNull(Call)) {
      if (std::optional<DefinedOrUnknownSVal> Defined =
              Call.getReturnValue().getAs<DefinedOrUnknownSVal>()) {
        if (ProgramStateRef NonNull = State->assume(*Defined, true)) {
          State = NonNull;
          Changed = true;
        }
      }
    }

    // __ownership_pointer_nonnull(object): see isPointerNonNullAxiom's own
    // comment above for why this is asserted directly against Clang's
    // native nonnull constraint (the same mechanism isAlwaysNonNull and
    // writesNonNullEndPointer already use just above) instead of through
    // this project's own token-state map. Asserting rather than requiring
    // is deliberate and matches every sibling leaf axiom in
    // ownership_stubs.h: State->assume(..., true) narrows the *current*
    // path's constraints for this one symbol without needing (or being
    // able to check) any precondition, exactly like a real
    // `if (object)` guard would -- the human caller is the one vouching
    // that the fact was already true before this call, not the checker.
    if (isPointerNonNullAxiom(Call) && Call.getNumArgs() > 0) {
      if (std::optional<DefinedOrUnknownSVal> Defined =
              Call.getArgSVal(0).getAs<DefinedOrUnknownSVal>()) {
        if (ProgramStateRef NonNull = State->assume(*Defined, true)) {
          State = NonNull;
          Changed = true;
        }
      }
    }

    if (Changed)
      C.addTransition(State);
  }

  // GCC/Clang's own `nonnull` attribute (`__attribute__((nonnull(N,...)))`,
  // or no argument list at all, meaning every pointer parameter) is the
  // C ecosystem's standard, general-purpose way to say exactly the fact
  // this whole checker otherwise has no way to learn about an ordinary
  // parameter: that it is a REQUIRED, non-optional pointer by the
  // function's own real, published contract, not a value the callee is
  // ever expected to validate. Real compilers already understand it (GCC
  // and Clang both diagnose a provably-NULL argument at a call site under
  // -Wnonnull), so recognizing it here piggybacks on a fact this project
  // is expected to state truthfully in its own headers anyway, rather
  // than inventing a checker-only heuristic. This assumes each nonnull
  // parameter is proven at function entry, the same way an explicit
  // `if (!p) return;` guard would establish it -- the difference is that
  // the guard the analyzer would otherwise need is the caller's job, not
  // this function's, per the attribute's own meaning.
  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function)
      return;
    const auto *NonNull = Function->getAttr<NonNullAttr>();
    if (!NonNull)
      return;
    ProgramStateRef State = C.getState();
    const LocationContext *LC = C.getLocationContext();
    bool Changed = false;
    unsigned Index = 0;
    for (const ParmVarDecl *Param : Function->parameters()) {
      unsigned ThisIndex = Index++;
      if (!Param->getType()->isPointerType() || !NonNull->isNonNull(ThisIndex))
        continue;
      SVal ParamValue = State->getSVal(State->getLValue(Param, LC));
      std::optional<DefinedOrUnknownSVal> Defined =
          ParamValue.getAs<DefinedOrUnknownSVal>();
      if (!Defined)
        continue;
      if (ProgramStateRef NonNullState = State->assume(*Defined, true)) {
        State = NonNullState;
        Changed = true;
      }
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkLocation(SVal Location, bool, const Stmt *Statement,
                     CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const MemRegion *Region = Location.getAsRegion();
    if (!Region) {
      report("pointer dereference is not proven nonnull", Statement, State, C);
      return;
    }
    if (!Region->getSymbolicBase() && !isa<ElementRegion>(Region))
      return;
    if (const SymbolicRegion *Base = Region->getSymbolicBase()) {
      const OwnershipKind *Kind = State->get<OwnershipMap>(Base->getSymbol());
      // A Consumed entry is positive evidence: this checker's own
      // allocator/deallocator tracking (OwnershipChecker above) watched
      // this exact symbol go through free()/realloc() on this path, so a
      // later dereference really is a use-after-free. That is the only
      // liveness fact this checker can ever *establish*.
      if (Kind && *Kind == OwnershipKind::Consumed &&
          !insideDynamicStorageConsumer(C)) {
        report("dereference accesses consumed storage", Statement, State, C);
        return;
      }
      // An *absent* entry is not evidence of anything -- it just means
      // this symbol never passed through OwnershipChecker's tracked
      // malloc family. That is the ordinary, expected shape of a borrowed
      // pointer: a function parameter, a global, or any value this
      // checker did not itself allocate. Reporting "not proven live" here
      // would fire for essentially every dereference of a plain pointer
      // parameter in the tree (the single most common pointer shape in a
      // C library), because per-function analysis can never produce
      // positive liveness evidence for a value whose provenance crosses a
      // call boundary -- no amount of code on the callee side can ever
      // satisfy that obligation, so this is not a proof requirement; it
      // would be unconditional noise. Nonnull-ness is still separately
      // required (see checkPointerExpression/above); this only stops
      // treating "unknown provenance" as if it were "known freed". See
      // tools/lint-ownership-fixtures/pointer-safe.c's opaque_borrow for
      // the worked example. (Extent proof below has the matching
      // relaxation, for the same reason -- see the comment there.)
    }

    QualType Type = accessType(Region, Statement);
    if (Type.isNull() || Type->isIncompleteType()) {
      report("dereference extent is not proven sufficient", Statement, State,
             C);
      return;
    }
    CharUnits Width = C.getASTContext().getTypeSizeInChars(Type);
    if (const auto *Element = dyn_cast<ElementRegion>(Region)) {
      if (arrayIndexProvenInBounds(Element, State, C)) {
        if (!alignmentProven(Region, Type, C.getASTContext()))
          report("dereference alignment is not proven valid", Statement, State,
                 C);
        return;
      }
    }
    SVal Remaining = getDynamicExtentWithOffset(State, Location);
    // getDynamicExtentWithOffset never actually returns Unknown/Undef in
    // practice for a region reachable from a pointer value: when nothing
    // has told it a real size (no setDynamicExtent call -- the only
    // callers of that in this checker list are malloc-family summaries
    // built into the core engine itself, keyed off the actual allocation
    // size argument), it conjures a fresh, wholly unconstrained
    // SymbolExtent placeholder instead (SymbolManager::getExtentSymbol)
    // so that the arithmetic below always has *something* symbolic to
    // operate on, then subtracts this access's byte offset from it. That
    // subtraction means Remaining itself is almost never literally a bare
    // SymbolExtent even when the underlying region has no real size
    // info -- f->type (a fixed, nonzero field offset) comes back as a
    // compound "extent_of_f minus offsetof(type)" expression symbol, not
    // a SymbolExtent -- so testing Remaining directly under-detects the
    // placeholder case for anything but a zero-offset access. Testing the
    // *base* region's own raw extent instead sidesteps that: the
    // subtraction hasn't happened yet, so a placeholder for f is still
    // exactly a SymbolExtent there, while a genuinely tracked base (a
    // malloc call's real byte count, or a concrete array/struct's static
    // size) is preserved and still drives the real comparison below for
    // any offset into it -- so a too-small malloc'd allocation accessed
    // through a field at a fixed offset is still caught.
    SVal BaseExtent =
        getDynamicExtent(State, Region->getBaseRegion(), C.getSValBuilder());
    bool NoRealExtentInfo =
        BaseExtent.isUnknownOrUndef() ||
        isa_and_nonnull<SymbolExtent>(BaseExtent.getAsSymbol());
    if (!NoRealExtentInfo) {
      if (const auto *Element = dyn_cast<ElementRegion>(Region)) {
        // z3ExtentProvenInBounds only ever runs once the ad hoc prover
        // above has already reported "not proven" -- a genuine soundness
        // improvement on top of it, never a substitute: if Z3 also can't
        // prove it, the finding below still fires exactly as before.
        if (linearExtentProvenInBounds(Element, BaseExtent, Width, C)
#ifdef NTLIBC_OWNERSHIP_Z3
            || z3ExtentProvenInBounds(Element, BaseExtent, Width, C)
#endif
        ) {
          if (!alignmentProven(Region, Type, C.getASTContext()))
            report("dereference alignment is not proven valid", Statement,
                   State, C);
          return;
        }
      }
    }
    if (NoRealExtentInfo) {
      // With no real extent to compare against, fall back to the same
      // "trust the type" reasoning as the liveness fix: a *fixed*,
      // compile-time-known offset (a plain single dereference, or a
      // struct field reached through one -- f->vfs, f->vnext, ...) is
      // guaranteed in-bounds by the C type system itself, which is
      // exactly what makes the pointer's static type meaningful to hold
      // in the first place. A *symbolic* (data-dependent) offset is a
      // genuinely different case -- errbuf[n] with a runtime-computed n
      // really can run past whatever the caller actually allocated, and
      // with no real extent to relate n to, that risk is real and still
      // reported.
      RegionOffset Offset = Region->getAsOffset();
      if (!Offset.isValid() || Offset.hasSymbolicOffset()) {
        report("dereference extent is not proven sufficient", Statement, State,
               C);
        return;
      }
    } else {
      SValBuilder &Builder = C.getSValBuilder();
      SVal Enough =
          Builder.evalBinOp(State, BO_GE, Remaining,
                            Builder.makeIntVal(Width.getQuantity(),
                                               C.getASTContext().getSizeType()),
                            Builder.getConditionType());
      std::optional<DefinedOrUnknownSVal> Condition =
          Enough.getAs<DefinedOrUnknownSVal>();
      // A *fixed*, compile-time-known offset (a plain single dereference,
      // or a struct field reached through one) gets the same "trust the
      // type" leniency here as the NoRealExtentInfo branch above, once
      // OwnershipChecker::allocationSizeInBytes started giving this
      // checker's own allocator family (__malloc, calloc, realloc, ...)
      // real tracked extents rather than leaving them as placeholders:
      // a real extent is very often *itself* a compound, data-dependent
      // expression (`sizeof(struct foo) + extra`, `n * width`, ...), and
      // the fixed-offset access's "Remaining >= Width" comparison
      // inherits that same compound-subtraction shape
      // sameSymbolExtentProvenInBounds exists to work around for the
      // matching-symbol case above -- but a plain fixed field offset
      // essentially never matches that narrow pattern, so before this
      // adjustment, giving __malloc-family allocations real extents
      // would turn every fixed-offset access into one from "trusted by
      // type" (no real extent existed to contradict it) to "unprovable,
      // so reported" (a real, compound extent now exists, but the
      // solver can't relate it to the fixed offset): src/internal/nt/
      // path.c's `*p`/`b[0..6]`-style fixed-offset accesses into
      // `__malloc`'d buffers are exactly this shape. The fix is
      // asymmetric on purpose: only report a fixed-offset access when
      // the real tracked extent makes sufficiency PROVABLY IMPOSSIBLE
      // (`assume(Enough, true)` itself refuted) -- not merely when
      // sufficiency isn't provable -- so a genuinely too-small
      // allocation reached through a fixed field offset (e.g.
      // `malloc(4)` accessed through an 8-byte field, where the
      // extent's real value is concrete or otherwise fully resolvable)
      // is still caught.
      RegionOffset Offset = Region->getAsOffset();
      bool FixedOffset = Offset.isValid() && !Offset.hasSymbolicOffset();
      if (!Condition) {
        if (!FixedOffset) {
          report("dereference extent is not proven sufficient", Statement,
                 State, C);
          return;
        }
      } else if (FixedOffset) {
        if (!State->assume(*Condition, true)) {
          report("dereference extent is not proven sufficient", Statement,
                 State, C);
          return;
        }
      } else {
        ProgramStateRef TooSmall = State->assume(*Condition, false);
        if (TooSmall) {
          report("dereference extent is not proven sufficient", Statement,
                 TooSmall, C);
          return;
        }
      }
    }
    if (!alignmentProven(Region, Type, C.getASTContext()))
      report("dereference alignment is not proven valid", Statement, State, C);
  }
};

class ResourceLifecycleChecker
    : public Checker<check::PreCall, check::PostCall> {
  mutable std::unique_ptr<BugType> BT;

  enum Family : unsigned {
    Descriptor = 1,
    Stream,
    Directory,
    Semaphore,
    Mapping,
    Handle
  };

  static unsigned live(Family Value) {
    return static_cast<unsigned>(Value) * 2;
  }
  static unsigned released(Family Value) { return live(Value) + 1; }

  static const FunctionDecl *function(const CallEvent &Call) {
    return dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  }

  static std::optional<Family> acquiredFamily(const CallEvent &Call) {
    const FunctionDecl *Function = function(Call);
    if (!Function || !Function->getIdentifier())
      return std::nullopt;
    StringRef Name = Function->getName();
    if (Name == "open" || Name == "openat" || Name == "creat" ||
        Name == "socket" || Name == "accept" || Name == "dup" ||
        Name == "dup2" || Name == "mkstemp" || Name == "mkostemp")
      return Descriptor;
    if (Name == "fopen" || Name == "fdopen" || Name == "tmpfile" ||
        Name == "popen")
      return Stream;
    if (Name == "opendir" || Name == "fdopendir")
      return Directory;
    if (Name == "sem_open")
      return Semaphore;
    if (Name == "mmap")
      return Mapping;
    return std::nullopt;
  }

  // NT's own syscalls (unlike the POSIX open()/socket()/... family above)
  // never return the handle they acquire: they return an NTSTATUS and
  // write the handle through an out-pointer argument instead --
  // NtCreateFile(&h, ...), NtDuplicateObject(..., &h, ...), and so on.
  // acquiredFamily()/checkPostCall's `Call.getReturnValue()` can only ever
  // see the NTSTATUS for these, so without the out-pointer tracking this
  // table drives, every Handle this codebase's NT backend acquires would
  // be invisible to ResourceMap -- and every later NtClose() on it would
  // therefore be unprovable by construction, not because of any real
  // lifecycle problem. This table is every NT handle-
  // acquiring syscall this codebase actually calls before an NtClose
  // (found by tracing each NtClose call site back to its handle's
  // origin); the argument index is almost always the first (NT's own
  // convention puts the out-handle first), except where a handle is
  // acquired alongside another one already in scope, as with
  // NtDuplicateObject's *target* handle (its 4th argument) and
  // NtOpenProcessToken's access-token handle (its 3rd).
  struct HandleOutParam {
    llvm::StringLiteral Name;
    unsigned Argument;
  };
  static std::optional<unsigned> handleOutParamArgument(const CallEvent &Call) {
    const FunctionDecl *Function = function(Call);
    if (!Function || !Function->getIdentifier())
      return std::nullopt;
    StringRef Name = Function->getName();
    static constexpr HandleOutParam OutParams[] = {
        {"NtCreateFile", 0},
        {"NtOpenFile", 0},
        {"NtCreateEvent", 0},
        {"NtCreateSemaphore", 0},
        {"NtOpenSemaphore", 0},
        {"NtCreateMutant", 0},
        {"NtCreateThreadEx", 0},
        {"NtOpenProcess", 0},
        {"NtCreateJobObject", 0},
        {"NtCreateSection", 0},
        {"NtCreateNamedPipeFile", 0},
        {"NtCreateTimer", 0},
        {"NtOpenSymbolicLinkObject", 0},
        {"NtDuplicateObject", 3},
        {"NtOpenProcessToken", 2},
    };
    for (const HandleOutParam &Candidate : OutParams)
      if (Name == Candidate.Name)
        return Candidate.Argument;
    return std::nullopt;
  }

  static std::optional<std::pair<Family, unsigned>>
  release(const CallEvent &Call) {
    const FunctionDecl *Function = function(Call);
    if (!Function || !Function->getIdentifier())
      return std::nullopt;
    StringRef Name = Function->getName();
    if (Name == "close")
      return std::pair{Descriptor, 0u};
    if (Name == "fclose" || Name == "pclose")
      return std::pair{Stream, 0u};
    if (Name == "closedir")
      return std::pair{Directory, 0u};
    if (Name == "sem_close")
      return std::pair{Semaphore, 0u};
    if (Name == "munmap")
      return std::pair{Mapping, 0u};
    if (Name == "NtClose")
      return std::pair{Handle, 0u};
    return std::nullopt;
  }

  static std::optional<std::pair<Family, unsigned>> use(const CallEvent &Call) {
    const FunctionDecl *Function = function(Call);
    if (!Function || !Function->getIdentifier())
      return std::nullopt;
    StringRef Name = Function->getName();
    if (Name == "read" || Name == "write" || Name == "pread" ||
        Name == "pwrite" || Name == "lseek" || Name == "fstat" ||
        Name == "fsync")
      return std::pair{Descriptor, 0u};
    if (Name == "fread" || Name == "fwrite")
      return std::pair{Stream, 3u};
    if (Name == "fflush" || Name == "fileno" || Name == "rewind")
      return std::pair{Stream, 0u};
    if (Name == "fseek")
      return std::pair{Stream, 0u};
    if (Name == "readdir" || Name == "rewinddir" || Name == "dirfd")
      return std::pair{Directory, 0u};
    if (Name == "sem_wait" || Name == "sem_trywait" ||
        Name == "sem_timedwait" || Name == "sem_post")
      return std::pair{Semaphore, 0u};
    return std::nullopt;
  }

  void report(StringRef Reason, const CallEvent &Call,
              CheckerContext &C) const {
    const Stmt *Statement = Call.getOriginExpr();
    if (!Statement)
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode();
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven resource lifecycle",
                                     categories::MemoryError);
    auto Report = std::make_unique<PathSensitiveBugReport>(
        *BT, diagnosticMessage(Reason, Statement, C), Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  // POSIX guarantees file descriptors 0/1/2 (STDIN_FILENO/STDOUT_FILENO/
  // STDERR_FILENO) are open on entry to main() and stay open unless a
  // program deliberately closes them -- this codebase's own writestr()/
  // __getopt_msg() (src/misc/getopt.c) and expand_param() (src/wordexp/
  // wordexp.c) write directly to the literal descriptor 2 for exactly
  // this reason, the same convention diagnostic output has followed
  // since long before this checker existed. A literal 0/1/2 argument is
  // never the result of an open()/socket()/... this analysis could have
  // tracked (it is a compile-time constant, not a symbol at all), so
  // without this it was indistinguishable from a wholly made-up
  // descriptor -- this is the Resource-checker analogue of trusting
  // __errno_location()'s always-valid return above.
  static bool isStandardDescriptor(const CallEvent &Call, unsigned Argument,
                                   CheckerContext &C) {
    if (Argument >= Call.getNumArgs())
      return false;
    std::optional<nonloc::ConcreteInt> Value =
        Call.getArgSVal(Argument).getAs<nonloc::ConcreteInt>();
    if (!Value)
      return false;
    const llvm::APSInt &Int = Value->getValue();
    return Int >= 0 && Int <= 2;
  }

  // ISO C (7.21.5.2p2) gives fflush(NULL) its own, different meaning --
  // "flush all streams" -- unlike every other Stream-family operation
  // here (fileno/rewind/fseek/fread/fwrite), which are simply undefined
  // on a null FILE*. Requiring proof of a live, specific stream for the
  // one call whose entire point is "there is no specific stream" was
  // never satisfiable, the same shape as free(NULL)/realloc(NULL, ...)
  // already being no-ops OwnershipChecker's checkPreCall special-cases.
  static bool isFflushAll(const CallEvent &Call, unsigned Argument,
                          CheckerContext &C) {
    const FunctionDecl *Function = function(Call);
    if (!Function || !Function->getIdentifier() ||
        Function->getName() != "fflush")
      return false;
    return C.getState()->isNull(Call.getArgSVal(Argument)).isConstrainedTrue();
  }

  // A hard-coded integer literal at the call site (resource-unsafe.c's
  // bogus_literal: `write(99, "x", 1)`) is real, checkable evidence that
  // this descriptor was authored out of thin air -- it is not, and could
  // never be, the result of any open()/socket()/... this analysis could
  // have tracked. A *computed* argument that merely evaluates concrete
  // on some explored path is a different claim entirely: the single most
  // common shape is a bounded `for` loop's own induction variable, e.g.
  // src/internal/fd.c's __fd_close_all_cloexec():
  //   for (i = 0; i < FD_MAX; i++)
  //     if (__fds[i].h && (__fds[i].flags & O_CLOEXEC)) close(i);
  // clang's analyzer explores only a handful of concrete values of `i`
  // before giving up and widening it to a fresh, unconstrained symbol
  // (FD_MAX == 1024) -- on those first few concrete iterations, `i` is
  // indistinguishable from a hand-written literal by SVal alone, even
  // though the source never wrote any such number down, and the loop's
  // own `__fds[i].h` guard is real, checkable evidence (of exactly the
  // same "someone else's acquire, invisible to this per-function
  // analysis" shape as a borrowed parameter) that whatever integer `i`
  // is on this path names a live descriptor this process's own table
  // says is open. The two are only distinguishable at the AST level --
  // by whether the argument expression is itself the literal, or merely
  // a variable/expression the analyzer's own limited exploration reduced
  // to a concrete value -- so that is what this checks, instead of the
  // SVal's concreteness.
  //
  // Deliberately scoped to Descriptor only: unlike Semaphore/Stream (see
  // the Stream/Semaphore-use carve-out in checkResource below), the file
  // descriptor namespace has exactly one acquire surface (open/socket/
  // accept/dup/...) and exactly one release function (close()), so there
  // is no "used the wrong release API for this concretely-addressed
  // object" hazard (sem_close() on an unnamed, sem_init()'d semaphore,
  // say) that a broader-than-literal trust could hide.
  static bool isLiteralArgument(const CallEvent &Call, unsigned Argument) {
    const Expr *ArgExpr = Call.getArgExpr(Argument);
    if (!ArgExpr)
      return false;
    ArgExpr = ArgExpr->IgnoreParenCasts();
    if (const auto *Unary = dyn_cast<UnaryOperator>(ArgExpr))
      if (Unary->getOpcode() == UO_Minus || Unary->getOpcode() == UO_Plus)
        ArgExpr = Unary->getSubExpr()->IgnoreParenCasts();
    return isa<IntegerLiteral>(ArgExpr);
  }

  // A resource read back through a data-dependent (symbolic) array index
  // -- src/sh/execute.c's __sh_exec_pipeline(), closing `pipes[i][1]`
  // inside a `for (i = 0; i < n; i++)` loop over each pipeline stage's
  // own pipe, is the concrete case that motivated this -- is a claim
  // this checker's per-symbol ResourceMap structurally cannot evaluate,
  // for a reason one level deeper than every other "no information"
  // case above: once such a loop's index is widened past its first few
  // concrete iterations, clang's RegionStore models a symbolic-index
  // ElementRegion read with one shared "default value" representative
  // for the *entire* array, not one distinct symbol per logical element
  // -- so `pipes[i][1]` at one loop iteration and `pipes[i][1]` at a
  // later, logically different iteration (a different pipeline stage
  // entirely) can resolve to the exact same SymbolRef purely as an
  // artifact of the memory model, not because they are really the same
  // resource. __sh_exec_pipeline() closes each pipeline index's ends in
  // exactly one of its two passes -- pass 1 for a real (SH_CMD_SIMPLE)
  // stage, pass 2 for a deferred compound-command stage -- gated by a
  // `deferred[]` array set once, before either pass runs, and never
  // revisited; genuinely correct, but a correlation between "which index
  // this iteration is" and "which pass already closed it" that this
  // per-symbol tracking has no way to see either way, on top of no
  // longer even being able to name the two array elements distinctly.
  // Trusted the same way any other "no information" shape is -- neither
  // direction (acquired-but-not-seen, or released-and-then-reused) is
  // provable when the underlying representation itself cannot tell two
  // different elements apart, so this returns before the state lookup,
  // for every resource operation on such an argument, symmetrically.
  static bool hasSymbolicArrayIndex(const Expr *ArgExpr, CheckerContext &C) {
    ArgExpr = ArgExpr->IgnoreParenCasts();
    const auto *Subscript = dyn_cast<ArraySubscriptExpr>(ArgExpr);
    if (!Subscript)
      return false;
    SVal Index = C.getSVal(Subscript->getIdx());
    if (!Index.getAs<nonloc::ConcreteInt>())
      return true;
    return hasSymbolicArrayIndex(Subscript->getBase(), C);
  }

  // A resource passed directly as a function parameter was acquired by
  // the caller, outside this per-function analysis.  Most scalar resource
  // parameters retain a SymbolRef and are handled by the absent-ResourceMap
  // branch below, but opaque pointer resources such as NT HANDLE can be
  // represented as a region value with no recoverable symbol.  That
  // representation difference must not turn the same borrowed-resource
  // contract into a fabricated-resource finding.  Keep this deliberately
  // direct: values loaded from globals, fields, arrays, or arbitrary
  // expressions still go through the ordinary proof logic.
  static bool isDirectParameterArgument(const CallEvent &Call,
                                        unsigned Argument) {
    const Expr *ArgExpr = Call.getArgExpr(Argument);
    if (!ArgExpr)
      return false;
    const auto *Ref = dyn_cast<DeclRefExpr>(ArgExpr->IgnoreParenCasts());
    return Ref && isa<ParmVarDecl>(Ref->getDecl());
  }

  void checkResource(const CallEvent &Call, Family Expected, unsigned Argument,
                     bool Consume, CheckerContext &C) const {
    if (Argument >= Call.getNumArgs())
      return;
    if (Expected == Descriptor && isStandardDescriptor(Call, Argument, C))
      return;
    if (Expected == Stream && !Consume && isFflushAll(Call, Argument, C))
      return;
    if (const Expr *ArgExpr = Call.getArgExpr(Argument))
      if (hasSymbolicArrayIndex(ArgExpr, C))
        return;
    SymbolRef Symbol = Call.getArgSVal(Argument).getAsSymbol(true);
    const unsigned *State =
        Symbol ? C.getState()->get<ResourceMap>(Symbol) : nullptr;
    if (!State) {
      if (isDirectParameterArgument(Call, Argument)) {
        if (Consume && Symbol)
          C.addTransition(
              C.getState()->set<ResourceMap>(Symbol, released(Expected)));
        return;
      }
      if (!Symbol) {
        // Symbol == nullptr: this argument is a concrete, wholly
        // non-symbolic value the analyzer can name outright -- the
        // address of a stack-local/global (e.g. `sem_t s; sem_wait(&s);`
        // for an unnamed, caller-owned semaphore, whose lifecycle
        // OwnedConstructChecker proves separately, not this checker; or
        // src/stdio/printf.c's vdprintf(), which builds a throwaway
        // stack `FILE f;` never passed through fopen/fdopen/tmpfile/
        // popen and calls `fflush(&f)` directly on it, exactly the same
        // "unnamed, caller-managed object" shape as the semaphore case,
        // just for Stream instead), a literal constant, or similar.
        // That is real, checkable evidence for every family except a
        // *use* (not release) of Semaphore or Stream, so it is kept
        // reported everywhere else: sem_wait/post and fflush's own
        // unnamed/ad-hoc-object cases are the two legitimate uses of
        // this shape (fclose(&f) on that same ad-hoc FILE, or
        // sem_close(&s) on that same unnamed semaphore, would still be
        // real bugs -- neither Semaphore nor Stream's carve-out here
        // extends to Consume, on purpose). A genuinely Unknown/Undef
        // value is a different case from either: the analyzer itself
        // lost track of what this is (most commonly a loop variable
        // widened away after clang's default max-loop iteration cap),
        // which is "no information" just like an untracked symbol
        // below, not positive evidence.
        if (Call.getArgSVal(Argument).isUnknownOrUndef())
          return;
        if ((Expected == Semaphore || Expected == Stream) && !Consume)
          return;
        // Descriptor is a separate carve-out, and applies regardless of
        // Consume (see isLiteralArgument's own comment for why that is
        // safe specifically for this one family): a concrete descriptor
        // this analysis merely could not trace back to an open()/
        // socket()/... call is only real evidence of a fabricated
        // resource when the source itself wrote the number down as a
        // literal, not when it is a loop induction variable or other
        // computed expression the analyzer's own limited exploration
        // happened to concretize.
        if (Expected == Descriptor && !isLiteralArgument(Call, Argument))
          return;
        report("resource is not proven live", Call, C);
        return;
      }
      // Symbol != nullptr but absent from ResourceMap: the resource's
      // provenance is opaque to this per-function analysis -- the same
      // "was this analysis's own acquire/release tracking ever able to
      // see this value" gap fixed for Ownership's deallocator check and
      // ValidPointer's liveness proof above. A descriptor reached
      // through a borrowed struct or passed as a plain parameter
      // (closedir()'s `dp->fd`, set by opendir() in a function this
      // analysis never sees; posix_close()'s `int fd` parameter, opened
      // by whatever called it) has no ResourceMap entry not because it
      // is known un-acquired, but because per-function analysis cannot
      // see what happened before this function was entered. Trust it,
      // but still transition a real release to the released state, so a
      // same-function double-release of this exact borrowed resource is
      // still caught by the *State == released(Expected) branch below.
      if (Consume)
        C.addTransition(
            C.getState()->set<ResourceMap>(Symbol, released(Expected)));
      return;
    }
    if (*State == released(Expected)) {
      report(Consume ? "resource is already released"
                     : "operation uses a released resource",
             Call, C);
      return;
    }
    if (*State != live(Expected)) {
      report("resource family does not match operation", Call, C);
      return;
    }
    if (Consume)
      C.addTransition(
          C.getState()->set<ResourceMap>(Symbol, released(Expected)));
  }

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    if (std::optional<Family> Family = acquiredFamily(Call)) {
      SymbolRef Symbol = Call.getReturnValue().getAsSymbol(true);
      if (Symbol)
        C.addTransition(C.getState()->set<ResourceMap>(Symbol, live(*Family)));
      return;
    }
    if (std::optional<unsigned> Argument = handleOutParamArgument(Call)) {
      if (*Argument >= Call.getNumArgs())
        return;
      const MemRegion *Out = Call.getArgSVal(*Argument).getAsRegion();
      if (!Out)
        return;
      // The call is opaque to the analyzer, so by the time checkPostCall
      // runs, the engine's own default conservative evaluation has
      // already invalidated *Out and bound a fresh symbolic value there
      // (every non-const pointer argument to an unmodeled call gets this
      // treatment) -- reading it back here is exactly how MallocChecker-
      // style checkers recover an out-parameter's acquired value.
      SymbolRef Symbol = C.getState()->getSVal(Out).getAsSymbol(true);
      if (Symbol)
        C.addTransition(C.getState()->set<ResourceMap>(Symbol, live(Handle)));
    }
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (auto Release = release(Call))
      checkResource(Call, Release->first, Release->second, true, C);
    else if (auto Use = use(Call))
      checkResource(Call, Use->first, Use->second, false, C);
  }
};

} // namespace

void registerAllocationLifetimeChecker(CheckerRegistry &Registry);
void registerMemoryContractChecker(CheckerRegistry &Registry);

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  registerAllocationLifetimeChecker(Registry);
  registerMemoryContractChecker(Registry);
  Registry.addChecker<OwnershipChecker>(
      "ntlibc.Ownership",
      "Proves allocator provenance and borrow lifetime at deallocation", "");
  Registry.addChecker<OwnedConstructChecker>(
      "ntlibc.OwnedConstruct",
      "Proves synchronization object construction and destruction", "");
  Registry.addChecker<OwnershipContractChecker>(
      "ntlibc.OwnershipContract",
      "Requires source definitions to repeat header ownership contracts", "");
  Registry.addChecker<AggregateElementTokenChecker>(
      "ntlibc.AggregateElementToken",
      "Relates versioned aggregate elements to nominal token states", "");
  Registry.addChecker<CapabilityTokenChecker>(
      "ntlibc.CapabilityToken",
      "Proves explicit linear and duplicable ownership-token transitions", "");
  Registry.addChecker<OwnershipTypeChecker>(
      "ntlibc.OwnershipType",
      "Proves ownership token bundles across value and storage types", "");
  Registry.addChecker<ValidPointerChecker>(
      "ntlibc.ValidPointer",
      "Proves every memory access has a nonnull, live, in-bounds, aligned "
      "pointer",
      "");
  Registry.addChecker<ResourceLifecycleChecker>(
      "ntlibc.Resource", "Proves acquire, use, and release resource lifecycles",
      "");
}
