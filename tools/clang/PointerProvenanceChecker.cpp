// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "clang/AST/Expr.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/AnalysisDeclContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "RelationContracts.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSwitch.h"

#include <cctype>
#include <memory>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

// PostCall tracks known "needle in haystack" library calls (see
// isNeedleFunction below): the symbolic region conjured for such a
// call's return value is recorded here, mapped to the base region its
// first argument (the haystack) resolved to.  checkPreStmt(BinaryOperator)
// consults this map so that, e.g., `q = strstr(p, ...); ... q - p` is
// recognised as same-provenance even though the call itself is opaque
// (its definition lives in a different translation unit, so the engine
// cannot inline it and conjures q a fresh, otherwise-unrelated symbol).
//
// Registered at namespace-global scope (not inside the anonymous
// namespace below) because REGISTER_MAP_WITH_PROGRAMSTATE expands to a
// specialization of clang::ento::ProgramStateTrait, and a template
// specialization must live in a namespace that encloses the template's
// own -- an anonymous namespace does not enclose clang::ento, only sits
// beside it.
REGISTER_MAP_WITH_PROGRAMSTATE(NeedleAlias, SymbolRef, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(RegistryElement, SymbolRef, const MemRegion *)

namespace {

class PointerProvenanceChecker
    : public Checker<check::PreStmt<BinaryOperator>, check::PreStmt<CastExpr>,
                      check::PreStmt<ReturnStmt>, check::PreCall,
                      check::PostCall, check::BeginFunction, check::Bind,
                      check::EndAnalysis> {
  mutable std::unique_ptr<BugType> BT;
  // Distinct BugType for reportRedundantMarker(): a marker's exemption
  // being redundant is the opposite finding from BT's "unproven" one
  // (the checker DID prove the conversion safe here), so it gets its
  // own category rather than reusing BT's.
  mutable std::unique_ptr<BugType> RedundantMarkerBT;
  mutable llvm::DenseMap<const FunctionDecl *, bool> RelationEligibility;
  mutable llvm::DenseMap<const VarDecl *, bool> RegistryEligibility;
  mutable llvm::SmallVector<const VarDecl *, 4> ContractRegistries;
  mutable bool ContractRegistriesInitialized = false;

  // SharedProvenanceMarkerObservation / SharedProvenanceMarkerObservations:
  // see recordSharedProvenanceMarkerObservation() below for why
  // unsafe_assume_shared_provenance()'s redundancy verdict has to be
  // accumulated across every explored path before it can be trusted,
  // unlike unsafe_assume_valid_pointer()'s. AllPathsProven starts true on
  // the first path that reaches a given marked Operation and is ANDed with
  // every later path's result, so it ends up true only if every explored
  // path proved the site by ordinary logic. Node is a representative
  // ExplodedNode from the first path that reached the marker, captured
  // once (not re-captured on later visits) purely so checkEndAnalysis() has
  // something to build a PathSensitiveBugReport from -- the report's own
  // message text is built from the Operation AST node, not from Node's
  // location, so which explored path Node came from doesn't matter.
  struct SharedProvenanceMarkerObservation {
    bool AllPathsProven;
    const ExplodedNode *Node;
  };
  mutable llvm::DenseMap<const BinaryOperator *,
                         SharedProvenanceMarkerObservation>
      SharedProvenanceMarkerObservations;

  // Transitive: `p = strstr(...); p2 = strstr(p + 2, ...);` (fnmatch.c's
  // bracket_match(), walking from one "[:class:]" delimiter to the
  // next) chains two needle calls, so p2's conjured symbol aliases to
  // p's conjured symbol, which itself only aliases to the *real*
  // parameter region one more hop away.  A single lookup would resolve
  // p2 one hop short of p's own origin and wrongly call the two
  // unequal.  Bounded defensively (aliasing is a DAG built by
  // checkPostCall one call at a time, so a real cycle should be
  // impossible, but an unbounded walk turning a checker bug into a
  // hang is a strictly worse failure mode than an unbounded walk
  // turning it into a false negative).
  static const MemRegion *resolveAlias(const MemRegion *Base,
                                        ProgramStateRef State) {
    for (int Hops = 0; Base && Hops < 32; ++Hops) {
      const auto *SR = dyn_cast<SymbolicRegion>(Base);
      if (!SR)
        break;
      const MemRegion *const *Aliased = State->get<NeedleAlias>(SR->getSymbol());
      if (!Aliased)
        break;
      Base = *Aliased;
    }
    return Base;
  }

  static const MemRegion *baseRegion(SVal Value, ProgramStateRef State) {
    const MemRegion *Region = Value.getAsRegion();
    if (!Region)
      return nullptr;
    return resolveAlias(Region->getBaseRegion(), State);
  }

  // text()/context(): given directly (SourceManager, LangOptions) and a
  // LocationContext rather than a CheckerContext, so both can be called
  // either from an ordinary path callback (which has a live CheckerContext)
  // or from checkEndAnalysis() (which only has the BugReporter and an
  // already-captured ExplodedNode -- see
  // recordSharedProvenanceMarkerObservation() below).
  static std::string text(const Stmt *Statement, const SourceManager &SM,
                          const LangOptions &LangOpts) {
    StringRef Raw =
        Lexer::getSourceText(CharSourceRange::getTokenRange(
                                 SM.getSpellingLoc(Statement->getBeginLoc()),
                                 SM.getSpellingLoc(Statement->getEndLoc())),
                             SM, LangOpts);
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

  static std::string context(const LocationContext *LC) {
    const Decl *Current = LC->getDecl();
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      return Named->getQualifiedNameAsString();
    return Current ? Current->getDeclKindName() : "unknown";
  }

  using RelationContract = spicule::ElementRelationContract;

  static std::optional<RelationContract>
  relationContract(const FunctionDecl *FD, spicule::ElementRelationKind Kind,
                   std::optional<unsigned> Parameter = std::nullopt) {
    if (!FD)
      return std::nullopt;
    for (const FunctionDecl *Redeclaration : FD->redecls()) {
      for (const auto *Attribute : Redeclaration->specific_attrs<AnnotateAttr>()) {
        std::optional<RelationContract> Contract =
            spicule::parseElementRelation(Attribute->getAnnotation());
        if (!Contract || Contract->Kind != Kind)
          continue;
        if (Kind == spicule::ElementRelationKind::Return || !Parameter ||
            *Parameter == Contract->Parameter)
          return Contract;
      }
    }
    return std::nullopt;
  }

  static const VarDecl *registryDecl(StringRef Name, ASTContext &Ctx) {
    const VarDecl *Result = nullptr;
    for (const Decl *Declaration : Ctx.getTranslationUnitDecl()->decls()) {
      const auto *Variable = dyn_cast<VarDecl>(Declaration);
      if (!Variable || Variable->getName() != Name ||
          !Variable->getType()->isPointerType() ||
          !Variable->hasGlobalStorage())
        continue;
      if (Result && Result->getCanonicalDecl() != Variable->getCanonicalDecl())
        return nullptr;
      Result = Variable;
    }
    return Result ? Result->getCanonicalDecl() : nullptr;
  }

  const llvm::SmallVectorImpl<const VarDecl *> &
  contractRegistries(ASTContext &Ctx) const {
    if (ContractRegistriesInitialized)
      return ContractRegistries;
    ContractRegistriesInitialized = true;
    for (const Decl *Declaration : Ctx.getTranslationUnitDecl()->decls()) {
      const auto *FD = dyn_cast<FunctionDecl>(Declaration);
      if (!FD)
        continue;
      for (const auto *Attribute : FD->specific_attrs<AnnotateAttr>()) {
        std::optional<RelationContract> Contract =
            spicule::parseElementRelation(Attribute->getAnnotation());
        StringRef Name = Contract ? Contract->Registry : StringRef();
        const VarDecl *Registry =
            Name.empty() ? nullptr : registryDecl(Name, Ctx);
        if (Registry && llvm::find(ContractRegistries, Registry) ==
                            ContractRegistries.end())
          ContractRegistries.push_back(Registry);
      }
    }
    return ContractRegistries;
  }

  class RegistryExposureVisitor
      : public RecursiveASTVisitor<RegistryExposureVisitor> {
    const VarDecl *Registry;

    bool mentionsRegistry(const Stmt *Statement) const {
      if (!Statement)
        return false;
      if (const auto *Reference = dyn_cast<DeclRefExpr>(Statement))
        return Reference->getDecl()->getCanonicalDecl() == Registry;
      for (const Stmt *Child : Statement->children())
        if (mentionsRegistry(Child))
          return true;
      return false;
    }

  public:
    bool Exposed = false;
    explicit RegistryExposureVisitor(const VarDecl *Registry)
        : Registry(Registry->getCanonicalDecl()) {}

    bool VisitUnaryOperator(UnaryOperator *Operation) {
      if (Operation->getOpcode() != UO_AddrOf)
        return true;
      const auto *Reference = dyn_cast<DeclRefExpr>(
          Operation->getSubExpr()->IgnoreParenImpCasts());
      if (Reference &&
          Reference->getDecl()->getCanonicalDecl() == Registry)
        Exposed = true;
      return true;
    }

    bool VisitGCCAsmStmt(GCCAsmStmt *Assembly) {
      if (mentionsRegistry(Assembly))
        Exposed = true;
      return true;
    }

    bool VisitMSAsmStmt(MSAsmStmt *Assembly) {
      if (mentionsRegistry(Assembly))
        Exposed = true;
      return true;
    }
  };

  bool registryEligible(const VarDecl *Registry, ASTContext &Ctx) const {
    if (!Registry || Registry->getFormalLinkage() != Linkage::Internal ||
        Registry->getType().isVolatileQualified())
      return false;
    Registry = Registry->getCanonicalDecl();
    if (auto Existing = RegistryEligibility.find(Registry);
        Existing != RegistryEligibility.end())
      return Existing->second;
    bool Eligible = true;
    for (const VarDecl *Redeclaration : Registry->redecls())
      if (Redeclaration->hasAttr<AliasAttr>() ||
          Redeclaration->hasAttr<WeakRefAttr>() ||
          Redeclaration->hasAttr<UsedAttr>() ||
          Redeclaration->hasAttr<RetainAttr>())
        Eligible = false;
    RegistryExposureVisitor Visitor(Registry);
    if (Eligible)
      Visitor.TraverseDecl(Ctx.getTranslationUnitDecl());
    Eligible = Eligible && !Visitor.Exposed;
    RegistryEligibility[Registry] = Eligible;
    return Eligible;
  }

  static bool directCallReference(const DeclRefExpr *Reference,
                                  const FunctionDecl *FD,
                                  ASTContext &Ctx) {
    DynTypedNode Current = DynTypedNode::create(*Reference);
    for (unsigned Depth = 0; Depth < 8; ++Depth) {
      auto Parents = Ctx.getParents(Current);
      if (Parents.size() != 1)
        return false;
      const DynTypedNode &Parent = Parents[0];
      if (const auto *Call = Parent.get<CallExpr>())
        return Call->getDirectCallee() &&
               Call->getDirectCallee()->getCanonicalDecl() ==
                   FD->getCanonicalDecl();
      const Stmt *Statement = Parent.get<Stmt>();
      if (!Statement ||
          (!isa<ParenExpr>(Statement) && !isa<CastExpr>(Statement)))
        return false;
      Current = Parent;
    }
    return false;
  }

  class FunctionReferenceVisitor
      : public RecursiveASTVisitor<FunctionReferenceVisitor> {
    const FunctionDecl *FD;
    ASTContext &Ctx;

  public:
    bool AddressTaken = false;
    unsigned DirectCalls = 0;
    FunctionReferenceVisitor(const FunctionDecl *FD, ASTContext &Ctx)
        : FD(FD->getCanonicalDecl()), Ctx(Ctx) {}

    bool VisitDeclRefExpr(DeclRefExpr *Reference) {
      const auto *Referenced = dyn_cast<FunctionDecl>(Reference->getDecl());
      if (!Referenced || Referenced->getCanonicalDecl() != FD)
        return true;
      if (directCallReference(Reference, FD, Ctx))
        ++DirectCalls;
      else
        AddressTaken = true;
      return true;
    }
  };

  bool relationEligible(const FunctionDecl *FD, ASTContext &Ctx) const {
    if (!FD || FD->getStorageClass() != SC_Static)
      return false;
    FD = FD->getCanonicalDecl();
    if (auto Existing = RelationEligibility.find(FD);
        Existing != RelationEligibility.end())
      return Existing->second;
    bool Eligible = true;
    for (const FunctionDecl *Redeclaration : FD->redecls())
      if (Redeclaration->hasAttr<AliasAttr>() ||
          Redeclaration->hasAttr<WeakRefAttr>() ||
          Redeclaration->hasAttr<IFuncAttr>() ||
          Redeclaration->hasAttr<UsedAttr>() ||
          Redeclaration->hasAttr<RetainAttr>())
        Eligible = false;
    FunctionReferenceVisitor Visitor(FD, Ctx);
    if (Eligible)
      Visitor.TraverseDecl(Ctx.getTranslationUnitDecl());
    Eligible = Eligible && !Visitor.AddressTaken && Visitor.DirectCalls > 0;
    RelationEligibility[FD] = Eligible;
    return Eligible;
  }

  static const MemRegion *registryBase(const VarDecl *Registry,
                                       CheckerContext &C) {
    if (!Registry)
      return nullptr;
    ProgramStateRef State = C.getState();
    Loc Location = State->getLValue(Registry, C.getLocationContext());
    return baseRegion(State->getSVal(Location), State);
  }

  static const MemRegion *registryStorage(const VarDecl *Registry,
                                          CheckerContext &C) {
    if (!Registry)
      return nullptr;
    return C.getState()
        ->getLValue(Registry, C.getLocationContext())
        .getAsRegion();
  }

  static const MemRegion *elementRegistry(SVal Value,
                                          ProgramStateRef State) {
    const MemRegion *Region = Value.getAsRegion();
    const auto *Symbol =
        Region ? dyn_cast<SymbolicRegion>(Region->getBaseRegion()) : nullptr;
    if (!Symbol)
      return nullptr;
    const MemRegion *const *Registry =
        State->get<RegistryElement>(Symbol->getSymbol());
    return Registry ? *Registry : nullptr;
  }

  static const VarDecl *directRegistryExpression(const Expr *Expression,
                                                 ASTContext &Ctx) {
    Expression = Expression ? Expression->IgnoreParenImpCasts() : nullptr;
    const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Expression);
    const auto *Variable =
        Reference ? dyn_cast<VarDecl>(Reference->getDecl()) : nullptr;
    if (!Variable || !Variable->getType()->isPointerType() ||
        !Variable->hasGlobalStorage())
      return nullptr;
    return registryDecl(Variable->getName(), Ctx);
  }

  // The standard strto* family writes either its input pointer or a pointer
  // later in that same array through endptr.  The analyzer correctly gives
  // the stored pointer a fresh symbol, but that symbol otherwise loses the
  // standard library's same-object contract.  Keep the list literal and
  // restricted to the narrow and wide conversion functions whose second
  // argument is endptr.
  static bool isStringConversionFunction(const FunctionDecl *FD) {
    if (!FD || !FD->getIdentifier())
      return false;
    StringRef Name = FD->getName();
    static constexpr llvm::StringLiteral Names[] = {
        "strtod",  "strtof",   "strtold", "strtol",  "strtoll",
        "strtoul", "strtoull", "wcstod",  "wcstof",  "wcstold",
        "wcstol",  "wcstoll",  "wcstoul", "wcstoull"};
    for (StringRef Candidate : Names)
      if (Name == Candidate)
        return true;
    return false;
  }

  // A narrow interprocedural summary for the common static cursor helper:
  // every non-null return is the same pointer parameter, possibly advanced
  // by ordinary pointer arithmetic.  Because the function has internal
  // linkage and the call is direct, its complete definition is available;
  // rejecting address exposure, resets, asm, and non-returning fallthrough
  // makes the returned pointer's array provenance an intrinsic contract of
  // the body rather than a call-site assumption.
  class ReturnedParameterVisitor
      : public RecursiveASTVisitor<ReturnedParameterVisitor> {
    const ParmVarDecl *Candidate;
    ASTContext &Ctx;
    bool Valid = true;
    bool SawDerivedReturn = false;

    bool isCandidate(const Expr *E) const {
      E = E->IgnoreParenImpCasts();
      const auto *DRE = dyn_cast<DeclRefExpr>(E);
      return DRE && DRE->getDecl() == Candidate;
    }

    bool isNull(const Expr *E) const {
      return E->isNullPointerConstant(Ctx,
                                      Expr::NPC_ValueDependentIsNotNull);
    }

    bool derivesFromCandidate(const Expr *E) const {
      E = E->IgnoreParens();
      if (const auto *CE = dyn_cast<CastExpr>(E)) {
        if (CE->getCastKind() == CK_NoOp ||
            CE->getCastKind() == CK_BitCast ||
            CE->getCastKind() == CK_LValueToRValue)
          return derivesFromCandidate(CE->getSubExpr());
        return false;
      }
      if (isCandidate(E))
        return true;
      if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
        if (BO->getOpcode() == BO_Add) {
          return (derivesFromCandidate(BO->getLHS()) &&
                  BO->getRHS()->getType()->isIntegerType()) ||
                 (BO->getLHS()->getType()->isIntegerType() &&
                  derivesFromCandidate(BO->getRHS()));
        }
        if (BO->getOpcode() == BO_Sub)
          return derivesFromCandidate(BO->getLHS()) &&
                 BO->getRHS()->getType()->isIntegerType();
        if (BO->getOpcode() == BO_Comma)
          return derivesFromCandidate(BO->getRHS());
        return false;
      }
      if (const auto *CO = dyn_cast<ConditionalOperator>(E))
        return (isNull(CO->getTrueExpr()) ||
                derivesFromCandidate(CO->getTrueExpr())) &&
               (isNull(CO->getFalseExpr()) ||
                derivesFromCandidate(CO->getFalseExpr()));
      return false;
    }

  public:
    ReturnedParameterVisitor(const ParmVarDecl *Candidate, ASTContext &Ctx)
        : Candidate(Candidate), Ctx(Ctx) {}

    bool VisitReturnStmt(ReturnStmt *Return) {
      const Expr *Value = Return->getRetValue();
      if (!Value) {
        Valid = false;
      } else if (!isNull(Value)) {
        if (!derivesFromCandidate(Value))
          Valid = false;
        else
          SawDerivedReturn = true;
      }
      return true;
    }

    bool VisitUnaryOperator(UnaryOperator *Operation) {
      if (Operation->getOpcode() == UO_AddrOf &&
          isCandidate(Operation->getSubExpr()))
        Valid = false;
      return true;
    }

    bool VisitBinaryOperator(BinaryOperator *Operation) {
      if (!Operation->isAssignmentOp() ||
          !isCandidate(Operation->getLHS()))
        return true;
      if (Operation->getOpcode() == BO_Assign) {
        if (!derivesFromCandidate(Operation->getRHS()))
          Valid = false;
      } else if (Operation->getOpcode() != BO_AddAssign &&
                 Operation->getOpcode() != BO_SubAssign) {
        Valid = false;
      }
      return true;
    }

    bool VisitGCCAsmStmt(GCCAsmStmt *) {
      Valid = false;
      return true;
    }

    bool VisitMSAsmStmt(MSAsmStmt *) {
      Valid = false;
      return true;
    }

    bool valid() const { return Valid && SawDerivedReturn; }
  };

  static std::optional<unsigned>
  returnedPointerParameter(const FunctionDecl *FD, ASTContext &Ctx) {
    if (!FD || FD->getStorageClass() != SC_Static ||
        !FD->getReturnType()->isPointerType())
      return std::nullopt;
    for (const FunctionDecl *Redeclaration : FD->redecls())
      if (Redeclaration->hasAttr<AliasAttr>() ||
          Redeclaration->hasAttr<WeakRefAttr>() ||
          Redeclaration->hasAttr<IFuncAttr>() ||
          Redeclaration->hasAttr<UsedAttr>() ||
          Redeclaration->hasAttr<RetainAttr>())
        return std::nullopt;
    const FunctionDecl *Definition = FD->getDefinition();
    const auto *Body =
        Definition ? dyn_cast_or_null<CompoundStmt>(Definition->getBody())
                   : nullptr;
    if (!Body || Body->body_empty() ||
        !isa<ReturnStmt>(Body->body_back()))
      return std::nullopt;
    std::optional<unsigned> Result;
    for (unsigned Index = 0; Index < Definition->getNumParams(); ++Index) {
      const ParmVarDecl *Parameter = Definition->getParamDecl(Index);
      if (!Parameter->getType()->isPointerType())
        continue;
      ReturnedParameterVisitor Visitor(Parameter, Ctx);
      Visitor.TraverseStmt(const_cast<Stmt *>(Definition->getBody()));
      if (!Visitor.valid())
        continue;
      if (Result)
        return std::nullopt;
      Result = Index;
    }
    return Result;
  }

  // isConstantSentinel: the source of an integer-to-pointer cast is a
  // compile-time constant (NT's `(HANDLE)(LONG_PTR)-1` pseudo-handle
  // convention, SIG_DFL/SIG_IGN/SIG_ERR- and MAP_FAILED-style invalid-
  // handle sentinels). "Provenance" isn't a coherent question for a
  // literal: it was never derived from any pointer and is fully visible
  // in the diff, unlike an integer from a variable, syscall, or untrusted
  // input. A strengthening of the checker's purpose, not a relaxation:
  // a fixed sentinel was never *derived* from anything.
  static bool isConstantSentinel(const Expr *E, ASTContext &Ctx) {
    if (E->isValueDependent() || E->isTypeDependent())
      return false;
    Expr::EvalResult Result;
    return E->EvaluateAsInt(Result, Ctx, Expr::SE_NoSideEffects);
  }

  // derivesFromPointer: true if E is built, through parens, arithmetic
  // (+, -, &, |, ^, unary ~) or a conditional operator, from a nested
  // pointer-to-integral cast. Recognises the pointer -> integer ->
  // (mask/offset) -> pointer round trip used for alignment throughout
  // this tree (posix_memalign(), align16(), stack-probe alignment,
  // mman.c's page-range intersection); the ternary case handles
  // `lo = a > b ? a : b`-style range clamps built from two such round
  // trips. The integer was never anything but a pointer's bit pattern
  // plus a compile-time-visible adjustment, so the cast back is
  // provenance-preserving by construction.
  static bool derivesFromPointer(const Expr *E) {
    E = E->IgnoreParens();
    if (const auto *CE = dyn_cast<CastExpr>(E)) {
      if (CE->getCastKind() == CK_PointerToIntegral)
        return true;
      return derivesFromPointer(CE->getSubExpr());
    }
    if (const auto *BO = dyn_cast<BinaryOperator>(E)) {
      switch (BO->getOpcode()) {
      case BO_Add:
      case BO_Sub:
      case BO_And:
      case BO_Or:
      case BO_Xor:
        return derivesFromPointer(BO->getLHS()) ||
               derivesFromPointer(BO->getRHS());
      default:
        return false;
      }
    }
    if (const auto *UO = dyn_cast<UnaryOperator>(E)) {
      switch (UO->getOpcode()) {
      case UO_Not:
      case UO_Plus:
      case UO_Minus:
        return derivesFromPointer(UO->getSubExpr());
      default:
        return false;
      }
    }
    if (const auto *CO = dyn_cast<ConditionalOperator>(E))
      return derivesFromPointer(CO->getTrueExpr()) ||
             derivesFromPointer(CO->getFalseExpr());
    // A reference to a local `uintptr_t ia = (uintptr_t)a;`-style
    // variable: mman.c's range-clamp idiom (`lo = a > m->base ? a :
    // m->base;`) names each round-tripped pointer before combining
    // them, rather than nesting the casts inline, so the derivation has
    // to be traced back through the one initializer rather than found
    // in the expression itself.  Looking at the initializer only (not
    // tracking reassignment) is a deliberate, narrow heuristic: these
    // are write-once locals by construction in every real call site
    // this covers, and the failure mode of being wrong here is a
    // missed relaxation (checker stays strict), not a missed bug.
    if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
        if (const Expr *Init = VD->getInit())
          return derivesFromPointer(Init);
      }
    }
    return false;
  }

  // Walk up past any wrapping parens/implicit casts to the first
  // "interesting" parent statement of Node.
  static const Stmt *significantParent(const Stmt *Node, CheckerContext &C) {
    ParentMap &PM = C.getLocationContext()->getAnalysisDeclContext()->getParentMap();
    const Stmt *Parent = PM.getParent(Node);
    while (Parent && (isa<ParenExpr>(Parent) || isa<ImplicitCastExpr>(Parent)))
      Parent = PM.getParent(Parent);
    return Parent;
  }

  // isClientIdAssignment: the cast's result is the right-hand side of an
  // assignment to a field literally named UniqueProcess or UniqueThread.
  // NT's own CLIENT_ID structure (src/internal/nt.h) declares both
  // fields HANDLE-typed, but the kernel treats them as plain numeric
  // process/thread IDs, not as real handles -- MSDN documents this
  // explicitly, and NtOpenProcess()/NtOpenThread() are the only real
  // consumers, neither of which ever dereferences the "handle" as
  // memory.  This is the same class of NT API quirk as
  // NtCurrentProcess()/NtCurrentThread() (which isConstantSentinel
  // already covers, since both expand to constant casts): a userspace-
  // opaque integer riding in a slot the public header types as HANDLE
  // purely by kernel-ABI convention.
  static bool isClientIdAssignment(const CastExpr *Cast, CheckerContext &C) {
    const Stmt *Parent = significantParent(Cast, C);
    const auto *BO = dyn_cast_or_null<BinaryOperator>(Parent);
    if (!BO || BO->getOpcode() != BO_Assign)
      return false;
    const auto *ME =
        dyn_cast<MemberExpr>(BO->getLHS()->IgnoreParenImpCasts());
    if (!ME)
      return false;
    StringRef Field = ME->getMemberDecl()->getName();
    return Field == "UniqueProcess" || Field == "UniqueThread";
  }

  // isOpaqueApcContext: the cast's result is passed directly as an
  // argument to one of a short, explicit list of NT/internal APIs whose
  // documented contract is "an opaque value handed back to a callback
  // unexamined" -- QueueUserAPC-style thread APCs and NT timer APCs.
  // NtQueueApcThread's ApcArgument1 and NtSetTimer's TimerApcContext are
  // both typed PVOID/HANDLE by Microsoft's own headers purely because
  // that is the ABI's generic "one machine word, caller's choice"
  // parameter type; neither NT nor this library's own signal_apc()/
  // alarm_apc() ever dereferences it (see src/thread/pthread_signal.c
  // and src/unistd/sleep.c, where the value is cast straight back to
  // the small integer -- a signal number or a monotonic sequence
  // counter -- it always was).
  static bool isOpaqueApcContext(const CastExpr *Cast, CheckerContext &C) {
    const Stmt *Parent = significantParent(Cast, C);
    const auto *CallE = dyn_cast_or_null<CallExpr>(Parent);
    if (!CallE)
      return false;
    const FunctionDecl *FD = CallE->getDirectCallee();
    if (!FD || !FD->getIdentifier())
      return false;
    StringRef Name = FD->getIdentifier()->getName();
    return Name == "NtQueueApcThread" || Name == "NtSetTimer" ||
           Name == "signal_apc" || Name == "__plat_thread_queue_apc";
  }

  // isProvenByOrdinaryLogic: every non-marker check this checker has for
  // proving an integer-to-pointer Cast provenance-preserving on its own
  // -- exactly the sequence checkPreStmt(CastExpr) below runs, in order,
  // before it ever consults isUnsafeAssumeValidPointer(). Factored out so
  // it can be re-run standalone, as a self-contained question, wherever
  // an unsafe_*-style marker's exemption needs testing for redundancy:
  // "would this cast have been proven safe even with the marker
  // temporarily ignored?" See isMarkerRedundant() below, and this
  // checker's own tools/lint-pointer-provenance-fixtures/unsafe.c
  // redundant_marker_constant_sentinel() for a marked cast where this
  // now answers yes.
  static bool isProvenByOrdinaryLogic(const CastExpr *Cast,
                                      CheckerContext &C) {
    const Expr *Source = Cast->getSubExpr();
    return isConstantSentinel(Source, C.getASTContext()) ||
           derivesFromPointer(Source) || isClientIdAssignment(Cast, C) ||
           isOpaqueApcContext(Cast, C);
  }

  // isMarkerRedundant: generic support for detecting when an unsafe_*-style
  // marker has stopped covering a real provenance gap. OrdinaryProof is a
  // callable re-running whatever checks would normally have proven the
  // guarded site safe WITHOUT the marker's exemption. If OrdinaryProof()
  // succeeds, the marker no longer covers anything: whatever gap it was
  // written to paper over has since closed (e.g. a later checker extension
  // learned to prove that shape), and a human should remove the
  // now-decorative marker rather than have it silently keep exempting an
  // already-provable site forever.
  //
  // This is sound ONLY when OrdinaryProof is path-insensitive -- true for
  // isProvenByOrdinaryLogic() (isUnsafeAssumeValidPointer()'s ordinary
  // proof), which is pure AST syntax and so answers identically on every
  // path that reaches the same Cast, meaning the single explored path a
  // PreStmt callback sees is already every path that matters. Calling this
  // directly with a path-sensitive OrdinaryProof (isProvenSharedProvenance()
  // for isUnsafeAssumeSharedProvenance()) would silently answer "exists a
  // path where it's provable" instead of the "provable on every path" a
  // real redundancy verdict requires -- see
  // recordSharedProvenanceMarkerObservation() and checkEndAnalysis() below
  // for how that marker's verdict is instead accumulated across the whole
  // function before being decided.
  template <typename OrdinaryProofFn>
  static bool isMarkerRedundant(OrdinaryProofFn OrdinaryProof) {
    return OrdinaryProof();
  }

  // hasAnnotatedAncestor: true if Node is (modulo the parens the
  // wrapping marker macro itself introduces) the direct initializer of a
  // compiler-generated local variable carrying the AnnotationName
  // annotation. This is exactly what src/internal/unsafe_pointer.h's
  // marker macros expand to, under the analyzer only: a GNU statement
  // expression declaring one such local, scoped to that single use,
  // initialized directly from the marked expression and yielded as the
  // whole expression's value -- a real build sees a plain `(expr)` and
  // pays nothing.
  //
  // This is the sole source-visible mechanism for a genuinely irreducible
  // provenance finding now: the opaque (file, function) NamedException
  // table this checker used to carry alongside it (an allowlist entry
  // invisible at the actual call site -- only this checker's own source
  // named it) was removed once these markers existed as an honest
  // alternative. A marker sits at the literal expression it covers,
  // appears in the same diff that adds it, and its own name says plainly
  // what it is: an unverified human assumption, never mistakable for a
  // proof. Because the annotation attaches to one compiler-generated
  // local scoped to one use (not to the marked expression's own type,
  // not to the enclosing function, not to any named source variable the
  // programmer could reuse), it can never silence a second, unmarked,
  // otherwise-identical expression written right next to it -- see this
  // checker's own tools/lint-pointer-provenance-fixtures/{safe,unsafe}.c
  // coverage of both directions, for both markers below.
  static bool hasAnnotatedAncestor(const Stmt *Node, StringRef AnnotationName,
                                   ASTContext &Ctx) {
    DynTypedNode Current = DynTypedNode::create(*Node);
    for (unsigned Depth = 0; Depth < 4; ++Depth) {
      auto Parents = Ctx.getParents(Current);
      if (Parents.size() != 1)
        return false;
      const DynTypedNode &Parent = Parents[0];
      if (const auto *Variable = Parent.get<VarDecl>()) {
        for (const auto *Attribute :
             Variable->specific_attrs<AnnotateAttr>())
          if (Attribute->getAnnotation() == AnnotationName)
            return true;
        return false;
      }
      const Stmt *Statement = Parent.get<Stmt>();
      if (!Statement ||
          (!isa<ParenExpr>(Statement) && !isa<CastExpr>(Statement)))
        return false;
      Current = Parent;
    }
    return false;
  }

  // isUnsafeAssumeValidPointer: Cast is wrapped in
  // unsafe_assume_valid_pointer() -- see hasAnnotatedAncestor() above.
  static bool isUnsafeAssumeValidPointer(const CastExpr *Cast,
                                         ASTContext &Ctx) {
    return hasAnnotatedAncestor(Cast, "spicule_unsafe_assume_valid_pointer",
                                Ctx);
  }

  // isUnsafeAssumeSharedProvenance: Operation (a pointer subtraction or
  // ordered comparison) is wrapped in unsafe_assume_shared_provenance()
  // -- see hasAnnotatedAncestor() above. The macro wraps the whole
  // BinaryOperator (not either operand separately), the same way
  // unsafe_assume_valid_pointer() wraps a whole CastExpr, so one marked
  // comparison can never cover a second, unmarked one beside it.
  static bool isUnsafeAssumeSharedProvenance(const BinaryOperator *Operation,
                                             ASTContext &Ctx) {
    return hasAnnotatedAncestor(
        Operation, "spicule_unsafe_assume_shared_provenance", Ctx);
  }

  void report(StringRef Reason, const Stmt *Statement,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode();
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven pointer provenance",
                                     categories::MemoryError);
    const SourceManager &SM = C.getSourceManager();
    std::string Message =
        (Reason + "; origin '" +
         SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())) +
         "'; context '" + context(C.getLocationContext()) + "'; expression '" +
         text(Statement, SM, C.getLangOpts()) + "'")
            .str();
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  // reportRedundantMarker: emitted in place of silent acceptance when
  // isMarkerRedundant() finds that MarkerName's exemption at Statement
  // was not actually needed -- the checker's own ordinary proof logic
  // would have cleared this site anyway. A distinct, clearly-worded
  // message from report()'s "unproven" finding: this is a request to
  // remove now-decorative source, not an unproven-provenance judgment
  // call.
  //
  // Takes an already-obtained Node and BugReporter, rather than a
  // CheckerContext, so the same function serves both the cast marker (whose
  // redundancy verdict is decided immediately, from the live CheckerContext
  // at the one callback site that sees it) and the shared-provenance marker
  // (whose verdict can only be trusted once every explored path has been
  // seen -- see checkEndAnalysis() below -- by which point the callback
  // that originally observed Statement has long since returned).
  void reportRedundantMarker(StringRef MarkerName, const Stmt *Statement,
                             const ExplodedNode *Node,
                             BugReporter &BR) const {
    if (!RedundantMarkerBT)
      RedundantMarkerBT = std::make_unique<BugType>(
          this, "Redundant provenance marker", categories::MemoryError);
    const SourceManager &SM = BR.getSourceManager();
    std::string Message =
        (MarkerName + "() is no longer necessary here: this conversion is "
         "now provable without it; consider removing the marker; origin '" +
         SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())) +
         "'; context '" + context(Node->getLocationContext()) +
         "'; expression '" +
         text(Statement, SM, BR.getContext().getLangOpts()) + "'")
            .str();
    auto Report = std::make_unique<PathSensitiveBugReport>(*RedundantMarkerBT,
                                                            Message, Node);
    Report->addRange(Statement->getSourceRange());
    BR.emitReport(std::move(Report));
  }

  // isProvenSharedProvenance: every non-marker check this checker has for
  // proving a pointer subtraction or ordered comparison Operation
  // provenance-preserving on its own -- exactly the sequence
  // checkPreStmt(BinaryOperator) below runs, in order, before it ever
  // consults isUnsafeAssumeSharedProvenance(). Factored out for the same
  // reason isProvenByOrdinaryLogic() is above, but with one crucial
  // difference from it: this predicate reads ProgramState (baseRegion() and
  // elementRegistry() both dereference State), so it is path-sensitive --
  // the very same Operation AST node can answer differently on two
  // different explored paths (e.g. a loop-carried pointer whose region
  // identity the analyzer's bounded widening only manages to track on some
  // iterations). isProvenByOrdinaryLogic() has no such problem (it is pure
  // AST syntax), which is exactly why the cast marker's redundancy check
  // may safely ask "does OrdinaryProof() succeed on the one path that
  // reached this callback" and treat that as the answer for every path.
  // This function's callers must not make that same assumption: see
  // recordSharedProvenanceMarkerObservation() immediately below.
  bool isProvenSharedProvenance(const BinaryOperator *Operation,
                                CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const LocationContext *LC = C.getLocationContext();
    const MemRegion *Left =
        baseRegion(State->getSVal(Operation->getLHS(), LC), State);
    const MemRegion *Right =
        baseRegion(State->getSVal(Operation->getRHS(), LC), State);
    if (Left && Right && Left == Right)
      return true;
    const MemRegion *LeftRegistry =
        elementRegistry(State->getSVal(Operation->getLHS(), LC), State);
    const MemRegion *RightRegistry =
        elementRegistry(State->getSVal(Operation->getRHS(), LC), State);
    if (const VarDecl *Registry = directRegistryExpression(
            Operation->getLHS(), C.getASTContext()))
      if (registryEligible(Registry, C.getASTContext()))
        LeftRegistry = registryStorage(Registry, C);
    if (const VarDecl *Registry = directRegistryExpression(
            Operation->getRHS(), C.getASTContext()))
      if (registryEligible(Registry, C.getASTContext()))
        RightRegistry = registryStorage(Registry, C);
    return LeftRegistry && LeftRegistry == RightRegistry;
  }

  // recordSharedProvenanceMarkerObservation: called from
  // checkPreStmt(BinaryOperator) once per explored path that reaches a
  // BinaryOperator wrapped in unsafe_assume_shared_provenance(), instead of
  // deciding redundancy right there. isProvenSharedProvenance() being
  // path-sensitive means "OrdinaryProof succeeded on this path" is not the
  // question a "remove this marker" verdict needs answered -- it needs
  // "OrdinaryProof succeeds on every path that reaches this marker", which
  // is only knowable once every path has been explored. So: AND this
  // path's result into whatever has been seen so far for this exact
  // Operation (true until proven otherwise, since AND-with-nothing-yet
  // should not force a false), and capture one representative ExplodedNode
  // the first time this Operation is seen, purely so checkEndAnalysis()
  // below has a node to build a PathSensitiveBugReport from. The verdict
  // itself is read back out of SharedProvenanceMarkerObservations in
  // checkEndAnalysis(), once this function's entire ExplodedGraph is done.
  //
  // Only paths where the marker's own enclosing function is this graph's
  // top frame (C.getLocationContext()->inTopFrame(), i.e. the analyzer is
  // analyzing that function directly rather than having inlined it into
  // some caller) get recorded. A marker exists to cover what its OWN
  // function's body cannot see about its caller (see e.g. timer.c's
  // timer_signal(), whose comment on this exact marker says so explicitly:
  // "an invariant this function's own body cannot see"), which is exactly
  // the question the analyzer answers by treating that function as its own
  // top-level entry point with an opaque, unconstrained parameter -- the
  // same "no assumptions about which caller" contract the marker itself
  // was written to satisfy, and the same thing a human tests by hand when
  // removing the marker and re-analyzing that function on its own. A path
  // reached by inlining into some particular caller instead answers a
  // narrower, caller-specific question (can THIS ONE caller always prove
  // it), which can look decided (even unanimously "provable" within that
  // one caller's own graph) purely because that caller happens to always
  // supply a friendly pointer, while a different, unanalyzed caller could
  // still supply one the function's own body cannot vouch for. Recording
  // those inlined-frame observations anyway would launder a single lucky
  // caller's local proof into a blanket "the marker is dead code"
  // verdict -- unsound in exactly the same shape as the original per-path
  // bug this mechanism exists to fix.
  void recordSharedProvenanceMarkerObservation(const BinaryOperator *Operation,
                                               bool ProvenOnThisPath,
                                               CheckerContext &C) const {
    if (!C.getLocationContext()->inTopFrame())
      return;
    auto Existing = SharedProvenanceMarkerObservations.find(Operation);
    if (Existing == SharedProvenanceMarkerObservations.end()) {
      SharedProvenanceMarkerObservations.insert(
          {Operation,
           {ProvenOnThisPath, C.generateNonFatalErrorNode()}});
      return;
    }
    Existing->second.AllPathsProven &= ProvenOnThisPath;
    if (!Existing->second.Node)
      Existing->second.Node = C.generateNonFatalErrorNode();
  }

public:
  void checkPreStmt(const BinaryOperator *Operation, CheckerContext &C) const {
    BinaryOperatorKind Opcode = Operation->getOpcode();
    bool Subtraction = Opcode == BO_Sub &&
                       Operation->getLHS()->getType()->isPointerType() &&
                       Operation->getRHS()->getType()->isPointerType();
    bool Ordering = (Opcode == BO_LT || Opcode == BO_LE || Opcode == BO_GT ||
                     Opcode == BO_GE) &&
                    Operation->getLHS()->getType()->isPointerType() &&
                    Operation->getRHS()->getType()->isPointerType();
    if (!Subtraction && !Ordering)
      return;

    // OrdinaryProof: see checkPreStmt(CastExpr)'s own OrdinaryProof
    // comment below for the shape -- but unlike that one, this call's
    // result must NOT be fed straight into isMarkerRedundant(): it is only
    // this one explored path's answer, and isProvenSharedProvenance() is
    // path-sensitive (see that function's own comment). Marked operations
    // are instead handed to recordSharedProvenanceMarkerObservation() to
    // accumulate across every path; the actual redundancy verdict is
    // decided later, in checkEndAnalysis(), once accumulation is complete.
    auto OrdinaryProof = [&] { return isProvenSharedProvenance(Operation, C); };
    if (isUnsafeAssumeSharedProvenance(Operation, C.getASTContext())) {
      recordSharedProvenanceMarkerObservation(Operation, OrdinaryProof(), C);
      return;
    }
    if (OrdinaryProof())
      return;
    report(
        Subtraction
            ? "pointer subtraction operands are not proven to share provenance"
            : "ordered pointer operands are not proven to share provenance",
        Operation, C);
  }

  void checkPreStmt(const CastExpr *Cast, CheckerContext &C) const {
    if (Cast->getCastKind() != CK_IntegralToPointer)
      return;
    // OrdinaryProof: "would this cast be proven safe with the
    // unsafe_assume_valid_pointer() marker's exemption temporarily
    // ignored?" -- exactly the checks that, unmarked, already make this
    // function return early below. Deferred to a lambda (rather than
    // called eagerly here) so it runs at most once per cast: either
    // inside isMarkerRedundant() when the marker is present, or directly
    // on the unmarked path, never both.
    auto OrdinaryProof = [&] { return isProvenByOrdinaryLogic(Cast, C); };
    if (isUnsafeAssumeValidPointer(Cast, C.getASTContext())) {
      // The marker exempts this cast from the "unproven" finding either
      // way; the only question is which diagnostic (if any) to emit. If
      // the checker's own ordinary logic would have proven this cast
      // safe anyway, the marker covers no real gap here -- say so,
      // rather than silently accepting an exemption that turned out to
      // be unnecessary.
      if (isMarkerRedundant(OrdinaryProof)) {
        if (ExplodedNode *Node = C.generateNonFatalErrorNode())
          reportRedundantMarker("unsafe_assume_valid_pointer", Cast, Node,
                                C.getBugReporter());
      }
      return;
    }
    if (OrdinaryProof())
      return;
    report(
        "integer-to-pointer conversion is not proven provenance-preserving",
        Cast, C);
  }

  void checkPreStmt(const ReturnStmt *Return, CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(
        C.getLocationContext()->getDecl());
    std::optional<RelationContract> Contract = relationContract(
        FD, spicule::ElementRelationKind::Return);
    const Expr *Value = Return->getRetValue();
    if (!Contract || !Value ||
        Value->isNullPointerConstant(C.getASTContext(),
                                     Expr::NPC_ValueDependentIsNotNull) ||
        !relationEligible(FD, C.getASTContext()))
      return;
    const VarDecl *Registry =
        registryDecl(Contract->Registry, C.getASTContext());
    if (!registryEligible(Registry, C.getASTContext()))
      return;
    ProgramStateRef State = C.getState();
    const MemRegion *Returned = baseRegion(C.getSVal(Value), State);
    const MemRegion *RegistryBase = registryBase(Registry, C);
    const MemRegion *Relation = elementRegistry(C.getSVal(Value), State);
    const MemRegion *Storage = registryStorage(Registry, C);
    if ((!Returned || !RegistryBase || Returned != RegistryBase) &&
        (!Relation || Relation != Storage))
      report("element relation contract is not proven", Return, C);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    const auto *OriginCall = dyn_cast_or_null<CallExpr>(Call.getOriginExpr());
    if (!FD || !OriginCall || OriginCall->getDirectCallee() != FD ||
        !relationEligible(FD, C.getASTContext()))
      return;
    for (unsigned Index = 0; Index < Call.getNumArgs(); ++Index) {
      std::optional<RelationContract> Contract = relationContract(
          FD, spicule::ElementRelationKind::Parameter, Index);
      if (!Contract)
        continue;
      const VarDecl *Registry =
          registryDecl(Contract->Registry, C.getASTContext());
      if (!registryEligible(Registry, C.getASTContext()))
        continue;
      ProgramStateRef State = C.getState();
      const MemRegion *Argument = baseRegion(Call.getArgSVal(Index), State);
      const MemRegion *RegistryBase = registryBase(Registry, C);
      const MemRegion *Relation =
          elementRegistry(Call.getArgSVal(Index), State);
      const MemRegion *Storage = registryStorage(Registry, C);
      if ((!Argument || !RegistryBase || Argument != RegistryBase) &&
          (!Relation || Relation != Storage)) {
        report("element relation contract is not proven", OriginCall, C);
        return;
      }
    }
  }

  void checkBeginFunction(CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(
        C.getLocationContext()->getDecl());
    if (!FD || !relationEligible(FD, C.getASTContext()))
      return;
    ProgramStateRef State = C.getState();
    bool Changed = false;
    for (unsigned Index = 0; Index < FD->getNumParams(); ++Index) {
      std::optional<RelationContract> Contract = relationContract(
          FD, spicule::ElementRelationKind::Parameter, Index);
      if (!Contract)
        continue;
      const VarDecl *Registry =
          registryDecl(Contract->Registry, C.getASTContext());
      if (!registryEligible(Registry, C.getASTContext()))
        continue;
      const MemRegion *Storage = registryStorage(Registry, C);
      Loc ParameterLocation =
          State->getLValue(FD->getParamDecl(Index), C.getLocationContext());
      const MemRegion *ParameterValue =
          State->getSVal(ParameterLocation).getAsRegion();
      const auto *ParameterSymbol =
          ParameterValue
              ? dyn_cast<SymbolicRegion>(ParameterValue->getBaseRegion())
              : nullptr;
      if (!Storage || !ParameterSymbol)
        continue;
      State = State->set<RegistryElement>(ParameterSymbol->getSymbol(),
                                          Storage);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkBind(SVal Location, SVal Value, const Stmt *,
                 CheckerContext &C) const {
    const MemRegion *Written = Location.getAsRegion();
    if (!Written)
      return;
    Written = Written->getBaseRegion();
    ProgramStateRef Original = C.getState();
    ProgramStateRef State = Original;
    for (const auto &Entry : Original->get<RegistryElement>())
      if (Entry.second == Written)
        State = State->remove<RegistryElement>(Entry.first);
    const MemRegion *ValueRegion = Value.getAsRegion();
    const auto *ValueSymbol =
        ValueRegion
            ? dyn_cast<SymbolicRegion>(ValueRegion->getBaseRegion())
            : nullptr;
    if (ValueSymbol) {
      for (const VarDecl *Registry : contractRegistries(C.getASTContext())) {
        if (!registryEligible(Registry, C.getASTContext()))
          continue;
        const MemRegion *CurrentBase = registryBase(Registry, C);
        if (CurrentBase && CurrentBase == ValueRegion->getBaseRegion()) {
          const MemRegion *Storage = registryStorage(Registry, C);
          if (Storage)
            State = State->set<RegistryElement>(ValueSymbol->getSymbol(),
                                                Storage);
        }
      }
    }
    if (State != Original)
      C.addTransition(State);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!FD || !FD->getIdentifier())
      return;
    if (const auto *OriginCall =
            dyn_cast_or_null<CallExpr>(Call.getOriginExpr())) {
      std::optional<RelationContract> Contract = relationContract(
          FD, spicule::ElementRelationKind::Return);
      if (Contract && OriginCall->getDirectCallee() == FD &&
          relationEligible(FD, C.getASTContext())) {
        ProgramStateRef State = C.getState();
        const VarDecl *Registry =
            registryDecl(Contract->Registry, C.getASTContext());
        if (!registryEligible(Registry, C.getASTContext()))
          return;
        const MemRegion *Storage = registryStorage(Registry, C);
        const MemRegion *Return = Call.getReturnValue().getAsRegion();
        const auto *ReturnSymbol =
            Return ? dyn_cast<SymbolicRegion>(Return->getBaseRegion())
                   : nullptr;
        if (Storage && ReturnSymbol) {
          State = State->set<RegistryElement>(ReturnSymbol->getSymbol(),
                                              Storage);
          C.addTransition(State);
          return;
        }
      }
    }
    if (isStringConversionFunction(FD) && Call.getNumArgs() > 1) {
      ProgramStateRef State = C.getState();
      const MemRegion *Haystack = Call.getArgSVal(0).getAsRegion();
      const MemRegion *EndStorage = Call.getArgSVal(1).getAsRegion();
      if (!Haystack || !EndStorage)
        return;
      Haystack = resolveAlias(Haystack->getBaseRegion(), State);
      const MemRegion *EndValue = State->getSVal(EndStorage).getAsRegion();
      const auto *EndSymbol =
          EndValue ? dyn_cast<SymbolicRegion>(EndValue->getBaseRegion())
                   : nullptr;
      if (!Haystack || !EndSymbol)
        return;
      State = State->set<NeedleAlias>(EndSymbol->getSymbol(), Haystack);
      C.addTransition(State);
      return;
    }
    const auto *OriginCall = dyn_cast_or_null<CallExpr>(Call.getOriginExpr());
    if (OriginCall && OriginCall->getDirectCallee() == FD) {
      std::optional<unsigned> Parameter =
          returnedPointerParameter(FD, C.getASTContext());
      if (Parameter && *Parameter < Call.getNumArgs()) {
        ProgramStateRef State = C.getState();
        const MemRegion *Origin = Call.getArgSVal(*Parameter).getAsRegion();
        const MemRegion *Return = Call.getReturnValue().getAsRegion();
        const auto *ReturnSymbol =
            Return ? dyn_cast<SymbolicRegion>(Return->getBaseRegion())
                   : nullptr;
        if (Origin && ReturnSymbol) {
          Origin = resolveAlias(Origin->getBaseRegion(), State);
          State = State->set<NeedleAlias>(ReturnSymbol->getSymbol(), Origin);
          C.addTransition(State);
          return;
        }
      }
    }
    // isNeedleFunction: a well-known C-library "needle in haystack"
    // function whose contract guarantees its return value, if non-null,
    // points somewhere inside its first argument.  Defined here, not as
    // a free function, purely to keep the StringSwitch next to its only
    // caller.
    StringRef Name = FD->getIdentifier()->getName();
    bool IsNeedle = llvm::StringSwitch<bool>(Name)
        .Cases("strchr", "strrchr", "strstr", "strcasestr", "strpbrk",
               "memchr", "rawmemchr", true)
        .Cases("wcschr", "wcsrchr", "wcsstr", "wmemchr", true)
        // wordexp.c's param_word_end(const char *p) and glob.c's
        // find_slash(const char *p, int flags) are this library's own
        // internal equivalents -- each scans forward from its first
        // argument and returns a pointer within that same word/path,
        // exactly like strchr does -- and each is analyzed standalone
        // (as its own entry point, per clang's default `--analyze`
        // behaviour) by every caller that is also analyzed standalone,
        // so the alias needs recording here rather than relying on
        // inlining.
        .Case("param_word_end", true)
        .Case("find_slash", true)
        .Default(false);
    if (!IsNeedle || Call.getNumArgs() < 1)
      return;
    const MemRegion *Haystack = Call.getArgSVal(0).getAsRegion();
    if (!Haystack)
      return;
    Haystack = Haystack->getBaseRegion();
    const MemRegion *Ret = Call.getReturnValue().getAsRegion();
    if (!Ret)
      return;
    if (const auto *SR = dyn_cast<SymbolicRegion>(Ret->getBaseRegion())) {
      ProgramStateRef State = C.getState();
      State = State->set<NeedleAlias>(SR->getSymbol(), Haystack);
      C.addTransition(State);
    }
  }

  // checkEndAnalysis: fires once per analyzed entry point (each top-level
  // function body the analyzer chooses to analyze standalone gets its own
  // ExplodedGraph and its own single checkEndAnalysis call, after every
  // path through it has been explored and before the engine moves on to
  // the next entry point) -- see
  // recordSharedProvenanceMarkerObservation()'s comment for why the
  // shared-provenance marker's redundancy verdict has to wait until here
  // rather than being decided inside checkPreStmt(BinaryOperator).
  //
  // Every observation accumulated during this just-finished graph's
  // exploration is read out and cleared here: any BinaryOperator whose
  // ordinary proof succeeded on every path that reached it (AllPathsProven)
  // gets the redundant-marker diagnostic, using the representative Node
  // captured on the first such path. A marker that was reached by zero
  // paths (e.g. genuinely dead code) is silently skipped rather than
  // treated as vacuously redundant -- Node stays null in that case, since
  // recordSharedProvenanceMarkerObservation() is itself only ever called
  // from a path that did reach it.
  //
  // recordSharedProvenanceMarkerObservation()'s inTopFrame() restriction
  // means a given marked Operation is only ever recorded from the one
  // graph where its own enclosing function is the top-level entry point
  // (never from a graph that merely inlined that function into some
  // caller), so it is only ever decided here once, in that graph's own
  // checkEndAnalysis() call. The map is still cleared unconditionally
  // after every graph regardless -- this checker's own instance persists
  // across every top-level entry point in the translation unit, and a
  // clean slate per graph is simpler to reason about than trusting that
  // no marker belonging to the graph just finished remains unprocessed.
  void checkEndAnalysis(ExplodedGraph &, BugReporter &BR, ExprEngine &) const {
    for (const auto &Entry : SharedProvenanceMarkerObservations) {
      const SharedProvenanceMarkerObservation &Observation = Entry.second;
      if (Observation.AllPathsProven && Observation.Node)
        reportRedundantMarker("unsafe_assume_shared_provenance", Entry.first,
                              Observation.Node, BR);
    }
    SharedProvenanceMarkerObservations.clear();
  }
};

} // namespace

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<PointerProvenanceChecker>(
      "spicule.PointerProvenance",
      "Proves pointer ordering, subtraction, and integer conversion provenance",
      "");
}
