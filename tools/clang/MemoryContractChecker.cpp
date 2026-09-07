// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "clang/AST/Expr.h"
#include "clang/AST/Attr.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/RangedConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "TokenAlgebra.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"

#ifdef SPICULE_MEMORY_CONTRACT_Z3
#include "ExactCScalarSMT.h"
#include "z3++.h"
#endif

#include <cctype>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>

using namespace clang;
using namespace ento;

// strlen(s)'s contract is "bytes before s's first NUL", so s is
// guaranteed at least that many bytes plus the terminator -- reading
// strlen(s) + up-to-1 bytes is always safe. strnlen(s, n)'s contract is
// looser: either it found a real terminator within n bytes (same "+1"
// reasoning) or it read all n bytes without finding one, so only n (not
// n+1) bytes are known-safe -- a slack bound of 0, not 1. Recording
// "this conjured return symbol came from strlen/strnlen(s)" at the call
// lets spanProven recognize the common "n = strlen(s) + 1; p =
// __malloc(n); memcpy(p, s, n);" idiom's source argument as in-bounds --
// this tree's own xstrdup and strdup.c/strndup.c share this shape.
REGISTER_MAP_WITH_PROGRAMSTATE(StrlenSource, SymbolRef, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(StrnlenSource, SymbolRef, const MemRegion *)
/* A checked annotated call establishes a span from the exact pointer value,
 * which may be an interior ElementRegion.  DynamicExtent is rooted at the
 * allocation's base and therefore cannot represent two independent
 * contracted suffixes without either losing the offset or overwriting the
 * base's real extent. */
REGISTER_MAP_WITH_PROGRAMSTATE(AssumedSpanExtent, const MemRegion *,
                               DefinedOrUnknownSVal)
using DisjointRegionKey = std::pair<const MemRegion *, const MemRegion *>;
REGISTER_MAP_WITH_PROGRAMSTATE(AssumedDisjointExtent, DisjointRegionKey,
                               DefinedOrUnknownSVal)
REGISTER_SET_WITH_PROGRAMSTATE(AllocatedBaseRegion, const MemRegion *)
// Keyed by the allocation's own SYMBOL (see allocationSymbol() below), not
// by the MemRegion object checkPostCall happened to observe -- a plain
// MemRegion* key breaks the instant any OTHER checker's own eval::Call or
// checkPostCall rewraps that same symbol in a differently-spaced
// SymbolicRegion later in the same call's checker chain (see
// allocationSymbol()'s own comment for the real, confirmed case this
// closes).
REGISTER_MAP_WITH_PROGRAMSTATE(AllocatedSpanExtent, SymbolRef,
                               DefinedOrUnknownSVal)
REGISTER_MAP_WITH_PROGRAMSTATE(GrantedSpanProof, const ParmVarDecl *,
                               const ParmVarDecl *)
using DisjointParameterKey =
    std::pair<const ParmVarDecl *, const ParmVarDecl *>;
REGISTER_MAP_WITH_PROGRAMSTATE(GrantedDisjointProof, DisjointParameterKey,
                               const ParmVarDecl *)
using SymbolRelation = std::pair<SymbolRef, SymbolRef>;
REGISTER_SET_WITH_PROGRAMSTATE(ProvenLessEqual, SymbolRelation)
REGISTER_SET_WITH_PROGRAMSTATE(ProvenLessThan, SymbolRelation)

/* Persisted, path-sensitive tracking for struct fields carrying a
 * readable_elements/writable_elements-style withtok(family(length))
 * contract (see FieldSpanContract below): fieldSpanContract/assumeFieldSpan
 * only ever read these annotations as a transient snapshot to satisfy an
 * OUTGOING call's precondition -- nothing previously enforced that a
 * struct's pointer field and its paired length field actually stay in
 * agreement with each other as the struct is mutated. A helper that
 * reallocates the pointer field without updating the length field (or vice
 * versa) previously went completely undetected.
 *
 * The two fields are written by two separate statements, not atomically
 * (`lb->v = g; lb->cap = newcap;` in src/util/patch.c, or -- the opposite
 * order -- `out.n = out.cap = pglob->gl_pathc;` before `out.v =
 * __malloc(...)` in src/glob/glob.c), so checking the invariant eagerly at
 * every single write would false-positive on the intermediate state of
 * whichever field is written first. checkBind (below) only records which
 * (aggregate, pointer field, length field) triple was disturbed and by
 * which statement; the actual proof is deferred to checkEndFunction (the
 * same stable point GrantedSpanProof's own deferred check already uses),
 * where both fields necessarily hold their settled values for this
 * update -- a CompoundStmt's own exit was tried first and dropped: Clang's
 * ExprEngine never visits an ordinary `{ ... }` block (function body,
 * if-body, ...) as a Stmt in its own right the way it visits expressions,
 * so check::PostStmt<CompoundStmt> silently never fires for one; only a
 * GNU statement-expression (`({ ... })`) would reach it, which is not
 * this shape. checkEndFunction fires exactly once per path regardless,
 * so it alone is both necessary and sufficient here. The proof itself
 * reuses spanProven exactly as the call-boundary check above does, but
 * against the pointer's real DynamicExtent rather than an unverified
 * assumption.
 *
 * The map's VALUE is a snapshot of both fields, not just a Stmt* to
 * re-read the store from later: liveness-driven dead-binding cleanup
 * (SymbolReaper/ProgramState::cleanupState) is free to discard a struct
 * field's binding once nothing downstream reads it again -- which is
 * exactly the common case for a helper that writes a struct's pointer and
 * length fields and then returns without itself reading either back. A
 * deferred re-read via getLValue/getSVal at checkEndFunction can
 * therefore silently observe Unknown for a field this checker itself
 * just watched get bound (confirmed empirically: an earlier version of
 * this mechanism that deferred the read, not just the proof, saw exactly
 * this). Capturing each write's own new value (the Bind callback's own
 * Value parameter) and the OTHER field's then-current value together, at
 * the moment of the write -- carrying the peer value forward from any
 * earlier snapshot for the same key rather than re-deriving it --
 * sidesteps that pruning entirely: by the time the deferred check runs,
 * both slots already hold whatever was last known, with no further store
 * query required. */
using RecordSpanTouchKey =
    std::pair<std::pair<const MemRegion *, const FieldDecl *>,
             const FieldDecl *>;
using RecordSpanSnapshot =
    std::pair<std::pair<DefinedOrUnknownSVal, DefinedOrUnknownSVal>,
             const Stmt *>;
REGISTER_MAP_WITH_PROGRAMSTATE(TouchedRecordSpan, RecordSpanTouchKey,
                               RecordSpanSnapshot)

namespace {

using spicule::algebra::findTokenSort;
using spicule::algebra::hasQualifier;

enum class MemoryTokenOperation : unsigned char { Require, Grant };

static bool tokenApplication(const FunctionDecl *Function,
                             StringRef Annotation,
                             MemoryTokenOperation &Operation, StringRef &Family,
                             SmallVectorImpl<unsigned> &Arguments) {
  if (Annotation.consume_front("withtok:"))
    Operation = MemoryTokenOperation::Require;
  else if (Annotation.consume_front("grant:"))
    Operation = MemoryTokenOperation::Grant;
  else
    return false;
  if (!Annotation.ends_with(")"))
    return false;
  size_t Open = Annotation.find('(');
  if (Open == StringRef::npos)
    return false;
  Family = Annotation.take_front(Open).trim();
  StringRef Parameters = Annotation.slice(Open + 1, Annotation.size() - 1);
  while (!Parameters.empty()) {
    auto [Name, Rest] = Parameters.split(',');
    Name = Name.trim();
    SmallVector<StringRef, 2> Factors;
    while (!Name.empty()) {
      auto [Factor, Remaining] = Name.split('*');
      Factors.push_back(Factor.trim());
      Name = Remaining;
    }
    if (Factors.size() > 2)
      return false;
    for (StringRef Factor : Factors) {
      bool Found = false;
      for (unsigned Index = 0; Index < Function->getNumParams(); ++Index)
        if (Function->getParamDecl(Index)->getName() == Factor) {
          Arguments.push_back(Index);
          Found = true;
          break;
        }
      if (!Found)
        return false;
      }
    Parameters = Rest;
  }
  return !Family.empty();
}

struct SpanContract {
  MemoryTokenOperation Operation;
  unsigned Pointer;
  unsigned Length;
  unsigned Multiplier;
  uint64_t Scale;
};

struct DisjointContract {
  MemoryTokenOperation Operation;
  unsigned First;
  unsigned Second;
  unsigned Length;
};

static bool operator==(const SpanContract &Left, const SpanContract &Right) {
  return Left.Operation == Right.Operation && Left.Pointer == Right.Pointer &&
         Left.Length == Right.Length && Left.Multiplier == Right.Multiplier &&
         Left.Scale == Right.Scale;
}

static bool operator==(const DisjointContract &Left,
                       const DisjointContract &Right) {
  return Left.Operation == Right.Operation && Left.First == Right.First &&
         Left.Second == Right.Second && Left.Length == Right.Length;
}

static void tokenContracts(const FunctionDecl *Function,
                           SmallVectorImpl<SpanContract> &Spans,
                           SmallVectorImpl<DisjointContract> &Disjoint) {
  if (!Function)
    return;
  for (const FunctionDecl *Redeclaration : Function->redecls()) {
    for (unsigned Pointer = 0; Pointer < Redeclaration->getNumParams();
         ++Pointer) {
      for (const AnnotateAttr *Attribute : Redeclaration->getParamDecl(Pointer)
                                               ->specific_attrs<AnnotateAttr>()) {
        StringRef Family;
        SmallVector<unsigned, 2> Arguments;
        MemoryTokenOperation Operation;
        if (!tokenApplication(Redeclaration, Attribute->getAnnotation(),
                              Operation, Family, Arguments))
          continue;
        const TypedefNameDecl *Token =
            findTokenSort(Function->getASTContext(), Family);
        bool ByteExtent = hasQualifier(Token, "qual:extent_at_least");
        bool ElementExtent = hasQualifier(Token, "qual:element_extent");
        if ((ByteExtent || ElementExtent) &&
            (Arguments.size() == 1 || Arguments.size() == 2)) {
          uint64_t Scale = 1;
          if (ElementExtent) {
            QualType Type = Redeclaration->getParamDecl(Pointer)->getType();
            if (!Type->isPointerType() ||
                Type->getPointeeType()->isIncompleteType())
              continue;
            Scale = Function->getASTContext()
                        .getTypeSizeInChars(Type->getPointeeType())
                        .getQuantity();
          }
          SpanContract Contract{Operation, Pointer, Arguments[0],
                                Arguments.size() == 2
                                    ? Arguments[1]
                                    : std::numeric_limits<unsigned>::max(),
                                Scale};
          if (llvm::find(Spans, Contract) == Spans.end())
            Spans.push_back(Contract);
        }
        if (hasQualifier(Token, "qual:disjoint_extent") &&
            Arguments.size() == 2) {
          DisjointContract Contract{
              Operation, Pointer, Arguments[0], Arguments[1]};
          if (llvm::find(Disjoint, Contract) == Disjoint.end())
            Disjoint.push_back(Contract);
        }
      }
    }
  }
}

static SVal scaledSpanLength(const SpanContract &Contract, SVal Count,
                             SVal Multiplier, ProgramStateRef State,
                             SValBuilder &Builder) {
  if (Count.isUnknownOrUndef())
    return Count;
  if (Contract.Multiplier != std::numeric_limits<unsigned>::max()) {
    if (Multiplier.isUnknownOrUndef())
      return UnknownVal();
    Count = Builder.evalBinOp(State, BO_Mul, Count, Multiplier,
                              Builder.getContext().getSizeType());
  }
  if (Contract.Scale == 1 || Count.isUnknownOrUndef())
    return Count;
  return Builder.evalBinOp(
      State, BO_Mul, Count,
      Builder.makeIntVal(Contract.Scale, Builder.getContext().getSizeType()),
      Builder.getContext().getSizeType());
}

struct FieldSpanContract {
  const MemberExpr *Pointer;
  const FieldDecl *Length;
  uint64_t Scale;
};

static const MemberExpr *pointerMember(const Expr *Expression) {
  if (!Expression)
    return nullptr;
  Expression = Expression->IgnoreParenCasts();
  if (const auto *Member = dyn_cast<MemberExpr>(Expression))
    return Member;
  if (const auto *Binary = dyn_cast<BinaryOperator>(Expression))
    if (Binary->getOpcode() == BO_Add || Binary->getOpcode() == BO_Sub)
      return pointerMember(Binary->getLHS());
  if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(Expression))
    return pointerMember(Subscript->getBase());
  return nullptr;
}

/* Shared by fieldSpanContract (which resolves a POINTER FIELD from an
 * access expression and only ever needed its first matching contract) and
 * collectRecordSpanContracts below (which needs every contract on every
 * field of a record, because a single field can carry more than one
 * withtok(...) -- src/util/patch.c's `struct linebuf`'s `v` field carries
 * both readable_elements(n) and writable_elements(cap)). */
static bool parseFieldSpanAnnotation(StringRef Annotation,
                                     const RecordDecl *Record,
                                     ASTContext &Context, QualType Pointee,
                                     const FieldDecl *&Length,
                                     uint64_t &Scale) {
  if (!Annotation.consume_front("withtok:") || !Annotation.ends_with(")"))
    return false;
  size_t Open = Annotation.find('(');
  if (Open == StringRef::npos)
    return false;
  StringRef Family = Annotation.take_front(Open).trim();
  const TypedefNameDecl *Token = findTokenSort(Context, Family);
  bool ByteExtent = hasQualifier(Token, "qual:extent_at_least");
  bool ElementExtent = hasQualifier(Token, "qual:element_extent");
  if (!ByteExtent && !ElementExtent)
    return false;
  StringRef LengthName =
      Annotation.slice(Open + 1, Annotation.size() - 1).trim();
  Length = nullptr;
  for (const FieldDecl *Candidate : Record->fields())
    if (Candidate->getName() == LengthName) {
      Length = Candidate;
      break;
    }
  if (!Length)
    return false;
  Scale = 1;
  if (ElementExtent) {
    if (Pointee->isIncompleteType())
      return false;
    Scale = Context.getTypeSizeInChars(Pointee).getQuantity();
  }
  return true;
}

static std::optional<FieldSpanContract>
fieldSpanContract(const Expr *Expression, ASTContext &Context) {
  const MemberExpr *Member = pointerMember(Expression);
  const auto *Pointer =
      Member ? dyn_cast<FieldDecl>(Member->getMemberDecl()) : nullptr;
  if (!Pointer || !Pointer->getType()->isPointerType())
    return std::nullopt;
  const RecordDecl *Record = Pointer->getParent();
  for (const AnnotateAttr *Attribute : Pointer->specific_attrs<AnnotateAttr>()) {
    const FieldDecl *Length = nullptr;
    uint64_t Scale = 1;
    if (parseFieldSpanAnnotation(Attribute->getAnnotation(), Record, Context,
                                 Pointer->getType()->getPointeeType(), Length,
                                 Scale))
      return FieldSpanContract{Member, Length, Scale};
  }
  return std::nullopt;
}

struct RecordSpanContract {
  const FieldDecl *Pointer;
  const FieldDecl *Length;
  uint64_t Scale;
};

/* Every readable_elements/writable_elements-style contract on Record's
 * fields, keyed by raw FieldDecl rather than by an access expression --
 * unlike fieldSpanContract above, this supports check::Bind (which only
 * ever gives a written MemRegion, never a source Expr) and returns every
 * contract on a field, not just the first. */
static void collectRecordSpanContracts(
    const RecordDecl *Record, ASTContext &Context,
    SmallVectorImpl<RecordSpanContract> &Out) {
  if (!Record)
    return;
  for (const FieldDecl *Pointer : Record->fields()) {
    if (!Pointer->getType()->isPointerType())
      continue;
    for (const AnnotateAttr *Attribute :
        Pointer->specific_attrs<AnnotateAttr>()) {
      const FieldDecl *Length = nullptr;
      uint64_t Scale = 1;
      if (parseFieldSpanAnnotation(Attribute->getAnnotation(), Record,
                                   Context,
                                   Pointer->getType()->getPointeeType(),
                                   Length, Scale))
        Out.push_back({Pointer, Length, Scale});
    }
  }
}

/* fields_established (see include/ownership.h's own comment for the
 * two-sided contract this implements): true exactly when Parameter
 * carries the bare "fields_established" annotation. Unlike withtok(...)
 * this takes no argument -- the struct type it points to already fully
 * specifies which fields pair via its OWN field-level
 * withtok(readable_elements(...))/withtok(writable_elements(...)). */
static bool hasFieldsEstablished(const ParmVarDecl *Parameter) {
  for (const AnnotateAttr *Attribute : Parameter->specific_attrs<AnnotateAttr>())
    if (Attribute->getAnnotation() == "fields_established")
      return true;
  return false;
}

/* The RecordDecl a fields_established parameter's type points to, or
 * null if Parameter does not carry the annotation or is not shaped like
 * a pointer to a struct. */
static const RecordDecl *fieldsEstablishedRecord(const ParmVarDecl *Parameter) {
  if (!hasFieldsEstablished(Parameter))
    return nullptr;
  QualType Type = Parameter->getType();
  if (!Type->isPointerType())
    return nullptr;
  return Type->getPointeeType()->getAsRecordDecl();
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
      return nullptr;
    SVal Base = C.getSVal(Member->getBase());
    if (!Member->isArrow()) {
      const MemRegion *BaseRegion = carrierRegion(Member->getBase(), C);
      if (!BaseRegion)
        return nullptr;
      Base = loc::MemRegionVal(BaseRegion);
    }
    return C.getState()->getLValue(Field, Base).getAsRegion();
  }
  return nullptr;
}

static const MemberExpr *memberForField(const Expr *Expression,
                                        const FieldDecl *Field) {
  if (!Expression)
    return nullptr;
  Expression = Expression->IgnoreParenCasts();
  if (const auto *Member = dyn_cast<MemberExpr>(Expression))
    return Member->getMemberDecl() == Field ? Member : nullptr;
  if (const auto *Binary = dyn_cast<BinaryOperator>(Expression)) {
    if (const MemberExpr *Left = memberForField(Binary->getLHS(), Field))
      return Left;
    return memberForField(Binary->getRHS(), Field);
  }
  if (const auto *Unary = dyn_cast<UnaryOperator>(Expression))
    return memberForField(Unary->getSubExpr(), Field);
  return nullptr;
}

static std::optional<SVal>
fieldExtentFromLength(const Expr *Expression, const FieldDecl *Field,
                      SVal Value, SValBuilder &Builder) {
  if (!Expression)
    return std::nullopt;
  Expression = Expression->IgnoreParenCasts();
  if (const auto *Member = dyn_cast<MemberExpr>(Expression))
    return Member->getMemberDecl() == Field && !Value.isUnknownOrUndef()
               ? std::optional<SVal>(Value)
               : std::nullopt;
  const auto *Binary = dyn_cast<BinaryOperator>(Expression);
  if (!Binary)
    return std::nullopt;
  bool InLeft = memberForField(Binary->getLHS(), Field);
  bool InRight = memberForField(Binary->getRHS(), Field);
  if (InLeft == InRight)
    return std::nullopt;
  SymbolRef Symbol = Value.getAsSymbol();
  while (const auto *Cast = dyn_cast_or_null<SymbolCast>(Symbol))
    Symbol = Cast->getOperand();
  if (!Symbol)
    return std::nullopt;
  SymbolRef Operand;
  if (const auto *Expression = dyn_cast<SymIntExpr>(Symbol)) {
    if (!InLeft)
      return std::nullopt;
    Operand = Expression->getLHS();
  } else if (const auto *Expression = dyn_cast<IntSymExpr>(Symbol)) {
    if (!InRight)
      return std::nullopt;
    Operand = Expression->getRHS();
  } else if (const auto *Expression = dyn_cast<SymSymExpr>(Symbol)) {
    Operand = InLeft ? Expression->getLHS() : Expression->getRHS();
  } else {
    return std::nullopt;
  }
  return fieldExtentFromLength(InLeft ? Binary->getLHS() : Binary->getRHS(),
                               Field, Builder.makeSymbolVal(Operand), Builder);
}

static bool sameMemberBase(const MemberExpr *Left, const MemberExpr *Right,
                           CheckerContext &C) {
  if (Left->isArrow() != Right->isArrow())
    return false;
  if (Left->isArrow())
    return C.getSVal(Left->getBase()) == C.getSVal(Right->getBase());
  return carrierRegion(Left->getBase(), C) ==
         carrierRegion(Right->getBase(), C);
}

static ProgramStateRef assumeFieldSpan(const Expr *Expression,
                                       const Expr *LengthExpression,
                                       SVal PointerValue,
                                       SVal RequiredLength,
                                       ProgramStateRef State,
                                       CheckerContext &C) {
  std::optional<FieldSpanContract> Contract =
      fieldSpanContract(Expression, C.getASTContext());
  if (!Contract)
    return State;
  std::optional<DefinedOrUnknownSVal> Length;
  if (const MemberExpr *Mention =
          memberForField(LengthExpression, Contract->Length))
    if (sameMemberBase(Contract->Pointer, Mention, C))
      if (std::optional<SVal> Extent = fieldExtentFromLength(
              LengthExpression, Contract->Length, RequiredLength,
              C.getSValBuilder()))
        Length = Extent->getAs<DefinedOrUnknownSVal>();
  if (!Length) {
    SVal Base = C.getSVal(Contract->Pointer->getBase());
    if (!Contract->Pointer->isArrow()) {
      const MemRegion *BaseRegion =
          carrierRegion(Contract->Pointer->getBase(), C);
      if (!BaseRegion)
        return State;
      Base = loc::MemRegionVal(BaseRegion);
    }
    SVal LengthLocation = State->getLValue(Contract->Length, Base);
    std::optional<Loc> LengthLoc = LengthLocation.getAs<Loc>();
    if (!LengthLoc)
      return State;
    Length = State->getSVal(*LengthLoc).getAs<DefinedOrUnknownSVal>();
  }
  const MemRegion *Pointer = PointerValue.getAsRegion();
  while (const auto *Element = dyn_cast_or_null<ElementRegion>(Pointer))
    Pointer = Element->getSuperRegion();
  if (!Length || !Pointer)
    return State;
  SVal Extent = *Length;
  if (Contract->Scale != 1)
    Extent = C.getSValBuilder().evalBinOp(
        State, BO_Mul, Extent,
        C.getSValBuilder().makeIntVal(Contract->Scale,
                                      C.getASTContext().getSizeType()),
        C.getASTContext().getSizeType());
  std::optional<DefinedOrUnknownSVal> DefinedExtent =
      Extent.getAs<DefinedOrUnknownSVal>();
  return DefinedExtent
             ? State->set<AssumedSpanExtent>(Pointer, *DefinedExtent)
             : State;
}

#ifdef SPICULE_MEMORY_CONTRACT_Z3
// A narrow bridge from the range constraint manager (and this checker's own
// ProvenLessEqual/ProvenLessThan relations, see checkBranchCondition above)
// to Z3.  It exists solely to discharge the no-wrap side condition that
// sameSymbolSpanProven's shared-affine-root lemma below otherwise proves
// with SValBuilder::getMaxValue(): that call only ever reports a single
// symbol's own range constraints, so it can never combine a relation
// between two *different* symbolic expressions -- exactly what
// ProvenLessEqual/ProvenLessThan exist to record, precisely because the
// range constraint manager cannot represent it -- with a concrete bound on
// the other side. Encoding both kinds of fact as Z3 bit-vector assertions
// and asking Z3 to refute the wrap event proves what the coarse per-symbol
// range check structurally cannot. A missing translation or an
// inconclusive solver result merely leaves the obligation exactly as
// unproven as it was before this fallback existed; it can never turn an
// UNSAT into a false proof.
class MemoryContractZ3Engine {
public:
  z3::context Context;
  z3::solver Solver;

  MemoryContractZ3Engine() : Solver(Context) {
    // Same budget as SizeCastChecker.cpp's ArithmeticZ3Engine: a generous
    // wall-clock stop only for pathological queries, not a knob ordinary
    // proofs are expected to depend on.
    z3::params Parameters(Context);
    Parameters.set("rlimit", 1000000u);
    Parameters.set("timeout", 2000u);
    Solver.set(Parameters);
  }
};

class MemoryContractZ3Proof {
  z3::context &ZCtx;
  z3::solver &Solver;
  ASTContext &AST;
  spicule::algebra::ScalarSMT Algebra;

  static bool isUnsigned(QualType Type) {
    return Type->isUnsignedIntegerOrEnumerationType();
  }

  spicule::algebra::CType cType(QualType Type) const {
    return {AST.getIntWidth(Type), AST.getIntWidth(Type), isUnsigned(Type)};
  }

  z3::expr bitVector(const llvm::APSInt &Value, unsigned Width) {
    llvm::APInt Bits = Value;
    if (Bits.getBitWidth() < Width)
      Bits = Value.isUnsigned() ? Bits.zext(Width) : Bits.sext(Width);
    else if (Bits.getBitWidth() > Width)
      Bits = Bits.trunc(Width);
    llvm::SmallString<80> Text;
    Bits.toString(Text, 10, false, false);
    return ZCtx.bv_val(Text.c_str(), Width);
  }

  // Deliberately narrower than a general expression translator: this proof
  // only ever needs to reconstruct the plain arithmetic building the root
  // symbol that decomposeAffine/symbolicConstantDifference already
  // isolated, never comparisons or casts. SymbolCast is rejected outright
  // for the same private-FromTy reason SizeCastChecker.cpp's own translator
  // rejects it: Clang 18 does not expose the cast's real source type, so
  // guessing its extension semantics could unsoundly manufacture a proof.
  std::optional<z3::expr> translate(SymbolRef Symbol, unsigned Depth = 0) {
    if (!Symbol || Depth > 24 || Symbol->getType().isNull() ||
        !Symbol->getType()->isIntegerType() || isa<SymbolCast>(Symbol))
      return std::nullopt;
    unsigned Width = AST.getIntWidth(Symbol->getType());
    if (const auto *Data = dyn_cast<SymbolData>(Symbol)) {
      std::string Name = "clang_sym_" + std::to_string(Data->getSymbolID());
      return ZCtx.bv_const(Name.c_str(), Width);
    }
    auto Arithmetic = [&](const z3::expr &Left, const z3::expr &Right,
                          BinaryOperator::Opcode Opcode,
                          QualType OperandType) -> std::optional<z3::expr> {
      if (Left.get_sort().bv_size() != Right.get_sort().bv_size() ||
          (Opcode != BO_Add && Opcode != BO_Sub && Opcode != BO_Mul))
        return std::nullopt;
      spicule::algebra::CType Type = cType(OperandType);
      std::optional<spicule::algebra::SemanticResult> L =
          Algebra.input(Left, Type);
      std::optional<spicule::algebra::SemanticResult> R =
          Algebra.input(Right, Type);
      if (!L || !R)
        return std::nullopt;
      std::optional<spicule::algebra::SemanticResult> Result =
          Opcode == BO_Add    ? Algebra.addConverted(*L, *R)
          : Opcode == BO_Sub  ? Algebra.subtractConverted(*L, *R)
                              : Algebra.multiplyConverted(*L, *R);
      return Result ? std::optional<z3::expr>(Result->Value) : std::nullopt;
    };
    if (const auto *Binary = dyn_cast<SymSymExpr>(Symbol)) {
      QualType LeftType = Binary->getLHS()->getType();
      QualType RightType = Binary->getRHS()->getType();
      if (LeftType.isNull() || RightType.isNull() ||
          AST.getIntWidth(LeftType) != Width ||
          AST.getIntWidth(RightType) != Width ||
          isUnsigned(LeftType) != isUnsigned(Symbol->getType()) ||
          isUnsigned(RightType) != isUnsigned(Symbol->getType()))
        return std::nullopt;
      std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
      std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
      if (!Left || !Right)
        return std::nullopt;
      return Arithmetic(*Left, *Right, Binary->getOpcode(), LeftType);
    }
    if (const auto *Binary = dyn_cast<SymIntExpr>(Symbol)) {
      QualType LeftType = Binary->getLHS()->getType();
      if (LeftType.isNull() || AST.getIntWidth(LeftType) != Width ||
          Binary->getRHS().getBitWidth() != Width ||
          Binary->getRHS().isUnsigned() != isUnsigned(LeftType))
        return std::nullopt;
      std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
      if (!Left)
        return std::nullopt;
      z3::expr Right = bitVector(Binary->getRHS(), Width);
      return Arithmetic(*Left, Right, Binary->getOpcode(), LeftType);
    }
    if (const auto *Binary = dyn_cast<IntSymExpr>(Symbol)) {
      QualType RightType = Binary->getRHS()->getType();
      if (RightType.isNull() || AST.getIntWidth(RightType) != Width ||
          Binary->getLHS().getBitWidth() != Width ||
          Binary->getLHS().isUnsigned() != isUnsigned(RightType))
        return std::nullopt;
      std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
      if (!Right)
        return std::nullopt;
      z3::expr Left = bitVector(Binary->getLHS(), Width);
      return Arithmetic(Left, *Right, Binary->getOpcode(), RightType);
    }
    return std::nullopt;
  }

  void addRange(const z3::expr &Expression, const RangeSet &Ranges) {
    if (!Expression.is_bv() || Ranges.isEmpty() ||
        Expression.get_sort().bv_size() != Ranges.getBitWidth())
      return;
    std::optional<z3::expr> Union;
    for (const Range &R : Ranges) {
      z3::expr From = bitVector(R.From(), Ranges.getBitWidth());
      z3::expr To = bitVector(R.To(), Ranges.getBitWidth());
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

  void addRelation(SymbolRef LeftSymbol, SymbolRef RightSymbol, bool Strict) {
    if (!LeftSymbol || !RightSymbol || LeftSymbol->getType().isNull() ||
        RightSymbol->getType().isNull())
      return;
    std::optional<z3::expr> Left = translate(LeftSymbol);
    std::optional<z3::expr> Right = translate(RightSymbol);
    if (!Left || !Right)
      return;
    std::optional<spicule::algebra::SemanticResult> LeftInput =
        Algebra.input(*Left, cType(LeftSymbol->getType()));
    std::optional<spicule::algebra::SemanticResult> RightInput =
        Algebra.input(*Right, cType(RightSymbol->getType()));
    if (!LeftInput || !RightInput)
      return;
    // less() applies the real C usual-arithmetic-conversion rules via the
    // shared algebra before comparing, exactly as the source comparison
    // that established this relation did.
    std::optional<z3::expr> LessThanRight = Algebra.less(*LeftInput, *RightInput);
    if (!LessThanRight)
      return;
    z3::expr Fact = *LessThanRight;
    if (!Strict) {
      std::optional<z3::expr> RightBeforeLeft =
          Algebra.less(*RightInput, *LeftInput);
      if (!RightBeforeLeft)
        return;
      Fact = !*RightBeforeLeft;
    }
    if (Fact.is_bool())
      Solver.add(Fact);
  }

  // ProvenLessEqual/ProvenLessThan record relations between two distinct
  // symbolic expressions -- exactly what the range constraint manager (and
  // therefore getMaxValue) cannot represent. Asserting them into the same
  // solver as the concrete range facts above is what lets Z3 chain
  // "a <= b" with a concrete bound on b into a bound on a, closing cases
  // the single-symbol getMaxValue() check can never reach.
  void addRelations(ProgramStateRef State) {
    for (const SymbolRelation &Relation : State->get<ProvenLessEqual>())
      addRelation(Relation.first, Relation.second, /*Strict=*/false);
    for (const SymbolRelation &Relation : State->get<ProvenLessThan>())
      addRelation(Relation.first, Relation.second, /*Strict=*/true);
  }

public:
  MemoryContractZ3Proof(MemoryContractZ3Engine &Engine, ProgramStateRef State,
                        ASTContext &AST)
      : ZCtx(Engine.Context), Solver(Engine.Solver), AST(AST),
        Algebra(ZCtx, cType(AST.IntTy), cType(AST.UnsignedIntTy)) {
    Solver.reset();
    for (const auto &Entry : getConstraintMap(State))
      if (std::optional<z3::expr> Expression = translate(Entry.first))
        addRange(*Expression, Entry.second);
    addRelations(State);
  }

  // Proves that `Base + Offset` cannot overflow/wrap BaseType, given every
  // range and relational fact already known on this path. Only an UNSAT
  // wrap event discharges the obligation; SAT, timeout, and every
  // untranslatable shape leave it exactly as unproven as getMaxValue alone
  // left it.
  bool provesNoWrap(SymbolRef Base, QualType BaseType, uint64_t Offset) {
    if (!Base || BaseType.isNull() || !BaseType->isIntegerType())
      return false;
    std::optional<z3::expr> BaseExpr = translate(Base);
    if (!BaseExpr)
      return false;
    unsigned Width = AST.getIntWidth(BaseType);
    if (BaseExpr->get_sort().bv_size() != Width)
      return false;
    spicule::algebra::CType Domain = cType(BaseType);
    std::optional<spicule::algebra::SemanticResult> BaseInput =
        Algebra.input(*BaseExpr, Domain);
    if (!BaseInput)
      return false;
    llvm::APSInt OffsetValue(Width, Domain.Unsigned);
    OffsetValue = Offset;
    std::optional<spicule::algebra::SemanticResult> OffsetInput =
        Algebra.input(bitVector(OffsetValue, Width), Domain);
    if (!OffsetInput)
      return false;
    std::optional<spicule::algebra::SemanticResult> Result =
        Algebra.addConverted(*BaseInput, *OffsetInput);
    if (!Result)
      return false;
    z3::expr Violation = (Domain.Unsigned ? Result->Events.UnsignedWrap
                                          : Result->Events.SignedOverflow)
                             .simplify();
    if (!Violation.is_bool())
      return false;
    Solver.add(Violation);
    return spicule::algebra::provesUnsatisfiable(Solver);
  }

  // Proves Extent's value is never smaller than Length's, from the two
  // symbols' full expression trees -- not just a shared root plus a
  // constant offset the way sameSymbolSpanProven's syntactic checks
  // above require. Those checks can only recognize a shared SymExpr
  // POINTER (Clang's SymbolManager interns identical expressions built
  // from the SAME evalBinOp call, but does not retroactively unify two
  // SEPARATELY-built ones) or an ADD/SUB linear decomposition; a
  // multiplication by a scale factor -- exactly this file's own
  // scaledSpanLength/Contract.Scale shape, needed whenever a
  // readable_elements/writable_elements-scaled length is compared
  // against a DynamicExtent established by a completely separate
  // expression evaluation (the allocating call's own argument, computed
  // once, long before this proof ever runs) -- routinely produces two
  // symbolically-distinct-but-semantically-identical SymIntExpr
  // instances neither of those checks can see through. Translating both
  // through the same bitvector algebra this file already uses for
  // no-wrap proofs sidesteps SymExpr identity entirely: Z3 only sees the
  // resulting bitvector structure, so `sym * 8` proves equal to `sym * 8`
  // regardless of which evalBinOp call built which instance.
  bool provesAtLeast(SymbolRef ExtentSymbol, SymbolRef LengthSymbol) {
    if (!ExtentSymbol || !LengthSymbol || ExtentSymbol->getType().isNull() ||
        LengthSymbol->getType().isNull())
      return false;
    std::optional<z3::expr> ExtentExpr = translate(ExtentSymbol);
    std::optional<z3::expr> LengthExpr = translate(LengthSymbol);
    if (!ExtentExpr || !LengthExpr)
      return false;
    std::optional<spicule::algebra::SemanticResult> ExtentInput =
        Algebra.input(*ExtentExpr, cType(ExtentSymbol->getType()));
    std::optional<spicule::algebra::SemanticResult> LengthInput =
        Algebra.input(*LengthExpr, cType(LengthSymbol->getType()));
    if (!ExtentInput || !LengthInput)
      return false;
    // Prove Extent >= Length by refuting its negation (Extent < Length),
    // the same "assert the violation, ask for UNSAT" shape provesNoWrap
    // and addRelation above both already use.
    std::optional<z3::expr> LessThan = Algebra.less(*ExtentInput, *LengthInput);
    if (!LessThan)
      return false;
    Solver.add(*LessThan);
    return spicule::algebra::provesUnsatisfiable(Solver);
  }

  // Peels exactly one top-level `Root * Scale` (or `Scale * Root`)
  // multiplication off Symbol, where Scale is a compile-time-constant
  // operand -- the exact shape scaledSpanLength/flushRecordSpanObligations
  // (this file's own Contract.Scale multiplication) and
  // declaredReturnSpanExtent's element-count*element-size product both
  // build. A SymbolCast wrapper (if any) is stripped first, matching every
  // other structural match in this file (see MemoryContractChecker::
  // stripCasts's own call sites) -- inlined here rather than shared with
  // that method since it is defined later in the file, on the outer
  // checker class, and this proof class has no access to it.
  static bool decomposeScaledProduct(SymbolRef Symbol, SymbolRef &Root,
                                     llvm::APSInt &Scale) {
    while (const auto *Cast = dyn_cast_or_null<SymbolCast>(Symbol))
      Symbol = Cast->getOperand();
    if (const auto *Product = dyn_cast_or_null<SymIntExpr>(Symbol)) {
      if (Product->getOpcode() != BO_Mul)
        return false;
      Root = Product->getLHS();
      Scale = Product->getRHS();
      return true;
    }
    if (const auto *Product = dyn_cast_or_null<IntSymExpr>(Symbol)) {
      if (Product->getOpcode() != BO_Mul)
        return false;
      Root = Product->getRHS();
      Scale = Product->getLHS();
      return true;
    }
    return false;
  }

  // Proves Root's own product with the compile-time constant Scale cannot
  // overflow/wrap Root's type -- the multiplicative analogue of
  // provesNoWrap above (that one proves a SUM cannot wrap; this one a
  // PRODUCT), needed as provesScaledAtLeast's side obligation below.
  //
  // Scoped with push()/pop() around its own violation assumption: unlike
  // every other prove* method in this class, this one's PURPOSE is to
  // leave a NEW, permanent fact (the negation of that same violation)
  // behind in the Solver for a later query in the same Proof object to
  // build on, not to report a yes/no answer on its own. The assumption
  // used only to refute itself must not linger once it has served that
  // purpose: every method here shares one Solver with no push()/pop() of
  // its own (each free-function wrapper below constructs a fresh Proof,
  // which resets the Solver, and calls exactly one prove* method), so an
  // already-refuted assumption left permanently in place would make every
  // later query against this same Solver trivially UNSAT -- i.e. appear
  // to prove anything -- which is exactly the unsoundness this scoping
  // avoids.
  bool provesNoOverflow(SymbolRef Root, const llvm::APSInt &Scale) {
    if (!Root || Root->getType().isNull() || !Root->getType()->isIntegerType())
      return false;
    std::optional<z3::expr> RootExpr = translate(Root);
    if (!RootExpr)
      return false;
    unsigned Width = AST.getIntWidth(Root->getType());
    if (RootExpr->get_sort().bv_size() != Width)
      return false;
    spicule::algebra::CType Domain = cType(Root->getType());
    std::optional<spicule::algebra::SemanticResult> RootInput =
        Algebra.input(*RootExpr, Domain);
    if (!RootInput)
      return false;
    std::optional<spicule::algebra::SemanticResult> ScaleInput =
        Algebra.input(bitVector(Scale, Width), Domain);
    if (!ScaleInput)
      return false;
    std::optional<spicule::algebra::SemanticResult> Result =
        Algebra.multiplyConverted(*RootInput, *ScaleInput);
    if (!Result)
      return false;
    z3::expr Violation = (Domain.Unsigned ? Result->Events.UnsignedWrap
                                          : Result->Events.SignedOverflow)
                             .simplify();
    if (!Violation.is_bool())
      return false;
    Solver.push();
    Solver.add(Violation);
    bool NoOverflow = spicule::algebra::provesUnsatisfiable(Solver);
    Solver.pop();
    if (!NoOverflow)
      return false;
    Solver.add(!Violation);
    return true;
  }

  // The concrete-Length counterpart to provesAtLeast above: proves
  // ExtentSymbol's value is never smaller than the concrete constant
  // Length. Needed because a SMALL, CONCRETELY-known element count has no
  // SymbolRef at all -- a fully concrete `n + 1` scaled by a compile-time
  // element size folds to a bare nonloc::ConcreteInt, not a SymIntExpr --
  // so provesAtLeast's own `!LengthSymbol` guard rejects it outright
  // before ever reaching Z3.
  //
  // Confirmed via an instrumented, Z3-enabled debug build run against the
  // real tree: src/glob/glob.c's comp_push/pv_push and src/util/patch.c's
  // lb_push all reach flushRecordSpanObligations with a bare CONCRETE
  // scaled length (a small, concretely-unrolled loop trip count) compared
  // against a SYMBOLIC Extent, so provesAtLeast's `!LengthSymbol` guard
  // was rejecting every one of them before this method existed. This
  // method genuinely proves a MINORITY of those occurrences -- whichever
  // exploration paths happen to still carry a directly-attached range
  // fact on the exact scaled expression ExtentSymbol itself (e.g.
  // `(nc_sym * 8) >= 16`), left over from these helpers' own unrelated
  // overflow sanity comparison (`if (oldbytes > bytes) return -1;`,
  // comparing two ALREADY element-size-scaled byte counts) that Clang's
  // native RangeConstraintManager happened to track under that exact
  // compound symbolic identity. It does NOT close the real, reported
  // findings themselves: those come from the MAJORITY of paths -- every
  // push that does NOT re-enter the growth branch at all -- where NOTHING
  // re-establishes any relation between the current (concrete) count and
  // the (symbolic, carried over from an earlier growth call) capacity on
  // that specific path; the invariant is true by construction of the
  // real growth algorithm, but nothing in a single path's own comparisons
  // re-derives it, so there is no fact of any kind -- scaled or unscaled,
  // range or relational -- left for a scaling lemma to work from. See
  // provesScaledAtLeast's own closing comment for the honest full
  // characterization.
  //
  // This needs no separate no-wrap side proof of its own, unlike
  // provesScaledAtLeast below: it translates ExtentSymbol -- whatever its
  // internal structure -- exactly as built, and only ever consults
  // whatever range/relational facts this Proof's constructor already
  // loaded for that exact expression. That is precisely the same
  // "translate the real expression, trust already-established facts
  // about its real wrapped value" contract provesAtLeast (symbol vs.
  // symbol) already relies on with no extra gating; this is only a
  // bare-concrete-RHS extension of it, not a new soundness argument.
  bool provesAtLeastConcrete(SymbolRef ExtentSymbol,
                            const llvm::APSInt &Length) {
    if (!ExtentSymbol || ExtentSymbol->getType().isNull())
      return false;
    std::optional<z3::expr> ExtentExpr = translate(ExtentSymbol);
    if (!ExtentExpr)
      return false;
    spicule::algebra::CType Domain = cType(ExtentSymbol->getType());
    std::optional<spicule::algebra::SemanticResult> ExtentInput =
        Algebra.input(*ExtentExpr, Domain);
    if (!ExtentInput)
      return false;
    std::optional<spicule::algebra::SemanticResult> LengthInput =
        Algebra.input(bitVector(Length, ExtentExpr->get_sort().bv_size()),
                      Domain);
    if (!LengthInput)
      return false;
    std::optional<z3::expr> LessThan = Algebra.less(*ExtentInput, *LengthInput);
    if (!LessThan)
      return false;
    Solver.add(*LessThan);
    return spicule::algebra::provesUnsatisfiable(Solver);
  }

  // Closes the proof gap this file's own field-span enforcement
  // (flushRecordSpanObligations) exposes whenever checkBranchCondition
  // records a relation between the UNSCALED values a source comparison
  // actually compared (e.g. `n + need <= cap`, from a guard shaped like
  // `if (lb->n + need > lb->cap) grow();`), while flushRecordSpanObliga-
  // tions poses the SCALED obligation `(n + need) * K <=
  // DynamicExtent(v)`, K the element size -- comparing an index-space
  // relation against a byte-space extent established by a wholly
  // separate expression (the allocating call's own count*element_size
  // argument). `A <= B` in the WRAPPING bit-vector domain
  // checkBranchCondition recorded does NOT imply `A*K <= B*K` in that
  // same domain merely because it holds as an exact, unbounded-integer
  // relation: B*K can wrap to a value SMALLER than A*K even though the
  // true, unbounded product B*K is the larger one (e.g. A=1, B=2^62, K=8
  // on a 64-bit size_t: A*K=8, but B*K wraps to 0) -- the identical class
  // of bug ValidPointerChecker's own linearExtentProvenInBounds fix
  // (873bf28c) confirmed with a concrete counterexample for the unscaled
  // ADDITIVE case, one multiplication away from this one. The only sound
  // way to close this is a genuine side proof that B*K itself cannot
  // overflow (provesNoOverflow above): once that holds, A*K cannot
  // overflow either (A <= B as true naturals, so A*K <= B*K as true
  // naturals, so A*K's true value already fits since B*K's does), and the
  // wrapped and true products then coincide on BOTH sides, so the wrapped
  // comparison provesAtLeast performs below exactly mirrors the
  // already-known unscaled relation.
  //
  // Verified sound and effective via tools/lint-memory-contract-
  // fixtures/{safe,unsafe}.c's grow_vector_scaled_relation_{bounded,
  // unbounded} pair -- but NOT, it turns out, what closes any of
  // src/glob/glob.c's/src/util/patch.c's real findings: instrumented
  // measurement against the real tree found their relevant length value
  // is always a bare CONCRETE integer (a small, concretely-unrolled loop
  // trip count) by the time it reaches here, never a second scaled
  // symbol this branch could decompose. See provesAtLeastConcrete above
  // for the lemma that DOES apply to their actual shape, and
  // provesScaledAtLeast's own closing comment below for why even that one
  // only closes a minority of them.
  bool provesScaledSymbolAtLeast(SymbolRef ExtentSymbol,
                                 SymbolRef LengthSymbol) {
    SymbolRef ExtentRoot, LengthRoot;
    llvm::APSInt ExtentScale, LengthScale;
    if (!decomposeScaledProduct(ExtentSymbol, ExtentRoot, ExtentScale) ||
        !decomposeScaledProduct(LengthSymbol, LengthRoot, LengthScale) ||
        llvm::APSInt::compareValues(ExtentScale, LengthScale) != 0)
      return false;
    return provesNoOverflow(ExtentRoot, ExtentScale) &&
           provesAtLeast(ExtentSymbol, LengthSymbol);
  }

  // Dispatches to whichever of the two lemmas above fits Length's actual
  // shape: provesScaledSymbolAtLeast when it is itself a second scaled
  // symbol (the shape this whole family of lemmas was originally built
  // to close), or the simpler, unconditionally-sound
  // provesAtLeastConcrete when it is a bare concrete integer -- the shape
  // that turned out to be the real one behind every one of this
  // extension's actual real-tree findings. See each lemma's own comment
  // for why only the symbolic branch needs provesNoOverflow's side proof:
  // a concrete Length is compared directly against whatever facts are
  // already loaded for ExtentSymbol's own exact expression, with no
  // separate relation to scale up in the first place.
  bool provesScaledAtLeast(SymbolRef ExtentSymbol, SVal Length) {
    if (SymbolRef LengthSymbol = Length.getAsSymbol())
      return provesScaledSymbolAtLeast(ExtentSymbol, LengthSymbol);
    if (std::optional<nonloc::ConcreteInt> Concrete =
            Length.getAs<nonloc::ConcreteInt>())
      return provesAtLeastConcrete(ExtentSymbol, Concrete->getValue());
    return false;
  }

  // Honest characterization of what this whole family of lemmas does NOT
  // close, measured directly (an instrumented, Z3-enabled debug build,
  // dumping every ExtentSymbol/LengthSymbol pair and constraint-map entry
  // this Proof ever saw, run against the real src/glob/glob.c and
  // src/util/patch.c): comp_push's, pv_push's, and lb_push's real
  // findings are NOT an unscaled-relation-needs-scaling gap at all. Each
  // push function's growth guard (comp_push/pv_push: `if (cl->n ==
  // cl->cap)`; lb_push: `if (lb->n >= lb->cap)`) only ever re-establishes
  // a used-count/capacity relation on the PATH THAT ACTUALLY GROWS. Every
  // OTHER push -- the common case, and the one every real finding here
  // traces back to -- takes the "no growth needed" branch without any
  // fresh comparison against the (by then already-widened, opaque)
  // capacity symbol at all: comp_push's/pv_push's guard is an EQUALITY
  // test between two symbols, whose FALSE outcome (`n != cap`) yields no
  // ordering fact in either direction, symbolically or via Clang's native
  // range constraints; lb_push's own `>=` guard IS a genuine ordering
  // test, but by the time loop widening has run, the count side is
  // typically a fresh, small CONCRETE trip count while the capacity side
  // is an opaque symbol carried over from an earlier growth call several
  // iterations back, and Clang's range constraint manager attaches the
  // resulting fact (`cap_sym > n_concrete`) as a bare LOWER bound on
  // cap_sym with no upper bound at all -- which is not enough: without
  // ALSO ruling out cap_sym being large enough for cap_sym*K to wrap
  // (provesNoOverflow's own job, and it correctly declines here since no
  // upper bound exists to rule that out), a lower bound alone cannot license
  // the scaled inequality (the identical A=1,B=2^62,K=8 counterexample
  // this file's own commentary already gives applies unchanged whether
  // B's lower bound came from a symbol-vs-symbol relation or a plain
  // symbol-vs-concrete range). The real invariant -- capacity always
  // strictly exceeds the used count -- is true by construction of the
  // growth algorithm itself, procedurally maintained across many
  // iterations, but nothing in any SINGLE path's own comparisons
  // re-derives it once several iterations of widening have passed; no
  // relation-scaling lemma, however sound, has anything to scale when the
  // unscaled fact was never re-established on that path to begin with.
  // Closing this for real would need tracking the growth invariant itself
  // across iterations (e.g. a genuine loop-invariant/widening extension,
  // or a formal postcondition contract on __array_next_capacity/
  // __util_array_capacity's own out-parameter) -- a materially different,
  // larger change than extending the Z3 bridge to scale an
  // already-established relation, and out of this change's scope.

  // Proves Symbol's value is always zero -- needed for exactly the same
  // reason provesAtLeast above is: State->isNull() on a COMPOUND value
  // (e.g. a readable_elements/writable_elements length scaled by this
  // file's own Contract.Scale, `count_symbol * elementSize`) only
  // consults the constraint manager's range fact for that compound
  // symbol ITSELF. Constraining count_symbol == 0 on some path does not
  // retroactively narrow the SEPARATE, already-built `count_symbol * K`
  // symbol's own range -- the two are different symbolic identities to
  // the range constraint manager even though one is derived from the
  // other. Translating through the same bitvector algebra lets Z3 fold
  // the multiplication using the range fact on the underlying factor
  // instead of requiring the compound's OWN range to already say so.
  bool provesZero(SymbolRef Symbol) {
    if (!Symbol || Symbol->getType().isNull())
      return false;
    std::optional<z3::expr> Expr = translate(Symbol);
    if (!Expr)
      return false;
    z3::expr NotZero = *Expr != ZCtx.bv_val(0, Expr->get_sort().bv_size());
    Solver.add(NotZero);
    return spicule::algebra::provesUnsatisfiable(Solver);
  }
};

static MemoryContractZ3Engine &memoryContractZ3Engine() {
  // Static-analyzer callbacks are serial within one translation-unit
  // process; lint.sh provides process parallelism across translation
  // units. Reusing both context and solver avoids repeated Z3
  // initialization, matching SizeCastChecker.cpp's identical engine.
  static thread_local MemoryContractZ3Engine Engine;
  return Engine;
}

static bool noWrapProvenZ3(SymbolRef Base, QualType BaseType, uint64_t Offset,
                           ProgramStateRef State, ASTContext &AST) {
  MemoryContractZ3Proof Proof(memoryContractZ3Engine(), State, AST);
  return Proof.provesNoWrap(Base, BaseType, Offset);
}

static bool spanCoveredZ3(SymbolRef ExtentSymbol, SymbolRef LengthSymbol,
                          ProgramStateRef State, ASTContext &AST) {
  MemoryContractZ3Proof Proof(memoryContractZ3Engine(), State, AST);
  return Proof.provesAtLeast(ExtentSymbol, LengthSymbol);
}

// See MemoryContractZ3Proof::provesScaledAtLeast's own comment: bridges an
// UNSCALED relation or plain range fact (checkBranchCondition's own
// ProvenLessEqual/ProvenLessThan, or Clang's native single-symbol range
// constraint, both already loaded into the Solver by this Proof's own
// constructor) through a shared element-size scale factor, via a genuine
// no-wrap side proof on the extent side's own scaled product. Length is
// passed as a full SVal, not a SymbolRef, so a bare concrete length (no
// SymbolRef at all) can still be handled -- see provesAtLeastConcrete.
static bool scaledSpanCoveredZ3(SymbolRef ExtentSymbol, SVal Length,
                                ProgramStateRef State, ASTContext &AST) {
  MemoryContractZ3Proof Proof(memoryContractZ3Engine(), State, AST);
  return Proof.provesScaledAtLeast(ExtentSymbol, Length);
}

static bool zeroProvenZ3(SymbolRef Symbol, ProgramStateRef State,
                         ASTContext &AST) {
  MemoryContractZ3Proof Proof(memoryContractZ3Engine(), State, AST);
  return Proof.provesZero(Symbol);
}
#endif // SPICULE_MEMORY_CONTRACT_Z3

class MemoryContractChecker
    : public Checker<check::PreCall, check::PostCall, check::BeginFunction,
                     check::EndFunction, check::Bind,
                     check::BranchCondition, check::LiveSymbols> {
  mutable std::unique_ptr<BugType> SpanBT;
  mutable std::unique_ptr<BugType> OverlapBT;
  mutable std::unique_ptr<BugType> TokenBT;
  mutable std::unique_ptr<BugType> RedundantBT;
  mutable std::unique_ptr<BugType> MovableBT;
  mutable std::unique_ptr<BugType> FieldSpanBT;

  static bool hasName(const CallEvent &Call, StringRef Wanted) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    return Function && Function->getIdentifier() &&
           Function->getName() == Wanted;
  }

  static bool isManualProofCall(const FunctionDecl *Function) {
    return Function && Function->getIdentifier() &&
           Function->getName().starts_with("unsafe_assume_");
  }

  /* A pointer-returning function carries its byte extent on the function
   * declaration itself: `withtok(writable_span(size))`.  Interpreting the
   * function-level token as a return-value grant keeps allocator knowledge in
   * headers and stubs; the checker never recognizes an allocator by name. */
  static std::optional<SVal>
  declaredReturnSpanExtent(const FunctionDecl *Function,
                           const CallEvent &Call, CheckerContext &C) {
    if (!Function || !Function->getReturnType()->isPointerType())
      return std::nullopt;
    auto ParameterIndex = [](const FunctionDecl *Declaration,
                             StringRef Name) -> std::optional<unsigned> {
      Name = Name.trim();
      for (unsigned Index = 0; Index < Declaration->getNumParams(); ++Index)
        if (Declaration->getParamDecl(Index)->getName() == Name)
          return Index;
      return std::nullopt;
    };
    for (const FunctionDecl *Redeclaration : Function->redecls())
      for (const AnnotateAttr *Attribute :
           Redeclaration->specific_attrs<AnnotateAttr>()) {
        StringRef Annotation = Attribute->getAnnotation();
        if (!Annotation.consume_front("withtok:") ||
            !Annotation.ends_with(")"))
          continue;
        size_t Open = Annotation.find('(');
        if (Open == StringRef::npos)
          continue;
        StringRef Family = Annotation.take_front(Open).trim();
        const TypedefNameDecl *Token =
            findTokenSort(Function->getASTContext(), Family);
        if (!hasQualifier(Token, "qual:extent_at_least"))
          continue;
        StringRef Expression =
            Annotation.slice(Open + 1, Annotation.size() - 1).trim();
        auto [LeftName, RightName] = Expression.split('*');
        std::optional<unsigned> Left = ParameterIndex(Redeclaration, LeftName);
        if (!Left || *Left >= Call.getNumArgs())
          continue;
        if (RightName.empty())
          return Call.getArgSVal(*Left);
        std::optional<unsigned> Right =
            ParameterIndex(Redeclaration, RightName);
        if (!Right || *Right >= Call.getNumArgs() ||
            RightName.contains('*'))
          continue;
        return C.getSValBuilder().evalBinOp(
            C.getState(), BO_Mul, Call.getArgSVal(*Left),
            Call.getArgSVal(*Right), C.getASTContext().getSizeType());
      }
    return std::nullopt;
  }

  static bool declaredFreshAllocation(const FunctionDecl *Function) {
    if (!Function || !Function->getReturnType()->isPointerType())
      return false;
    for (const FunctionDecl *Redeclaration : Function->redecls())
      for (const AnnotateAttr *Attribute :
           Redeclaration->specific_attrs<AnnotateAttr>()) {
        StringRef Annotation = Attribute->getAnnotation();
        if (!Annotation.consume_front("withtok:"))
          continue;
        StringRef Family = Annotation.split('(').first.trim();
        const TypedefNameDecl *Token =
            findTokenSort(Function->getASTContext(), Family);
        if (hasQualifier(Token, "qual:dynamic_storage"))
          return true;
      }
    return false;
  }

  static SymbolRef stripCasts(SymbolRef Symbol) {
    while (const auto *Cast = dyn_cast_or_null<SymbolCast>(Symbol))
      Symbol = Cast->getOperand();
    return Symbol;
  }

  // The stable identity behind an allocation's SymbolicRegion, for keying
  // AllocatedSpanExtent. A plain `const MemRegion *` key looks stable but
  // is not: SValBuilder hands out a distinct canonical SymbolicRegion per
  // (symbol, memory space) pair (see SymbolicRegion::Profile, which folds
  // in getSuperRegion()), so the SAME conjured symbol gets a DIFFERENT
  // MemRegion object depending on which memory space it is wrapped in at
  // the time of the call -- getSymbolicRegion(sym) (clang's own default
  // conservative call-eval, UnknownSpaceRegion) versus
  // getSymbolicHeapRegion(sym) (clang's builtin unix.Malloc checker,
  // HeapSpaceRegion). Confirmed via a minimal reproduction of this
  // exact struct-pline shape allocated by plain malloc() in a loop
  // (mirroring src/util/patch.c's lb_push()): a debug dump of
  // checkPostCall's own Region across both checkers showed IDENTICAL
  // symbol IDs (e.g. "conj_$11") but printed as "SymRegion{...}" when
  // this checker's own checkPostCall observed it (running before
  // unix.Malloc's, seeing clang's un-rewrapped default) versus
  // "HeapSymRegion{...}" by the time the field write bound the pointer
  // (after unix.Malloc's own checkPostCall rewrapped the identical
  // symbol into its own heap-space region and rebound the call
  // expression to it) -- two distinct MemRegion* values for one real
  // allocation. clang's own core DynamicExtentMap tolerates this because
  // BOTH checkers call setDynamicExtent with the same computed size, so
  // whichever region ends up actually referenced still has a correct
  // entry; this checker's OWN AllocatedSpanExtent copy (kept, per
  // checkLiveSymbols' comment, specifically because the core map's
  // entries do NOT reliably survive to checkEndFunction) has no such
  // second writer, so a key recorded against the stale, discarded region
  // is never found again. Resolving through the underlying symbol
  // instead of the region wrapper fixes this for any such rewrap, not
  // just unix.Malloc's specific one. Returns null for a region with no
  // single underlying symbol (e.g. a VarRegion), which callers already
  // treat as "no fact to record/find" the same way a map miss would be.
  static SymbolRef allocationSymbol(const MemRegion *Region) {
    if (const auto *Symbolic = dyn_cast_or_null<SymbolicRegion>(Region))
      return Symbolic->getSymbol();
    return nullptr;
  }

  // Decompose an SVal into (root symbol, constant offset), i.e. treat it
  // as "root + offset" for a bare symbol (offset 0) or a `root + K`
  // SymIntExpr (offset K). Clang's range-based constraint solver does not
  // fold "(S + K) >= S" for separately-built compound expressions, so the
  // decomposition exposes their common root.  Offset ordering alone is not
  // a proof, however: sameSymbolSpanProven also asks the solver to exclude
  // wrap before using it.
  static bool decomposeAffine(SVal V, SymbolRef &Base, int64_t &Offset) {
    SymbolRef Original = V.getAsSymbol();
    SymbolRef Sym = stripCasts(Original);
    if (!Sym || Sym != Original)
      return false;
    if (const auto *IntExpr = dyn_cast<SymIntExpr>(Sym)) {
      if (IntExpr->getOpcode() != BO_Add)
        return false;
      const llvm::APSInt &Constant = IntExpr->getRHS();
      /* Negative offsets need a corresponding lower-bound/underflow proof,
       * and constants outside int64_t cannot be ordered by Offset below.
       * Neither case occurs in the size expressions this lemma targets. */
      if (Constant.isNegative() || Constant.getActiveBits() > 63)
        return false;
      Base = IntExpr->getLHS();
      if (isa<SymbolCast>(Base))
        return false;
      Offset = static_cast<int64_t>(Constant.getZExtValue());
      return true;
    }
    Base = Sym;
    Offset = 0;
    return true;
  }

  static bool decomposeSignedAffine(SVal V, SymbolRef &Base,
                                    int64_t &Offset) {
    SymbolRef Original = V.getAsSymbol();
    SymbolRef Sym = stripCasts(Original);
    if (!Sym || Sym != Original)
      return false;
    if (const auto *IntExpr = dyn_cast<SymIntExpr>(Sym)) {
      if (IntExpr->getOpcode() != BO_Add &&
          IntExpr->getOpcode() != BO_Sub)
        return false;
      const llvm::APSInt &Constant = IntExpr->getRHS();
      if (Constant.isNegative() || Constant.getActiveBits() > 63)
        return false;
      Base = IntExpr->getLHS();
      if (isa<SymbolCast>(Base))
        return false;
      int64_t Magnitude = static_cast<int64_t>(Constant.getZExtValue());
      Offset = IntExpr->getOpcode() == BO_Add ? Magnitude : -Magnitude;
      return true;
    }
    Base = Sym;
    Offset = 0;
    return true;
  }

  struct LinearSymbolForm {
    std::map<SymbolRef, int64_t> Terms;
    __int128 Constant = 0;
  };

  static bool addLinearSymbol(SymbolRef Symbol, int64_t Sign,
                              LinearSymbolForm &Form) {
    Symbol = stripCasts(Symbol);
    if (!Symbol)
      return false;
    if (const auto *Expression = dyn_cast<SymSymExpr>(Symbol)) {
      if (Expression->getOpcode() != BO_Add &&
          Expression->getOpcode() != BO_Sub)
        goto atomic;
      return addLinearSymbol(Expression->getLHS(), Sign, Form) &&
             addLinearSymbol(Expression->getRHS(),
                             Expression->getOpcode() == BO_Add ? Sign : -Sign,
                             Form);
    }
    if (const auto *Expression = dyn_cast<SymIntExpr>(Symbol)) {
      if (Expression->getOpcode() != BO_Add &&
          Expression->getOpcode() != BO_Sub)
        goto atomic;
      const llvm::APSInt &Value = Expression->getRHS();
      if (!Value.isSignedIntN(64))
        return false;
      Form.Constant += static_cast<__int128>(Sign) * Value.getSExtValue() *
                       (Expression->getOpcode() == BO_Add ? 1 : -1);
      return addLinearSymbol(Expression->getLHS(), Sign, Form);
    }
    if (const auto *Expression = dyn_cast<IntSymExpr>(Symbol)) {
      if (Expression->getOpcode() != BO_Add &&
          Expression->getOpcode() != BO_Sub)
        goto atomic;
      const llvm::APSInt &Value = Expression->getLHS();
      if (!Value.isSignedIntN(64))
        return false;
      Form.Constant += static_cast<__int128>(Sign) * Value.getSExtValue();
      return addLinearSymbol(Expression->getRHS(),
                             Expression->getOpcode() == BO_Add ? Sign : -Sign,
                             Form);
    }
  atomic:
    Form.Terms[Symbol] += Sign;
    return true;
  }

  static std::optional<int64_t> symbolicConstantDifference(SVal Left,
                                                            SVal Right) {
    SymbolRef L = Left.getAsSymbol();
    SymbolRef R = Right.getAsSymbol();
    if (!L || !R)
      return std::nullopt;
    LinearSymbolForm Difference;
    if (!addLinearSymbol(L, 1, Difference) ||
        !addLinearSymbol(R, -1, Difference))
      return std::nullopt;
    for (const auto &[Symbol, Coefficient] : Difference.Terms)
      if (Coefficient != 0)
        return std::nullopt;
    if (Difference.Constant < std::numeric_limits<int64_t>::min() ||
        Difference.Constant > std::numeric_limits<int64_t>::max())
      return std::nullopt;
    return static_cast<int64_t>(Difference.Constant);
  }

  static bool symbolicallyEquivalent(SVal Left, SVal Right) {
    return symbolicConstantDifference(Left, Right) == 0;
  }

  // For a heap allocation whose dynamic extent was set from its own size
  // argument expression, prove a span in-bounds when the length argument
  // shares that same expression's root symbol: `d = __malloc(l + 1);
  // memcpy(d, s, l);` (extent = l+1, length = l) is strndup.c's shape,
  // but `n = strlen(s) + 1; p = __malloc(n); memcpy(p, s, n);` (extent =
  // length = the same compound expression, this tree's own xstrdup) is
  // at least as common, and a bare-symbol match doesn't recognize it.
  // Decomposing both sides into root+offset subsumes the bare-symbol
  // case (offset 0 on the length side) and covers equal-nonzero-offset
  // cases too, subject to the solver-backed no-wrap proof below.
  static bool sameSymbolSpanProven(SVal Extent, SVal Length,
                                   ProgramStateRef State,
                                   CheckerContext &C) {
    SymbolRef ExtentSymbol = Extent.getAsSymbol();
    SymbolRef LengthSymbol = Length.getAsSymbol();
    /* Identical symbolic values compare equal even if their common
     * expression wrapped before reaching this point. */
    if (ExtentSymbol && ExtentSymbol == LengthSymbol)
      return true;
    if (symbolicallyEquivalent(Extent, Length))
      return true;
    if (std::optional<int64_t> Difference =
            symbolicConstantDifference(Extent, Length)) {
      if (*Difference > 0 && LengthSymbol) {
        QualType LengthType = LengthSymbol->getType();
        if (LengthType->isIntegerType()) {
          llvm::APSInt Limit =
              C.getSValBuilder().getBasicValueFactory().getMaxValue(LengthType);
          llvm::APSInt Delta(
              llvm::APInt(Limit.getBitWidth(),
                          static_cast<uint64_t>(*Difference)),
              Limit.isUnsigned());
          Limit -= Delta;
          const llvm::APSInt *Maximum =
              C.getSValBuilder().getMaxValue(State, Length);
          if (Maximum && *Maximum <= Limit)
            return true;
#ifdef SPICULE_MEMORY_CONTRACT_Z3
          // getMaxValue only sees LengthSymbol's own range constraints; it
          // cannot combine a proven relation to another symbol (see
          // MemoryContractZ3Proof's comment above) with that other
          // symbol's own range.  Fall back to a real Z3 proof before
          // giving up on this side condition.
          if (noWrapProvenZ3(LengthSymbol, LengthType,
                             static_cast<uint64_t>(*Difference), State,
                             C.getASTContext()))
            return true;
#endif
        }
      }
    }
    const auto *ExtentProduct = dyn_cast_or_null<SymSymExpr>(ExtentSymbol);
    const auto *LengthProduct = dyn_cast_or_null<SymSymExpr>(LengthSymbol);
    if (ExtentProduct && LengthProduct &&
        ExtentProduct->getOpcode() == BO_Mul &&
        LengthProduct->getOpcode() == BO_Mul) {
      SymbolRef EL = stripCasts(ExtentProduct->getLHS());
      SymbolRef ER = stripCasts(ExtentProduct->getRHS());
      SymbolRef LL = stripCasts(LengthProduct->getLHS());
      SymbolRef LR = stripCasts(LengthProduct->getRHS());
      if ((EL == LL && ER == LR) || (EL == LR && ER == LL))
        return true;
    }
#ifdef SPICULE_MEMORY_CONTRACT_Z3
    // The two structural checks above (a shared SymExpr pointer, and a
    // SymSymExpr*SymSymExpr product with matching factors) both require
    // syntactic identity of at least part of the expression tree. A
    // scale-multiplied length compared against a DynamicExtent that was
    // established by a SEPARATE evalBinOp call over the SAME underlying
    // symbol and constant (this file's own scaledSpanLength/
    // Contract.Scale shape, and MemoryContractChecker's field-span
    // enforcement's Scale multiplication above) produces a SymIntExpr
    // pair (`sym * K` on both sides) that is semantically identical but
    // not the same SymExpr instance, and neither prior check recognizes
    // it. Try a real Z3 proof of Extent >= Length over the full
    // expression trees before falling through to the narrower
    // shared-base/constant-offset check below, which requires exactly
    // the same kind of syntactic base identity this is meant to route
    // around.
    if (spanCoveredZ3(ExtentSymbol, LengthSymbol, State, C.getASTContext()))
      return true;
    // spanCoveredZ3 above only proves Extent >= Length when the two
    // expression trees are otherwise IDENTICAL once translated -- a ring
    // identity, safe under wraparound regardless of whether any relation
    // between distinct subexpressions is even provable (see its own
    // comment). It cannot bridge a genuine INEQUALITY -- either between
    // two DIFFERENT unscaled symbols (checkBranchCondition's own
    // ProvenLessEqual/ProvenLessThan, e.g. `n + need <= cap` from a guard
    // shaped like `if (lb->n + need > lb->cap) grow();`) or between an
    // unscaled symbol and a plain concrete bound (Clang's own native
    // range constraint from a guard where one side was already concrete,
    // e.g. `if (lb->n >= lb->cap)` with `lb->n` still a small concrete
    // loop-trip count) -- through a shared scale factor; that needs the
    // dedicated no-wrap side proof MemoryContractZ3Proof::
    // provesScaledAtLeast performs. Length (the original SVal, not
    // LengthSymbol) is passed through so a bare concrete length -- which
    // has no SymbolRef at all -- is not silently dropped here either.
    if (scaledSpanCoveredZ3(ExtentSymbol, Length, State, C.getASTContext()))
      return true;
#endif
    SymbolRef ExtentBase, LengthBase;
    int64_t ExtentOffset, LengthOffset;
    if (!decomposeAffine(Extent, ExtentBase, ExtentOffset))
      return false;
    if (!decomposeAffine(Length, LengthBase, LengthOffset))
      return false;
    if (ExtentBase != LengthBase || ExtentOffset < LengthOffset)
      return false;
    QualType BaseType = ExtentBase->getType();
    if (!BaseType->isIntegerType())
      return false;
    if (ExtentOffset == LengthOffset)
      return true;

    /* Offset ordering is valid only when the larger addition cannot wrap.
     * Ask the path solver to prove base <= TYPE_MAX - ExtentOffset; a
     * syntactic shared base alone is not enough for unsigned size_t (for
     * example SIZE_MAX + 1 wraps to zero). */
    llvm::APSInt Limit =
        C.getSValBuilder().getBasicValueFactory().getMaxValue(BaseType);
    llvm::APSInt Delta(llvm::APInt(Limit.getBitWidth(), ExtentOffset),
                       Limit.isUnsigned());
    Limit -= Delta;
    const llvm::APSInt *Maximum = C.getSValBuilder().getMaxValue(
        State, C.getSValBuilder().makeSymbolVal(ExtentBase));
    if (Maximum && *Maximum <= Limit)
      return true;
#ifdef SPICULE_MEMORY_CONTRACT_Z3
    // Same fallback as above: getMaxValue(ExtentBase) alone cannot use a
    // proven relation to a different bounded symbol.
    if (noWrapProvenZ3(ExtentBase, BaseType,
                       static_cast<uint64_t>(ExtentOffset), State,
                       C.getASTContext()))
      return true;
#endif
    return false;
  }

  // The allocator-extent lemma above only closes the DESTINATION side of
  // a memcpy's span obligation: most memcpy calls here copy FROM a plain
  // `const char *` with no dynamic extent, so checkPreCall's check on
  // the source argument still fails even after the destination is
  // proven (measured: the tree-wide finding count didn't move after the
  // allocator-extent lemma alone). Almost all of those sources share the
  // "n = strlen(s) + 1; p = __malloc(n); memcpy(p, s, n);" shape (this
  // tree's own xstrdup, strdup.c, strndup.c) or the strnlen()-bounded
  // equivalent. strlen(s)'s byte-count contract makes the source safe by
  // construction: s has at least that many bytes plus the terminator.
  // strnlen(s, n) is looser -- only n (not n+1) bytes are known-safe if
  // it walked all n without finding a terminator -- so this credits it
  // with zero-byte, not one-byte, slack. See the StrlenSource/
  // StrnlenSource ProgramState maps and checkPostCall below.
  static bool stringLengthSourceSpanProven(SVal Pointer, SVal Length,
                                           ProgramStateRef State,
                                           CheckerContext &C) {
    const MemRegion *PointerRegion = Pointer.getAsRegion();
    if (!PointerRegion)
      return false;
    RegionOffset PointerOffset = PointerRegion->getAsOffset();
    if (!PointerOffset.isValid() || PointerOffset.hasSymbolicOffset() ||
        PointerOffset.getOffset() < 0 || PointerOffset.getOffset() % 8 != 0)
      return false;
    auto RelativePointerBytes = [&](const MemRegion *Source)
        -> std::optional<int64_t> {
      RegionOffset SourceOffset = Source->getAsOffset();
      if (!SourceOffset.isValid() || SourceOffset.hasSymbolicOffset() ||
          SourceOffset.getRegion() != PointerOffset.getRegion() ||
          SourceOffset.getOffset() % 8 != 0)
        return std::nullopt;
      int64_t Difference =
          (PointerOffset.getOffset() - SourceOffset.getOffset()) / 8;
      return Difference < 0 ? std::nullopt
                            : std::optional<int64_t>(Difference);
    };
    SymbolRef LengthSym;
    int64_t Slack;
    if (decomposeSignedAffine(Length, LengthSym, Slack)) {
      if (const MemRegion *const *Source = State->get<StrlenSource>(LengthSym))
        if (std::optional<int64_t> Bytes = RelativePointerBytes(*Source))
          if (!(Slack > 0 &&
                *Bytes > std::numeric_limits<int64_t>::max() - Slack) &&
              *Bytes + Slack <= 1)
            return true;
      if (const MemRegion *const *Source =
              State->get<StrnlenSource>(LengthSym))
        if (std::optional<int64_t> Bytes = RelativePointerBytes(*Source))
          if (!(Slack > 0 &&
                *Bytes > std::numeric_limits<int64_t>::max() - Slack) &&
              *Bytes + Slack <= 0)
            return true;
    }

    /* Once a guard proves B <= strlen(P), the unsigned subtraction cannot
     * underflow and strlen(P) - B is necessarily a readable prefix of P. */
    const auto *Difference =
        dyn_cast_or_null<SymSymExpr>(Length.getAsSymbol());
    if (Difference && Difference->getOpcode() == BO_Sub) {
      SymbolRef Measured = stripCasts(Difference->getLHS());
      SymbolRef Removed = stripCasts(Difference->getRHS());
      const MemRegion *const *Source = State->get<StrlenSource>(Measured);
      if (Source && RelativePointerBytes(*Source) == 0) {
        SVal NoUnderflow = C.getSValBuilder().evalBinOp(
            State, BO_GE, C.getSValBuilder().makeSymbolVal(Measured),
            C.getSValBuilder().makeSymbolVal(Removed),
            C.getSValBuilder().getConditionType());
        std::optional<DefinedOrUnknownSVal> Condition =
            NoUnderflow.getAs<DefinedOrUnknownSVal>();
        if (Condition && !State->assume(*Condition, false))
          return true;
      }
    }

    SymbolRef Bounded = stripCasts(Length.getAsSymbol());
    if (!Bounded)
      return false;
    auto RelationProvesStringBound = [&](SymbolRef Candidate) {
      for (const SymbolRelation &Relation : State->get<ProvenLessEqual>()) {
        if (stripCasts(Relation.first) != Candidate)
          continue;
        SymbolRef Bound = stripCasts(Relation.second);
        const MemRegion *const *Strlen = State->get<StrlenSource>(Bound);
        const MemRegion *const *Strnlen = State->get<StrnlenSource>(Bound);
        if ((Strlen || Strnlen) &&
            RelativePointerBytes(Strlen ? *Strlen : *Strnlen) == 0)
          return true;
      }
      return false;
    };
    if (RelationProvesStringBound(Bounded))
      return true;
    if (const auto *DifferenceLength = dyn_cast<SymIntExpr>(Bounded)) {
      if (DifferenceLength->getOpcode() != BO_Sub ||
          DifferenceLength->getRHS().isNegative())
        return false;
      SymbolRef Base = stripCasts(DifferenceLength->getLHS());
      SVal NoUnderflow = C.getSValBuilder().evalBinOp(
          State, BO_GE, C.getSValBuilder().makeSymbolVal(Base),
          C.getSValBuilder().makeIntVal(DifferenceLength->getRHS()),
          C.getSValBuilder().getConditionType());
      std::optional<DefinedOrUnknownSVal> Condition =
          NoUnderflow.getAs<DefinedOrUnknownSVal>();
      if (!Condition || State->assume(*Condition, false))
        return false;
      Bounded = Base;
    }
    return RelationProvesStringBound(Bounded);
  }

  static std::optional<SVal>
  callerArgumentValue(unsigned Argument, ProgramStateRef State,
                      const LocationContext *Context) {
    const auto *Frame = dyn_cast_or_null<StackFrameContext>(Context);
    if (!Frame || Frame->inTopFrame())
      return std::nullopt;
    const auto *Call = dyn_cast_or_null<CallExpr>(Frame->getCallSite());
    if (!Call || Argument >= Call->getNumArgs())
      return std::nullopt;
    SVal Value = State->getSVal(Call->getArg(Argument), Frame->getParent());
    return Value.isUnknownOrUndef() ? std::nullopt
                                    : std::optional<SVal>(Value);
  }

public:
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    const auto *Comparison = dyn_cast<BinaryOperator>(Condition);
    if (!Comparison || !Comparison->isComparisonOp())
      return;
    ProgramStateRef State = C.getState();
    bool IsTrue =
        State->isNonNull(C.getSVal(Condition)).isConstrainedTrue();
    bool IsFalse = State->isNull(C.getSVal(Condition)).isConstrainedTrue();
    if (!IsTrue && !IsFalse)
      return;
    SymbolRef Left = C.getSVal(Comparison->getLHS()).getAsSymbol();
    SymbolRef Right = C.getSVal(Comparison->getRHS()).getAsSymbol();
    if (!Left || !Right)
      return;
    bool LeftLessEqual =
        (IsTrue && (Comparison->getOpcode() == BO_LE ||
                    Comparison->getOpcode() == BO_LT)) ||
        (IsFalse && (Comparison->getOpcode() == BO_GT ||
                     Comparison->getOpcode() == BO_GE));
    bool RightLessEqual =
        (IsTrue && (Comparison->getOpcode() == BO_GE ||
                    Comparison->getOpcode() == BO_GT)) ||
        (IsFalse && (Comparison->getOpcode() == BO_LT ||
                     Comparison->getOpcode() == BO_LE));
    if (LeftLessEqual)
      State = State->add<ProvenLessEqual>({Left, Right});
    if (RightLessEqual)
      State = State->add<ProvenLessEqual>({Right, Left});
    bool LeftLessThan =
        (IsTrue && Comparison->getOpcode() == BO_LT) ||
        (IsFalse && Comparison->getOpcode() == BO_GE);
    bool RightLessThan =
        (IsTrue && Comparison->getOpcode() == BO_GT) ||
        (IsFalse && Comparison->getOpcode() == BO_LE);
    if (LeftLessThan)
      State = State->add<ProvenLessThan>({Left, Right});
    if (RightLessThan)
      State = State->add<ProvenLessThan>({Right, Left});
    if (State != C.getState())
      C.addTransition(State);
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

  void report(StringRef Reason, BugType *&Type, const CallEvent &Call,
              ProgramStateRef State, CheckerContext &C) const {
    const Stmt *Statement = Call.getOriginExpr();
    if (!Statement)
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!Type) {
      StringRef Title = "Unproven memory overlap";
      if (Reason == "memory operation span is not proven valid")
        Title = "Unproven memory span";
      else if (Reason == "manual memory proof axiom is redundant")
        Title = "Redundant memory proof axiom";
      else if (Reason == "manual memory proof axiom can be narrowed")
        Title = "Overbroad memory proof axiom";
      std::unique_ptr<BugType> New = std::make_unique<BugType>(
          this, Title, categories::MemoryError);
      Type = New.release();
    }
    const SourceManager &SM = C.getSourceManager();
    std::string Message =
        (Reason + "; origin '" +
         SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())) +
         "'; context '" + context(C) + "'; expression '" + text(Statement, C) +
         "'; site '" + site(Statement, C) + "'")
            .str();
    auto Report =
        std::make_unique<PathSensitiveBugReport>(*Type, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  void reportToken(StringRef Reason, const Stmt *Statement,
                   ProgramStateRef State, CheckerContext &C) const {
    if (!Statement)
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!TokenBT)
      TokenBT = std::make_unique<BugType>(this,
                                          "Unproven memory token contract",
                                          categories::MemoryError);
    const SourceManager &SM = C.getSourceManager();
    std::string Message =
        (Reason + "; origin '" +
         SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())) +
         "'; context '" + context(C) + "'; expression '" + text(Statement, C) +
         "'; site '" + site(Statement, C) + "'")
            .str();
    auto Report =
        std::make_unique<PathSensitiveBugReport>(*TokenBT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  void reportFieldSpan(StringRef Reason, const Stmt *Statement,
                       ProgramStateRef State, CheckerContext &C) const {
    if (!Statement)
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!FieldSpanBT)
      FieldSpanBT = std::make_unique<BugType>(
          this, "Unproven paired field span", categories::MemoryError);
    const SourceManager &SM = C.getSourceManager();
    std::string Message =
        (Reason + "; origin '" +
         SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())) +
         "'; context '" + context(C) + "'; expression '" + text(Statement, C) +
         "'; site '" + site(Statement, C) + "'")
            .str();
    auto Report =
        std::make_unique<PathSensitiveBugReport>(*FieldSpanBT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  bool spanProven(SVal Pointer, SVal Length, ProgramStateRef State,
                  CheckerContext &C, bool UseAssumedSpans = true) const {
    if (State->isNull(Length).isConstrainedTrue())
      return true;
#ifdef SPICULE_MEMORY_CONTRACT_Z3
    // isNull() only consults the constraint manager's own range fact for
    // Length's exact symbolic identity. A scaled length built via this
    // file's own Contract.Scale multiplication (count_symbol * elemSize)
    // is a DIFFERENT symbol than count_symbol itself, so constraining
    // count_symbol == 0 on some path does not automatically narrow the
    // already-built product's own range -- see MemoryContractZ3Proof::
    // provesZero's comment. zero_vacuous's whole point is that a
    // genuinely zero-length operation needs no span proof at all, so
    // this is worth a real Z3 attempt before falling through to the
    // extent-based checks below, which cannot help when Pointer itself
    // never got a real extent (the common case for zero_vacuous's own
    // "operation trivially skipped" shape).
    if (SymbolRef LengthSymbol = Length.getAsSymbol())
      if (zeroProvenZ3(LengthSymbol, State, C.getASTContext()))
        return true;
#endif
    auto ExtentProvesLength = [&](SVal Extent) {
      if (Extent.isUnknownOrUndef() || Length.isUnknownOrUndef())
        return false;
      if (sameSymbolSpanProven(Extent, Length, State, C))
        return true;
      SymbolRef ExtentSymbol = stripCasts(Extent.getAsSymbol());
      SymbolRef LengthSymbol = stripCasts(Length.getAsSymbol());
      if (ExtentSymbol && LengthSymbol) {
        if (State->contains<ProvenLessEqual>({LengthSymbol, ExtentSymbol}))
          return true;
        /* A strict upper bound is stronger than the non-strict bound a
         * span requires.  BranchCondition records `length < remaining`
         * separately (notably from the false edge of
         * `if (length >= remaining) return`), so retain that proof here
         * instead of requiring source code to spell the equivalent `>`
         * guard merely for the analyzer. */
        if (State->contains<ProvenLessThan>({LengthSymbol, ExtentSymbol}))
          return true;
        if (const auto *OffsetLength = dyn_cast<SymIntExpr>(LengthSymbol))
          if (OffsetLength->getOpcode() == BO_Add &&
              !OffsetLength->getRHS().isNegative() &&
              OffsetLength->getRHS().getLimitedValue() == 1 &&
              State->contains<ProvenLessThan>(
                  {stripCasts(OffsetLength->getLHS()), ExtentSymbol}))
            return true;
        if (const auto *Shorter = dyn_cast<SymIntExpr>(LengthSymbol))
          if (Shorter->getOpcode() == BO_Sub &&
              !Shorter->getRHS().isNegative() &&
              stripCasts(Shorter->getLHS()) == ExtentSymbol) {
            SVal NoUnderflow = C.getSValBuilder().evalBinOp(
                State, BO_GE,
                C.getSValBuilder().makeSymbolVal(ExtentSymbol),
                C.getSValBuilder().makeIntVal(Shorter->getRHS()),
                C.getSValBuilder().getConditionType());
            std::optional<DefinedOrUnknownSVal> Condition =
                NoUnderflow.getAs<DefinedOrUnknownSVal>();
            if (Condition && !State->assume(*Condition, false))
              return true;
          }
      }
      SVal Enough = C.getSValBuilder().evalBinOp(
          State, BO_GE, Extent, Length,
          C.getSValBuilder().getConditionType());
      std::optional<DefinedOrUnknownSVal> Condition =
          Enough.getAs<DefinedOrUnknownSVal>();
      return Condition && !State->assume(*Condition, false);
    };
    if (UseAssumedSpans)
      if (const MemRegion *Region = Pointer.getAsRegion())
        if (const DefinedOrUnknownSVal *Assumed =
                State->get<AssumedSpanExtent>(Region))
          if (ExtentProvesLength(*Assumed))
            return true;
    if (UseAssumedSpans)
      if (const auto *Element =
              dyn_cast_or_null<ElementRegion>(Pointer.getAsRegion()))
        {
          const DefinedOrUnknownSVal *BaseExtent =
              State->get<AssumedSpanExtent>(Element->getSuperRegion());
          if (!BaseExtent)
            if (SymbolRef Symbol = allocationSymbol(
                    Element->getSuperRegion()->getBaseRegion()))
              BaseExtent = State->get<AllocatedSpanExtent>(Symbol);
          if (BaseExtent) {
          SVal ElementBytes = getElementExtent(Element->getElementType(),
                                               C.getSValBuilder());
          SVal Offset = Element->getIndex();
          const llvm::APSInt *KnownElementBytes =
              C.getSValBuilder().getKnownValue(State, ElementBytes);
          if (!KnownElementBytes || KnownElementBytes->getZExtValue() != 1)
            Offset = C.getSValBuilder().evalBinOp(
                State, BO_Mul, Offset, ElementBytes,
                C.getASTContext().getSizeType());
          SVal OffsetFits = C.getSValBuilder().evalBinOp(
              State, BO_GE, *BaseExtent, Offset,
              C.getSValBuilder().getConditionType());
          std::optional<DefinedOrUnknownSVal> Fits =
              OffsetFits.getAs<DefinedOrUnknownSVal>();
          if (Fits && !State->assume(*Fits, false)) {
            SVal Remaining = C.getSValBuilder().evalBinOp(
                State, BO_Sub, *BaseExtent, Offset,
                C.getASTContext().getSizeType());
            if (ExtentProvesLength(Remaining))
              return true;
          }
        }
        }
    SVal Extent = getDynamicExtentWithOffset(State, Pointer);
    if (Extent.isUnknownOrUndef() || Length.isUnknownOrUndef())
      return false;
    if (sameSymbolSpanProven(Extent, Length, State, C))
      return true;
    if (stringLengthSourceSpanProven(Pointer, Length, State, C))
      return true;
    return ExtentProvesLength(Extent);
  }

  bool typedObjectSpanProven(const Expr *PointerExpression,
                             const Expr *LengthExpression, SVal Length,
                             ProgramStateRef State, CheckerContext &C,
                             bool RequireConstantLength = false) const {
    if (!PointerExpression || Length.isUnknownOrUndef())
      return false;
    const Expr *Object = PointerExpression->IgnoreParenCasts();
    QualType ObjectType = Object->getType();
    QualType ExtentType;
    if (const auto *Address = dyn_cast<UnaryOperator>(Object);
        Address && Address->getOpcode() == UO_AddrOf) {
      Object = Address->getSubExpr()->IgnoreParenImpCasts();
      ExtentType = Object->getType();
    } else if (ObjectType->isArrayType()) {
      ExtentType = ObjectType;
    } else {
      if (!isa<DeclRefExpr>(Object) && !isa<MemberExpr>(Object))
        return false;
      if (!ObjectType->isPointerType())
        return false;
      ExtentType = ObjectType->getPointeeType();
    }
    if (ExtentType.isNull() || ExtentType->isVoidType() ||
        ExtentType->isFunctionType() || ExtentType->isIncompleteType() ||
        ExtentType->isVariableArrayType())
      return false;
    CharUnits Bytes = C.getASTContext().getTypeSizeInChars(ExtentType);
    if (RequireConstantLength) {
      Expr::EvalResult Result;
      if (!LengthExpression ||
          !LengthExpression->EvaluateAsInt(Result, C.getASTContext()))
        return false;
      const llvm::APSInt &Constant = Result.Val.getInt();
      return !Constant.isNegative() && Constant.getActiveBits() <= 64 &&
             Constant.getZExtValue() <=
                 static_cast<uint64_t>(Bytes.getQuantity());
    }
    SVal Extent = C.getSValBuilder().makeIntVal(
        static_cast<uint64_t>(Bytes.getQuantity()),
        C.getASTContext().getSizeType());
    SVal Enough = C.getSValBuilder().evalBinOp(
        State, BO_GE, Extent, Length,
        C.getSValBuilder().getConditionType());
    std::optional<DefinedOrUnknownSVal> Condition =
        Enough.getAs<DefinedOrUnknownSVal>();
    return Condition && !State->assume(*Condition, false);
  }

  bool typedDisjointSpanProven(const Expr *FirstExpression,
                               const Expr *SecondExpression,
                               const Expr *LengthExpression,
                               CheckerContext &C) const {
    if (!FirstExpression || !SecondExpression || !LengthExpression)
      return false;
    const auto *First = dyn_cast<DeclRefExpr>(
        FirstExpression->IgnoreParenCasts());
    const auto *Second = dyn_cast<DeclRefExpr>(
        SecondExpression->IgnoreParenCasts());
    if (!First || !Second || First->getDecl() == Second->getDecl() ||
        !First->getType()->isArrayType() ||
        !Second->getType()->isArrayType() ||
        First->getType()->isVariableArrayType() ||
        Second->getType()->isVariableArrayType())
      return false;
    Expr::EvalResult Result;
    if (!LengthExpression->EvaluateAsInt(Result, C.getASTContext()))
      return false;
    const llvm::APSInt &Length = Result.Val.getInt();
    if (Length.isNegative() || Length.getActiveBits() > 64)
      return false;
    uint64_t Bytes = Length.getZExtValue();
    return Bytes <= static_cast<uint64_t>(
                        C.getASTContext().getTypeSizeInChars(First->getType())
                            .getQuantity()) &&
           Bytes <= static_cast<uint64_t>(
                        C.getASTContext().getTypeSizeInChars(Second->getType())
                            .getQuantity());
  }

  static const ValueDecl *rootRestrictedPointer(const Expr *Expression) {
    if (!Expression)
      return nullptr;
    Expression = Expression->IgnoreParenCasts();
    if (const auto *Reference = dyn_cast<DeclRefExpr>(Expression))
      if (const auto *Value = dyn_cast<ValueDecl>(Reference->getDecl()))
        return Value;
    if (const auto *Binary = dyn_cast<BinaryOperator>(Expression))
      if (Binary->getOpcode() == BO_Add || Binary->getOpcode() == BO_Sub)
        return rootRestrictedPointer(Binary->getLHS());
    if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(Expression))
      return rootRestrictedPointer(Subscript->getBase());
    if (const auto *Member = dyn_cast<MemberExpr>(Expression))
      return rootRestrictedPointer(Member->getBase());
    if (const auto *Address = dyn_cast<UnaryOperator>(Expression))
      if (Address->getOpcode() == UO_AddrOf)
        return rootRestrictedPointer(Address->getSubExpr());
    return nullptr;
  }

  static bool restrictDisjointSpanProven(const Expr *FirstExpression,
                                         const Expr *SecondExpression,
                                         SVal First, SVal Second) {
    const ValueDecl *A = rootRestrictedPointer(FirstExpression);
    const ValueDecl *B = rootRestrictedPointer(SecondExpression);
    if ((!A || !A->getType().isRestrictQualified()) &&
        (!B || !B->getType().isRestrictQualified()))
      return false;
    const MemRegion *FirstRegion = First.getAsRegion();
    const MemRegion *SecondRegion = Second.getAsRegion();
    if (!FirstRegion || !SecondRegion)
      return false;
    RegionOffset FirstOffset = FirstRegion->getAsOffset();
    RegionOffset SecondOffset = SecondRegion->getAsOffset();
    return FirstOffset.isValid() && SecondOffset.isValid() &&
           FirstOffset.getRegion() != SecondOffset.getRegion();
  }

  bool derivedContractSpanProven(SVal Pointer, SVal Length,
                                 ProgramStateRef State,
                                 CheckerContext &C) const {
    const auto *Element =
        dyn_cast_or_null<ElementRegion>(Pointer.getAsRegion());
    if (!Element)
      return false;
    const auto *CurrentFunction = dyn_cast_or_null<FunctionDecl>(
        C.getLocationContext()->getDecl());
    if (!CurrentFunction)
      return false;
    SmallVector<SpanContract, 2> Spans;
    SmallVector<DisjointContract, 1> Disjoint;
    tokenContracts(CurrentFunction, Spans, Disjoint);
    std::optional<DefinedOrUnknownSVal> Extent;
    if (const DefinedOrUnknownSVal *Assumed =
            State->get<AssumedSpanExtent>(Element->getSuperRegion()))
      Extent = *Assumed;
    for (const SpanContract &Contract : Spans) {
      if (Extent)
        break;
      if (Contract.Operation != MemoryTokenOperation::Require)
        continue;
      const ParmVarDecl *PointerParameter =
          CurrentFunction->getParamDecl(Contract.Pointer);
      const MemRegion *Base = State->getSVal(
          State->getLValue(PointerParameter, C.getLocationContext()))
                                  .getAsRegion();
      if (!Base || Element->getSuperRegion()->getBaseRegion() !=
                       Base->getBaseRegion())
        continue;
      const ParmVarDecl *LengthParameter =
          CurrentFunction->getParamDecl(Contract.Length);
      SVal LengthValue = callerArgumentValue(
          Contract.Length, State, C.getLocationContext()).value_or(
          State->getSVal(
              State->getLValue(LengthParameter, C.getLocationContext())));
      SVal Multiplier = UnknownVal();
      if (Contract.Multiplier != std::numeric_limits<unsigned>::max()) {
        const ParmVarDecl *Parameter =
            CurrentFunction->getParamDecl(Contract.Multiplier);
        Multiplier = callerArgumentValue(
            Contract.Multiplier, State, C.getLocationContext()).value_or(
            State->getSVal(
                State->getLValue(Parameter, C.getLocationContext())));
      }
      LengthValue = scaledSpanLength(Contract, LengthValue, Multiplier, State,
                                     C.getSValBuilder());
      Extent = LengthValue.getAs<DefinedOrUnknownSVal>();
      break;
    }
    if (!Extent || Length.isUnknownOrUndef())
      return false;
    SVal Offset = Element->getIndex();
    SVal ElementBytes =
        getElementExtent(Element->getElementType(), C.getSValBuilder());
    const llvm::APSInt *KnownElementBytes =
        C.getSValBuilder().getKnownValue(State, ElementBytes);
    if (!KnownElementBytes || KnownElementBytes->getZExtValue() != 1)
      Offset = C.getSValBuilder().evalBinOp(
          State, BO_Mul, Offset, ElementBytes,
          C.getASTContext().getSizeType());
    SVal Remaining = C.getSValBuilder().evalBinOp(
        State, BO_Sub, *Extent, Offset, C.getASTContext().getSizeType());
    for (const SymbolRelation &Relation : State->get<ProvenLessEqual>()) {
      SVal Smaller = C.getSValBuilder().makeSymbolVal(Relation.first);
      SVal Larger = C.getSValBuilder().makeSymbolVal(Relation.second);
      if (symbolicallyEquivalent(Length, Smaller) &&
          symbolicallyEquivalent(Remaining, Larger))
        return true;
    }
    SVal Enough = C.getSValBuilder().evalBinOp(
        State, BO_GE, Remaining, Length,
        C.getSValBuilder().getConditionType());
    std::optional<DefinedOrUnknownSVal> Condition =
        Enough.getAs<DefinedOrUnknownSVal>();
    if (Condition && !State->assume(*Condition, false))
      return true;
    SymbolRef RemainingSymbol = Remaining.getAsSymbol();
    SymbolRef LengthSymbol = Length.getAsSymbol();
    if (!RemainingSymbol || !LengthSymbol)
      return false;
    if (State->contains<ProvenLessEqual>({LengthSymbol, RemainingSymbol}))
      return true;
    if (State->contains<ProvenLessThan>({LengthSymbol, RemainingSymbol}))
      return true;
    SymbolRef DynamicRemaining =
        getDynamicExtentWithOffset(State, Pointer).getAsSymbol();
    if (DynamicRemaining) {
      const auto *DynamicDifference = dyn_cast<IntSymExpr>(DynamicRemaining);
      for (const SymbolRelation &Relation : State->get<ProvenLessEqual>()) {
        const auto *BoundDifference = dyn_cast<IntSymExpr>(Relation.second);
        if (Relation.first == LengthSymbol && DynamicDifference &&
            BoundDifference && DynamicDifference->getOpcode() == BO_Sub &&
            BoundDifference->getOpcode() == BO_Sub &&
            DynamicDifference->getRHS() == BoundDifference->getRHS() &&
            llvm::APSInt::compareValues(DynamicDifference->getLHS(),
                                        BoundDifference->getLHS()) == 0)
          return true;
      }
    }
    SymbolRef ExtentSymbol = Extent->getAsSymbol();
    SymbolRef OffsetSymbol = Offset.getAsSymbol();
    if (!OffsetSymbol)
      return false;
    for (const SymbolRelation &Relation : State->get<ProvenLessEqual>()) {
      if (Relation.first != LengthSymbol)
        continue;
      const auto *Difference = dyn_cast<SymSymExpr>(Relation.second);
      if (ExtentSymbol && Difference && Difference->getOpcode() == BO_Sub &&
          Difference->getRHS() == OffsetSymbol) {
        SymbolRef Minuend = Difference->getLHS();
        if (Minuend == ExtentSymbol)
          return true;
      }
      const auto *ConstantDifference = dyn_cast<IntSymExpr>(Relation.second);
      const llvm::APSInt *KnownExtent =
          C.getSValBuilder().getKnownValue(State, *Extent);
      if (!KnownExtent || !ConstantDifference ||
          ConstantDifference->getOpcode() != BO_Sub ||
          ConstantDifference->getRHS() != OffsetSymbol ||
          llvm::APSInt::compareValues(ConstantDifference->getLHS(),
                                      *KnownExtent) > 0)
        continue;
      SVal OffsetWithinBound = C.getSValBuilder().evalBinOp(
          State, BO_LE, Offset,
          C.getSValBuilder().makeIntVal(ConstantDifference->getLHS()),
          C.getSValBuilder().getConditionType());
      std::optional<DefinedOrUnknownSVal> Within =
          OffsetWithinBound.getAs<DefinedOrUnknownSVal>();
      if (Within && !State->assume(*Within, false))
        return true;
    }
    return false;
  }

  bool overlapProven(SVal First, SVal Second, SVal Length,
                     ProgramStateRef State, CheckerContext &C,
                     bool UseAssumedSpans = true) const {
    if (State->isNull(Length).isConstrainedTrue())
      return true;
    const MemRegion *A = First.getAsRegion();
    const MemRegion *B = Second.getAsRegion();
    if (!A || !B)
      return false;
    if (UseAssumedSpans)
      if (const DefinedOrUnknownSVal *Assumed =
              State->get<AssumedDisjointExtent>({A, B})) {
        SVal Enough = C.getSValBuilder().evalBinOp(
            State, BO_GE, *Assumed, Length,
            C.getSValBuilder().getConditionType());
        if (std::optional<DefinedOrUnknownSVal> Condition =
                Enough.getAs<DefinedOrUnknownSVal>())
          if (!State->assume(*Condition, false))
            return true;
      }
    RegionOffset AO = A->getAsOffset();
    RegionOffset BO = B->getAsOffset();
    if (!AO.isValid() || !BO.isValid())
      return false;
    if (AO.getRegion() != BO.getRegion()) {
      /* Two symbolic pointer parameters may still alias even though Clang
       * represents their pointees with distinct SymbolicRegions.  Distinct
       * concrete storage objects (separate locals/globals) cannot overlap;
       * distinct symbolic roots alone are not such a proof. */
      if (AO.getRegion()->getMemorySpace() != BO.getRegion()->getMemorySpace())
        return true;
      auto IsFreshAllocation = [&](const MemRegion *Region) {
        const MemRegion *Base = Region->getBaseRegion();
        for (const MemRegion *Allocated :
             State->get<AllocatedBaseRegion>())
          if (Allocated == Region || Allocated == Base ||
              Allocated->getBaseRegion() == Base)
            return true;
        return false;
      };
      if (IsFreshAllocation(AO.getRegion()) ||
          IsFreshAllocation(BO.getRegion()))
        return true;
      if (isa<SymbolicRegion>(AO.getRegion()) ||
          isa<SymbolicRegion>(BO.getRegion()))
        return false;
      return true;
    }
    if (AO.hasSymbolicOffset() || BO.hasSymbolicOffset())
      return false;
    const llvm::APSInt *KnownLength =
        C.getSValBuilder().getKnownValue(State, Length);
    if (!KnownLength)
      return false;
    uint64_t Bytes = KnownLength->getLimitedValue();
    int64_t ABytes = AO.getOffset() / 8;
    int64_t BBytes = BO.getOffset() / 8;
    return ABytes + static_cast<int64_t>(Bytes) <= BBytes ||
           BBytes + static_cast<int64_t>(Bytes) <= ABytes;
  }

  static DefinedOrUnknownSVal protocolSucceeded(
      const FunctionDecl *Function, DefinedOrUnknownSVal Return,
      SValBuilder &Builder, ProgramStateRef State) {
    DefinedOrUnknownSVal IsZero = Builder.evalEQ(
        State, Return, Builder.makeZeroVal(Function->getReturnType()));
    if (!Function->getReturnType()->isPointerType())
      return IsZero;
    return Builder
        .evalBinOp(State, BO_EQ, IsZero, Builder.makeTruthVal(false),
                   Builder.getConditionType())
        .castAs<DefinedOrUnknownSVal>();
  }

  static const ParmVarDecl *argumentParameter(const CallEvent &Call,
                                              unsigned Argument) {
    if (Argument >= Call.getNumArgs())
      return nullptr;
    const Expr *Expression = Call.getArgExpr(Argument);
    Expression = Expression ? Expression->IgnoreParenImpCasts() : nullptr;
    const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Expression);
    return Reference ? dyn_cast<ParmVarDecl>(Reference->getDecl()) : nullptr;
  }

  /* Array-to-pointer decay represents the array's base as an ElementRegion
   * at index zero.  Store a span granted to that exact base on the array
   * region itself, so later bounded suffixes (`base + offset`) can consume
   * the remaining extent.  An interior-pointer grant deliberately stays on
   * its ElementRegion: promoting that would incorrectly prove bytes before
   * the pointer. */
  static const MemRegion *spanProofRegion(const MemRegion *Region,
                                          ProgramStateRef State) {
    const auto *Element = dyn_cast_or_null<ElementRegion>(Region);
    if (Element && State->isNull(Element->getIndex()).isConstrainedTrue())
      return Element->getSuperRegion();
    return Region;
  }

  static ProgramStateRef applyGrants(
      ProgramStateRef State, const CallEvent &Call,
      ArrayRef<SpanContract> Spans, ArrayRef<DisjointContract> Disjoint,
      SValBuilder &Builder) {
    for (const SpanContract &Contract : Spans) {
      if (Contract.Operation != MemoryTokenOperation::Grant ||
          Contract.Pointer >= Call.getNumArgs() ||
          Contract.Length >= Call.getNumArgs() ||
          (Contract.Multiplier != std::numeric_limits<unsigned>::max() &&
           Contract.Multiplier >= Call.getNumArgs()))
        continue;
      const MemRegion *Region =
          Call.getArgSVal(Contract.Pointer).getAsRegion();
      SVal Multiplier =
          Contract.Multiplier == std::numeric_limits<unsigned>::max()
              ? UnknownVal()
              : Call.getArgSVal(Contract.Multiplier);
      SVal Length = scaledSpanLength(Contract,
                                     Call.getArgSVal(Contract.Length),
                                     Multiplier, State, Builder);
      std::optional<DefinedOrUnknownSVal> Extent =
          Length.getAs<DefinedOrUnknownSVal>();
      Region = spanProofRegion(Region, State);
      if (Region && Extent)
        State = State->set<AssumedSpanExtent>(Region, *Extent);
    }
    for (const DisjointContract &Contract : Disjoint) {
      if (Contract.Operation != MemoryTokenOperation::Grant ||
          Contract.First >= Call.getNumArgs() ||
          Contract.Second >= Call.getNumArgs() ||
          Contract.Length >= Call.getNumArgs())
        continue;
      const MemRegion *First = Call.getArgSVal(Contract.First).getAsRegion();
      const MemRegion *Second = Call.getArgSVal(Contract.Second).getAsRegion();
      std::optional<DefinedOrUnknownSVal> Extent =
          Call.getArgSVal(Contract.Length).getAs<DefinedOrUnknownSVal>();
      if (First && Second && Extent)
        State = State->set<AssumedDisjointExtent>({First, Second}, *Extent);
    }
    return State;
  }

  static ProgramStateRef recordGrantProofs(
      ProgramStateRef State, const CallEvent &Call,
      ArrayRef<SpanContract> Spans, ArrayRef<DisjointContract> Disjoint) {
    for (const SpanContract &Contract : Spans) {
      if (Contract.Operation != MemoryTokenOperation::Grant ||
          Contract.Pointer >= Call.getNumArgs() ||
          Contract.Length >= Call.getNumArgs())
        continue;
      const ParmVarDecl *Parameter =
          argumentParameter(Call, Contract.Pointer);
      const ParmVarDecl *Length = argumentParameter(Call, Contract.Length);
      if (Parameter && Length)
        State = State->set<GrantedSpanProof>(Parameter, Length);
    }
    for (const DisjointContract &Contract : Disjoint) {
      if (Contract.Operation != MemoryTokenOperation::Grant ||
          Contract.First >= Call.getNumArgs() ||
          Contract.Second >= Call.getNumArgs() ||
          Contract.Length >= Call.getNumArgs())
        continue;
      const ParmVarDecl *First = argumentParameter(Call, Contract.First);
      const ParmVarDecl *Second = argumentParameter(Call, Contract.Second);
      const ParmVarDecl *Length = argumentParameter(Call, Contract.Length);
      if (First && Second && Length)
        State = State->set<GrantedDisjointProof>({First, Second}, Length);
    }
    return State;
  }

  static ProgramStateRef removeGrantProofs(
      ProgramStateRef State, const CallEvent &Call,
      ArrayRef<SpanContract> Spans, ArrayRef<DisjointContract> Disjoint) {
    for (const SpanContract &Contract : Spans) {
      if (Contract.Operation != MemoryTokenOperation::Grant)
        continue;
      if (const ParmVarDecl *Parameter =
              argumentParameter(Call, Contract.Pointer))
        State = State->remove<GrantedSpanProof>(Parameter);
    }
    for (const DisjointContract &Contract : Disjoint) {
      if (Contract.Operation != MemoryTokenOperation::Grant)
        continue;
      const ParmVarDecl *First = argumentParameter(Call, Contract.First);
      const ParmVarDecl *Second = argumentParameter(Call, Contract.Second);
      if (First && Second)
        State = State->remove<GrantedDisjointProof>({First, Second});
    }
    return State;
  }

  // Called from checkEndFunction, the one point (see the TouchedRecordSpan
  // comment above for why CompoundStmt-exit does not work) every touched
  // pair's update is guaranteed to have fully settled. Consumes the
  // (Pointer, Length) value snapshot checkBind already captured for each
  // touched pair -- not a fresh store re-read, which dead-binding cleanup
  // may have already discarded by this point (see TouchedRecordSpan's
  // comment) -- so a pointer-then-length or length-then-pointer update is
  // judged only once both writes have actually landed, using whichever
  // value each field was last known to hold.
  ProgramStateRef
  flushRecordSpanObligations(ProgramStateRef State, CheckerContext &C) const {
    for (const auto &Entry : State->get<TouchedRecordSpan>()) {
      const FieldDecl *Pointer = Entry.first.first.second;
      const FieldDecl *Length = Entry.first.second;
      SVal PointerValue = Entry.second.first.first;
      SVal LengthValue = Entry.second.first.second;
      const Stmt *Site = Entry.second.second;
      State = State->remove<TouchedRecordSpan>(Entry.first);
      if (PointerValue.isUnknownOrUndef() || LengthValue.isUnknownOrUndef())
        continue;
      SmallVector<RecordSpanContract, 2> Contracts;
      collectRecordSpanContracts(Pointer->getParent(), C.getASTContext(),
                                 Contracts);
      uint64_t Scale = 1;
      bool Found = false;
      for (const RecordSpanContract &Contract : Contracts)
        if (Contract.Pointer == Pointer && Contract.Length == Length) {
          Scale = Contract.Scale;
          Found = true;
          break;
        }
      if (!Found)
        continue;
      if (Scale != 1)
        LengthValue = C.getSValBuilder().evalBinOp(
            State, BO_Mul, LengthValue,
            C.getSValBuilder().makeIntVal(Scale,
                                          C.getASTContext().getSizeType()),
            C.getASTContext().getSizeType());
      if (!spanProven(PointerValue, LengthValue, State, C,
                      /*UseAssumedSpans=*/false))
        reportFieldSpan(
            "paired length field is not proven within its pointer field's "
            "real allocation extent",
            Site, State, C);
    }
    return State;
  }

  // checkBind fires once per write, BEFORE the engine applies it -- so
  // C.getState() here still reflects every EARLIER write but not this one.
  // For the field actually being written, its new value is exactly Value
  // (the Bind callback's own parameter); for the field's PAIRED partner,
  // reuse whatever value the last touch of this same key already
  // captured (Prior), and only fall back to reading the store when this
  // is the pair's first touch -- the same read-back this file's other
  // mechanisms already rely on, and still safe here because nothing has
  // had a chance to prune it between then and now.
  static ProgramStateRef recordFieldSpanTouch(
      ProgramStateRef State, const RecordSpanTouchKey &Key,
      bool WrittenIsPointer, SVal Value, const Stmt *BindStmt,
      const MemRegion *Base, const FieldDecl *OtherField,
      CheckerContext &C) {
    DefinedOrUnknownSVal NewValue =
        Value.getAs<DefinedOrUnknownSVal>().value_or(UnknownVal());
    DefinedOrUnknownSVal OtherValue = UnknownVal();
    if (const RecordSpanSnapshot *Prior = State->get<TouchedRecordSpan>(Key)) {
      OtherValue = WrittenIsPointer ? Prior->first.second : Prior->first.first;
    } else if (std::optional<Loc> OtherLoc =
                   State->getLValue(OtherField, loc::MemRegionVal(Base))
                       .getAs<Loc>()) {
      OtherValue =
          State->getSVal(*OtherLoc).getAs<DefinedOrUnknownSVal>().value_or(
              UnknownVal());
    }
    DefinedOrUnknownSVal PointerValue = WrittenIsPointer ? NewValue : OtherValue;
    DefinedOrUnknownSVal LengthValue = WrittenIsPointer ? OtherValue : NewValue;
    return State->set<TouchedRecordSpan>(
        Key, {{PointerValue, LengthValue}, BindStmt});
  }

public:
  void checkBind(SVal Location, SVal Value, const Stmt *BindStmt,
                CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    const MemRegion *Bound = Location.getAsRegion();
    if (!Function || !Bound)
      return;
    ProgramStateRef State = C.getState();
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      if (State->getLValue(Parameter, C.getLocationContext()).getAsRegion() !=
          Bound)
        continue;
      SmallVector<const ParmVarDecl *, 2> RemoveSpans;
      for (const auto &Proof : State->get<GrantedSpanProof>())
        if (Proof.first == Parameter || Proof.second == Parameter)
          RemoveSpans.push_back(Proof.first);
      for (const ParmVarDecl *Key : RemoveSpans)
        State = State->remove<GrantedSpanProof>(Key);
      SmallVector<DisjointParameterKey, 2> Remove;
      for (const auto &Proof : State->get<GrantedDisjointProof>())
        if (Proof.first.first == Parameter || Proof.first.second == Parameter ||
            Proof.second == Parameter)
          Remove.push_back(Proof.first);
      for (const DisjointParameterKey &Key : Remove)
        State = State->remove<GrantedDisjointProof>(Key);
      break;
    }
    if (const auto *Field = dyn_cast<FieldRegion>(Bound)) {
      SmallVector<RecordSpanContract, 2> Contracts;
      collectRecordSpanContracts(Field->getDecl()->getParent(),
                                 C.getASTContext(), Contracts);
      const MemRegion *Base = Field->getSuperRegion();
      for (const RecordSpanContract &Contract : Contracts) {
        bool WrittenIsPointer = Contract.Pointer == Field->getDecl();
        bool WrittenIsLength = Contract.Length == Field->getDecl();
        if (!WrittenIsPointer && !WrittenIsLength)
          continue;
        RecordSpanTouchKey Key{{Base, Contract.Pointer}, Contract.Length};
        const FieldDecl *OtherField =
            WrittenIsPointer ? Contract.Length : Contract.Pointer;
        State = recordFieldSpanTouch(State, Key, WrittenIsPointer, Value,
                                     BindStmt, Base, OtherField, C);
      }
    }
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    SmallVector<SpanContract, 2> Spans;
    SmallVector<DisjointContract, 1> Disjoint;
    tokenContracts(Function, Spans, Disjoint);
    ProgramStateRef State = C.getState();
    for (const SpanContract &Contract : Spans) {
      if (Contract.Operation != MemoryTokenOperation::Require)
        continue;
      const ParmVarDecl *PointerParameter =
          Function->getParamDecl(Contract.Pointer);
      const ParmVarDecl *LengthParameter =
          Function->getParamDecl(Contract.Length);
      SVal PointerValue = State->getSVal(
          State->getLValue(PointerParameter, C.getLocationContext()));
      SVal LengthValue = State->getSVal(
          State->getLValue(LengthParameter, C.getLocationContext()));
      if (std::optional<SVal> CallerLength = callerArgumentValue(
              Contract.Length, State, C.getLocationContext()))
        LengthValue = *CallerLength;
      SVal Multiplier = UnknownVal();
      if (Contract.Multiplier != std::numeric_limits<unsigned>::max()) {
        const ParmVarDecl *Parameter =
            Function->getParamDecl(Contract.Multiplier);
        Multiplier = State->getSVal(
            State->getLValue(Parameter, C.getLocationContext()));
        if (std::optional<SVal> Caller = callerArgumentValue(
                Contract.Multiplier, State, C.getLocationContext()))
          Multiplier = *Caller;
      }
      LengthValue = scaledSpanLength(Contract, LengthValue, Multiplier, State,
                                     C.getSValBuilder());
      const MemRegion *Region = PointerValue.getAsRegion();
      std::optional<DefinedOrUnknownSVal> DefinedLength =
          LengthValue.getAs<DefinedOrUnknownSVal>();
      Region = spanProofRegion(Region, State);
      if (Region && DefinedLength) {
        State = State->set<AssumedSpanExtent>(Region, *DefinedLength);
        /* A contract on a base pointer is also a conservative dynamic extent
         * for that function-local symbolic region.  Do not overwrite an
         * allocation's base extent when the contracted parameter itself is
         * already interior. */
        if (Region == Region->getBaseRegion())
          State = setDynamicExtent(State, Region, *DefinedLength,
                                   C.getSValBuilder());
      }
    }
    for (const DisjointContract &Contract : Disjoint) {
      if (Contract.Operation != MemoryTokenOperation::Require)
        continue;
      const ParmVarDecl *First = Function->getParamDecl(Contract.First);
      const ParmVarDecl *Second = Function->getParamDecl(Contract.Second);
      const ParmVarDecl *Length = Function->getParamDecl(Contract.Length);
      const MemRegion *A = State->getSVal(
          State->getLValue(First, C.getLocationContext())).getAsRegion();
      const MemRegion *B = State->getSVal(
          State->getLValue(Second, C.getLocationContext())).getAsRegion();
      std::optional<DefinedOrUnknownSVal> Extent = State->getSVal(
          State->getLValue(Length, C.getLocationContext()))
          .getAs<DefinedOrUnknownSVal>();
      if (A && B && Extent)
        State = State->set<AssumedDisjointExtent>({A, B}, *Extent);
    }
    // fields_established (see include/ownership.h's comment and
    // checkPreCall's mirror-image verification below): seed the real
    // DynamicExtent for each contracted pointer field's INITIAL value,
    // from the struct's OWN field values at function entry, so a
    // standalone analysis of this function (no visible caller, e.g.
    // --analyze's own per-function entry points, or an opaque/non-
    // inlined call site) can still judge the function's own internal
    // field mutations fairly. This is the callee-side half of the
    // contract; checkPreCall independently verifies, at every REAL call
    // site, that the caller's own current state actually proves the
    // same fields before this ever runs -- so a caller that never
    // established the invariant is still caught there, regardless of
    // what this seeds. A field carrying more than one contract (this
    // tree's own readable_elements(n)+writable_elements(cap) pairing)
    // seeds once per contract in field-declaration order; the later
    // (conventionally larger, writable-capacity) one wins the shared
    // DynamicExtent entry -- a precision choice for the callee's own
    // reasoning only, since soundness rests entirely on the call-site
    // check below, not on this seed being the tightest possible bound.
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      const RecordDecl *Record = fieldsEstablishedRecord(Parameter);
      if (!Record)
        continue;
      SmallVector<RecordSpanContract, 2> Contracts;
      collectRecordSpanContracts(Record, C.getASTContext(), Contracts);
      const MemRegion *StructRegion =
          State->getSVal(State->getLValue(Parameter, C.getLocationContext()))
              .getAsRegion();
      if (!StructRegion)
        continue;
      // A fresh symbolic pointer parameter's pointee starts out as a
      // bare, untyped SymbolicRegion. The analyzer's own evaluation of a
      // REAL `lb->field` MemberExpr later casts that same region to the
      // pointee's record type first (an ElementRegion at index zero,
      // clang's standard "view this opaque block as type T" idiom) --
      // without this same cast here, getLValue below would build a
      // FieldRegion on the UNCAST base, which compares unequal to the
      // FieldRegion the real source statements produce even though both
      // ultimately name the same bytes, silently defeating the seed.
      if (std::optional<const MemRegion *> Cast =
              C.getStoreManager().castRegion(StructRegion, Parameter->getType()))
        StructRegion = *Cast;
      for (const RecordSpanContract &Contract : Contracts) {
        std::optional<Loc> PointerLoc =
            State->getLValue(Contract.Pointer, loc::MemRegionVal(StructRegion))
                .getAs<Loc>();
        std::optional<Loc> LengthLoc =
            State->getLValue(Contract.Length, loc::MemRegionVal(StructRegion))
                .getAs<Loc>();
        if (!PointerLoc || !LengthLoc)
          continue;
        const MemRegion *PointerRegion =
            State->getSVal(*PointerLoc).getAsRegion();
        if (!PointerRegion)
          continue;
        SVal LengthValue = State->getSVal(*LengthLoc);
        if (Contract.Scale != 1)
          LengthValue = C.getSValBuilder().evalBinOp(
              State, BO_Mul, LengthValue,
              C.getSValBuilder().makeIntVal(Contract.Scale,
                                            C.getASTContext().getSizeType()),
              C.getASTContext().getSizeType());
        if (std::optional<DefinedOrUnknownSVal> DefinedLength =
                LengthValue.getAs<DefinedOrUnknownSVal>())
          State = setDynamicExtent(State, PointerRegion->getBaseRegion(),
                                   *DefinedLength, C.getSValBuilder());
      }
    }
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    SmallVector<SpanContract, 2> Spans;
    SmallVector<DisjointContract, 1> Disjoint;
    tokenContracts(Function, Spans, Disjoint);
    ProgramStateRef ContractState = C.getState();
    const auto *Frame =
        dyn_cast_or_null<StackFrameContext>(C.getLocationContext());
    /* A proof axiom that is necessary in its defining function can become
     * redundant after that function is inlined into a stronger caller.  Such
     * a caller-specific fact cannot be used to narrow the source-level axiom;
     * diagnose migration scaffolding only in the function's own entry frame. */
    if (isManualProofCall(Function) && Frame && Frame->inTopFrame()) {
      bool Reported = false;
      for (const SpanContract &Contract : Spans) {
        if (Contract.Operation != MemoryTokenOperation::Grant ||
            Contract.Pointer >= Call.getNumArgs() ||
            Contract.Length >= Call.getNumArgs())
          continue;
        bool Redundant = typedObjectSpanProven(
            Call.getArgExpr(Contract.Pointer),
            Call.getArgExpr(Contract.Length),
            Call.getArgSVal(Contract.Length), C.getState(), C, true);
        bool ProvenOnPath = Redundant ||
            spanProven(Call.getArgSVal(Contract.Pointer),
                       Call.getArgSVal(Contract.Length), C.getState(), C,
                       false) ||
            typedObjectSpanProven(Call.getArgExpr(Contract.Pointer),
                                  Call.getArgExpr(Contract.Length),
                                  Call.getArgSVal(Contract.Length),
                                  C.getState(), C);
        if (ProvenOnPath) {
          BugType *Type = Redundant ? RedundantBT.get() : MovableBT.get();
          report(Redundant ? "manual memory proof axiom is redundant"
                           : "manual memory proof axiom can be narrowed",
                 Type, Call, C.getState(), C);
          if (Redundant && !RedundantBT && Type)
            RedundantBT.reset(Type);
          if (!Redundant && !MovableBT && Type)
            MovableBT.reset(Type);
          Reported = true;
          break;
        }
      }
      if (!Reported) {
        for (const DisjointContract &Contract : Disjoint) {
          if (Contract.Operation != MemoryTokenOperation::Grant ||
              Contract.First >= Call.getNumArgs() ||
              Contract.Second >= Call.getNumArgs() ||
              Contract.Length >= Call.getNumArgs())
            continue;
          bool Redundant = typedDisjointSpanProven(
              Call.getArgExpr(Contract.First),
              Call.getArgExpr(Contract.Second),
              Call.getArgExpr(Contract.Length), C);
          bool ProvenOnPath = Redundant || overlapProven(
              Call.getArgSVal(Contract.First),
              Call.getArgSVal(Contract.Second),
              Call.getArgSVal(Contract.Length), C.getState(), C, false);
          if (ProvenOnPath) {
            BugType *Type = Redundant ? RedundantBT.get() : MovableBT.get();
            report(Redundant ? "manual memory proof axiom is redundant"
                             : "manual memory proof axiom can be narrowed",
                   Type, Call, C.getState(), C);
            if (Redundant && !RedundantBT && Type)
              RedundantBT.reset(Type);
            if (!Redundant && !MovableBT && Type)
              MovableBT.reset(Type);
            break;
          }
        }
      }
    }
    for (const SpanContract &Contract : Spans) {
      if (Contract.Operation != MemoryTokenOperation::Require)
        continue;
      if (Contract.Pointer >= Call.getNumArgs() ||
          Contract.Length >= Call.getNumArgs() ||
          (Contract.Multiplier != std::numeric_limits<unsigned>::max() &&
           Contract.Multiplier >= Call.getNumArgs()))
        continue;
      const MemRegion *Region =
          Call.getArgSVal(Contract.Pointer).getAsRegion();
      SVal Multiplier =
          Contract.Multiplier == std::numeric_limits<unsigned>::max()
              ? UnknownVal()
              : Call.getArgSVal(Contract.Multiplier);
      SVal Length = scaledSpanLength(Contract,
                                     Call.getArgSVal(Contract.Length),
                                     Multiplier, C.getState(),
                                     C.getSValBuilder());
      std::optional<DefinedOrUnknownSVal> DefinedLength =
          Length.getAs<DefinedOrUnknownSVal>();
      Region = spanProofRegion(Region, ContractState);
      if (Region && DefinedLength)
        ContractState =
            ContractState->set<AssumedSpanExtent>(Region, *DefinedLength);
    }
    for (const SpanContract &Contract : Spans) {
      if (Contract.Operation != MemoryTokenOperation::Require)
        continue;
      if (Contract.Pointer >= Call.getNumArgs() ||
          Contract.Length >= Call.getNumArgs())
        continue;
      SVal Multiplier =
          Contract.Multiplier == std::numeric_limits<unsigned>::max()
              ? UnknownVal()
              : Call.getArgSVal(Contract.Multiplier);
      SVal Length = scaledSpanLength(Contract,
                                     Call.getArgSVal(Contract.Length),
                                     Multiplier, C.getState(),
                                     C.getSValBuilder());
      ProgramStateRef ProofState = assumeFieldSpan(
          Call.getArgExpr(Contract.Pointer),
          Call.getArgExpr(Contract.Length),
          Call.getArgSVal(Contract.Pointer),
          Call.getArgSVal(Contract.Length), C.getState(), C);
      if (!spanProven(Call.getArgSVal(Contract.Pointer), Length,
                      ProofState, C) &&
          !typedObjectSpanProven(Call.getArgExpr(Contract.Pointer),
                                 Call.getArgExpr(Contract.Length),
                                 Length, ProofState, C) &&
          !derivedContractSpanProven(Call.getArgSVal(Contract.Pointer),
                                     Length, ProofState, C)) {
        BugType *Type = SpanBT.get();
        report("memory operation span is not proven valid", Type, Call,
               ContractState, C);
        if (!SpanBT && Type)
          SpanBT.reset(Type);
        break;
      }
    }
    for (const DisjointContract &Contract : Disjoint) {
      if (Contract.Operation != MemoryTokenOperation::Require)
        continue;
      if (Contract.First >= Call.getNumArgs() ||
          Contract.Second >= Call.getNumArgs() ||
          Contract.Length >= Call.getNumArgs())
        continue;
      SVal First = Call.getArgSVal(Contract.First);
      SVal Second = Call.getArgSVal(Contract.Second);
      SVal Length = Call.getArgSVal(Contract.Length);
      if (!restrictDisjointSpanProven(Call.getArgExpr(Contract.First),
                                     Call.getArgExpr(Contract.Second), First,
                                     Second) &&
          !overlapProven(First, Second, Length, C.getState(), C)) {
        BugType *Type = OverlapBT.get();
        report("memcpy ranges are not proven nonoverlapping", Type, Call,
               C.getState(), C);
        if (!OverlapBT && Type)
          OverlapBT.reset(Type);
      }
      const MemRegion *A = First.getAsRegion();
      const MemRegion *B = Second.getAsRegion();
      std::optional<DefinedOrUnknownSVal> Extent =
          Length.getAs<DefinedOrUnknownSVal>();
      if (A && B && Extent)
        ContractState =
            ContractState->set<AssumedDisjointExtent>({A, B}, *Extent);
    }
    // fields_established's caller-side half: whatever checkBeginFunction
    // seeds for the callee is only a convenience for that function's OWN
    // internal reasoning (see its comment) -- the actual obligation is
    // enforced HERE, against the CALLER's real, current knowledge of the
    // argument's fields, exactly the same way a plain withtok(...)
    // Require parameter's span is proven against the caller's state
    // above rather than merely trusted. A caller that has not actually
    // established the invariant (e.g. passed a struct whose count field
    // was bumped without the matching reallocation) is reported here,
    // at the call, not silently believed.
    if (Function)
      for (unsigned Index = 0;
           Index < Function->getNumParams() && Index < Call.getNumArgs();
           ++Index) {
        const RecordDecl *Record =
            fieldsEstablishedRecord(Function->getParamDecl(Index));
        if (!Record)
          continue;
        SmallVector<RecordSpanContract, 2> Contracts;
        collectRecordSpanContracts(Record, C.getASTContext(), Contracts);
        const MemRegion *StructRegion = Call.getArgSVal(Index).getAsRegion();
        if (!StructRegion)
          continue;
        for (const RecordSpanContract &Contract : Contracts) {
          std::optional<Loc> PointerLoc =
              C.getState()
                  ->getLValue(Contract.Pointer, loc::MemRegionVal(StructRegion))
                  .getAs<Loc>();
          std::optional<Loc> LengthLoc =
              C.getState()
                  ->getLValue(Contract.Length, loc::MemRegionVal(StructRegion))
                  .getAs<Loc>();
          if (!PointerLoc || !LengthLoc)
            continue;
          SVal PointerValue = C.getState()->getSVal(*PointerLoc);
          SVal LengthValue = C.getState()->getSVal(*LengthLoc);
          if (Contract.Scale != 1)
            LengthValue = C.getSValBuilder().evalBinOp(
                C.getState(), BO_Mul, LengthValue,
                C.getSValBuilder().makeIntVal(Contract.Scale,
                                              C.getASTContext().getSizeType()),
                C.getASTContext().getSizeType());
          if (PointerValue.isUnknownOrUndef() || LengthValue.isUnknownOrUndef())
            continue;
          if (!spanProven(PointerValue, LengthValue, C.getState(), C,
                          /*UseAssumedSpans=*/false))
            reportFieldSpan(
                "struct argument passed to a fields_established parameter "
                "is not proven to already satisfy its own paired-field "
                "extent invariant before this call",
                Call.getOriginExpr(), C.getState(), C);
        }
      }
    ContractState =
        recordGrantProofs(ContractState, Call, Spans, Disjoint);
    if (ContractState != C.getState())
      C.addTransition(ContractState);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (declaredFreshAllocation(Function))
      if (const MemRegion *Region = Call.getReturnValue().getAsRegion())
        State = State->add<AllocatedBaseRegion>(Region->getBaseRegion());
    if (std::optional<SVal> Extent =
            declaredReturnSpanExtent(Function, Call, C)) {
      if (std::optional<DefinedOrUnknownSVal> DefinedSize =
              Extent->getAs<DefinedOrUnknownSVal>())
        if (const MemRegion *Region = Call.getReturnValue().getAsRegion()) {
          const MemRegion *Base = Region->getBaseRegion();
          State = setDynamicExtent(State, Base, *DefinedSize,
                                   C.getSValBuilder());
          if (SymbolRef Symbol = allocationSymbol(Base))
            State = State->set<AllocatedSpanExtent>(Symbol, *DefinedSize);
        }
      }
    // See stringLengthSourceSpanProven above: record which pointer
    // argument a strlen()/strnlen() call's return symbol was measured
    // from, so a later memcpy/memset/etc using that same (conjured)
    // length against that same pointer can be recognized as in-bounds
    // by construction.
    bool IsStrlen = hasName(Call, "strlen") && Call.getNumArgs() >= 1;
    bool IsStrnlen = hasName(Call, "strnlen") && Call.getNumArgs() >= 2;
    if (IsStrlen || IsStrnlen) {
      const MemRegion *ArgRegion = Call.getArgSVal(0).getAsRegion();
      SymbolRef ReturnSym = stripCasts(Call.getReturnValue().getAsSymbol());
      if (ArgRegion && ReturnSym)
        State = IsStrlen ? State->set<StrlenSource>(ReturnSym, ArgRegion)
                         : State->set<StrnlenSource>(ReturnSym, ArgRegion);
    }

    SmallVector<SpanContract, 2> Spans;
    SmallVector<DisjointContract, 1> Disjoint;
    tokenContracts(Function, Spans, Disjoint);
    bool HasGrant = llvm::any_of(Spans, [](const SpanContract &Contract) {
      return Contract.Operation == MemoryTokenOperation::Grant;
    }) || llvm::any_of(Disjoint, [](const DisjointContract &Contract) {
      return Contract.Operation == MemoryTokenOperation::Grant;
    });
    if (!HasGrant) {
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    if (Function->getReturnType()->isVoidType()) {
      C.addTransition(applyGrants(State, Call, Spans, Disjoint,
                                  C.getSValBuilder()));
      return;
    }
    std::optional<DefinedOrUnknownSVal> Return =
        Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
    if (!Return) {
      ProgramStateRef Unproven =
          removeGrantProofs(State, Call, Spans, Disjoint);
      if (Unproven != C.getState())
        C.addTransition(Unproven);
      return;
    }
    DefinedOrUnknownSVal Success = protocolSucceeded(
        Function, *Return, C.getSValBuilder(), State);
    auto [Succeeded, Failed] = State->assume(Success);
    if (Succeeded)
      C.addTransition(applyGrants(Succeeded, Call, Spans, Disjoint,
                                  C.getSValBuilder()));
    if (Failed)
      C.addTransition(removeGrantProofs(Failed, Call, Spans, Disjoint));
  }

  // TouchedRecordSpan's own comment already explains why the (Pointer,
  // Length) VALUES are captured as a snapshot rather than re-read from the
  // store at checkEndFunction: liveness-driven dead-binding cleanup would
  // otherwise silently return Unknown for a field nothing downstream reads
  // again. That snapshot protects the VALUES themselves (the checker holds
  // its own copy of each SVal in its private GDM state), but not the RANGE
  // CONSTRAINTS those values may depend on: ProgramState::cleanupState
  // prunes ConstraintRangeTy entries for any symbol the SymbolReaper does
  // not consider live, and holding a symbol inside a checker's own private
  // GDM map (TouchedRecordSpan is exactly that) does not by itself count --
  // only an explicit checkLiveSymbols vote keeps the SymbolReaper from
  // reaping it. Confirmed via a minimal reproduction of glob.c's own
  // `out.cap = pglob->gl_pathc; if (out.cap) { out.v = __malloc(out.cap *
  // sizeof *out.v); ... } return 0;` shape (one field, one branch, one
  // return): the analyzer's own trace records "Assuming field 'cap' is 0"
  // on the false branch (a real constraint IS added on that path), yet by
  // the time checkEndFunction's flush runs at the return statement,
  // getConstraintMap(State) comes back completely empty -- every range
  // fact on the path has already been reaped, because nothing ever marked
  // any of them live. Without this, both spanProven's plain isNull() check
  // and 906b757c's own Z3 provesZero bridge have nothing left to prove
  // from: an empty constraint map lets Z3 satisfy "scaled length != 0"
  // trivially, so what should be a provable zero-length vacuous case
  // (out.cap == 0 on that path, therefore out.cap * elementSize == 0)
  // reports as unproven instead. Marking every symbol a still-pending
  // TouchedRecordSpan obligation references keeps its constraints alive
  // exactly as long as the obligation itself survives -- the entry is
  // removed by flushRecordSpanObligations the moment it is judged, so this
  // stops protecting the symbol on the very next liveness pass after that,
  // the same bounded lifetime the snapshot values themselves already have.
  //
  // Marking the captured Pointer/Length VALUES alone is not sufficient by
  // itself, though: src/util/patch.c's own `struct pline.text`/`.len` pair
  // (readable_span, not the growable-array shape above) showed a second,
  // narrower instance of the identical class of bug. Minimal reproduction
  // (a `bytes; size_add(len, 1, &bytes); copy = __malloc(bytes); ...
  // pl->text = copy; pl->len = len;` shape, matching lb_push() exactly):
  // a bounded loop copying `len` bytes before the two field writes causes
  // the analyzer to explore several concretely-bounded loop trip counts,
  // and by the time `pl->len = len;` runs, the STORE genuinely holds a
  // concrete value for `len` on that path (confirmed via a debug dump: the
  // captured LengthValue prints as a plain concrete integer, e.g. "1
  // U64b") -- so the captured snapshot itself carries no symbol to mark
  // live at all. The DynamicExtent established for `copy` back at the
  // `__malloc(bytes)` call, however, is `len_symbol + 1` -- a SEPARATE,
  // still-symbolic expression that must relate to the SAME `len_symbol`'s
  // range (narrowed to that one concrete value on this path) to prove
  // `Extent >= Length`. Nothing marks `len_symbol` itself live merely
  // because it appears inside an Extent computed long before this
  // obligation's own two field-writing statements ever ran, so its range
  // is reaped by the same loop-widening cleanup pass, and the proof fails
  // for exactly the reason above even though the snapshot values
  // themselves are intact.
  //
  // checkPostCall (below) already keeps AllocatedSpanExtent, a parallel
  // COPY of every declaredReturnSpanExtent-established DynamicExtent, in
  // this checker's own GDM specifically because that state (unlike
  // clang's core DynamicExtentMap) is never auto-pruned -- so the Extent
  // expression's own STRUCTURE always survives to flush time regardless
  // of this fix. Walking that already-preserved copy here and marking
  // every leaf symbol its expression tree references (SymExpr::symbols())
  // closes the gap without needing a SValBuilder (unavailable in this
  // callback) to query clang's core map directly: only a pointer region
  // with a PENDING obligation on it is considered, so this stays scoped
  // to symbols a still-open proof might actually need, the same bounded
  // lifetime as the rest of this function.
  void checkLiveSymbols(ProgramStateRef State, SymbolReaper &SR) const {
    auto markSValLive = [&SR](SVal Value) {
      if (SymbolRef Symbol = Value.getAsSymbol())
        for (const SymExpr *Leaf : Symbol->symbols())
          SR.markLive(Leaf);
      if (const MemRegion *Region = Value.getAsRegion())
        SR.markLive(Region);
    };
    for (const auto &Entry : State->get<TouchedRecordSpan>()) {
      SVal PointerValue = Entry.second.first.first;
      SVal LengthValue = Entry.second.first.second;
      markSValLive(PointerValue);
      markSValLive(LengthValue);
      if (const MemRegion *PointerRegion = PointerValue.getAsRegion())
        if (SymbolRef Symbol =
                allocationSymbol(PointerRegion->getBaseRegion()))
          if (const DefinedOrUnknownSVal *Extent =
                  State->get<AllocatedSpanExtent>(Symbol))
            markSValLive(*Extent);
    }
  }

  void checkEndFunction(const ReturnStmt *Return, CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function || !Function->doesThisDeclarationHaveABody())
      return;
    SmallVector<SpanContract, 2> Spans;
    SmallVector<DisjointContract, 1> Disjoint;
    tokenContracts(Function, Spans, Disjoint);
    ProgramStateRef State = C.getState();
    // Discharge every TouchedRecordSpan obligation accumulated so far --
    // but ONLY at the outermost frame of this analysis, never an inlined
    // callee's own return. Inlining shares the CALLER's ProgramState with
    // the callee (that is the entire point of inlining -- precise
    // cross-function reasoning), so checkEndFunction fires for every
    // inlined callee's own return too, not just the top-level entry
    // function's. Flushing there was observed to misfire in practice:
    // src/glob/glob.c's `glob()` writes `out.v`/`out.cap` itself, then
    // calls small inlined helpers (find_slash, has_meta, ...) that touch
    // neither field -- yet an unconditional flush fired (and mis-
    // attributed its report to the helper's own name, since context()
    // reads the CURRENT location context) at the FIRST such helper's
    // return, well before `glob()` had actually finished its own update,
    // because nothing distinguished "this frame is exiting" from "some
    // inlined callee sharing my state happened to return". Restricting
    // the flush to Frame->inTopFrame() is the same guard checkPreCall's
    // isManualProofCall migration diagnostic already uses for an
    // identical inlining-visibility concern.
    const auto *Frame = dyn_cast_or_null<StackFrameContext>(C.getLocationContext());
    if (Frame && Frame->inTopFrame()) {
      ProgramStateRef Flushed = flushRecordSpanObligations(State, C);
      if (Flushed != State) {
        C.addTransition(Flushed);
        State = Flushed;
      }
    }
    if (!Function->getReturnType()->isVoidType()) {
      if (!Return || !Return->getRetValue())
        return;
      std::optional<DefinedOrUnknownSVal> Result =
          C.getSVal(Return->getRetValue()).getAs<DefinedOrUnknownSVal>();
      if (!Result)
        return;
      DefinedOrUnknownSVal Success = protocolSucceeded(
          Function, *Result, C.getSValBuilder(), State);
      State = State->assume(Success).first;
      if (!State)
        return;
    }
    const LocationContext *LC = C.getLocationContext();
    const Stmt *Site =
        Return ? static_cast<const Stmt *>(Return) : Function->getBody();
    for (const SpanContract &Contract : Spans) {
      if (Contract.Operation != MemoryTokenOperation::Grant)
        continue;
      const ParmVarDecl *Pointer = Function->getParamDecl(Contract.Pointer);
      const ParmVarDecl *Length = Function->getParamDecl(Contract.Length);
      SVal PointerValue =
          State->getSVal(State->getLValue(Pointer, LC));
      SVal LengthValue = State->getSVal(State->getLValue(Length, LC));
      SVal Multiplier = UnknownVal();
      if (Contract.Multiplier != std::numeric_limits<unsigned>::max()) {
        const ParmVarDecl *Parameter =
            Function->getParamDecl(Contract.Multiplier);
        Multiplier = State->getSVal(State->getLValue(Parameter, LC));
      }
      LengthValue = scaledSpanLength(Contract, LengthValue, Multiplier, State,
                                     C.getSValBuilder());
      const MemRegion *Region = PointerValue.getAsRegion();
      bool Proven = State->isNull(LengthValue).isConstrainedTrue();
      if (!Proven)
        Proven = spanProven(PointerValue, LengthValue, State, C, false);
      if (Region)
        if (const ParmVarDecl *const *ProvenLength =
                State->get<GrantedSpanProof>(Pointer)) {
          if (*ProvenLength == Length) {
            if (std::optional<DefinedOrUnknownSVal> Extent =
                    LengthValue.getAs<DefinedOrUnknownSVal>()) {
              ProgramStateRef ProofState =
                  State->set<AssumedSpanExtent>(Region, *Extent);
              Proven = spanProven(PointerValue, LengthValue, ProofState, C);
            }
          }
        }
      if (!Proven) {
        reportToken("declared memory token addition is not proven by function "
                    "body",
                    Site, State, C);
        return;
      }
    }
    for (const DisjointContract &Contract : Disjoint) {
      if (Contract.Operation != MemoryTokenOperation::Grant)
        continue;
      const ParmVarDecl *First = Function->getParamDecl(Contract.First);
      const ParmVarDecl *Second = Function->getParamDecl(Contract.Second);
      const ParmVarDecl *Length = Function->getParamDecl(Contract.Length);
      SVal FirstValue = State->getSVal(State->getLValue(First, LC));
      SVal SecondValue = State->getSVal(State->getLValue(Second, LC));
      SVal LengthValue = State->getSVal(State->getLValue(Length, LC));
      const MemRegion *FirstRegion = FirstValue.getAsRegion();
      const MemRegion *SecondRegion = SecondValue.getAsRegion();
      bool Proven = State->isNull(LengthValue).isConstrainedTrue();
      if (FirstRegion && SecondRegion)
        if (const ParmVarDecl *const *ProvenLength =
                State->get<GrantedDisjointProof>({First, Second})) {
          if (*ProvenLength == Length) {
            if (std::optional<DefinedOrUnknownSVal> Extent =
                    LengthValue.getAs<DefinedOrUnknownSVal>()) {
              ProgramStateRef ProofState =
                  State->set<AssumedDisjointExtent>(
                      {FirstRegion, SecondRegion}, *Extent);
              Proven = overlapProven(FirstValue, SecondValue, LengthValue,
                                     ProofState, C);
            }
          }
        }
      if (!Proven) {
        reportToken("declared memory token addition is not proven by function "
                    "body",
                    Site, State, C);
        return;
      }
    }
  }
};

} // namespace

void registerMemoryContractChecker(CheckerRegistry &Registry) {
  Registry.addChecker<MemoryContractChecker>(
      "spicule.MemoryContract",
      "Proves memory spans and memcpy non-overlap contracts", "");
}

#ifndef OWNERSHIP_CHECKER_BUNDLE
extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  registerMemoryContractChecker(Registry);
}
#endif
