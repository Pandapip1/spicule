// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ASTTypeTraits.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/RangedConstraintManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "llvm/ADT/APSInt.h"
#include "llvm/ADT/SmallString.h"
#include "TokenAlgebra.h"
#ifdef NTLIBC_ARITHMETIC_Z3
#include "ExactCScalarSMT.h"
#include "z3++.h"
#endif

#include <algorithm>
#include <cctype>
#include <memory>
#include <optional>
#include <string>
#include <utility>

using namespace clang;
using namespace ento;

// A scalar value returned by an integer_sentinel(V)/long_sentinel(V)-marked
// function, or bound to a matching parameter at function entry, is tracked
// by the SPECIFIC Decl (FunctionDecl or ParmVarDecl) that carried the
// qualifier -- not by the already-parsed int64_t literal -- so
// ntlibc.IntegerSentinel re-derives the literal through
// ntlibc::algebra::scalarSentinel() at every use site instead of caching a
// second, possibly-diverging copy of it. This mirrors AllocationOrigin's
// own SymbolRef -> const Stmt* shape immediately below: a plain pointer
// value is a POD FoldingSet key with no template-instantiation risk plain
// int64_t/uint64_t map values would carry into a header this many checker
// translation units already include.
REGISTER_MAP_WITH_PROGRAMSTATE(IntegerSentinelOrigin, SymbolRef, const Decl *)
REGISTER_MAP_WITH_PROGRAMSTATE(ArithmeticContractField,
                               const StackFrameContext *, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(ArithmeticContractOutput,
                               const StackFrameContext *, const MemRegion *)
REGISTER_SET_WITH_PROGRAMSTATE(ArithmeticContractOutputValid,
                               const StackFrameContext *)
REGISTER_SET_WITH_PROGRAMSTATE(ArithmeticWideReducer, const MemRegion *)
#ifdef NTLIBC_ARITHMETIC_Z3
REGISTER_MAP_WITH_PROGRAMSTATE(ArithmeticZ3BranchFact, SymbolRef, bool)
// A second, SizeCast-scoped branch-fact map -- deliberately not shared with
// ArithmeticZ3BranchFact above, so recording a fact here can only ever
// affect CastZ3Proof's own query, never arithub's.  It exists because
// getConstraintMap(State) -- the mechanism ArithmeticZ3Proof relies on for
// its own facts -- was observed empty at every ntlibc.SizeCast callback on
// a real, minimal guarded-cast test case in this Clang 18 build, for a
// plain `if (room > 1000) return 0;` guard as much as for a `count < room`
// comparison between two live symbols: the diagnostic path notes already
// show the engine evaluated and assumed both ("Assuming 'room' is <=
// 1000", "Assuming 'count' is < 'room'"), but neither leaves a queryable
// trace of itself in that map by the time the guarded cast is reached.
// eval::Assume is the one checker callback that sees every such SVal
// directly as the engine assumes it, before whatever this build's
// constraint manager does or does not keep of it afterward -- so this map
// records every comparison assumption unconditionally, making this
// checker's Z3 proof power self-sufficient rather than dependent on that
// other map being populated.
REGISTER_MAP_WITH_PROGRAMSTATE(CastZ3BranchFact, SymbolRef, bool)
// A third, ArrayIndexChecker-scoped branch-fact map, deliberately not shared
// with either map above: see ArrayIndexZ3Proof's own comment (just before
// class ArrayIndexChecker below) for why ntlibc.ArrayIndex needs this exact
// same eval::Assume-sourced recording technique CastZ3BranchFact already
// uses for ntlibc.SizeCast.
REGISTER_MAP_WITH_PROGRAMSTATE(ArrayIndexZ3BranchFact, SymbolRef, bool)
#endif

namespace {

#ifdef NTLIBC_ARITHMETIC_Z3
// A small Z3 bridge scoped to ntlibc.SizeCast alone -- deliberately a
// separate context/solver/translate() from arithub's ArithmeticZ3Proof
// below, so this extension can only ever change SizeCast's own findings,
// never arithub's (ntlibc.Divisor/ShiftCount/SignedArithmetic/
// ArithmeticContract).
//
// The gap this closes: expressionInterval()/symbolInterval() above are
// pure interval arithmetic over one symbol at a time, backed by
// bisectInterval()'s binary search over concrete assumeInclusiveRange()
// queries.  That binary search asks the state "is X within [lo, hi]?" for
// literal, concrete [lo, hi] -- it can only ever discover a bound on X
// that is already a plain number, never one expressed in terms of a
// second live symbol.  So a guard shaped like `if (x < y) ... (T)x ...`
// (y itself independently bounded, e.g. by its own declared type or an
// earlier `if (y <= 0) return;`) leaves x's own tracked range untouched by
// this file's existing machinery, even though x < y together with y's own
// known bound already entails a real bound on x sufficient to prove the
// cast -- confirmed both on a synthetic fixture (see
// tools/lint-cast-range-fixtures/relational.c) and while investigating
// real sites such as src/misc/resource.c's __fsize_clamp().
//
// Z3 has no such limitation, but only if it is actually given the
// relational fact: CastZ3BranchFact below is populated from eval::Assume,
// not from getConstraintMap(State) the way arithub's ArithmeticZ3Proof
// reads its own facts -- getConstraintMap() was observed empty at every
// ntlibc.SizeCast callback on real, minimal guarded-cast cases in this
// Clang 18 build, for a plain symbol-vs-literal guard as much as for a
// symbol-vs-symbol one (see CastZ3BranchFact's own comment for how this
// was confirmed).  Asserting every such recorded fact and asking whether
// the cast's source value can then lie outside the destination range is
// decidable in one Z3 query.
class CastZ3Engine {
public:
  z3::context Context;
  z3::solver Solver;

  CastZ3Engine() : Solver(Context) {
    z3::params Parameters(Context);
    Parameters.set("rlimit", 1000000u);
    Parameters.set("timeout", 2000u);
    Solver.set(Parameters);
  }
};

static CastZ3Engine &castZ3Engine() {
  // Static-analyzer callbacks are serial within one translation-unit
  // process; lint.sh provides process parallelism across translation
  // units (see arithmeticZ3Engine()'s identical rationale below).
  static thread_local CastZ3Engine Engine;
  return Engine;
}

class CastZ3Proof {
  z3::context &ZCtx;
  z3::solver &Solver;
  ASTContext &AST;

  static bool isUnsigned(QualType Type) {
    return Type->isUnsignedIntegerOrEnumerationType();
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

  // Deliberately smaller than ArithmeticZ3Proof::translate() below: this
  // class only ever needs to relate a cast's source value to ranges other
  // symbols are already independently known to hold, never to model an
  // arithmetic operation's own overflow/wrap/narrowing events, so plain
  // wrapping bit-vector +/-/* is exactly C's defined modular semantics for
  // those opcodes with no ScalarSMT SemanticResult bookkeeping needed.
  //
  // ArithmeticZ3Proof::translate() rejects every SymbolCast outright,
  // because Clang 18 exposes no accessor for a SymbolCast's private source
  // type and a chain of narrowing/widening casts folded into one node
  // cannot be replayed without it. That risk is specifically a *width*
  // risk (choosing the wrong extension). It does not exist when the
  // cast's operand already has the exact same bit width as the cast's own
  // type: no extension or truncation happens at all, so the bit pattern
  // this function must produce is bit-for-bit identical to the operand's
  // own bit pattern regardless of what the private source type was --
  // reinterpreting a same-width value's sign is a narrower, genuinely
  // sound case the shared class does not attempt.
  std::optional<z3::expr> translate(const SymExpr *Expression,
                                    unsigned Depth = 0) {
    if (!Expression || Depth > 24 || Expression->getType().isNull() ||
        !Expression->getType()->isIntegerType())
      return std::nullopt;
    unsigned Width = AST.getIntWidth(Expression->getType());
    if (const auto *Data = dyn_cast<SymbolData>(Expression)) {
      std::string Name = "ntlibc_cast_sym_" + std::to_string(Data->getSymbolID());
      return ZCtx.bv_const(Name.c_str(), Width);
    }
    if (const auto *Cast = dyn_cast<SymbolCast>(Expression)) {
      QualType OperandType = Cast->getOperand()->getType();
      if (OperandType.isNull() || !OperandType->isIntegerType() ||
          AST.getIntWidth(OperandType) != Width)
        return std::nullopt;
      return translate(Cast->getOperand(), Depth + 1);
    }

    auto Apply = [&](const z3::expr &Left, const z3::expr &Right,
                     BinaryOperator::Opcode Opcode,
                     QualType OperandType) -> std::optional<z3::expr> {
      if (Left.get_sort().bv_size() != Right.get_sort().bv_size())
        return std::nullopt;
      switch (Opcode) {
      case BO_Add:
        return Left + Right;
      case BO_Sub:
        return Left - Right;
      case BO_Mul:
        return Left * Right;
      case BO_And:
        return Left & Right;
      case BO_EQ:
      case BO_NE:
      case BO_LT:
      case BO_LE:
      case BO_GT:
      case BO_GE: {
        bool OperandUnsigned = isUnsigned(OperandType);
        z3::expr Predicate = [&]() -> z3::expr {
          switch (Opcode) {
          case BO_EQ:
            return Left == Right;
          case BO_NE:
            return Left != Right;
          case BO_LT:
            return OperandUnsigned ? z3::ult(Left, Right) : Left < Right;
          case BO_LE:
            return OperandUnsigned ? z3::ule(Left, Right) : Left <= Right;
          case BO_GT:
            return OperandUnsigned ? z3::ugt(Left, Right) : Left > Right;
          default: // BO_GE: the only remaining opcode this case can reach.
            return OperandUnsigned ? z3::uge(Left, Right) : Left >= Right;
          }
        }();
        unsigned ResultWidth = Width;
        return z3::ite(Predicate, ZCtx.bv_val(1, ResultWidth),
                       ZCtx.bv_val(0, ResultWidth));
      }
      default:
        return std::nullopt;
      }
    };

    // Every shape below requires the two operands to share one bit width --
    // required for the bit-vector operator itself, since Apply() rejects
    // mismatched widths regardless. A *signedness* mismatch is additionally
    // rejected only for comparison opcodes, where the wrong predicate
    // (z3::ult vs plain <) would be a genuinely wrong answer: Add/Sub/Mul/And
    // are ordinary two's-complement bit-vector operators whose raw result is
    // identical no matter how either operand's bits are interpreted, so
    // rejecting those on a signedness mismatch alone would only discard sound
    // facts, e.g. plain `(long long)x - y` where Clang represents the
    // explicitly-cast operand `x` by its own pre-cast (and thus differently
    // signed, same-width) symbol rather than wrapping a SymbolCast around it.
    auto SameWidth = [&](QualType Left, QualType Right) {
      return !Left.isNull() && !Right.isNull() && Left->isIntegerType() &&
             Right->isIntegerType() &&
             AST.getIntWidth(Left) == AST.getIntWidth(Right);
    };
    if (const auto *Binary = dyn_cast<SymSymExpr>(Expression)) {
      QualType LeftType = Binary->getLHS()->getType();
      QualType RightType = Binary->getRHS()->getType();
      BinaryOperator::Opcode Opcode = Binary->getOpcode();
      if (LeftType.isNull() || RightType.isNull() ||
          !LeftType->isIntegerType() || !RightType->isIntegerType())
        return std::nullopt;
      if (SameWidth(LeftType, RightType)) {
        if (BinaryOperator::isComparisonOp(Opcode) &&
            isUnsigned(LeftType) != isUnsigned(RightType))
          return std::nullopt;
        std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
        std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
        if (!Left || !Right)
          return std::nullopt;
        return Apply(*Left, *Right, Opcode, LeftType);
      }
      // Mismatched-width operands: real, confirmed on man.c's
      // man_builtin_pager() and awk_run.c's awk_format() (both scan a fixed
      // `const char *end` with a cursor advanced by a *narrower*-typed
      // offset -- an `int`/`unsigned` loop or match index -- before
      // subtracting or comparing it against `end`'s own size_t-typed
      // distance from the buffer's start). RegionStore's own pointer-offset
      // arithmetic keeps each side's ORIGINAL integer type instead of
      // inserting the SymbolCast a real source-level mixed-width
      // subtraction or comparison would have, for the identical reason
      // documented just above for a signedness-only mismatch: nothing
      // downstream of RegionStore's index bookkeeping re-derives that
      // missing conversion node. Modeling the fix the same way as
      // provesRepresentable()'s own CommonWidth trick -- sign/zero-extend
      // each operand through ITS OWN type's signedness into one guard-bit
      // padded common width, wide enough for the result type too, then
      // compute/compare there as ordinary signed values -- reproduces
      // exactly what a real mixed-type expression's inserted usual
      // arithmetic conversions would have computed for a same-rank
      // widening (the only shape RegionStore's own index arithmetic can
      // produce: one type's value promoted to fit the other's range, never
      // truncated), without asserting anything about whichever real
      // conversion Clang would have chosen for a source-level comparison
      // between the two ORIGINAL types. Deliberately narrower than Apply():
      // only Add/Sub/Mul and the six comparisons are given a mismatched-
      // width interpretation, so a mismatched-width BO_And/Or/Shl/Shr (a
      // shape no real pointer-offset expression produces) simply falls
      // through unproven rather than risk a wrong bit-pattern assumption.
      bool IsArithmetic =
          Opcode == BO_Add || Opcode == BO_Sub || Opcode == BO_Mul;
      if (!IsArithmetic && !BinaryOperator::isComparisonOp(Opcode))
        return std::nullopt;
      std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
      std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
      unsigned LeftWidth = AST.getIntWidth(LeftType);
      unsigned RightWidth = AST.getIntWidth(RightType);
      if (!Left || !Right || Left->get_sort().bv_size() != LeftWidth ||
          Right->get_sort().bv_size() != RightWidth)
        return std::nullopt;
      unsigned CommonWidth = std::max({LeftWidth, RightWidth, Width}) + 1;
      z3::expr LeftWide = isUnsigned(LeftType)
                              ? z3::zext(*Left, CommonWidth - LeftWidth)
                              : z3::sext(*Left, CommonWidth - LeftWidth);
      z3::expr RightWide = isUnsigned(RightType)
                               ? z3::zext(*Right, CommonWidth - RightWidth)
                               : z3::sext(*Right, CommonWidth - RightWidth);
      if (IsArithmetic) {
        z3::expr Wide = Opcode == BO_Add   ? LeftWide + RightWide
                        : Opcode == BO_Sub ? LeftWide - RightWide
                                           : LeftWide * RightWide;
        // Truncating an already wide-enough two's-complement sum/difference/
        // product down to the result's own true width is exactly the same
        // modular value plain Width-bit arithmetic would have produced --
        // this is the well-known extend-then-truncate identity for +/-/*,
        // not a new assumption -- so this remains an exact model of the
        // result, never an approximation of it.
        return Wide.extract(Width - 1, 0);
      }
      z3::expr Predicate = [&]() -> z3::expr {
        switch (Opcode) {
        case BO_EQ:
          return LeftWide == RightWide;
        case BO_NE:
          return LeftWide != RightWide;
        case BO_LT:
          return LeftWide < RightWide;
        case BO_LE:
          return LeftWide <= RightWide;
        case BO_GT:
          return LeftWide > RightWide;
        default: // BO_GE: the only remaining opcode this case can reach.
          return LeftWide >= RightWide;
        }
      }();
      return z3::ite(Predicate, ZCtx.bv_val(1, Width), ZCtx.bv_val(0, Width));
    }
    if (const auto *Binary = dyn_cast<SymIntExpr>(Expression)) {
      QualType LeftType = Binary->getLHS()->getType();
      if (LeftType.isNull() || !LeftType->isIntegerType() ||
          Binary->getRHS().getBitWidth() != AST.getIntWidth(LeftType) ||
          (BinaryOperator::isComparisonOp(Binary->getOpcode()) &&
           Binary->getRHS().isUnsigned() != isUnsigned(LeftType)))
        return std::nullopt;
      std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
      if (!Left || Left->get_sort().bv_size() != AST.getIntWidth(LeftType))
        return std::nullopt;
      z3::expr Right = bitVector(Binary->getRHS(), Left->get_sort().bv_size());
      return Apply(*Left, Right, Binary->getOpcode(), LeftType);
    }
    if (const auto *Binary = dyn_cast<IntSymExpr>(Expression)) {
      QualType RightType = Binary->getRHS()->getType();
      if (RightType.isNull() || !RightType->isIntegerType() ||
          Binary->getLHS().getBitWidth() != AST.getIntWidth(RightType) ||
          (BinaryOperator::isComparisonOp(Binary->getOpcode()) &&
           Binary->getLHS().isUnsigned() != isUnsigned(RightType)))
        return std::nullopt;
      std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
      if (!Right || Right->get_sort().bv_size() != AST.getIntWidth(RightType))
        return std::nullopt;
      z3::expr Left = bitVector(Binary->getLHS(), Right->get_sort().bv_size());
      return Apply(Left, *Right, Binary->getOpcode(), RightType);
    }
    return std::nullopt;
  }

  std::optional<z3::expr> translate(NonLoc Value, QualType Type) {
    if (std::optional<nonloc::ConcreteInt> Integer =
            Value.getAs<nonloc::ConcreteInt>())
      return bitVector(Integer->getValue(), AST.getIntWidth(Type));
    return translate(Value.getAsSymbol());
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

public:
  CastZ3Proof(CastZ3Engine &Engine, ProgramStateRef State, ASTContext &AST)
      : ZCtx(Engine.Context), Solver(Engine.Solver), AST(AST) {
    Solver.reset();
    for (const auto &Entry : getConstraintMap(State))
      if (std::optional<z3::expr> Expression = translate(Entry.first))
        addRange(*Expression, Entry.second);
    for (const auto &Entry : State->get<CastZ3BranchFact>()) {
      std::optional<z3::expr> Comparison = translate(Entry.first);
      if (!Comparison || !Comparison->is_bv())
        continue;
      // Apply()'s comparison case always returns a z3::ite bit-vector
      // {0,1}, mirroring how RangeSet already represents a Boolean-typed
      // SVal elsewhere in this file (an int-typed 0/1, not a Z3 Bool) --
      // so the recorded fact is an equality against that same encoding.
      z3::expr Fact = *Comparison == ZCtx.bv_val(Entry.second ? 1 : 0,
                                                 Comparison->get_sort().bv_size());
      if (Fact.is_bool())
        Solver.add(Fact);
    }
  }

  // Proves that Value (of type SourceType) always lies within
  // [DestMin, DestMax] under every currently-known path constraint.  Only
  // an UNSAT answer for "Value can lie outside that range" discharges the
  // obligation, matching every other Z3 consumer in this file: SAT,
  // timeout, and unknown all preserve the finding.
  bool provesRepresentable(NonLoc Value, QualType SourceType,
                           const llvm::APSInt &DestMin,
                           const llvm::APSInt &DestMax) {
    std::optional<z3::expr> Source = translate(Value, SourceType);
    if (!Source)
      return false;
    unsigned SourceWidth = AST.getIntWidth(SourceType);
    if (Source->get_sort().bv_size() != SourceWidth)
      return false;
    bool SourceUnsigned = isUnsigned(SourceType);

    // One extra guard bit above the wider of Source/Dest keeps every
    // value -- including an unsigned source's or dest's own maximum --
    // representable as an ordinary signed CommonWidth-bit integer, so a
    // single signed comparison below is correct regardless of either
    // side's original signedness.
    unsigned CommonWidth =
        std::max(SourceWidth, DestMin.getBitWidth()) + 1;
    z3::expr SourceWide = SourceUnsigned
                              ? z3::zext(*Source, CommonWidth - SourceWidth)
                              : z3::sext(*Source, CommonWidth - SourceWidth);
    z3::expr LowerWide = bitVector(DestMin, CommonWidth);
    z3::expr UpperWide = bitVector(DestMax, CommonWidth);
    z3::expr OutsideRange = SourceWide < LowerWide || SourceWide > UpperWide;
    if (!OutsideRange.is_bool())
      return false;
    Solver.add(OutsideRange);
    return ntlibc::algebra::provesUnsatisfiable(Solver);
  }

  // Proves a pointer-difference cast is safe by comparing the exact,
  // untruncated mathematical difference between its two operand symbols
  // directly against the cast's destination range, rather than routing
  // through provesRepresentable()'s generic reinterpret-through-the-cast's-
  // own-source-type path. That generic path is exactly right for every
  // OTHER cast this file proves (the source value really was computed
  // modulo its own declared width, so reinterpreting its bit pattern
  // through that width is the correct model) -- it is specifically wrong
  // here: C only defines `a - b` between two pointers into the same array
  // at all when their true difference already fits in ptrdiff_t, so a
  // buffer-size symbol with no independently-known upper bound (the
  // ordinary case -- nothing about `size_t len` alone says len fits in
  // PTRDIFF_MAX) makes provesRepresentable()'s own Width-bit truncate step
  // reintroduce exactly the sign-bit wraparound the cast is trying to
  // rule out, purely as an artifact of modeling a value through a width
  // its true, real-hardware computation never actually wraps at (confirmed
  // directly: instrumenting provesRepresentable() on man_builtin_pager()'s
  // own `(size_t)(end - p)` shape showed a real, provable `end_idx >=
  // p_idx` fact reaching the solver correctly, yet the proof still failed
  // until this method bypassed the truncate/re-widen step -- see this
  // file's SymSymExpr mismatched-width comment above for the sibling half
  // of that same investigation).
  //
  // Re-deriving that ptrdiff_t-representability precondition itself is a
  // pointer-provenance/object-bound obligation this file already declines
  // to check elsewhere -- see ArithmeticContractChecker::checkPreStmt
  // (BinaryOperator)'s own explicit skip of a pointer BO_Sub's overflow
  // check, for the identical reason -- so trusting it here, rather than
  // reproving it, matches this file's own existing convention rather than
  // inventing a new exception. Given that guarantee, `a - b`'s actual
  // runtime value already equals the exact mathematical difference with
  // no modular reduction, so comparing that same exact, guard-bit-padded
  // difference against the cast's destination range is sound.
  //
  // Deliberately narrow: only matches a bare top-level BO_Sub between two
  // plain integer operands (SymSymExpr/SymIntExpr/IntSymExpr) -- exactly
  // the shape RegionStore's own element-region offset arithmetic produces
  // for `end - p` once both pointers resolve to a comparable offset into
  // the same base region. checkPreStmt only ever calls this after
  // independently confirming, from the cast's own AST, that its source
  // expression really is a pointer-typed BO_Sub -- never for ordinary
  // integer subtraction, where no such standing guarantee exists and
  // skipping the width truncation would be unsound.
  bool provesPointerDifferenceRepresentable(NonLoc Value,
                                            const llvm::APSInt &DestMin,
                                            const llvm::APSInt &DestMax) {
    SymbolRef Sym = Value.getAsSymbol();
    if (!Sym)
      return false;
    const SymExpr *LeftSym = nullptr;
    const SymExpr *RightSym = nullptr;
    QualType LeftType, RightType;
    llvm::APSInt LeftLiteral, RightLiteral;
    bool LeftIsLiteral = false, RightIsLiteral = false;
    if (const auto *Binary = dyn_cast<SymSymExpr>(Sym)) {
      if (Binary->getOpcode() != BO_Sub)
        return false;
      LeftSym = Binary->getLHS();
      RightSym = Binary->getRHS();
      LeftType = LeftSym->getType();
      RightType = RightSym->getType();
    } else if (const auto *Binary = dyn_cast<SymIntExpr>(Sym)) {
      if (Binary->getOpcode() != BO_Sub)
        return false;
      LeftSym = Binary->getLHS();
      LeftType = LeftSym->getType();
      RightLiteral = Binary->getRHS();
      RightIsLiteral = true;
      RightType = LeftType;
    } else if (const auto *Binary = dyn_cast<IntSymExpr>(Sym)) {
      if (Binary->getOpcode() != BO_Sub)
        return false;
      RightSym = Binary->getRHS();
      RightType = RightSym->getType();
      LeftLiteral = Binary->getLHS();
      LeftIsLiteral = true;
      LeftType = RightType;
    } else {
      return false;
    }
    if (LeftType.isNull() || RightType.isNull() ||
        !LeftType->isIntegerType() || !RightType->isIntegerType())
      return false;
    unsigned LeftWidth = AST.getIntWidth(LeftType);
    unsigned RightWidth = AST.getIntWidth(RightType);
    std::optional<z3::expr> LeftRaw =
        LeftIsLiteral ? std::optional<z3::expr>(bitVector(LeftLiteral, LeftWidth))
                      : translate(LeftSym);
    std::optional<z3::expr> RightRaw =
        RightIsLiteral ? std::optional<z3::expr>(bitVector(RightLiteral, RightWidth))
                       : translate(RightSym);
    if (!LeftRaw || !RightRaw || LeftRaw->get_sort().bv_size() != LeftWidth ||
        RightRaw->get_sort().bv_size() != RightWidth)
      return false;
    unsigned CommonWidth =
        std::max({LeftWidth, RightWidth, DestMin.getBitWidth()}) + 1;
    z3::expr LeftWide = isUnsigned(LeftType)
                            ? z3::zext(*LeftRaw, CommonWidth - LeftWidth)
                            : z3::sext(*LeftRaw, CommonWidth - LeftWidth);
    z3::expr RightWide = isUnsigned(RightType)
                             ? z3::zext(*RightRaw, CommonWidth - RightWidth)
                             : z3::sext(*RightRaw, CommonWidth - RightWidth);
    z3::expr Diff = LeftWide - RightWide;
    z3::expr LowerWide = bitVector(DestMin, CommonWidth);
    z3::expr UpperWide = bitVector(DestMax, CommonWidth);
    z3::expr OutsideRange = Diff < LowerWide || Diff > UpperWide;
    if (!OutsideRange.is_bool())
      return false;
    Solver.add(OutsideRange);
    return ntlibc::algebra::provesUnsatisfiable(Solver);
  }
};
#endif

class SizeCastChecker
    : public Checker<check::PreStmt<ExplicitCastExpr>
#ifdef NTLIBC_ARITHMETIC_Z3
                     , eval::Assume
#endif
                     > {
  mutable std::unique_ptr<BugType> BT;

public:
  struct Interval {
    llvm::APSInt Min;
    llvm::APSInt Max;
  };

  static constexpr unsigned MathBits = 256;

  static llvm::APSInt typeMin(ASTContext &Ctx, QualType Type) {
    unsigned Bits = Ctx.getIntWidth(Type);
    bool Unsigned = Type->isUnsignedIntegerOrEnumerationType();
    return llvm::APSInt::getMinValue(Bits, Unsigned);
  }

  static llvm::APSInt typeMax(ASTContext &Ctx, QualType Type) {
    unsigned Bits = Ctx.getIntWidth(Type);
    bool Unsigned = Type->isUnsignedIntegerOrEnumerationType();
    return llvm::APSInt::getMaxValue(Bits, Unsigned);
  }

  static llvm::APSInt asSourceType(const llvm::APSInt &Value, unsigned Bits,
                                   bool Unsigned) {
    llvm::APInt Converted = Value;
    if (Converted.getBitWidth() < Bits)
      Converted =
          Value.isUnsigned() ? Converted.zext(Bits) : Converted.sext(Bits);
    else if (Converted.getBitWidth() > Bits)
      Converted = Converted.trunc(Bits);
    return llvm::APSInt(Converted, Unsigned);
  }

  static llvm::APSInt asMath(const llvm::APSInt &Value) {
    llvm::APInt Converted = Value;
    if (Converted.getBitWidth() < MathBits)
      Converted = Value.isUnsigned() ? Converted.zext(MathBits)
                                     : Converted.sext(MathBits);
    else if (Converted.getBitWidth() > MathBits)
      Converted = Converted.trunc(MathBits);
    return llvm::APSInt(Converted, false);
  }

  static Interval typeInterval(ASTContext &Ctx, QualType Type) {
    return {asMath(typeMin(Ctx, Type)), asMath(typeMax(Ctx, Type))};
  }

  static bool contains(const Interval &Outer, const Interval &Inner) {
    return llvm::APSInt::compareValues(Outer.Min, Inner.Min) <= 0 &&
           llvm::APSInt::compareValues(Outer.Max, Inner.Max) >= 0;
  }

  static bool containsMaskOrUnsignedShift(const Expr *Expression,
                                          unsigned Depth = 0) {
    if (!Expression || Depth >= 16)
      return false;
    Expression = Expression->IgnoreParens();
    if (const auto *Cast = dyn_cast<CastExpr>(Expression))
      return containsMaskOrUnsignedShift(Cast->getSubExpr(), Depth + 1);
    const auto *Binary = dyn_cast<BinaryOperator>(Expression);
    if (!Binary)
      return false;
    if (Binary->getOpcode() == BO_And ||
        (Binary->getOpcode() == BO_Shr &&
         Binary->getLHS()->getType()->isUnsignedIntegerOrEnumerationType()))
      return true;
    return containsMaskOrUnsignedShift(Binary->getLHS(), Depth + 1) ||
           containsMaskOrUnsignedShift(Binary->getRHS(), Depth + 1);
  }

  static std::optional<Interval>
  syntacticReducerInterval(const Expr *Expression, ASTContext &Ctx,
                           unsigned Depth = 0) {
    if (!Expression || Depth >= 16)
      return std::nullopt;
    Expression = Expression->IgnoreParens();
    if (const auto *Cast = dyn_cast<CastExpr>(Expression)) {
      auto Operand = syntacticReducerInterval(Cast->getSubExpr(), Ctx,
                                              Depth + 1);
      if (!Operand)
        return std::nullopt;
      return Operand;
    }
    const auto *Binary = dyn_cast<BinaryOperator>(Expression);
    if (!Binary)
      return std::nullopt;
    Interval Bounds = typeInterval(Ctx, Binary->getType());
    if (Binary->getOpcode() == BO_And) {
      const auto *Right = dyn_cast<IntegerLiteral>(
          Binary->getRHS()->IgnoreParenImpCasts());
      const auto *Left = dyn_cast<IntegerLiteral>(
          Binary->getLHS()->IgnoreParenImpCasts());
      const IntegerLiteral *Mask = Right ? Right : Left;
      if (!Mask)
        return Bounds;
      llvm::APSInt Value(
          Mask->getValue(),
          Mask->getType()->isUnsignedIntegerOrEnumerationType());
      llvm::APSInt Maximum = asMath(Value);
      if (Maximum.isNegative() || Maximum > Bounds.Max)
        return Bounds;
      llvm::APSInt Zero(llvm::APInt(MathBits, 0), false);
      return Interval{Zero, Maximum};
    }
    if (Binary->getOpcode() == BO_Shr &&
        Binary->getLHS()->getType()->isUnsignedIntegerOrEnumerationType()) {
      const auto *Count = dyn_cast<IntegerLiteral>(
          Binary->getRHS()->IgnoreParenImpCasts());
      if (!Count)
        return Bounds;
      uint64_t Shift = Count->getValue().getLimitedValue();
      unsigned Width = Ctx.getIntWidth(Binary->getLHS()->getType());
      if (Shift >= Width)
        return Bounds;
      llvm::APSInt Maximum = typeMax(Ctx, Binary->getLHS()->getType());
      Maximum = llvm::APSInt(Maximum.lshr(static_cast<unsigned>(Shift)),
                             Maximum.isUnsigned());
      llvm::APSInt Zero(llvm::APInt(MathBits, 0), false);
      return Interval{Zero, asMath(Maximum)};
    }
    return std::nullopt;
  }

  static llvm::APSInt minValue(std::initializer_list<llvm::APSInt> Values) {
    return *std::min_element(Values.begin(), Values.end(),
                             [](const auto &A, const auto &B) {
                               return llvm::APSInt::compareValues(A, B) < 0;
                             });
  }

  static llvm::APSInt maxValue(std::initializer_list<llvm::APSInt> Values) {
    return *std::max_element(Values.begin(), Values.end(),
                             [](const auto &A, const auto &B) {
                               return llvm::APSInt::compareValues(A, B) < 0;
                             });
  }

  // The tightest of two independently-sound over-approximations is still
  // sound: whatever the symbol's true value is, it lies in both intervals,
  // so it lies in their intersection too. Guards the one way that could
  // stop being true -- a bug in one side computing a genuinely disjoint
  // range -- by falling back to the solver-derived interval alone, which
  // this file already shipped and trusted before this lemma existed,
  // rather than ever handing back an inverted (Min > Max) interval that
  // callers would read as "no value is possible here", which is a
  // stronger and therefore unsound claim.
  static Interval intersectInterval(const Interval &Solver,
                                    const Interval &Symbolic) {
    Interval Result{maxValue({Solver.Min, Symbolic.Min}),
                    minValue({Solver.Max, Symbolic.Max})};
    if (llvm::APSInt::compareValues(Result.Min, Result.Max) > 0)
      return Solver;
    return Result;
  }

  // The binary-search-over-assume() solver query constrainedInterval()
  // already performed for a source Expr, generalized to any NonLoc so
  // symbolInterval() below can run the identical query for a bare
  // SymbolRef that names no Expr of its own (the whole point of that
  // function is to be reachable from a materialized value that was
  // stored into a variable or field and read back later).
  // State is a required, explicit parameter so recursive interval proofs
  // inspect one consistent program point.  The arithmetic-UB stage disables
  // Clang's overlapping DivideZero and BitwiseShift checkers; consequently
  // the current state retains genuine branch constraints without containing
  // a same-operation assumption supplied by a built-in checker.
  static Interval bisectInterval(NonLoc Value, QualType Type,
                                 ProgramStateRef State, CheckerContext &C) {
    ASTContext &Ctx = C.getASTContext();
    unsigned Bits = Ctx.getIntWidth(Type);
    bool Unsigned = Type->isUnsignedIntegerOrEnumerationType();
    llvm::APSInt NativeMin = typeMin(Ctx, Type);
    llvm::APSInt NativeMax = typeMax(Ctx, Type);
    llvm::APSInt One(llvm::APInt(MathBits, 1), false);
    llvm::APSInt Two(llvm::APInt(MathBits, 2), false);

    llvm::APSInt Low = asMath(NativeMin);
    llvm::APSInt High = asMath(NativeMax);
    while (Low < High) {
      llvm::APSInt Mid = Low + (High - Low) / Two;
      llvm::APSInt NativeMid = asSourceType(Mid, Bits, Unsigned);
      if (State->assumeInclusiveRange(Value, NativeMin, NativeMid, true))
        High = Mid;
      else
        Low = Mid + One;
    }
    llvm::APSInt Minimum = Low;

    Low = Minimum;
    High = asMath(NativeMax);
    while (Low < High) {
      llvm::APSInt Mid = Low + (High - Low + One) / Two;
      llvm::APSInt NativeMid = asSourceType(Mid, Bits, Unsigned);
      if (State->assumeInclusiveRange(Value, NativeMid, NativeMax, true))
        Low = Mid;
      else
        High = Mid - One;
    }
    return Interval{Minimum, Low};
  }

  static Interval combineBinary(BinaryOperator::Opcode Op,
                                const Interval &Left, const Interval &Right) {
    switch (Op) {
    case BO_Add:
      return Interval{Left.Min + Right.Min, Left.Max + Right.Max};
    case BO_Sub:
      return Interval{Left.Min - Right.Max, Left.Max - Right.Min};
    case BO_Mul: {
      llvm::APSInt A = Left.Min * Right.Min;
      llvm::APSInt B = Left.Min * Right.Max;
      llvm::APSInt D = Left.Max * Right.Min;
      llvm::APSInt E = Left.Max * Right.Max;
      return Interval{minValue({A, B, D, E}), maxValue({A, B, D, E})};
    }
    default:
      llvm_unreachable("combineBinary called with an unhandled opcode");
    }
  }

  static constexpr unsigned MaxSymbolDepth = 16;

  static bool containsRangeReducer(SymbolRef Sym, unsigned Depth = 0) {
    if (!Sym || Depth >= MaxSymbolDepth)
      return false;
    if (const auto *Expression = dyn_cast<SymIntExpr>(Sym)) {
      BinaryOperator::Opcode Op = Expression->getOpcode();
      return Op == BO_Rem;
    }
    if (const auto *Expression = dyn_cast<IntSymExpr>(Sym)) {
      BinaryOperator::Opcode Op = Expression->getOpcode();
      return Op == BO_Rem;
    }
    if (const auto *Expression = dyn_cast<SymSymExpr>(Sym)) {
      BinaryOperator::Opcode Op = Expression->getOpcode();
      return Op == BO_Rem;
    }
    if (const auto *Cast = dyn_cast<SymbolCast>(Sym))
      return containsRangeReducer(Cast->getOperand(), Depth + 1);
    return false;
  }

  // expressionInterval() below already narrows `hash % n`, `mask & bits`,
  // and `value >> shift` when it walks those operators inline in the
  // source AST -- but that walk starts fresh from each Expr, so it only
  // sees a divisor/mask/shift-count still written out at the use site.
  // strtod.c's bn_shl() writes `int b = k % 32;` once and rereads plain
  // `b` in `v >> (32 - b)`; printf.c's fmt_a() writes `int shift =
  // (13 - prec) * 4;` once and rereads `shift` four times. Both are a
  // value already narrow by construction, re-read past where the
  // source-level walk can see the operator that narrowed it.
  //
  // RegionStore gives an exact answer for what that reread finds: absent
  // an intervening call that could write through an escaped alias, a
  // load from that local returns the same SVal that was stored, so the
  // symbol behind a reread of `b` IS the SymIntExpr for `$k % 32`. The
  // default solver doesn't re-derive a tight range for that compound
  // symbol on its own (nothing branched on `b`'s value to teach it one),
  // which is why expressionInterval()'s Rem/And/Shr cases exist;
  // symbolInterval() runs that same reasoning over the SymExpr the
  // engine already built instead of the Expr the programmer wrote.
  //
  // Every branch here is a strict subset of what expressionInterval()
  // already computes for the equivalent AST shape, so this adds no new
  // interval theory, only a second path to the existing one. A shape
  // this can't decompose falls through to the same solver bisection
  // constrainedInterval() already ran, so this can only tighten a
  // result, never replace a sound one with an unsound one --
  // intersectInterval() falls back to the solver-only side on
  // disagreement.
  static Interval symbolInterval(SymbolRef Sym, ProgramStateRef State,
                                 CheckerContext &C, unsigned Depth) {
    ASTContext &Ctx = C.getASTContext();
    QualType Type = Sym->getType();
    // A sub-symbol whose own type is not an integer -- concretely, a
    // pointer-region-value symbol reached while decomposing an integer
    // cast of pointer arithmetic, e.g. `(long)p - (long)q` -- can never
    // be wrapped in nonloc::SymbolVal at all: that constructor asserts
    // !Loc::isLocType(Sym->getType()), so calling it here is not merely
    // imprecise but a guaranteed analyzer crash (confirmed directly: an
    // earlier version of this function called bisectInterval() on such a
    // symbol unconditionally and crashed clang --analyze on real files,
    // e.g. arch/aarch64/src/ld128_convert.c, with exactly that
    // assertion). Fully unbounded -- MathBits' own widest range -- is
    // always a sound, if useless, answer for a term with no integer type
    // this function has any way to reason about; the solver bisection
    // below is likewise skipped once MaxSymbolDepth is reached, for the
    // same reason expressionInterval() itself never recurses unbounded.
    if (!Type->isIntegerType())
      return {llvm::APSInt::getMinValue(MathBits, false),
             llvm::APSInt::getMaxValue(MathBits, false)};
    if (Depth >= MaxSymbolDepth)
      return bisectInterval(nonloc::SymbolVal(Sym), Type, State, C);
    Interval Bound = typeInterval(Ctx, Type);

    llvm::APSInt Zero(llvm::APInt(MathBits, 0), false);
    llvm::APSInt One(llvm::APInt(MathBits, 1), false);
    bool ResultUnsigned = Type->isUnsignedIntegerOrEnumerationType();

    if (const auto *IntExpr = dyn_cast<SymIntExpr>(Sym)) {
      BinaryOperator::Opcode Op = IntExpr->getOpcode();
      llvm::APSInt Right = asMath(IntExpr->getRHS());
      if (Op == BO_Rem && Right.isStrictlyPositive()) {
        llvm::APSInt Magnitude = Right - One;
        if (ResultUnsigned)
          return intersectInterval(Bound, Interval{Zero, Magnitude});
        Interval Left = symbolInterval(IntExpr->getLHS(), State, C, Depth + 1);
        if (Left.Min >= Zero)
          return intersectInterval(Bound, Interval{Zero, Magnitude});
        if (Left.Max <= Zero)
          return intersectInterval(Bound, Interval{-Magnitude, Zero});
        return intersectInterval(Bound, Interval{-Magnitude, Magnitude});
      }
      if (Op == BO_And && !Right.isNegative() && Right <= Bound.Max)
        return intersectInterval(Bound, Interval{Zero, Right});
      if (Op == BO_Shr && ResultUnsigned) {
        unsigned Width = Ctx.getIntWidth(Type);
        if (!Right.isNegative() && Right.getLimitedValue() < Width) {
          unsigned Shift = static_cast<unsigned>(Right.getLimitedValue());
          llvm::APSInt Maximum = typeMax(Ctx, Type);
          Maximum = llvm::APSInt(Maximum.lshr(Shift), Maximum.isUnsigned());
          return intersectInterval(Bound, Interval{Zero, asMath(Maximum)});
        }
      }
      if (Op == BO_Add || Op == BO_Sub || Op == BO_Mul) {
        Interval Left = symbolInterval(IntExpr->getLHS(), State, C, Depth + 1);
        Interval Result = combineBinary(Op, Left, Interval{Right, Right});
        return intersectInterval(Bound, Result);
      }
    } else if (const auto *SymInt = dyn_cast<IntSymExpr>(Sym)) {
      BinaryOperator::Opcode Op = SymInt->getOpcode();
      llvm::APSInt LeftValue = asMath(SymInt->getLHS());
      if (Op == BO_And && !LeftValue.isNegative() &&
          LeftValue <= Bound.Max)
        return intersectInterval(Bound, Interval{Zero, LeftValue});
      if (Op == BO_Add || Op == BO_Sub || Op == BO_Mul) {
        Interval Right = symbolInterval(SymInt->getRHS(), State, C, Depth + 1);
        Interval Result =
            combineBinary(Op, Interval{LeftValue, LeftValue}, Right);
        return intersectInterval(Bound, Result);
      }
    } else if (const auto *SymExprB = dyn_cast<SymSymExpr>(Sym)) {
      BinaryOperator::Opcode Op = SymExprB->getOpcode();
      if (Op == BO_Rem || Op == BO_And || Op == BO_Shr || Op == BO_Add ||
          Op == BO_Sub || Op == BO_Mul) {
        Interval Left =
            symbolInterval(SymExprB->getLHS(), State, C, Depth + 1);
        Interval Right =
            symbolInterval(SymExprB->getRHS(), State, C, Depth + 1);
        if (Op == BO_Rem && Right.Min > Zero) {
          llvm::APSInt Magnitude = Right.Max - One;
          if (ResultUnsigned)
            return intersectInterval(Bound, Interval{Zero, Magnitude});
          if (Left.Min >= Zero)
            return intersectInterval(Bound, Interval{Zero, Magnitude});
          if (Left.Max <= Zero)
            return intersectInterval(Bound, Interval{-Magnitude, Zero});
          return intersectInterval(Bound,
                                   Interval{-Magnitude, Magnitude});
        }
        if (Op == BO_And && Right.Min == Right.Max &&
            !Right.Min.isNegative() && Right.Max <= Bound.Max)
          return intersectInterval(Bound, Interval{Zero, Right.Max});
        if (Op == BO_Shr && ResultUnsigned && Right.Min == Right.Max) {
          unsigned Width = Ctx.getIntWidth(Type);
          if (!Right.Min.isNegative() &&
              Right.Min.getLimitedValue() < Width) {
            unsigned Shift =
                static_cast<unsigned>(Right.Min.getLimitedValue());
            llvm::APSInt Maximum = typeMax(Ctx, Type);
            Maximum = llvm::APSInt(Maximum.lshr(Shift), Maximum.isUnsigned());
            return intersectInterval(Bound,
                                     Interval{Zero, asMath(Maximum)});
          }
        }
        if (Op == BO_Add || Op == BO_Sub || Op == BO_Mul) {
          Interval Result = combineBinary(Op, Left, Right);
          return intersectInterval(Bound, Result);
        }
      }
    } else if (const auto *CastSym = dyn_cast<SymbolCast>(Sym)) {
      // Only trusted if the operand's own range already fits inside this
      // cast's destination type without truncation -- the same
      // contains()-gated rule expressionInterval() applies to an
      // ImplicitCastExpr, so a genuinely narrowing cast still falls
      // through to the plain solver bisection below rather than being
      // handed a pre-cast range that a truncation could have invalidated.
      Interval Operand =
          symbolInterval(CastSym->getOperand(), State, C, Depth + 1);
      if (contains(Bound, Operand))
        return Operand;
      if (containsRangeReducer(CastSym->getOperand()))
        return Bound;
    }

    return intersectInterval(
        bisectInterval(nonloc::SymbolVal(Sym), Type, State, C), Bound);
  }

  // State defaults to C.getState(); the explicit overload exists so every
  // recursive query can be pinned to the same program point.
  static std::optional<Interval>
  constrainedInterval(const Expr *Expr, CheckerContext &C,
                      ProgramStateRef State = nullptr) {
    if (!State)
      State = C.getState();
    SVal Value = State->getSVal(Expr, C.getLocationContext());
    // Unary ++/-- hand us their lvalue operand directly, rather than the
    // ImplicitCastExpr(CK_LValueToRValue) that a binary arithmetic operand
    // contains.  Load that location explicitly so the range solver sees the
    // path constraints on the variable.  Treating the location as an unknown
    // integer interval made every guarded loop induction step look capable of
    // overflowing even at `i < 3`.
    if (Expr->isLValue() && Expr->getType()->isIntegerType())
      if (std::optional<Loc> Location = Value.getAs<Loc>())
        Value = State->getSVal(*Location, Expr->getType());
    if (const llvm::APSInt *Integer = Value.getAsInteger()) {
      llvm::APSInt Exact = asMath(*Integer);
      return Interval{Exact, Exact};
    }
    std::optional<NonLoc> Defined = Value.getAs<NonLoc>();
    if (!Defined)
      return std::nullopt;

    SymbolRef Sym = Value.getAsSymbol();
    Interval Result = bisectInterval(*Defined, Expr->getType(), State, C);
    if (Sym) {
      Interval Symbolic = symbolInterval(Sym, State, C, 0);
      // Clang retains unsigned remainder/mask/right-shift expressions beneath
      // a representable cast to a signed materialized local.  Its generic
      // range query applies the signed expression bounds to that unsigned
      // SVal and can return a spurious disjoint extreme.  The reducer interval
      // is independently sound; carry it through only when every possible
      // value fits the source expression's destination type.  All other
      // symbol shapes keep the historical solver/intersection behavior.
      Interval ExprRange = typeInterval(C.getASTContext(), Expr->getType());
      if (containsRangeReducer(Sym) &&
          !C.getASTContext().hasSameType(Sym->getType(), Expr->getType()) &&
          contains(ExprRange, Symbolic))
        return Symbolic;
      Result = intersectInterval(Result, Symbolic);
    }
    return Result;
  }

  // Same State-defaulting rule as constrainedInterval() just above: this
  // function threads one program point through every recursive query.
  static Interval expressionInterval(const Expr *Expr, CheckerContext &C,
                                     ProgramStateRef State = nullptr) {
    if (!State)
      State = C.getState();
    Expr = Expr->IgnoreParens();
    ASTContext &Ctx = C.getASTContext();
    Interval ResultType = typeInterval(Ctx, Expr->getType());

    if (const auto *Cast = dyn_cast<CastExpr>(Expr);
        Cast && (isa<ImplicitCastExpr>(Cast) ||
                 containsMaskOrUnsignedShift(Cast->getSubExpr()))) {
      if (Cast->getCastKind() == CK_LValueToRValue) {
        if (std::optional<Interval> Known =
                constrainedInterval(Cast, C, State))
          return *Known;
        return ResultType;
      }
      Interval Operand = expressionInterval(Cast->getSubExpr(), C, State);
      return contains(ResultType, Operand) ? Operand : ResultType;
    }

    if (const auto *Unary = dyn_cast<UnaryOperator>(Expr)) {
      Interval Operand = expressionInterval(Unary->getSubExpr(), C, State);
      if (Unary->getOpcode() == UO_Plus)
        return Operand;
      if (Unary->getOpcode() == UO_Minus) {
        Interval Result{-Operand.Max, -Operand.Min};
        return contains(ResultType, Result) ? Result : ResultType;
      }
    }

    if (const auto *Binary = dyn_cast<BinaryOperator>(Expr)) {
      /* Terminal range reducers are deliberately handled before the left
       * operand.  A hash may be arbitrarily complicated, but `hash % n` is
       * bounded by n alone; walking the hash to manufacture bounds would be
       * both slower and less precise. */
      if (Binary->getOpcode() == BO_Rem) {
        Interval Right = expressionInterval(Binary->getRHS(), C, State);
        llvm::APSInt Zero(llvm::APInt(MathBits, 0), false);
        llvm::APSInt One(llvm::APInt(MathBits, 1), false);
        if (Right.Min > Zero) {
          llvm::APSInt Magnitude = Right.Max - One;
          if (Expr->getType()->isUnsignedIntegerOrEnumerationType())
            return Interval{Zero, Magnitude};
          Interval Left = expressionInterval(Binary->getLHS(), C, State);
          if (Left.Min >= Zero)
            return Interval{Zero, Magnitude};
          if (Left.Max <= Zero)
            return Interval{-Magnitude, Zero};
          return Interval{-Magnitude, Magnitude};
        }
      }
      if (Binary->getOpcode() == BO_And) {
        Interval Right = expressionInterval(Binary->getRHS(), C, State);
        if (Right.Min == Right.Max && !Right.Min.isNegative() &&
            Right.Max <= ResultType.Max) {
          llvm::APSInt Zero(llvm::APInt(MathBits, 0), false);
          return Interval{Zero, Right.Max};
        }
      }
      if (Binary->getOpcode() == BO_Shr &&
          Expr->getType()->isUnsignedIntegerOrEnumerationType()) {
        Interval Right = expressionInterval(Binary->getRHS(), C, State);
        unsigned Width = Ctx.getIntWidth(Expr->getType());
        if (Right.Min == Right.Max && !Right.Min.isNegative() &&
            Right.Min.getLimitedValue() < Width) {
          unsigned Shift = static_cast<unsigned>(Right.Min.getLimitedValue());
          llvm::APSInt Zero(llvm::APInt(MathBits, 0), false);
          llvm::APSInt Maximum = typeMax(Ctx, Expr->getType());
          Maximum = llvm::APSInt(Maximum.lshr(Shift), Maximum.isUnsigned());
          return Interval{Zero, asMath(Maximum)};
        }
      }

      Interval Left = expressionInterval(Binary->getLHS(), C, State);
      Interval Right = expressionInterval(Binary->getRHS(), C, State);
      std::optional<Interval> Result;
      switch (Binary->getOpcode()) {
      case BO_Add:
        Result = Interval{Left.Min + Right.Min, Left.Max + Right.Max};
        break;
      case BO_Sub:
        Result = Interval{Left.Min - Right.Max, Left.Max - Right.Min};
        break;
      case BO_Mul: {
        llvm::APSInt A = Left.Min * Right.Min;
        llvm::APSInt B = Left.Min * Right.Max;
        llvm::APSInt D = Left.Max * Right.Min;
        llvm::APSInt E = Left.Max * Right.Max;
        Result = Interval{minValue({A, B, D, E}), maxValue({A, B, D, E})};
        break;
      }
      default:
        break;
      }
      if (Result && contains(ResultType, *Result))
        return *Result;
      return ResultType;
    }

    if (std::optional<Interval> Known = constrainedInterval(Expr, C, State))
      return *Known;
    return ResultType;
  }

  static std::string sourceText(const Expr *Expr, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    SourceLocation Begin = SM.getSpellingLoc(Expr->getBeginLoc());
    SourceLocation End = SM.getSpellingLoc(Expr->getEndLoc());
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
    if (Result.empty() && Expr->getBeginLoc().isMacroID())
      Result = Lexer::getImmediateMacroNameForDiagnostics(Expr->getBeginLoc(),
                                                          SM, C.getLangOpts())
                   .str();
    if (Result.empty())
      Result = Expr->getStmtClassName();
    return Result;
  }

  static std::string sourceOrigin(const Expr *Expr, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    return SM.getFilename(SM.getExpansionLoc(Expr->getBeginLoc())).str();
  }

  static std::string sourceSite(const Expr *Expr, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Expr->getBeginLoc());
    FileID File = SM.getFileID(Location);
    bool Invalid = false;
    StringRef Buffer = SM.getBufferData(File, &Invalid);
    if (Invalid)
      return Expr->getStmtClassName();
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

public:
  void checkPreStmt(const ExplicitCastExpr *Cast, CheckerContext &C) const {
    if (Cast->getCastKind() != CK_IntegralCast &&
        Cast->getCastKind() != CK_IntegralToBoolean)
      return;

    QualType Source = Cast->getSubExpr()->getType();
    QualType Dest = Cast->getType();
    if (!Source->isIntegerType() || !Dest->isIntegerType())
      return;

    ASTContext &Ctx = C.getASTContext();
    llvm::APSInt SourceMin = typeMin(Ctx, Source);
    llvm::APSInt SourceMax = typeMax(Ctx, Source);
    llvm::APSInt DestMin = typeMin(Ctx, Dest);
    llvm::APSInt DestMax = typeMax(Ctx, Dest);
    unsigned SourceBits = Ctx.getIntWidth(Source);
    unsigned DestBits = Ctx.getIntWidth(Dest);

    if (llvm::APSInt::compareValues(DestMin, SourceMin) <= 0 &&
        llvm::APSInt::compareValues(DestMax, SourceMax) >= 0)
      return;

    const llvm::APSInt &Lower =
        llvm::APSInt::compareValues(SourceMin, DestMin) >= 0 ? SourceMin
                                                             : DestMin;
    const llvm::APSInt &Upper =
        llvm::APSInt::compareValues(SourceMax, DestMax) <= 0 ? SourceMax
                                                             : DestMax;
    bool Disjoint = llvm::APSInt::compareValues(Lower, Upper) > 0;
    SVal Value = C.getSVal(Cast->getSubExpr());
    std::optional<NonLoc> Defined = Value.getAs<NonLoc>();
    ProgramStateRef PathState = C.getState();
    ProgramStateRef Outside = PathState;
    if (Defined && !Disjoint) {
      bool SourceUnsigned = Source->isUnsignedIntegerOrEnumerationType();
      llvm::APSInt From = asSourceType(Lower, SourceBits, SourceUnsigned);
      llvm::APSInt To = asSourceType(Upper, SourceBits, SourceUnsigned);
      Outside = PathState->assumeInclusiveRange(*Defined, From, To, false);
      if (!Outside)
        return;
    }
    if (SourceBits <= MathBits && DestBits <= MathBits &&
        contains(typeInterval(Ctx, Dest),
                 expressionInterval(Cast->getSubExpr(), C)))
      return;
#ifdef NTLIBC_ARITHMETIC_Z3
    // The interval-only proof above gave up.  Ask the SizeCast-scoped Z3
    // bridge whether every range Clang's own engine has already narrowed
    // on this real path (PathState, not the report-only Outside state
    // above -- that state was itself constructed by *assuming* the value
    // falls outside the safe overlap, which would bias the query) jointly
    // entails that Value fits in [DestMin, DestMax].  Purely additive: a
    // failed query changes nothing, since the existing report path below
    // still runs exactly as it always has.
    if (Defined && SourceBits <= MathBits && DestBits <= MathBits) {
      CastZ3Proof Proof(castZ3Engine(), PathState, Ctx);
      // A cast whose own source expression is literally a pointer
      // difference (`(size_t)(end - p)`-shaped) gets the dedicated,
      // truncation-free proof first -- see provesPointerDifferenceRepresentable()'s
      // own comment for why the generic path below can spuriously fail on
      // exactly this shape once the buffer-size operand has no proven
      // upper bound. Gated on the CAST's own AST, not on Value's runtime
      // shape, so this can never fire for an ordinary integer subtraction
      // that merely happens to produce the same kind of SymExpr.
      //
      // SameBaseRegion is what makes trusting the C-standard "representable
      // in ptrdiff_t" precondition sound rather than merely convenient:
      // provesPointerDifferenceRepresentable() itself pattern-matches only
      // on the resulting integer SymExpr's shape (a bare top-level BO_Sub
      // between two plain symbols), which says nothing on its own about
      // whether those two symbols were ever offsets into the same object --
      // two entirely unrelated pointers subtracted could in principle
      // produce the identical shape. Two adversarial fixtures probed this
      // directly (tools/lint-cast-range-fixtures/pointer-diff.c's
      // unrelated_buffers() and unrelated_cursors()): in practice, for
      // both, Clang's own engine already declines to produce a usable
      // relational fact for a `<` comparison (or, for unrelated_buffers,
      // the ordinary assumeInclusiveRange() check just above already
      // short-circuits before CastZ3Proof ever runs) -- comparing pointers
      // into two unrelated objects is itself undefined behavior in C, and
      // the analyzer treats it conservatively. Neither fixture was
      // observed to actually flip from that ablation, so this guard was
      // not caught fixing a live false accept on either -- it is kept
      // anyway as this class's own explicit, independently-verifiable
      // invariant, rather than resting soundness on the incidental fact
      // that some other part of the engine happens to decline first.
      // getBaseRegion() strips away any ElementRegion/FieldRegion layers
      // down to each pointer's own root region (a VarRegion,
      // SymbolicRegion, etc.), the same technique
      // PointerProvenanceChecker.cpp already uses elsewhere in this tree
      // to decide whether two pointers alias one object; two pointers into
      // the very same array always share that same root by construction,
      // so pointer identity between the two roots is exact, not a
      // heuristic.
      const auto *Difference =
          dyn_cast<BinaryOperator>(Cast->getSubExpr()->IgnoreParens());
      bool IsPointerDifference =
          Difference && Difference->getOpcode() == BO_Sub &&
          Difference->getLHS()->getType()->isPointerType() &&
          Difference->getRHS()->getType()->isPointerType();
      const MemRegion *LeftRegion =
          IsPointerDifference
              ? C.getSVal(Difference->getLHS()).getAsRegion()
              : nullptr;
      const MemRegion *RightRegion =
          IsPointerDifference
              ? C.getSVal(Difference->getRHS()).getAsRegion()
              : nullptr;
      bool SameBaseRegion =
          LeftRegion && RightRegion &&
          LeftRegion->getBaseRegion() == RightRegion->getBaseRegion();
      if (IsPointerDifference && SameBaseRegion &&
          Proof.provesPointerDifferenceRepresentable(*Defined, DestMin,
                                                      DestMax))
        return;
      if (Proof.provesRepresentable(*Defined, Source, DestMin, DestMax))
        return;
    }
#endif

    ExplodedNode *Node = C.generateNonFatalErrorNode(Outside);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven integer cast",
                                     categories::LogicError);

    const Decl *Current = C.getLocationContext()->getDecl();
    std::string Context = Current ? Current->getDeclKindName() : "unknown";
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      Context = Named->getQualifiedNameAsString();
    std::string Message =
        "integer cast from '" + Source.getAsString() + "' to '" +
        Dest.getAsString() + "' is not proven to preserve its value; origin '" +
        sourceOrigin(Cast, C) + "'; context '" + Context + "'; cast '" +
        sourceText(Cast, C) + "'; site '" + sourceSite(Cast, C) + "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Cast->getSourceRange());
    C.emitReport(std::move(Report));
  }

#ifdef NTLIBC_ARITHMETIC_Z3
  // Records a relational fact so CastZ3Proof can assert it later.  This is
  // deliberately not limited to symbol-vs-symbol (SymSymExpr) comparisons:
  // empirically, getConstraintMap(State) -- the mechanism this file's
  // other Z3 bridge (ArithmeticZ3Proof) relies on for ordinary
  // symbol-vs-*concrete* facts too -- was observed returning completely
  // empty on real, minimal guarded-cast test cases in this Clang 18 build
  // (confirmed by dumping it directly: a plain `if (room > 1000) return
  // 0;` guard, whose effect the plain diagnostic path text already shows
  // as "Assuming 'room' is <= 1000", produced zero entries by the time the
  // guarded return statement's cast was reached). Recording *every*
  // comparison assumption here -- symbol-vs-concrete and
  // symbol-vs-symbol alike -- makes this checker's own Z3 proof power
  // self-sufficient rather than depending on that map being populated.
  // Purely additive to ProgramState: never rejects or narrows anything the
  // engine's own constraint manager already decided, only remembers a fact
  // it would otherwise drop or that this class cannot otherwise recover.
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Condition,
                             bool Assumption) const {
    SymbolRef Symbol = Condition.getAsSymbol();
    const auto *Comparison = dyn_cast_or_null<BinarySymExpr>(Symbol);
    if (!Comparison || !BinaryOperator::isComparisonOp(Comparison->getOpcode()))
      return State;
    return State->set<CastZ3BranchFact>(Symbol, Assumption);
  }
#endif
};

#ifdef NTLIBC_ARITHMETIC_Z3
// A third Z3 bridge, scoped to ntlibc.ArrayIndex alone for the identical
// isolation reason CastZ3Engine/CastZ3Proof above document for
// ntlibc.SizeCast: this extension can only ever change ArrayIndex's own
// findings, never SizeCast's or arithub's.
//
// The obligation this proves is a different shape from either of this
// file's other two Z3 consumers. include/string.h's withtok(null_terminated)
// -- the same per-parameter trust boundary TotalityChecker.cpp's
// nullTerminatedParameter() already reads off strlen/wcslen's own
// declaration -- guarantees a null-terminated buffer's extent is at least
// one element (the terminator, if nothing else), so index 0 into one is
// always in bounds with no further proof needed. Index 1 is NOT: it is in
// bounds only on paths where a real, dominating branch has already
// established that byte 0 is not the terminator, e.g. `if (a[0] != '-' ||
// a[1] == 0) break;` (src/util/m4.c's own option-parsing idiom, repeated
// across dozens of these utilities) only ever evaluates `a[1]` once `a[0]
// != '-'` has tested false, i.e. once a[0] == '-' -- a concrete, nonzero
// byte. An unguarded a[1] on a length-0-or-1 string is a REAL bug and must
// stay flagged; this bridge exists specifically to tell the two cases
// apart on real path constraints, not to accept a[1] unconditionally.
//
// getConstraintMap(State) was already shown empty for realistic guard
// shapes in this Clang 18 build -- see CastZ3BranchFact's own comment for
// how that was confirmed -- which is exactly why CastZ3Proof cannot just
// rely on it, and exactly why this bridge cannot either: ArrayIndexZ3BranchFact
// records every comparison assumption from eval::Assume unconditionally, the
// same technique CastZ3BranchFact already uses, so this checker's own proof
// power does not depend on that other map being populated.
class ArrayIndexZ3Engine {
public:
  z3::context Context;
  z3::solver Solver;

  ArrayIndexZ3Engine() : Solver(Context) {
    z3::params Parameters(Context);
    Parameters.set("rlimit", 1000000u);
    Parameters.set("timeout", 2000u);
    Solver.set(Parameters);
  }
};

static ArrayIndexZ3Engine &arrayIndexZ3Engine() {
  // Static-analyzer callbacks are serial within one translation-unit
  // process; lint.sh provides process parallelism across translation units
  // (see arithmeticZ3Engine()'s identical rationale elsewhere in this file).
  static thread_local ArrayIndexZ3Engine Engine;
  return Engine;
}

class ArrayIndexZ3Proof {
  z3::context &ZCtx;
  z3::solver &Solver;
  ASTContext &AST;
  // The one already-conjured byte symbol this whole proof exists to reason
  // about (e.g. a[0]'s own SymbolRegionValue) -- see translate()'s
  // SymbolCast case for why this specific symbol, and only this one, is
  // ever allowed to cross a widening cast.
  SymbolRef TrustedLeaf;

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

  // Deliberately the same restricted shape as CastZ3Proof::translate()
  // above (same-width SymbolCast passthrough; plain comparisons produce a
  // {0,1} bit-vector exactly like RangeSet's own Boolean-typed SVal
  // representation elsewhere in this file): this proof only ever needs to
  // relate one already-conjured byte symbol to the literal/relational facts
  // a branch recorded about it, never to model a real arithmetic
  // operation's own overflow/wrap/narrowing events.
  std::optional<z3::expr> translate(const SymExpr *Expression,
                                    unsigned Depth = 0) {
    if (!Expression || Depth > 24 || Expression->getType().isNull() ||
        !Expression->getType()->isIntegerType())
      return std::nullopt;
    unsigned Width = AST.getIntWidth(Expression->getType());
    if (const auto *Data = dyn_cast<SymbolData>(Expression)) {
      std::string Name =
          "ntlibc_arrayidx_sym_" + std::to_string(Data->getSymbolID());
      return ZCtx.bv_const(Name.c_str(), Width);
    }
    if (const auto *Cast = dyn_cast<SymbolCast>(Expression)) {
      QualType OperandType = Cast->getOperand()->getType();
      if (OperandType.isNull() || !OperandType->isIntegerType())
        return std::nullopt;
      unsigned OperandWidth = AST.getIntWidth(OperandType);
      if (OperandWidth == Width)
        return translate(Cast->getOperand(), Depth + 1);
      // A genuine WIDENING cast -- concretely, the ordinary C integer
      // promotion `a[0] != '-'` applies to a[0]'s own char-typed value
      // before comparing it against int-typed '-' -- is rejected in
      // general for the identical reason CastZ3Proof/ArithmeticZ3Proof
      // reject every SymbolCast elsewhere in this file: Clang 18 exposes
      // no accessor for a SymbolCast's true source type, so
      // Cast->getOperand()->getType() is not a safe substitute in general
      // -- a chain of casts can be folded into one SymbolCast node, and
      // getOperand() can return a type from further back in that chain
      // than the immediate cast this node claims to be, silently skipping
      // over an intermediate *narrowing* step this function would then
      // never see.
      //
      // That risk does not apply when the operand IS, by pointer identity,
      // TrustedLeaf itself: TrustedLeaf is always a freshly conjured
      // SymbolRegionValue (see nullTerminatedIndexInBounds()'s own
      // comment) with no cast of any kind ever previously applied to it,
      // so a SymbolCast directly wrapping it cannot be hiding a folded
      // chain -- there is nothing upstream of it to fold. This still never
      // accepts a widening cast over any OTHER symbol, and never accepts a
      // narrowing one at all.
      if (Cast->getOperand() != TrustedLeaf || OperandWidth > Width)
        return std::nullopt;
      std::optional<z3::expr> Operand =
          translate(Cast->getOperand(), Depth + 1);
      if (!Operand || Operand->get_sort().bv_size() != OperandWidth)
        return std::nullopt;
      return OperandType->isUnsignedIntegerOrEnumerationType()
                 ? z3::zext(*Operand, Width - OperandWidth)
                 : z3::sext(*Operand, Width - OperandWidth);
    }

    auto Apply = [&](const z3::expr &Left, const z3::expr &Right,
                     BinaryOperator::Opcode Opcode,
                     QualType OperandType) -> std::optional<z3::expr> {
      if (Left.get_sort().bv_size() != Right.get_sort().bv_size())
        return std::nullopt;
      switch (Opcode) {
      case BO_EQ:
      case BO_NE:
      case BO_LT:
      case BO_LE:
      case BO_GT:
      case BO_GE: {
        bool OperandUnsigned =
            OperandType->isUnsignedIntegerOrEnumerationType();
        z3::expr Predicate = [&]() -> z3::expr {
          switch (Opcode) {
          case BO_EQ:
            return Left == Right;
          case BO_NE:
            return Left != Right;
          case BO_LT:
            return OperandUnsigned ? z3::ult(Left, Right) : Left < Right;
          case BO_LE:
            return OperandUnsigned ? z3::ule(Left, Right) : Left <= Right;
          case BO_GT:
            return OperandUnsigned ? z3::ugt(Left, Right) : Left > Right;
          default: // BO_GE: the only remaining opcode this case can reach.
            return OperandUnsigned ? z3::uge(Left, Right) : Left >= Right;
          }
        }();
        return z3::ite(Predicate, ZCtx.bv_val(1, Width), ZCtx.bv_val(0, Width));
      }
      default:
        return std::nullopt;
      }
    };

    auto SameWidth = [&](QualType Left, QualType Right) {
      return !Left.isNull() && !Right.isNull() && Left->isIntegerType() &&
             Right->isIntegerType() &&
             AST.getIntWidth(Left) == AST.getIntWidth(Right);
    };
    if (const auto *Binary = dyn_cast<SymSymExpr>(Expression)) {
      QualType LeftType = Binary->getLHS()->getType();
      QualType RightType = Binary->getRHS()->getType();
      if (!SameWidth(LeftType, RightType) ||
          (BinaryOperator::isComparisonOp(Binary->getOpcode()) &&
           LeftType->isUnsignedIntegerOrEnumerationType() !=
               RightType->isUnsignedIntegerOrEnumerationType()))
        return std::nullopt;
      std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
      std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
      if (!Left || !Right)
        return std::nullopt;
      return Apply(*Left, *Right, Binary->getOpcode(), LeftType);
    }
    if (const auto *Binary = dyn_cast<SymIntExpr>(Expression)) {
      QualType LeftType = Binary->getLHS()->getType();
      if (LeftType.isNull() || !LeftType->isIntegerType() ||
          Binary->getRHS().getBitWidth() != AST.getIntWidth(LeftType) ||
          (BinaryOperator::isComparisonOp(Binary->getOpcode()) &&
           Binary->getRHS().isUnsigned() !=
               LeftType->isUnsignedIntegerOrEnumerationType()))
        return std::nullopt;
      std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
      if (!Left || Left->get_sort().bv_size() != AST.getIntWidth(LeftType))
        return std::nullopt;
      z3::expr Right = bitVector(Binary->getRHS(), Left->get_sort().bv_size());
      return Apply(*Left, Right, Binary->getOpcode(), LeftType);
    }
    if (const auto *Binary = dyn_cast<IntSymExpr>(Expression)) {
      QualType RightType = Binary->getRHS()->getType();
      if (RightType.isNull() || !RightType->isIntegerType() ||
          Binary->getLHS().getBitWidth() != AST.getIntWidth(RightType) ||
          (BinaryOperator::isComparisonOp(Binary->getOpcode()) &&
           Binary->getLHS().isUnsigned() !=
               RightType->isUnsignedIntegerOrEnumerationType()))
        return std::nullopt;
      std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
      if (!Right || Right->get_sort().bv_size() != AST.getIntWidth(RightType))
        return std::nullopt;
      z3::expr Left = bitVector(Binary->getLHS(), Right->get_sort().bv_size());
      return Apply(Left, *Right, Binary->getOpcode(), RightType);
    }
    return std::nullopt;
  }

public:
  ArrayIndexZ3Proof(ArrayIndexZ3Engine &Engine, ProgramStateRef State,
                    ASTContext &AST, SymbolRef TrustedLeaf)
      : ZCtx(Engine.Context), Solver(Engine.Solver), AST(AST),
        TrustedLeaf(TrustedLeaf) {
    Solver.reset();
    for (const auto &Entry : getConstraintMap(State)) {
      std::optional<z3::expr> Expression = translate(Entry.first);
      if (!Expression)
        continue;
      const RangeSet &Ranges = Entry.second;
      if (!Expression->is_bv() || Ranges.isEmpty() ||
          Expression->get_sort().bv_size() != Ranges.getBitWidth())
        continue;
      std::optional<z3::expr> Union;
      for (const Range &R : Ranges) {
        z3::expr From = bitVector(R.From(), Ranges.getBitWidth());
        z3::expr To = bitVector(R.To(), Ranges.getBitWidth());
        z3::expr Member =
            R.getConcreteValue()
                ? *Expression == From
                : Ranges.isUnsigned()
                      ? z3::ule(From, *Expression) && z3::ule(*Expression, To)
                      : From <= *Expression && *Expression <= To;
        Union = Union ? std::optional<z3::expr>(*Union || Member)
                      : std::optional<z3::expr>(Member);
      }
      if (Union && Union->is_bool())
        Solver.add(*Union);
    }
    for (const auto &Entry : State->get<ArrayIndexZ3BranchFact>()) {
      std::optional<z3::expr> Comparison = translate(Entry.first);
      if (!Comparison || !Comparison->is_bv())
        continue;
      z3::expr Fact = *Comparison == ZCtx.bv_val(Entry.second ? 1 : 0,
                                                 Comparison->get_sort().bv_size());
      if (Fact.is_bool())
        Solver.add(Fact);
    }
  }

  // Proves that Sym can never be zero under every currently-known path
  // constraint. Only an UNSAT answer for "Sym can be zero" discharges the
  // obligation, matching every other Z3 consumer in this file: SAT,
  // timeout, and unknown all preserve the finding.
  bool provesNonzero(SymbolRef Sym) {
    std::optional<z3::expr> Translated = translate(Sym);
    if (!Translated || !Translated->is_bv())
      return false;
    Solver.add(*Translated ==
              ZCtx.bv_val(0, Translated->get_sort().bv_size()));
    return ntlibc::algebra::provesUnsatisfiable(Solver);
  }
};
#endif

class ArrayIndexChecker
    : public Checker<check::PreStmt<ArraySubscriptExpr>
#ifdef NTLIBC_ARITHMETIC_Z3
                     , eval::Assume
#endif
                     > {
  mutable std::unique_ptr<BugType> BT;

  // include/ownership.h's elements_withtok(token_name, extent_name) marks a
  // pointer parameter as having extent_name's value elements; it already
  // documents this exact fact for every argc/argv-shaped utility entry point
  // (elements_withtok(null_terminated, argc)) purely so OwnershipChecker's
  // linear-token tracking can name the array's length.  A plain pointer
  // parameter has no dynamic extent this checker's DynamicExtent query can
  // ever discover on its own -- the allocation that ultimately backs argv
  // happened in the OS loader or a distant caller, never in a statement this
  // translation unit can see -- so every index into it was unprovable by
  // construction, regardless of how tightly a loop guards it against argc.
  // Reading the same annotation OwnershipChecker already consumes costs
  // nothing new to the source and states nothing this checker did not
  // already effectively assume by leaving every such access unproven; it
  // only turns a permanent "cannot know" into a real bound.  This is the
  // same trust boundary the file already relies on for ntlibc_arith_range
  // (rangeContract() below) and for ordinary nonnull/alloc_size attributes:
  // a declared parameter contract is taken as an axiom, not independently
  // reverified.  A lie in the annotation is a lie this checker inherits
  // exactly the way a wrong nonnull annotation would deceive any consumer.
  static std::optional<StringRef>
  elementCountParamName(const ParmVarDecl *Param) {
    for (const AnnotateAttr *Attr : Param->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attr->getAnnotation();
      if (!Text.consume_front("elements_withtok:"))
        continue;
      StringRef Token = Text.split(':').second;
      if (Token.empty())
        continue;
      return Token;
    }
    return std::nullopt;
  }

  // A second, independent bound for Subscript's index, read straight from a
  // declared element-count contract: compares Idx directly against whatever
  // integer parameter the contract names, in that parameter's own native
  // symbol, rather than routing through DynamicExtent's byte extent and
  // back (a multiply-then-divide the plain RangeConstraintManager this file
  // uses for ArrayIndex has no general algebra to cancel back to the loop
  // guard's own "index < count" symbol).  Comparing the literal count
  // parameter directly is exactly what a same-statement guard against argc
  // already established for the constraint manager -- this only has to ask
  // the same question about the same two symbols the source already
  // relates.  Purely additive: a null result changes nothing, since the
  // caller only consults this after its own DynamicExtent-based proof
  // already failed.
  static std::optional<NonLoc>
  contractElementCount(const ArraySubscriptExpr *Subscript,
                       CheckerContext &C) {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function)
      return std::nullopt;
    ProgramStateRef State = C.getState();
    const LocationContext *LCtx = C.getLocationContext();
    const MemRegion *BaseRegion = C.getSVal(Subscript->getBase()).getAsRegion();
    if (!BaseRegion)
      return std::nullopt;
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      if (!Parameter->getType()->isPointerType())
        continue;
      std::optional<StringRef> ExtentName = elementCountParamName(Parameter);
      if (!ExtentName)
        continue;
      SVal PointerValue = State->getSVal(State->getLValue(Parameter, LCtx));
      if (PointerValue.getAsRegion() != BaseRegion)
        continue;
      const ParmVarDecl *CountParameter = nullptr;
      for (const ParmVarDecl *Candidate : Function->parameters())
        if (Candidate->getName() == *ExtentName) {
          CountParameter = Candidate;
          break;
        }
      if (!CountParameter || !CountParameter->getType()->isIntegerType())
        continue;
      SVal CountValue = State->getSVal(State->getLValue(CountParameter, LCtx));
      if (std::optional<NonLoc> Defined = CountValue.getAs<NonLoc>())
        return Defined;
    }
    return std::nullopt;
  }

#ifdef NTLIBC_ARITHMETIC_Z3
  // include/string.h's withtok(null_terminated) -- the identical per-
  // parameter trust boundary TotalityChecker.cpp's nullTerminatedParameter()
  // already reads off strlen/wcslen's own declaration for this exact literal
  // annotation text -- names a *direct* single-pointer contract: `T *p
  // withtok(null_terminated)` means p itself points at a valid, finite,
  // NUL-terminated buffer. Walks every redecl the way TotalityChecker's own
  // helper does, since the attribute commonly lives only on a header
  // prototype the analyzed definition does not repeat it on.
  static bool isWithtokNullTerminated(const ParmVarDecl *Param) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(
        Param->getDeclContext());
    if (!Function)
      return false;
    unsigned Index = Param->getFunctionScopeIndex();
    for (const FunctionDecl *Redeclaration : Function->redecls()) {
      if (Index >= Redeclaration->getNumParams())
        continue;
      for (const AnnotateAttr *Attribute :
           Redeclaration->getParamDecl(Index)->specific_attrs<AnnotateAttr>())
        if (Attribute->getAnnotation() == "withtok:null_terminated")
          return true;
    }
    return false;
  }

  // The argv-shaped case: elementCountParamName() above already reads
  // elements_withtok(token_name, extent_name) purely for the OUTER array's
  // own element count (how many char* slots argv has). Every real
  // declaration of that contract in this tree spells its token name
  // "null_terminated" (see include/ownership.h's own doc comment on
  // elements_withtok and every argc/argv-shaped entry in
  // src/internal/util.h) -- reusing that identical literal, the same way
  // isWithtokNullTerminated() above reuses withtok(null_terminated)'s, is
  // what licenses reading it a SECOND time here for a completely different
  // fact: POSIX guarantees every argv[i] with i in [0, argc) is *itself* a
  // valid, finite, null-terminated C string (not merely that argv has argc
  // pointer-sized slots). That guarantee stops exactly at argv[argc] (only
  // guaranteed NULL by POSIX) -- so the caller below must still separately
  // reprove the specific index used falls inside [0, argc) before trusting
  // this fact; this only returns the extent parameter's name for that
  // reproof, mirroring contractElementCount()'s own field lookup.
  static std::optional<StringRef>
  nullTerminatedElementsExtent(const ParmVarDecl *Param) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(
        Param->getDeclContext());
    if (!Function)
      return std::nullopt;
    unsigned Index = Param->getFunctionScopeIndex();
    for (const FunctionDecl *Redeclaration : Function->redecls()) {
      if (Index >= Redeclaration->getNumParams())
        continue;
      for (const AnnotateAttr *Attribute :
           Redeclaration->getParamDecl(Index)->specific_attrs<AnnotateAttr>()) {
        StringRef Text = Attribute->getAnnotation();
        if (!Text.consume_front("elements_withtok:"))
          continue;
        StringRef Token, Extent;
        std::tie(Token, Extent) = Text.split(':');
        if (Token != "null_terminated" || Extent.empty())
          continue;
        return Extent;
      }
    }
    return std::nullopt;
  }

  // Traces PointeeRegion -- what a subscript's base pointer actually points
  // at -- back to whichever real, trusted null-terminated contract (if any)
  // ultimately backs it, following the SAME region/symbol lineage the
  // analyzer's own engine already built while evaluating the code (no new
  // syntactic pattern matching over the source text). A plain pointer copy
  // (`char *b = a;`) conjures no new symbol, so this works through any
  // number of local-variable hops for free; each case below only has to
  // recognize the one, real conjuring step where an unwritten region was
  // first read.
  //
  // RegionStore's read-without-write path conjures a SymbolRegionValue keyed
  // to the EXACT region that produced it: reading a parameter's own storage
  // yields SymbolRegionValue(VarRegion(param)) whose pointee is
  // SymbolicRegion(that symbol) -- the direct case below. Reading
  // argv[i] (itself unwritten) similarly yields
  // SymbolRegionValue(ElementRegion(SymbolicRegion(argv's own symbol), i))
  // -- the argv-shaped case. Either shape's absence (a write occurred, or
  // the pointer came from somewhere this checker cannot see, e.g. a call
  // result) is simply not recognized, exactly as unprovable as it already
  // was; this can only ever add proving power, never remove it.
  static const MemRegion *nullTerminatedStringRegion(
      const MemRegion *PointeeRegion, CheckerContext &C) {
    const auto *Symbolic = dyn_cast_or_null<SymbolicRegion>(PointeeRegion);
    if (!Symbolic)
      return nullptr;
    const auto *Origin = dyn_cast<SymbolRegionValue>(Symbolic->getSymbol());
    if (!Origin)
      return nullptr;
    const MemRegion *Source = Origin->getRegion();

    // Direct case: `T *p withtok(null_terminated)` and p[0]/p[1] read in
    // the same function p was declared in.
    if (const auto *Var = dyn_cast<VarRegion>(Source)) {
      const auto *Param = dyn_cast<ParmVarDecl>(Var->getDecl());
      if (Param && isWithtokNullTerminated(Param))
        return PointeeRegion;
      return nullptr;
    }

    // argv-shaped case: `char *a = argv[i];` (or any chain of plain
    // pointer copies from it).
    const auto *Element = dyn_cast<ElementRegion>(Source);
    if (!Element)
      return nullptr;
    const auto *OuterSymbolic =
        dyn_cast_or_null<SymbolicRegion>(Element->getSuperRegion());
    if (!OuterSymbolic)
      return nullptr;
    const auto *OuterOrigin =
        dyn_cast<SymbolRegionValue>(OuterSymbolic->getSymbol());
    if (!OuterOrigin)
      return nullptr;
    const auto *OuterVar = dyn_cast<VarRegion>(OuterOrigin->getRegion());
    if (!OuterVar)
      return nullptr;
    const auto *ArrayParam = dyn_cast<ParmVarDecl>(OuterVar->getDecl());
    if (!ArrayParam)
      return nullptr;
    std::optional<StringRef> ExtentName =
        nullTerminatedElementsExtent(ArrayParam);
    if (!ExtentName)
      return nullptr;
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(ArrayParam->getDeclContext());
    if (!Function)
      return nullptr;
    const ParmVarDecl *CountParameter = nullptr;
    for (const ParmVarDecl *Candidate : Function->parameters())
      if (Candidate->getName() == *ExtentName) {
        CountParameter = Candidate;
        break;
      }
    if (!CountParameter || !CountParameter->getType()->isIntegerType())
      return nullptr;

    // Independently reprove the SAME bound the argv[i] subscript that
    // produced this pointer would itself need to satisfy: trusting this
    // pointer's content on a path where i was never actually shown to be
    // below argc would trust content of a slot POSIX makes no promise
    // about (argv[argc] is only guaranteed NULL, not a valid string).
    ProgramStateRef State = C.getState();
    const LocationContext *LCtx = C.getLocationContext();
    SVal CountValue = State->getSVal(State->getLValue(CountParameter, LCtx));
    std::optional<NonLoc> Count = CountValue.getAs<NonLoc>();
    if (!Count)
      return nullptr;
    ProgramStateRef IndexOutside = State->assumeInBound(
        Element->getIndex(), *Count, false, CountParameter->getType());
    if (IndexOutside)
      return nullptr;
    return PointeeRegion;
  }

  // The DynamicExtent- and declared-count-based proofs in checkPreStmt both
  // gave up; try the one remaining fact this checker can lean on: a
  // null-terminated buffer's own structural invariant. Deliberately
  // restricted to the two constant indices that invariant alone can ever
  // justify -- index 0 needs no guard at all (a null-terminated buffer's
  // extent is always at least one element), and index 1 needs a real,
  // path-sensitive Z3 proof that a dominating branch already established
  // byte 0 is nonzero. An unguarded a[1] on a length-0-or-1 string is a
  // REAL bug and must stay flagged: this never accepts index 1 without
  // that proof, and never accepts any index above 1 at all -- this file has
  // no sound story yet for a[2], a[3], ..., and guessing one here would
  // risk exactly the suppressed-true-positive outcome this checker exists
  // to prevent.
  static bool nullTerminatedIndexInBounds(const ArraySubscriptExpr *Subscript,
                                          SVal Base, CheckerContext &C) {
    Expr::EvalResult Result;
    if (!Subscript->getIdx()->EvaluateAsInt(Result, C.getASTContext()))
      return false;
    const llvm::APSInt &Index = Result.Val.getInt();
    if (Index.isNegative() || Index > 1)
      return false;
    const MemRegion *PointeeRegion = Base.getAsRegion();
    if (!PointeeRegion)
      return false;
    const MemRegion *StringRegion =
        nullTerminatedStringRegion(PointeeRegion, C);
    if (!StringRegion)
      return false;
    if (Index == 0)
      return true;

    // Index == 1: re-derive byte 0's own lvalue the same way the engine
    // would for a literal `StringRegion[0]` and read it back. RegionStore's
    // own reread guarantee (see symbolInterval()'s comment elsewhere in
    // this file) is what makes "the same byte" well defined at all: absent
    // an intervening write, this is the IDENTICAL SymbolRegionValue the
    // original a[0] read produced, carrying forward every constraint a
    // branch on it already established.
    ProgramStateRef State = C.getState();
    ASTContext &Ctx = C.getASTContext();
    SValBuilder &SVB = C.getSValBuilder();
    SVal Byte0Loc = State->getLValue(Subscript->getType(),
                                     SVB.makeZeroArrayIndex(),
                                     loc::MemRegionVal(StringRegion));
    std::optional<Loc> Byte0LValue = Byte0Loc.getAs<Loc>();
    if (!Byte0LValue)
      return false;
    SVal Byte0Val = State->getSVal(*Byte0LValue, Subscript->getType());
    // Once a dominating branch narrows byte 0's own range to a single
    // concrete value (e.g. `a[0] != '-'`'s false edge, which pins a[0] to
    // exactly '-'), Clang's own constraint manager already simplifies a
    // rereard of that region straight to the concrete integer -- nothing
    // symbolic is left to hand Z3 at all. Deciding nonzero-ness for a
    // plain constant is exact, not a proof obligation.
    if (const llvm::APSInt *Concrete = Byte0Val.getAsInteger())
      return !Concrete->isZero();
    // Otherwise byte 0 is still a live symbol (e.g. `a[0] == 0`'s false
    // edge only excludes the single value 0, leaving every other value
    // possible) -- ask the Z3 bridge whether every fact this path has
    // already established about that exact symbol jointly excludes zero.
    SymbolRef Byte0Sym = Byte0Val.getAsSymbol();
    if (!Byte0Sym)
      return false;
    ArrayIndexZ3Proof Proof(arrayIndexZ3Engine(), State, Ctx, Byte0Sym);
    return Proof.provesNonzero(Byte0Sym);
  }
#endif

  static std::string sourceText(const Expr *Expr, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    SourceLocation Begin = SM.getSpellingLoc(Expr->getBeginLoc());
    SourceLocation End = SM.getSpellingLoc(Expr->getEndLoc());
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
    if (Result.empty() && Expr->getBeginLoc().isMacroID())
      Result = Lexer::getImmediateMacroNameForDiagnostics(Expr->getBeginLoc(),
                                                          SM, C.getLangOpts())
                   .str();
    if (Result.empty())
      Result = Expr->getStmtClassName();
    return Result;
  }

  static std::string sourceOrigin(const Expr *Expr, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    return SM.getFilename(SM.getExpansionLoc(Expr->getBeginLoc())).str();
  }

  static std::string sourceSite(const Expr *Expr, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    SourceLocation Location = SM.getExpansionLoc(Expr->getBeginLoc());
    FileID File = SM.getFileID(Location);
    bool Invalid = false;
    StringRef Buffer = SM.getBufferData(File, &Invalid);
    if (Invalid)
      return Expr->getStmtClassName();
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

public:
  void checkPreStmt(const ArraySubscriptExpr *Subscript,
                    CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    SVal Base = C.getSVal(Subscript->getBase());
    DefinedOrUnknownSVal Count =
        getDynamicElementCountWithOffset(State, Base, Subscript->getType());
    SVal Index = C.getSVal(Subscript->getIdx());
    std::optional<NonLoc> DefinedIndex = Index.getAs<NonLoc>();
    ProgramStateRef Outside = State;
    if (DefinedIndex) {
      Outside = State->assumeInBound(*DefinedIndex, Count, false,
                                     Subscript->getIdx()->getType());
      if (!Outside)
        return;
      // The DynamicExtent-based proof above failed; try the declared
      // element-count contract as a second, independent bound before
      // concluding this access is unproven.
      if (std::optional<NonLoc> ContractCount =
              contractElementCount(Subscript, C)) {
        ProgramStateRef ContractOutside = State->assumeInBound(
            *DefinedIndex, *ContractCount, false,
            Subscript->getIdx()->getType());
        if (!ContractOutside)
          return;
      }
#ifdef NTLIBC_ARITHMETIC_Z3
      // Both DynamicExtent-based proofs above failed; try the
      // null-terminated-string structural invariant as a third,
      // independent route before concluding this access is unproven.
      if (nullTerminatedIndexInBounds(Subscript, Base, C))
        return;
#endif
    }

    ExplodedNode *Node = C.generateNonFatalErrorNode(Outside);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven array index",
                                     categories::LogicError);

    const Decl *Current = C.getLocationContext()->getDecl();
    std::string Context = Current ? Current->getDeclKindName() : "unknown";
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      Context = Named->getQualifiedNameAsString();
    std::string Message = "array index is not proven in bounds; origin '" +
                          sourceOrigin(Subscript, C) + "'; context '" +
                          Context + "'; subscript '" +
                          sourceText(Subscript, C) + "'; site '" +
                          sourceSite(Subscript, C) + "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Subscript->getSourceRange());
    C.emitReport(std::move(Report));
  }

#ifdef NTLIBC_ARITHMETIC_Z3
  // Records a relational fact so ArrayIndexZ3Proof can assert it later --
  // the identical technique SizeCastChecker::evalAssume above uses for
  // CastZ3BranchFact, and for the identical reason: getConstraintMap(State)
  // was already shown empty for realistic guard shapes in this Clang 18
  // build (see CastZ3BranchFact's own comment), so this checker's own Z3
  // proof power must not depend on that other map being populated either.
  // Purely additive to ProgramState: never rejects or narrows anything the
  // engine's own constraint manager already decided, only remembers a fact
  // it would otherwise drop.
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Condition,
                             bool Assumption) const {
    SymbolRef Symbol = Condition.getAsSymbol();
    const auto *Comparison = dyn_cast_or_null<BinarySymExpr>(Symbol);
    if (!Comparison || !BinaryOperator::isComparisonOp(Comparison->getOpcode()))
      return State;
    return State->set<ArrayIndexZ3BranchFact>(Symbol, Assumption);
  }
#endif
};

static std::string arithmeticOrigin(const Expr *Expression, CheckerContext &C);
static std::string arithmeticText(const Stmt *Statement, CheckerContext &C);
static std::string arithmeticSite(const Expr *Expression, CheckerContext &C);
static std::string arithmeticContext(CheckerContext &C);

#ifdef NTLIBC_ARITHMETIC_Z3
// A deliberately small bridge from the range constraint manager to Z3.  It
// translates only integer bit-vector expressions for which the Clang analyzer
// records exact semantics.  Missing expressions merely omit a constraint, so
// they can reduce proving power but cannot turn SAT into UNSAT.  The bridge
// models C values, not lint policy: unsigned wrap and narrowing are represented
// as their defined bit-vector results.  Callers separately assert the forbidden
// semantic event (currently signed overflow), so this algebra can later serve
// policy checks that intentionally forbid otherwise-defined wrapping.
class ArithmeticZ3Engine {
public:
  z3::context Context;
  z3::solver Solver;

  ArithmeticZ3Engine() : Solver(Context) {
    z3::params Parameters(Context);
    // Z3's deterministic resource counter is the primary query budget.  In
    // 4.8.12 the reported counter is context-cumulative, but rlimit applies to
    // each check independently even when this solver is reset and reused.  A
    // generous wall limit remains only as a pathological safety stop; it must
    // not make ordinary proof results depend on concurrent analyzer load.
    Parameters.set("rlimit", 1000000u);
    Parameters.set("timeout", 2000u);
    Solver.set(Parameters);
  }
};

class ArithmeticZ3Proof {
  z3::context &ZCtx;
  z3::solver &Solver;
  ASTContext &AST;
  ntlibc::algebra::ScalarSMT Algebra;

  static bool isUnsigned(QualType Type) {
    return Type->isUnsignedIntegerOrEnumerationType();
  }

  ntlibc::algebra::CType cType(QualType Type) const {
    // The analyzer's SymExpr operands have already undergone C's integer
    // promotions and usual arithmetic conversions.  Width orders all target
    // domains used here; the shared algebra retains an explicit rank so a
    // future AST adapter can distinguish equal-width ranks where needed.
    return {AST.getIntWidth(Type), AST.getIntWidth(Type), isUnsigned(Type)};
  }

  bool sameDomain(QualType Left, QualType Right) const {
    return !Left.isNull() && !Right.isNull() && Left->isIntegerType() &&
           Right->isIntegerType() &&
           AST.getIntWidth(Left) == AST.getIntWidth(Right) &&
           isUnsigned(Left) == isUnsigned(Right);
  }

  bool constantDomain(const llvm::APSInt &Value, QualType Type) const {
    return Value.getBitWidth() == AST.getIntWidth(Type) &&
           Value.isUnsigned() == isUnsigned(Type);
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

  // Widens two already-translated operands from their own exact domains to
  // their C usual-arithmetic-conversion common type via ScalarSMT::convert,
  // for the shapes where the analyzer builds a comparison directly from two
  // differently-typed operands with no intervening SymbolCast.  Left/Right's
  // domains must be exact for this to be sound; a concrete literal's own
  // width and sign are always exact, and so is any SymExpr's own getType()
  // -- only SymbolCast's inaccessible FromTy is not, which is why that node
  // is still rejected outright above.
  std::optional<std::pair<z3::expr, z3::expr>>
  widenToCommon(const z3::expr &Left, ntlibc::algebra::CType LeftType,
               const z3::expr &Right, ntlibc::algebra::CType RightType,
               QualType &CommonTypeOut) {
    std::optional<ntlibc::algebra::CType> Common =
        Algebra.usualArithmeticType(LeftType, RightType);
    if (!Common)
      return std::nullopt;
    CommonTypeOut = AST.getIntTypeForBitwidth(Common->Width, !Common->Unsigned);
    if (CommonTypeOut.isNull())
      return std::nullopt;
    std::optional<ntlibc::algebra::SemanticResult> LeftInput =
        Algebra.input(Left, LeftType);
    std::optional<ntlibc::algebra::SemanticResult> RightInput =
        Algebra.input(Right, RightType);
    std::optional<ntlibc::algebra::SemanticResult> LeftWide =
        LeftInput ? Algebra.convert(*LeftInput, *Common) : std::nullopt;
    std::optional<ntlibc::algebra::SemanticResult> RightWide =
        RightInput ? Algebra.convert(*RightInput, *Common) : std::nullopt;
    if (!LeftWide || !RightWide)
      return std::nullopt;
    return std::pair<z3::expr, z3::expr>(LeftWide->Value, RightWide->Value);
  }

  std::optional<z3::expr> translate(const SymExpr *Expression,
                                    unsigned Depth = 0) {
    if (!Expression || Depth > 24 || Expression->getType().isNull() ||
        !Expression->getType()->isIntegerType())
      return std::nullopt;
    unsigned Width = AST.getIntWidth(Expression->getType());
    if (const auto *Data = dyn_cast<SymbolData>(Expression)) {
      std::string Name = "clang_sym_" + std::to_string(Data->getSymbolID());
      return ZCtx.bv_const(Name.c_str(), Width);
    }
    // SymbolCast retains the effective source type internally, but Clang 18
    // does not expose it.  The operand's type is not an equivalent substitute:
    // chained narrowing/sign extension may be folded into one SymbolCast.
    // Reject casts rather than risk choosing the wrong extension semantics.
    if (isa<SymbolCast>(Expression))
      return std::nullopt;
    if (const auto *Unary = dyn_cast<UnarySymExpr>(Expression)) {
      std::optional<z3::expr> Operand =
          translate(Unary->getOperand(), Depth + 1);
      if (!Operand || Operand->get_sort().bv_size() != Width)
        return std::nullopt;
      if (Unary->getOpcode() == UO_Minus)
        return -*Operand;
      if (Unary->getOpcode() == UO_Not)
        return ~*Operand;
      return std::nullopt;
    }

    auto Apply = [&](const z3::expr &Left, const z3::expr &Right,
                     BinaryOperator::Opcode Opcode,
                     QualType OperandType) -> std::optional<z3::expr> {
      if (Left.get_sort().bv_size() != Right.get_sort().bv_size())
        return std::nullopt;
      switch (Opcode) {
      case BO_Add:
      case BO_Sub:
      case BO_Mul: {
        ntlibc::algebra::CType Type = cType(OperandType);
        std::optional<ntlibc::algebra::SemanticResult> L =
            Algebra.input(Left, Type);
        std::optional<ntlibc::algebra::SemanticResult> R =
            Algebra.input(Right, Type);
        if (!L || !R)
          return std::nullopt;
        std::optional<ntlibc::algebra::SemanticResult> Result =
            Opcode == BO_Add    ? Algebra.addConverted(*L, *R)
            : Opcode == BO_Sub  ? Algebra.subtractConverted(*L, *R)
                                : Algebra.multiplyConverted(*L, *R);
        return Result ? std::optional<z3::expr>(Result->Value)
                      : std::nullopt;
      }
      case BO_And:
        return Left & Right;
      case BO_Or:
        return Left | Right;
      case BO_Xor:
        return Left ^ Right;
      case BO_EQ:
      case BO_NE:
      case BO_LT:
      case BO_LE:
      case BO_GT:
      case BO_GE: {
        bool Unsigned = isUnsigned(OperandType);
        z3::expr Predicate = [&]() -> z3::expr {
          switch (Opcode) {
          case BO_EQ:
            return Left == Right;
          case BO_NE:
            return Left != Right;
          case BO_LT:
            return Unsigned ? z3::ult(Left, Right) : Left < Right;
          case BO_LE:
            return Unsigned ? z3::ule(Left, Right) : Left <= Right;
          case BO_GT:
            return Unsigned ? z3::ugt(Left, Right) : Left > Right;
          default: // BO_GE: the only remaining opcode this case can reach.
            return Unsigned ? z3::uge(Left, Right) : Left >= Right;
          }
        }();
        // Clang symbolic comparisons have the C result type (normally int),
        // not Boolean type.  Preserve that representation for RangeSet {0}
        // and {1} constraints.
        return z3::ite(Predicate, ZCtx.bv_val(1, Width),
                       ZCtx.bv_val(0, Width));
      }
      default:
        return std::nullopt;
      }
    };

    if (const auto *Binary = dyn_cast<SymSymExpr>(Expression)) {
      QualType LeftType = Binary->getLHS()->getType();
      QualType RightType = Binary->getRHS()->getType();
      std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
      std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
      if (!Left || !Right)
        return std::nullopt;
      if (sameDomain(LeftType, RightType)) {
        if (!BinaryOperator::isComparisonOp(Binary->getOpcode()) &&
            !sameDomain(LeftType, Binary->getType()))
          return std::nullopt;
        return Apply(*Left, *Right, Binary->getOpcode(), LeftType);
      }
      // A relational comparison is the one shape the analyzer legitimately
      // builds from two differently-typed operand symbols without an
      // intervening SymbolCast (e.g. comparing a wider loop counter
      // against a narrower field): widen both to their common type.
      if (!BinaryOperator::isComparisonOp(Binary->getOpcode()) ||
          LeftType.isNull() || RightType.isNull() ||
          !LeftType->isIntegerType() || !RightType->isIntegerType() ||
          Left->get_sort().bv_size() != AST.getIntWidth(LeftType) ||
          Right->get_sort().bv_size() != AST.getIntWidth(RightType))
        return std::nullopt;
      QualType CommonType;
      std::optional<std::pair<z3::expr, z3::expr>> Widened = widenToCommon(
          *Left, cType(LeftType), *Right, cType(RightType), CommonType);
      if (!Widened)
        return std::nullopt;
      return Apply(Widened->first, Widened->second, Binary->getOpcode(),
                 CommonType);
    }
    if (const auto *Binary = dyn_cast<SymIntExpr>(Expression)) {
      QualType LeftType = Binary->getLHS()->getType();
      std::optional<z3::expr> Left = translate(Binary->getLHS(), Depth + 1);
      if (!Left)
        return std::nullopt;
      if (constantDomain(Binary->getRHS(), LeftType)) {
        if (!BinaryOperator::isComparisonOp(Binary->getOpcode()) &&
            !sameDomain(LeftType, Binary->getType()))
          return std::nullopt;
        z3::expr Right = bitVector(Binary->getRHS(),
                                   Left->get_sort().bv_size());
        return Apply(*Left, Right, Binary->getOpcode(), LeftType);
      }
      // The literal's own width and sign are an exact, unambiguous fact
      // about a concrete value, so widening it to the symbol's common type
      // carries none of SymbolCast's private-FromTy risk.
      if (!BinaryOperator::isComparisonOp(Binary->getOpcode()) ||
          !LeftType->isIntegerType() ||
          Left->get_sort().bv_size() != AST.getIntWidth(LeftType))
        return std::nullopt;
      const llvm::APSInt &RightValue = Binary->getRHS();
      ntlibc::algebra::CType RightType{RightValue.getBitWidth(),
                                       RightValue.getBitWidth(),
                                       RightValue.isUnsigned()};
      z3::expr RightRaw = bitVector(RightValue, RightValue.getBitWidth());
      QualType CommonType;
      std::optional<std::pair<z3::expr, z3::expr>> Widened = widenToCommon(
          *Left, cType(LeftType), RightRaw, RightType, CommonType);
      if (!Widened)
        return std::nullopt;
      return Apply(Widened->first, Widened->second, Binary->getOpcode(),
                 CommonType);
    }
    if (const auto *Binary = dyn_cast<IntSymExpr>(Expression)) {
      QualType RightType = Binary->getRHS()->getType();
      std::optional<z3::expr> Right = translate(Binary->getRHS(), Depth + 1);
      if (!Right)
        return std::nullopt;
      if (constantDomain(Binary->getLHS(), RightType)) {
        if (!BinaryOperator::isComparisonOp(Binary->getOpcode()) &&
            !sameDomain(RightType, Binary->getType()))
          return std::nullopt;
        z3::expr Left = bitVector(Binary->getLHS(),
                                  Right->get_sort().bv_size());
        return Apply(Left, *Right, Binary->getOpcode(), RightType);
      }
      if (!BinaryOperator::isComparisonOp(Binary->getOpcode()) ||
          !RightType->isIntegerType() ||
          Right->get_sort().bv_size() != AST.getIntWidth(RightType))
        return std::nullopt;
      const llvm::APSInt &LeftValue = Binary->getLHS();
      ntlibc::algebra::CType LeftType{LeftValue.getBitWidth(),
                                      LeftValue.getBitWidth(),
                                      LeftValue.isUnsigned()};
      z3::expr LeftRaw = bitVector(LeftValue, LeftValue.getBitWidth());
      QualType CommonType;
      std::optional<std::pair<z3::expr, z3::expr>> Widened = widenToCommon(
          LeftRaw, LeftType, *Right, cType(RightType), CommonType);
      if (!Widened)
        return std::nullopt;
      return Apply(Widened->first, Widened->second, Binary->getOpcode(),
                 CommonType);
    }
    return std::nullopt;
  }

  std::optional<z3::expr> translate(NonLoc Value, QualType Type) {
    if (std::optional<nonloc::ConcreteInt> Integer =
            Value.getAs<nonloc::ConcreteInt>())
      return bitVector(Integer->getValue(), AST.getIntWidth(Type));
    return translate(Value.getAsSymbol());
  }

  bool isExactQueryValue(NonLoc Value, const Expr *Source, QualType Type) {
    if (Value.getAs<nonloc::ConcreteInt>())
      return true;
    const Expr *Core = Source->IgnoreParenImpCasts();
    if (isa<ExplicitCastExpr>(Core) ||
        Core->getType().getCanonicalType() != Type.getCanonicalType())
      return false;
    SymbolRef Symbol = Value.getAsSymbol();
    if (!Symbol || Symbol->getType().isNull() ||
        !Symbol->getType()->isIntegerType())
      return false;
    return AST.getIntWidth(Symbol->getType()) == AST.getIntWidth(Type) &&
           isUnsigned(Symbol->getType()) == isUnsigned(Type);
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

public:
  ArithmeticZ3Proof(ArithmeticZ3Engine &Engine, ProgramStateRef State,
                    ASTContext &AST)
      : ZCtx(Engine.Context), Solver(Engine.Solver), AST(AST),
        Algebra(ZCtx, cType(AST.IntTy), cType(AST.UnsignedIntTy)) {
    Solver.reset();
    for (const auto &Entry : getConstraintMap(State))
      if (std::optional<z3::expr> Expression = translate(Entry.first))
        addRange(*Expression, Entry.second);
    for (const auto &Entry : State->get<ArithmeticZ3BranchFact>()) {
      std::optional<z3::expr> Comparison = translate(Entry.first);
      if (!Comparison)
        continue;
      if (Comparison->is_bool()) {
        Solver.add(Entry.second ? *Comparison : !*Comparison);
      } else if (Comparison->is_bv()) {
        z3::expr Fact =
            *Comparison == ZCtx.bv_val(Entry.second ? 1 : 0,
                                       Comparison->get_sort().bv_size());
        if (Fact.is_bool())
          Solver.add(Fact);
      }
    }
  }

  bool provesNoSignedAddSubOverflow(NonLoc LeftValue, const Expr *LeftSource,
                                    NonLoc RightValue,
                                    const Expr *RightSource, QualType Type,
                                    bool Subtract) {
    // Loads through integer casts/narrow locals may be represented by the
    // analyzer as their pre-conversion composite SymExpr.  Without the
    // private source type of that conversion, accept a symbolic query only
    // when the source expression itself has the exact operation domain and
    // contains no explicit outer conversion.  Earlier defined arithmetic in
    // a same-domain SVal DAG may remain composite; modular models of any
    // already-undefined path only enlarge the query and are conservative.
    if (!isExactQueryValue(LeftValue, LeftSource, Type) ||
        !isExactQueryValue(RightValue, RightSource, Type))
      return false;
    std::optional<z3::expr> Left = translate(LeftValue, Type);
    std::optional<z3::expr> Right = translate(RightValue, Type);
    unsigned Width = AST.getIntWidth(Type);
    if (!Left || !Right || Left->get_sort().bv_size() != Width ||
        Right->get_sort().bv_size() != Width)
      return false;
    ntlibc::algebra::CType Domain = cType(Type);
    std::optional<ntlibc::algebra::SemanticResult> L =
        Algebra.input(*Left, Domain);
    std::optional<ntlibc::algebra::SemanticResult> R =
        Algebra.input(*Right, Domain);
    if (!L || !R)
      return false;
    std::optional<ntlibc::algebra::SemanticResult> Result =
        Subtract ? Algebra.subtract(*L, *R) : Algebra.add(*L, *R);
    if (!Result)
      return false;
    // The scalar algebra describes exact semantics and events.  This checker's
    // existing permission policy still forbids only signed overflow; defined
    // unsigned wrap and narrowing are deliberately not new findings here.
    z3::expr Violation = Result->Events.SignedOverflow.simplify();
    if (!Violation.is_bool())
      return false;
    Solver.add(Violation);
    // Only an UNSAT answer discharges the source obligation.  Timeout,
    // unknown, and an explicit counterexample all preserve the finding.
    return ntlibc::algebra::provesUnsatisfiable(Solver);
  }

  bool provesNoSignedUnitOverflow(NonLoc Value, const Expr *Source,
                                  QualType Type, bool Increasing) {
    if (!isExactQueryValue(Value, Source, Type))
      return false;
    std::optional<z3::expr> Operand = translate(Value, Type);
    if (!Operand)
      return false;
    ntlibc::algebra::CType Domain = cType(Type);
    std::optional<ntlibc::algebra::SemanticResult> Input =
        Algebra.input(*Operand, Domain);
    if (!Input)
      return false;
    std::optional<ntlibc::algebra::SemanticResult> Result =
        Algebra.unitStep(*Input, Increasing);
    if (!Result)
      return false;
    std::optional<ntlibc::algebra::SemanticResult> Stored =
        Algebra.convert(*Result, Domain);
    if (!Stored)
      return false;
    // ++/-- computes in the promoted domain and stores back into the operand.
    // Preserve the lint's existing signed-representability policy by rejecting
    // loss in that assignment conversion; the algebra itself correctly keeps
    // such a target conversion defined and merely records the event.
    z3::expr Violation = Result->Type.sameDomain(Domain)
                             ? Result->Events.SignedOverflow
                             : Stored->Events.SignedOverflow ||
                                   Stored->Events.NarrowingLoss;
    Violation = Violation.simplify();
    if (!Violation.is_bool())
      return false;
    Solver.add(Violation);
    return ntlibc::algebra::provesUnsatisfiable(Solver);
  }

  bool provesNoSignedNegationOverflow(NonLoc Value, const Expr *Source,
                                      QualType Type) {
    if (!isExactQueryValue(Value, Source, Type))
      return false;
    std::optional<z3::expr> Operand = translate(Value, Type);
    if (!Operand)
      return false;
    std::optional<ntlibc::algebra::SemanticResult> Input =
        Algebra.input(*Operand, cType(Type));
    std::optional<ntlibc::algebra::SemanticResult> Result =
        Input ? Algebra.negate(*Input) : std::nullopt;
    if (!Result)
      return false;
    z3::expr Violation = Result->Events.SignedOverflow.simplify();
    if (!Violation.is_bool())
      return false;
    Solver.add(Violation);
    return ntlibc::algebra::provesUnsatisfiable(Solver);
  }

  bool provesNoSignedDivisionOverflow(NonLoc LeftValue, const Expr *LeftSource,
                                      NonLoc RightValue,
                                      const Expr *RightSource, QualType Type,
                                      bool Remainder) {
    if (!isExactQueryValue(LeftValue, LeftSource, Type) ||
        !isExactQueryValue(RightValue, RightSource, Type))
      return false;
    std::optional<z3::expr> Left = translate(LeftValue, Type);
    std::optional<z3::expr> Right = translate(RightValue, Type);
    if (!Left || !Right)
      return false;
    ntlibc::algebra::CType Domain = cType(Type);
    std::optional<ntlibc::algebra::SemanticResult> L =
        Algebra.input(*Left, Domain);
    std::optional<ntlibc::algebra::SemanticResult> R =
        Algebra.input(*Right, Domain);
    if (!L || !R)
      return false;
    std::optional<ntlibc::algebra::SemanticResult> Result =
        Remainder ? Algebra.remainderConverted(*L, *R)
                  : Algebra.divideConverted(*L, *R);
    if (!Result)
      return false;
    // DivisorChecker separately consumes DivisionByZero.  This checker asks
    // only whether the signed MIN/-1 result is representable.
    z3::expr Violation = Result->Events.SignedOverflow.simplify();
    if (!Violation.is_bool())
      return false;
    Solver.add(Violation);
    return ntlibc::algebra::provesUnsatisfiable(Solver);
  }
};

static ArithmeticZ3Engine &arithmeticZ3Engine() {
  // Static-analyzer callbacks are serial within one translation-unit process;
  // lint.sh provides process parallelism across translation units.  Reusing
  // both context and solver avoids repeated Z3 initialization.  reset() gives
  // each proof an independent assertion set while preserving both budgets.
  static thread_local ArithmeticZ3Engine Engine;
  return Engine;
}
#endif

class SignedArithmeticChecker
    : public Checker<check::PreStmt<BinaryOperator>,
                     check::PreStmt<UnaryOperator>,
                     check::PostStmt<BinaryOperator>,
                     check::PostStmt<DeclStmt>
#ifdef NTLIBC_ARITHMETIC_Z3
                     , eval::Assume
#endif
                     > {
  mutable std::unique_ptr<BugType> BT;

  static std::optional<NonLoc> integerValue(const Expr *Expression,
                                             ProgramStateRef State,
                                             CheckerContext &C) {
    SVal Value = State->getSVal(Expression, C.getLocationContext());
    if (Expression->isLValue())
      if (std::optional<Loc> Location = Value.getAs<Loc>())
        Value = State->getSVal(*Location, Expression->getType());
    return Value.getAs<NonLoc>();
  }

  static ProgramStateRef assumeComparison(ProgramStateRef State, NonLoc Left,
                                          NonLoc Right,
                                          BinaryOperator::Opcode Opcode,
                                          CheckerContext &C) {
    SVal Comparison = C.getSValBuilder().evalBinOpNN(
        State, Opcode, Left, Right, C.getASTContext().IntTy);
    std::optional<DefinedOrUnknownSVal> Defined =
        Comparison.getAs<DefinedOrUnknownSVal>();
    // An unmodelled comparison cannot establish safety.
    return Defined ? State->assume(*Defined, true) : State;
  }

  static std::optional<NonLoc>
  evaluate(ProgramStateRef State, NonLoc Left, NonLoc Right,
           BinaryOperator::Opcode Opcode, QualType Type, CheckerContext &C) {
    return C.getSValBuilder()
        .evalBinOpNN(State, Opcode, Left, Right, Type)
        .getAs<NonLoc>();
  }

  // Independent operand intervals lose relational facts such as `i < n`
  // together with n's own type bound.  Ask the path solver the standard
  // overflow predicates before reporting.  This is only an additional proof
  // of safety: any predicate the solver cannot model remains feasible.
  static bool addOrSubOverflowFeasible(const BinaryOperator *Operation,
                                       CheckerContext &C, bool Subtract) {
    ProgramStateRef Input = C.getState();
    QualType Type = Operation->getType();
    std::optional<NonLoc> Left =
        integerValue(Operation->getLHS(), Input, C);
    std::optional<NonLoc> Right =
        integerValue(Operation->getRHS(), Input, C);
    if (!Left || !Right)
      return true;
#ifdef NTLIBC_ARITHMETIC_Z3
    ArithmeticZ3Proof Z3(arithmeticZ3Engine(), Input, C.getASTContext());
    if (Z3.provesNoSignedAddSubOverflow(
            *Left, Operation->getLHS(), *Right, Operation->getRHS(), Type,
            Subtract))
      return false;
#endif
    SValBuilder &Builder = C.getSValBuilder();
    NonLoc Zero = Builder.makeIntVal(0, Type).castAs<NonLoc>();
    NonLoc Maximum = Builder.makeIntVal(
        SizeCastChecker::typeMax(C.getASTContext(), Type));
    NonLoc Minimum = Builder.makeIntVal(
        SizeCastChecker::typeMin(C.getASTContext(), Type));

    // Relational guards can prove subtraction safe without manufacturing a
    // MIN+right or MAX+right boundary expression.  If 0 <= right <= left,
    // the result is in [0, MAX]; symmetrically, left <= right <= 0 puts it in
    // [MIN, 0].  These are sufficient conditions only: an unmodelled or
    // feasible negation falls through to the general overflow predicates.
    if (Subtract) {
      if (!assumeComparison(Input, *Right, Zero, BO_LT, C) &&
          !assumeComparison(Input, *Left, *Right, BO_LT, C))
        return false;
      if (!assumeComparison(Input, *Right, Zero, BO_GT, C) &&
          !assumeComparison(Input, *Left, *Right, BO_GT, C))
        return false;
    }

    ProgramStateRef Positive =
        assumeComparison(Input, *Right, Zero, BO_GT, C);
    if (Positive) {
      BinaryOperator::Opcode LimitOp = Subtract ? BO_Add : BO_Sub;
      NonLoc BoundBase = Subtract ? Minimum : Maximum;
      std::optional<NonLoc> Limit =
          evaluate(Positive, BoundBase, *Right, LimitOp, Type, C);
      if (!Limit || assumeComparison(Positive, *Left, *Limit,
                                     Subtract ? BO_LT : BO_GT, C))
        return true;
    }

    ProgramStateRef Negative =
        assumeComparison(Input, *Right, Zero, BO_LT, C);
    if (Negative) {
      BinaryOperator::Opcode LimitOp = Subtract ? BO_Add : BO_Sub;
      NonLoc BoundBase = Subtract ? Maximum : Minimum;
      std::optional<NonLoc> Limit =
          evaluate(Negative, BoundBase, *Right, LimitOp, Type, C);
      if (!Limit || assumeComparison(Negative, *Left, *Limit,
                                     Subtract ? BO_GT : BO_LT, C))
        return true;
    }
    return false;
  }

#ifdef NTLIBC_ARITHMETIC_Z3
  static bool unitOverflowFeasible(const UnaryOperator *Operation,
                                   CheckerContext &C) {
    ProgramStateRef State = C.getState();
    std::optional<NonLoc> Value =
        integerValue(Operation->getSubExpr(), State, C);
    if (!Value)
      return true;
    UnaryOperatorKind Opcode = Operation->getOpcode();
    bool Increasing = Opcode == UO_PreInc || Opcode == UO_PostInc;
    ArithmeticZ3Proof Z3(arithmeticZ3Engine(), State, C.getASTContext());
    bool Proved = Z3.provesNoSignedUnitOverflow(
        *Value, Operation->getSubExpr(), Operation->getType(), Increasing);
    return !Proved;
  }

  static bool negationOverflowFeasible(const UnaryOperator *Operation,
                                       CheckerContext &C) {
    ProgramStateRef State = C.getState();
    std::optional<NonLoc> Value =
        integerValue(Operation->getSubExpr(), State, C);
    if (!Value)
      return true;
    ArithmeticZ3Proof Z3(arithmeticZ3Engine(), State, C.getASTContext());
    return !Z3.provesNoSignedNegationOverflow(*Value, Operation->getSubExpr(),
                                              Operation->getType());
  }

  static bool divisionOverflowFeasible(const BinaryOperator *Operation,
                                       CheckerContext &C) {
    ProgramStateRef State = C.getState();
    std::optional<NonLoc> Left = integerValue(Operation->getLHS(), State, C);
    std::optional<NonLoc> Right = integerValue(Operation->getRHS(), State, C);
    if (!Left || !Right)
      return true;
    BinaryOperatorKind Opcode = Operation->getOpcode();
    bool Remainder = Opcode == BO_Rem || Opcode == BO_RemAssign;
    ArithmeticZ3Proof Z3(arithmeticZ3Engine(), State, C.getASTContext());
    return !Z3.provesNoSignedDivisionOverflow(*Left, Operation->getLHS(),
                                              *Right, Operation->getRHS(),
                                              Operation->getType(), Remainder);
  }
#endif

  static bool multiplicationOverflowFeasible(const BinaryOperator *Operation,
                                              CheckerContext &C) {
    ProgramStateRef Input = C.getState();
    QualType Type = Operation->getType();
    std::optional<NonLoc> Left =
        integerValue(Operation->getLHS(), Input, C);
    std::optional<NonLoc> Right =
        integerValue(Operation->getRHS(), Input, C);
    if (!Left || !Right)
      return true;
    SValBuilder &Builder = C.getSValBuilder();
    NonLoc Zero = Builder.makeIntVal(0, Type).castAs<NonLoc>();
    NonLoc MinusOne = Builder.makeIntVal(llvm::APSInt(
        llvm::APInt::getAllOnes(C.getASTContext().getIntWidth(Type)), false));
    NonLoc Maximum = Builder.makeIntVal(
        SizeCastChecker::typeMax(C.getASTContext(), Type));
    NonLoc Minimum = Builder.makeIntVal(
        SizeCastChecker::typeMin(C.getASTContext(), Type));

    struct SignCase {
      BinaryOperator::Opcode LeftSign;
      BinaryOperator::Opcode RightSign;
      NonLoc RightBound;
      NonLoc Numerator;
      BinaryOperator::Opcode OverflowComparison;
    };
    const SignCase Cases[] = {
        {BO_GT, BO_GT, Zero, Maximum, BO_GT},
        {BO_GT, BO_LT, MinusOne, Minimum, BO_GT},
        {BO_LT, BO_GT, Zero, Minimum, BO_LT},
        {BO_LT, BO_LT, Zero, Maximum, BO_LT},
    };
    for (const SignCase &Case : Cases) {
      ProgramStateRef State =
          assumeComparison(Input, *Left, Zero, Case.LeftSign, C);
      if (!State)
        continue;
      State = assumeComparison(State, *Right, Case.RightBound, Case.RightSign,
                               C);
      if (!State)
        continue;
      std::optional<NonLoc> Limit =
          evaluate(State, Case.Numerator, *Right, BO_Div, Type, C);
      if (!Limit || assumeComparison(State, *Left, *Limit,
                                     Case.OverflowComparison, C))
        return true;
    }
    return false;
  }

  static bool outside(const SizeCastChecker::Interval &Range,
                      const SizeCastChecker::Interval &Type) {
    return llvm::APSInt::compareValues(Range.Min, Type.Min) < 0 ||
           llvm::APSInt::compareValues(Range.Max, Type.Max) > 0;
  }

  static void constrainLocal(const VarDecl *Variable, const Expr *Source,
                             CheckerContext &C) {
    if (!Variable || !Variable->hasLocalStorage() ||
        !SizeCastChecker::containsMaskOrUnsignedShift(Source))
      return;
    ProgramStateRef State = C.getState();
    SVal Location = State->getLValue(Variable, C.getLocationContext());
    const MemRegion *Region = Location.getAsRegion();
    auto Value = Region ? State->getSVal(Location.castAs<Loc>())
                              .getAs<DefinedOrUnknownSVal>()
                        : std::nullopt;
    if (!Region || !Value)
      return;
    auto Syntactic = SizeCastChecker::syntacticReducerInterval(
        Source, C.getASTContext());
    SizeCastChecker::Interval Range =
        Syntactic ? *Syntactic
                  : SizeCastChecker::expressionInterval(Source, C, State);
    SizeCastChecker::Interval Bounds = SizeCastChecker::typeInterval(
        C.getASTContext(), Variable->getType());
    if (!SizeCastChecker::contains(Bounds, Range)) {
      ProgramStateRef Marked = State->add<ArithmeticWideReducer>(Region);
      if (Marked != State)
        C.addTransition(Marked);
      return;
    }
    State = State->remove<ArithmeticWideReducer>(Region);
    unsigned Bits = C.getASTContext().getIntWidth(Variable->getType());
    bool Unsigned =
        Variable->getType()->isUnsignedIntegerOrEnumerationType();
    llvm::APSInt Minimum =
        SizeCastChecker::asSourceType(Range.Min, Bits, Unsigned);
    llvm::APSInt Maximum =
        SizeCastChecker::asSourceType(Range.Max, Bits, Unsigned);
    ProgramStateRef Restricted = State->assumeInclusiveRange(
        *Value, Minimum, Maximum, true);
    if (Restricted && Restricted != C.getState())
      C.addTransition(Restricted);
  }

  static SizeCastChecker::Interval operandInterval(const Expr *Expression,
                                                   CheckerContext &C) {
    ProgramStateRef State = C.getState();
    const Expr *Storage = Expression;
    while (const auto *Cast = dyn_cast<CastExpr>(Storage))
      Storage = Cast->getSubExpr()->IgnoreParens();
    if (Storage->isLValue()) {
      SVal Location = State->getSVal(Storage, C.getLocationContext());
      if (const MemRegion *Region = Location.getAsRegion())
        if (State->contains<ArithmeticWideReducer>(Region)) {
          return SizeCastChecker::typeInterval(C.getASTContext(),
                                               Expression->getType());
        }
    }
    return SizeCastChecker::expressionInterval(Expression, C);
  }

  void report(const Expr *Expression, CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode(C.getState());
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven signed arithmetic",
                                     categories::LogicError);
    std::string Message =
        "signed arithmetic result is not proven representable; origin '" +
        arithmeticOrigin(Expression, C) + "'; context '" +
        arithmeticContext(C) + "'; expression '" +
        arithmeticText(Expression, C) + "'; site '" +
        arithmeticSite(Expression, C) + "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Expression->getSourceRange());
    C.emitReport(std::move(Report));
  }

public:
#ifdef NTLIBC_ARITHMETIC_Z3
  ProgramStateRef evalAssume(ProgramStateRef State, SVal Condition,
                             bool Assumption) const {
    SymbolRef Symbol = Condition.getAsSymbol();
    const auto *Comparison = dyn_cast_or_null<SymSymExpr>(Symbol);
    if (!Comparison)
      return State;
    BinaryOperator::Opcode Opcode = Comparison->getOpcode();
    bool StrictFact =
        (Assumption && (Opcode == BO_LT || Opcode == BO_GT)) ||
        (!Assumption && (Opcode == BO_LE || Opcode == BO_GE));
    if (!StrictFact)
      return State;
    SymbolRef Left = Comparison->getLHS();
    SymbolRef Right = Comparison->getRHS();
    QualType LeftType = Left->getType();
    QualType RightType = Right->getType();
    // Same-width same-signedness operands are the ordinary case; a
    // same-canonical-type requirement used to gate this, but the analyzer
    // legitimately builds a strict comparison between two integer symbols
    // of different width/signedness too (e.g. comparing a wider loop
    // counter against a narrower field with no intervening SymbolCast).
    // ArithmeticZ3Proof::translate()'s SymSymExpr case widens each side
    // through its own exact type before comparing, so recording remains
    // sound for that case as well; only a non-integer operand is rejected.
    if (LeftType.isNull() || RightType.isNull() ||
        !LeftType->isIntegerType() || !RightType->isIntegerType())
      return State;
    return State->set<ArithmeticZ3BranchFact>(Symbol, Assumption);
  }
#endif
  void checkPostStmt(const DeclStmt *Statement, CheckerContext &C) const {
    for (const Decl *Declaration : Statement->decls()) {
      const auto *Variable = dyn_cast<VarDecl>(Declaration);
      if (Variable && Variable->hasInit())
        constrainLocal(Variable, Variable->getInit(), C);
    }
  }

  void checkPostStmt(const BinaryOperator *Operation,
                     CheckerContext &C) const {
    if (Operation->getOpcode() != BO_Assign)
      return;
    const auto *Reference = dyn_cast<DeclRefExpr>(
        Operation->getLHS()->IgnoreParenImpCasts());
    constrainLocal(Reference ? dyn_cast<VarDecl>(Reference->getDecl())
                             : nullptr,
                   Operation->getRHS(), C);
  }

  void checkPreStmt(const BinaryOperator *Operation, CheckerContext &C) const {
    // Pointer subtraction has a signed ptrdiff_t result, but its validity is
    // not an ordinary signed-integer overflow question: C requires both
    // common array provenance and a representable element distance.  Those
    // are pointer-provenance/object-bound obligations.  Applying the generic
    // integer interval rule here loses the pointer regions and independently
    // reports on an operation whose validity it cannot decide.
    if (Operation->getOpcode() == BO_Sub &&
        Operation->getLHS()->getType()->isPointerType() &&
        Operation->getRHS()->getType()->isPointerType())
      return;
    QualType Type = Operation->getType();
    if (!Type->isSignedIntegerType())
      return;
    auto Left = operandInterval(Operation->getLHS(), C);
    auto Right = operandInterval(Operation->getRHS(), C);
    auto Bounds = SizeCastChecker::typeInterval(C.getASTContext(), Type);
    std::optional<SizeCastChecker::Interval> Result;
    switch (Operation->getOpcode()) {
    case BO_Add:
    case BO_AddAssign:
      Result =
          SizeCastChecker::Interval{Left.Min + Right.Min, Left.Max + Right.Max};
      if (outside(*Result, Bounds) &&
          !addOrSubOverflowFeasible(Operation, C, false))
        return;
      break;
    case BO_Sub:
    case BO_SubAssign:
      Result =
          SizeCastChecker::Interval{Left.Min - Right.Max, Left.Max - Right.Min};
      if (outside(*Result, Bounds) &&
          !addOrSubOverflowFeasible(Operation, C, true))
        return;
      break;
    case BO_Mul:
    case BO_MulAssign: {
      llvm::APSInt A = Left.Min * Right.Min;
      llvm::APSInt B = Left.Min * Right.Max;
      llvm::APSInt D = Left.Max * Right.Min;
      llvm::APSInt E = Left.Max * Right.Max;
      Result =
          SizeCastChecker::Interval{SizeCastChecker::minValue({A, B, D, E}),
                                    SizeCastChecker::maxValue({A, B, D, E})};
      if (outside(*Result, Bounds) &&
          !multiplicationOverflowFeasible(Operation, C))
        return;
      break;
    }
    case BO_Shl:
    case BO_ShlAssign: {
      unsigned Width = C.getASTContext().getIntWidth(Type);
      if (Left.Min.isNegative() || Right.Min.isNegative() ||
          Right.Max.getLimitedValue() >= Width) {
        report(Operation, C);
        return;
      }
      unsigned LowShift = static_cast<unsigned>(Right.Min.getLimitedValue());
      unsigned HighShift = static_cast<unsigned>(Right.Max.getLimitedValue());
      Result = SizeCastChecker::Interval{
          llvm::APSInt(Left.Min.shl(LowShift), false),
          llvm::APSInt(Left.Max.shl(HighShift), false)};
      break;
    }
    case BO_Div:
    case BO_Rem:
    case BO_DivAssign:
    case BO_RemAssign: {
      llvm::APSInt MinusOne(llvm::APInt(SizeCastChecker::MathBits, 1), false);
      MinusOne = -MinusOne;
      if (Left.Min <= Bounds.Min && Left.Max >= Bounds.Min &&
          Right.Min <= MinusOne && Right.Max >= MinusOne
#ifdef NTLIBC_ARITHMETIC_Z3
          && divisionOverflowFeasible(Operation, C)
#endif
      )
        report(Operation, C);
      return;
    }
    default:
      return;
    }
    if (Result && outside(*Result, Bounds))
      report(Operation, C);
  }

  void checkPreStmt(const UnaryOperator *Operation, CheckerContext &C) const {
    UnaryOperatorKind Opcode = Operation->getOpcode();
    if (Opcode != UO_Minus && Opcode != UO_PreInc && Opcode != UO_PostInc &&
        Opcode != UO_PreDec && Opcode != UO_PostDec)
      return;
    QualType Type = Operation->getType();
    if (!Type->isSignedIntegerType())
      return;
    auto Operand =
        SizeCastChecker::expressionInterval(Operation->getSubExpr(), C);
    auto Bounds = SizeCastChecker::typeInterval(C.getASTContext(), Type);
    bool Unsafe = Opcode == UO_Minus ? Operand.Min <= Bounds.Min
                  : (Opcode == UO_PreInc || Opcode == UO_PostInc)
                      ? Operand.Max >= Bounds.Max
                      : Operand.Min <= Bounds.Min;
    if (Unsafe
#ifdef NTLIBC_ARITHMETIC_Z3
        && (Opcode == UO_Minus ? negationOverflowFeasible(Operation, C)
                               : unitOverflowFeasible(Operation, C))
#endif
    )
      report(Operation, C);
  }
};

static std::string arithmeticOrigin(const Expr *Expression, CheckerContext &C) {
  const SourceManager &SM = C.getSourceManager();
  return SM.getFilename(SM.getExpansionLoc(Expression->getBeginLoc())).str();
}

static std::string arithmeticText(const Stmt *Statement, CheckerContext &C) {
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

static std::string arithmeticSite(const Expr *Expression, CheckerContext &C) {
  const SourceManager &SM = C.getSourceManager();
  SourceLocation Location = SM.getExpansionLoc(Expression->getBeginLoc());
  FileID File = SM.getFileID(Location);
  bool Invalid = false;
  StringRef Buffer = SM.getBufferData(File, &Invalid);
  if (Invalid)
    return Expression->getStmtClassName();
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

static std::string arithmeticContext(CheckerContext &C) {
  const Decl *Current = C.getLocationContext()->getDecl();
  if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
    return Named->getQualifiedNameAsString();
  return Current ? Current->getDeclKindName() : "unknown";
}

class ArithmeticContractChecker
    : public Checker<eval::Call, check::BeginFunction, check::PreCall,
                     check::PostCall, check::Bind, check::EndFunction> {
  mutable std::unique_ptr<BugType> BT;

  struct RangeContract {
    int64_t Minimum;
    int64_t Maximum;
  };

  struct FieldContract {
    unsigned Argument;
    StringRef Field;
  };

  struct OutputContract {
    unsigned Argument;
    QualType Type;
    RangeContract Range;
  };

  static std::optional<RangeContract> rangeContract(const ParmVarDecl *Param) {
    for (const AnnotateAttr *Attr : Param->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attr->getAnnotation();
      if (!Text.consume_front("ntlibc_arith_range:"))
        continue;
      auto Parts = Text.split(':');
      int64_t Minimum, Maximum;
      if (Parts.first.getAsInteger(10, Minimum) ||
          Parts.second.getAsInteger(10, Maximum) || Minimum > Maximum)
        return std::nullopt;
      return RangeContract{Minimum, Maximum};
    }
    return std::nullopt;
  }

  static bool hasAnnotation(const FunctionDecl *Function, StringRef Name) {
    for (const FunctionDecl *Redeclaration : Function->redecls())
      for (const AnnotateAttr *Attr :
           Redeclaration->specific_attrs<AnnotateAttr>())
        if (Attr->getAnnotation() == Name)
          return true;
    return false;
  }

  class AddressUseVisitor : public RecursiveASTVisitor<AddressUseVisitor> {
    const FunctionDecl *Target;
    ASTContext &Ctx;

    bool isDirectCallee(const DeclRefExpr *Reference) const {
      DynTypedNode Node = DynTypedNode::create(*Reference);
      for (;;) {
        auto Parents = Ctx.getParents(Node);
        if (Parents.size() != 1)
          return false;
        if (const auto *Call = Parents[0].get<CallExpr>()) {
          const FunctionDecl *Direct = Call->getDirectCallee();
          return Direct &&
                 Direct->getCanonicalDecl() == Target->getCanonicalDecl();
        }
        const Expr *Parent = Parents[0].get<Expr>();
        if (!Parent || (!isa<ImplicitCastExpr>(Parent) &&
                        !isa<ParenExpr>(Parent)))
          return false;
        Node = DynTypedNode::create(*Parent);
      }
    }

  public:
    bool AddressTaken = false;

    AddressUseVisitor(const FunctionDecl *Target, ASTContext &Ctx)
        : Target(Target), Ctx(Ctx) {}

    bool VisitDeclRefExpr(const DeclRefExpr *Reference) {
      const auto *Function = dyn_cast<FunctionDecl>(Reference->getDecl());
      if (Function &&
          Function->getCanonicalDecl() == Target->getCanonicalDecl() &&
          !isDirectCallee(Reference))
        AddressTaken = true;
      return !AddressTaken;
    }
  };

  static bool directOnlyRangeCallee(const FunctionDecl *Function,
                                    ASTContext &Ctx) {
    if (Function->getStorageClass() != SC_Static)
      return false;
    AddressUseVisitor Visitor(Function, Ctx);
    Visitor.TraverseDecl(Ctx.getTranslationUnitDecl());
    return !Visitor.AddressTaken;
  }

  static bool matchesFreedParameter(const Expr *Argument,
                                    const ParmVarDecl *Param) {
    const auto *Reference =
        dyn_cast<DeclRefExpr>(Argument->IgnoreParenImpCasts());
    return Reference && Reference->getDecl() == Param;
  }

  static bool isTrustedDeallocCall(const Stmt *Statement,
                                   const ParmVarDecl *Param) {
    const auto *Call = dyn_cast<CallExpr>(Statement);
    if (!Call || Call->getNumArgs() != 1)
      return false;
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee)
      return false;
    StringRef Name = Callee->getName();
    // free() is the public allocator's release primitive; __plat_dealloc()
    // is the same primitive one layer down -- src/malloc/malloc.c's free()
    // itself bottoms out in __plat_dealloc(), and src/malloc/crt_alloc.c's
    // __free() calls it directly to avoid linking free()'s translation
    // unit into crt1.o. Both are already-vetted release calls, not new
    // surface this checker takes on faith.
    if (Name != "free" && Name != "__plat_dealloc")
      return false;
    return matchesFreedParameter(Call->getArg(0), Param);
  }

  // `if (!param) return;` reads and branches on the parameter but writes
  // nothing, so a wrapper may open with one before its trusted release call
  // and still be a scalar no-op.
  static bool isNullGuardReturn(const Stmt *Statement,
                                const ParmVarDecl *Param) {
    const auto *If = dyn_cast<IfStmt>(Statement);
    if (!If || If->getElse())
      return false;
    const auto *Return = dyn_cast<ReturnStmt>(If->getThen());
    if (!Return || Return->getRetValue())
      return false;
    const auto *Not =
        dyn_cast<UnaryOperator>(If->getCond()->IgnoreParenImpCasts());
    if (!Not || Not->getOpcode() != UO_LNot)
      return false;
    return matchesFreedParameter(Not->getSubExpr(), Param);
  }

  static bool verifiedScalarNoop(const FunctionDecl *Function) {
    const FunctionDecl *Definition = Function->getDefinition();
    if (!Definition)
      return true; // The annotated declaration's defining TU is linted too.
    const auto *Body = dyn_cast_or_null<CompoundStmt>(Definition->getBody());
    if (!Body || Definition->getNumParams() != 1)
      return false;
    const ParmVarDecl *Param = Definition->getParamDecl(0);
    Stmt *const *Statements = Body->body_begin();
    unsigned CallIndex;
    if (Body->size() == 1) {
      CallIndex = 0;
    } else if (Body->size() == 2 && isNullGuardReturn(Statements[0], Param)) {
      CallIndex = 1;
    } else {
      return false;
    }
    return isTrustedDeallocCall(Statements[CallIndex], Param);
  }

  static std::optional<OutputContract>
  outputContract(const FunctionDecl *Function, CheckerContext &C) {
    if (!Function)
      return std::nullopt;
    std::optional<unsigned> Argument;
    for (const FunctionDecl *Redeclaration : Function->redecls())
      for (const AnnotateAttr *Attr :
           Redeclaration->specific_attrs<AnnotateAttr>()) {
        StringRef Text = Attr->getAnnotation();
        if (!Text.consume_front("ntlibc_arith_output_excludes_min:"))
          continue;
        unsigned Parsed;
        if (Text.getAsInteger(10, Parsed))
          return std::nullopt;
        if (Argument && *Argument != Parsed)
          return std::nullopt;
        Argument = Parsed;
      }
    if (!Argument || *Argument >= Function->getNumParams())
      return std::nullopt;
    QualType OutputType = Function->getParamDecl(*Argument)->getType();
    if (!OutputType->isPointerType())
      return std::nullopt;
    QualType Pointee = OutputType->getPointeeType();
    if (!Pointee->isSignedIntegerType())
      return std::nullopt;
    llvm::APSInt IntMinimum =
        SizeCastChecker::typeMin(C.getASTContext(), Pointee);
    llvm::APSInt IntMaximum =
        SizeCastChecker::typeMax(C.getASTContext(), Pointee);
    if (IntMinimum.getBitWidth() > 64 || IntMaximum.getBitWidth() > 64)
      return std::nullopt;
    int64_t Minimum = IntMinimum.getSExtValue() + 1;
    int64_t Maximum = IntMaximum.getSExtValue();
    RangeContract Range{Minimum, Maximum};
    return nativeRange(Pointee, Range, C)
               ? std::optional<OutputContract>(
                     OutputContract{*Argument, Pointee, Range})
               : std::nullopt;
  }

  static std::optional<FieldContract>
  fieldContract(const FunctionDecl *Function) {
    for (const FunctionDecl *Redeclaration : Function->redecls()) {
      for (const AnnotateAttr *Attr :
           Redeclaration->specific_attrs<AnnotateAttr>()) {
        StringRef Text = Attr->getAnnotation();
        if (!Text.consume_front(
                "ntlibc_arith_nonzero_field_on_success:"))
          continue;
        auto Parts = Text.split(':');
        unsigned Argument;
        if (Parts.first.getAsInteger(10, Argument) || Parts.second.empty())
          return std::nullopt;
        return FieldContract{Argument, Parts.second};
      }
    }
    return std::nullopt;
  }

  static const FunctionDecl *function(const CallEvent &Call) {
    return dyn_cast_or_null<FunctionDecl>(Call.getDecl());
  }

  static const FunctionDecl *definition(const FunctionDecl *Function) {
    if (!Function)
      return nullptr;
    if (const FunctionDecl *Definition = Function->getDefinition())
      return Definition;
    return Function;
  }

  static std::optional<std::pair<llvm::APSInt, llvm::APSInt>>
  nativeRange(QualType Type, const RangeContract &Contract,
              CheckerContext &C) {
    if (Type.isNull() || !Type->isIntegerType())
      return std::nullopt;
    llvm::APSInt MinimumMath(
        llvm::APInt(SizeCastChecker::MathBits,
                    static_cast<uint64_t>(Contract.Minimum), true),
        false);
    llvm::APSInt MaximumMath(
        llvm::APInt(SizeCastChecker::MathBits,
                    static_cast<uint64_t>(Contract.Maximum), true),
        false);
    SizeCastChecker::Interval Bounds =
        SizeCastChecker::typeInterval(C.getASTContext(), Type);
    if (MinimumMath < Bounds.Min || MaximumMath > Bounds.Max)
      return std::nullopt;
    unsigned Bits = C.getASTContext().getIntWidth(Type);
    bool Unsigned = Type->isUnsignedIntegerOrEnumerationType();
    return std::pair{
        SizeCastChecker::asSourceType(MinimumMath, Bits, Unsigned),
        SizeCastChecker::asSourceType(MaximumMath, Bits, Unsigned)};
  }

  static const FieldDecl *field(const ParmVarDecl *Parameter,
                                StringRef Name) {
    QualType Type = Parameter->getType();
    if (!Type->isPointerType())
      return nullptr;
    const RecordType *Record = Type->getPointeeType()->getAs<RecordType>();
    if (!Record)
      return nullptr;
    for (const FieldDecl *Candidate : Record->getDecl()->fields())
      if (Candidate->getName() == Name)
        return Candidate;
    return nullptr;
  }

  static std::optional<DefinedOrUnknownSVal>
  fieldValue(ProgramStateRef State, SVal Pointer, const FieldDecl *Field,
             CheckerContext &C) {
    if (!Pointer.getAsRegion() || !Field)
      return std::nullopt;
    SVal Location = State->getLValue(Field, Pointer);
    return State->getSVal(Location.castAs<Loc>())
        .getAs<DefinedOrUnknownSVal>();
  }

  void report(const Stmt *Statement, ProgramStateRef State, StringRef Detail,
              CheckerContext &C) const {
    ExplodedNode *Node = C.generateErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Violated arithmetic contract",
                                     categories::LogicError);
    std::string Message =
        "arithmetic contract is not proven: " + Detail.str() + "; origin '" +
        arithmeticOrigin(cast<Expr>(Statement), C) + "'; context '" +
        arithmeticContext(C) + "'; expression '" +
        arithmeticText(Statement, C) + "'; site '" +
        arithmeticSite(cast<Expr>(Statement), C) + "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

  void reportInvalidNoop(const FunctionDecl *Function,
                         CheckerContext &C) const {
    const Stmt *Body = Function->getBody();
    ExplodedNode *Node = C.generateNonFatalErrorNode(C.getState());
    if (!Node || !Body)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Violated arithmetic contract",
                                     categories::LogicError);
    const SourceManager &SM = C.getSourceManager();
    std::string Origin =
        SM.getFilename(SM.getExpansionLoc(Body->getBeginLoc())).str();
    std::string Message =
        "arithmetic contract is not proven: annotated scalar no-op is not "
        "the exact free(parameter) wrapper; origin '" +
        Origin + "'; context '" + Function->getQualifiedNameAsString() +
        "'; expression 'function body'; site 'annotated function "
        "definition'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Body->getSourceRange());
    C.emitReport(std::move(Report));
  }

  void reportInvalidOutput(const FunctionDecl *Function, StringRef Detail,
                           CheckerContext &C) const {
    const Stmt *Body = Function->getBody();
    ExplodedNode *Node = C.generateNonFatalErrorNode(C.getState());
    if (!Node || !Body)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Violated arithmetic contract",
                                     categories::LogicError);
    const SourceManager &SM = C.getSourceManager();
    std::string Origin =
        SM.getFilename(SM.getExpansionLoc(Body->getBeginLoc())).str();
    std::string Message =
        "arithmetic contract is not proven: " + Detail.str() + "; origin '" +
        Origin + "'; context '" + Function->getQualifiedNameAsString() +
        "'; expression 'function body'; site 'annotated function "
        "definition'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Body->getSourceRange());
    C.emitReport(std::move(Report));
  }

public:
  bool evalCall(const CallEvent &Call, CheckerContext &C) const {
    const FunctionDecl *Function = function(Call);
    if (!Function || Function->getName() != "__free" ||
        Call.getNumArgs() != 1 || !Function->getReturnType()->isVoidType() ||
        !hasAnnotation(Function, "ntlibc_arith_scalar_noop") ||
        !verifiedScalarNoop(Function))
      return false;
    // ntlibc's internal __free is a one-line allocator wrapper.  It changes
    // only allocation lifetime/allocator-private bookkeeping; it cannot
    // mutate the caller's scalar objects or globals.  The arithmetic stage
    // does not model heap lifetime, so treating this wrapper as an arithmetic
    // no-op preserves relational guards across cleanup loops without making
    // any claim about memory that remains legal to access after the free.
    C.addTransition(C.getState());
    return true;
  }

  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function = definition(
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl()));
    if (!Function)
      return;
    if (Function->getName() == "__free" &&
        hasAnnotation(Function, "ntlibc_arith_scalar_noop") &&
        !verifiedScalarNoop(Function)) {
      reportInvalidNoop(Function, C);
      return;
    }
    ProgramStateRef State = C.getState();
    bool Changed = false;
    if (auto Contract = outputContract(Function, C)) {
      SVal Pointer = State->getSVal(State->getLValue(
          Function->getParamDecl(Contract->Argument), C.getLocationContext()));
      if (const MemRegion *Region = Pointer.getAsRegion()) {
        const StackFrameContext *Frame =
            C.getLocationContext()->getStackFrame();
        State = State->set<ArithmeticContractOutput>(Frame, Region);
        State = State->remove<ArithmeticContractOutputValid>(Frame);
        Changed = true;
      }
    }
    for (const ParmVarDecl *Parameter : Function->parameters()) {
      auto Contract = rangeContract(Parameter);
      if (!Contract || !directOnlyRangeCallee(Function, C.getASTContext()))
        continue;
      auto Bounds = nativeRange(Parameter->getType(), *Contract, C);
      if (!Bounds)
        continue;
      SVal Value = State->getSVal(
          State->getLValue(Parameter, C.getLocationContext()));
      auto Defined = Value.getAs<DefinedOrUnknownSVal>();
      if (!Defined)
        continue;
      ProgramStateRef Restricted = State->assumeInclusiveRange(
          *Defined, Bounds->first, Bounds->second, true);
      if (Restricted && Restricted != State) {
        State = Restricted;
        Changed = true;
      }
    }
    if (auto Contract = fieldContract(Function)) {
      if (Contract->Argument < Function->getNumParams()) {
        const ParmVarDecl *Parameter =
            Function->getParamDecl(Contract->Argument);
        const FieldDecl *Field = field(Parameter, Contract->Field);
        SVal Pointer = State->getSVal(
            State->getLValue(Parameter, C.getLocationContext()));
        if (Pointer.getAsRegion() && Field) {
          SVal Location = State->getLValue(Field, Pointer);
          if (const MemRegion *Region = Location.getAsRegion()) {
            State = State->set<ArithmeticContractField>(
                C.getLocationContext()->getStackFrame(), Region);
            Changed = true;
          }
        }
      }
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    bool Changed = false;
    const auto *Current = definition(
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl()));
    const StackFrameContext *Frame =
        C.getLocationContext()->getStackFrame();
    if (outputContract(Current, C) &&
        State->contains<ArithmeticContractOutputValid>(Frame)) {
      // A generic call may mutate the output directly, through a copied
      // alias, or through an escaped/global alias.  A later proven full store
      // may re-establish the contract; absent that, normal return must fail.
      State = State->remove<ArithmeticContractOutputValid>(Frame);
      Changed = true;
    }
    const FunctionDecl *Function = function(Call);
    if (!Function) {
      if (Changed)
        C.addTransition(State);
      return;
    }
    for (unsigned Index = 0;
         Index < Function->getNumParams() && Index < Call.getNumArgs();
         ++Index) {
      auto Contract = rangeContract(Function->getParamDecl(Index));
      if (!Contract)
        continue;
      auto Bounds =
          nativeRange(Function->getParamDecl(Index)->getType(), *Contract, C);
      auto Argument = Call.getArgSVal(Index).getAs<DefinedOrUnknownSVal>();
      if (!Bounds || !Argument)
        continue;
      ProgramStateRef Violation = State->assumeInclusiveRange(
          *Argument, Bounds->first, Bounds->second, false);
      if (Violation) {
        const Expr *Expression = Call.getArgExpr(Index);
        std::string Detail = "argument " + std::to_string(Index + 1) +
                             " is outside declared range [" +
                             std::to_string(Contract->Minimum) + ", " +
                             std::to_string(Contract->Maximum) + "]";
        report(Expression, Violation, Detail, C);
      }
      State = State->assumeInclusiveRange(*Argument, Bounds->first,
                                          Bounds->second, true);
      if (!State)
        return;
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const FunctionDecl *Function = function(Call);
    if (auto Contract = outputContract(Function, C)) {
      auto Location = Call.getArgSVal(Contract->Argument).getAs<Loc>();
      auto Bounds = nativeRange(Contract->Type, Contract->Range, C);
      if (Location && Bounds) {
        DefinedOrUnknownSVal Fresh =
            C.getSValBuilder().conjureSymbolVal(
                this, Call.getOriginExpr(), C.getLocationContext(),
                Contract->Type, C.blockCount());
        ProgramStateRef State = C.getState()->bindLoc(
            *Location, Fresh, C.getLocationContext());
        State = State->assumeInclusiveRange(
            Fresh, Bounds->first, Bounds->second, true);
        if (State)
          C.addTransition(State);
        return;
      }
    }
    const FunctionDecl *Definition = Function ? Function->getDefinition()
                                              : nullptr;
    auto Contract = Definition ? fieldContract(Definition) : std::nullopt;
    if (!Contract || Contract->Argument >= Call.getNumArgs() ||
        Contract->Argument >= Function->getNumParams())
      return;
    auto Return = Call.getReturnValue().getAs<DefinedOrUnknownSVal>();
    const FieldDecl *Field = field(
        Function->getParamDecl(Contract->Argument), Contract->Field);
    if (!Return || !Field)
      return;
    ProgramStateRef State = C.getState();
    ProgramStateRef Failure = State->assume(*Return, false);
    ProgramStateRef Success = State->assume(*Return, true);
    if (Success) {
      SVal Pointer = Call.getArgSVal(Contract->Argument);
      SVal Location = Success->getLValue(Field, Pointer);
      if (auto FieldLocation = Location.getAs<Loc>()) {
        DefinedOrUnknownSVal Fresh =
            C.getSValBuilder().conjureSymbolVal(
                this, Call.getOriginExpr(), C.getLocationContext(),
                Field->getType(), C.blockCount());
        Success =
            Success->bindLoc(*FieldLocation, Fresh, C.getLocationContext());
        Success = Success->assume(Fresh, true);
      }
    }
    if (Failure)
      C.addTransition(Failure);
    if (Success)
      C.addTransition(Success);
  }

  void checkBind(SVal Location, SVal Value, const Stmt *,
                 CheckerContext &C) const {
    const auto *Function = definition(
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl()));
    auto Contract = Function ? outputContract(Function, C) : std::nullopt;
    const StackFrameContext *Frame =
        C.getLocationContext()->getStackFrame();
    const MemRegion *const *Output =
        C.getState()->get<ArithmeticContractOutput>(Frame);
    const MemRegion *Written = Location.getAsRegion();
    if (!Contract || !Output || !Written)
      return;
    ProgramStateRef State = C.getState();
    bool Exact = Written == *Output;
    bool Overlaps = Exact || Written->isSubRegionOf(*Output) ||
                    (*Output)->isSubRegionOf(Written) ||
                    Written->getBaseRegion() == (*Output)->getBaseRegion();
    if (!Overlaps)
      return;
    if (!Exact) {
      State = State->remove<ArithmeticContractOutputValid>(Frame);
      if (State != C.getState())
        C.addTransition(State);
      return;
    }
    bool Valid = false;
    if (auto Defined = Value.getAs<NonLoc>()) {
      SizeCastChecker::Interval Range = SizeCastChecker::bisectInterval(
          *Defined, Contract->Type, State, C);
      if (SymbolRef Symbol = Value.getAsSymbol())
        Range = SizeCastChecker::intersectInterval(
            Range,
            SizeCastChecker::symbolInterval(Symbol, State, C, 0));
      if (auto Bounds = nativeRange(Contract->Type, Contract->Range, C)) {
        SizeCastChecker::Interval ContractRange{
            SizeCastChecker::asMath(Bounds->first),
            SizeCastChecker::asMath(Bounds->second)};
        Valid = SizeCastChecker::contains(ContractRange, Range);
      }
    }
    State = Valid ? State->add<ArithmeticContractOutputValid>(Frame)
                  : State->remove<ArithmeticContractOutputValid>(Frame);
    if (State != C.getState())
      C.addTransition(State);
  }

  void checkEndFunction(const ReturnStmt *Return, CheckerContext &C) const {
    const auto *Function = definition(
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl()));
    if (outputContract(Function, C)) {
      ProgramStateRef State = C.getState();
      const StackFrameContext *Frame =
          C.getLocationContext()->getStackFrame();
      if (!State->contains<ArithmeticContractOutputValid>(Frame)) {
        if (Return) {
          const Expr *Expression = Return->getRetValue();
          if (Expression)
            report(Expression, State,
                   "output parameter may equal its signed type minimum",
                   C);
          else
            reportInvalidOutput(
                Function, "output parameter is not established on return",
                C);
        } else {
          reportInvalidOutput(
              Function, "output parameter is not established on fallthrough",
              C);
        }
      }
      return;
    }
    auto Contract = Function ? fieldContract(Function) : std::nullopt;
    if (!Contract || !Return || !Return->getRetValue() ||
        Contract->Argument >= Function->getNumParams())
      return;
    ProgramStateRef State = C.getState();
    auto Returned = C.getSVal(Return->getRetValue())
                        .getAs<DefinedOrUnknownSVal>();
    if (!Returned)
      return;
    ProgramStateRef Success = State->assume(*Returned, true);
    if (!Success)
      return;
    const MemRegion *const *Region = Success->get<ArithmeticContractField>(
        C.getLocationContext()->getStackFrame());
    auto Value = Region ? Success->getSVal(*Region)
                              .getAs<DefinedOrUnknownSVal>()
                        : std::nullopt;
    if (!Value) {
      report(Return->getRetValue(), Success,
             "successful return cannot prove nonzero field '" +
                 Contract->Field.str() + "'",
             C);
      return;
    }
    ProgramStateRef Violation = Success->assume(*Value, false);
    if (Violation)
      report(Return->getRetValue(), Violation,
             "successful return does not establish nonzero field '" +
                 Contract->Field.str() + "'",
             C);
  }
};

class DivisorChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPreStmt(const BinaryOperator *Operation, CheckerContext &C) const {
    BinaryOperatorKind Opcode = Operation->getOpcode();
    if (Opcode != BO_Div && Opcode != BO_Rem && Opcode != BO_DivAssign &&
        Opcode != BO_RemAssign)
      return;
    if (!Operation->getLHS()->getType()->isIntegerType() ||
        !Operation->getRHS()->getType()->isIntegerType())
      return;
    ProgramStateRef Input = C.getState();
    ProgramStateRef Violation = Input;
    if (std::optional<DefinedOrUnknownSVal> Divisor =
            C.getSVal(Operation->getRHS()).getAs<DefinedOrUnknownSVal>()) {
      Violation = Violation->assume(*Divisor, false);
      if (!Violation)
        return;
    }
    // The assume() above asks the path-sensitive solver alone, which
    // doesn't re-derive a divisor's range from an already-narrow SymExpr
    // the way expressionInterval() does. That reasoning, built for
    // SignedArithmeticChecker, applies just as soundly here as a second,
    // independent proof avenue: a divisor the solver can't rule out zero
    // for, but whose statically-computed range provably excludes zero.
    // The stage disables Clang's core.DivideZero, so this can't borrow a
    // nonzero assumption from that overlapping checker.
    SizeCastChecker::Interval Range = SizeCastChecker::expressionInterval(
        Operation->getRHS(), C, Input);
    llvm::APSInt Zero(llvm::APInt(SizeCastChecker::MathBits, 0), false);
    if (Range.Min > Zero || Range.Max < Zero)
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode(Violation);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven nonzero divisor",
                                     categories::LogicError);
    std::string Message = "divisor is not proven nonzero; origin '" +
                          arithmeticOrigin(Operation, C) + "'; context '" +
                          arithmeticContext(C) + "'; expression '" +
                          arithmeticText(Operation, C) + "'; site '" +
                          arithmeticSite(Operation, C) + "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Operation->getRHS()->getSourceRange());
    C.emitReport(std::move(Report));
  }
};

class ShiftCountChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BugType> BT;

public:
  void checkPreStmt(const BinaryOperator *Operation, CheckerContext &C) const {
    BinaryOperatorKind Opcode = Operation->getOpcode();
    if (Opcode != BO_Shl && Opcode != BO_Shr && Opcode != BO_ShlAssign &&
        Opcode != BO_ShrAssign)
      return;
    ASTContext &Context = C.getASTContext();
    QualType ValueType = Operation->getLHS()->getType();
    QualType CountType = Operation->getRHS()->getType();
    if (!ValueType->isIntegerType() || !CountType->isIntegerType())
      return;
    unsigned Width = Context.getIntWidth(ValueType);
    unsigned CountBits = Context.getIntWidth(CountType);
    bool CountUnsigned = CountType->isUnsignedIntegerOrEnumerationType();
    llvm::APSInt Low(llvm::APInt(CountBits, 0), CountUnsigned);
    llvm::APSInt High(llvm::APInt(CountBits, Width - 1), CountUnsigned);
    ProgramStateRef Input = C.getState();
    ProgramStateRef Violation = Input;
    if (std::optional<DefinedOrUnknownSVal> Count =
            C.getSVal(Operation->getRHS()).getAs<DefinedOrUnknownSVal>()) {
      Violation = Violation->assumeInclusiveRange(*Count, Low, High, false);
      if (!Violation)
        return;
    }
    // Same second, independent proof avenue as DivisorChecker just above:
    // the stage likewise disables core.BitwiseShift, so the raw solver
    // only sees a shift count's own SVal, not the Rem/And/Shr/Add/Sub/Mul
    // structure expressionInterval() reconstructs.
    SizeCastChecker::Interval CountRange = SizeCastChecker::expressionInterval(
        Operation->getRHS(), C, Input);
    SizeCastChecker::Interval Safe{SizeCastChecker::asMath(Low),
                                   SizeCastChecker::asMath(High)};
    if (SizeCastChecker::contains(Safe, CountRange))
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode(Violation);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven shift count",
                                     categories::LogicError);
    std::string Message = "shift count is not proven in range [0, " +
                          std::to_string(Width) + "); origin '" +
                          arithmeticOrigin(Operation, C) + "'; context '" +
                          arithmeticContext(C) + "'; expression '" +
                          arithmeticText(Operation, C) + "'; site '" +
                          arithmeticSite(Operation, C) + "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Operation->getRHS()->getSourceRange());
    C.emitReport(std::move(Report));
  }
};

class TaggedResultChecker : public Checker<check::Location> {
  mutable std::unique_ptr<BugType> BT;

  static std::string sourceOrigin(const Stmt *Statement, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    return SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())).str();
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

public:
  void checkLocation(SVal Location, bool IsLoad, const Stmt *Statement,
                     CheckerContext &C) const {
    if (!IsLoad)
      return;
    const auto *Field = dyn_cast_or_null<FieldRegion>(Location.getAsRegion());
    if (!Field)
      return;
    const FieldDecl *Accessed = Field->getDecl();
    StringRef FieldName = Accessed->getName();
    bool WantsNormal = FieldName == "normal";
    bool WantsSpecial = FieldName == "special";
    if (!WantsNormal && !WantsSpecial)
      return;
    const RecordDecl *Record = Accessed->getParent();
    if (!Record->getName().ends_with("_variant_result"))
      return;

    const FieldDecl *Kind = nullptr;
    for (const FieldDecl *Candidate : Record->fields()) {
      if (Candidate->getName() == "kind") {
        Kind = Candidate;
        break;
      }
    }
    ProgramStateRef State = C.getState();
    ProgramStateRef Violation = State;
    const auto *Super = dyn_cast<SubRegion>(Field->getSuperRegion());
    if (Kind && Super) {
      const FieldRegion *KindRegion =
          C.getSValBuilder().getRegionManager().getFieldRegion(Kind, Super);
      SVal KindValue = State->getSVal(KindRegion);
      if (std::optional<NonLoc> Defined = KindValue.getAs<NonLoc>()) {
        Violation = State->assume(*Defined, WantsNormal);
        if (!Violation)
          return;
      }
    }

    ExplodedNode *Node = C.generateNonFatalErrorNode(Violation);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unselected tagged result field",
                                     categories::LogicError);
    const Decl *Current = C.getLocationContext()->getDecl();
    std::string Context = Current ? Current->getDeclKindName() : "unknown";
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      Context = Named->getQualifiedNameAsString();
    std::string Message = "tagged result field '" + FieldName.str() +
                          "' is not proven selected; origin '" +
                          sourceOrigin(Statement, C) + "'; context '" +
                          Context + "'; access '" + sourceText(Statement, C) +
                          "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }
};

/* Enforces include/ownership.h's integer_sentinel(value)/long_sentinel(value):
 * a PLAIN scalar function return or parameter that names one excluded
 * literal, the parametric sibling of sentinel_exclude(value) for values that
 * are not a tokdef'd opaque handle. src/util/timeout.c's parse_duration()
 * (fixed by hand in commit 1c4fc3b2, before this checker existed) is exactly
 * the shape this closes: a `long` return whose -1 means "unrepresentable
 * duration", cast to time_t on a path that never ruled -1 out first.
 *
 * The proof obligation here -- "is it possible for this exact value to equal
 * one fixed literal" -- is a single-symbol equality query, not the
 * cross-symbol relational bound ntlibc.SizeCast's own CastZ3Proof exists for
 * (see CastZ3Engine's comment above for why THAT problem needs Z3: two
 * independently-bounded symbols compared to each other, which plain interval
 * arithmetic cannot combine). A fixed-literal equality is exactly what the
 * engine's ordinary RangeConstraintManager already decides exactly, with no
 * completeness gap -- so this checker calls TokenAlgebra.h's
 * splitOnExcludedSentinel() directly, the same real path-sensitive proof
 * OwnershipChecker.cpp's refineExcludedSentinel() already relies on for
 * sentinel_exclude(value)'s tokdef case, rather than adding a second,
 * disconnected proof engine. It still lives in this translation unit
 * alongside ntlibc.SizeCast/ntlibc.ArrayIndex, sharing their diagnostic
 * shape and BugReporter conventions, so a NTLIBC_ARITHMETIC_Z3 escalation
 * can be added here later without disturbing callers if a real relational
 * guard shape (e.g. "checked against another, independently-bounded
 * variable" rather than a literal) is ever found to need one. */
class IntegerSentinelChecker
    : public Checker<check::PostCall, check::BeginFunction,
                     check::PreStmt<BinaryOperator>,
                     check::PreStmt<ArraySubscriptExpr>,
                     check::PreStmt<ExplicitCastExpr>> {
  mutable std::unique_ptr<BugType> BT;

  static std::optional<int64_t> declSentinel(const Decl *Declaration) {
    return Declaration ? ntlibc::algebra::scalarSentinel(Declaration)
                       : std::nullopt;
  }

  // Every redeclaration gets its own ParmVarDecl/FunctionDecl objects; the
  // qualifier commonly sits on a header prototype the .c file's own
  // definition does not restate (see tokenContracts() in
  // MemoryContractChecker.cpp for the identical redecls() walk memory
  // contracts already need for the same reason).
  static const Decl *returnSentinelDecl(const FunctionDecl *Function) {
    if (!Function)
      return nullptr;
    for (const FunctionDecl *Redeclaration : Function->redecls())
      if (declSentinel(Redeclaration))
        return Redeclaration;
    return nullptr;
  }

  static const Decl *parameterSentinelDecl(const FunctionDecl *Function,
                                           unsigned Index) {
    if (!Function)
      return nullptr;
    for (const FunctionDecl *Redeclaration : Function->redecls()) {
      if (Index >= Redeclaration->getNumParams())
        continue;
      const ParmVarDecl *Parameter = Redeclaration->getParamDecl(Index);
      if (declSentinel(Parameter))
        return Parameter;
    }
    return nullptr;
  }

  // Walks through SymbolCast wrappers (an intervening implicit or explicit
  // conversion -- e.g. assigning a sentinel-marked `long` return into an
  // `int` local) to find the tracked base symbol underneath, the same
  // unwrapping CastZ3Proof::translate() above already does for the same
  // reason.
  static std::pair<SymbolRef, const Decl *>
  trackedOrigin(SVal Value, ProgramStateRef State) {
    SymbolRef Symbol = Value.getAsSymbol(true);
    for (unsigned Depth = 0; Symbol && Depth < 12; ++Depth) {
      if (const Decl *const *Found = State->get<IntegerSentinelOrigin>(Symbol))
        return {Symbol, *Found};
      const auto *Cast = dyn_cast<SymbolCast>(Symbol);
      if (!Cast)
        break;
      Symbol = Cast->getOperand();
    }
    return {nullptr, nullptr};
  }

  static std::string sourceText(const Expr *Expr, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    SourceLocation Begin = SM.getSpellingLoc(Expr->getBeginLoc());
    SourceLocation End = SM.getSpellingLoc(Expr->getEndLoc());
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
    if (Result.empty())
      Result = Expr->getStmtClassName();
    return Result;
  }

  static std::string sourceOrigin(const Expr *Expr, CheckerContext &C) {
    const SourceManager &SM = C.getSourceManager();
    return SM.getFilename(SM.getExpansionLoc(Expr->getBeginLoc())).str();
  }

  void checkUse(const Expr *UseExpr, CheckerContext &C,
               StringRef UseKind) const {
    if (!UseExpr)
      return;
    ProgramStateRef State = C.getState();
    SVal Value = C.getSVal(UseExpr);
    auto [Symbol, Origin] = trackedOrigin(Value, State);
    if (!Symbol || !Origin)
      return;
    std::optional<int64_t> Sentinel = declSentinel(Origin);
    if (!Sentinel)
      return;
    std::optional<DefinedOrUnknownSVal> Defined =
        Value.getAs<DefinedOrUnknownSVal>();
    if (!Defined)
      return;
    QualType Type = Value.getType(C.getASTContext());
    if (Type.isNull() || !Type->isIntegralOrEnumerationType())
      return;
    ntlibc::algebra::SentinelSplit Split = ntlibc::algebra::splitOnExcludedSentinel(
        State, *Defined, Type, *Sentinel, C.getSValBuilder());
    if (!Split.Sentinel)
      return; // infeasible for Value to equal Sentinel: proven excluded.

    ExplodedNode *Node = C.generateNonFatalErrorNode(Split.Sentinel);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven integer sentinel",
                                     categories::LogicError);
    const Decl *Current = C.getLocationContext()->getDecl();
    std::string Context = Current ? Current->getDeclKindName() : "unknown";
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      Context = Named->getQualifiedNameAsString();
    std::string OriginName = "<expression>";
    if (const auto *Parameter = dyn_cast<ParmVarDecl>(Origin)) {
      OriginName = "parameter '" + Parameter->getNameAsString() + "'";
      if (const auto *Function =
              dyn_cast_or_null<FunctionDecl>(Parameter->getDeclContext()))
        OriginName += " of '" + Function->getQualifiedNameAsString() + "'";
    } else if (const auto *Named = dyn_cast<NamedDecl>(Origin)) {
      OriginName = "'" + Named->getQualifiedNameAsString() + "'";
    }
    std::string Message =
        "value from " + OriginName + " carries excluded sentinel " +
        std::to_string(*Sentinel) + " not proven ruled out before " +
        UseKind.str() + "; origin '" + sourceOrigin(UseExpr, C) +
        "'; context '" + Context + "'; use '" + sourceText(UseExpr, C) + "'";
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(UseExpr->getSourceRange());
    C.emitReport(std::move(Report));
  }

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    const auto *Callee = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Callee || !Callee->getReturnType()->isIntegralOrEnumerationType())
      return;
    const Decl *Origin = returnSentinelDecl(Callee);
    if (!Origin)
      return;
    SymbolRef Symbol = Call.getReturnValue().getAsSymbol(true);
    if (!Symbol)
      return;
    ProgramStateRef State = C.getState();
    C.addTransition(State->set<IntegerSentinelOrigin>(Symbol, Origin));
  }

  void checkBeginFunction(CheckerContext &C) const {
    const auto *Function =
        dyn_cast_or_null<FunctionDecl>(C.getLocationContext()->getDecl());
    if (!Function)
      return;
    ProgramStateRef State = C.getState();
    const LocationContext *LCtx = C.getLocationContext();
    bool Changed = false;
    for (unsigned Index = 0; Index < Function->getNumParams(); ++Index) {
      const ParmVarDecl *Parameter = Function->getParamDecl(Index);
      if (!Parameter->getType()->isIntegralOrEnumerationType())
        continue;
      const Decl *Origin = parameterSentinelDecl(Function, Index);
      if (!Origin)
        continue;
      SVal ParamValue = State->getSVal(State->getLValue(Parameter, LCtx));
      SymbolRef Symbol = ParamValue.getAsSymbol(true);
      if (!Symbol)
        continue;
      State = State->set<IntegerSentinelOrigin>(Symbol, Origin);
      Changed = true;
    }
    if (Changed)
      C.addTransition(State);
  }

  void checkPreStmt(const BinaryOperator *Operation, CheckerContext &C) const {
    switch (Operation->getOpcode()) {
    case BO_Add:
    case BO_Sub:
    case BO_Mul:
    case BO_Div:
      break;
    default:
      return;
    }
    checkUse(Operation->getLHS(), C, "arithmetic");
    checkUse(Operation->getRHS(), C, "arithmetic");
  }

  void checkPreStmt(const ArraySubscriptExpr *Subscript,
                    CheckerContext &C) const {
    checkUse(Subscript->getIdx(), C, "an array index");
  }

  void checkPreStmt(const ExplicitCastExpr *Cast, CheckerContext &C) const {
    checkUse(Cast->getSubExpr(), C, "a cast");
  }
};

} // namespace

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<SizeCastChecker>(
      "ntlibc.SizeCast", "Proves that explicit integer casts preserve values",
      "");
  Registry.addChecker<ArrayIndexChecker>(
      "ntlibc.ArrayIndex", "Proves that array indices are in bounds", "");
  Registry.addChecker<TaggedResultChecker>(
      "ntlibc.TaggedResult",
      "Proves that tagged normal and special result fields are selected", "");
  Registry.addChecker<DivisorChecker>(
      "ntlibc.Divisor", "Proves that integer divisors are nonzero", "");
  Registry.addChecker<ShiftCountChecker>(
      "ntlibc.ShiftCount", "Proves that integer shift counts are in range", "");
  Registry.addChecker<SignedArithmeticChecker>(
      "ntlibc.SignedArithmetic",
      "Proves that signed arithmetic results are representable", "");
  Registry.addChecker<ArithmeticContractChecker>(
      "ntlibc.ArithmeticContract",
      "Enforces arithmetic parameter and successful-call contracts", "");
  Registry.addChecker<IntegerSentinelChecker>(
      "ntlibc.IntegerSentinel",
      "Proves integer_sentinel/long_sentinel values are ruled out before "
      "arithmetic, cast, or index use",
      "");
}
