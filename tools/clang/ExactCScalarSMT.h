// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef SPICULE_EXACT_C_SCALAR_SMT_H
#define SPICULE_EXACT_C_SCALAR_SMT_H

#include "z3++.h"

#include <optional>
#include <utility>

namespace spicule::algebra {

// Target-specific C integer type information.  Rank is the C conversion rank,
// not the bit width: consumers must distinguish (for example) a same-width
// signed char and int on unusual targets.
struct CType {
  unsigned Width;
  unsigned Rank;
  bool Unsigned;

  bool valid() const { return Width != 0 && Rank != 0; }
  bool sameDomain(CType Other) const {
    return valid() && Other.valid() && Width == Other.Width &&
           Rank == Other.Rank && Unsigned == Other.Unsigned;
  }
};

struct SemanticEvents {
  z3::expr SignedOverflow;
  z3::expr UnsignedWrap;
  z3::expr NarrowingLoss;
  z3::expr InvalidShift;
  z3::expr DivisionByZero;

  SemanticEvents(z3::expr SignedOverflow, z3::expr UnsignedWrap,
                 z3::expr NarrowingLoss, z3::expr InvalidShift,
                 z3::expr DivisionByZero)
      : SignedOverflow(std::move(SignedOverflow)),
        UnsignedWrap(std::move(UnsignedWrap)),
        NarrowingLoss(std::move(NarrowingLoss)),
        InvalidShift(std::move(InvalidShift)),
        DivisionByZero(std::move(DivisionByZero)) {}
};

// Value is always the target bit pattern, including on an undefined path.  A
// client may therefore use it to keep later reasoning conservative.  Defined
// is the exact conjunction of the supported C definedness requirements, while
// Events records both undefined behavior and defined-but-policy-relevant
// events.  Permission to accept an event belongs to the consuming checker.
struct SemanticResult {
  CType Type;
  z3::expr Value;
  z3::expr Defined;
  SemanticEvents Events;

  SemanticResult(CType Type, z3::expr Value, z3::expr Defined,
                 SemanticEvents Events)
      : Type(Type), Value(std::move(Value)), Defined(std::move(Defined)),
        Events(std::move(Events)) {}
};

// The common trust boundary for side-solver consumers: only an UNSAT answer
// proves that the forbidden semantic event is unreachable.  SAT, timeout,
// resource exhaustion, and every other unknown result remain obligations.
inline bool provesUnsatisfiable(z3::solver &Solver) {
  return Solver.check() == z3::unsat;
}

// Scalar is the integer-value module of spicule's common semantic algebra.
// Future path propositions and token/resource modules can bind these immutable
// results to their own versioned identities without duplicating C conversions
// or conflating solver truth with checker permission.
class ScalarSMT {
  z3::context &Z;
  CType IntType;
  CType UnsignedIntType;

  z3::expr noEvent() const { return Z.bool_val(false); }

  SemanticEvents noEvents() const {
    return {noEvent(), noEvent(), noEvent(), noEvent(), noEvent()};
  }

  SemanticEvents combine(const SemanticEvents &Left,
                         const SemanticEvents &Right) const {
    return {Left.SignedOverflow || Right.SignedOverflow,
            Left.UnsignedWrap || Right.UnsignedWrap,
            Left.NarrowingLoss || Right.NarrowingLoss,
            Left.InvalidShift || Right.InvalidShift,
            Left.DivisionByZero || Right.DivisionByZero};
  }

  static bool canRepresentAll(CType Destination, CType Source) {
    if (Destination.Unsigned)
      return Source.Unsigned && Destination.Width >= Source.Width;
    if (!Source.Unsigned)
      return Destination.Width >= Source.Width;
    return Destination.Width > Source.Width;
  }

  z3::expr resize(const z3::expr &Value, CType Source,
                  CType Destination) const {
    if (Destination.Width < Source.Width)
      return Value.extract(Destination.Width - 1, 0);
    if (Destination.Width > Source.Width)
      return Source.Unsigned
                 ? z3::zext(Value, Destination.Width - Source.Width)
                 : z3::sext(Value, Destination.Width - Source.Width);
    return Value;
  }

  z3::expr mathematicalValue(const z3::expr &Value, CType Type) const {
    return z3::bv2int(Value, !Type.Unsigned);
  }

  std::optional<std::pair<SemanticResult, SemanticResult>>
  usualOperands(const SemanticResult &Left, const SemanticResult &Right) const {
    std::optional<SemanticResult> PromotedLeft = promote(Left);
    std::optional<SemanticResult> PromotedRight = promote(Right);
    if (!PromotedLeft || !PromotedRight)
      return std::nullopt;
    std::optional<CType> Common =
        usualArithmeticType(PromotedLeft->Type, PromotedRight->Type);
    if (!Common)
      return std::nullopt;
    std::optional<SemanticResult> ConvertedLeft =
        convert(*PromotedLeft, *Common);
    std::optional<SemanticResult> ConvertedRight =
        convert(*PromotedRight, *Common);
    if (!ConvertedLeft || !ConvertedRight)
      return std::nullopt;
    return std::pair<SemanticResult, SemanticResult>(
        std::move(*ConvertedLeft), std::move(*ConvertedRight));
  }

  template <typename ValueBuilder, typename EventBuilder>
  std::optional<SemanticResult>
  convertedArithmetic(const SemanticResult &L, const SemanticResult &R,
                      ValueBuilder BuildValue,
                      EventBuilder BuildLocalEvents) const {
    if (!L.Type.sameDomain(R.Type) || !wellTyped(L.Value, L.Type) ||
        !wellTyped(R.Value, R.Type))
      return std::nullopt;
    z3::expr Value = BuildValue(L.Value, R.Value);
    SemanticEvents Local = BuildLocalEvents(L.Value, R.Value, L.Type);
    SemanticEvents Events = combine(combine(L.Events, R.Events), Local);
    z3::expr Defined = L.Defined && R.Defined && !Local.SignedOverflow &&
                       !Local.InvalidShift && !Local.DivisionByZero;
    return SemanticResult(L.Type, std::move(Value), std::move(Defined),
                          std::move(Events));
  }

  template <typename Operation>
  std::optional<SemanticResult> sourceArithmetic(const SemanticResult &Left,
                                                 const SemanticResult &Right,
                                                 Operation Apply) const {
    std::optional<std::pair<SemanticResult, SemanticResult>> Operands =
        usualOperands(Left, Right);
    return Operands ? Apply(Operands->first, Operands->second) : std::nullopt;
  }

public:
  ScalarSMT(z3::context &Z, CType IntType, CType UnsignedIntType)
      : Z(Z), IntType(IntType), UnsignedIntType(UnsignedIntType) {}

  bool wellTyped(const z3::expr &Value, CType Type) const {
    return Type.valid() && Value.is_bv() &&
           Value.get_sort().bv_size() == Type.Width;
  }

  std::optional<SemanticResult> input(const z3::expr &Value, CType Type) const {
    if (!wellTyped(Value, Type))
      return std::nullopt;
    return SemanticResult(Type, Value, Z.bool_val(true), noEvents());
  }

  std::optional<SemanticResult> convert(const SemanticResult &Input,
                                        CType Destination) const {
    if (!wellTyped(Input.Value, Input.Type) || !Destination.valid())
      return std::nullopt;
    z3::expr Value = resize(Input.Value, Input.Type, Destination);
    z3::expr Loss = mathematicalValue(Input.Value, Input.Type) !=
                    mathematicalValue(Value, Destination);
    SemanticEvents Events = Input.Events;
    Events.NarrowingLoss = Events.NarrowingLoss || Loss;
    // Integer conversion to an out-of-range signed type is implementation-
    // defined, not undefined.  Clang's supported targets use the represented
    // low-bit/two's-complement value above; the event remains available to a
    // client whose policy rejects loss of mathematical value.
    return SemanticResult(Destination, std::move(Value), Input.Defined,
                          std::move(Events));
  }

  std::optional<SemanticResult> promote(const SemanticResult &Input) const {
    if (!Input.Type.valid() || !IntType.valid() || !UnsignedIntType.valid() ||
        IntType.Rank != UnsignedIntType.Rank ||
        IntType.Width != UnsignedIntType.Width || IntType.Unsigned ||
        !UnsignedIntType.Unsigned)
      return std::nullopt;
    if (Input.Type.Rank >= IntType.Rank)
      return Input;
    return convert(Input, canRepresentAll(IntType, Input.Type)
                              ? IntType
                              : UnsignedIntType);
  }

  std::optional<CType> usualArithmeticType(CType Left, CType Right) const {
    if (!Left.valid() || !Right.valid())
      return std::nullopt;
    if (Left.sameDomain(Right))
      return Left;
    if (Left.Unsigned == Right.Unsigned)
      return Left.Rank >= Right.Rank ? Left : Right;

    CType Unsigned = Left.Unsigned ? Left : Right;
    CType Signed = Left.Unsigned ? Right : Left;
    if (Unsigned.Rank >= Signed.Rank)
      return Unsigned;
    if (canRepresentAll(Signed, Unsigned))
      return Signed;
    return CType{Signed.Width, Signed.Rank, true};
  }

  std::optional<SemanticResult> add(const SemanticResult &Left,
                                    const SemanticResult &Right) const {
    return sourceArithmetic(
        Left, Right, [&](const SemanticResult &L, const SemanticResult &R) {
          return addConverted(L, R);
        });
  }

  // Clang's symbolic-value DAG and similar typed IRs already contain C's
  // promotions/conversions.  These entry points retain that exact domain
  // instead of applying source-language conversions a second time.
  std::optional<SemanticResult>
  addConverted(const SemanticResult &Left, const SemanticResult &Right) const {
    return convertedArithmetic(
        Left, Right, [](const z3::expr &L, const z3::expr &R) { return L + R; },
        [&](const z3::expr &L, const z3::expr &R, CType Type) {
          if (Type.Unsigned)
            return SemanticEvents(noEvent(),
                                  !z3::bvadd_no_overflow(L, R, false),
                                  noEvent(), noEvent(), noEvent());
          z3::expr Overflow = !(z3::bvadd_no_overflow(L, R, true) &&
                                z3::bvadd_no_underflow(L, R));
          return SemanticEvents(Overflow, noEvent(), noEvent(), noEvent(),
                                noEvent());
        });
  }

  std::optional<SemanticResult> subtract(const SemanticResult &Left,
                                         const SemanticResult &Right) const {
    return sourceArithmetic(
        Left, Right, [&](const SemanticResult &L, const SemanticResult &R) {
          return subtractConverted(L, R);
        });
  }

  std::optional<SemanticResult>
  subtractConverted(const SemanticResult &Left,
                    const SemanticResult &Right) const {
    return convertedArithmetic(
        Left, Right, [](const z3::expr &L, const z3::expr &R) { return L - R; },
        [&](const z3::expr &L, const z3::expr &R, CType Type) {
          if (Type.Unsigned)
            return SemanticEvents(noEvent(),
                                  !z3::bvsub_no_underflow(L, R, false),
                                  noEvent(), noEvent(), noEvent());
          z3::expr Overflow = !(z3::bvsub_no_overflow(L, R) &&
                                z3::bvsub_no_underflow(L, R, true));
          return SemanticEvents(Overflow, noEvent(), noEvent(), noEvent(),
                                noEvent());
        });
  }

  std::optional<SemanticResult> multiply(const SemanticResult &Left,
                                         const SemanticResult &Right) const {
    return sourceArithmetic(
        Left, Right, [&](const SemanticResult &L, const SemanticResult &R) {
          return multiplyConverted(L, R);
        });
  }

  std::optional<SemanticResult>
  multiplyConverted(const SemanticResult &Left,
                    const SemanticResult &Right) const {
    return convertedArithmetic(
        Left, Right, [](const z3::expr &L, const z3::expr &R) { return L * R; },
        [&](const z3::expr &L, const z3::expr &R, CType Type) {
          if (Type.Unsigned)
            return SemanticEvents(noEvent(),
                                  !z3::bvmul_no_overflow(L, R, false),
                                  noEvent(), noEvent(), noEvent());
          z3::expr Overflow = !(z3::bvmul_no_overflow(L, R, true) &&
                                z3::bvmul_no_underflow(L, R));
          return SemanticEvents(Overflow, noEvent(), noEvent(), noEvent(),
                                noEvent());
        });
  }

  std::optional<SemanticResult> divide(const SemanticResult &Left,
                                       const SemanticResult &Right) const {
    return sourceArithmetic(
        Left, Right, [&](const SemanticResult &L, const SemanticResult &R) {
          return divideConverted(L, R);
        });
  }

  std::optional<SemanticResult>
  divideConverted(const SemanticResult &Left,
                  const SemanticResult &Right) const {
    if (!Left.Type.sameDomain(Right.Type) ||
        !wellTyped(Left.Value, Left.Type) ||
        !wellTyped(Right.Value, Right.Type))
      return std::nullopt;
    CType Type = Left.Type;
    z3::expr Value = Type.Unsigned ? z3::udiv(Left.Value, Right.Value)
                                   : Left.Value / Right.Value;
    z3::expr Zero = Right.Value == Z.bv_val(0, Type.Width);
    z3::expr Overflow = Type.Unsigned
                            ? noEvent()
                            : !z3::bvsdiv_no_overflow(Left.Value, Right.Value);
    SemanticEvents Local(Overflow, noEvent(), noEvent(), noEvent(), Zero);
    SemanticEvents Events = combine(combine(Left.Events, Right.Events), Local);
    return SemanticResult(Type, std::move(Value),
                          Left.Defined && Right.Defined && !Overflow && !Zero,
                          std::move(Events));
  }

  std::optional<SemanticResult> remainder(const SemanticResult &Left,
                                          const SemanticResult &Right) const {
    return sourceArithmetic(
        Left, Right, [&](const SemanticResult &L, const SemanticResult &R) {
          return remainderConverted(L, R);
        });
  }

  std::optional<SemanticResult>
  remainderConverted(const SemanticResult &Left,
                     const SemanticResult &Right) const {
    if (!Left.Type.sameDomain(Right.Type) ||
        !wellTyped(Left.Value, Left.Type) ||
        !wellTyped(Right.Value, Right.Type))
      return std::nullopt;
    CType Type = Left.Type;
    z3::expr Value = Type.Unsigned ? z3::urem(Left.Value, Right.Value)
                                   : z3::srem(Left.Value, Right.Value);
    z3::expr Zero = Right.Value == Z.bv_val(0, Type.Width);
    z3::expr Overflow = Type.Unsigned
                            ? noEvent()
                            : !z3::bvsdiv_no_overflow(Left.Value, Right.Value);
    SemanticEvents Local(Overflow, noEvent(), noEvent(), noEvent(), Zero);
    SemanticEvents Events = combine(combine(Left.Events, Right.Events), Local);
    return SemanticResult(Type, std::move(Value),
                          Left.Defined && Right.Defined && !Overflow && !Zero,
                          std::move(Events));
  }

  std::optional<SemanticResult> unitStep(const SemanticResult &Input,
                                         bool Increasing) const {
    std::optional<SemanticResult> Promoted = promote(Input);
    if (!Promoted)
      return std::nullopt;
    unsigned Width = Promoted->Type.Width;
    z3::expr One = Z.bv_val(1, Width);
    z3::expr Value = Increasing ? Promoted->Value + One : Promoted->Value - One;
    z3::expr Zero = Z.bv_val(0, Width);
    z3::expr AllOnes = ~Zero;
    z3::expr SignBit = z3::shl(One, Width - 1);
    z3::expr Maximum = SignBit - One;
    z3::expr SignedOverflow =
        Promoted->Type.Unsigned
            ? noEvent()
            : Promoted->Value == (Increasing ? Maximum : SignBit);
    z3::expr UnsignedWrap =
        Promoted->Type.Unsigned
            ? Promoted->Value == (Increasing ? AllOnes : Zero)
            : noEvent();
    SemanticEvents Local(SignedOverflow, UnsignedWrap, noEvent(), noEvent(),
                         noEvent());
    SemanticEvents Events = combine(Promoted->Events, Local);
    return SemanticResult(Promoted->Type, std::move(Value),
                          Promoted->Defined && !SignedOverflow,
                          std::move(Events));
  }

  std::optional<SemanticResult> negate(const SemanticResult &Input) const {
    std::optional<SemanticResult> Promoted = promote(Input);
    if (!Promoted)
      return std::nullopt;
    z3::expr Value = -Promoted->Value;
    z3::expr SignedOverflow = Promoted->Type.Unsigned
                                  ? noEvent()
                                  : !z3::bvneg_no_overflow(Promoted->Value);
    z3::expr UnsignedWrap =
        Promoted->Type.Unsigned
            ? Promoted->Value != Z.bv_val(0, Promoted->Type.Width)
            : noEvent();
    SemanticEvents Local(SignedOverflow, UnsignedWrap, noEvent(), noEvent(),
                         noEvent());
    SemanticEvents Events = combine(Promoted->Events, Local);
    return SemanticResult(Promoted->Type, std::move(Value),
                          Promoted->Defined && !SignedOverflow,
                          std::move(Events));
  }

  std::optional<SemanticResult> bitwiseNot(const SemanticResult &Input) const {
    std::optional<SemanticResult> Promoted = promote(Input);
    if (!Promoted)
      return std::nullopt;
    Promoted->Value = ~Promoted->Value;
    return Promoted;
  }

  std::optional<SemanticResult> shiftLeft(const SemanticResult &Left,
                                          const SemanticResult &Right) const {
    std::optional<SemanticResult> L = promote(Left);
    std::optional<SemanticResult> R = promote(Right);
    if (!L || !R)
      return std::nullopt;
    z3::expr ShiftMath = mathematicalValue(R->Value, R->Type);
    z3::expr Invalid = ShiftMath < 0 || ShiftMath >= Z.int_val(L->Type.Width);
    z3::expr Shift = z3::int2bv(L->Type.Width, ShiftMath);
    z3::expr Value = z3::shl(L->Value, Shift);
    z3::expr Recover =
        L->Type.Unsigned ? z3::lshr(Value, Shift) : z3::ashr(Value, Shift);
    z3::expr SignedOverflow =
        !L->Type.Unsigned && !Invalid &&
        (mathematicalValue(L->Value, L->Type) < 0 || Recover != L->Value);
    z3::expr UnsignedWrap = L->Type.Unsigned && !Invalid && Recover != L->Value;
    SemanticEvents Local(SignedOverflow, UnsignedWrap, noEvent(), Invalid,
                         noEvent());
    SemanticEvents Events = combine(combine(L->Events, R->Events), Local);
    return SemanticResult(L->Type, std::move(Value),
                          L->Defined && R->Defined && !Invalid &&
                              !SignedOverflow,
                          std::move(Events));
  }

  std::optional<z3::expr> less(const SemanticResult &Left,
                               const SemanticResult &Right) const {
    std::optional<std::pair<SemanticResult, SemanticResult>> Operands =
        usualOperands(Left, Right);
    if (!Operands)
      return std::nullopt;
    return Operands->first.Type.Unsigned
               ? z3::ult(Operands->first.Value, Operands->second.Value)
               : Operands->first.Value < Operands->second.Value;
  }
};

} // namespace spicule::algebra

#endif
