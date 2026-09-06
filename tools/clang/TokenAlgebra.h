// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef NTLIBC_TOKEN_ALGEBRA_H
#define NTLIBC_TOKEN_ALGEBRA_H

#include "clang/AST/ASTContext.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SValBuilder.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Casting.h"

#include <cctype>
#include <cstdint>
#include <optional>

namespace ntlibc::algebra {

/* Unknown is abstract knowledge, not a fourth runtime multiplicity.  It is
 * the havoc state used after a policy-violating edge, which remains a real C
 * edge even though its token contract can no longer justify facts. */
enum class TokenState : uint8_t { Unknown, Absent, Linear, Duplicable };

enum class TokenOperation : uint8_t {
  Require,
  RequireAbsent,
  Consume,
  ConsumeIfPresent,
  Drop,
  GrantLinear,
  GrantDuplicable,
};

/* Policy violations are diagnostics.  They are deliberately distinct from
 * state effects such as expiring outstanding strict loans. */
enum class TokenEvent : uint8_t {
  None = 0,
  MissingRequired = 1U << 0,
  PresentWhenAbsentRequired = 1U << 1,
  LinearDuplication = 1U << 2,
  DuplicationClassMismatch = 1U << 3,
  DestinationOccupied = 1U << 4,
  StateUnproven = 1U << 5,
};

enum class TokenEffect : uint8_t {
  None = 0,
  InvalidateStrictLoans = 1U << 0,
};

constexpr TokenEvent operator|(TokenEvent Left, TokenEvent Right) {
  return static_cast<TokenEvent>(static_cast<uint8_t>(Left) |
                                 static_cast<uint8_t>(Right));
}

constexpr bool contains(TokenEvent Events, TokenEvent Event) {
  return (static_cast<uint8_t>(Events) & static_cast<uint8_t>(Event)) != 0;
}

struct TokenTransition {
  TokenState Before;
  TokenState After;
  TokenEvent Events;
  TokenEffect Effects;

  constexpr bool permitted() const { return Events == TokenEvent::None; }
};

enum class RelationSupport : uint8_t { Exact, Havoced, Unsupported };
enum class ProofStatus : uint8_t { Unproved, Refuted, Proved };

struct ElementTokenRelation {
  TokenState Elements;
  RelationSupport Support;
  bool RequiresValuePredicate;
  bool RefinesExcludedSentinel;
};

struct ElementTokenLookup {
  TokenState Element;
  TokenEvent Events;
  bool ApplyValueRefinement;

  constexpr bool proved() const { return Events == TokenEvent::None; }
};

/* Object identity, memory version, and index-domain proofs are supplied by
 * each checker's semantic adapter.  The common algebra only releases the
 * element token when every relation premise is exact; omitted or stale state
 * remains unproved rather than being silently framed. */
constexpr ElementTokenLookup lookupElementToken(
    ElementTokenRelation Relation, bool SameMemoryVersion,
    ProofStatus ValidIndex, ProofStatus ValueRefinement) {
  if (Relation.Support != RelationSupport::Exact || !SameMemoryVersion ||
      ValidIndex != ProofStatus::Proved ||
      (Relation.RequiresValuePredicate &&
       ValueRefinement != ProofStatus::Proved))
    return {TokenState::Unknown, TokenEvent::StateUnproven, false};
  return {Relation.Elements, TokenEvent::None,
          Relation.RefinesExcludedSentinel};
}

/* A policy event does not erase the underlying C edge.  Unless an operation
 * has a precise result independently of its input (Drop and
 * ConsumeIfPresent), an unproved input or a violated precondition havocs the
 * token fact so later operations cannot reuse it. */
constexpr TokenTransition applyTokenOperation(TokenState Before,
                                              TokenOperation Operation) {
  switch (Operation) {
  case TokenOperation::Require:
    if (Before == TokenState::Unknown)
      return {Before, TokenState::Unknown, TokenEvent::StateUnproven,
              TokenEffect::None};
    return Before == TokenState::Absent
               ? TokenTransition{Before, TokenState::Unknown,
                                 TokenEvent::MissingRequired, TokenEffect::None}
               : TokenTransition{Before, Before, TokenEvent::None,
                                 TokenEffect::None};
  case TokenOperation::RequireAbsent:
    if (Before == TokenState::Unknown)
      return {Before, TokenState::Unknown, TokenEvent::StateUnproven,
              TokenEffect::None};
    return Before == TokenState::Absent
               ? TokenTransition{Before, Before, TokenEvent::None,
                                 TokenEffect::None}
               : TokenTransition{Before, TokenState::Unknown,
                                 TokenEvent::PresentWhenAbsentRequired,
                                 TokenEffect::None};
  case TokenOperation::Consume:
    if (Before == TokenState::Unknown)
      return {Before, TokenState::Unknown, TokenEvent::StateUnproven,
              TokenEffect::None};
    return Before == TokenState::Absent
               ? TokenTransition{Before, TokenState::Unknown,
                                 TokenEvent::MissingRequired, TokenEffect::None}
               : TokenTransition{Before, TokenState::Absent, TokenEvent::None,
                                 TokenEffect::None};
  case TokenOperation::ConsumeIfPresent:
  case TokenOperation::Drop:
    return {Before, TokenState::Absent, TokenEvent::None, TokenEffect::None};
  case TokenOperation::GrantLinear:
    if (Before == TokenState::Unknown)
      return {Before, TokenState::Unknown, TokenEvent::StateUnproven,
              TokenEffect::None};
    return Before == TokenState::Absent
               ? TokenTransition{Before, TokenState::Linear, TokenEvent::None,
                                 TokenEffect::None}
               : TokenTransition{Before, TokenState::Unknown,
                                 TokenEvent::LinearDuplication,
                                 TokenEffect::None};
  case TokenOperation::GrantDuplicable:
    if (Before == TokenState::Unknown)
      return {Before, TokenState::Unknown, TokenEvent::StateUnproven,
              TokenEffect::None};
    if (Before == TokenState::Absent)
      return {Before, TokenState::Duplicable, TokenEvent::None,
              TokenEffect::None};
    if (Before == TokenState::Duplicable)
      return {Before, Before, TokenEvent::None, TokenEffect::None};
    return {Before, TokenState::Unknown, TokenEvent::DuplicationClassMismatch,
            TokenEffect::None};
  }
  return {Before, TokenState::Unknown, TokenEvent::StateUnproven,
          TokenEffect::None};
}

enum class LinearLoanClass : uint8_t { Permissive, Strict };

struct TokenTransferPolicy {
  LinearLoanClass Loans;
  bool DestinationDroppable;
};

struct TokenTransfer {
  TokenState SourceBefore;
  TokenState DestinationBefore;
  TokenState SourceAfter;
  TokenState DestinationAfter;
  TokenEvent Events;
  TokenEffect Effects;

  constexpr bool permitted() const { return Events == TokenEvent::None; }
};

/* Assignment copies duplicable authority and moves linear authority.  A
 * strict linear move also asks the path-state adapter to expire every loan
 * rooted in the old carrier.  An occupied destination may be replaced only
 * when its nominal sort is explicitly droppable.  Otherwise equal classes
 * report occupation, while unequal classes also report the contradictory
 * multiplicity. */
constexpr TokenTransfer transferToken(TokenState Source, TokenState Destination,
                                      TokenTransferPolicy Policy) {
  if (Source == TokenState::Unknown || Destination == TokenState::Unknown)
    return {Source,
            Destination,
            TokenState::Unknown,
            TokenState::Unknown,
            TokenEvent::StateUnproven,
            TokenEffect::None};
  TokenEvent Events = TokenEvent::None;
  if (Source == TokenState::Absent)
    Events = Events | TokenEvent::MissingRequired;
  if (Destination != TokenState::Absent && !Policy.DestinationDroppable)
    Events = Events | TokenEvent::DestinationOccupied;
  if (Source != TokenState::Absent && Destination != TokenState::Absent &&
      Source != Destination)
    Events = Events | TokenEvent::DuplicationClassMismatch;
  if (Events != TokenEvent::None)
    return {Source, Destination,      TokenState::Unknown, TokenState::Unknown,
            Events, TokenEffect::None};
  if (Source == TokenState::Duplicable)
    return {Source,           Destination,      Source, TokenState::Duplicable,
            TokenEvent::None, TokenEffect::None};
  TokenEffect Effects = Policy.Loans == LinearLoanClass::Strict
                            ? TokenEffect::InvalidateStrictLoans
                            : TokenEffect::None;
  return {Source,           Destination, TokenState::Absent, TokenState::Linear,
          TokenEvent::None, Effects};
}

/* A token sort is nominal: its typedef declaration, not the spelling of its
 * name or of an unrelated annotation, supplies the policy qualifiers. */
using TokenSort = clang::TypedefNameDecl;

inline const TokenSort *findTokenSort(clang::ASTContext &Context,
                                      llvm::StringRef Name) {
  clang::IdentifierInfo &Identifier = Context.Idents.get(Name);
  clang::DeclarationName Declaration(&Identifier);
  for (clang::NamedDecl *Candidate :
       Context.getTranslationUnitDecl()->lookup(Declaration))
    if (const auto *Token = llvm::dyn_cast<TokenSort>(Candidate))
      return Token;
  return nullptr;
}

inline bool hasQualifier(const TokenSort *Token, llvm::StringRef Qualifier) {
  if (!Token)
    return false;
  for (const clang::AnnotateAttr *Attribute :
       Token->specific_attrs<clang::AnnotateAttr>())
    if (Attribute->getAnnotation() == Qualifier)
      return true;
  return false;
}

enum class TokenImplementationStatus : uint8_t {
  Missing,
  Valid,
  Malformed,
  UnknownFamily,
  Conflicting,
  Self,
  Cyclic,
  Unsupported,
};

struct TokenImplementation {
  TokenImplementationStatus Status;
  const TokenSort *External;
  const TokenSort *Internal;

  bool valid() const { return Status == TokenImplementationStatus::Valid; }
};

struct RawTokenImplementation {
  TokenImplementationStatus Status;
  llvm::StringRef Name;
};

inline bool isTokenSortName(llvm::StringRef Name) {
  if (Name.empty() ||
      !(std::isalpha(static_cast<unsigned char>(Name.front())) ||
        Name.front() == '_'))
    return false;
  for (char Character : Name.drop_front())
    if (!(std::isalnum(static_cast<unsigned char>(Character)) ||
          Character == '_'))
      return false;
  return true;
}

inline RawTokenImplementation
rawTokenImplementation(const TokenSort *External) {
  if (!External)
    return {TokenImplementationStatus::Missing, {}};
  constexpr llvm::StringRef Prefix = "qual:implemented_by=";
  llvm::StringRef Selected;
  for (const clang::AnnotateAttr *Attribute :
       External->specific_attrs<clang::AnnotateAttr>()) {
    llvm::StringRef Text = Attribute->getAnnotation();
    if (!Text.consume_front(Prefix))
      continue;
    if (!isTokenSortName(Text))
      return {TokenImplementationStatus::Malformed, {}};
    if (!Selected.empty() && Selected != Text)
      return {TokenImplementationStatus::Conflicting, {}};
    Selected = Text;
  }
  return Selected.empty()
             ? RawTokenImplementation{TokenImplementationStatus::Missing, {}}
             : RawTokenImplementation{TokenImplementationStatus::Valid,
                                      Selected};
}

/* Resolve an exact, one-edge nominal implementation permission.  A mapping is
 * not an equivalence: it is consumed only by lifecycle producer/freer
 * boundaries, and the returned Internal is always the directly declared
 * target.  The visible graph may contain further acyclic edges because real
 * implementations have nested boundaries (public allocator -> platform
 * allocator -> kernel allocator), but an adapter must cross those edges in
 * separate boundary transitions.  Validate the whole reachable graph here so
 * a malformed tail, unknown sort, unsupported sort, or cycle cannot make an
 * otherwise plausible prefix usable. */
inline TokenImplementation tokenImplementation(clang::ASTContext &Context,
                                               const TokenSort *External) {
  RawTokenImplementation Raw = rawTokenImplementation(External);
  if (Raw.Status != TokenImplementationStatus::Valid)
    return {Raw.Status, External, nullptr};
  const TokenSort *Internal = findTokenSort(Context, Raw.Name);
  if (!Internal)
    return {TokenImplementationStatus::UnknownFamily, External, nullptr};
  if (Internal == External)
    return {TokenImplementationStatus::Self, External, Internal};
  if (!hasQualifier(External, "qual:dynamic_storage") ||
      !hasQualifier(Internal, "qual:dynamic_storage"))
    return {TokenImplementationStatus::Unsupported, External, Internal};

  llvm::SmallPtrSet<const TokenSort *, 8> Seen;
  const TokenSort *Current = External;
  for (;;) {
    if (!Seen.insert(Current).second)
      return {TokenImplementationStatus::Cyclic, External, Internal};
    RawTokenImplementation NextRaw = rawTokenImplementation(Current);
    if (NextRaw.Status == TokenImplementationStatus::Missing)
      break;
    if (NextRaw.Status != TokenImplementationStatus::Valid)
      return {NextRaw.Status, External, Internal};
    const TokenSort *Next = findTokenSort(Context, NextRaw.Name);
    if (!Next)
      return {TokenImplementationStatus::UnknownFamily, External, Internal};
    if (!hasQualifier(Current, "qual:dynamic_storage") ||
        !hasQualifier(Next, "qual:dynamic_storage"))
      return {TokenImplementationStatus::Unsupported, External, Internal};
    Current = Next;
  }
  return {TokenImplementationStatus::Valid, External, Internal};
}

inline std::optional<int64_t> excludedSentinel(const TokenSort *Token) {
  if (!Token)
    return std::nullopt;
  constexpr llvm::StringRef Prefix = "qual:sentinel_exclude=";
  for (const clang::AnnotateAttr *Attribute :
       Token->specific_attrs<clang::AnnotateAttr>()) {
    llvm::StringRef Text = Attribute->getAnnotation();
    if (!Text.consume_front(Prefix))
      continue;
    if (Text == "NULL")
      return 0;
    int64_t Value = 0;
    if (!Text.getAsInteger(10, Value))
      return Value;
  }
  return std::nullopt;
}

/* The two halves of testing whether a symbolic Value is Token's declared
 * sentinel_exclude value: Sentinel is the state where it is, NonSentinel is
 * the state where it provably is not. Either half may be null if that
 * branch is infeasible under State's existing constraints. Callers that
 * only care about the "not the sentinel" continuation (the common case for
 * a value already known to hold real ownership) use NonSentinel alone and
 * discard Sentinel. */
struct SentinelSplit {
  clang::ento::ProgramStateRef Sentinel;
  clang::ento::ProgramStateRef NonSentinel;
};

/* Splits State on whether Value equals Sentinel, the constant a caller has
 * already read from excludedSentinel(Token). Type must be Value's real
 * expression type: SValBuilder::makeIntVal(uint64_t, QualType) dispatches
 * on it to build either a NonLoc integer or a Loc pointer constant, so for
 * a pointer-typed token (for example iconv_t's (iconv_t)-1) this ends up
 * comparing two pointer values, the same technique the analyzer's own
 * MAP_FAILED-style checks use, rather than an integer comparison that could
 * never be true for a symbolic pointer. */
inline SentinelSplit splitOnExcludedSentinel(
    clang::ento::ProgramStateRef State, clang::ento::DefinedOrUnknownSVal Value,
    clang::QualType Type, int64_t Sentinel, clang::ento::SValBuilder &SVB) {
  clang::ento::DefinedSVal SentinelValue =
      SVB.makeIntVal(static_cast<uint64_t>(Sentinel), Type);
  clang::ento::DefinedOrUnknownSVal IsSentinel =
      SVB.evalEQ(State, Value, SentinelValue);
  auto [SentinelState, NonSentinelState] = State->assume(IsSentinel);
  return {SentinelState, NonSentinelState};
}

} // namespace ntlibc::algebra

#endif
