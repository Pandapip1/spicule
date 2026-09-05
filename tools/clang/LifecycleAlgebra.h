// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef NTLIBC_LIFECYCLE_ALGEBRA_H
#define NTLIBC_LIFECYCLE_ALGEBRA_H

#include <cstdint>

namespace ntlibc::algebra {

/* An equality-only nominal atom.  Values have no numeric meaning; the
 * integer representation merely keeps this pure table independent of Clang
 * pointer identities and suitable for a later SMT uninterpreted-sort
 * encoding.  Zero denotes the absence of a family. */
struct LifecycleFamilyId {
  uint64_t Value;

  constexpr explicit operator bool() const { return Value != 0; }
};

constexpr bool operator==(LifecycleFamilyId Left, LifecycleFamilyId Right) {
  return Left.Value == Right.Value;
}

constexpr bool operator!=(LifecycleFamilyId Left, LifecycleFamilyId Right) {
  return !(Left == Right);
}

inline constexpr LifecycleFamilyId NoLifecycleFamily{0};

/* Unknown is abstract knowledge, not a concrete runtime phase.  Absent is a
 * proved lack of a lifecycle, while Released retains the nominal family of a
 * completed lifetime so double release and family mismatch remain visible. */
enum class LifecycleState : uint8_t { Unknown, Absent, Live, Released };

struct LifecycleFact {
  LifecycleState State;
  LifecycleFamilyId Family;
};

constexpr LifecycleFact unknownLifecycle() {
  return {LifecycleState::Unknown, NoLifecycleFamily};
}

constexpr LifecycleFact absentLifecycle() {
  return {LifecycleState::Absent, NoLifecycleFamily};
}

constexpr LifecycleFact liveLifecycle(LifecycleFamilyId Family) {
  return {LifecycleState::Live, Family};
}

constexpr LifecycleFact releasedLifecycle(LifecycleFamilyId Family) {
  return {LifecycleState::Released, Family};
}

constexpr bool operator==(LifecycleFact Left, LifecycleFact Right) {
  return Left.State == Right.State && Left.Family == Right.Family;
}

constexpr bool operator!=(LifecycleFact Left, LifecycleFact Right) {
  return !(Left == Right);
}

constexpr bool isCanonicalLifecycle(LifecycleFact Fact) {
  bool HasFamily = static_cast<bool>(Fact.Family);
  return Fact.State == LifecycleState::Live ||
                 Fact.State == LifecycleState::Released
             ? HasFamily
             : !HasFamily;
}

enum class LifecycleOperation : uint8_t { Acquire, RequireLive, Release };

/* These are policy diagnostics, not C-expression definedness events.  They
 * never remove the underlying C edge.  Scalar definedness, object identity,
 * and alias invalidation belong to the corresponding common algebra sorts
 * and path-state adapter. */
enum class LifecycleEvent : uint16_t {
  None = 0,
  StateUnproven = 1U << 0,
  MissingLive = 1U << 1,
  AlreadyLive = 1U << 2,
  AlreadyReleased = 1U << 3,
  FamilyMismatch = 1U << 4,
  LiveAtScopeExit = 1U << 5,
  MorphismMissing = 1U << 6,
  MorphismMismatch = 1U << 7,
};

constexpr LifecycleEvent operator|(LifecycleEvent Left, LifecycleEvent Right) {
  return static_cast<LifecycleEvent>(static_cast<uint16_t>(Left) |
                                     static_cast<uint16_t>(Right));
}

constexpr bool contains(LifecycleEvent Events, LifecycleEvent Event) {
  return (static_cast<uint16_t>(Events) & static_cast<uint16_t>(Event)) != 0;
}

struct LifecycleTransition {
  LifecycleFact Before;
  LifecycleFact After;
  LifecycleEvent Events;

  constexpr bool permitted() const { return Events == LifecycleEvent::None; }
};

constexpr LifecycleEvent lifecycleFamilyMismatch(LifecycleFact Fact,
                                                 LifecycleFamilyId Expected) {
  if (Fact.State != LifecycleState::Live &&
      Fact.State != LifecycleState::Released)
    return LifecycleEvent::None;
  return Fact.Family == Expected ? LifecycleEvent::None
                                 : LifecycleEvent::FamilyMismatch;
}

/* RequireLive is observational: even a violated requirement preserves the
 * exact incoming lifecycle fact.  Whether an invalid resource use has a
 * defined C successor is a separate object/pointer obligation.
 *
 * Acquire is called only on a producer's success branch.  It therefore
 * establishes a new live generation even when prior knowledge was Unknown or
 * Live, while reporting that the old lifetime may have been lost.
 *
 * Release is called only when the adapter's contract says the release
 * operation occurred.  Only a matching live fact has a precise Released
 * successor.  An invalid release havocs lifecycle knowledge; adapters must
 * not invent a guaranteed-release contract for calls whose outcome is still
 * unknown. */
constexpr LifecycleTransition
applyLifecycleOperation(LifecycleFact Before, LifecycleFamilyId Expected,
                        LifecycleOperation Operation) {
  if (!Expected) {
    LifecycleFact After = Operation == LifecycleOperation::RequireLive
                              ? Before
                              : unknownLifecycle();
    return {Before, After, LifecycleEvent::StateUnproven};
  }

  bool Canonical = isCanonicalLifecycle(Before);
  switch (Operation) {
  case LifecycleOperation::Acquire: {
    LifecycleEvent Events = LifecycleEvent::None;
    if (!Canonical || Before.State == LifecycleState::Unknown)
      Events = Events | LifecycleEvent::StateUnproven;
    else if (Before.State == LifecycleState::Live) {
      Events = Events | LifecycleEvent::AlreadyLive;
      Events = Events | lifecycleFamilyMismatch(Before, Expected);
    }
    return {Before, liveLifecycle(Expected), Events};
  }
  case LifecycleOperation::RequireLive: {
    LifecycleEvent Events = LifecycleEvent::None;
    if (!Canonical || Before.State == LifecycleState::Unknown)
      Events = Events | LifecycleEvent::StateUnproven;
    else if (Before.State == LifecycleState::Absent)
      Events = Events | LifecycleEvent::MissingLive;
    else {
      if (Before.State == LifecycleState::Released)
        Events = Events | LifecycleEvent::AlreadyReleased;
      Events = Events | lifecycleFamilyMismatch(Before, Expected);
    }
    return {Before, Before, Events};
  }
  case LifecycleOperation::Release: {
    if (!Canonical || Before.State == LifecycleState::Unknown)
      return {Before, unknownLifecycle(), LifecycleEvent::StateUnproven};
    if (Before.State == LifecycleState::Absent)
      return {Before, unknownLifecycle(), LifecycleEvent::MissingLive};
    LifecycleEvent Events = lifecycleFamilyMismatch(Before, Expected);
    if (Before.State == LifecycleState::Released)
      Events = Events | LifecycleEvent::AlreadyReleased;
    if (Events != LifecycleEvent::None)
      return {Before, unknownLifecycle(), Events};
    return {Before, releasedLifecycle(Expected), LifecycleEvent::None};
  }
  }
  return {Before, unknownLifecycle(), LifecycleEvent::StateUnproven};
}

enum class ReplacementOutcome : uint8_t { Failed, Succeeded };

struct LifecycleReplacementPolicy {
  LifecycleFamilyId Family;
  bool AllowAbsentSource;
};

struct LifecycleReplacement {
  LifecycleFact SourceBefore;
  LifecycleFact ResultBefore;
  LifecycleFact SourceAfter;
  LifecycleFact ResultAfter;
  LifecycleEvent Events;

  constexpr bool permitted() const { return Events == LifecycleEvent::None; }
};

constexpr LifecycleEvent
replacementSourceEvents(LifecycleFact Source,
                        LifecycleReplacementPolicy Policy) {
  if (!Policy.Family || !isCanonicalLifecycle(Source) ||
      Source.State == LifecycleState::Unknown)
    return LifecycleEvent::StateUnproven;
  if (Source.State == LifecycleState::Absent)
    return Policy.AllowAbsentSource ? LifecycleEvent::None
                                    : LifecycleEvent::MissingLive;
  LifecycleEvent Events = lifecycleFamilyMismatch(Source, Policy.Family);
  if (Source.State == LifecycleState::Released)
    Events = Events | LifecycleEvent::AlreadyReleased;
  return Events;
}

/* Replacement relates two lifecycle generations, not two numeric addresses:
 * a successful realloc-like operation consumes the old generation and
 * creates the result generation even when an implementation reuses the same
 * address.  A failed replacement is observational and preserves both facts
 * exactly.  Its input policy events are still reported because failure does
 * not make an invalid source argument valid. */
constexpr LifecycleReplacement
replaceLifecycle(LifecycleFact Source, LifecycleFact Result,
                 ReplacementOutcome Outcome,
                 LifecycleReplacementPolicy Policy) {
  LifecycleEvent SourceEvents = replacementSourceEvents(Source, Policy);
  if (Outcome == ReplacementOutcome::Failed)
    return {Source, Result, Source, Result, SourceEvents};

  LifecycleTransition Acquisition = applyLifecycleOperation(
      Result, Policy.Family, LifecycleOperation::Acquire);
  LifecycleFact SourceAfter = unknownLifecycle();
  if (SourceEvents == LifecycleEvent::None) {
    if (Source.State == LifecycleState::Live)
      SourceAfter = releasedLifecycle(Policy.Family);
    else if (Source.State == LifecycleState::Absent && Policy.AllowAbsentSource)
      SourceAfter = absentLifecycle();
  }
  return {Source, Result, SourceAfter, Acquisition.After,
          SourceEvents | Acquisition.Events};
}

/* A scoped morphism is an explicit permission to implement an externally
 * named lifecycle family with one internally named family.  Both atoms come
 * from contracts: for example, a widget producer may retag the live heap
 * allocation returned by malloc, and the paired widget consumer may
 * discharge its external obligation by calling the heap-family free.  It is
 * not a global family equivalence and it is not transitive. */
struct LifecycleFamilyMorphism {
  LifecycleFamilyId External;
  LifecycleFamilyId Internal;
};

constexpr bool isCanonicalLifecycleMorphism(LifecycleFamilyMorphism Morphism) {
  return static_cast<bool>(Morphism.External) &&
         static_cast<bool>(Morphism.Internal);
}

struct LifecycleMorphismTransition {
  LifecycleFact Before;
  LifecycleFact After;
  LifecycleFamilyMorphism Morphism;
  LifecycleEvent Events;

  constexpr bool permitted() const { return Events == LifecycleEvent::None; }
};

constexpr LifecycleEvent lifecycleInputEvents(LifecycleFact Before,
                                              LifecycleFamilyId Required) {
  if (!Required || !isCanonicalLifecycle(Before) ||
      Before.State == LifecycleState::Unknown)
    return LifecycleEvent::StateUnproven;
  if (Before.State == LifecycleState::Absent)
    return LifecycleEvent::MissingLive;
  LifecycleEvent Events = lifecycleFamilyMismatch(Before, Required);
  if (Before.State == LifecycleState::Released)
    Events = Events | LifecycleEvent::AlreadyReleased;
  return Events;
}

/* Retag a live internal result at an annotated producer boundary.  A missing
 * mapping, a target other than its external family, or an input other than
 * its internal family cannot justify any successor lifecycle fact. */
constexpr LifecycleMorphismTransition
retagLifecycle(LifecycleFact Before, LifecycleFamilyId TargetExternal,
               LifecycleFamilyMorphism Morphism) {
  if (!isCanonicalLifecycleMorphism(Morphism))
    return {Before, unknownLifecycle(), Morphism,
            LifecycleEvent::MorphismMissing};
  LifecycleEvent Events = lifecycleInputEvents(Before, Morphism.Internal);
  if (TargetExternal != Morphism.External)
    Events = Events | LifecycleEvent::MorphismMismatch;
  if ((Before.State == LifecycleState::Live ||
       Before.State == LifecycleState::Released) &&
      Before.Family != Morphism.Internal)
    Events = Events | LifecycleEvent::MorphismMismatch;
  if (Events != LifecycleEvent::None)
    return {Before, unknownLifecycle(), Morphism, Events};
  return {Before, liveLifecycle(Morphism.External), Morphism,
          LifecycleEvent::None};
}

/* Discharge an external obligation through the exact internal release family
 * named by the scoped morphism.  The external lifecycle remains the tracked
 * nominal fact, so a later call can still diagnose double release. */
constexpr LifecycleMorphismTransition
dischargeLifecycle(LifecycleFact Before, LifecycleFamilyId ReleaseInternal,
                   LifecycleFamilyMorphism Morphism) {
  if (!isCanonicalLifecycleMorphism(Morphism))
    return {Before, unknownLifecycle(), Morphism,
            LifecycleEvent::MorphismMissing};
  LifecycleEvent Events = lifecycleInputEvents(Before, Morphism.External);
  if (ReleaseInternal != Morphism.Internal)
    Events = Events | LifecycleEvent::MorphismMismatch;
  if ((Before.State == LifecycleState::Live ||
       Before.State == LifecycleState::Released) &&
      Before.Family != Morphism.External)
    Events = Events | LifecycleEvent::MorphismMismatch;
  if (Events != LifecycleEvent::None)
    return {Before, unknownLifecycle(), Morphism, Events};
  return {Before, releasedLifecycle(Morphism.External), Morphism,
          LifecycleEvent::None};
}

struct LifecycleObservation {
  LifecycleFact Fact;
  LifecycleEvent Events;

  constexpr bool permitted() const { return Events == LifecycleEvent::None; }
};

/* The adapter calls this only for a lifecycle it is responsible for
 * discharging.  Allocation origin/frame/freer metadata determines the final
 * diagnostic wording; constructs and borrowed resources need not call it. */
constexpr LifecycleObservation observeLifecycleExit(LifecycleFact Fact) {
  if (!isCanonicalLifecycle(Fact) || Fact.State == LifecycleState::Unknown)
    return {Fact, LifecycleEvent::StateUnproven};
  if (Fact.State == LifecycleState::Live)
    return {Fact, LifecycleEvent::LiveAtScopeExit};
  return {Fact, LifecycleEvent::None};
}

/* The photographic negative of RequireLive: proves a resource is safe to
 * destroy or discard because nothing currently holds it live.  Absent and
 * Released both already mean "not currently held", so -- unlike
 * RequireLive, which treats Absent and Released as two distinct failure
 * modes (MissingLive vs AlreadyReleased) -- this reports only the one
 * failure mode a destroy-while-held operation actually has.  Purely
 * observational, like RequireLive: the fact is never mutated, since a
 * caller that ignores the reported violation and destroys anyway leaves
 * lifecycle knowledge exactly as uncertain as it already was. */
constexpr LifecycleObservation requireNotLive(LifecycleFact Fact) {
  if (!isCanonicalLifecycle(Fact) || Fact.State == LifecycleState::Unknown)
    return {Fact, LifecycleEvent::StateUnproven};
  if (Fact.State == LifecycleState::Live)
    return {Fact, LifecycleEvent::AlreadyLive};
  return {Fact, LifecycleEvent::None};
}

/* Adapter mapping assumptions:
 * - ConstructMap Live/Destroyed becomes Live/Released keyed by MemRegion.
 * - ResourceMap's encoded family/liveness becomes a fact keyed by SymbolRef.
 * - AllocationFamily presence is Live; ownership transfer or a proved free
 *   makes it Absent, while origin/frame/freer/replacement remain metadata.
 * - OwnershipMap Owned/Consumed is Live/Released, with pointer definedness
 *   and pointee extent tracked by the object algebra rather than this table.
 */

} // namespace ntlibc::algebra

#endif
