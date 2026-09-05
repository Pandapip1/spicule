// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "LifecycleAlgebra.h"

#include <cstdio>

using namespace ntlibc::algebra;

static bool test(bool Condition, const char *Message) {
  if (!Condition)
    std::fprintf(stderr, "lifecycle-algebra-test: %s\n", Message);
  return Condition;
}

struct ExpectedTransition {
  LifecycleFact After;
  LifecycleEvent Events;
};

static bool testOperationTable() {
  constexpr LifecycleFamilyId Family{1};
  constexpr LifecycleFact States[] = {unknownLifecycle(), absentLifecycle(),
                                      liveLifecycle(Family),
                                      releasedLifecycle(Family)};
  constexpr LifecycleOperation Operations[] = {LifecycleOperation::Acquire,
                                               LifecycleOperation::RequireLive,
                                               LifecycleOperation::Release};
  constexpr ExpectedTransition Expected[][4] = {
      {{liveLifecycle(Family), LifecycleEvent::StateUnproven},
       {liveLifecycle(Family), LifecycleEvent::None},
       {liveLifecycle(Family), LifecycleEvent::AlreadyLive},
       {liveLifecycle(Family), LifecycleEvent::None}},
      {{unknownLifecycle(), LifecycleEvent::StateUnproven},
       {absentLifecycle(), LifecycleEvent::MissingLive},
       {liveLifecycle(Family), LifecycleEvent::None},
       {releasedLifecycle(Family), LifecycleEvent::AlreadyReleased}},
      {{unknownLifecycle(), LifecycleEvent::StateUnproven},
       {unknownLifecycle(), LifecycleEvent::MissingLive},
       {releasedLifecycle(Family), LifecycleEvent::None},
       {unknownLifecycle(), LifecycleEvent::AlreadyReleased}},
  };
  bool Passed = true;
  for (unsigned Operation = 0; Operation < 3; ++Operation)
    for (unsigned State = 0; State < 4; ++State) {
      LifecycleTransition Result =
          applyLifecycleOperation(States[State], Family, Operations[Operation]);
      bool Cell = Result.Before == States[State] &&
                  Result.After == Expected[Operation][State].After &&
                  Result.Events == Expected[Operation][State].Events &&
                  Result.permitted() == (Expected[Operation][State].Events ==
                                         LifecycleEvent::None);
      if (!Cell)
        std::fprintf(stderr,
                     "lifecycle-algebra-test: operation cell op=%u state=%u\n",
                     Operation, State);
      Passed &= Cell;
    }
  return Passed;
}

static bool testFamilyAndMalformedFacts() {
  constexpr LifecycleFamilyId Expected{1};
  constexpr LifecycleFamilyId Other{2};
  constexpr LifecycleEvent ReleasedMismatch =
      LifecycleEvent::AlreadyReleased | LifecycleEvent::FamilyMismatch;
  bool Passed = true;

  LifecycleTransition AcquireLive = applyLifecycleOperation(
      liveLifecycle(Other), Expected, LifecycleOperation::Acquire);
  Passed &= test(AcquireLive.After == liveLifecycle(Expected) &&
                     AcquireLive.Events == (LifecycleEvent::AlreadyLive |
                                            LifecycleEvent::FamilyMismatch),
                 "acquire did not replace mismatched live generation");
  LifecycleTransition AcquireReleased = applyLifecycleOperation(
      releasedLifecycle(Other), Expected, LifecycleOperation::Acquire);
  Passed &= test(AcquireReleased.After == liveLifecycle(Expected) &&
                     AcquireReleased.Events == LifecycleEvent::None,
                 "acquire did not admit a new family after release");

  LifecycleTransition RequireLive = applyLifecycleOperation(
      liveLifecycle(Other), Expected, LifecycleOperation::RequireLive);
  Passed &= test(RequireLive.After == liveLifecycle(Other) &&
                     RequireLive.Events == LifecycleEvent::FamilyMismatch,
                 "require did not preserve mismatched live fact");
  LifecycleTransition RequireReleased = applyLifecycleOperation(
      releasedLifecycle(Other), Expected, LifecycleOperation::RequireLive);
  Passed &= test(RequireReleased.After == releasedLifecycle(Other) &&
                     RequireReleased.Events == ReleasedMismatch,
                 "require did not preserve released mismatched fact");

  LifecycleTransition ReleaseLive = applyLifecycleOperation(
      liveLifecycle(Other), Expected, LifecycleOperation::Release);
  Passed &= test(ReleaseLive.After == unknownLifecycle() &&
                     ReleaseLive.Events == LifecycleEvent::FamilyMismatch,
                 "mismatched release did not havoc");
  LifecycleTransition ReleaseReleased = applyLifecycleOperation(
      releasedLifecycle(Other), Expected, LifecycleOperation::Release);
  Passed &= test(ReleaseReleased.After == unknownLifecycle() &&
                     ReleaseReleased.Events == ReleasedMismatch,
                 "mismatched double release did not havoc");

  constexpr LifecycleFact MalformedAbsent{LifecycleState::Absent, Expected};
  constexpr LifecycleFact MalformedLive{LifecycleState::Live,
                                        NoLifecycleFamily};
  constexpr LifecycleFact MalformedFacts[] = {MalformedAbsent, MalformedLive};
  for (LifecycleFact Malformed : MalformedFacts) {
    LifecycleTransition Require = applyLifecycleOperation(
        Malformed, Expected, LifecycleOperation::RequireLive);
    Passed &= test(Require.After == Malformed &&
                       Require.Events == LifecycleEvent::StateUnproven,
                   "observational require changed malformed fact");
    LifecycleTransition Acquire = applyLifecycleOperation(
        Malformed, Expected, LifecycleOperation::Acquire);
    Passed &= test(Acquire.After == liveLifecycle(Expected) &&
                       Acquire.Events == LifecycleEvent::StateUnproven,
                   "successful acquire did not replace malformed fact");
    LifecycleTransition Release = applyLifecycleOperation(
        Malformed, Expected, LifecycleOperation::Release);
    Passed &= test(Release.After == unknownLifecycle() &&
                       Release.Events == LifecycleEvent::StateUnproven,
                   "release accepted malformed fact");
  }
  LifecycleTransition MissingFamily =
      applyLifecycleOperation(liveLifecycle(Expected), NoLifecycleFamily,
                              LifecycleOperation::RequireLive);
  Passed &= test(MissingFamily.After == liveLifecycle(Expected) &&
                     MissingFamily.Events == LifecycleEvent::StateUnproven,
                 "require with missing nominal family changed its fact");
  return Passed;
}

static LifecycleEvent expectedSourceEvents(LifecycleFact Source,
                                           LifecycleFamilyId Family,
                                           bool AllowAbsent) {
  switch (Source.State) {
  case LifecycleState::Unknown:
    return LifecycleEvent::StateUnproven;
  case LifecycleState::Absent:
    return AllowAbsent ? LifecycleEvent::None : LifecycleEvent::MissingLive;
  case LifecycleState::Live:
    return Source.Family == Family ? LifecycleEvent::None
                                   : LifecycleEvent::FamilyMismatch;
  case LifecycleState::Released:
    return Source.Family == Family ? LifecycleEvent::AlreadyReleased
                                   : LifecycleEvent::AlreadyReleased |
                                         LifecycleEvent::FamilyMismatch;
  }
  return LifecycleEvent::StateUnproven;
}

static bool testReplacementTable() {
  constexpr LifecycleFamilyId Family{1};
  constexpr LifecycleFamilyId Other{2};
  constexpr LifecycleFact States[] = {
      unknownLifecycle(),    absentLifecycle(),
      liveLifecycle(Family), releasedLifecycle(Family),
      liveLifecycle(Other),  releasedLifecycle(Other)};
  constexpr LifecycleEvent AcquireEvents[] = {
      LifecycleEvent::StateUnproven,
      LifecycleEvent::None,
      LifecycleEvent::AlreadyLive,
      LifecycleEvent::None,
      LifecycleEvent::AlreadyLive | LifecycleEvent::FamilyMismatch,
      LifecycleEvent::None};
  bool Passed = true;
  for (unsigned Outcome = 0; Outcome < 2; ++Outcome)
    for (unsigned AllowAbsent = 0; AllowAbsent < 2; ++AllowAbsent)
      for (unsigned SourceIndex = 0; SourceIndex < 6; ++SourceIndex)
        for (unsigned ResultIndex = 0; ResultIndex < 6; ++ResultIndex) {
          LifecycleFact Source = States[SourceIndex];
          LifecycleFact Result = States[ResultIndex];
          ReplacementOutcome Selected = Outcome == 0
                                            ? ReplacementOutcome::Failed
                                            : ReplacementOutcome::Succeeded;
          LifecycleReplacement Transition = replaceLifecycle(
              Source, Result, Selected, {Family, AllowAbsent != 0});
          LifecycleEvent SourceEvents =
              expectedSourceEvents(Source, Family, AllowAbsent != 0);
          LifecycleFact ExpectedSource = Source;
          LifecycleFact ExpectedResult = Result;
          LifecycleEvent ExpectedEvents = SourceEvents;
          if (Selected == ReplacementOutcome::Succeeded) {
            ExpectedResult = liveLifecycle(Family);
            ExpectedEvents = ExpectedEvents | AcquireEvents[ResultIndex];
            if (SourceEvents == LifecycleEvent::None) {
              if (Source.State == LifecycleState::Live)
                ExpectedSource = releasedLifecycle(Family);
              else if (Source.State == LifecycleState::Absent && AllowAbsent)
                ExpectedSource = absentLifecycle();
              else
                ExpectedSource = unknownLifecycle();
            } else {
              ExpectedSource = unknownLifecycle();
            }
          }
          bool Cell = Transition.SourceBefore == Source &&
                      Transition.ResultBefore == Result &&
                      Transition.SourceAfter == ExpectedSource &&
                      Transition.ResultAfter == ExpectedResult &&
                      Transition.Events == ExpectedEvents &&
                      Transition.permitted() ==
                          (ExpectedEvents == LifecycleEvent::None);
          if (!Cell)
            std::fprintf(stderr,
                         "lifecycle-algebra-test: replacement cell outcome=%u "
                         "allow=%u source=%u result=%u\n",
                         Outcome, AllowAbsent, SourceIndex, ResultIndex);
          Passed &= Cell;
        }

  LifecycleReplacement FailedMismatch =
      replaceLifecycle(liveLifecycle(Other), releasedLifecycle(Other),
                       ReplacementOutcome::Failed, {Family, false});
  Passed &= test(FailedMismatch.SourceAfter == liveLifecycle(Other) &&
                     FailedMismatch.ResultAfter == releasedLifecycle(Other) &&
                     FailedMismatch.Events == LifecycleEvent::FamilyMismatch,
                 "failed replacement did not preserve both exact facts");
  LifecycleReplacement SucceededMismatch =
      replaceLifecycle(releasedLifecycle(Other), liveLifecycle(Other),
                       ReplacementOutcome::Succeeded, {Family, false});
  constexpr LifecycleEvent AllMismatch = LifecycleEvent::AlreadyReleased |
                                         LifecycleEvent::FamilyMismatch |
                                         LifecycleEvent::AlreadyLive;
  Passed &= test(SucceededMismatch.SourceAfter == unknownLifecycle() &&
                     SucceededMismatch.ResultAfter == liveLifecycle(Family) &&
                     SucceededMismatch.Events == AllMismatch,
                 "successful invalid replacement lost events or result");

  constexpr LifecycleFact Malformed{LifecycleState::Live, NoLifecycleFamily};
  LifecycleReplacement FailedMalformed = replaceLifecycle(
      Malformed, Malformed, ReplacementOutcome::Failed, {Family, false});
  Passed &= test(FailedMalformed.SourceAfter == Malformed &&
                     FailedMalformed.ResultAfter == Malformed &&
                     FailedMalformed.Events == LifecycleEvent::StateUnproven,
                 "failed replacement did not preserve malformed facts");
  LifecycleReplacement SucceededMalformed =
      replaceLifecycle(liveLifecycle(Family), Malformed,
                       ReplacementOutcome::Succeeded, {Family, false});
  Passed &= test(SucceededMalformed.SourceAfter == releasedLifecycle(Family) &&
                     SucceededMalformed.ResultAfter == liveLifecycle(Family) &&
                     SucceededMalformed.Events == LifecycleEvent::StateUnproven,
                 "successful replacement did not establish its result");
  LifecycleReplacement MissingFamily = replaceLifecycle(
      liveLifecycle(Family), absentLifecycle(), ReplacementOutcome::Succeeded,
      {NoLifecycleFamily, false});
  Passed &= test(MissingFamily.SourceAfter == unknownLifecycle() &&
                     MissingFamily.ResultAfter == unknownLifecycle() &&
                     MissingFamily.Events == LifecycleEvent::StateUnproven,
                 "replacement accepted a missing nominal family");
  return Passed;
}

static bool testMorphismTables() {
  constexpr LifecycleFamilyId External{1};
  constexpr LifecycleFamilyId Internal{2};
  constexpr LifecycleFamilyId Other{3};
  constexpr LifecycleFamilyMorphism Morphism{External, Internal};
  constexpr LifecycleFact States[] = {
      unknownLifecycle(),      absentLifecycle(),
      liveLifecycle(External), releasedLifecycle(External),
      liveLifecycle(Internal), releasedLifecycle(Internal)};
  constexpr LifecycleEvent RetagInputEvents[] = {
      LifecycleEvent::StateUnproven,
      LifecycleEvent::MissingLive,
      LifecycleEvent::FamilyMismatch | LifecycleEvent::MorphismMismatch,
      LifecycleEvent::AlreadyReleased | LifecycleEvent::FamilyMismatch |
          LifecycleEvent::MorphismMismatch,
      LifecycleEvent::None,
      LifecycleEvent::AlreadyReleased};
  constexpr LifecycleEvent DischargeInputEvents[] = {
      LifecycleEvent::StateUnproven,
      LifecycleEvent::MissingLive,
      LifecycleEvent::None,
      LifecycleEvent::AlreadyReleased,
      LifecycleEvent::FamilyMismatch | LifecycleEvent::MorphismMismatch,
      LifecycleEvent::AlreadyReleased | LifecycleEvent::FamilyMismatch |
          LifecycleEvent::MorphismMismatch};
  bool Passed = true;
  for (unsigned WrongTarget = 0; WrongTarget < 2; ++WrongTarget)
    for (unsigned State = 0; State < 6; ++State) {
      LifecycleFamilyId Target = WrongTarget ? Other : External;
      LifecycleMorphismTransition Result =
          retagLifecycle(States[State], Target, Morphism);
      LifecycleEvent Events = RetagInputEvents[State];
      if (WrongTarget)
        Events = Events | LifecycleEvent::MorphismMismatch;
      LifecycleFact After = Events == LifecycleEvent::None
                                ? liveLifecycle(External)
                                : unknownLifecycle();
      bool Cell = Result.Before == States[State] && Result.After == After &&
                  Result.Morphism.External == External &&
                  Result.Morphism.Internal == Internal &&
                  Result.Events == Events &&
                  Result.permitted() == (Events == LifecycleEvent::None);
      if (!Cell)
        std::fprintf(stderr,
                     "lifecycle-algebra-test: retag cell target=%u state=%u\n",
                     WrongTarget, State);
      Passed &= Cell;
    }

  for (unsigned WrongRelease = 0; WrongRelease < 2; ++WrongRelease)
    for (unsigned State = 0; State < 6; ++State) {
      LifecycleFamilyId Release = WrongRelease ? Other : Internal;
      LifecycleMorphismTransition Result =
          dischargeLifecycle(States[State], Release, Morphism);
      LifecycleEvent Events = DischargeInputEvents[State];
      if (WrongRelease)
        Events = Events | LifecycleEvent::MorphismMismatch;
      LifecycleFact After = Events == LifecycleEvent::None
                                ? releasedLifecycle(External)
                                : unknownLifecycle();
      bool Cell = Result.Before == States[State] && Result.After == After &&
                  Result.Morphism.External == External &&
                  Result.Morphism.Internal == Internal &&
                  Result.Events == Events &&
                  Result.permitted() == (Events == LifecycleEvent::None);
      if (!Cell)
        std::fprintf(
            stderr,
            "lifecycle-algebra-test: discharge cell release=%u state=%u\n",
            WrongRelease, State);
      Passed &= Cell;
    }

  constexpr LifecycleFamilyMorphism MissingExternal{NoLifecycleFamily,
                                                    Internal};
  constexpr LifecycleFamilyMorphism MissingInternal{External,
                                                    NoLifecycleFamily};
  constexpr LifecycleFamilyMorphism MissingMorphisms[] = {MissingExternal,
                                                          MissingInternal};
  for (LifecycleFamilyMorphism Missing : MissingMorphisms) {
    LifecycleMorphismTransition Retag =
        retagLifecycle(liveLifecycle(Internal), External, Missing);
    Passed &= test(Retag.After == unknownLifecycle() &&
                       Retag.Events == LifecycleEvent::MorphismMissing,
                   "retag accepted an incomplete morphism");
    LifecycleMorphismTransition Discharge =
        dischargeLifecycle(liveLifecycle(External), Internal, Missing);
    Passed &= test(Discharge.After == unknownLifecycle() &&
                       Discharge.Events == LifecycleEvent::MorphismMissing,
                   "discharge accepted an incomplete morphism");
  }
  constexpr LifecycleFamilyMorphism Reversed{Internal, External};
  LifecycleMorphismTransition ReversedRetag =
      retagLifecycle(liveLifecycle(Internal), External, Reversed);
  Passed &=
      test(ReversedRetag.After == unknownLifecycle() &&
               contains(ReversedRetag.Events, LifecycleEvent::MorphismMismatch),
           "retag accepted a reversed morphism");
  LifecycleMorphismTransition ReversedDischarge =
      dischargeLifecycle(liveLifecycle(External), Internal, Reversed);
  Passed &= test(
      ReversedDischarge.After == unknownLifecycle() &&
          contains(ReversedDischarge.Events, LifecycleEvent::MorphismMismatch),
      "discharge accepted a reversed morphism");

  /* A contract graph may be A -> B -> C, but each boundary transition is
   * still exactly one edge.  Sequential producer and consumer boundaries
   * succeed; attempting to collapse A directly to C does not. */
  constexpr LifecycleFamilyId Outer{4};
  constexpr LifecycleFamilyId Middle{5};
  constexpr LifecycleFamilyId Backend{6};
  constexpr LifecycleFamilyMorphism OuterEdge{Outer, Middle};
  constexpr LifecycleFamilyMorphism MiddleEdge{Middle, Backend};
  LifecycleMorphismTransition ProduceMiddle =
      retagLifecycle(liveLifecycle(Backend), Middle, MiddleEdge);
  LifecycleMorphismTransition ProduceOuter =
      retagLifecycle(ProduceMiddle.After, Outer, OuterEdge);
  Passed &= test(ProduceMiddle.permitted() && ProduceOuter.permitted() &&
                     ProduceOuter.After == liveLifecycle(Outer),
                 "sequential producer edges did not compose at boundaries");
  LifecycleMorphismTransition ReleaseOuter =
      dischargeLifecycle(liveLifecycle(Outer), Middle, OuterEdge);
  LifecycleMorphismTransition ReleaseMiddle =
      dischargeLifecycle(liveLifecycle(Middle), Backend, MiddleEdge);
  Passed &= test(ReleaseOuter.permitted() && ReleaseMiddle.permitted(),
                 "sequential consumer edges did not discharge at boundaries");
  LifecycleMorphismTransition CollapsedProducer =
      retagLifecycle(liveLifecycle(Backend), Outer, OuterEdge);
  LifecycleMorphismTransition CollapsedConsumer =
      dischargeLifecycle(liveLifecycle(Outer), Backend, OuterEdge);
  Passed &= test(!CollapsedProducer.permitted() &&
                     CollapsedProducer.After == unknownLifecycle() &&
                     contains(CollapsedProducer.Events,
                              LifecycleEvent::MorphismMismatch),
                 "producer crossed two implementation edges at once");
  Passed &= test(!CollapsedConsumer.permitted() &&
                     CollapsedConsumer.After == unknownLifecycle() &&
                     contains(CollapsedConsumer.Events,
                              LifecycleEvent::MorphismMismatch),
                 "consumer crossed two implementation edges at once");
  return Passed;
}

static bool testExitTable() {
  constexpr LifecycleFamilyId Family{1};
  constexpr LifecycleFact States[] = {unknownLifecycle(), absentLifecycle(),
                                      liveLifecycle(Family),
                                      releasedLifecycle(Family)};
  constexpr LifecycleEvent Expected[] = {
      LifecycleEvent::StateUnproven, LifecycleEvent::None,
      LifecycleEvent::LiveAtScopeExit, LifecycleEvent::None};
  bool Passed = true;
  for (unsigned Index = 0; Index < 4; ++Index) {
    LifecycleObservation Observation = observeLifecycleExit(States[Index]);
    bool Cell =
        Observation.Fact == States[Index] &&
        Observation.Events == Expected[Index] &&
        Observation.permitted() == (Expected[Index] == LifecycleEvent::None);
    if (!Cell)
      std::fprintf(stderr, "lifecycle-algebra-test: exit cell state=%u\n",
                   Index);
    Passed &= Cell;
  }
  constexpr LifecycleFact Malformed{LifecycleState::Released,
                                    NoLifecycleFamily};
  LifecycleObservation Observation = observeLifecycleExit(Malformed);
  Passed &= test(Observation.Fact == Malformed &&
                     Observation.Events == LifecycleEvent::StateUnproven,
                 "scope exit accepted malformed fact");
  return Passed;
}

static bool testRequireNotLiveTable() {
  constexpr LifecycleFamilyId Family{1};
  constexpr LifecycleFact States[] = {unknownLifecycle(), absentLifecycle(),
                                      liveLifecycle(Family),
                                      releasedLifecycle(Family)};
  // Absent and Released are both "safe to destroy" -- unlike RequireLive,
  // this predicate does not distinguish "never held" from "held, then
  // released" among its passing cases; only a currently-Live fact fails.
  constexpr LifecycleEvent Expected[] = {
      LifecycleEvent::StateUnproven, LifecycleEvent::None,
      LifecycleEvent::AlreadyLive, LifecycleEvent::None};
  bool Passed = true;
  for (unsigned Index = 0; Index < 4; ++Index) {
    LifecycleObservation Observation = requireNotLive(States[Index]);
    bool Cell =
        Observation.Fact == States[Index] &&
        Observation.Events == Expected[Index] &&
        Observation.permitted() == (Expected[Index] == LifecycleEvent::None);
    if (!Cell)
      std::fprintf(stderr,
                   "lifecycle-algebra-test: require-not-live cell state=%u\n",
                   Index);
    Passed &= Cell;
  }
  constexpr LifecycleFact Malformed{LifecycleState::Live, NoLifecycleFamily};
  LifecycleObservation Observation = requireNotLive(Malformed);
  Passed &= test(Observation.Fact == Malformed &&
                     Observation.Events == LifecycleEvent::StateUnproven,
                 "require-not-live accepted malformed fact");
  return Passed;
}

int main() {
  return testOperationTable() && testFamilyAndMalformedFacts() &&
                 testReplacementTable() && testMorphismTables() &&
                 testExitTable() && testRequireNotLiveTable()
             ? 0
             : 1;
}
