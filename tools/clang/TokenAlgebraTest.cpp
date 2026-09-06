// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "TokenAlgebra.h"

#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"

#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <string>
#include <vector>

using namespace ntlibc::algebra;

static bool require(bool Condition, const char *Message) {
  if (!Condition)
    std::fprintf(stderr, "token-algebra-test: %s\n", Message);
  return Condition;
}

struct ExpectedTransition {
  TokenState After;
  TokenEvent Events;
};

static bool testTransitionTable() {
  constexpr TokenState States[] = {TokenState::Unknown, TokenState::Absent,
                                   TokenState::Linear, TokenState::Duplicable};
  constexpr TokenOperation Operations[] = {
      TokenOperation::Require,
      TokenOperation::RequireAbsent,
      TokenOperation::Consume,
      TokenOperation::ConsumeIfPresent,
      TokenOperation::Drop,
      TokenOperation::GrantLinear,
      TokenOperation::GrantDuplicable,
  };
  constexpr ExpectedTransition Expected[][4] = {
      {{TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Unknown, TokenEvent::MissingRequired},
       {TokenState::Linear, TokenEvent::None},
       {TokenState::Duplicable, TokenEvent::None}},
      {{TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Absent, TokenEvent::None},
       {TokenState::Unknown, TokenEvent::PresentWhenAbsentRequired},
       {TokenState::Unknown, TokenEvent::PresentWhenAbsentRequired}},
      {{TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Unknown, TokenEvent::MissingRequired},
       {TokenState::Absent, TokenEvent::None},
       {TokenState::Absent, TokenEvent::None}},
      {{TokenState::Absent, TokenEvent::None},
       {TokenState::Absent, TokenEvent::None},
       {TokenState::Absent, TokenEvent::None},
       {TokenState::Absent, TokenEvent::None}},
      {{TokenState::Absent, TokenEvent::None},
       {TokenState::Absent, TokenEvent::None},
       {TokenState::Absent, TokenEvent::None},
       {TokenState::Absent, TokenEvent::None}},
      {{TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Linear, TokenEvent::None},
       {TokenState::Unknown, TokenEvent::LinearDuplication},
       {TokenState::Unknown, TokenEvent::LinearDuplication}},
      {{TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Duplicable, TokenEvent::None},
       {TokenState::Unknown, TokenEvent::DuplicationClassMismatch},
       {TokenState::Duplicable, TokenEvent::None}},
  };
  bool Passed = true;
  for (unsigned Operation = 0; Operation < 7; ++Operation)
    for (unsigned State = 0; State < 4; ++State) {
      TokenTransition Result =
          applyTokenOperation(States[State], Operations[Operation]);
      bool Cell = Result.Before == States[State] &&
                  Result.After == Expected[Operation][State].After &&
                  Result.Events == Expected[Operation][State].Events &&
                  Result.Effects == TokenEffect::None &&
                  Result.permitted() ==
                      (Expected[Operation][State].Events == TokenEvent::None);
      if (!Cell)
        std::fprintf(stderr,
                     "token-algebra-test: transition cell op=%u state=%u\n",
                     Operation, State);
      Passed &= Cell;
    }
  return Passed;
}

struct ExpectedTransfer {
  TokenState SourceAfter;
  TokenState DestinationAfter;
  TokenEvent Events;
};

static bool testTransferTable() {
  constexpr TokenState States[] = {TokenState::Unknown, TokenState::Absent,
                                   TokenState::Linear, TokenState::Duplicable};
  constexpr TokenEvent MissingOccupied =
      TokenEvent::MissingRequired | TokenEvent::DestinationOccupied;
  constexpr TokenEvent OccupiedMismatch =
      TokenEvent::DestinationOccupied | TokenEvent::DuplicationClassMismatch;
  constexpr ExpectedTransfer Expected[4][4] = {
      {{TokenState::Unknown, TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Unknown, TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Unknown, TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Unknown, TokenState::Unknown, TokenEvent::StateUnproven}},
      {{TokenState::Unknown, TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Unknown, TokenState::Unknown, TokenEvent::MissingRequired},
       {TokenState::Unknown, TokenState::Unknown, MissingOccupied},
       {TokenState::Unknown, TokenState::Unknown, MissingOccupied}},
      {{TokenState::Unknown, TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Absent, TokenState::Linear, TokenEvent::None},
       {TokenState::Unknown, TokenState::Unknown,
        TokenEvent::DestinationOccupied},
       {TokenState::Unknown, TokenState::Unknown, OccupiedMismatch}},
      {{TokenState::Unknown, TokenState::Unknown, TokenEvent::StateUnproven},
       {TokenState::Duplicable, TokenState::Duplicable, TokenEvent::None},
       {TokenState::Unknown, TokenState::Unknown, OccupiedMismatch},
       {TokenState::Unknown, TokenState::Unknown,
        TokenEvent::DestinationOccupied}},
  };
  constexpr LinearLoanClass Loans[] = {LinearLoanClass::Permissive,
                                       LinearLoanClass::Strict};
  bool Passed = true;
  for (unsigned Loan = 0; Loan < 2; ++Loan)
    for (unsigned Droppable = 0; Droppable < 2; ++Droppable)
      for (unsigned Source = 0; Source < 4; ++Source)
        for (unsigned Destination = 0; Destination < 4; ++Destination) {
          TokenTransfer Result =
              transferToken(States[Source], States[Destination],
                            {Loans[Loan], Droppable != 0});
          ExpectedTransfer Cell = Expected[Source][Destination];
          if (Droppable && Source != 0 && Destination > 1) {
            if (Source == 1)
              Cell = {TokenState::Unknown, TokenState::Unknown,
                      TokenEvent::MissingRequired};
            else if (Source != Destination)
              Cell = {TokenState::Unknown, TokenState::Unknown,
                      TokenEvent::DuplicationClassMismatch};
            else if (Source == 2)
              Cell = {TokenState::Absent, TokenState::Linear, TokenEvent::None};
            else
              Cell = {TokenState::Duplicable, TokenState::Duplicable,
                      TokenEvent::None};
          }
          bool StrictLinearMove =
              Loan == 1 && Source == 2 &&
              (Destination == 1 || (Droppable && Destination == 2));
          TokenEffect Effect = StrictLinearMove
                                   ? TokenEffect::InvalidateStrictLoans
                                   : TokenEffect::None;
          bool Matches =
              Result.SourceBefore == States[Source] &&
              Result.DestinationBefore == States[Destination] &&
              Result.SourceAfter == Cell.SourceAfter &&
              Result.DestinationAfter == Cell.DestinationAfter &&
              Result.Events == Cell.Events && Result.Effects == Effect &&
              Result.permitted() == (Cell.Events == TokenEvent::None);
          if (!Matches)
            std::fprintf(stderr,
                         "token-algebra-test: transfer cell loan=%u drop=%u "
                         "source=%u destination=%u\n",
                         Loan, Droppable, Source, Destination);
          Passed &= Matches;
        }
  return Passed;
}

static bool testElementRelations() {
  constexpr ElementTokenRelation Exact{TokenState::Duplicable,
                                       RelationSupport::Exact, false, true};
  constexpr ElementTokenRelation Conditional{TokenState::Duplicable,
                                             RelationSupport::Exact, true,
                                             true};
  constexpr ElementTokenRelation Havoced{TokenState::Duplicable,
                                         RelationSupport::Havoced, false,
                                         true};
  ElementTokenLookup Present = lookupElementToken(
      Exact, true, ProofStatus::Proved, ProofStatus::Unproved);
  ElementTokenLookup Refined = lookupElementToken(
      Conditional, true, ProofStatus::Proved, ProofStatus::Proved);
  return require(Present.proved() &&
                     Present.Element == TokenState::Duplicable &&
                     Present.ApplyValueRefinement,
                 "exact element relation was not released") &&
         require(Refined.proved() && Refined.ApplyValueRefinement,
                 "conditional element refinement was not preserved") &&
         require(!lookupElementToken(Exact, false, ProofStatus::Proved,
                                     ProofStatus::Unproved)
                      .proved(),
                 "stale memory version released an element token") &&
         require(!lookupElementToken(Exact, true, ProofStatus::Unproved,
                                     ProofStatus::Unproved)
                      .proved(),
                 "unproved index released an element token") &&
         require(!lookupElementToken(Conditional, true, ProofStatus::Proved,
                                     ProofStatus::Refuted)
                      .proved(),
                 "refuted value predicate released an element token") &&
         require(!lookupElementToken(Havoced, true, ProofStatus::Proved,
                                     ProofStatus::Unproved)
                      .proved(),
                 "havoced relation released an element token");
}

// findTokenSort above only ever resolves a TypedefNameDecl; integer_sentinel/
// long_sentinel attach to a plain FunctionDecl (or, via its parameters, a
// ParmVarDecl), so this test needs its own by-name function lookup. Real
// checker code never needs this: it already holds the FunctionDecl/
// ParmVarDecl directly (from a CallEvent or a LocationContext), never by
// name.
static const clang::FunctionDecl *findFunction(clang::ASTContext &Context,
                                               llvm::StringRef Name) {
  clang::IdentifierInfo &Identifier = Context.Idents.get(Name);
  clang::DeclarationName Declaration(&Identifier);
  for (clang::NamedDecl *Candidate :
       Context.getTranslationUnitDecl()->lookup(Declaration))
    if (const auto *Function = llvm::dyn_cast<clang::FunctionDecl>(Candidate))
      return Function;
  return nullptr;
}

int main() {
  constexpr const char *Source = R"(
typedef struct { char byte; } dynamic_token
  __attribute__((annotate("qual:dynamic_storage")));
typedef struct { char byte; } wrong_qualifier
  __attribute__((annotate("qual:dynamic_storage_extra")));
int value_only __attribute__((annotate("qual:dynamic_storage")));
typedef struct { char byte; } malformed_word
  __attribute__((annotate("qual:sentinel_exclude=not-a-number")));
typedef struct { char byte; } malformed_overflow
  __attribute__((annotate("qual:sentinel_exclude=9223372036854775808")));
typedef struct { char byte; } null_sentinel
  __attribute__((annotate("qual:sentinel_exclude=NULL")));
typedef struct { char byte; } minimum_sentinel
  __attribute__((annotate("qual:sentinel_exclude=-9223372036854775808")));
typedef struct { char byte; } maximum_sentinel
  __attribute__((annotate("qual:sentinel_exclude=9223372036854775807")));
typedef struct { char byte; } heap_family
  __attribute__((annotate("qual:dynamic_storage")));
typedef struct { char byte; } wrapper_family
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=heap_family")));
typedef struct { char byte; } duplicate_mapping
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=heap_family"),
                 annotate("qual:implemented_by=heap_family")));
typedef struct { char byte; } missing_mapping
  __attribute__((annotate("qual:dynamic_storage")));
typedef struct { char byte; } malformed_mapping
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=not-a-family")));
typedef struct { char byte; } unknown_mapping
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=unknown_family")));
typedef struct { char byte; } conflicting_mapping
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=heap_family"),
                 annotate("qual:implemented_by=wrapper_family")));
typedef struct { char byte; } self_mapping
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=self_mapping")));
typedef struct { char byte; } chained_mapping
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=wrapper_family")));
typedef struct { char byte; } chained_malformed
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=malformed_mapping")));
typedef struct { char byte; } chained_unknown
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=unknown_mapping")));
typedef struct cycle_a cycle_a
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=cycle_b")));
typedef struct cycle_b cycle_b
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=cycle_a")));
struct cycle_a { char byte; };
struct cycle_b { char byte; };
typedef struct { char byte; } plain_family;
typedef struct { char byte; } unsupported_external
  __attribute__((annotate("qual:implemented_by=heap_family")));
typedef struct { char byte; } unsupported_internal
  __attribute__((annotate("qual:dynamic_storage"),
                 annotate("qual:implemented_by=plain_family")));
int int_sentinel_return(void)
  __attribute__((annotate("qual:integer_sentinel=-1")));
long long_sentinel_return(void)
  __attribute__((annotate("qual:long_sentinel=-2")));
int no_sentinel_return(void);
int malformed_sentinel_return(void)
  __attribute__((annotate("qual:integer_sentinel=not-a-number")));
void sentinel_param(int value __attribute__((annotate("qual:integer_sentinel=-1"))));
)";
  std::unique_ptr<clang::ASTUnit> AST =
      clang::tooling::buildASTFromCodeWithArgs(
          Source, std::vector<std::string>{"-xc", "-std=c11"},
          "token-algebra-fixture.c");
  if (!require(AST != nullptr, "failed to parse fixture"))
    return 1;
  clang::ASTContext &Context = AST->getASTContext();
  const TokenSort *Dynamic = findTokenSort(Context, "dynamic_token");
  bool Passed =
      testTransitionTable() && testTransferTable() && testElementRelations();
  Passed &= require(Dynamic != nullptr, "nominal token typedef not found");
  Passed &= require(hasQualifier(Dynamic, "qual:dynamic_storage"),
                    "exact qualifier not found");
  Passed &= require(!hasQualifier(findTokenSort(Context, "wrong_qualifier"),
                                  "qual:dynamic_storage"),
                    "prefix lookalike accepted as qualifier");
  Passed &= require(findTokenSort(Context, "value_only") == nullptr,
                    "annotation on non-typedef created a token sort");
  Passed &= require(!excludedSentinel(findTokenSort(Context, "malformed_word")),
                    "nonnumeric sentinel accepted");
  Passed &=
      require(!excludedSentinel(findTokenSort(Context, "malformed_overflow")),
              "out-of-range sentinel accepted");
  Passed &=
      require(excludedSentinel(findTokenSort(Context, "null_sentinel")) == 0,
              "NULL sentinel did not denote zero");
  Passed &=
      require(excludedSentinel(findTokenSort(Context, "minimum_sentinel")) ==
                  std::numeric_limits<int64_t>::min(),
              "minimum signed sentinel was not preserved");
  Passed &=
      require(excludedSentinel(findTokenSort(Context, "maximum_sentinel")) ==
                  std::numeric_limits<int64_t>::max(),
              "maximum signed sentinel was not preserved");
  // integer_sentinel(value)/long_sentinel(value): the same literal grammar,
  // reused verbatim (parseSentinelLiteral/sentinelFromQualifier), applied to
  // a plain FunctionDecl/ParmVarDecl instead of a tokdef TypedefNameDecl.
  const clang::FunctionDecl *IntReturn =
      findFunction(Context, "int_sentinel_return");
  const clang::FunctionDecl *LongReturn =
      findFunction(Context, "long_sentinel_return");
  const clang::FunctionDecl *NoSentinelReturn =
      findFunction(Context, "no_sentinel_return");
  const clang::FunctionDecl *MalformedReturn =
      findFunction(Context, "malformed_sentinel_return");
  const clang::FunctionDecl *SentinelParamFn =
      findFunction(Context, "sentinel_param");
  Passed &= require(integerSentinel(IntReturn) == -1,
                    "integer_sentinel literal not recovered off a FunctionDecl");
  Passed &= require(!longSentinel(IntReturn),
                    "long_sentinel matched an integer_sentinel qualifier");
  Passed &= require(longSentinel(LongReturn) == -2,
                    "long_sentinel literal not recovered off a FunctionDecl");
  Passed &= require(!integerSentinel(LongReturn),
                    "integer_sentinel matched a long_sentinel qualifier");
  Passed &= require(scalarSentinel(IntReturn) == -1,
                    "scalarSentinel did not dispatch to integer_sentinel");
  Passed &= require(scalarSentinel(LongReturn) == -2,
                    "scalarSentinel did not dispatch to long_sentinel");
  Passed &= require(!scalarSentinel(NoSentinelReturn),
                    "scalarSentinel invented a sentinel with none declared");
  Passed &= require(!scalarSentinel(MalformedReturn),
                    "scalarSentinel accepted a nonnumeric literal");
  Passed &= require(SentinelParamFn && SentinelParamFn->getNumParams() == 1,
                    "sentinel_param fixture did not parse as expected");
  if (SentinelParamFn && SentinelParamFn->getNumParams() == 1)
    Passed &= require(
        scalarSentinel(SentinelParamFn->getParamDecl(0)) == -1,
        "scalarSentinel did not read a qualifier off a ParmVarDecl");
  auto Implementation = [&](const char *Name) {
    return tokenImplementation(Context, findTokenSort(Context, Name));
  };
  TokenImplementation Wrapper = Implementation("wrapper_family");
  Passed &=
      require(Wrapper.valid() &&
                  Wrapper.Internal == findTokenSort(Context, "heap_family"),
              "valid one-hop implementation was not resolved");
  Passed &= require(Implementation("duplicate_mapping").valid(),
                    "identical duplicate implementation was rejected");
  Passed &= require(Implementation("missing_mapping").Status ==
                        TokenImplementationStatus::Missing,
                    "missing implementation was accepted");
  Passed &= require(Implementation("malformed_mapping").Status ==
                        TokenImplementationStatus::Malformed,
                    "malformed implementation was accepted");
  Passed &= require(Implementation("unknown_mapping").Status ==
                        TokenImplementationStatus::UnknownFamily,
                    "unknown implementation family was accepted");
  Passed &= require(Implementation("conflicting_mapping").Status ==
                        TokenImplementationStatus::Conflicting,
                    "conflicting implementations were accepted");
  Passed &= require(Implementation("self_mapping").Status ==
                        TokenImplementationStatus::Self,
                    "self implementation was accepted");
  TokenImplementation Chained = Implementation("chained_mapping");
  Passed &= require(Chained.valid() &&
                        Chained.Internal ==
                            findTokenSort(Context, "wrapper_family"),
                    "valid acyclic graph did not preserve its direct edge");
  Passed &= require(Implementation("chained_malformed").Status ==
                        TokenImplementationStatus::Malformed,
                    "malformed graph tail was accepted");
  Passed &= require(Implementation("chained_unknown").Status ==
                        TokenImplementationStatus::UnknownFamily,
                    "unknown graph tail was accepted");
  Passed &= require(Implementation("cycle_a").Status ==
                        TokenImplementationStatus::Cyclic,
                    "cyclic implementation was accepted");
  Passed &= require(Implementation("unsupported_external").Status ==
                        TokenImplementationStatus::Unsupported,
                    "non-dynamic external implementation was accepted");
  Passed &= require(Implementation("unsupported_internal").Status ==
                        TokenImplementationStatus::Unsupported,
                    "non-dynamic internal implementation was accepted");
  return Passed ? 0 : 1;
}
