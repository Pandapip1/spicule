// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
//
// LoopConditionChecker -- flags a `for`/`while`/`do` header whose condition
// is a compound `&&`/`||` expression that mixes a structural bound (a
// range, a fixed count, a cursor-vs-NULL/sentinel test) with a distinct,
// incidental data-dependent bail-out (a found/success/error flag, or an
// unrelated function-call result).
//
// The underlying readability rule this is one instance of: code should
// read like the clearest pseudocode describing it. A `for` loop's whole
// value is that its header lets a reader see the entire loop control at a
// glance; a `while` loop's whole value is that its header names the one
// real reason the loop keeps going. Folding a second, unrelated reason to
// stop into the SAME header via `&&`/`||` defeats both: the reader now has
// to hold two unrelated conditions in their head to know why the loop
// ends, when the language already has a place for the secondary one -- an
// explicit `if (condition) break;` statement in the body. That applies
// equally to a `for` loop capping a data-dependent search (the found/
// success flag belongs in the body, not `&&`'d into the header) and to a
// `while` loop retrying until success but also capped at N attempts (the
// attempt-count belongs in the body, not `&&`'d into the header).
//
// This is deliberately NOT a check against the mere presence of a `break`
// in a loop body -- an `if (...) break;` inside an otherwise clean
// range/cursor `for` loop, or inside a `while` loop's own natural
// condition, is exactly the pattern this rule steers code TOWARDS, not
// away from. Only the loop HEADER's own condition is examined.
//
// Detection is a single per-condition classification, not a proof: split
// the condition into its top-level `&&`/`||` operands (only when the
// WHOLE top-level operator is uniform -- a mix of `&&` and `||` without
// parentheses is rare enough, and ambiguous enough about grouping, that
// guessing at it is not worth the false-positive risk) and classify each
// leaf as one of:
//
//   Bound  a relational/equality comparison (`i < n`, `p != NULL`,
//          `*p != '\0'`, `buf[i] == target`); a dereference or array
//          subscript used bare as a truth test (`*p`, `s[i]` -- the
//          classic "content under the cursor" scan idiom, which is a
//          structural end-of-structure test even though it inspects
//          content); or a bare pointer-typed variable (`p`, `!p` --
//          the classic cursor-vs-NULL test).
//
//   Flag   a bare non-pointer scalar variable used alone as a truth test
//          (`ok`, `!success`) or a function call used alone as a truth
//          test (`try_x()`, `!is_done()`) -- UNLESS that call's own
//          arguments already mention one of the variables a Bound leaf in
//          this same condition compared against (see BoundVars below),
//          in which case it reads as "check content at the cursor" like
//          the dereference/subscript case, not as an independent flag.
//
//   Other  anything else (a ternary, a member access used bare, nested
//          logic, ...) -- deliberately unclassified rather than guessed
//          at.
//
// A finding is reported only when the leaf set contains at least one
// Bound leaf and at least one Flag leaf: that specific mix is what
// signals "this header is doing two unrelated jobs". A condition of all
// Bound leaves (`i < n && i >= 0`, a dual-range scan) or all Flag leaves
// (`!done && !aborted`, two co-primary reasons to keep retrying) is left
// alone, since neither case identifies one side as clearly incidental to
// the other -- which of two flags is "the real one" is a judgment call
// this checker does not attempt.
//
// Known, disclosed imprecision: a bare non-pointer scalar used alone as a
// truth test (`remaining`, `n`) is classified Flag, even though it is
// sometimes a legitimate structural "items left" counter rather than a
// boolean flag -- the two are syntactically identical once written as a
// bare truth test, and disambiguating them would need naming-convention
// guessing this checker deliberately does not do. In practice this
// tree almost always spells a remaining-count test as an explicit
// comparison (`remaining > 0`, `n != 0`), which classifies as Bound, so
// the ambiguity mostly does not bite; where it does, the result is a
// false positive for a human to dismiss, not a missed real one.
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

#include <memory>
#include <set>
#include <string>
#include <vector>

using namespace clang;
using namespace ento;

namespace {

// -- small text helpers, mirroring PurityChecker.cpp's own (each checker
// file in this tree is self-contained; there is no shared text-utility
// header to pull these from) --

std::string collapseWhitespace(StringRef Raw) {
  std::string Result;
  bool Space = false;
  for (char C : Raw) {
    if (isspace(static_cast<unsigned char>(C))) {
      Space = !Result.empty();
      continue;
    }
    if (Space)
      Result += ' ';
    Result += C;
    Space = false;
  }
  return Result;
}

std::string sourceText(const Expr *E, const SourceManager &SM, const LangOptions &LangOpts) {
  if (!E)
    return "<none>";
  SourceLocation Begin = SM.getSpellingLoc(E->getBeginLoc());
  SourceLocation End = SM.getSpellingLoc(E->getEndLoc());
  StringRef Raw = Lexer::getSourceText(CharSourceRange::getTokenRange(Begin, End), SM, LangOpts);
  std::string Result = collapseWhitespace(Raw);
  return Result.empty() ? E->getStmtClassName() : Result;
}

std::string originOf(SourceLocation Loc, const SourceManager &SM) {
  return SM.getFilename(SM.getExpansionLoc(Loc)).str();
}

// -- AST helpers --

// Strips parens/implicit casts and one outer logical negation. Negation
// does not change whether a leaf is a structural bound or an incidental
// flag, only which way it currently reads (`p` vs `!p`, `ok` vs `!ok`).
const Expr *stripOuterNot(const Expr *E) {
  E = E->IgnoreParenImpCasts();
  if (const auto *UO = dyn_cast<UnaryOperator>(E))
    if (UO->getOpcode() == UO_LNot)
      return UO->getSubExpr()->IgnoreParenImpCasts();
  return E;
}

// Collects every DeclRefExpr's referenced VarDecl within a subtree, for
// two uses: identifying the variable(s) a Bound leaf's comparison is
// actually about (BoundVars), and testing whether some other leaf (a
// bare call) mentions one of those same variables.
void collectVars(const Stmt *S, std::set<const VarDecl *> &Out) {
  if (!S)
    return;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      Out.insert(VD);
  for (const Stmt *Child : S->children())
    collectVars(Child, Out);
}

bool mentionsAny(const Stmt *S, const std::set<const VarDecl *> &Vars) {
  if (!S || Vars.empty())
    return false;
  if (const auto *DRE = dyn_cast<DeclRefExpr>(S))
    if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()))
      if (Vars.count(VD))
        return true;
  for (const Stmt *Child : S->children())
    if (mentionsAny(Child, Vars))
      return true;
  return false;
}

// Splits E into its top-level `&&`-or-`||` operands, recursing only
// through further nodes of the SAME operator -- a bare, unparenthesized
// mix of `&&` and `||` is rare and ambiguous enough about grouping that
// this treats the first differently-opcoded subexpression it meets as an
// opaque leaf rather than guessing how it associates.
void flattenLogical(const Expr *E, BinaryOperatorKind Op, std::vector<const Expr *> &Leaves) {
  const Expr *Stripped = E->IgnoreParenImpCasts();
  if (const auto *BO = dyn_cast<BinaryOperator>(Stripped)) {
    if (BO->getOpcode() == Op) {
      flattenLogical(BO->getLHS(), Op, Leaves);
      flattenLogical(BO->getRHS(), Op, Leaves);
      return;
    }
  }
  Leaves.push_back(Stripped);
}

std::vector<const Expr *> topLevelLeaves(const Expr *Cond) {
  const Expr *Stripped = Cond->IgnoreParenImpCasts();
  std::vector<const Expr *> Leaves;
  if (const auto *BO = dyn_cast<BinaryOperator>(Stripped); BO && BO->isLogicalOp())
    flattenLogical(Stripped, BO->getOpcode(), Leaves);
  else
    Leaves.push_back(Stripped);
  return Leaves;
}

enum class LeafKind { Bound, Flag, Other };

// First-pass classification for everything except a bare call, which
// needs BoundVars from its siblings first (see classifyLeaves below).
LeafKind classifyLeafBasic(const Expr *Leaf) {
  const Expr *E = stripOuterNot(Leaf);
  if (const auto *BO = dyn_cast<BinaryOperator>(E); BO && BO->isComparisonOp())
    return LeafKind::Bound; // i < n, p != NULL, *p != '\'', buf[i] == target
  if (const auto *UO = dyn_cast<UnaryOperator>(E); UO && UO->getOpcode() == UO_Deref)
    return LeafKind::Bound; // *p  (content-under-cursor test)
  if (isa<ArraySubscriptExpr>(E))
    return LeafKind::Bound; // s[i]  (content-under-index test)
  if (const auto *DRE = dyn_cast<DeclRefExpr>(E)) {
    if (DRE->getType()->isPointerType())
      return LeafKind::Bound; // bare `p` / `!p` cursor test
    return LeafKind::Flag;    // bare scalar truthy test
  }
  if (isa<CallExpr>(E))
    return LeafKind::Flag; // provisional; refined in classifyLeaves()
  return LeafKind::Other;   // ternary, bare member access, ...: don't guess
}

struct Classified {
  const Expr *Leaf;
  LeafKind Kind;
};

// True if VD is incremented, decremented, or compound-assigned (`n--`,
// `n -= k`) anywhere in Body -- deliberately NOT true for a plain `=`
// assignment (`success = attempt();`), which is exactly how a boolean
// flag is normally set and never how a countdown is. This is the
// checker's one piece of real disambiguation between the two shapes a
// bare non-pointer identifier used alone as a truth test can have: a
// remaining-budget counter (`while (n && *s) { ...; n--; s++; }`, the
// bounded-copy idiom this tree's strncmp/strncat/wcsncpy/wmemcmp family
// all share) reads identically to a boolean flag (`while (!success)`)
// until this mutation evidence is checked.
bool isCounterMutated(const Stmt *S, const VarDecl *VD) {
  if (!S)
    return false;
  if (const auto *UO = dyn_cast<UnaryOperator>(S)) {
    if (UO->isIncrementDecrementOp())
      if (const auto *DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenImpCasts()))
        if (DRE->getDecl() == VD)
          return true;
  } else if (const auto *CAO = dyn_cast<CompoundAssignOperator>(S)) {
    if (const auto *DRE = dyn_cast<DeclRefExpr>(CAO->getLHS()->IgnoreParenImpCasts()))
      if (DRE->getDecl() == VD)
        return true;
  }
  for (const Stmt *Child : S->children())
    if (isCounterMutated(Child, VD))
      return true;
  return false;
}

std::vector<Classified> classifyLeaves(const std::vector<const Expr *> &Leaves,
                                       const Stmt *Body) {
  std::vector<Classified> Result;
  Result.reserve(Leaves.size());
  for (const Expr *Leaf : Leaves)
    Result.push_back({Leaf, classifyLeafBasic(Leaf)});

  std::set<const VarDecl *> BoundVars;
  for (const Classified &C : Result)
    if (C.Kind == LeafKind::Bound)
      collectVars(C.Leaf, BoundVars);

  for (Classified &C : Result) {
    if (C.Kind != LeafKind::Flag)
      continue;
    const Expr *Stripped = stripOuterNot(C.Leaf);
    // A bare non-pointer identifier that is incremented/decremented in
    // the loop body is a counter, not a flag -- reclassify it as
    // structural (see isCounterMutated's own comment).
    if (const auto *DRE = dyn_cast<DeclRefExpr>(Stripped)) {
      if (const auto *VD = dyn_cast<VarDecl>(DRE->getDecl()); VD && isCounterMutated(Body, VD))
        C.Kind = LeafKind::Bound;
      continue;
    }
    // A bare call that itself references one of the same variables a
    // Bound leaf's comparison was about reads as "check content at the
    // cursor" (like `page_lock_state(m, first)` alongside
    // `first < m->npages`), not as an independent, incidental flag.
    if (isa<CallExpr>(Stripped) && mentionsAny(Stripped, BoundVars))
      C.Kind = LeafKind::Bound;
  }
  return Result;
}

class LoopConditionChecker;

class LoopConditionVisitor : public RecursiveASTVisitor<LoopConditionVisitor> {
public:
  LoopConditionVisitor(const LoopConditionChecker &Checker, BugReporter &BR, const FunctionDecl *FD)
      : Checker(Checker), BR(BR), FD(FD) {}

  bool VisitForStmt(ForStmt *FS) {
    analyze(FS->getCond(), FS->getBody(), "for");
    return true;
  }
  bool VisitWhileStmt(WhileStmt *WS) {
    analyze(WS->getCond(), WS->getBody(), "while");
    return true;
  }
  bool VisitDoStmt(DoStmt *DS) {
    analyze(DS->getCond(), DS->getBody(), "do");
    return true;
  }

private:
  const LoopConditionChecker &Checker;
  BugReporter &BR;
  const FunctionDecl *FD;

  // Defined out-of-line below, after LoopConditionChecker's own definition:
  // it upcasts &Checker to `const CheckerBase *` for EmitBasicReport, which
  // needs LoopConditionChecker to be a complete type, not merely the
  // forward declaration visible at this point in the file.
  void analyze(const Expr *Cond, const Stmt *Body, const char *LoopKind);
};

class LoopConditionChecker : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &, BugReporter &BR) const {
    const auto *FD = dyn_cast<FunctionDecl>(D);
    if (!FD || !FD->hasBody())
      return;
    LoopConditionVisitor Visitor(*this, BR, FD);
    Visitor.TraverseStmt(FD->getBody());
  }
};

void LoopConditionVisitor::analyze(const Expr *Cond, const Stmt *Body, const char *LoopKind) {
  if (!Cond)
    return;
  std::vector<const Expr *> Leaves = topLevelLeaves(Cond);
  if (Leaves.size() < 2)
    return; // only a compound header condition is in scope

  std::vector<Classified> Kinds = classifyLeaves(Leaves, Body);
  const Expr *BoundLeaf = nullptr;
  const Expr *FlagLeaf = nullptr;
  for (const Classified &C : Kinds) {
    if (C.Kind == LeafKind::Bound && !BoundLeaf)
      BoundLeaf = C.Leaf;
    if (C.Kind == LeafKind::Flag && !FlagLeaf)
      FlagLeaf = C.Leaf;
  }
  if (!BoundLeaf || !FlagLeaf)
    return;

  const ASTContext &Ctx = FD->getASTContext();
  const SourceManager &SM = BR.getSourceManager();
  const LangOptions &LO = Ctx.getLangOpts();

  std::string Message =
      std::string("this `") + LoopKind +
      "` loop's condition compounds a structural bound with an apparently "
      "incidental, data-dependent condition via `&&`/`||`; keep the "
      "primary condition in the loop header and move the other into an "
      "explicit `if (...) break;` inside the loop body; kind "
      "'compound-header'; loop_kind '" +
      LoopKind + "'; origin '" + originOf(Cond->getBeginLoc(), SM) + "'; context '" +
      FD->getQualifiedNameAsString() + "'; bound '" + sourceText(BoundLeaf, SM, LO) +
      "'; flag '" + sourceText(FlagLeaf, SM, LO) + "'; expression '" +
      sourceText(Cond, SM, LO) + "'";

  SourceLocation Loc = SM.getExpansionLoc(Cond->getBeginLoc());
  PathDiagnosticLocation PDLoc(Loc, SM);
  BR.EmitBasicReport(FD, &Checker,
                      "Loop header compounds a structural bound with a data-dependent condition",
                      categories::LogicError, Message, PDLoc, Cond->getSourceRange());
}

} // namespace

extern "C" const char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<LoopConditionChecker>(
      "ntlibc.LoopCondition",
      "Flags a for/while/do header whose condition compounds a structural "
      "bound with an incidental data-dependent bail-out via &&/||",
      "");
}
