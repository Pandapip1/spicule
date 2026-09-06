// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
//
// PurityChecker -- proves __attribute__((pure)) eligibility, and, at least
// as importantly, disproves it where the tree has already claimed it.
//
// `pure` is a stronger, riskier claim than most annotations these checkers
// verify: it licenses the compiler to eliminate, reorder, or coalesce
// calls the program depends on if the claim is wrong. A function is ruled
// in only if, across its own body and whole reachable call graph: it never
// reads/writes errno; never writes through a pointer argument or
// global/static pointer; performs no I/O; never reads/writes non-const
// global/static state; every callee is itself proven or trusted pure; and
// it never touches lock state.
//
// This is a whole-function-body property, not a per-path bug pattern -- a
// single disqualifying construct anywhere is definitive regardless of the
// values flowing through it, so bounded ExprEngine symbolic execution buys
// nothing a complete AST walk doesn't already give more simply. Hence a
// check::ASTCodeBody checker (like clang's own DeadStoresChecker): walks
// every function definition's full body via RecursiveASTVisitor, and does
// the same, memoized, for every callee reachable within the TU.
//
// Three known, disclosed limitations, all conservative (safe):
//   - No alias analysis: `int *p = &global; *p` reads as a load through
//     the local `p`, not `global`, so a global touched only via a local
//     alias can be missed. Real code here doesn't launder access this way
//     (see the sched.c/locale.c split-refactor precedent, which returns
//     tagged structs to avoid needing an output pointer).
//   - Absence of a violation is evidence of purity for the "candidate"
//     direction, not proof -- candidates are for a human to spot-check.
//     The "false claim" direction is stronger: any disqualifying
//     construct found is real and unconditional, with no bounded-
//     exploration escape hatch.
//   - No call-site-sensitive escape analysis for a callee's own
//     pointer-parameter writes: computePurity() memoizes one verdict per
//     callee, matching how `pure` really works, but a callee that writes
//     through its own pointer parameter is never pure even where the
//     actual argument is always a local. fnmatch.c's bracket_match() used
//     to have exactly this shape -- fnm_match() called it as
//     bracket_match(&probe, c), writing through a `const char **pp`
//     out-parameter whose one and only actual argument was always a
//     fnm_match()-local -- and was the live false-claim finding this
//     limitation produced. It has since been refactored to return a
//     `struct bracket_result` by value instead, which sidesteps the gap
//     structurally rather than this checker growing full per-call-site
//     parameter-write tracking; no current tree code hits this
//     limitation, but nothing prevents a future callee from reintroducing
//     the shape.
//
// Cross-TU calls are trusted only if already declared
// __attribute__((pure))/((const)) visible in this TU, or if the callee is
// one of a small hand-picked set of foundational accessors --
// __errno_location() and __teb() -- that OwnershipChecker.cpp already
// leans on for its always-nonnull lemma: both compute a pointer stable for
// the calling thread via a mechanism opaque to this AST-level analysis,
// with no observable side effect of their own (the errno/TEB *content* is
// a separate matter the ordinary read-write rules below still cover).

#include "clang/AST/ASTContext.h"
#include "clang/AST/Attr.h"
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

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringRef.h"

#include <cctype>
#include <string>

using namespace clang;
using namespace ento;

namespace {

constexpr llvm::StringLiteral TrustedPrimitives[] = {
    "__errno_location", "__teb", "__ownership_string_terminated"};

bool isTrustedPrimitive(StringRef Name) {
  for (StringRef Trusted : TrustedPrimitives)
    if (Name == Trusted)
      return true;
  return false;
}

// memset()/bzero() are real writes through their first argument -- not
// trusted unconditionally the way __errno_location()/__teb() are, since a
// global or parameter destination would be a genuine externally observable
// side effect. But when that destination resolves (via resolveBase(),
// below) to a stack-local object that never escapes this function -- the
// `char byteset[N]; memset(byteset, 0, sizeof byteset);` shape strcspn()/
// strspn() use to zero a local scratch buffer (src/string/strcspn.c,
// strspn.c) -- the write is invisible to any caller, exactly as if it were
// inlined as a local assignment loop. Deliberately not extended to memcpy/
// memmove: those also *read* through a second pointer argument this
// call-opaque analysis cannot see into, so trusting them here would risk
// missing a real global/param read the same way a direct load would be
// caught.
constexpr llvm::StringLiteral LocalOnlyWriteBuiltins[] = {"memset", "bzero"};

bool isLocalOnlyWriteBuiltin(StringRef Name) {
  for (StringRef Name2 : LocalOnlyWriteBuiltins)
    if (Name == Name2)
      return true;
  return false;
}

// Mirrors LockDisciplineChecker.cpp's own protocolFor() table: every
// pthread entry point that acquires, releases, waits on, initializes, or
// destroys a lock has an observable side effect on lock state independent
// of its return value.
constexpr llvm::StringLiteral LockNames[] = {
    "pthread_mutex_init",         "pthread_mutex_lock",
    "pthread_mutex_trylock",      "pthread_mutex_timedlock",
    "pthread_mutex_unlock",       "pthread_mutex_destroy",
    "pthread_rwlock_init",        "pthread_rwlock_rdlock",
    "pthread_rwlock_tryrdlock",   "pthread_rwlock_timedrdlock",
    "pthread_rwlock_wrlock",      "pthread_rwlock_trywrlock",
    "pthread_rwlock_timedwrlock", "pthread_rwlock_unlock",
    "pthread_rwlock_destroy",     "pthread_spin_init",
    "pthread_spin_lock",          "pthread_spin_trylock",
    "pthread_spin_unlock",        "pthread_spin_destroy",
    "pthread_cond_wait",          "pthread_cond_timedwait",
    "pthread_cond_signal",        "pthread_cond_broadcast",
};

bool isLockCall(StringRef Name) {
  for (StringRef Name2 : LockNames)
    if (Name == Name2)
      return true;
  return false;
}

// Anything spelled Nt*/Zw* (this tree's Windows Native API convention) or a
// raw syscall() (src/unistd/syscall.c) is I/O regardless of name; every
// other real I/O/syscall entry point carries include/ownership.h's
// io_operation bare, function-level annotate() marker, so any redeclaration
// may carry it (mirrors FallibleResultChecker.cpp's isFallible()). Replaces
// the hardcoded IoNames[] list this checker used to carry itself.
bool isIoCall(const FunctionDecl *Function, StringRef Name) {
  if (Name.starts_with("Nt") || Name.starts_with("Zw"))
    return true;
  if (Name == "syscall")
    return true;
  for (const FunctionDecl *Redecl : Function->redecls())
    for (const AnnotateAttr *Attribute : Redecl->specific_attrs<AnnotateAttr>())
      if (Attribute->getAnnotation() == "io_operation")
        return true;
  return false;
}

std::string collapseWhitespace(StringRef Raw) {
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

std::string sourceText(const Stmt *Statement, const SourceManager &SM,
                       const LangOptions &LangOpts) {
  if (!Statement)
    return "<none>";
  SourceLocation Begin = SM.getSpellingLoc(Statement->getBeginLoc());
  SourceLocation End = SM.getSpellingLoc(Statement->getEndLoc());
  StringRef Raw = Lexer::getSourceText(CharSourceRange::getTokenRange(Begin, End),
                                       SM, LangOpts);
  std::string Result = collapseWhitespace(Raw);
  return Result.empty() ? Statement->getStmtClassName() : Result;
}

std::string signatureText(const FunctionDecl *FD) {
  std::string Result =
      FD->getReturnType().getAsString() + " " + FD->getQualifiedNameAsString() + "(";
  bool First = true;
  for (const ParmVarDecl *Param : FD->parameters()) {
    if (!First)
      Result += ", ";
    First = false;
    Result += Param->getType().getAsString();
  }
  if (FD->isVariadic())
    Result += First ? "..." : ", ...";
  else if (First)
    Result += "void";
  Result += ")";
  return Result;
}

std::string originOf(SourceLocation Loc, const SourceManager &SM) {
  return SM.getFilename(SM.getExpansionLoc(Loc)).str();
}

// An array's own qualifiers do not always carry the element type's
// const-ness at the QualType level the way scalar variables do; walk down
// through array types to find the real element constness (matches the
// `static const char *const table[]` shape string.h's strerror() uses).
bool isEffectivelyConst(QualType Type) {
  if (Type.isConstQualified())
    return true;
  if (const ArrayType *Array = Type->getAsArrayTypeUnsafe())
    return isEffectivelyConst(Array->getElementType());
  return false;
}

bool hasPureOrConstAttr(const FunctionDecl *FD) {
  for (const FunctionDecl *Redecl : FD->redecls())
    if (Redecl->hasAttr<PureAttr>() || Redecl->hasAttr<ConstAttr>())
      return true;
  return false;
}

bool hasPureAttr(const FunctionDecl *FD) {
  for (const FunctionDecl *Redecl : FD->redecls())
    if (Redecl->hasAttr<PureAttr>())
      return true;
  return false;
}

// Where a load or write's lvalue ultimately bottoms out: reading through a
// pointer *parameter* (any depth of ->/[]/ *) is fine -- that is exactly how
// this tree's own memcmp/strcmp family (already pure, per string.h) work --
// but a global/static object, or a pointer of unproven provenance, is not.
enum class Base { Local, Param, GlobalConst, GlobalMutable, Unknown };

Base resolveBase(const Expr *Expression) {
  Expression = Expression->IgnoreParenCasts();
  if (const auto *Ref = dyn_cast<DeclRefExpr>(Expression)) {
    if (const auto *Var = dyn_cast<VarDecl>(Ref->getDecl())) {
      if (isa<ParmVarDecl>(Var))
        return Base::Param;
      if (Var->hasGlobalStorage())
        return isEffectivelyConst(Var->getType()) ? Base::GlobalConst
                                                   : Base::GlobalMutable;
      return Base::Local;
    }
    return Base::Unknown;
  }
  if (const auto *Member = dyn_cast<MemberExpr>(Expression))
    return resolveBase(Member->getBase());
  if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(Expression))
    return resolveBase(Subscript->getBase());
  if (const auto *Unary = dyn_cast<UnaryOperator>(Expression))
    if (Unary->getOpcode() == UO_Deref)
      return resolveBase(Unary->getSubExpr());
  return Base::Unknown;
}

bool isPointerWriteTarget(const Expr *LHS) {
  LHS = LHS->IgnoreParenCasts();
  if (const auto *Unary = dyn_cast<UnaryOperator>(LHS))
    return Unary->getOpcode() == UO_Deref;
  if (isa<ArraySubscriptExpr>(LHS))
    return true;
  if (const auto *Member = dyn_cast<MemberExpr>(LHS))
    return Member->isArrow();
  return false;
}

// True only when Expression, after unwrapping any chain of nested array
// subscripts, bottoms out directly at a local variable that is itself an
// array OBJECT (not a pointer variable) -- the `byteset[i] |= ...` shape
// strcspn()/strspn()'s BITOP macro uses to build a local bitmap in place
// (src/string/strcspn.c, strspn.c). Deliberately narrower than
// resolveBase()'s own Base::Local: a local *pointer* variable
// (`int *p = &global; p[i] = x;` or `*p = x;`) is never trusted here,
// since -- absent alias analysis, a disclosed limitation of this checker
// -- there is no way to tell such a pointer apart from one that aliases a
// global; only a true array object, whose storage can never be
// reassigned to alias something else, is safe to trust this way.
bool isLocalArrayWrite(const Expr *Expression) {
  Expression = Expression->IgnoreParenCasts();
  if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(Expression))
    return isLocalArrayWrite(Subscript->getBase());
  if (const auto *Ref = dyn_cast<DeclRefExpr>(Expression)) {
    const auto *Var = dyn_cast<VarDecl>(Ref->getDecl());
    return Var && !isa<ParmVarDecl>(Var) && !Var->hasGlobalStorage() &&
           Var->getType()->isArrayType();
  }
  return false;
}

bool isDirectGlobalWriteTarget(const Expr *LHS) {
  LHS = LHS->IgnoreParenCasts();
  if (const auto *Ref = dyn_cast<DeclRefExpr>(LHS)) {
    const auto *Var = dyn_cast<VarDecl>(Ref->getDecl());
    return Var && !isa<ParmVarDecl>(Var) && Var->hasGlobalStorage();
  }
  if (const auto *Member = dyn_cast<MemberExpr>(LHS))
    if (!Member->isArrow())
      return isDirectGlobalWriteTarget(Member->getBase());
  return false;
}

bool isVolatileAccess(const Expr *Expression) {
  return !Expression->getType().isNull() &&
         Expression->getType().isVolatileQualified();
}

struct PurityResult {
  bool Pure = false;
  std::string Reason;
  const Stmt *Offender = nullptr;
};

class PurityChecker : public Checker<check::ASTCodeBody> {
  mutable llvm::DenseMap<const FunctionDecl *, PurityResult> Memo;
  mutable llvm::DenseSet<const FunctionDecl *> InProgress;

  class BodyWalker : public RecursiveASTVisitor<BodyWalker> {
  public:
    const PurityChecker *Owner;
    ASTContext &Context;
    bool Violated = false;
    std::string Reason;
    const Stmt *Offender = nullptr;

    BodyWalker(const PurityChecker *Owner, ASTContext &Context)
        : Owner(Owner), Context(Context) {}

    void fail(const std::string &Why, const Stmt *Statement) {
      if (Violated)
        return; // Keep the first offender found; it is enough to disprove.
      Violated = true;
      Reason = Why;
      Offender = Statement;
    }

    bool VisitGCCAsmStmt(GCCAsmStmt *Asm) {
      fail("contains inline assembly", Asm);
      return true;
    }

    bool VisitCallExpr(CallExpr *Call) {
      const auto *Function = dyn_cast_or_null<FunctionDecl>(Call->getCalleeDecl());
      if (!Function || !Function->getIdentifier()) {
        fail("calls through an unresolved function pointer", Call);
        return true;
      }
      StringRef Name = Function->getName();
      if (Name == "__errno_location") {
        fail("touches errno", Call);
        return true;
      }
      if (isTrustedPrimitive(Name))
        return true;
      if (isLockCall(Name)) {
        fail("acquires or releases a lock", Call);
        return true;
      }
      if (isIoCall(Function, Name)) {
        fail("performs I/O or a syscall", Call);
        return true;
      }
      if (isLocalOnlyWriteBuiltin(Name)) {
        // isLocalArrayWrite(), not resolveBase()==Base::Local: the same
        // alias-blindness gap a direct `*p = x` write has applies here too
        // -- a local *pointer* variable that happens to alias a global
        // must not be trusted just because the pointer variable itself has
        // local storage. Only a true local array object (whose storage can
        // never be reassigned to alias something else) is safe.
        const Expr *Dest = Call->getNumArgs() > 0 ? Call->getArg(0) : nullptr;
        if (Dest && isLocalArrayWrite(Dest))
          return true;
        // Same message text a direct `*p = ...` write through this same
        // destination would produce -- to lint-purity.py's regex-driven
        // classifier (and to a human reading the report) an unproven-local
        // memset()/bzero() destination is exactly as real a violation as
        // any other pointer write, not a distinct category.
        fail("writes through a pointer", Call);
        return true;
      }
      if (hasPureOrConstAttr(Function))
        return true;
      PurityResult Result = Owner->computePurity(Function, Context);
      if (!Result.Pure) {
        std::string Why = "calls " + Function->getNameAsString() +
                          "(), which is not proven pure (" + Result.Reason + ")";
        fail(Why, Call);
      }
      return true;
    }

    bool VisitBinaryOperator(BinaryOperator *Binary) {
      if (!Binary->isAssignmentOp())
        return true;
      const Expr *LHS = Binary->getLHS();
      if (isVolatileAccess(LHS)) {
        fail("accesses volatile state", Binary);
      } else if (isPointerWriteTarget(LHS)) {
        if (!isLocalArrayWrite(LHS))
          fail("writes through a pointer", Binary);
      } else if (isDirectGlobalWriteTarget(LHS)) {
        fail("writes to global or static state", Binary);
      }
      return true;
    }

    bool VisitUnaryOperator(UnaryOperator *Unary) {
      if (!Unary->isIncrementDecrementOp())
        return true;
      const Expr *Sub = Unary->getSubExpr();
      if (isVolatileAccess(Sub)) {
        fail("accesses volatile state", Unary);
      } else if (isPointerWriteTarget(Sub)) {
        if (!isLocalArrayWrite(Sub))
          fail("writes through a pointer", Unary);
      } else if (isDirectGlobalWriteTarget(Sub)) {
        fail("writes to global or static state", Unary);
      }
      return true;
    }

    bool VisitImplicitCastExpr(ImplicitCastExpr *Cast) {
      if (Cast->getCastKind() != CK_LValueToRValue)
        return true;
      const Expr *Sub = Cast->getSubExpr();
      if (isVolatileAccess(Sub)) {
        fail("accesses volatile state", Cast);
        return true;
      }
      Base Resolved = resolveBase(Sub);
      if (Resolved == Base::GlobalMutable) {
        fail("reads mutable global or static state", Cast);
      } else if (Resolved == Base::Unknown) {
        fail("reads through a pointer of unproven provenance", Cast);
      }
      return true;
    }
  };

  PurityResult walkBody(const FunctionDecl *FD, const FunctionDecl *Def,
                        ASTContext &Ctx) const {
    const FunctionDecl *Key = FD->getCanonicalDecl();
    InProgress.insert(Key);
    BodyWalker Walker(this, Ctx);
    Walker.TraverseStmt(Def->getBody());
    InProgress.erase(Key);
    PurityResult Result;
    Result.Pure = !Walker.Violated;
    if (Walker.Violated) {
      Result.Reason = Walker.Reason;
      Result.Offender = Walker.Offender;
    }
    return Result;
  }

public:
  // Callee-trust-aware, memoized: used whenever some OTHER function's body
  // asks "is this call safe to treat as pure". Trusts an already-declared
  // __attribute__((pure))/((const)) callee, or a bootstrap primitive,
  // without re-deriving it; recurses and caches otherwise.
  PurityResult computePurity(const FunctionDecl *FD, ASTContext &Ctx) const {
    if (FD->getIdentifier() && isTrustedPrimitive(FD->getName()))
      return {true, "", nullptr};
    if (hasPureOrConstAttr(FD))
      return {true, "", nullptr};
    const FunctionDecl *Key = FD->getCanonicalDecl();
    auto Found = Memo.find(Key);
    if (Found != Memo.end())
      return Found->second;
    // A back-edge into a function whose own walkBody() is already running
    // further up this same C++ call stack (direct or mutual recursion, e.g.
    // fnm_match() calling itself -- src/fnmatch/fnmatch.c). This is an
    // optimistic fixed point, not a blind trust: the edge itself carries no
    // side effect, and Key's own concrete disqualifiers (a global write, an
    // I/O call, errno, ...) are still found by the very walkBody() call this
    // recursion is nested inside, via VisitCallExpr/VisitBinaryOperator/etc
    // firing independently on whatever other statements that body contains
    // -- so a genuinely impure cycle member is still caught, just not by
    // this particular edge. Only the recursive edge itself is elided.
    if (InProgress.count(Key))
      return {true, "", nullptr};
    const FunctionDecl *Def = FD->getDefinition();
    if (!Def || !Def->hasBody()) {
      PurityResult Result{false, "has no definition visible in this translation unit",
                          nullptr};
      Memo[Key] = Result;
      return Result;
    }
    PurityResult Result = walkBody(FD, Def, Ctx);
    Memo[Key] = Result;
    return Result;
  }

  // Always walks FD's own body directly, regardless of FD's own attribute
  // -- this is the entry point that actually verifies (or disproves) a
  // claim already made on FD itself, so it must never take the
  // already-trusted shortcut computePurity() takes for callees.
  PurityResult analyzeStructurally(const FunctionDecl *FD, ASTContext &Ctx) const {
    const FunctionDecl *Def = FD->getDefinition();
    if (!Def || !Def->hasBody())
      return {false, "has no definition visible in this translation unit", nullptr};
    return walkBody(FD, Def, Ctx);
  }

  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
    const auto *FD = dyn_cast<FunctionDecl>(D);
    if (!FD || !FD->hasBody())
      return;
    ASTContext &Ctx = Mgr.getASTContext();
    const SourceManager &SM = BR.getSourceManager();
    bool Claimed = hasPureAttr(FD);
    PurityResult Result = analyzeStructurally(FD, Ctx);

    if (Claimed && !Result.Pure) {
      std::string Message = "already-declared pure function " + Result.Reason +
                            "; origin '" +
                            originOf(Result.Offender ? Result.Offender->getBeginLoc()
                                                     : FD->getLocation(),
                                    SM) +
                            "'; context '" + FD->getQualifiedNameAsString() +
                            "'; expression '" +
                            sourceText(Result.Offender, SM, Ctx.getLangOpts()) + "'";
      SourceLocation Loc = SM.getExpansionLoc(
          Result.Offender ? Result.Offender->getBeginLoc() : FD->getLocation());
      PathDiagnosticLocation PDLoc(Loc, SM);
      BR.EmitBasicReport(FD, this, "False __attribute__((pure)) claim",
                         categories::LogicError, Message, PDLoc,
                         Result.Offender ? Result.Offender->getSourceRange()
                                         : FD->getSourceRange());
      return;
    }

    if (!Claimed && Result.Pure) {
      // A void-returning function has nothing a caller could observably
      // depend on other than its (disallowed, by definition) side effects
      // -- pure on such a function is meaningless, not a real candidate.
      if (FD->getReturnType()->isVoidType())
        return;
      std::string Message =
          "function has no proven side effects and could be declared "
          "__attribute__((pure)); origin '" +
          originOf(FD->getLocation(), SM) + "'; context '" +
          FD->getQualifiedNameAsString() + "'; expression '" + signatureText(FD) + "'";
      SourceLocation Loc = SM.getExpansionLoc(FD->getLocation());
      PathDiagnosticLocation PDLoc(Loc, SM);
      BR.EmitBasicReport(FD, this, "Pure function candidate", categories::LogicError,
                         Message, PDLoc, FD->getSourceRange());
    }
  }
};

} // namespace

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<PurityChecker>(
      "ntlibc.Purity",
      "Proves __attribute__((pure)) eligibility and disproves false claims",
      "");
}
