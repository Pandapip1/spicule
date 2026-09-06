// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "TokenAlgebra.h"

#include <cctype>
#include <memory>
#include <string>

using namespace clang;
using namespace ento;

/* The call whose return-value symbol is being tracked, keyed by that
 * symbol, for every call this path has made to a function capable of
 * setting errno (checkPostCall fills this in below). */
REGISTER_MAP_WITH_PROGRAMSTATE(ErrnoSetterOf, SymbolRef, const Stmt *)

/* Two per-path facts, keyed by a fixed slot number the way
 * LockDisciplineChecker keys HeldLocks by a MemRegion: the call currently
 * "under diagnosis" (the most recent capable call whose return value was
 * compared for failure), and the most recent capable call at all (whether
 * or not it was ever compared).  When Diagnosed and LastCapable diverge, an
 * errno read is reading the wrong call's errno.  (Whether *any* call or
 * assignment on this path could have set errno at all -- the checker's
 * other proof obligation -- is a value-independent, once-per-path fact
 * with no need for either slot's identity; see errno_grounds and
 * ThreadCapabilityMap below.) */
REGISTER_MAP_WITH_PROGRAMSTATE(CallSlot, unsigned, const Stmt *)

/* A local this path has seen initialized or assigned directly from an
 * errno read (`V = errno;` or `TYPE V = errno;`), keyed by its own
 * MemRegion.  See checkPreStmt(UnaryOperator)'s savedInto handling for
 * why capturing errno's current value this way needs no proof, and
 * comparedToSavedErrno for the "did it change" read this exists to
 * recognise as safe afterward. */
REGISTER_MAP_WITH_PROGRAMSTATE(SavedErrnoVar, const MemRegion *, bool)

/* Mirrors OwnershipChecker.cpp's own CarrierCapabilityKind/CarrierCapabilityMap
 * exactly (same four states, same "absent map entry reads as Absent, not
 * Unknown" convention), keyed by token family alone instead of by a
 * MemRegion/SymbolRef carrier: this checker is built as its own standalone
 * plugin (tools/lint.sh's stage_errno compiles only this .cpp, separately
 * from stage_ownership's OwnershipChecker.cpp), so it cannot literally
 * share OwnershipChecker.cpp's C++ definitions across that boundary -- the
 * same reason LockDisciplineChecker.cpp's familyId() re-derives, rather
 * than imports, OwnedConstructChecker::familyId()'s own logic. A
 * family-only key is exactly what errno_grounds below needs: whether
 * *some* call or assignment on this path could have set errno at all is a
 * fact about the path, not about any one call's return value or the
 * assignment's own MemRegion. */
enum class CarrierCapabilityKind : unsigned char {
  Unknown,
  Absent,
  Linear,
  Duplicable
};
REGISTER_MAP_WITH_PROGRAMSTATE(ThreadCapabilityMap, const IdentifierInfo *,
                               CarrierCapabilityKind)

namespace {

using ntlibc::algebra::applyTokenOperation;
using ntlibc::algebra::contains;
using ntlibc::algebra::TokenEvent;
using ntlibc::algebra::TokenOperation;
using ntlibc::algebra::TokenState;
using ntlibc::algebra::TokenTransition;

constexpr unsigned SlotDiagnosed = 0;
constexpr unsigned SlotLastCapable = 1;

/* A third CallSlot key, distinct from the two per-path facts described
 * above: the setter statement a branch condition this checker can
 * prove is a genuine failure check -- `!<capable-call>`, or one of the
 * handful of `<capable-call> <cmp> <constant>` shapes
 * classifyComparison() below recognises as this codebase's own
 * established conventions -- *would* diagnose if the branch actually
 * taken turns out to be the failure one. Unlike SlotDiagnosed/
 * SlotLastCapable, this one is never read back by the mismatch check
 * itself -- it is purely a hand-off from checkBranchCondition to
 * evalAssume, alive for exactly the one branch decision in between,
 * cleared by whichever of the two consumes it first (or by the next
 * checkBranchCondition, if evalAssume is for some reason never called
 * for this exact decision -- e.g. a `!f` or `fd < 0` that is evaluated
 * but never actually used to decide a branch, such as being merely
 * assigned to a bool).
 *
 * Every comparison this checker cannot place in one of those known
 * conventions keeps the old, direction-agnostic unconditional
 * diagnoseIfSetter() treatment instead of going through this slot at
 * all -- guessing which side of an unfamiliar comparison is "failure"
 * wrong would silently turn a real violation into a miss, which is
 * worse than this slot's own narrower false positives it exists to
 * remove. */
constexpr unsigned SlotPendingFailOnTrueDiagnosis = 2;
/* The mirror image of the slot above, reserved for any future
 * classifyComparison() convention whose failure outcome is the
 * *false* branch rather than the true one (none currently exist --
 * every convention classifyComparison() recognises today happens to
 * be OnTrueOutcome, including after negating `>`/`>=` back to `<`/`<=`
 * -- but the Diagnosed-commit side in evalAssume is exactly as cheap
 * to keep symmetric as to special-case away). Kept as a distinct slot
 * rather than a polarity flag alongside SlotPendingFailOnTrueDiagnosis
 * so evalAssume can stay a plain "does this slot exist" check in both
 * directions rather than unpacking a pair. */
constexpr unsigned SlotPendingFailOnFalseDiagnosis = 3;

static TokenState threadTokenState(ProgramStateRef State,
                                   const IdentifierInfo *Family) {
  const CarrierCapabilityKind *Kind = State->get<ThreadCapabilityMap>(Family);
  if (!Kind)
    return TokenState::Absent;
  switch (*Kind) {
  case CarrierCapabilityKind::Unknown:
    return TokenState::Unknown;
  case CarrierCapabilityKind::Absent:
    return TokenState::Absent;
  case CarrierCapabilityKind::Linear:
    return TokenState::Linear;
  case CarrierCapabilityKind::Duplicable:
    return TokenState::Duplicable;
  }
  return TokenState::Unknown;
}

static CarrierCapabilityKind fromTokenState(TokenState State) {
  switch (State) {
  case TokenState::Unknown:
    return CarrierCapabilityKind::Unknown;
  case TokenState::Absent:
    return CarrierCapabilityKind::Absent;
  case TokenState::Linear:
    return CarrierCapabilityKind::Linear;
  case TokenState::Duplicable:
    return CarrierCapabilityKind::Duplicable;
  }
  return CarrierCapabilityKind::Unknown;
}

/* errno_grounds is granted Duplicable -- never consumed, never granted
 * Linear -- by every capable call and every direct assignment alike: once
 * *some* origin has been established on this path it stays established,
 * the same "idempotent, never contradicts a second grant" character
 * GrantDuplicable already has for a genuinely duplicable value token. The
 * transition's own Events are unreachable here (Duplicable-on-Duplicable
 * and Absent-on-first-grant are both the event-free cases) and are
 * discarded rather than threaded through a caller that has nothing to do
 * with them. */
static ProgramStateRef grantThreadDuplicable(ProgramStateRef State,
                                             const IdentifierInfo *Family) {
  TokenTransition Transition =
      applyTokenOperation(threadTokenState(State, Family),
                          TokenOperation::GrantDuplicable);
  return State->set<ThreadCapabilityMap>(Family,
                                         fromTokenState(Transition.After));
}

/* The TU-wide family this checker's one thread-scoped fact is filed under;
 * its name is not this checker's own invention -- see include/errno.h's
 * requires_thread_token(errno_grounds) and include/unistd.h's
 * grants_thread_token(errno_grounds), the two real annotations
 * hasThreadTokenAnnotation() below reads it back out of. */
static const IdentifierInfo *errnoGroundsFamily(ASTContext &Context) {
  return &Context.Idents.get("errno_grounds");
}

/* Mirrors OwnershipChecker.cpp's own withtok:/consume:/grant:/drop:
 * parsing idiom (e.g. its checkPreCall: `Text.consume_front("withtok:") &&
 * Text == ReturnedFamily`): a function-level annotate() attribute, on any
 * of Function's redeclarations, whose text is exactly Prefix followed by
 * FamilyName. */
static bool hasThreadTokenAnnotation(const FunctionDecl *Function,
                                     StringRef Prefix, StringRef FamilyName) {
  if (!Function)
    return false;
  for (const FunctionDecl *Redecl : Function->redecls())
    for (const AnnotateAttr *Attribute :
        Redecl->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attribute->getAnnotation();
      if (Text.consume_front(Prefix) && Text == FamilyName)
        return true;
    }
  return false;
}

/* Like hasThreadTokenAnnotation above, but for a caller (the
 * requires_thread_token(errno_grounds) lookup in
 * checkPreStmt(UnaryOperator)) that does not yet know the family name and
 * needs to read it out of the annotation itself, the same way
 * OwnershipChecker.cpp's own withtok(...) parsing resolves its family
 * name from the annotation text rather than from a checker-side constant. */
static const IdentifierInfo *threadTokenFamilyFromAnnotation(
    const FunctionDecl *Function, StringRef Prefix) {
  if (!Function)
    return nullptr;
  for (const FunctionDecl *Redecl : Function->redecls())
    for (const AnnotateAttr *Attribute :
        Redecl->specific_attrs<AnnotateAttr>()) {
      StringRef Text = Attribute->getAnnotation();
      if (Text.consume_front(Prefix) && !Text.empty())
        return &Function->getASTContext().Idents.get(Text);
    }
  return nullptr;
}

class ErrnoDisciplineChecker
    : public Checker<check::PostCall, check::PreStmt<BinaryOperator>,
                     check::PreStmt<UnaryOperator>, check::BranchCondition,
                     eval::Assume, check::BeginFunction> {
  mutable std::unique_ptr<BugType> BT;

  /* Functions this codebase's own implementation proves capable of
   * setting errno as a side effect, grounded against this tree (not
   * glibc convention) via `grep -rn "errno = " src/` and each callee's
   * own doc comment in src/internal/libc.h.  close() and munmap() are
   * kept as the two POSIX-named calls the CERT ERR30-C "cleanup after a
   * diagnosed failure" pattern this checker looks for actually uses --
   * close() is recognised through its own include/unistd.h
   * grants_thread_token(errno_grounds) annotation instead of appearing in
   * Names below, demonstrating that a real header annotation, not just
   * this hardcoded list, can supply a capable call. */
  static bool isErrnoCapable(const CallEvent &Call) {
    const auto *Function = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
    if (!Function || !Function->getIdentifier())
      return false;
    if (hasThreadTokenAnnotation(Function, "grants_thread_token:",
                                 "errno_grounds"))
      return true;
    static constexpr llvm::StringLiteral Names[] = {
        // NTSTATUS -> errno mapper
        "__set_errno_status",
        // path translation
        "__ntpath", "__ntpath_native", "__ntpath_at", "__ntpath_at_native",
        // open/unlink/rmdir/stat internals
        "__open_handle", "__unlink_at", "__fstat_handle",
        // descriptor table
        "__fd_alloc", "__fd_install", "__fd_get", "__fd_handle",
        "__fd_pos_save", "__fd_runtime_data",
        // POSIX namespace resolver
        "__vfs_resolve_at", "__vfs_open_dir", "__vfs_stat",
        // process/exec and WSL mode-attribute helpers
        "__spawn", "__lxmod_set", "__find_program", "__plat_dup",
        // alertable wait shared by nanosleep/sleep/clock_nanosleep
        "__alertable_delay", "wait_handle", "sem_trywait",
        // RLIMIT_FSIZE enforcement
        "__fsize_exceeded",
        // UTF-8/UTF-16 conversion
        "__utf8_to_utf16", "__utf16_to_utf8_buf",
        // AFD/Winsock helpers, dirstream cursor, handle-to-path resolver
        "__afd_open", "__afd_addr_from_sockaddr", "__dirstream_next",
        "__handle_path", "raw_mmap",
        // munmap(): the second of the two POSIX-named "cleanup after a
        // diagnosed failure" calls this checker's pattern actually uses;
        // see close()'s own grants_thread_token(errno_grounds) above for
        // the other one
        "munmap",
        // remaining POSIX entries, each confirmed directly in this
        // tree's own src/unistd, src/fcntl/open.c and src/stat
        "read", "write", "open", "unlink", "mkdir", "mkfifo", "stat",
        "lstat", "statvfs", "nftw", "rmdir", "readlink", "utimensat",
        "chmod", "realpath", "link", "symlink", "isatty", "getcwd",
        // stdio entry points and the utility wrappers preserving them
        "fopen", "fread", "fwrite", "fclose", "fflush",
        "cksum_stream", "read_all", "write_all", "link_one", "mkdir_p",
        // src/stdio/buf.c's shared fd-and-buffer-position seek helper
        "__file_seek",
        // src/dirent/opendir.c: every return path sets errno, either via
        // open()/__fd_get() (both already above) or its own explicit
        // ENOMEM/ENOTDIR assignment
        "opendir", "fdopendir",
        // src/socket/linux/plat_socket.c and src/socket/nt/plat_socket.c:
        // every __plat_socketpair() implementation sets errno on its
        // only failure return
        "__plat_socketpair",
        // src/util/spool.c: every return path sets errno, either via a
        // capable call already above (open()/mkdir()) or its own explicit
        // ENOENT/ENAMETOOLONG assignment
        "__spool_dir", "__spool_crontab_path",
        // src/dlfcn/linux/plat_dlfcn.c's open_needed(): every return path
        // sets errno, either via open() (already above) or its own
        // explicit ENAMETOOLONG assignment
        "open_needed",
    };
    StringRef Name = Function->getName();
    for (StringRef Candidate : Names)
      if (Name == Candidate)
        return true;
    return false;
  }

  /* The FunctionDecl `*E` calls, if E is a call to __errno_location and
   * nothing else -- shared by isErrnoLocationCall below and by the
   * requires_thread_token(errno_grounds) lookup in checkPreStmt(UnaryOperator),
   * which needs the actual declaration (to read its annotations back off),
   * not just a yes/no answer. */
  static const FunctionDecl *errnoLocationDecl(const Expr *E) {
    const auto *Call = dyn_cast_or_null<CallExpr>(E->IgnoreParenImpCasts());
    if (!Call)
      return nullptr;
    const FunctionDecl *Function = Call->getDirectCallee();
    return Function && Function->getIdentifier() &&
                   Function->getName() == "__errno_location"
               ? Function
               : nullptr;
  }

  static bool isErrnoLocationCall(const Expr *E) {
    return errnoLocationDecl(E) != nullptr;
  }

  /* errno expands to `(*__errno_location())`; this recognises that
   * expansion regardless of which macro instantiated it. */
  static bool isErrnoDeref(const UnaryOperator *Op) {
    return Op->getOpcode() == UO_Deref &&
           isErrnoLocationCall(Op->getSubExpr());
  }

  /* True when Node is exactly the left-hand side of a plain (non-compound)
   * assignment -- a write that gives errno a fresh, trusted origin, not a
   * read this checker should evaluate.
   *
   * The `errno` macro itself is `(*__errno_location())` -- note the
   * macro's own parentheses -- so the UnaryOperator's immediate syntactic
   * parent is a ParenExpr, not the BinaryOperator, for every use of the
   * macro. Walk up through any wrapping ParenExpr nodes before checking
   * for the assignment, or every `errno = ...;` misses its own trusted
   * origin and both the assignment and the next read falsely report as
   * unproven. */
  static bool isAssignmentTarget(const UnaryOperator *Node,
                                 CheckerContext &C) {
    DynTypedNode Current = DynTypedNode::create(*Node);
    for (;;) {
      auto Parents = C.getASTContext().getParents(Current);
      if (Parents.size() != 1)
        return false;
      if (const auto *Paren = Parents[0].get<ParenExpr>()) {
        Current = DynTypedNode::create(*Paren);
        continue;
      }
      const auto *Parent = Parents[0].get<BinaryOperator>();
      return Parent && Parent->getOpcode() == BO_Assign &&
             Parent->getLHS()->IgnoreParens() == Node;
    }
  }

  /* True, returning the target VarDecl, when Node (an errno read) is
   * exactly the right-hand side of `V = errno;` or the initializer of
   * `TYPE V = errno;`.  Unlike isAssignmentTarget's walk, this one also
   * has to step over the ImplicitCastExpr (LValueToRValue) the compiler
   * inserts wherever an lvalue is used as an rvalue, since here errno is
   * being *read*, not assigned to. Capturing errno's current value into
   * a fresh local this way -- the textbook "preserve errno across an
   * unrelated cleanup" idiom this tree uses throughout, e.g.
   * src/process/spawn_file_actions.c's fa_push() and every shm.c helper
   * that frees a temporary afterward -- never itself misinterprets
   * errno as meaning anything in particular, so it needs no proof of a
   * preceding capable call: the risk this checker exists to catch would
   * only be in a *later* semantic use of the copy, which is out of
   * scope for a checker whose obligations are about the literal `errno`
   * expression. */
  static const VarDecl *savedInto(const UnaryOperator *Node,
                                  CheckerContext &C) {
    DynTypedNode Current = DynTypedNode::create(*Node);
    for (;;) {
      auto Parents = C.getASTContext().getParents(Current);
      if (Parents.size() != 1)
        return nullptr;
      if (const auto *Paren = Parents[0].get<ParenExpr>()) {
        Current = DynTypedNode::create(*Paren);
        continue;
      }
      if (const auto *Cast = Parents[0].get<ImplicitCastExpr>()) {
        Current = DynTypedNode::create(*Cast);
        continue;
      }
      if (const auto *BO = Parents[0].get<BinaryOperator>()) {
        if (BO->getOpcode() != BO_Assign)
          return nullptr;
        const auto *DRE =
            dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenCasts());
        return DRE ? dyn_cast<VarDecl>(DRE->getDecl()) : nullptr;
      }
      if (const auto *VD = Parents[0].get<VarDecl>())
        return VD;
      return nullptr;
    }
  }

  /* True when Node (an errno read) is one side of a `==`/`!=` comparison
   * whose other side names a variable savedInto() has already recorded
   * -- CERT ERR30-C's own "did errno change since I last looked"
   * pattern (src/ftw/ftw.c's report(): `saved_errno = errno; ...; if (r
   * == -1 && errno == saved_errno) errno = EACCES;`), which does not
   * assert that any particular call set errno to anything: it only asks
   * whether the value moved, which is well-defined regardless. */
  static bool comparedToSavedErrno(const UnaryOperator *Node,
                                   CheckerContext &C,
                                   ProgramStateRef State) {
    DynTypedNode Current = DynTypedNode::create(*Node);
    for (;;) {
      auto Parents = C.getASTContext().getParents(Current);
      if (Parents.size() != 1)
        return false;
      if (const auto *Paren = Parents[0].get<ParenExpr>()) {
        Current = DynTypedNode::create(*Paren);
        continue;
      }
      if (const auto *Cast = Parents[0].get<ImplicitCastExpr>()) {
        Current = DynTypedNode::create(*Cast);
        continue;
      }
      const auto *BO = Parents[0].get<BinaryOperator>();
      if (!BO || (BO->getOpcode() != BO_EQ && BO->getOpcode() != BO_NE))
        return false;
      for (const Expr *Side : {BO->getLHS(), BO->getRHS()}) {
        const auto *DRE = dyn_cast<DeclRefExpr>(Side->IgnoreParenImpCasts());
        if (!DRE)
          continue;
        const auto *VD = dyn_cast<VarDecl>(DRE->getDecl());
        if (!VD)
          continue;
        const MemRegion *R =
            State->getLValue(VD, C.getLocationContext()).getAsRegion();
        if (R && State->get<SavedErrnoVar>(R))
          return true;
      }
      return false;
    }
  }

  /* True when Node (an errno read) is either side of a `errno ? errno :
   * <default>` conditional -- an idiom this tree uses across at least
   * ten call sites (src/util/cksum.c, src/util/tsort.c,
   * src/dirent/scandir.c, src/process/posix_spawn.c, and every
   * src/ipc/nt/plat_{shm,msg,sem}.c) to fall back to a fixed default
   * (ENOMEM, EIO, ...) precisely when errno is *not* known to have been
   * set by whatever failed: unlike every other read this checker
   * proves, this one is not claiming the value reflects any particular
   * call's failure at all, it is asking "is there a nonzero value here
   * worth trusting, and if not, use a sane default instead" -- a
   * strictly more defensive stance than trusting errno outright, which
   * is exactly why it needs no proof of a preceding capable call: the
   * caller has already priced in the possibility that nothing set it. */
  static bool selfGuardedByErrnoTernary(const UnaryOperator *Node,
                                        CheckerContext &C) {
    auto IsErrnoDeref = [](const Expr *E) {
      const auto *UO = dyn_cast<UnaryOperator>(E->IgnoreParenImpCasts());
      return UO && isErrnoDeref(UO);
    };
    DynTypedNode Current = DynTypedNode::create(*Node);
    for (;;) {
      auto Parents = C.getASTContext().getParents(Current);
      if (Parents.size() != 1)
        return false;
      if (const auto *Paren = Parents[0].get<ParenExpr>()) {
        Current = DynTypedNode::create(*Paren);
        continue;
      }
      if (const auto *Cast = Parents[0].get<ImplicitCastExpr>()) {
        Current = DynTypedNode::create(*Cast);
        continue;
      }
      const auto *CO = Parents[0].get<ConditionalOperator>();
      if (!CO)
        return false;
      return IsErrnoDeref(CO->getCond()) && IsErrnoDeref(CO->getTrueExpr());
    }
  }

  /* True when Node (an errno read) is the right-hand operand of a comma
   * expression whose left-hand operand is exactly CapableCall --
   * src/thread/semaphore.c's sem_open(): `saved = NT_SUCCESS(st) ? EIO :
   * (__set_errno_status(st), errno);`.  There is nothing "intervening"
   * between a capable call and a read that is syntactically part of the
   * very same expression -- unlike the two-statement `__set_errno_status
   * (5); if (errno == 9)` shape this checker's Diagnosed/LastCapable
   * mismatch exists to catch, where a second statement could run first,
   * this read cannot execute without CapableCall having just executed
   * immediately before it, in the same expression, with nothing able to
   * run in between. */
  static bool isCommaAfterCall(const UnaryOperator *Node, CheckerContext &C,
                               const Stmt *CapableCall) {
    DynTypedNode Current = DynTypedNode::create(*Node);
    for (;;) {
      auto Parents = C.getASTContext().getParents(Current);
      if (Parents.size() != 1)
        return false;
      if (const auto *Paren = Parents[0].get<ParenExpr>()) {
        Current = DynTypedNode::create(*Paren);
        continue;
      }
      if (const auto *Cast = Parents[0].get<ImplicitCastExpr>()) {
        Current = DynTypedNode::create(*Cast);
        continue;
      }
      const auto *BO = Parents[0].get<BinaryOperator>();
      if (!BO || BO->getOpcode() != BO_Comma)
        return false;
      return BO->getLHS()->IgnoreParenCasts() == CapableCall;
    }
  }

  /* Walks up from S to the nearest ancestor that is itself a direct
   * child of a CompoundStmt (a `{ ... }` block) -- i.e. the full
   * statement S sits inside, whatever expression form S itself takes. */
  static const Stmt *enclosingBlockStatement(const Stmt *S,
                                             CheckerContext &C) {
    DynTypedNode Current = DynTypedNode::create(*S);
    for (;;) {
      auto Parents = C.getASTContext().getParents(Current);
      if (Parents.size() != 1)
        return nullptr;
      if (Parents[0].get<CompoundStmt>())
        return Current.get<Stmt>();
      const Stmt *ParentStmt = Parents[0].get<Stmt>();
      if (!ParentStmt)
        return nullptr;
      Current = DynTypedNode::create(*ParentStmt);
    }
  }

  /* True when Node (an errno read) is, after unwrapping parens and
   * casts, the direct operand of a `return` statement -- the value is
   * being handed back to the caller opaquely, the same "not
   * interpreted, just carried" character as savedInto's capture into a
   * local, rather than compared against a specific constant the way a
   * genuine "does this match the call I diagnosed" check
   * (checkPreStmt(BinaryOperator)'s whole reason to exist) would.  This
   * is what keeps isImmediatelyAfter below from also excusing the
   * fixture's real stale_after_cleanup() bug: `if (errno == 9) return
   * -1;` reads errno to compare it against a constant that only makes
   * sense as close()'s own diagnosed code, not `return errno;` handing
   * back whatever the immediately preceding call put there. */
  static bool isReturnedDirectly(const UnaryOperator *Node,
                                 CheckerContext &C) {
    DynTypedNode Current = DynTypedNode::create(*Node);
    for (;;) {
      auto Parents = C.getASTContext().getParents(Current);
      if (Parents.size() != 1)
        return false;
      if (const auto *Paren = Parents[0].get<ParenExpr>()) {
        Current = DynTypedNode::create(*Paren);
        continue;
      }
      if (const auto *Cast = Parents[0].get<ImplicitCastExpr>()) {
        Current = DynTypedNode::create(*Cast);
        continue;
      }
      return Parents[0].get<ReturnStmt>() != nullptr;
    }
  }

  /* True when Later's own enclosing block-statement is the literal next
   * statement, in the same `{ ... }` block, after Earlier's -- e.g.
   * src/process/posix_spawn.c's do_action():
   * `if (!NT_SUCCESS(st)) { __set_errno_status(st); return errno; }`.
   * Symmetric with isCommaAfterCall above for the two-statement form of
   * the same idiom: nothing can execute between a capable call and the
   * very next statement in its own block, so a stale Diagnosed slot
   * left over from an unrelated earlier branch (a different switch
   * case, a previous loop iteration inlined into the same frame) cannot
   * actually have anything intervene here either.  Only paired with
   * isReturnedDirectly above at the call site below, not sufficient by
   * itself -- adjacency alone does not distinguish this from
   * stale_after_cleanup()'s real bug, which is exactly as adjacent. */
  static bool isImmediatelyAfter(const Stmt *Earlier, const Stmt *Later,
                                 CheckerContext &C) {
    const Stmt *EarlierBlock = enclosingBlockStatement(Earlier, C);
    const Stmt *LaterBlock = enclosingBlockStatement(Later, C);
    if (!EarlierBlock || !LaterBlock || EarlierBlock == LaterBlock)
      return false;
    auto Parents =
        C.getASTContext().getParents(DynTypedNode::create(*EarlierBlock));
    if (Parents.size() != 1)
      return false;
    const auto *CS = Parents[0].get<CompoundStmt>();
    if (!CS)
      return false;
    const Stmt *Prev = nullptr;
    for (const Stmt *Child : CS->body()) {
      if (Prev == EarlierBlock && Child == LaterBlock)
        return true;
      Prev = Child;
    }
    return false;
  }

  static std::string calleeName(const Stmt *CallStmt) {
    if (!CallStmt)
      return "nothing";
    if (const auto *Call = dyn_cast_or_null<CallExpr>(CallStmt)) {
      if (const FunctionDecl *Function = Call->getDirectCallee())
        if (Function->getIdentifier())
          return Function->getNameAsString();
      return "<call>";
    }
    return "a direct errno assignment";
  }

  /* True when Setter is a call to one of the four POSIX I/O primitives
   * whose return value is a byte count, not a status code -- fread/
   * fwrite (already errno-capable by name) and read/write (ditto).
   * Every comparison classifyComparison() would otherwise recognise
   * (`< 0`, `== 0`, `!= 0`, `> 0`, ...) is ambiguous for exactly these
   * four regardless of operator: 0 means "nothing transferred", which
   * read()/fread() can reach on a completely clean, non-error EOF
   * (disambiguated separately, by ferror() or a second read, never by
   * the count itself), the same way src/util/cksum.c cksum_stream()'s
   * `while ((n = fread(...)) > 0)` and src/util/get.c
   * read_whole_file()'s `if (got == 0) break;` both do. Recognising
   * this by callee identity rather than trying to read the intent out
   * of the comparison's own shape is what keeps `close(fd) < 0` (a
   * real status code, where `< 0` unambiguously means failure) fully
   * intact while still refusing to guess here. */
  static bool isByteCountCall(const Stmt *Setter) {
    std::string Name = calleeName(Setter);
    return Name == "fread" || Name == "fwrite" || Name == "read" ||
          Name == "write";
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

  static std::string context(CheckerContext &C) {
    const Decl *Current = C.getLocationContext()->getDecl();
    if (const auto *Named = dyn_cast_or_null<NamedDecl>(Current))
      return Named->getQualifiedNameAsString();
    return Current ? Current->getDeclKindName() : "unknown";
  }

  void report(const std::string &Reason, const Stmt *Statement,
              ProgramStateRef State, CheckerContext &C) const {
    if (!Statement)
      return;
    ExplodedNode *Node = C.generateNonFatalErrorNode(State);
    if (!Node)
      return;
    if (!BT)
      BT = std::make_unique<BugType>(this, "Unproven errno discipline",
                                     categories::LogicError);
    const SourceManager &SM = C.getSourceManager();
    std::string Message =
        (llvm::Twine(Reason) + "; origin '" +
         SM.getFilename(SM.getExpansionLoc(Statement->getBeginLoc())) +
         "'; context '" + context(C) + "'; expression '" + text(Statement, C) +
         "'")
            .str();
    auto Report = std::make_unique<PathSensitiveBugReport>(*BT, Message, Node);
    Report->addRange(Statement->getSourceRange());
    C.emitReport(std::move(Report));
  }

public:
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    if (!isErrnoCapable(Call))
      return;
    const Stmt *Statement = Call.getOriginExpr();
    if (!Statement)
      return;
    ProgramStateRef State =
        C.getState()->set<CallSlot>(SlotLastCapable, Statement);
    SymbolRef Symbol = Call.getReturnValue().getAsSymbol(true);
    if (Symbol)
      State = State->set<ErrnoSetterOf>(Symbol, Statement);
    State = grantThreadDuplicable(State,
                                  errnoGroundsFamily(C.getASTContext()));
    C.addTransition(State);
  }

  /* Shared by both checkPreStmt overloads below: if Symbol is a capable
   * call's tracked return value, mark that call Diagnosed. Used for
   * `<capable-call> <cmp> <sentinel>` (BinaryOperator) and for
   * `!<capable-call>` (UnaryOperator, UO_LNot) -- the pointer-returning
   * idiom (`if (!fopen(...))`) that a bare comparison never sees since it
   * has no BinaryOperator of its own. */
  static void diagnoseIfSetter(SymbolRef Symbol, CheckerContext &C) {
    if (!Symbol)
      return;
    ProgramStateRef State = C.getState();
    const Stmt *const *Setter = State->get<ErrnoSetterOf>(Symbol);
    if (!Setter)
      return;
    C.addTransition(State->set<CallSlot>(SlotDiagnosed, *Setter));
  }

  /* Which, if either, outcome of a `<capable-call> <cmp> <constant>`
   * comparison this checker can prove means the call under test
   * failed. Undetermined keeps the old, direction-agnostic
   * diagnoseIfSetter() treatment (guessing wrong would silently turn a
   * real ERR30-C violation into a miss); OnTrueOutcome/OnFalseOutcome
   * feed checkBranchCondition/evalAssume's branch-sensitive diagnosis;
   * NeitherOutcome recognises a comparison that -- unlike the other
   * three -- this checker can positively prove is *not* a failure
   * check of any kind in either direction, so it should not diagnose
   * anything on either branch (not even the old unconditional
   * treatment), rather than merely lacking an opinion. */
  enum class FailureOutcome { Undetermined, OnTrueOutcome, OnFalseOutcome,
                             NeitherOutcome };

  /* Shared by checkPreStmt(BinaryOperator) below and by
   * checkBranchCondition further down: given a `<capable-call> <cmp>
   * <constant>` comparison (Symbol already established on one side,
   * ConstVal a compile-time constant on the other -- both callers' own
   * job to establish before calling this), classify it against this
   * codebase's own established conventions:
   *
   *   - a POSIX `< 0` (or `<= -1`) integer return, or a `!= 0`
   *     0-means-success return code (src/util/admin.c create_one()'s
   *     `fclose(rest) != 0`): OnTrueOutcome:
   *   - a `== -1` or NULL/0 pointer check: also OnTrueOutcome (the
   *     pointer-vs-integer split only matters for `== 0`/`!= 0`, where
   *     a null pointer and a 0 return code mean opposite things);
   *   - a `>`/`>=` bound against 0 or 1 on a non-pointer: NeitherOutcome.
   *     This is deliberately not "guess the opposite of `<`/`<="`:
   *     src/util/cksum.c cksum_stream()'s own `while ((n = fread(...))
   *     > 0)` is exactly this shape and n > 0 means "some bytes were
   *     read", not "the call succeeded" in any sense that licenses
   *     trusting errno on the loop's *other* exit either -- fread's 0
   *     return is separately EOF-or-error, disambiguated by ferror(),
   *     never by this comparison. Suppressing diagnosis entirely here
   *     (rather than leaving it Undetermined, which would fall back to
   *     the old unconditional both-branches treatment) is what keeps a
   *     stale "fread" diagnosis from leaking out of a byte-counting
   *     loop like this one into the caller's own, unrelated failure
   *     check by way of interprocedural inlining;
   *   - everything else (`==`/`!=` against a positive constant, or
   *     against 0 for a non-pointer where cksum_stream's own
   *     ambiguity above generalises) is genuinely Undetermined. */
  static FailureOutcome classifyComparison(BinaryOperatorKind Op,
                                           bool SymbolOnLHS, SVal ConstVal,
                                           QualType SymbolType) {
    if (!SymbolOnLHS) {
      /* Normalise so Op always reads as "Symbol Op Constant": `0 >
       * fd` is the same claim as `fd < 0`. */
      switch (Op) {
      case BO_LT: Op = BO_GT; break;
      case BO_LE: Op = BO_GE; break;
      case BO_GT: Op = BO_LT; break;
      case BO_GE: Op = BO_LE; break;
      default: break;
      }
    }
    bool IsPointer = SymbolType->isPointerType();
    bool IsZero = ConstVal.isZeroConstant();
    auto ConstInt = ConstVal.getAs<nonloc::ConcreteInt>();
    bool IsNegative = ConstInt && ConstInt->getValue().isNegative();
    bool IsZeroOrOne = IsZero || (ConstInt && ConstInt->getValue() == 1);
    switch (Op) {
    case BO_LT:
    case BO_LE:
      if (!IsPointer && (IsZero || IsNegative))
        return FailureOutcome::OnTrueOutcome;
      return FailureOutcome::Undetermined;
    case BO_GT:
    case BO_GE:
      if (!IsPointer && IsZeroOrOne)
        return FailureOutcome::NeitherOutcome;
      return FailureOutcome::Undetermined;
    case BO_EQ:
      if (IsPointer && IsZero)
        return FailureOutcome::OnTrueOutcome;
      if (!IsPointer && IsNegative)
        return FailureOutcome::OnTrueOutcome;
      if (!IsPointer && IsZero)
        /* `rc == 0` for an integer return code is a success check --
         * e.g. src/mman/shm.c ensure_namespace()'s own retry loop
         * (`unlink(path) == 0`) and any `stat()`/`fstat() == 0` --
         * so the call only failed on the *false* outcome. Sound now
         * that isByteCountCall() above (checked by both call sites
         * before this function is even consulted) already routes
         * fread/fwrite/read/write around this entirely: those are the
         * only callees for which "0" is not a clean success/failure
         * split, which is the sole reason this case was previously
         * left Undetermined. */
        return FailureOutcome::OnFalseOutcome;
      return FailureOutcome::Undetermined;
    case BO_NE:
      if (!IsPointer && IsZero)
        return FailureOutcome::OnTrueOutcome;
      return FailureOutcome::Undetermined;
    default:
      return FailureOutcome::Undetermined;
    }
  }

  /* Recognise `<capable-call> <cmp> <sentinel>` (and the transitive form
   * through a variable the call's result was copied into, which the
   * engine's own symbolic execution already resolves to the same
   * symbol) as "the code is diagnosing this call's failure" -- CERT
   * ERR30-C's precondition for trusting errno afterward.
   *
   * "<sentinel>" is the operative word this checker's own comment above
   * already used, and it means what it says: the *other* side of the
   * comparison must be a compile-time constant (0, -1, NULL, ...), not
   * an arbitrary runtime value. Without that restriction, a completely
   * unrelated comparison like src/util/awk.c load_progfiles()'s `if (f
   * != stdin) fclose(f);` -- deciding whether to close a stream, not
   * whether a call failed -- also "diagnoses" f's setter (fopen)
   * whether or not fopen actually failed, leaving a stale Diagnosed
   * that then collides with fclose()'s own, unrelated LastCapable the
   * next time any errno read anywhere later in the function runs. A
   * real sentinel comparison (`fd < 0`, `rc == -1`, `p == NULL`) is
   * unaffected: its other side is always a literal.
   *
   * A comparison classifyComparison can actually place in one of this
   * codebase's own conventions (OnTrueOutcome/OnFalseOutcome) is *not*
   * diagnosed here at all -- checkBranchCondition/evalAssume below
   * handle those branch-aware, for the same reason
   * checkPreStmt(UnaryOperator)'s old `!X` handling moved there: this
   * callback fires for every occurrence of the comparison, including
   * ones never used to decide a branch, which is the wrong granularity
   * for a fact that must only survive into whichever branch actually is
   * the failure one. A NeitherOutcome comparison (a byte-count `> 0`
   * loop guard, not a failure check at all) is not diagnosed here
   * either, nor by checkBranchCondition -- only a genuinely Undetermined
   * comparison keeps this function's own unconditional treatment. */
  void checkPreStmt(const BinaryOperator *Operation, CheckerContext &C) const {
    switch (Operation->getOpcode()) {
    case BO_LT:
    case BO_LE:
    case BO_GT:
    case BO_GE:
    case BO_EQ:
    case BO_NE:
      break;
    default:
      return;
    }
    SVal LHSVal = C.getSVal(Operation->getLHS());
    SVal RHSVal = C.getSVal(Operation->getRHS());
    SymbolRef Symbol = nullptr;
    bool SymbolOnLHS = true;
    if (RHSVal.isConstant()) {
      Symbol = LHSVal.getAsSymbol(true);
      SymbolOnLHS = true;
    }
    if (!Symbol && LHSVal.isConstant()) {
      Symbol = RHSVal.getAsSymbol(true);
      SymbolOnLHS = false;
    }
    if (!Symbol)
      return;
    if (const Stmt *const *Setter = C.getState()->get<ErrnoSetterOf>(Symbol))
      if (isByteCountCall(*Setter))
        return; /* ambiguous for a byte count regardless of operator --
                  * see isByteCountCall's own comment */
    FailureOutcome Outcome = classifyComparison(
        Operation->getOpcode(), SymbolOnLHS, SymbolOnLHS ? RHSVal : LHSVal,
        SymbolOnLHS ? Operation->getLHS()->getType()
                    : Operation->getRHS()->getType());
    if (Outcome != FailureOutcome::Undetermined)
      return; /* handled by checkBranchCondition/evalAssume instead, or
                * (NeitherOutcome) not a failure check at all */
    diagnoseIfSetter(Symbol, C);
  }

  void checkPreStmt(const UnaryOperator *Operation, CheckerContext &C) const {
    /* `if (!fopen(...))` etc.: the idiomatic C null-check for a
     * pointer-returning capable call diagnoses that call's failure
     * exactly as `== 0`/`== NULL` already does above -- same trust
     * boundary, just reached through negation instead of an explicit
     * comparison against zero. Unlike that BinaryOperator form, this
     * one is handled entirely by checkBranchCondition/evalAssume below
     * now (see their own comments), not here: `!X` fires for every
     * UnaryOperator in the function regardless of whether it is ever
     * used as a branch condition at all, which is exactly the wrong
     * granularity for a fact that must only survive into the specific
     * branch where the call actually failed. */
    if (Operation->getOpcode() == UO_LNot)
      return;
    if (!isErrnoDeref(Operation))
      return;
    ProgramStateRef State = C.getState();
    if (isAssignmentTarget(Operation, C)) {
      /* A direct `errno = ...` write is its own trusted origin: it
       * outranks whatever call was previously under diagnosis, and
       * establishes errno_grounds on its own merits. */
      State = State->remove<CallSlot>(SlotDiagnosed);
      State = State->remove<CallSlot>(SlotLastCapable);
      State = grantThreadDuplicable(State,
                                    errnoGroundsFamily(C.getASTContext()));
      C.addTransition(State);
      return;
    }
    if (const VarDecl *VD = savedInto(Operation, C)) {
      const MemRegion *R =
          State->getLValue(VD, C.getLocationContext()).getAsRegion();
      if (R)
        C.addTransition(State->set<SavedErrnoVar>(R, true));
      return;
    }
    if (comparedToSavedErrno(Operation, C, State))
      return;
    if (selfGuardedByErrnoTernary(Operation, C))
      return;
    const Stmt *const *Diagnosed = State->get<CallSlot>(SlotDiagnosed);
    const Stmt *const *LastCapable = State->get<CallSlot>(SlotLastCapable);
    if (Diagnosed) {
      if (!LastCapable || *LastCapable != *Diagnosed) {
        if (LastCapable &&
            (isCommaAfterCall(Operation, C, *LastCapable) ||
             (isReturnedDirectly(Operation, C) &&
              isImmediatelyAfter(*LastCapable, Operation, C))))
          return;
        std::string Reason =
            "errno read after an intervening call to '" +
            calleeName(LastCapable ? *LastCapable : nullptr) +
            "' may not reflect '" + calleeName(*Diagnosed) + "'s failure";
        report(Reason, Operation, State, C);
      }
      return;
    }
    if (LastCapable)
      return; /* a capable call happened; its result was just never
               * compared, which is not one of this checker's two proof
               * obligations. */
    /* __errno_location()'s own requires_thread_token(errno_grounds)
     * annotation (include/errno.h) drives this: only a genuine read of
     * *that* declaration's result asks the question at all, and the
     * family it asks about comes from the header, not from a name baked
     * into this checker. A missing annotation silently skips the check,
     * the same "opt-in" character every other ownership.h annotation
     * already has. */
    const FunctionDecl *Location = errnoLocationDecl(Operation->getSubExpr());
    const IdentifierInfo *Family =
        Location ? threadTokenFamilyFromAnnotation(Location,
                                                    "requires_thread_token:")
                 : nullptr;
    if (!Family)
      return;
    /* Require, not RequireAbsent: this checker only ever asks "has some
     * origin been established at all", never "has it been consumed by
     * exactly one read" -- see this file's own top-of-file design note on
     * why a family-only-keyed fact cannot soundly answer the
     * Diagnosed-vs-LastCapable identity question the branch above already
     * settled without it. Discarding the resulting state (rather than
     * committing it via C.addTransition) mirrors LockDisciplineChecker's
     * own checkPreCall: this call proves or disproves a precondition, it
     * never commits a transition. */
    TokenTransition Transition =
        applyTokenOperation(threadTokenState(State, Family),
                            TokenOperation::Require);
    if (contains(Transition.Events, TokenEvent::MissingRequired))
      report("errno is read with no proven prior call or assignment that "
             "could have set it",
             Operation, State, C);
  }

  /* Recognises `!<capable-call>` and the handful of `<capable-call>
   * <cmp> <constant>` shapes classifyComparison() above can place
   * in one of this codebase's own conventions (directly, or through a
   * variable the call's result was copied into) as the condition of
   * the branch currently being decided, and stashes the setter
   * statement in SlotPendingFailOnTrueDiagnosis for evalAssume below to
   * pick up -- never committing SlotDiagnosed itself, unlike the old
   * checkPreStmt(UnaryOperator) handling for `!X` this replaced. The
   * two together are what make the diagnosis branch-sensitive: `if
   * (!f) { ... }`'s `f == 0` true branch is a real diagnosis of f's
   * setter; falling through past a *successful* call (the false
   * branch) is not a diagnosis of anything and must not leave one
   * lying around for some later, unrelated capable call and read to
   * collide with -- exactly the false positive
   * src/dirent/readdir.c's fill()/readdir_r(), src/util/admin.c's
   * create_one() (`fclose(rest) != 0`'s own success falling through to
   * a *second*, unrelated fwrite() diagnosis further down), and every
   * util.c "open one file per loop iteration" main() hit before this
   * fix: a first, successful check has nothing to do with a second,
   * independent call's later failure, but the old unconditional
   * diagnoseIfSetter() could not tell the two apart.
   *
   * Any other branch condition -- including one this checker cannot
   * make sense of, or a determinable comparison never actually
   * diagnosing anything (Symbol not tied to a tracked setter) -- clears
   * a stale pending candidate first, so evalAssume never accidentally
   * resurrects an orphaned one left over from a condition that was not
   * actually this decision's (e.g. one merely assigned to a bool and
   * never branched on at all, which would otherwise leave
   * SlotPendingFailOnTrueDiagnosis set with no matching evalAssume call
   * ever coming along to consume it). */
  void checkBranchCondition(const Stmt *Condition, CheckerContext &C) const {
    ProgramStateRef State =
        C.getState()
            ->remove<CallSlot>(SlotPendingFailOnTrueDiagnosis)
            ->remove<CallSlot>(SlotPendingFailOnFalseDiagnosis);
    const auto *E = dyn_cast<Expr>(Condition);
    E = E ? E->IgnoreParens() : nullptr;
    SymbolRef Symbol = nullptr;
    FailureOutcome Outcome = FailureOutcome::Undetermined;
    if (const auto *UO = E ? dyn_cast<UnaryOperator>(E) : nullptr) {
      if (UO->getOpcode() == UO_LNot) {
        Symbol = C.getSVal(UO->getSubExpr()).getAsSymbol(true);
        Outcome = FailureOutcome::OnTrueOutcome;
      }
    } else if (const auto *BO = E ? dyn_cast<BinaryOperator>(E) : nullptr) {
      switch (BO->getOpcode()) {
      case BO_LT: case BO_LE: case BO_GT: case BO_GE: case BO_EQ: case BO_NE:
        break;
      default:
        BO = nullptr;
      }
      if (BO) {
        SVal LHSVal = C.getSVal(BO->getLHS());
        SVal RHSVal = C.getSVal(BO->getRHS());
        bool SymbolOnLHS = true;
        if (RHSVal.isConstant())
          Symbol = LHSVal.getAsSymbol(true);
        if (!Symbol && LHSVal.isConstant()) {
          Symbol = RHSVal.getAsSymbol(true);
          SymbolOnLHS = false;
        }
        if (Symbol)
          Outcome = classifyComparison(
              BO->getOpcode(), SymbolOnLHS, SymbolOnLHS ? RHSVal : LHSVal,
              SymbolOnLHS ? BO->getLHS()->getType() : BO->getRHS()->getType());
        if (Outcome == FailureOutcome::Undetermined ||
            Outcome == FailureOutcome::NeitherOutcome)
          Symbol = nullptr; /* Undetermined: checkPreStmt(BinaryOperator)'s
                              * own unconditional path already handled
                              * this one. NeitherOutcome: not a failure
                              * check in either direction (a byte-count
                              * loop guard) -- nothing to stash either
                              * way. */
      }
    }
    if (Symbol) {
      if (const Stmt *const *Setter = State->get<ErrnoSetterOf>(Symbol)) {
        if (!isByteCountCall(*Setter))
          State = State->set<CallSlot>(
              Outcome == FailureOutcome::OnTrueOutcome
                  ? SlotPendingFailOnTrueDiagnosis
                  : SlotPendingFailOnFalseDiagnosis,
              *Setter);
      }
    }
    C.addTransition(State);
  }

  /* Consumes the candidate checkBranchCondition just stashed (if any)
   * for whichever one of the two branches this particular call is
   * resolving -- Assumption is true exactly on the branch where the
   * condition holds. checkBranchCondition stashes into
   * SlotPendingFailOnTrueDiagnosis when it has proven the condition
   * being true means the call under test failed, or
   * SlotPendingFailOnFalseDiagnosis when it has proven the opposite
   * (`rc == 0` for a 0-means-success return code); each is committed to
   * SlotDiagnosed only on the branch it names as the failure one. Every
   * other evalAssume call in the whole translation unit sees neither
   * pending candidate and returns State unchanged, at negligible cost. */
  ProgramStateRef evalAssume(ProgramStateRef State, SVal /*Cond*/,
                             bool Assumption) const {
    if (const Stmt *const *Pending =
            State->get<CallSlot>(SlotPendingFailOnTrueDiagnosis)) {
      const Stmt *Setter = *Pending;
      State = State->remove<CallSlot>(SlotPendingFailOnTrueDiagnosis);
      if (Assumption)
        State = State->set<CallSlot>(SlotDiagnosed, Setter);
      return State;
    }
    if (const Stmt *const *Pending =
            State->get<CallSlot>(SlotPendingFailOnFalseDiagnosis)) {
      const Stmt *Setter = *Pending;
      State = State->remove<CallSlot>(SlotPendingFailOnFalseDiagnosis);
      if (!Assumption)
        State = State->set<CallSlot>(SlotDiagnosed, Setter);
      return State;
    }
    return State;
  }

  /* CallSlot's two per-path facts (Diagnosed/LastCapable) and their two
   * pending hand-off slots are, by design, about whether *this
   * function's own* control flow has diagnosed a call it itself made --
   * not a fact meant to reach across a call boundary. Clang's
   * interprocedural inlining does not know that distinction: without
   * this reset, a callee inlined into an already-fully-resolved
   * diagnosis in its caller (the diagnosing comparison true, the read
   * already matched against it, nothing left pending) inherits that
   * stale Diagnosed value anyway, and a later, entirely unrelated
   * capable call and errno read inside the callee's own body then
   * collides with it -- exactly the false positive
   * src/mman/shm.c's shm_unlink() calling rename_mapped_away() hit
   * before this fix: shm_unlink() legitimately diagnoses its own
   * unlink() failure, then calls rename_mapped_away(), which mallocs,
   * snprintf()s, and does its own completely independent error
   * handling -- none of which has anything to do with the unlink()
   * three call frames up. ThreadCapabilityMap (errno_grounds) is
   * deliberately left untouched here: *that* fact really is meant to
   * mean "established at all, anywhere on this path", which is the one
   * place cross-function persistence is the intended, documented
   * design (see its own top-of-file comment) rather than an inlining
   * accident. */
  void checkBeginFunction(CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    State = State->remove<CallSlot>(SlotDiagnosed);
    State = State->remove<CallSlot>(SlotLastCapable);
    State = State->remove<CallSlot>(SlotPendingFailOnTrueDiagnosis);
    State = State->remove<CallSlot>(SlotPendingFailOnFalseDiagnosis);
    C.addTransition(State);
  }
};

} // namespace

extern "C" const char clang_analyzerAPIVersionString[] =
    CLANG_ANALYZER_API_VERSION_STRING;

extern "C" void clang_registerCheckers(CheckerRegistry &Registry) {
  Registry.addChecker<ErrnoDisciplineChecker>(
      "ntlibc.ErrnoDiscipline",
      "Proves errno is read only from the call whose failure it reports, "
      "and only after some call or assignment could have set it",
      "");
}
