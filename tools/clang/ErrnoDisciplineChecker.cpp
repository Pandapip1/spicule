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
                     check::PreStmt<UnaryOperator>> {
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

  /* Recognise `<capable-call> <cmp> <sentinel>` (and the transitive form
   * through a variable the call's result was copied into, which the
   * engine's own symbolic execution already resolves to the same
   * symbol) as "the code is diagnosing this call's failure" -- CERT
   * ERR30-C's precondition for trusting errno afterward. */
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
    SymbolRef Symbol = C.getSVal(Operation->getLHS()).getAsSymbol(true);
    if (!Symbol)
      Symbol = C.getSVal(Operation->getRHS()).getAsSymbol(true);
    diagnoseIfSetter(Symbol, C);
  }

  void checkPreStmt(const UnaryOperator *Operation, CheckerContext &C) const {
    /* `if (!fopen(...))` etc.: the idiomatic C null-check for a
     * pointer-returning capable call diagnoses that call's failure
     * exactly as `== 0`/`== NULL` already does above -- same trust
     * boundary, just reached through negation instead of an explicit
     * comparison against zero. */
    if (Operation->getOpcode() == UO_LNot) {
      diagnoseIfSetter(C.getSVal(Operation->getSubExpr()).getAsSymbol(true),
                       C);
      return;
    }
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
