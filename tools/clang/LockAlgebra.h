// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Reads include/pthread.h's own consume:/consume_any:/grant:/withtok:/
// construct:/destroy: token annotations off a callee's declaration and
// classifies the real lock protocol operation they jointly encode, purely
// from that callee's own AST -- no per-function name matching. This is the
// single source of truth LockDisciplineChecker.cpp's ntlibc.LockDiscipline
// and PurityChecker.cpp's ntlibc.Purity both need for "does this call have
// an observable effect on a lock's held/not-held state", replacing what
// used to be two independently hand-maintained name lists that had already
// drifted apart (PurityChecker.cpp's LockNames[] included
// pthread_cond_signal/pthread_cond_broadcast, which LockDisciplineChecker's
// own table never did).
#ifndef NTLIBC_LOCK_ALGEBRA_H
#define NTLIBC_LOCK_ALGEBRA_H

#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "TokenAlgebra.h"

#include "llvm/ADT/StringRef.h"

#include <optional>

namespace ntlibc::lock {

enum class LockOperation : unsigned char {
  Initialize,
  AcquireRead,
  AcquireWrite,
  Release,
  RequireHeld,
  Destroy,
};

struct LockCall {
  LockOperation Operation;
  unsigned Argument;
  // The real tokdef name this operation's own grant:/withtok: names (the
  // specific held family for Acquire*/RequireHeld, the specific unlocked
  // family for Initialize/Release) -- empty for Destroy, which has none.
  // Lets a caller distinguish, e.g., pthread_rwlock_shared from
  // pthread_rwlock_exclusive precisely instead of a coarse read/write tag.
  llvm::StringRef Family;
};

namespace detail {

using ntlibc::algebra::findTokenSort;
using ntlibc::algebra::hasQualifier;

inline bool isHeldToken(clang::ASTContext &Context, llvm::StringRef Name) {
  return hasQualifier(findTokenSort(Context, Name), "qual:lock_held");
}

// The facts one parameter's own annotate() attributes carry, exactly the
// shapes include/pthread.h's real lock family declarations use (see this
// header's own classifyParameter() doc comment for the six shapes these
// facts jointly distinguish).
struct ParameterLockFacts {
  bool HasExactConsume = false;
  bool HasConsumeAny = false;
  bool HasConstruct = false;
  bool HasDestroy = false;
  bool HasHandle = false;
  bool HasBareWithtok = false;
  llvm::StringRef WithtokName;
  bool GrantsHeld = false;
  bool GrantsUnheld = false;
  llvm::StringRef GrantedHeldName;
  llvm::StringRef GrantedUnheldName;
};

inline ParameterLockFacts collect(const clang::ParmVarDecl *Parameter) {
  ParameterLockFacts Facts;
  clang::ASTContext &Context = Parameter->getASTContext();
  bool HasAnyConsumeOrGrant = false;
  for (const auto *Attribute :
       Parameter->specific_attrs<clang::AnnotateAttr>()) {
    llvm::StringRef Text = Attribute->getAnnotation();
    llvm::StringRef Payload = Text;
    if (Payload.consume_front("consume:")) {
      Facts.HasExactConsume = true;
      HasAnyConsumeOrGrant = true;
    } else if (Payload.consume_front("consume_any:")) {
      Facts.HasConsumeAny = true;
      HasAnyConsumeOrGrant = true;
    } else if (Payload.consume_front("grant:")) {
      HasAnyConsumeOrGrant = true;
      if (isHeldToken(Context, Payload)) {
        Facts.GrantsHeld = true;
        Facts.GrantedHeldName = Payload;
      } else {
        Facts.GrantsUnheld = true;
        Facts.GrantedUnheldName = Payload;
      }
    } else if (Payload.consume_front("withtok:")) {
      Facts.HasBareWithtok = true;
      Facts.WithtokName = Payload;
    } else if (Text.starts_with("construct:")) {
      Facts.HasConstruct = true;
    } else if (Text.starts_with("destroy:")) {
      Facts.HasDestroy = true;
    } else if (Text.starts_with("handle:") || Text.starts_with("static_handle:")) {
      Facts.HasHandle = true;
    }
  }
  // A bare withtok(...) means "required, but neither consumed nor
  // granted" -- if this same parameter also consumes or grants something,
  // it is not the RequireHeld shape (pthread_cond_wait's mutex argument
  // carries withtok(pthread_mutex_locked) alone; no real declaration pairs
  // withtok with consume/consume_any/grant on the same parameter).
  if (HasAnyConsumeOrGrant)
    Facts.HasBareWithtok = false;
  return Facts;
}

} // namespace detail

// Classifies one parameter's own consume:/consume_any:/grant:/withtok:/
// construct:/destroy: annotations into the LockOperation they jointly
// encode. The six shapes, verified against every real
// include/pthread.h entry point:
//   Initialize:   construct(...) + grant(unheld), nothing consumed.
//   Destroy:      destroy(...) + exact consume(...), nothing granted.
//   AcquireWrite: exact consume(...) + grant(held) + handle(...).
//   AcquireRead:  consume_any(...) only (no exact consume) + grant(held)
//                 + handle(...).
//   Release:      consume(...)/consume_any(...) + grant(unheld) + handle(...).
//   RequireHeld:  a bare withtok(held) + handle(...), nothing else on this
//                 parameter.
//
// AcquireWrite/AcquireRead/Release/RequireHeld additionally require a
// handle:/static_handle: annotation on the same parameter: every real
// pthread.h entry point carries one alongside its token annotations, but so
// do this tree's internal implementation helpers that consume/grant the
// exact same tokens on an equally real, correctly-typed parameter purely as
// their own private plumbing (e.g. src/thread/pthread_mutex.c's static
// mutex_acquire(), src/thread/pthread_cond.c's static cond_wait()) --
// neither carries handle()/static_handle() of its own. So do
// src/internal/ownership_stubs.h's own analyzer-only "leaf axiom" proof
// primitives (__ownership_pthread_mutex_locked() and its siblings), which
// OwnershipChecker.cpp's own CapabilityMap consumes at the exact point a
// hand-rolled state transition (e.g. a direct data->owner assignment) needs
// to be asserted into ownership-token terms; requiring handle: excludes
// those too, since their parameter is a generic, untyped void*. Without
// this, calls to any of the above got misclassified as real lock protocol
// operations under this checker's own state -- confirmed by rebuilding and
// re-running tools/lint.sh locks against the real tree, which surfaced 17
// false findings before this requirement was added, zero after. Initialize
// and Destroy need no such requirement: pthread_spin_init()/
// pthread_spin_destroy() are real, intentionally-classified entry points
// that carry no handle()/static_handle() of their own, and their own
// construct:/destroy: requirement is not a shape any of the above internal
// helpers or proof stubs otherwise share.
inline std::optional<LockCall>
classifyParameter(const clang::ParmVarDecl *Parameter, unsigned Argument) {
  detail::ParameterLockFacts Facts = detail::collect(Parameter);
  if (Facts.HasBareWithtok && Facts.HasHandle &&
      detail::isHeldToken(Parameter->getASTContext(), Facts.WithtokName))
    return LockCall{LockOperation::RequireHeld, Argument, Facts.WithtokName};
  if (Facts.HasDestroy && Facts.HasExactConsume && !Facts.GrantsHeld &&
      !Facts.GrantsUnheld)
    return LockCall{LockOperation::Destroy, Argument, {}};
  if (Facts.HasConstruct && Facts.GrantsUnheld && !Facts.HasExactConsume &&
      !Facts.HasConsumeAny)
    return LockCall{LockOperation::Initialize, Argument,
                    Facts.GrantedUnheldName};
  if (Facts.HasHandle && Facts.GrantsHeld && Facts.HasExactConsume)
    return LockCall{LockOperation::AcquireWrite, Argument,
                    Facts.GrantedHeldName};
  if (Facts.HasHandle && Facts.GrantsHeld && Facts.HasConsumeAny &&
      !Facts.HasExactConsume)
    return LockCall{LockOperation::AcquireRead, Argument,
                    Facts.GrantedHeldName};
  if (Facts.HasHandle && Facts.GrantsUnheld &&
      (Facts.HasExactConsume || Facts.HasConsumeAny))
    return LockCall{LockOperation::Release, Argument, Facts.GrantedUnheldName};
  return std::nullopt;
}

// Scans Function's own parameters, in order, for the first one whose
// annotations classify as a LockOperation -- every real
// include/pthread.h lock entry point carries exactly one such parameter.
inline std::optional<LockCall>
classifyCall(const clang::FunctionDecl *Function) {
  if (!Function)
    return std::nullopt;
  unsigned Argument = 0;
  for (const clang::ParmVarDecl *Parameter : Function->parameters()) {
    if (std::optional<LockCall> Call =
            classifyParameter(Parameter, Argument))
      return Call;
    ++Argument;
  }
  return std::nullopt;
}

// True if Function's own declaration carries the annotation shape
// classifyCall() recognizes -- the shared, stateless "this call has an
// observable effect on lock-acquisition state" fact.
inline bool isLockProtocolCall(const clang::FunctionDecl *Function) {
  return classifyCall(Function).has_value();
}

} // namespace ntlibc::lock

#endif
