// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef SPICULE_LOCK_HANDOFF_CONTRACTS_H
#define SPICULE_LOCK_HANDOFF_CONTRACTS_H

#include "llvm/ADT/StringRef.h"

#include <optional>

namespace spicule {

// Shared syntax for a function's own lock hand-off contract, attached via
// __attribute__((annotate(...))) directly to the function's own
// declaration (see src/thread/pthread_cond.c's
// lock_requires_held_on_entry()/lock_acquires_for_caller macros). Either
// kind exempts one specific held lock region from
// LockDisciplineChecker.cpp's "function exits while a lock is held"
// report, for the one stack frame the annotated function is running in:
// ending while holding that lock is a deliberate hand-off the contract
// documents, not a leak.
//
// RequiresHeldOnEntry(Argument): the designated parameter names a lock
// that is, by contract, already held by the caller when this function is
// entered, and handed back held on every return path (e.g. POSIX's
// pthread_cond_wait()/pthread_cond_timedwait() mutex argument).
//
// AcquiresForCaller: this function acquires a lock purely to hand it off
// held to whatever runs next, not to release it itself (e.g. a
// pthread_cleanup_push() handler restoring a "locked" postcondition on a
// cancellation path).
enum class LockHandoffKind { RequiresHeldOnEntry, AcquiresForCaller };

struct LockHandoffContract {
  LockHandoffKind Kind;
  unsigned Argument = 0; // Meaningful only for RequiresHeldOnEntry.
};

inline std::optional<LockHandoffContract>
parseLockHandoff(llvm::StringRef Annotation) {
  constexpr llvm::StringRef RequiresHeldPrefix =
      "spicule_lock_requires_held_on_entry:";
  constexpr llvm::StringRef AcquiresForCaller =
      "spicule_lock_acquires_for_caller";
  if (Annotation == AcquiresForCaller)
    return LockHandoffContract{LockHandoffKind::AcquiresForCaller, 0};
  if (!Annotation.starts_with(RequiresHeldPrefix))
    return std::nullopt;
  llvm::StringRef IndexText =
      Annotation.drop_front(RequiresHeldPrefix.size());
  unsigned Index;
  if (IndexText.getAsInteger(10, Index))
    return std::nullopt;
  return LockHandoffContract{LockHandoffKind::RequiresHeldOnEntry, Index};
}

} // namespace spicule

#endif
