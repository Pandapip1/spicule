// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef SPICULE_RELATION_CONTRACTS_H
#define SPICULE_RELATION_CONTRACTS_H

#include "llvm/ADT/StringRef.h"

#include <optional>

namespace spicule {

// Shared syntax for path-scoped pointer/object relations.  "element_of"
// means the pointer belongs to the allocation currently named by the
// registry (including its permitted one-past value).  Mutating element
// contents preserves the relation; rebinding or address-exposing registry
// storage invalidates it.
enum class ElementRelationKind { Return, Parameter };

struct ElementRelationContract {
  ElementRelationKind Kind;
  unsigned Parameter = 0;
  llvm::StringRef Registry;
};

inline std::optional<ElementRelationContract>
parseElementRelation(llvm::StringRef Annotation) {
  constexpr llvm::StringRef ReturnPrefix =
      "spicule_relation_returns_element_of:";
  constexpr llvm::StringRef ParameterPrefix =
      "spicule_relation_parameter_element_of:";
  if (Annotation.starts_with(ReturnPrefix)) {
    llvm::StringRef Registry = Annotation.drop_front(ReturnPrefix.size());
    if (!Registry.empty())
      return ElementRelationContract{ElementRelationKind::Return, 0,
                                     Registry};
    return std::nullopt;
  }
  if (!Annotation.starts_with(ParameterPrefix))
    return std::nullopt;
  auto [IndexText, Registry] =
      Annotation.drop_front(ParameterPrefix.size()).split(':');
  unsigned Index;
  if (IndexText.getAsInteger(10, Index) || Registry.empty())
    return std::nullopt;
  return ElementRelationContract{ElementRelationKind::Parameter, Index,
                                 Registry};
}

} // namespace spicule

#endif
