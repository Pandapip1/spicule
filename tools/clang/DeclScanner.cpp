// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
//
// DeclScanner -- a real AST walk, replacing tools/linkcheck.sh's inline
// hand-rolled awk scanner for "what functions does this header declare".
//
// The awk scanner treated "the first identifier immediately followed by
// '('" as a declarator name, which breaks on two patterns now common in
// the headers: `// NOLINTBEGIN(...)`/`NOLINTEND(...)` (the awk only strips
// /* */ comments, never //, so it parses "NOLINTBEGIN" as a declarator),
// and `withtok(token_name)` (include/ownership.h) used as a prefix
// attribute before a return type, where the match lands on `withtok(`
// instead of the real declarator after it. Neither is patchable in
// general -- any heuristic that doesn't know what a declaration is will
// misparse the next macro-attribute idiom -- so this walks the real
// clang AST instead.
//
// Usage: run once per header, in C mode, with this project's own CFLAGS
// (see tools/linkcheck.sh), e.g.:
//
//   clang-18 -std=c99 -fsyntax-only $CFLAGS \
//     -Xclang -load -Xclang spicule-declscan.so \
//     -Xclang -add-plugin -Xclang spicule-declscan \
//     -Xclang -plugin-arg-spicule-declscan -Xclang "$header" \
//     "$header"
//
// Output: one line per declared function, tab-separated, to stdout:
//
//   name  header  fixed_argc  undefined_ok(0/1)
//
// "header" is printed exactly as given via the plugin argument, not
// re-derived from the AST, so linkcheck.sh's declfile format needs no
// changes.
//
// A function is skipped when doesThisDeclarationHaveABody() is true: a
// static-inline function defined right in the header is already defined
// everywhere it's included, not something to link-check. FunctionDecl is
// the only Decl kind matched, so typedefs and top-level variables are
// naturally excluded.
//
// fixed_argc is FD->getNumParams(): clang already treats an explicit
// `(void)` parameter list as zero parameters, matching the old scanner's
// `void` special case, and an unprototyped bare `()` also yields zero.
//
// undefined_ok is computed by searching the raw header source, from this
// declaration's start offset to the next top-level declaration's start
// (or EOF), for the substring "undefined-ok:" -- matching the old awk
// scanner's line-level "hasmark" flag, since every marker in use today
// sits on the declaration's own line.
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/raw_ostream.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace clang;

namespace {

class DeclScanConsumer : public ASTConsumer {
  std::string HeaderPath;

  // Every direct top-level declaration written in the file under scan
  // (not just the FunctionDecls this tool reports), in source order.
  // Any Decl kind at all serves as a boundary for the undefined-ok text
  // search below -- a typedef or struct between two functions ends the
  // first function's search range just as a function does.
  static void collectMainFile(DeclContext *DC, const SourceManager &SM,
                               std::vector<std::pair<unsigned, const Decl *>> &Out) {
    for (const Decl *D : DC->decls()) {
      SourceLocation Begin = SM.getExpansionLoc(D->getBeginLoc());
      if (!SM.isWrittenInMainFile(Begin))
        continue;
      Out.emplace_back(SM.getFileOffset(Begin), D);
    }
  }

public:
  explicit DeclScanConsumer(std::string HeaderPath)
      : HeaderPath(std::move(HeaderPath)) {}

  void HandleTranslationUnit(ASTContext &Context) override {
    const SourceManager &SM = Context.getSourceManager();
    bool Invalid = false;
    StringRef Buffer = SM.getBufferData(SM.getMainFileID(), &Invalid);
    if (Invalid) {
      llvm::errs() << "spicule-declscan: could not read the main file's source "
                      "buffer for '"
                   << HeaderPath << "'\n";
      return;
    }

    TranslationUnitDecl *TU = Context.getTranslationUnitDecl();
    std::vector<std::pair<unsigned, const Decl *>> TopLevel;
    collectMainFile(TU, SM, TopLevel);
    // extern "C" { ... } is not entered when these headers are parsed in C
    // mode (the only mode tools/linkcheck.sh's CFLAGS ever asks for -- see
    // this file's own header comment), so this is unreachable today.  It
    // costs nothing to unwrap anyway, one level deep, matching what a C++
    // consumer of these same headers would see.
    for (const Decl *D : TU->decls())
      if (const auto *LS = dyn_cast<LinkageSpecDecl>(D))
        collectMainFile(const_cast<LinkageSpecDecl *>(LS), SM, TopLevel);

    llvm::stable_sort(TopLevel, [](const auto &A, const auto &B) {
      return A.first < B.first;
    });

    for (size_t I = 0; I < TopLevel.size(); ++I) {
      const auto *FD = dyn_cast<FunctionDecl>(TopLevel[I].second);
      if (!FD || FD->doesThisDeclarationHaveABody())
        continue;

      unsigned Begin = TopLevel[I].first;
      unsigned End =
          (I + 1 < TopLevel.size()) ? TopLevel[I + 1].first : Buffer.size();
      if (End < Begin)
        End = Begin;
      bool UndefinedOk = Buffer.substr(Begin, End - Begin).contains("undefined-ok:");

      llvm::outs() << FD->getNameAsString() << '\t' << HeaderPath << '\t'
                   << FD->getNumParams() << '\t' << (UndefinedOk ? 1 : 0)
                   << '\n';
    }
  }
};

class DeclScanAction : public PluginASTAction {
  std::string HeaderPath;

protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &,
                                                  StringRef) override {
    return std::make_unique<DeclScanConsumer>(HeaderPath);
  }

  bool ParseArgs(const CompilerInstance &,
                 const std::vector<std::string> &Args) override {
    if (Args.size() != 1) {
      llvm::errs() << "spicule-declscan: expected exactly one plugin "
                      "argument (the header path to report), got "
                   << Args.size() << "\n";
      return false;
    }
    HeaderPath = Args[0];
    return true;
  }

  ActionType getActionType() override { return AddAfterMainAction; }
};

} // namespace

static FrontendPluginRegistry::Add<DeclScanAction>
    X("spicule-declscan", "list top-level function declarations for linkcheck.sh");
