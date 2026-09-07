// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later
//
// LintDeclScanner -- a real AST walk, replacing tools/lint-decls.awk's
// hand-rolled character-at-a-time scanner for "what functions does this
// file declare (MODE=decl) or define (MODE=def)".
//
// tools/lint-decls.awk (shared by lint-undefined.sh/lint-unreferenced.sh)
// has the same two blind spots DeclScanner.cpp already fixed for
// linkcheck.sh: it only strips /* */ comments, never //, and uses a
// naive "first identifier before '('" name heuristic. Not theoretical:
// `awk -v MODE=def -f tools/lint-decls.awk src/stdlib/abs.c` prints
// "NOLINTBEGIN<TAB>11" instead of "abs<TAB>11", because the `//
// NOLINTBEGIN(misc-include-cleaner)` banner most .c files carry gets
// absorbed into the declarator buffer -- which is why lint-undefined.sh
// currently misreports abs(), bsearch(), div(), ecvt(), mblen() and
// others as undefined despite being archived into lib/libc.a.
//
// A distinct tool from DeclScanner.cpp, not an extra mode on it: that one
// reports (name, header, fixed_argc, undefined_ok) for linkcheck.sh's
// call-synthesis needs, while this mirrors lint-decls.awk's simpler
// MODE=decl/MODE=def split and "name<TAB>line" shape, since neither
// lint-undefined.sh nor lint-unreferenced.sh needs an argument count.
//
// Usage: run once per file, in C mode, with the same CFLAGS a real
// compile would use, e.g.:
//
//   clang-18 -std=c99 -fsyntax-only $CFLAGS \
//     -Xclang -load -Xclang spicule-lintdecls.so \
//     -Xclang -add-plugin -Xclang spicule-lintdecls \
//     -Xclang -plugin-arg-spicule-lintdecls -Xclang decl \
//     -Xclang -plugin-arg-spicule-lintdecls -Xclang "$file" \
//     "$file"
//
// Plugin arguments are MODE ("decl"/"def") and PATH, in that order; PATH
// is printed back exactly as given so a caller can concatenate every
// file's output into one stream without losing track of which line came
// from which file.
//
// Output, to stdout, one line per top-level function declarator:
//   MODE=decl (header, every FunctionDecl with no body):
//     name  path  line  undefined_ok(0/1)
//   MODE=def (.c file, every FunctionDecl WITH a body):
//     name  path  line
//
// "line" is the declaration's starting line (1-based). undefined_ok
// (MODE=decl only) is computed as DeclScanner.cpp does: search the raw
// source from this declaration's start offset to the next top-level
// declaration's start (or EOF) for "undefined-ok:".
//
// FunctionDecl is the only Decl kind matched, so typedefs and top-level
// variables are naturally excluded. A static-inline function defined in
// a header has a body, so it's invisible to MODE=decl, matching the
// awk's behavior. MODE=def doesn't distinguish storage class: a `static`
// function is reported like an external one, since both callers only
// ask "is this name defined somewhere in this tree".
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

enum class ScanMode { Decl, Def };

class LintDeclScanConsumer : public ASTConsumer {
  ScanMode Mode;
  std::string Path;

  // Every direct top-level declaration written in the file under scan
  // (not just the FunctionDecls this tool reports), in source order --
  // see DeclScanner.cpp's identical helper for why any Decl kind serves
  // as a boundary for the undefined-ok text search below.
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
  LintDeclScanConsumer(ScanMode Mode, std::string Path)
      : Mode(Mode), Path(std::move(Path)) {}

  void HandleTranslationUnit(ASTContext &Context) override {
    const SourceManager &SM = Context.getSourceManager();
    bool Invalid = false;
    StringRef Buffer = SM.getBufferData(SM.getMainFileID(), &Invalid);
    if (Invalid) {
      llvm::errs() << "spicule-lintdecls: could not read the main file's "
                      "source buffer\n";
      return;
    }

    TranslationUnitDecl *TU = Context.getTranslationUnitDecl();
    std::vector<std::pair<unsigned, const Decl *>> TopLevel;
    collectMainFile(TU, SM, TopLevel);
    // extern "C" { ... } is never entered when these files are parsed in
    // C mode (the only mode either caller ever asks for), so this is
    // unreachable today -- see DeclScanner.cpp's identical note. Costs
    // nothing to unwrap anyway, one level deep.
    for (const Decl *D : TU->decls())
      if (const auto *LS = dyn_cast<LinkageSpecDecl>(D))
        collectMainFile(const_cast<LinkageSpecDecl *>(LS), SM, TopLevel);

    llvm::stable_sort(TopLevel, [](const auto &A, const auto &B) {
      return A.first < B.first;
    });

    for (size_t I = 0; I < TopLevel.size(); ++I) {
      const auto *FD = dyn_cast<FunctionDecl>(TopLevel[I].second);
      if (!FD)
        continue;
      bool HasBody = FD->doesThisDeclarationHaveABody();
      if (Mode == ScanMode::Decl && HasBody)
        continue;
      if (Mode == ScanMode::Def && !HasBody)
        continue;

      unsigned Begin = TopLevel[I].first;
      SourceLocation BeginLoc = SM.getExpansionLoc(FD->getBeginLoc());
      unsigned Line = SM.getExpansionLineNumber(BeginLoc);

      if (Mode == ScanMode::Def) {
        llvm::outs() << FD->getNameAsString() << '\t' << Path << '\t' << Line
                     << '\n';
        continue;
      }

      unsigned End =
          (I + 1 < TopLevel.size()) ? TopLevel[I + 1].first : Buffer.size();
      if (End < Begin)
        End = Begin;
      bool UndefinedOk = Buffer.substr(Begin, End - Begin).contains("undefined-ok:");

      llvm::outs() << FD->getNameAsString() << '\t' << Path << '\t' << Line
                   << '\t' << (UndefinedOk ? 1 : 0) << '\n';
    }
  }
};

class LintDeclScanAction : public PluginASTAction {
  ScanMode Mode = ScanMode::Decl;
  std::string Path;

protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &,
                                                  StringRef) override {
    return std::make_unique<LintDeclScanConsumer>(Mode, Path);
  }

  bool ParseArgs(const CompilerInstance &,
                 const std::vector<std::string> &Args) override {
    if (Args.size() != 2 || (Args[0] != "decl" && Args[0] != "def")) {
      llvm::errs() << "spicule-lintdecls: expected exactly two plugin "
                      "arguments, ('decl'|'def') then a path to echo back, "
                      "got "
                   << Args.size() << " argument(s)\n";
      return false;
    }
    Mode = (Args[0] == "decl") ? ScanMode::Decl : ScanMode::Def;
    Path = Args[1];
    return true;
  }

  ActionType getActionType() override { return AddAfterMainAction; }
};

} // namespace

static FrontendPluginRegistry::Add<LintDeclScanAction>
    X("spicule-lintdecls",
      "list top-level function declarators/definitions for "
      "lint-undefined.sh and lint-unreferenced.sh");
