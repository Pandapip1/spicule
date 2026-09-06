// SPDX-FileCopyrightText: (C) 2026 Gavin John
// SPDX-License-Identifier: GPL-3.0-or-later

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/Builtins.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"
#include <z3++.h>

#include <cctype>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace clang;

namespace {

/* Locally defined read-only helpers cannot mutate a caller's induction rank,
 * bound, or sentinel object.  Infer that property conservatively so a small
 * scalar predicate does not need a public semantic attribute merely to be
 * transparent to a loop proof.  Termination remains an independent
 * obligation: every accepted definition is still traversed normally. */
class ReadonlyFunctionFacts {
  struct Candidate {
    bool Valid = true;
    std::vector<const FunctionDecl *> Dependencies;
  };

  ASTContext &Context;
  std::map<const FunctionDecl *, const FunctionDecl *> Definitions;
  std::map<const FunctionDecl *, Candidate> Candidates;
  std::set<const FunctionDecl *> Readonly;

  static const Expr *ignore(const Expr *Expression) {
    return Expression ? Expression->IgnoreParenImpCasts() : nullptr;
  }

  static bool localScalarWrite(const Expr *Expression,
                               const FunctionDecl *Function) {
    const auto *Reference = dyn_cast_or_null<DeclRefExpr>(ignore(Expression));
    const auto *Variable =
        Reference ? dyn_cast<VarDecl>(Reference->getDecl()) : nullptr;
    return Variable && !Variable->hasGlobalStorage() &&
           Variable->getDeclContext() == Function;
  }

  void inspect(const Stmt *Statement, const FunctionDecl *Function,
               Candidate &Result) {
    if (!Statement || !Result.Valid)
      return;
    if (isa<AsmStmt>(Statement)) {
      Result.Valid = false;
      return;
    }
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      if (Expression->getType().isVolatileQualified()) {
        Result.Valid = false;
        return;
      }
      const Expr *Plain = ignore(Expression);
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain)) {
        if (Unary->isIncrementDecrementOp() &&
            !localScalarWrite(Unary->getSubExpr(), Function)) {
          Result.Valid = false;
          return;
        }
      }
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain)) {
        if (Binary->isAssignmentOp() &&
            !localScalarWrite(Binary->getLHS(), Function)) {
          Result.Valid = false;
          return;
        }
      }
      if (const auto *Call = dyn_cast_or_null<CallExpr>(Plain)) {
        const FunctionDecl *Callee = Call->getDirectCallee();
        if (!Callee) {
          Result.Valid = false;
          return;
        }
        Callee = Callee->getCanonicalDecl();
        if (!Callee->hasAttr<PureAttr>() && !Callee->hasAttr<ConstAttr>()) {
          auto Definition = Definitions.find(Callee);
          if (Definition == Definitions.end()) {
            Result.Valid = false;
            return;
          }
          Result.Dependencies.push_back(Callee);
        }
      }
    }
    for (const Stmt *Child : Statement->children())
      inspect(Child, Function, Result);
  }

public:
  explicit ReadonlyFunctionFacts(ASTContext &Context) : Context(Context) {
    for (Decl *Declaration : Context.getTranslationUnitDecl()->decls()) {
      const auto *Function = dyn_cast<FunctionDecl>(Declaration);
      if (!Function || !Function->isThisDeclarationADefinition() ||
          !Context.getSourceManager().isWrittenInMainFile(
              Context.getSourceManager().getExpansionLoc(
                  Function->getLocation())))
        continue;
      Definitions[Function->getCanonicalDecl()] = Function;
    }
    for (const auto &[Canonical, Definition] : Definitions) {
      Candidate Result;
      inspect(Definition->getBody(), Definition, Result);
      if (Result.Valid) {
        Candidates.emplace(Canonical, std::move(Result));
        Readonly.insert(Canonical);
      }
    }
    bool Changed = true;
    while (Changed) {
      Changed = false;
      for (const auto &[Function, Candidate] : Candidates) {
        if (!Readonly.count(Function))
          continue;
        for (const FunctionDecl *Dependency : Candidate.Dependencies)
          if (!Readonly.count(Dependency)) {
            Readonly.erase(Function);
            Changed = true;
            break;
          }
      }
    }
  }

  bool contains(const FunctionDecl *Function) const {
    return Function && Readonly.count(Function->getCanonicalDecl());
  }
};

/* A static function whose address never escapes has a closed set of callers
 * in this translation unit.  This summary proves an integer parameter
 * positive when every one of those calls supplies either a positive constant
 * or a similarly proved, unmodified parameter.  Requiring a constant-rooted
 * fixpoint rejects unreachable recursive forwarding cycles. */
class PositiveParameterFacts {
  struct CallSite {
    const CallExpr *Call;
    const FunctionDecl *Caller;
  };

  ASTContext &Context;
  std::map<const FunctionDecl *, const FunctionDecl *> Definitions;
  std::map<const FunctionDecl *, std::vector<CallSite>> Calls;
  std::set<const FunctionDecl *> AddressTaken;
  std::set<std::string> AliasedNames;
  std::set<const ParmVarDecl *> Positive;

  class Collector : public RecursiveASTVisitor<Collector> {
    PositiveParameterFacts &Facts;
    const FunctionDecl *Current = nullptr;

    bool directCallee(const DeclRefExpr *Reference,
                      const FunctionDecl *Target) const {
      DynTypedNode Node = DynTypedNode::create(*Reference);
      for (;;) {
        auto Parents = Facts.Context.getParents(Node);
        if (Parents.size() != 1)
          return false;
        if (const auto *Call = Parents[0].get<CallExpr>()) {
          const FunctionDecl *Direct = Call->getDirectCallee();
          return Direct && Direct->getCanonicalDecl() == Target;
        }
        const Expr *Parent = Parents[0].get<Expr>();
        if (!Parent || (!isa<ImplicitCastExpr>(Parent) &&
                        !isa<ParenExpr>(Parent)))
          return false;
        Node = DynTypedNode::create(*Parent);
      }
    }

    bool potentiallyEvaluated(const CallExpr *Call) const {
      DynTypedNode Node = DynTypedNode::create(*Call);
      for (;;) {
        auto Parents = Facts.Context.getParents(Node);
        if (Parents.size() != 1)
          return true;
        if (Parents[0].get<UnaryExprOrTypeTraitExpr>())
          return false;
        if (const auto *Parent = Parents[0].get<Expr>()) {
          Node = DynTypedNode::create(*Parent);
          continue;
        }
        return true;
      }
    }

  public:
    explicit Collector(PositiveParameterFacts &Facts) : Facts(Facts) {}

    bool TraverseFunctionDecl(FunctionDecl *Function) {
      const FunctionDecl *Saved = Current;
      if (const FunctionDecl *Definition = Function->getDefinition())
        Current = Definition;
      bool Result =
          RecursiveASTVisitor<Collector>::TraverseFunctionDecl(Function);
      Current = Saved;
      return Result;
    }

    bool VisitFunctionDecl(FunctionDecl *Function) {
      if (Function->isThisDeclarationADefinition())
        Facts.Definitions[Function->getCanonicalDecl()] = Function;
      if (const auto *Alias = Function->getAttr<AliasAttr>())
        Facts.AliasedNames.insert(Alias->getAliasee().str());
      if (const auto *WeakReference = Function->getAttr<WeakRefAttr>())
        if (!WeakReference->getAliasee().empty())
          Facts.AliasedNames.insert(WeakReference->getAliasee().str());
      if (const auto *Indirect = Function->getAttr<IFuncAttr>())
        Facts.AliasedNames.insert(Indirect->getResolver().str());
      return true;
    }

    bool VisitCallExpr(CallExpr *Call) {
      const FunctionDecl *Callee = Call->getDirectCallee();
      if (Callee && potentiallyEvaluated(Call))
        Facts.Calls[Callee->getCanonicalDecl()].push_back({Call, Current});
      return true;
    }

    bool VisitDeclRefExpr(DeclRefExpr *Reference) {
      const auto *Function = dyn_cast<FunctionDecl>(Reference->getDecl());
      if (Function) {
        const FunctionDecl *Canonical = Function->getCanonicalDecl();
        if (!directCallee(Reference, Canonical))
          Facts.AddressTaken.insert(Canonical);
      }
      return true;
    }
  };

  static const Expr *ignore(const Expr *Expression) {
    return Expression ? Expression->IgnoreParenImpCasts() : nullptr;
  }

  static bool containsAsm(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (isa<AsmStmt>(Statement))
      return true;
    for (const Stmt *Child : Statement->children())
      if (containsAsm(Child))
        return true;
    return false;
  }

  static bool externallyRetained(const FunctionDecl *Function) {
    for (const FunctionDecl *Redeclaration : Function->redecls())
      if (Redeclaration->hasAttr<AliasAttr>() ||
          Redeclaration->hasAttr<WeakRefAttr>() ||
          Redeclaration->hasAttr<IFuncAttr>() ||
          Redeclaration->hasAttr<UsedAttr>() ||
          Redeclaration->hasAttr<RetainAttr>())
        return true;
    return false;
  }

  static bool writtenOrEscaped(const Stmt *Statement,
                               const ParmVarDecl *Parameter) {
    if (!Statement)
      return false;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain)) {
        const auto *Reference = dyn_cast_or_null<DeclRefExpr>(
            ignore(Unary->getSubExpr()));
        if (Reference && Reference->getDecl() == Parameter &&
            (Unary->isIncrementDecrementOp() ||
             Unary->getOpcode() == UO_AddrOf))
          return true;
      }
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain)) {
        const auto *Reference = dyn_cast_or_null<DeclRefExpr>(
            ignore(Binary->getLHS()));
        if (Binary->isAssignmentOp() && Reference &&
            Reference->getDecl() == Parameter)
          return true;
      }
    }
    for (const Stmt *Child : Statement->children())
      if (writtenOrEscaped(Child, Parameter))
        return true;
    return false;
  }

  bool samePositiveConstant(const Expr *Argument) const {
    if (!Argument)
      return false;
    Expr::EvalResult Initial;
    if (!Argument->EvaluateAsInt(Initial, Context))
      return false;
    const llvm::APSInt &Value = Initial.Val.getInt();
    if (Value.isNegative() || Value.isZero())
      return false;
    const Expr *Current = Argument->IgnoreParens();
    while (const auto *Cast = dyn_cast<CastExpr>(Current)) {
      Expr::EvalResult Before;
      Current = Cast->getSubExpr()->IgnoreParens();
      if (!Current->EvaluateAsInt(Before, Context) ||
          Before.Val.getInt().isNegative() || Before.Val.getInt().isZero() ||
          llvm::APSInt::compareValues(Value, Before.Val.getInt()) != 0)
        return false;
    }
    return true;
  }

  bool preservesPositiveParameter(const Expr *Expression,
                                  const ParmVarDecl *&Source) const {
    Expression = Expression ? Expression->IgnoreParens() : nullptr;
    if (const auto *Cast = dyn_cast_or_null<ImplicitCastExpr>(Expression)) {
      QualType From = Cast->getSubExpr()->getType();
      QualType To = Cast->getType();
      if (!From->isIntegerType() || !To->isIntegerType())
        return false;
      unsigned FromWidth = Context.getIntWidth(From);
      unsigned ToWidth = Context.getIntWidth(To);
      bool Preserved = To->isUnsignedIntegerType()
                           ? ToWidth >= FromWidth
                           : (From->isSignedIntegerType()
                                  ? ToWidth >= FromWidth
                                  : ToWidth > FromWidth);
      return Preserved &&
             preservesPositiveParameter(Cast->getSubExpr(), Source);
    }
    const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Expression);
    Source = Reference ? dyn_cast<ParmVarDecl>(Reference->getDecl()) : nullptr;
    return Source != nullptr;
  }

public:
  explicit PositiveParameterFacts(ASTContext &Context) : Context(Context) {
    Collector(*this).TraverseDecl(Context.getTranslationUnitDecl());

    struct Constraint {
      bool Valid = true;
      bool Anchor = false;
      std::vector<const ParmVarDecl *> Dependencies;
    };
    std::map<const ParmVarDecl *, Constraint> Constraints;
    for (const auto &[Canonical, Definition] : Definitions) {
      if (Definition->getStorageClass() != SC_Static ||
          AddressTaken.count(Canonical) || externallyRetained(Definition) ||
          AliasedNames.count(Definition->getNameAsString()) ||
          containsAsm(Definition->getBody()))
        continue;
      auto FoundCalls = Calls.find(Canonical);
      if (FoundCalls == Calls.end() || FoundCalls->second.empty())
        continue;
      for (const ParmVarDecl *Parameter : Definition->parameters()) {
        if (!Parameter->getType()->isIntegerType() ||
            writtenOrEscaped(Definition->getBody(), Parameter))
          continue;
        unsigned Index = Parameter->getFunctionScopeIndex();
        Constraint Candidate;
        for (const CallSite &Site : FoundCalls->second) {
          if (Index >= Site.Call->getNumArgs()) {
            Candidate.Valid = false;
            break;
          }
          const Expr *Argument = Site.Call->getArg(Index);
          if (samePositiveConstant(Argument)) {
            Candidate.Anchor = true;
            continue;
          }
          const ParmVarDecl *Source = nullptr;
          if (!Site.Caller ||
              !preservesPositiveParameter(Argument, Source) ||
              Source->getDeclContext() != Site.Caller ||
              writtenOrEscaped(Site.Caller->getBody(), Source)) {
            Candidate.Valid = false;
            break;
          }
          Candidate.Dependencies.push_back(Source);
        }
        if (Candidate.Valid)
          Constraints.emplace(Parameter, std::move(Candidate));
      }
    }

    for (const auto &[Parameter, Constraint] : Constraints)
      if (Constraint.Anchor)
        Positive.insert(Parameter);
    bool Changed = true;
    while (Changed) {
      Changed = false;
      for (const auto &[Parameter, Constraint] : Constraints) {
        if (Positive.count(Parameter))
          continue;
        for (const ParmVarDecl *Dependency : Constraint.Dependencies)
          if (Positive.count(Dependency)) {
            Positive.insert(Parameter);
            Changed = true;
            break;
          }
      }
    }
    Changed = true;
    while (Changed) {
      Changed = false;
      for (const auto &[Parameter, Constraint] : Constraints) {
        if (Positive.count(Parameter))
          for (const ParmVarDecl *Dependency : Constraint.Dependencies)
            if (!Positive.count(Dependency)) {
              Positive.erase(Parameter);
              Changed = true;
              break;
            }
      }
    }
  }

  bool contains(const ParmVarDecl *Parameter) const {
    return Positive.count(Parameter) != 0;
  }
};

class TotalityVisitor : public RecursiveASTVisitor<TotalityVisitor> {
  ASTContext &Context;
  SourceManager &SM;
  const ReadonlyFunctionFacts &ReadonlyFunctions;
  const PositiveParameterFacts &PositiveParameters;
  const FunctionDecl *Current = nullptr;
  std::unique_ptr<CFG> CurrentCFG;
  mutable const Stmt *ActiveLoop = nullptr;
  mutable std::map<const RecordDecl *, bool> GlobalRecordCache;

  enum class ProgressKind { Up, Down };

  struct Progress {
    const ValueDecl *Variable;
    ProgressKind Kind;
    const ValueDecl *Base;
    /* Non-null for an integer non-unit additive/subtractive step.  Such a
     * change is strict progress only when its dedicated guard, relational,
     * or residue proof shows that the operation cannot wrap. */
    const Expr *GuardedStep = nullptr;
    bool VolatileAccess = false;
    bool RequiresNonzeroCondition = false;
    bool UnitStep = false;
    bool UnitOnly = false;
    const ValueDecl *DynamicStep = nullptr;
    bool UnaryStep = false;
  };

  std::string file(SourceLocation Location) const {
    return SM.getFilename(SM.getExpansionLoc(Location)).str();
  }

  unsigned line(SourceLocation Location) const {
    return SM.getExpansionLineNumber(Location);
  }

  static std::string clean(StringRef Raw) {
    std::string Result;
    bool Space = false;
    for (char Character : Raw) {
      if (std::isspace(static_cast<unsigned char>(Character))) {
        Space = !Result.empty();
      } else {
        if (Space)
          Result += ' ';
        Result += Character == '\t' ? ' ' : Character;
        Space = false;
      }
    }
    return Result;
  }

  std::string text(const Stmt *Statement) const {
    SourceLocation Begin = SM.getSpellingLoc(Statement->getBeginLoc());
    SourceLocation End = SM.getSpellingLoc(Statement->getEndLoc());
    return clean(Lexer::getSourceText(
        CharSourceRange::getTokenRange(Begin, End), SM, Context.getLangOpts()));
  }

  std::string key(const FunctionDecl *Function) const {
    std::string Name = Function->getQualifiedNameAsString();
    if (Function->getFormalLinkage() == Linkage::Internal)
      return file(Function->getLocation()) + "::" + Name;
    return Name;
  }

  static const Expr *ignore(const Expr *Expression) {
    return Expression ? Expression->IgnoreParenImpCasts() : nullptr;
  }

  static const ParmVarDecl *parameter(const Expr *Expression) {
    const auto *Reference = dyn_cast_or_null<DeclRefExpr>(ignore(Expression));
    return Reference ? dyn_cast<ParmVarDecl>(Reference->getDecl()) : nullptr;
  }

  static const ValueDecl *value(const Expr *Expression) {
    Expression = ignore(Expression);
    if (const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Expression))
      return dyn_cast<ValueDecl>(Reference->getDecl());
    if (const auto *Member = dyn_cast_or_null<MemberExpr>(Expression))
      return Member->getMemberDecl();
    return nullptr;
  }

  static const ValueDecl *integerSource(const Expr *Expression) {
    Expression = Expression ? Expression->IgnoreParens() : nullptr;
    while (const auto *Cast = dyn_cast_or_null<CastExpr>(Expression))
      Expression = Cast->getSubExpr()->IgnoreParens();
    return value(Expression);
  }

  static bool unitInteger(const Expr *Expression) {
    const auto *Literal = dyn_cast_or_null<IntegerLiteral>(ignore(Expression));
    return Literal && Literal->getValue() == 1;
  }

  static bool integerGreaterThanOne(const Expr *Expression) {
    const auto *Literal = dyn_cast_or_null<IntegerLiteral>(ignore(Expression));
    return Literal && Literal->getValue().ugt(1);
  }

  static bool positiveInteger(const Expr *Expression) {
    const auto *Literal = dyn_cast_or_null<IntegerLiteral>(ignore(Expression));
    return Literal && !Literal->getValue().isZero();
  }

  static bool positiveConstantStep(const Expr *Expression) {
    if (positiveInteger(Expression))
      return true;
    const auto *Trait =
        dyn_cast_or_null<UnaryExprOrTypeTraitExpr>(ignore(Expression));
    return Trait && (Trait->getKind() == UETT_SizeOf ||
                     Trait->getKind() == UETT_AlignOf);
  }

  static bool unsignedByteValue(const Expr *Expression) {
    Expression = ignore(Expression);
    if (const auto *Cast = dyn_cast_or_null<ExplicitCastExpr>(Expression))
      Expression = ignore(Cast->getSubExpr());
    const auto *Builtin = Expression
                              ? Expression->getType()->getAs<BuiltinType>()
                              : nullptr;
    return Builtin && (Builtin->getKind() == BuiltinType::UChar ||
                       Builtin->getKind() == BuiltinType::Char_U);
  }

  static bool strictlyPositive(const Expr *Expression) {
    Expression = ignore(Expression);
    if (positiveInteger(Expression))
      return true;
    const auto *Binary = dyn_cast_or_null<BinaryOperator>(Expression);
    if (!Binary || Binary->getOpcode() != BO_Add)
      return false;
    const Expr *Left = ignore(Binary->getLHS());
    const Expr *Right = ignore(Binary->getRHS());
    /* An arbitrary unsigned value plus one can wrap to zero.  The byte
     * source is the one useful bounded form in this tree: after integer
     * promotion its maximum plus one is still strictly positive. */
    return (unitInteger(Left) && unsignedByteValue(Right)) ||
           (unitInteger(Right) && unsignedByteValue(Left));
  }

  static bool zeroInteger(const Expr *Expression) {
    const auto *Literal = dyn_cast_or_null<IntegerLiteral>(ignore(Expression));
    return Literal && Literal->getValue().isZero();
  }

  static bool nonzeroWhen(const Expr *Condition, const ValueDecl *Parameter,
                          bool Truth) {
    Condition = ignore(Condition);
    if (!Condition)
      return false;
    if (value(Condition) == Parameter)
      return Truth;
    if (const auto *Unary = dyn_cast<UnaryOperator>(Condition)) {
      if (Unary->getOpcode() == UO_LNot)
        return nonzeroWhen(Unary->getSubExpr(), Parameter, !Truth);
    }
    const auto *Binary = dyn_cast<BinaryOperator>(Condition);
    if (!Binary)
      return false;
    if (Binary->getOpcode() == BO_LAnd) {
      if (Truth)
        return nonzeroWhen(Binary->getLHS(), Parameter, true) ||
               nonzeroWhen(Binary->getRHS(), Parameter, true);
      return nonzeroWhen(Binary->getLHS(), Parameter, false) &&
             nonzeroWhen(Binary->getRHS(), Parameter, false);
    }
    if (Binary->getOpcode() == BO_LOr) {
      if (Truth)
        return nonzeroWhen(Binary->getLHS(), Parameter, true) &&
               nonzeroWhen(Binary->getRHS(), Parameter, true);
      return nonzeroWhen(Binary->getLHS(), Parameter, false) ||
             nonzeroWhen(Binary->getRHS(), Parameter, false);
    }
    bool ParameterLeft =
        value(Binary->getLHS()) == Parameter && zeroInteger(Binary->getRHS());
    bool ParameterRight =
        value(Binary->getRHS()) == Parameter && zeroInteger(Binary->getLHS());
    if (!ParameterLeft && !ParameterRight)
      return false;
    switch (Binary->getOpcode()) {
    case BO_NE:
      return Truth;
    case BO_EQ:
      return !Truth;
    case BO_GT:
      return ParameterLeft && Truth;
    case BO_LT:
      return ParameterRight && Truth;
    case BO_LE:
      return ParameterLeft && !Truth;
    case BO_GE:
      return ParameterRight && !Truth;
    default:
      return false;
    }
  }

  bool guardedNonzero(const CallExpr *Call,
                      const ParmVarDecl *Parameter) const {
    DynTypedNode Node = DynTypedNode::create(*Call);
    while (true) {
      const Stmt *Child = Node.get<Stmt>();
      DynTypedNodeList Parents = Context.getParents(Node);
      if (Parents.size() != 1)
        return false;
      const DynTypedNode &Parent = Parents[0];
      if (const auto *If = Parent.get<IfStmt>()) {
        if (Child == If->getThen() &&
            nonzeroWhen(If->getCond(), Parameter, true))
          return true;
        if (Child == If->getElse() &&
            nonzeroWhen(If->getCond(), Parameter, false))
          return true;
      }
      if (const auto *While = Parent.get<WhileStmt>())
        if (Child == While->getBody() &&
            nonzeroWhen(While->getCond(), Parameter, true))
          return true;
      if (const auto *For = Parent.get<ForStmt>())
        if (Child == For->getBody() &&
            nonzeroWhen(For->getCond(), Parameter, true))
          return true;
      if (const auto *Do = Parent.get<DoStmt>())
        if (Child == Do->getBody() &&
            nonzeroWhen(Do->getCond(), Parameter, true))
          return true;
      if (const auto *Binary = Parent.get<BinaryOperator>()) {
        if (Child == Binary->getRHS() && Binary->getOpcode() == BO_LAnd &&
            nonzeroWhen(Binary->getLHS(), Parameter, true))
          return true;
        if (Child == Binary->getRHS() && Binary->getOpcode() == BO_LOr &&
            nonzeroWhen(Binary->getLHS(), Parameter, false))
          return true;
      }
      if (const auto *Conditional = Parent.get<ConditionalOperator>()) {
        if (Child == Conditional->getTrueExpr() &&
            nonzeroWhen(Conditional->getCond(), Parameter, true))
          return true;
        if (Child == Conditional->getFalseExpr() &&
            nonzeroWhen(Conditional->getCond(), Parameter, false))
          return true;
      }
      Node = Parent;
    }
  }

  const ParmVarDecl *strictlySmallerThanParameter(const Expr *Expression,
                                                  const CallExpr *Call) const {
    const auto *Binary = dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    if (!Binary || Binary->getOpcode() != BO_Sub ||
        !unitInteger(Binary->getRHS()))
      return nullptr;
    const ParmVarDecl *Left = parameter(Binary->getLHS());
    if (!Left || !Left->getType()->isIntegerType() ||
        !guardedNonzero(Call, Left))
      return nullptr;
    return Left;
  }

  /* A pointer argument carried into a recursive call unchanged (the plain
   * '=' case just below) gives the size-change graph no decrease to
   * report, even when the callee is provably closer to done: a parser
   * struct passed by pointer at every call of a recursive-descent grammar
   * is that exact shape, with the real progress in a cursor FIELD of the
   * pointee instead of the pointer value itself.  firstPointerField()
   * fixes which field that is -- the struct's own first pointer-typed
   * field, in declaration order -- once and for all from the type alone,
   * so any two functions sharing the struct type agree on it without
   * comparing notes.  Each function gets one extra "virtual parameter"
   * slot per real parameter (see the doubled count in TraverseFunctionDecl
   * below) carrying that field's own progress across the same call graph
   * lint-totality.py already walks for the real parameters -- a strict
   * step there composes exactly like a strict step on a real argument. */
  static const FieldDecl *firstPointerField(QualType Type) {
    const auto *Pointer = Type->getAs<PointerType>();
    const RecordDecl *Record =
        Pointer ? Pointer->getPointeeType()->getAsRecordDecl() : nullptr;
    if (!Record || !Record->isCompleteDefinition())
      return nullptr;
    for (const FieldDecl *Field : Record->fields())
      if (Field->getType()->isPointerType())
        return Field;
    return nullptr;
  }

  /* A global (or file-static) of the cursor struct's own type gives some
   * entirely unrelated function a second, untracked route to the same
   * field.  Bail rather than assume every write to it arrives only
   * through the parameter this analysis is following. */
  bool recordDeclaredGlobally(const RecordDecl *Record) const {
    Record = cast<RecordDecl>(Record->getCanonicalDecl());
    auto Cached = GlobalRecordCache.find(Record);
    if (Cached != GlobalRecordCache.end())
      return Cached->second;
    bool Found = false;
    for (const Decl *Declaration : Context.getTranslationUnitDecl()->decls()) {
      const auto *Variable = dyn_cast<VarDecl>(Declaration);
      if (!Variable || !Variable->hasGlobalStorage())
        continue;
      QualType Type = Variable->getType();
      const RecordDecl *Candidate = Type->getAsRecordDecl();
      if (!Candidate) {
        const auto *Pointer = Type->getAs<PointerType>();
        Candidate = Pointer ? Pointer->getPointeeType()->getAsRecordDecl() : nullptr;
      }
      if (Candidate && Candidate->getCanonicalDecl() == Record) {
        Found = true;
        break;
      }
    }
    GlobalRecordCache[Record] = Found;
    return Found;
  }

  static bool containsGotoOrLabel(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (isa<GotoStmt>(Statement) || isa<IndirectGotoStmt>(Statement) ||
        isa<LabelStmt>(Statement))
      return true;
    for (const Stmt *Child : Statement->children())
      if (containsGotoOrLabel(Child))
        return true;
    return false;
  }

  /* Every statement guaranteed to already have run, in order, by the time
   * Node is reached: Node's own preceding siblings, then its enclosing
   * block's preceding siblings, and so on out to the function body.
   * Climbing past a non-block ancestor (an IfStmt's then-branch, a loop
   * body) contributes nothing at that level -- entering it at all already
   * implies whatever test guards it ran, but nothing about which of its
   * own statements executed, so this stays conservative and adds no
   * false prefix.  An ambiguous or non-statement parent -- unexpected in
   * a plain C function body -- empties the result rather than risk an
   * incomplete one, with one deliberate exception: a call that is itself
   * a local variable's own initializer (`T x = f(...);`, the single most
   * common recursive-descent shape in this tree -- every `T v =
   * production(p);` first line) has that VarDecl as its immediate AST
   * parent, not a Stmt, since the grammar for a declarator's initializer
   * has no Stmt node of its own. Climbing one further hop to the
   * DeclStmt that actually IS the enclosing CompoundStmt's direct child
   * recovers exactly the unit a plain `T x; x = f(...);` two-statement
   * spelling would already present here -- same statement boundary,
   * same preceding-siblings semantics, just without an extra line. */
  std::vector<const Stmt *> precedingStatements(const Stmt *Node) const {
    std::vector<const Stmt *> Result;
    const Stmt *Target = Node;
    while (true) {
      DynTypedNodeList Parents =
          Context.getParents(DynTypedNode::create(*Target));
      if (Parents.size() != 1)
        return {};
      const Stmt *Parent = Parents[0].get<Stmt>();
      if (!Parent) {
        const auto *AsVar = Parents[0].get<VarDecl>();
        if (!AsVar)
          return {};
        DynTypedNodeList DeclParents =
            Context.getParents(DynTypedNode::create(*AsVar));
        const auto *AsDeclStmt =
            DeclParents.size() == 1 ? DeclParents[0].get<DeclStmt>() : nullptr;
        if (!AsDeclStmt)
          return {};
        Target = AsDeclStmt;
        continue;
      }
      const auto *Compound = dyn_cast<CompoundStmt>(Parent);
      if (!Compound) {
        Target = Parent;
        continue;
      }
      for (const Stmt *Child : Compound->body()) {
        if (Child == Target)
          break;
        Result.push_back(Child);
      }
      if (Compound == Current->getBody())
        return Result;
      Target = Compound;
    }
  }

  /* True exactly for the same shape the witness search in
   * fieldProgressRelation() looks for: Expression is itself a strict,
   * admissible, pointer-typed advance of Field through Base.  Reused so
   * an already-recognized advance reached through a further call --
   * ere_branch() calling ere_atom(), whose own "ps->p++" is a statement
   * in a different function entirely -- excuses itself the same way a
   * direct one would, instead of registering as unexplained interference
   * (see the TolerateAdvances parameter below). */
  bool safeFieldAdvance(const Expr *Expression, const ValueDecl *Base,
                        const FieldDecl *Field) const {
    std::optional<Progress> Candidate = progress(Expression);
    return Candidate && Candidate->Base == Base && Candidate->Variable == Field &&
           Candidate->Kind == ProgressKind::Up &&
           Candidate->Variable->getType()->isPointerType() &&
           admissibleProgress(*Candidate);
  }

  /* Is Argument (0-based) of Function's own parameter list annotated
   * endptr_advances (see ownership.h)?  Mirrors nullTerminatedParameter()
   * below verbatim -- same redecls walk, same reason (the annotation is a
   * fact about the declared contract, so any redeclaration carrying it is
   * as good as the others). */
  static bool endptrAdvancesParameter(const FunctionDecl *Function,
                                      unsigned Argument) {
    if (!Function)
      return false;
    for (const FunctionDecl *Redeclaration : Function->redecls()) {
      if (Argument >= Redeclaration->getNumParams())
        continue;
      for (const AnnotateAttr *Attribute :
           Redeclaration->getParamDecl(Argument)->specific_attrs<AnnotateAttr>())
        if (Attribute->getAnnotation() == "qual:endptr_advances")
          return true;
    }
    return false;
  }

  /* Statement's own immediately-preceding sibling in whichever
   * CompoundStmt directly contains it -- nullptr if Statement is the
   * first statement there, or isn't a direct CompoundStmt child at all
   * (an unbraced `if (x) base->field = end;`, say). Deliberately does
   * NOT climb further like precedingStatements() does: this is used to
   * confirm one very specific two-statement idiom sits exactly next to
   * itself, not to gather everything that provably already ran.  Usable
   * from inside ANY function body mayWriteFieldThroughParam() is
   * currently walking (unlike precedingStatements(), which is only ever
   * meaningful relative to Current). */
  static const Stmt *immediatelyPrecedingSibling(ASTContext &Context,
                                                 const Stmt *Statement) {
    DynTypedNodeList Parents =
        Context.getParents(DynTypedNode::create(*Statement));
    if (Parents.size() != 1)
      return nullptr;
    const auto *Compound = Parents[0].get<CompoundStmt>();
    if (!Compound)
      return nullptr;
    const Stmt *Previous = nullptr;
    for (const Stmt *Child : Compound->body()) {
      if (Child == Statement)
        return Previous;
      Previous = Child;
    }
    return nullptr;
  }

  /* The CallExpr Statement most directly makes, if any: `f(...);` alone,
   * `x = f(...);`, or `T v = f(...);` -- exactly the handful of shapes a
   * one-line "convert and advance" idiom actually appears in.  Not a
   * general expression walk: a call buried further inside some larger
   * expression is deliberately left unmatched, the same conservatism
   * safeFieldAdvance()'s own witness shapes already apply. */
  static const CallExpr *directCall(const Stmt *Statement) {
    if (const auto *Declaration = dyn_cast<DeclStmt>(Statement)) {
      if (!Declaration->isSingleDecl())
        return nullptr;
      const auto *Local = dyn_cast<VarDecl>(Declaration->getSingleDecl());
      return Local ? dyn_cast_or_null<CallExpr>(ignore(Local->getInit()))
                   : nullptr;
    }
    const auto *Expression = dyn_cast<Expr>(Statement);
    if (!Expression)
      return nullptr;
    const Expr *Plain = ignore(Expression);
    const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain);
    if (Binary && Binary->isAssignmentOp())
      return dyn_cast_or_null<CallExpr>(ignore(Binary->getRHS()));
    return dyn_cast_or_null<CallExpr>(Plain);
  }

  /* True for exactly the C standard's own strtol()/strtoul()/strtod()/...
   * idiom: `T *end; ...; Base->Field = end;`, where `end` was populated,
   * in the immediately preceding statement, by a call whose own first
   * argument reads Base->Field's CURRENT value and whose endptr_advances
   * parameter is `&end`. Base->Field can therefore not have MOVED
   * BACKWARD across this statement -- see ownership.h's endptr_advances
   * comment for the exact standard citation -- which is all that is
   * needed to fold it into an already-witnessed '<' proof the same way
   * safeFieldAdvance()'s own recognized shapes already are (see
   * bodyMayWriteField()'s Excused computation). It is deliberately never
   * itself offered as a witness: the standard guarantees no more than
   * "did not go backward" here (a completely failed conversion leaves
   * *endptr == the input pointer), the non-strict half of the proof. */
  bool toleratedPointerReassign(const Stmt *Statement, const ValueDecl *Base,
                                const FieldDecl *Field) const {
    const auto *Expression = dyn_cast<Expr>(Statement);
    const auto *Binary =
        Expression ? dyn_cast_or_null<BinaryOperator>(ignore(Expression))
                   : nullptr;
    if (!Binary || Binary->getOpcode() != BO_Assign)
      return false;
    const auto *Member = dyn_cast_or_null<MemberExpr>(ignore(Binary->getLHS()));
    if (!Member || Member->getMemberDecl() != Field ||
        value(Member->getBase()) != Base)
      return false;
    const auto *EndReference =
        dyn_cast_or_null<DeclRefExpr>(ignore(Binary->getRHS()));
    const auto *End =
        EndReference ? dyn_cast<VarDecl>(EndReference->getDecl()) : nullptr;
    if (!End || !End->hasLocalStorage() || End->getType().isVolatileQualified())
      return false;
    const Stmt *Previous = immediatelyPrecedingSibling(Context, Statement);
    const CallExpr *Call = Previous ? directCall(Previous) : nullptr;
    const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
    if (!Callee || Call->getNumArgs() == 0)
      return false;
    const auto *Arg0 = dyn_cast_or_null<MemberExpr>(ignore(Call->getArg(0)));
    if (!Arg0 || Arg0->getMemberDecl() != Field ||
        value(Arg0->getBase()) != Base)
      return false;
    for (unsigned K = 1; K < Call->getNumArgs() && K < Callee->getNumParams();
        ++K) {
      if (!endptrAdvancesParameter(Callee, K))
        continue;
      const auto *AddrOf =
          dyn_cast_or_null<UnaryOperator>(ignore(Call->getArg(K)));
      if (AddrOf && AddrOf->getOpcode() == UO_AddrOf &&
          value(AddrOf->getSubExpr()) == End)
        return true;
    }
    return false;
  }

  using FieldVisitSet = std::set<std::pair<const FunctionDecl *, unsigned>>;

  /* Does invoking Function, with Base's own pointer value landed in its
   * ParamIndex-th parameter, reach a write to Field -- directly, or by
   * forwarding that same parameter on into a further call?  A call that
   * never receives Base at all cannot reach Field through it regardless
   * of the call's own parameter types, which is what lets a call like
   * realloc(rx->prog, ...) -- typed compatibly but never handed ps --
   * pass unexamined without this ever having to look inside realloc().
   *
   * A (Function, ParamIndex) pair already on the active Visiting stack is
   * a real call-graph cycle back to an obligation this same query is
   * still in the middle of discharging -- exactly the shape
   * ere_branch()->ere_atom()->ere_alt() closes back on ere_alt() itself.
   * "May write unsafely" is a safety property (every reachable write, on
   * every explored path, must be a safe advance), and the standard proof
   * technique for a safety property over a cyclic graph is coinductive:
   * assume the property along a back-edge and verify every NEW
   * obligation it unfolds to.  Every direct write reachable without
   * detouring through this exact back-edge was already inspected on the
   * way to it, so resolving the back-edge itself as safe adds no
   * unchecked write -- unlike guessing "safe" at an arbitrary, unrelated
   * point, which would. */
  bool mayWriteFieldThroughParam(const FunctionDecl *Function,
                                 unsigned ParamIndex, const FieldDecl *Field,
                                 FieldVisitSet &Visiting,
                                 bool TolerateAdvances) const {
    if (!Function)
      return true;
    const FunctionDecl *Canonical = Function->getCanonicalDecl();
    if (Canonical->hasAttr<PureAttr>() || Canonical->hasAttr<ConstAttr>() ||
        ReadonlyFunctions.contains(Canonical))
      return false;
    const FunctionDecl *Definition = Canonical->getDefinition();
    if (!Definition || !Definition->hasBody() ||
        ParamIndex >= Definition->getNumParams())
      return true;
    if (!Visiting.insert({Definition, ParamIndex}).second)
      return false;
    bool Result = bodyMayWriteField(Definition->getBody(),
                                    Definition->getParamDecl(ParamIndex),
                                    Field, Visiting, nullptr, TolerateAdvances);
    Visiting.erase({Definition, ParamIndex});
    return Result;
  }

  /* TolerateAdvances is always true along every path down from
   * fieldProgressRelation() today (see its own comment: both of its
   * possible claims -- '<' with a witness in hand, or '<=' with none --
   * are safe to compose past an already-recognized forward-or-unchanged
   * write, since neither claim is "Field is bit-for-bit identical").
   * The parameter still exists, rather than being dropped in favor of a
   * bare `true`, so a future caller wanting the strictly stronger "not
   * even a recognized advance occurred" claim can ask for it without
   * another traversal function to keep in sync with this one. */
  bool bodyMayWriteField(const Stmt *Statement, const ValueDecl *Base,
                         const FieldDecl *Field, FieldVisitSet &Visiting,
                         const Stmt *Ignore, bool TolerateAdvances) const {
    if (!Statement || Statement == Ignore)
      return false;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      bool Excused = TolerateAdvances &&
          (safeFieldAdvance(Plain, Base, Field) ||
           toleratedPointerReassign(Statement, Base, Field));
      if (!Excused) {
        if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain)) {
          const auto *Member = Unary->isIncrementDecrementOp()
              ? dyn_cast_or_null<MemberExpr>(ignore(Unary->getSubExpr()))
              : nullptr;
          if (Member && Member->getMemberDecl() == Field &&
              value(Member->getBase()) == Base)
            return true;
        }
        if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain)) {
          if (Binary->isAssignmentOp()) {
            const Expr *LHS = ignore(Binary->getLHS());
            const auto *Member = dyn_cast_or_null<MemberExpr>(LHS);
            if (Member && Member->getMemberDecl() == Field &&
                value(Member->getBase()) == Base)
              return true;
            const auto *Deref = dyn_cast_or_null<UnaryOperator>(LHS);
            if (Deref && Deref->getOpcode() == UO_Deref &&
                value(Deref->getSubExpr()) == Base)
              return true; // *base = wholeObject overwrites every field.
            if (Binary->getOpcode() == BO_Assign &&
                value(Binary->getRHS()) == Base && value(LHS) != Base &&
                LHS->getType()->isPointerType())
              return true; // a second alias of Base, untracked from here.
          }
        }
      }
      if (const auto *Call = dyn_cast<CallExpr>(Plain)) {
        const FunctionDecl *Callee = Call->getDirectCallee();
        for (unsigned I = 0; I < Call->getNumArgs(); ++I)
          if (value(Call->getArg(I)) == Base &&
              mayWriteFieldThroughParam(Callee, I, Field, Visiting,
                                        TolerateAdvances))
            return true;
      }
    }
    if (const auto *Declaration = dyn_cast<DeclStmt>(Statement))
      for (const Decl *Item : Declaration->decls())
        if (const auto *Local = dyn_cast<VarDecl>(Item))
          if (Local->getType()->isPointerType() &&
              value(Local->getInit()) == Base)
            return true; // Base's pointer value escapes to a fresh alias.
    for (const Stmt *Child : Statement->children())
      if (bodyMayWriteField(Child, Base, Field, Visiting, Ignore,
                            TolerateAdvances))
        return true;
    return false;
  }

  /* std::nullopt: no virtual-slot relation applies (Source isn't a
   * pointer to a struct with a tracked field, or the shape wasn't
   * recognized -- or some intervening statement writes Field in a way
   * that is neither a recognized advance nor provably absent, so even
   * "non-decreasing" cannot be claimed).  false: the field demonstrably
   * never moves BACKWARD before this call ('=' in the size-change matrix
   * lint-totality.py composes -- read here as "no smaller", i.e. <=,
   * not literally "identical": every intervening write, if any, is
   * itself one of the recognized forward-or-unchanged shapes
   * safeFieldAdvance()/toleratedPointerReassign() already accept
   * elsewhere, such as a whitespace-skipping helper that may or may not
   * have actually consumed anything). true: it strictly advanced first
   * ('<'), by the same escape-to-UB argument pointerObjectDistanceRank()
   * already relies on for loops -- a monotonic pointer step through a
   * finite object either meets its bound in finitely many steps or
   * leaves defined C, which this proof is not responsible for.
   *
   * Composing a "<=" edge with a "<" edge anywhere else on the same
   * cycle is still exactly the strict overall relation lint-totality.py
   * requires (x <= y < z implies x < z), which is what makes it sound to
   * tolerate a recognized forward-or-unchanged write here even when this
   * SPECIFIC call has no witness of its own to offer: unlike the real
   * (non-virtual) parameter slots, where '=' means the caller handed the
   * callee the exact same value and TolerateAdvances therefore has to
   * stay false with no witness (a real write there would be a
   * contradiction, not just a weaker fact), this virtual slot's whole
   * purpose is tracking a monotonically-advancing cursor, so "did not go
   * backward" is a genuine, useful, and always-soundly-composable fact
   * regardless of whether THIS call site also happens to supply the
   * cycle's own strict step. */
  std::optional<bool> fieldProgressRelation(const CallExpr *Call,
                                            const ParmVarDecl *Source,
                                            const FunctionDecl *Callee,
                                            unsigned Destination) const {
    if (!Source->getType()->isPointerType() ||
        Destination >= Callee->getNumParams())
      return std::nullopt;
    const ParmVarDecl *CalleeParam = Callee->getParamDecl(Destination);
    const FieldDecl *Field = firstPointerField(Source->getType());
    if (!Field || firstPointerField(CalleeParam->getType()) != Field)
      return std::nullopt;
    if (recordDeclaredGlobally(Field->getParent()) ||
        containsGotoOrLabel(Current->getBody()) ||
        writesVariable(Current->getBody(), Source))
      return std::nullopt;
    std::vector<const Stmt *> Preceding = precedingStatements(Call);
    const Stmt *Witness = nullptr;
    for (auto It = Preceding.rbegin(); It != Preceding.rend() && !Witness;
        ++It) {
      const auto *AsExpr = dyn_cast<Expr>(*It);
      if (AsExpr && safeFieldAdvance(AsExpr, Source, Field))
        Witness = *It;
    }
    /* Seeding with (Current, Source's own index) blocks re-descending
     * into Current through this same parameter for the same reason a
     * true cycle stops there -- see mayWriteFieldThroughParam(). */
    FieldVisitSet Visiting{{Current, Source->getFunctionScopeIndex()}};
    for (const Stmt *Statement : Preceding)
      if (Statement != Witness &&
          bodyMayWriteField(Statement, Source, Field, Visiting, nullptr,
                            /*TolerateAdvances=*/true))
        return std::nullopt;
    return Witness ? std::make_optional(true) : std::make_optional(false);
  }

  std::string callRelations(const CallExpr *Call,
                            const FunctionDecl *Callee) const {
    std::string Result;
    auto Append = [&Result](unsigned Destination, unsigned SourceIndex,
                            char Relation) {
      if (!Result.empty())
        Result += ',';
      Result += std::to_string(Destination) + ':' +
                std::to_string(SourceIndex) + ':' + Relation;
    };
    for (unsigned Destination = 0; Destination < Call->getNumArgs() &&
                                   Destination < Callee->getNumParams();
         ++Destination) {
      const Expr *Argument = Call->getArg(Destination);
      const ParmVarDecl *Source = parameter(Argument);
      char Relation = '=';
      if (!Source) {
        Source = strictlySmallerThanParameter(Argument, Call);
        Relation = '<';
      }
      if (!Source)
        continue;
      unsigned SourceIndex = 0;
      while (SourceIndex < Current->getNumParams() &&
             Current->getParamDecl(SourceIndex) != Source)
        ++SourceIndex;
      if (SourceIndex == Current->getNumParams())
        continue;
      Append(Destination, SourceIndex, Relation);
      if (Relation == '=') {
        std::optional<bool> FieldRelation =
            fieldProgressRelation(Call, Source, Callee, Destination);
        if (FieldRelation)
          Append(Callee->getNumParams() + Destination,
                Current->getNumParams() + SourceIndex,
                *FieldRelation ? '<' : '=');
      }
    }
    return Result.empty() ? "-" : Result;
  }

  static Progress makeProgress(const ValueDecl *Variable, ProgressKind Kind,
                               const ValueDecl *Base, const Expr *Access,
                               const Expr *GuardedStep = nullptr,
                               bool RequiresNonzeroCondition = false,
                               bool UnitStep = false,
                               const ValueDecl *DynamicStep = nullptr,
                               bool UnaryStep = false) {
    return Progress{Variable, Kind, Base, GuardedStep,
                    Access && Access->getType().isVolatileQualified(),
                    RequiresNonzeroCondition, UnitStep, false, DynamicStep,
                    UnaryStep};
  }

  static bool sameRank(const Progress &Left, const Progress &Right) {
    if (Left.Variable != Right.Variable)
      return false;
    return !isa<FieldDecl>(Left.Variable) || Left.Base == Right.Base;
  }

  static bool rankAccess(const Expr *Expression, const Progress &Rank) {
    Expression = ignore(Expression);
    if (const auto *Field = dyn_cast<FieldDecl>(Rank.Variable)) {
      const auto *Member = dyn_cast_or_null<MemberExpr>(Expression);
      return Member && Member->getMemberDecl() == Field &&
             value(Member->getBase()) == Rank.Base;
    }
    return value(Expression) == Rank.Variable;
  }

  static bool basedOn(const Expr *Expression, const Progress &Rank) {
    Expression = ignore(Expression);
    if (rankAccess(Expression, Rank))
      return true;
    if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Expression))
      return basedOn(Unary->getSubExpr(), Rank);
    if (const auto *Member = dyn_cast_or_null<MemberExpr>(Expression))
      return basedOn(Member->getBase(), Rank);
    if (const auto *Subscript =
            dyn_cast_or_null<ArraySubscriptExpr>(Expression))
      return basedOn(Subscript->getBase(), Rank) ||
             basedOn(Subscript->getIdx(), Rank);
    return false;
  }

  static std::optional<Progress> progress(const Expr *Expression) {
    Expression = ignore(Expression);
    if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Expression)) {
      const ValueDecl *Variable = value(Unary->getSubExpr());
      if (!Variable)
        return std::nullopt;
      const auto *Member = dyn_cast_or_null<MemberExpr>(
          ignore(Unary->getSubExpr()));
      const ValueDecl *Base = Member ? value(Member->getBase()) : nullptr;
      if (Unary->isIncrementOp())
        return makeProgress(Variable, ProgressKind::Up, Base,
                            Unary->getSubExpr(), nullptr, false, true,
                            nullptr, true);
      if (Unary->isDecrementOp())
        return makeProgress(Variable, ProgressKind::Down, Base,
                            Unary->getSubExpr(), nullptr, false, true,
                            nullptr, true);
    }
    const auto *Binary = dyn_cast_or_null<BinaryOperator>(Expression);
    if (!Binary)
      return std::nullopt;
    const ValueDecl *Variable = value(Binary->getLHS());
    if (!Variable)
      return std::nullopt;
    const auto *Member =
        dyn_cast_or_null<MemberExpr>(ignore(Binary->getLHS()));
    const ValueDecl *Base = Member ? value(Member->getBase()) : nullptr;
    const ValueDecl *DynamicStep = integerSource(Binary->getRHS());
    bool DynamicIntegerStep = DynamicStep &&
        Binary->getLHS()->getType()->isIntegerType() &&
        Binary->getRHS()->getType()->isIntegerType() &&
        DynamicStep->getType()->isIntegerType();
    bool DynamicPointerStep = DynamicStep &&
        Binary->getLHS()->getType()->isPointerType() &&
        Binary->getRHS()->getType()->isIntegerType() &&
        DynamicStep->getType()->isIntegerType();
    /* A step larger than one can jump over the bound and wrap.  In
     * particular, `for (unsigned i = 0; i < UINT_MAX; i += 2)` does not
     * terminate.  Unit steps are the only context-free scalar proof. */
    if (Binary->getOpcode() == BO_AddAssign &&
        (unitInteger(Binary->getRHS()) ||
         (Variable->getType()->isSignedIntegerType() &&
          positiveInteger(Binary->getRHS())) ||
         (Variable->getType()->isUnsignedIntegerType() &&
          positiveConstantStep(Binary->getRHS())) ||
         (Variable->getType()->isPointerType() &&
          strictlyPositive(Binary->getRHS())) ||
         DynamicIntegerStep || DynamicPointerStep))
      return makeProgress(
          Variable, ProgressKind::Up, Base, Binary->getLHS(),
          DynamicIntegerStep || DynamicPointerStep ||
                  (Variable->getType()->isUnsignedIntegerType() &&
                   !unitInteger(Binary->getRHS()))
              ? Binary->getRHS()
              : nullptr,
          false, unitInteger(Binary->getRHS()),
          (DynamicIntegerStep || DynamicPointerStep) ? DynamicStep : nullptr);
    if (Binary->getOpcode() == BO_SubAssign &&
        (unitInteger(Binary->getRHS()) ||
         (Variable->getType()->isSignedIntegerType() &&
          positiveInteger(Binary->getRHS())) ||
         (Variable->getType()->isUnsignedIntegerType() &&
          positiveConstantStep(Binary->getRHS())) ||
         DynamicIntegerStep))
      return makeProgress(
          Variable, ProgressKind::Down, Base, Binary->getLHS(),
          DynamicIntegerStep ? Binary->getRHS() :
          (Variable->getType()->isUnsignedIntegerType() &&
                   !unitInteger(Binary->getRHS())
              ? Binary->getRHS()
              : nullptr),
          false, unitInteger(Binary->getRHS()),
          DynamicIntegerStep ? DynamicStep : nullptr);
    /* For an unsigned value tested for nonzero, division by a constant
     * greater than one is a strict descent to zero.  This is the common
     * integer-to-text digit loop (`while (u) u /= 10`); unlike a non-unit
     * additive step it cannot skip a bound and wrap back around. */
    if (Binary->getOpcode() == BO_DivAssign &&
        Variable->getType()->isIntegerType() &&
        integerGreaterThanOne(Binary->getRHS()))
      return makeProgress(Variable, ProgressKind::Down, Base,
                          Binary->getLHS(), nullptr, true);
    if (Binary->getOpcode() == BO_ShrAssign &&
        Variable->getType()->isUnsignedIntegerType() &&
        positiveInteger(Binary->getRHS()))
      return makeProgress(Variable, ProgressKind::Down, Base,
                          Binary->getLHS(), nullptr, true);
    if (!Binary->isAssignmentOp())
      return std::nullopt;
    const Expr *Right = ignore(Binary->getRHS());
    if (const auto *Operation = dyn_cast<BinaryOperator>(Right)) {
      if (value(Operation->getLHS()) == Variable) {
        const ValueDecl *AssignedStep = integerSource(Operation->getRHS());
        bool DynamicAssignedStep = AssignedStep &&
            Binary->getLHS()->getType()->isIntegerType() &&
            Operation->getRHS()->getType()->isIntegerType() &&
            AssignedStep->getType()->isIntegerType();
        bool DynamicAssignedPointerStep = AssignedStep &&
            Binary->getLHS()->getType()->isPointerType() &&
            Operation->getRHS()->getType()->isIntegerType() &&
            AssignedStep->getType()->isIntegerType();
        if (Operation->getOpcode() == BO_Add &&
            (unitInteger(Operation->getRHS()) ||
             (Variable->getType()->isSignedIntegerType() &&
              positiveInteger(Operation->getRHS())) ||
             (Variable->getType()->isUnsignedIntegerType() &&
              positiveConstantStep(Operation->getRHS())) ||
             (Variable->getType()->isPointerType() &&
              strictlyPositive(Operation->getRHS())) ||
             DynamicAssignedStep || DynamicAssignedPointerStep))
          return makeProgress(
              Variable, ProgressKind::Up, Base, Binary->getLHS(),
              DynamicAssignedStep || DynamicAssignedPointerStep ||
                      (Variable->getType()->isUnsignedIntegerType() &&
                       !unitInteger(Operation->getRHS()))
                  ? Operation->getRHS()
                  : nullptr,
              false, unitInteger(Operation->getRHS()),
              (DynamicAssignedStep || DynamicAssignedPointerStep)
                  ? AssignedStep
                  : nullptr);
        if (Operation->getOpcode() == BO_Sub &&
            (unitInteger(Operation->getRHS()) ||
             (Variable->getType()->isSignedIntegerType() &&
              positiveInteger(Operation->getRHS())) ||
             (Variable->getType()->isUnsignedIntegerType() &&
              positiveConstantStep(Operation->getRHS())) ||
             DynamicAssignedStep))
          return makeProgress(
              Variable, ProgressKind::Down, Base, Binary->getLHS(),
              DynamicAssignedStep ? Operation->getRHS() :
              (Variable->getType()->isUnsignedIntegerType() &&
                       !unitInteger(Operation->getRHS())
                      ? Operation->getRHS()
                      : nullptr),
              false, unitInteger(Operation->getRHS()),
              DynamicAssignedStep ? AssignedStep : nullptr);
        if (Operation->getOpcode() == BO_Div &&
            Variable->getType()->isIntegerType() &&
            integerGreaterThanOne(Operation->getRHS()))
          return makeProgress(Variable, ProgressKind::Down, Base,
                              Binary->getLHS(), nullptr, true);
        if (Operation->getOpcode() == BO_Shr &&
            Variable->getType()->isUnsignedIntegerType() &&
            positiveInteger(Operation->getRHS()))
          return makeProgress(Variable, ProgressKind::Down, Base,
                              Binary->getLHS(), nullptr, true);
      }
    }
    /* `node = node->next` is progress only when the structure is acyclic.
     * C's type system does not carry that invariant, so recognizing the
     * assignment syntactically would "prove" a circular list. */
    return std::nullopt;
  }

  enum FlowOutcome : unsigned {
    FallWithoutProgress = 1,
    FallWithProgress = 2,
    BackWithoutProgress = 4,
    BackWithProgress = 8,
    ExitsLoop = 16,
    BreakWithoutProgress = 32,
    BreakWithProgress = 64,
    FallAtTerminatingSentinel = 128,
    BreakAtTerminatingSentinel = 256,
  };

  struct Flow {
    unsigned Outcomes;
    bool Invalid;
    /* Multiple upward unsigned steps can skip a strict bound and wrap. */
    bool RepeatedProgress = false;
  };

  enum class Mutation { None, Good, Bad };

  static Mutation mergeMutation(Mutation Left, Mutation Right) {
    if (Left == Mutation::Bad || Right == Mutation::Bad)
      return Mutation::Bad;
    if (Left == Mutation::Good || Right == Mutation::Good)
      return Mutation::Good;
    return Mutation::None;
  }

  static Mutation mutation(const Stmt *Statement, const Progress &Expected) {
    if (!Statement)
      return Mutation::None;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      if (std::optional<Progress> Change = progress(Expression)) {
        if (sameRank(*Change, Expected)) {
          if (Change->Kind != Expected.Kind)
            return Mutation::Bad;
          /* A condition guarding one unsigned chunk size says nothing about
           * a different chunk on another path.  Requiring the very same AST
           * update keeps the guarded proof single-step.  A proof which
           * specifically requires a unit step must likewise not be
           * satisfied by a wider signed update on another path. */
          if ((Change->GuardedStep || Expected.GuardedStep) &&
              Change->GuardedStep != Expected.GuardedStep) {
            /* A mandatory unit pointer rank may be accompanied by another
             * same-direction unsigned offset.  The latter cannot reverse
             * the rank; if it leaves the array object, pointer arithmetic
             * is already undefined rather than wrapping into a cycle. */
            bool NonnegativePointerExtra =
                Expected.Variable->getType()->isPointerType() &&
                Expected.UnitStep && !Expected.GuardedStep &&
                Change->DynamicStep && Change->GuardedStep &&
                Change->GuardedStep->getType()->isUnsignedIntegerType();
            if (!NonnegativePointerExtra)
              return Mutation::Bad;
          }
          if (Change->RequiresNonzeroCondition !=
              Expected.RequiresNonzeroCondition)
            return Mutation::Bad;
          if (Expected.UnitOnly && !Change->UnitStep)
            return Mutation::Bad;
          return Mutation::Good;
        }
      }
      const Expr *Plain = ignore(Expression);
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain)) {
        if ((Unary->isIncrementDecrementOp() ||
             Unary->getOpcode() == UO_AddrOf) &&
            rankAccess(Unary->getSubExpr(), Expected))
          return Mutation::Bad;
      }
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain))
        if (Binary->isAssignmentOp() &&
            rankAccess(Binary->getLHS(), Expected))
          return Mutation::Bad;
    }
    Mutation Result = Mutation::None;
    for (const Stmt *Child : Statement->children())
      Result = mergeMutation(Result, mutation(Child, Expected));
    return Result;
  }

  static Flow sequence(Flow First, Flow Second) {
    if (First.Invalid || Second.Invalid)
      return {0, true};
    unsigned Result = First.Outcomes &
        (BackWithoutProgress | BackWithProgress | ExitsLoop |
         BreakWithoutProgress | BreakWithProgress);
    unsigned RepeatedOnPath = 0;
    if (First.Outcomes & FallWithoutProgress)
      Result |= Second.Outcomes;
    if (First.Outcomes & FallWithProgress) {
      RepeatedOnPath = Second.Outcomes &
          (FallWithProgress | BackWithProgress | BreakWithProgress);
      if (Second.Outcomes & (FallWithoutProgress | FallWithProgress))
        Result |= FallWithProgress;
      if (Second.Outcomes & (BackWithoutProgress | BackWithProgress))
        Result |= BackWithProgress;
      if (Second.Outcomes & ExitsLoop)
        Result |= ExitsLoop;
      if (Second.Outcomes &
          (BreakWithoutProgress | BreakWithProgress))
        Result |= BreakWithProgress;
      if (Second.Outcomes & FallAtTerminatingSentinel)
        Result |= FallAtTerminatingSentinel;
      if (Second.Outcomes & BreakAtTerminatingSentinel)
        Result |= BreakAtTerminatingSentinel;
    }
    if (First.Outcomes & FallAtTerminatingSentinel) {
      unsigned UnsafeContinuation = Second.Outcomes &
          (FallWithProgress | BackWithProgress | BreakWithProgress);
      if (UnsafeContinuation)
        return {0, true};
      if (Second.Outcomes &
          (FallWithoutProgress | FallAtTerminatingSentinel))
        Result |= FallAtTerminatingSentinel;
      if (Second.Outcomes & BackWithoutProgress)
        Result |= ExitsLoop;
      if (Second.Outcomes & ExitsLoop)
        Result |= ExitsLoop;
      if (Second.Outcomes & BreakWithoutProgress)
        Result |= BreakAtTerminatingSentinel;
      if (Second.Outcomes & BreakAtTerminatingSentinel)
        Result |= BreakAtTerminatingSentinel;
    }
    bool Repeated = First.RepeatedProgress || Second.RepeatedProgress ||
                    ((First.Outcomes & FallWithProgress) && RepeatedOnPath);
    return {Result, false, Repeated};
  }

  static bool sentinelLoad(const Expr *Expression, const Progress &Rank) {
    const auto *Unary = dyn_cast_or_null<UnaryOperator>(ignore(Expression));
    return Unary && Unary->getOpcode() == UO_Deref &&
           basedOn(Unary->getSubExpr(), Rank);
  }

  static bool zeroSentinelMakesConditionFalse(const Expr *Condition,
                                              const Progress &Rank) {
    Condition = ignore(Condition);
    if (sentinelLoad(Condition, Rank))
      return true;
    const auto *Binary = dyn_cast_or_null<BinaryOperator>(Condition);
    if (!Binary)
      return false;
    if (Binary->getOpcode() == BO_LAnd)
      return zeroSentinelMakesConditionFalse(Binary->getLHS(), Rank) ||
             zeroSentinelMakesConditionFalse(Binary->getRHS(), Rank);
    if (Binary->getOpcode() == BO_LOr)
      return zeroSentinelMakesConditionFalse(Binary->getLHS(), Rank) &&
             zeroSentinelMakesConditionFalse(Binary->getRHS(), Rank);
    bool LoadLeft = sentinelLoad(Binary->getLHS(), Rank) &&
                    zeroInteger(Binary->getRHS());
    bool LoadRight = sentinelLoad(Binary->getRHS(), Rank) &&
                     zeroInteger(Binary->getLHS());
    if (!LoadLeft && !LoadRight)
      return false;
    return Binary->getOpcode() == BO_NE ||
           (LoadLeft && Binary->getOpcode() == BO_GT) ||
           (LoadRight && Binary->getOpcode() == BO_LT);
  }

  static bool assignsEmptyStringSentinel(const Expr *Expression,
                                         const Progress &Rank,
                                         const Expr *LoopCondition) {
    const auto *Assignment =
        dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    if (!Assignment || Assignment->getOpcode() != BO_Assign ||
        !rankAccess(Assignment->getLHS(), Rank) ||
        !zeroSentinelMakesConditionFalse(LoopCondition, Rank))
      return false;
    const Expr *Right = Assignment->getRHS()->IgnoreParens();
    while (const auto *Cast = dyn_cast<CastExpr>(Right))
      Right = Cast->getSubExpr()->IgnoreParens();
    const auto *Literal = dyn_cast<StringLiteral>(Right);
    return Literal && Literal->getLength() == 0;
  }

  /* A direct goto to a lexically later label outside the active loop is an
   * exit edge, just like break or return.  Requiring every goto in the
   * function to target after this loop closes the route by which code at
   * the exit label could jump back and re-enter it; computed gotos remain
   * opaque.  Source-manager ordering also rejects labels hidden in the
   * loop body and macro/file ambiguities conservatively. */
  bool allGotosExitActiveLoop(const Stmt *Statement) const {
    if (!Statement || !ActiveLoop)
      return Statement != nullptr;
    if (isa<IndirectGotoStmt>(Statement))
      return false;
    if (const auto *Jump = dyn_cast<GotoStmt>(Statement)) {
      const LabelStmt *Target = Jump->getLabel()->getStmt();
      if (!Target)
        return false;
      SourceLocation LoopEnd = SM.getExpansionLoc(ActiveLoop->getEndLoc());
      SourceLocation TargetBegin =
          SM.getExpansionLoc(Target->getBeginLoc());
      if (LoopEnd.isInvalid() || TargetBegin.isInvalid() ||
          SM.getFileID(LoopEnd) != SM.getFileID(TargetBegin) ||
          !SM.isBeforeInTranslationUnit(LoopEnd, TargetBegin))
        return false;
    }
    for (const Stmt *Child : Statement->children())
      if (!allGotosExitActiveLoop(Child))
        return false;
    return true;
  }

  Flow flow(const Stmt *Statement, const Progress &Expected,
            const Expr *LoopCondition = nullptr) const {
    if (!Statement)
      return {FallWithoutProgress, false};
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain)) {
        if (Binary->getOpcode() == BO_Comma)
          return sequence(flow(Binary->getLHS(), Expected, LoopCondition),
                          flow(Binary->getRHS(), Expected, LoopCondition));
        if (Binary->getOpcode() == BO_LAnd || Binary->getOpcode() == BO_LOr) {
          Flow Left = flow(Binary->getLHS(), Expected, LoopCondition);
          Flow WithRight = sequence(
              Left, flow(Binary->getRHS(), Expected, LoopCondition));
          return {Left.Outcomes | WithRight.Outcomes,
                  Left.Invalid || WithRight.Invalid,
                  Left.RepeatedProgress || WithRight.RepeatedProgress};
        }
      }
      if (const auto *Conditional =
              dyn_cast_or_null<ConditionalOperator>(Plain)) {
        Flow Condition = flow(Conditional->getCond(), Expected, LoopCondition);
        Flow True = flow(Conditional->getTrueExpr(), Expected, LoopCondition);
        Flow False = flow(Conditional->getFalseExpr(), Expected, LoopCondition);
        Flow Arms{True.Outcomes | False.Outcomes,
                  True.Invalid || False.Invalid,
                  True.RepeatedProgress || False.RepeatedProgress};
        return sequence(Condition, Arms);
      }
      if (assignsEmptyStringSentinel(Expression, Expected, LoopCondition))
        return {FallAtTerminatingSentinel, false};
    }
    if (const auto *Compound = dyn_cast<CompoundStmt>(Statement)) {
      Flow Result{FallWithoutProgress, false};
      for (const Stmt *Child : Compound->body())
        Result = sequence(Result, flow(Child, Expected, LoopCondition));
      return Result;
    }
    if (const auto *If = dyn_cast<IfStmt>(Statement)) {
      Flow Condition = flow(If->getCond(), Expected, LoopCondition);
      Flow Then = flow(If->getThen(), Expected, LoopCondition);
      Flow Else = flow(If->getElse(), Expected, LoopCondition);
      Flow Branches{Then.Outcomes | Else.Outcomes,
                    Then.Invalid || Else.Invalid,
                    Then.RepeatedProgress || Else.RepeatedProgress};
      return sequence(Condition, Branches);
    }
    if (const auto *Label = dyn_cast<LabelStmt>(Statement))
      return flow(Label->getSubStmt(), Expected, LoopCondition);
    if (const auto *Case = dyn_cast<CaseStmt>(Statement))
      return flow(Case->getSubStmt(), Expected, LoopCondition);
    if (const auto *Default = dyn_cast<DefaultStmt>(Statement))
      return flow(Default->getSubStmt(), Expected, LoopCondition);
    if (isa<ContinueStmt>(Statement))
      return {BackWithoutProgress, false};
    if (isa<BreakStmt>(Statement))
      return {BreakWithoutProgress, false};
    if (isa<ReturnStmt>(Statement))
      return {ExitsLoop, false};
    if (isa<ForStmt>(Statement) || isa<WhileStmt>(Statement) ||
        isa<DoStmt>(Statement)) {
      /* Nested loops receive their own independent totality obligation, so
       * this proof may assume one terminates and ask only what it leaves
       * behind for Expected.  mutation() already recurses through the
       * nested loop's own condition/increment/body: None means Expected
       * is untouched, Good means every touch it found agrees with
       * Expected's own direction and guards, and Bad means it found a
       * reversal.  None and Good are therefore both, at worst, an
       * ordinary falling-through statement for the enclosing rank --
       * rejecting Good outright made a proved inner scan (a tokenizer's
       * `while (isspace) p++;`, say) poison an otherwise elementary outer
       * loop that only ever calls such scans.  A nested loop can still
       * apply Expected's own update an unbounded number of times before
       * it returns control, so a Good verdict carries the same repeated-
       * step wrap risk as any other multi-step path. */
      Mutation NestedResult = mutation(Statement, Expected);
      if (NestedResult == Mutation::Bad)
        return {0, true};
      return {FallWithoutProgress, false, NestedResult == Mutation::Good};
    }
    if (isa<GotoStmt>(Statement))
      return ActiveLoop && Current &&
                     allGotosExitActiveLoop(Current->getBody())
                 ? Flow{ExitsLoop, false}
                 : Flow{0, true};
    if (isa<IndirectGotoStmt>(Statement))
      return {0, true};
    if (const auto *Switch = dyn_cast<SwitchStmt>(Statement)) {
      const auto *Body = dyn_cast_or_null<CompoundStmt>(Switch->getBody());
      if (!Body)
        return {0, true};
      auto LabelCount = [](const Stmt *Root) {
        unsigned Count = 0;
        std::vector<const Stmt *> Pending{Root};
        while (!Pending.empty()) {
          const Stmt *Item = Pending.back();
          Pending.pop_back();
          if (!Item)
            continue;
          if (Item != Root && isa<SwitchStmt>(Item))
            continue;
          if (isa<CaseStmt>(Item) || isa<DefaultStmt>(Item))
            ++Count;
          for (const Stmt *Child : Item->children())
            Pending.push_back(Child);
        }
        return Count;
      };
      unsigned AllLabels = LabelCount(Body);
      unsigned EntryLabels = 0;
      bool HasDefault = false;
      Flow Entries{0, false};
      auto CountLabelChain = [&](const Stmt *Root) {
        unsigned Count = 0;
        const Stmt *Item = Root;
        while (const auto *Case = dyn_cast_or_null<CaseStmt>(Item)) {
          ++Count;
          Item = Case->getSubStmt();
        }
        if (const auto *Default = dyn_cast_or_null<DefaultStmt>(Item)) {
          ++Count;
          HasDefault = true;
        }
        return Count;
      };
      std::vector<const Stmt *> Statements(Body->body_begin(),
                                           Body->body_end());
      for (size_t I = 0; I < Statements.size(); ++I) {
        const Stmt *Entry = Statements[I];
        if (!isa<CaseStmt>(Entry) && !isa<DefaultStmt>(Entry))
          continue;
        EntryLabels += CountLabelChain(Entry);
        Flow Path{FallWithoutProgress, false};
        for (size_t J = I; J < Statements.size(); ++J)
          Path = sequence(Path, flow(Statements[J], Expected, LoopCondition));
        Entries.Outcomes |= Path.Outcomes;
        Entries.Invalid |= Path.Invalid;
        Entries.RepeatedProgress |= Path.RepeatedProgress;
      }
      /* Labels nested beneath ordinary control flow can jump past guards or
       * rank updates.  Supporting them needs a real CFG; direct labels and
       * chains of adjacent labels cover ordinary C switches. */
      if (EntryLabels != AllLabels)
        return {0, true};
      if (!HasDefault)
        Entries.Outcomes |= FallWithoutProgress;
      if (Entries.Outcomes & BreakWithoutProgress)
        Entries.Outcomes |= FallWithoutProgress;
      if (Entries.Outcomes & BreakWithProgress)
        Entries.Outcomes |= FallWithProgress;
      if (Entries.Outcomes & BreakAtTerminatingSentinel)
        Entries.Outcomes |= FallAtTerminatingSentinel;
      Entries.Outcomes &= ~(BreakWithoutProgress | BreakWithProgress |
                            BreakAtTerminatingSentinel);
      Flow Prefix = sequence(flow(Switch->getInit(), Expected, LoopCondition),
                             flow(Switch->getConditionVariableDeclStmt(),
                                  Expected, LoopCondition));
      Prefix = sequence(Prefix,
                        flow(Switch->getCond(), Expected, LoopCondition));
      return sequence(Prefix, Entries);
    }
    switch (mutation(Statement, Expected)) {
    case Mutation::None:
      return {FallWithoutProgress, false};
    case Mutation::Good:
      return {FallWithProgress, false};
    case Mutation::Bad:
      return {0, true};
    }
    llvm_unreachable("all mutations handled");
  }

  bool bodyGuaranteesProgress(const Stmt *Body, const Progress &Expected,
                              const Expr *LoopCondition = nullptr,
                              const Stmt *Loop = nullptr) const {
    const Stmt *SavedLoop = ActiveLoop;
    ActiveLoop = Loop;
    Flow Result = flow(Body, Expected, LoopCondition);
    ActiveLoop = SavedLoop;
    return !Result.Invalid && Result.Outcomes != 0 &&
           (!(Expected.Variable->getType()->isUnsignedIntegerType() &&
              Expected.Kind == ProgressKind::Up) ||
            !Result.RepeatedProgress) &&
           !(Result.Outcomes & (FallWithoutProgress | BackWithoutProgress));
  }

  enum class IntervalPatternKind { Halving, Bounds };

  struct IntervalPattern {
    IntervalPatternKind Kind;
    const VarDecl *Low;
    const VarDecl *High;
    const VarDecl *Middle;
    const DeclStmt *MiddleDeclaration;
  };

  struct IntervalFlow {
    /* Bit N records paths with N=0 no update, N=1 one exact shrinking
     * update, or N=2 an unrecognized/repeated update. */
    unsigned FallMasks;
    unsigned BackMasks;
    bool Exits;
    bool Invalid;
  };

  static unsigned combineIntervalMasks(unsigned First, unsigned Second) {
    unsigned Result = 0;
    for (unsigned A = 0; A != 3; ++A)
      if (First & (1u << A))
        for (unsigned B = 0; B != 3; ++B)
          if (Second & (1u << B)) {
            unsigned Combined = A == 2 || B == 2 || (A == 1 && B == 1)
                                    ? 2
                                    : A + B;
            Result |= 1u << Combined;
          }
    return Result;
  }

  static IntervalFlow intervalSequence(IntervalFlow First,
                                       IntervalFlow Second) {
    if (First.Invalid || Second.Invalid)
      return {0, 0, false, true};
    unsigned Fall = combineIntervalMasks(First.FallMasks, Second.FallMasks);
    unsigned Back = First.BackMasks |
                    combineIntervalMasks(First.FallMasks, Second.BackMasks);
    return {Fall, Back, First.Exits || (First.FallMasks && Second.Exits),
            false};
  }

  static bool exactVariable(const Expr *Expression,
                            const ValueDecl *Variable) {
    return value(Expression) == Variable;
  }

  static bool exactAddOne(const Expr *Expression,
                          const ValueDecl *Variable) {
    const auto *Add = dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    return Add && Add->getOpcode() == BO_Add &&
           ((exactVariable(Add->getLHS(), Variable) &&
             unitInteger(Add->getRHS())) ||
            (unitInteger(Add->getLHS()) &&
             exactVariable(Add->getRHS(), Variable)));
  }

  static bool exactHalf(const Expr *Expression,
                        const ValueDecl *Variable) {
    const auto *Divide =
        dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    const auto *Two = Divide ? dyn_cast_or_null<IntegerLiteral>(
                                   ignore(Divide->getRHS()))
                             : nullptr;
    return Divide && Divide->getOpcode() == BO_Div && Two &&
           Two->getValue() == 2 && exactVariable(Divide->getLHS(), Variable);
  }

  static bool exactMidpoint(const Expr *Expression, const ValueDecl *Low,
                            const ValueDecl *High) {
    const auto *Add = dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    if (!Add || Add->getOpcode() != BO_Add ||
        !exactVariable(Add->getLHS(), Low))
      return false;
    const auto *Divide =
        dyn_cast_or_null<BinaryOperator>(ignore(Add->getRHS()));
    const auto *Difference = Divide ? dyn_cast_or_null<BinaryOperator>(
                                          ignore(Divide->getLHS()))
                                    : nullptr;
    const auto *Two = Divide ? dyn_cast_or_null<IntegerLiteral>(
                                   ignore(Divide->getRHS()))
                             : nullptr;
    return Divide && Divide->getOpcode() == BO_Div && Difference &&
           Difference->getOpcode() == BO_Sub && Two &&
           Two->getValue() == 2 &&
           exactVariable(Difference->getLHS(), High) &&
           exactVariable(Difference->getRHS(), Low);
  }

  static unsigned intervalMutation(const Stmt *Statement,
                                   const IntervalPattern &Pattern) {
    if (!Statement || Statement == Pattern.MiddleDeclaration)
      return 0;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const auto *Assignment =
          dyn_cast_or_null<BinaryOperator>(ignore(Expression));
      if (Assignment && Assignment->isAssignmentOp()) {
        const ValueDecl *Target = value(Assignment->getLHS());
        if (Pattern.Kind == IntervalPatternKind::Halving &&
            Target == Pattern.High) {
          if (Assignment->getOpcode() == BO_Assign &&
              exactVariable(Assignment->getRHS(), Pattern.Middle))
            return 1;
          if (Assignment->getOpcode() == BO_SubAssign &&
              exactAddOne(Assignment->getRHS(), Pattern.Middle))
            return 1;
          return 2;
        }
        if (Pattern.Kind == IntervalPatternKind::Bounds) {
          if (Target == Pattern.High)
            return Assignment->getOpcode() == BO_Assign &&
                           exactVariable(Assignment->getRHS(), Pattern.Middle)
                       ? 1
                       : 2;
          if (Target == Pattern.Low)
            return Assignment->getOpcode() == BO_Assign &&
                           exactAddOne(Assignment->getRHS(), Pattern.Middle)
                       ? 1
                       : 2;
        }
        if (Target == Pattern.Middle)
          return 2;
      }
      const auto *Unary = dyn_cast_or_null<UnaryOperator>(ignore(Expression));
      if (Unary && (Unary->isIncrementDecrementOp() ||
                    Unary->getOpcode() == UO_AddrOf)) {
        const ValueDecl *Target = value(Unary->getSubExpr());
        if (Target == Pattern.Low || Target == Pattern.High ||
            Target == Pattern.Middle)
          return 2;
      }
    }
    unsigned Result = 0;
    for (const Stmt *Child : Statement->children()) {
      unsigned ChildResult = intervalMutation(Child, Pattern);
      if (ChildResult == 2 || (Result == 1 && ChildResult == 1))
        return 2;
      Result |= ChildResult;
    }
    return Result;
  }

  static IntervalFlow intervalFlow(const Stmt *Statement,
                                   const IntervalPattern &Pattern) {
    if (!Statement)
      return {1u, 0, false, false};
    if (containsAsm(Statement) ||
        containsUnevaluatedOrEmbeddedControl(Statement) ||
        containsConditionalExecution(Statement))
      return {0, 0, false, true};
    if (const auto *Compound = dyn_cast<CompoundStmt>(Statement)) {
      IntervalFlow Result{1u, 0, false, false};
      for (const Stmt *Child : Compound->body())
        Result = intervalSequence(Result, intervalFlow(Child, Pattern));
      return Result;
    }
    if (const auto *If = dyn_cast<IfStmt>(Statement)) {
      IntervalFlow Prefix = intervalSequence(
          intervalFlow(If->getInit(), Pattern),
          intervalFlow(If->getConditionVariableDeclStmt(), Pattern));
      Prefix = intervalSequence(Prefix,
                                intervalFlow(If->getCond(), Pattern));
      IntervalFlow Then = intervalFlow(If->getThen(), Pattern);
      IntervalFlow Else = intervalFlow(If->getElse(), Pattern);
      IntervalFlow Arms{Then.FallMasks | Else.FallMasks,
                        Then.BackMasks | Else.BackMasks,
                        Then.Exits || Else.Exits,
                        Then.Invalid || Else.Invalid};
      return intervalSequence(Prefix, Arms);
    }
    if (const auto *Label = dyn_cast<LabelStmt>(Statement))
      return intervalFlow(Label->getSubStmt(), Pattern);
    if (isa<ContinueStmt>(Statement))
      return {0, 1u, false, false};
    if (isa<BreakStmt>(Statement) || isa<ReturnStmt>(Statement))
      return {0, 0, true, false};
    if (isa<GotoStmt>(Statement) || isa<IndirectGotoStmt>(Statement) ||
        isa<SwitchStmt>(Statement))
      return {0, 0, false, true};
    if (isa<ForStmt>(Statement) || isa<WhileStmt>(Statement) ||
        isa<DoStmt>(Statement))
      return {intervalMutation(Statement, Pattern) ? 1u << 2 : 1u,
              0, false, false};
    unsigned Mutation = intervalMutation(Statement, Pattern);
    return {1u << Mutation, 0, false, false};
  }

  static const VarDecl *directInitializedVariable(
      const CompoundStmt *Body, const DeclStmt *&Declaration,
      const ValueDecl *First, const ValueDecl *Second = nullptr) {
    const VarDecl *Result = nullptr;
    Declaration = nullptr;
    for (const Stmt *Child : Body->body()) {
      const auto *Decls = dyn_cast<DeclStmt>(Child);
      if (!Decls || !Decls->isSingleDecl())
        continue;
      for (const Decl *Item : Decls->decls()) {
        const auto *Variable = dyn_cast<VarDecl>(Item);
        if (!Variable || !Variable->getInit())
          continue;
        bool Matches = Second
                           ? exactMidpoint(Variable->getInit(), First, Second)
                           : exactHalf(Variable->getInit(), First);
        if (!Matches)
          continue;
        if (Result)
          return nullptr;
        Result = Variable;
        Declaration = Decls;
      }
    }
    return Result;
  }

  bool branchCompleteIntervalDescent(const Expr *Condition,
                                     const Stmt *Body) const {
    /* For unsigned n>0, h=n/2 satisfies h<n and h+1<=n, so both
     * n=h and n-=h+1 strictly decrease without wrapping.  For same-type
     * unsigned lo<hi, d=hi-lo is representable and
     * mid=lo+d/2 satisfies lo<=mid<hi; therefore hi=mid and lo=mid+1
     * each strictly shrink hi-lo, and mid+1<=hi proves representability.
     * intervalFlow additionally requires exactly one of those assignments
     * on every backedge and discards arbitrary mutations only on paths
     * which exit the loop first. */
    const auto *Compound = dyn_cast_or_null<CompoundStmt>(Body);
    if (!Condition || !Compound || !Current)
      return false;
    const Expr *PlainCondition = ignore(Condition);
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(PlainCondition);
    IntervalPattern Pattern{};
    const DeclStmt *MiddleDeclaration = nullptr;
    if (Comparison && Comparison->getOpcode() == BO_LT) {
      const auto *Low = dyn_cast_or_null<VarDecl>(value(Comparison->getLHS()));
      const auto *High = dyn_cast_or_null<VarDecl>(value(Comparison->getRHS()));
      if (!Low || !High || Low == High ||
          !Low->getType()->isUnsignedIntegerType() ||
          Low->getType().getCanonicalType().getUnqualifiedType() !=
              High->getType().getCanonicalType().getUnqualifiedType())
        return false;
      const VarDecl *Middle = directInitializedVariable(
          Compound, MiddleDeclaration, Low, High);
      if (!Middle)
        return false;
      Pattern = {IntervalPatternKind::Bounds, Low, High, Middle,
                 MiddleDeclaration};
    } else {
      const auto *High = dyn_cast_or_null<VarDecl>(value(PlainCondition));
      if (!High || !High->getType()->isUnsignedIntegerType() ||
          !nonzeroWhen(Condition, High, true))
        return false;
      const VarDecl *Middle = directInitializedVariable(
          Compound, MiddleDeclaration, High);
      if (!Middle)
        return false;
      Pattern = {IntervalPatternKind::Halving, nullptr, High, Middle,
                 MiddleDeclaration};
    }
    if (Pattern.Middle->getType().getCanonicalType().getUnqualifiedType() !=
            Pattern.High->getType().getCanonicalType().getUnqualifiedType() ||
        !(Pattern.Middle->hasLocalStorage()) ||
        !(isa<ParmVarDecl>(Pattern.High) || Pattern.High->hasLocalStorage()) ||
        (Pattern.Low && !(isa<ParmVarDecl>(Pattern.Low) ||
                          Pattern.Low->hasLocalStorage())) ||
        Pattern.Middle->getType().isVolatileQualified() ||
        Pattern.High->getType().isVolatileQualified() ||
        (Pattern.Low && Pattern.Low->getType().isVolatileQualified()) ||
        addressTaken(Current->getBody(), Pattern.Middle) ||
        addressTaken(Current->getBody(), Pattern.High) ||
        (Pattern.Low && addressTaken(Current->getBody(), Pattern.Low)))
      return false;
    IntervalFlow Result = intervalFlow(Body, Pattern);
    unsigned Backedges = Result.FallMasks | Result.BackMasks;
    return !Result.Invalid && Backedges && Backedges == (1u << 1);
  }

  struct GeometricFlow {
    /* Path state 0 has not passed the overflow guard, 1 has passed it,
     * 2 has performed the one exact doubling, and 3 is invalid. */
    unsigned FallMasks;
    unsigned BackMasks;
    bool Exits;
    bool Invalid;
  };

  static unsigned combineGeometricMasks(unsigned First, unsigned Second) {
    unsigned Result = 0;
    for (unsigned A = 0; A != 4; ++A)
      if (First & (1u << A))
        for (unsigned B = 0; B != 4; ++B)
          if (Second & (1u << B)) {
            unsigned Combined = 3;
            if (B == 0)
              Combined = A;
            else if (B == 1 && A == 0)
              Combined = 1;
            else if (B == 2 && A == 1)
              Combined = 2;
            Result |= 1u << Combined;
          }
    return Result;
  }

  static GeometricFlow geometricSequence(GeometricFlow First,
                                         GeometricFlow Second) {
    if (First.Invalid || Second.Invalid)
      return {0, 0, false, true};
    unsigned Fall = combineGeometricMasks(First.FallMasks,
                                          Second.FallMasks);
    unsigned Back = First.BackMasks |
                    combineGeometricMasks(First.FallMasks,
                                          Second.BackMasks);
    return {Fall, Back, First.Exits || (First.FallMasks && Second.Exits),
            false};
  }

  bool positiveConstant(const Expr *Expression) const {
    if (!Expression)
      return false;
    Expr::EvalResult Result;
    return Expression->EvaluateAsInt(Result, Context) &&
           !Result.Val.getInt().isNegative() &&
           !Result.Val.getInt().isZero();
  }

  bool positiveInitializer(const Expr *Expression,
                           QualType RankType) const {
    if (positiveConstant(Expression))
      return true;
    const auto *Conditional = dyn_cast_or_null<ConditionalOperator>(
        ignore(Expression));
    if (!Conditional ||
        Conditional->getType().getCanonicalType().getUnqualifiedType() !=
            RankType.getCanonicalType().getUnqualifiedType())
      return false;
    const ValueDecl *TrueValue = value(Conditional->getTrueExpr());
    bool TruePositive = positiveConstant(Conditional->getTrueExpr()) ||
        (Conditional->getTrueExpr()->getType()->isUnsignedIntegerType() &&
         TrueValue && !TrueValue->getType().isVolatileQualified() &&
         sameScalarAccess(Conditional->getCond(),
                          Conditional->getTrueExpr()));
    return TruePositive && positiveConstant(Conditional->getFalseExpr());
  }

  static bool containsJumpIntoScope(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (isa<GotoStmt>(Statement) || isa<IndirectGotoStmt>(Statement))
      return true;
    for (const Stmt *Child : Statement->children())
      if (containsJumpIntoScope(Child))
        return true;
    return false;
  }

  bool positiveEntryGuard(const Stmt *Statement,
                          const VarDecl *Rank) const {
    const auto *If = dyn_cast_or_null<IfStmt>(Statement);
    if (!If || If->getInit() || If->getConditionVariableDeclStmt() ||
        If->getElse())
      return false;
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(
        ignore(If->getCond()));
    if (!Comparison || Comparison->getOpcode() != BO_LT ||
        !exactVariable(Comparison->getLHS(), Rank) ||
        Comparison->getLHS()->getType().getCanonicalType()
                .getUnqualifiedType() !=
            Rank->getType().getCanonicalType().getUnqualifiedType() ||
        Comparison->getRHS()->getType().getCanonicalType()
                .getUnqualifiedType() !=
            Rank->getType().getCanonicalType().getUnqualifiedType() ||
        !positiveConstant(Comparison->getRHS()))
      return false;
    const Stmt *Then = If->getThen();
    if (const auto *Compound = dyn_cast<CompoundStmt>(Then)) {
      if (Compound->size() != 1)
        return false;
      Then = *Compound->body_begin();
    }
    const auto *Assignment = dyn_cast_or_null<BinaryOperator>(
        ignore(dyn_cast_or_null<Expr>(Then)));
    return Assignment && Assignment->getOpcode() == BO_Assign &&
           exactVariable(Assignment->getLHS(), Rank) &&
           positiveConstant(Assignment->getRHS());
  }

  bool positiveAtLoopEntry(const Stmt *Loop, const VarDecl *Rank) const {
    if (!Loop || !Rank || !Rank->hasLocalStorage() || !Current ||
        containsJumpIntoScope(Current->getBody()))
      return false;
    DynTypedNodeList Parents = Context.getParents(*Loop);
    if (Parents.size() != 1)
      return false;
    const auto *Compound = Parents[0].get<CompoundStmt>();
    if (!Compound)
      return false;
    const Stmt *Previous = nullptr;
    bool Found = false;
    for (const Stmt *Child : Compound->body()) {
      if (Child == Loop) {
        Found = true;
        break;
      }
      Previous = Child;
    }
    if (!Found || !Previous)
      return false;
    if (const auto *Declaration = dyn_cast<DeclStmt>(Previous)) {
      if (!Declaration->isSingleDecl())
        return false;
      const auto *Variable = dyn_cast<VarDecl>(Declaration->getSingleDecl());
      return Variable == Rank &&
             positiveInitializer(Rank->getInit(), Rank->getType());
    }
    return positiveEntryGuard(Previous, Rank);
  }

  bool limitAtMostRankHalf(const Expr *Limit, const VarDecl *Rank) const {
    if (!Limit || !Rank || !Limit->getType()->isIntegerType())
      return false;
    QualType RankType = Rank->getType().getCanonicalType().getUnqualifiedType();
    if (Limit->getType().getCanonicalType().getUnqualifiedType() != RankType)
      return false;
    Expr::EvalResult Result;
    if (!Limit->EvaluateAsInt(Result, Context) ||
        Result.Val.getInt().isNegative())
      return false;
    llvm::APSInt Maximum = llvm::APSInt::getMaxValue(
        Context.getIntWidth(RankType),
        RankType->isUnsignedIntegerOrEnumerationType());
    llvm::APSInt Half(Maximum.lshr(1), Maximum.isUnsigned());
    return llvm::APSInt::compareValues(Result.Val.getInt(), Half) <= 0;
  }

  bool overflowGuardExits(const IfStmt *If, const VarDecl *Rank) const {
    if (!If || If->getInit() || If->getConditionVariableDeclStmt() ||
        If->getElse() || !exitsBeforeBackedge(If->getThen()))
      return false;
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(
        ignore(If->getCond()));
    if (!Comparison)
      return false;
    const Expr *Limit = nullptr;
    if (Comparison->getOpcode() == BO_GT &&
        exactVariable(Comparison->getLHS(), Rank))
      Limit = Comparison->getRHS();
    else if (Comparison->getOpcode() == BO_LT &&
             exactVariable(Comparison->getRHS(), Rank))
      Limit = Comparison->getLHS();
    if (!Limit ||
        Comparison->getLHS()->getType().getCanonicalType()
                .getUnqualifiedType() !=
            Rank->getType().getCanonicalType().getUnqualifiedType())
      return false;
    return limitAtMostRankHalf(Limit, Rank);
  }

  static bool exactDoubling(const Expr *Expression, const VarDecl *Rank) {
    const auto *Assignment = dyn_cast_or_null<BinaryOperator>(
        ignore(Expression));
    if (!Assignment || !exactVariable(Assignment->getLHS(), Rank))
      return false;
    if (Assignment->getOpcode() == BO_MulAssign) {
      const auto *Compound = dyn_cast<CompoundAssignOperator>(Assignment);
      const auto *Two = dyn_cast_or_null<IntegerLiteral>(
          ignore(Assignment->getRHS()));
      return Compound && Two && Two->getValue() == 2 &&
             Compound->getComputationResultType().getCanonicalType()
                     .getUnqualifiedType() ==
                 Rank->getType().getCanonicalType().getUnqualifiedType();
    }
    if (Assignment->getOpcode() != BO_Assign)
      return false;
    const auto *Multiply = dyn_cast_or_null<BinaryOperator>(
        ignore(Assignment->getRHS()));
    const auto *Two = Multiply ? dyn_cast_or_null<IntegerLiteral>(
                                     ignore(Multiply->getRHS()))
                               : nullptr;
    return Multiply && Multiply->getOpcode() == BO_Mul && Two &&
           Two->getValue() == 2 &&
           exactVariable(Multiply->getLHS(), Rank) &&
           Multiply->getType().getCanonicalType().getUnqualifiedType() ==
               Rank->getType().getCanonicalType().getUnqualifiedType();
  }

  static unsigned geometricMutation(const Stmt *Statement,
                                    const VarDecl *Rank) {
    if (!Statement)
      return 0;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      if (exactDoubling(Expression, Rank))
        return 2;
      const Expr *Plain = ignore(Expression);
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain))
        if ((Unary->isIncrementDecrementOp() ||
             Unary->getOpcode() == UO_AddrOf) &&
            exactVariable(Unary->getSubExpr(), Rank))
          return 3;
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain))
        if (Binary->isAssignmentOp() &&
            exactVariable(Binary->getLHS(), Rank))
          return 3;
    }
    unsigned Result = 0;
    for (const Stmt *Child : Statement->children()) {
      unsigned ChildResult = geometricMutation(Child, Rank);
      if (ChildResult == 3 || (Result && ChildResult))
        return 3;
      Result |= ChildResult;
    }
    return Result;
  }

  GeometricFlow geometricFlow(const Stmt *Statement,
                              const VarDecl *Rank) const {
    if (!Statement)
      return {1u, 0, false, false};
    if (containsAsm(Statement) ||
        containsUnevaluatedOrEmbeddedControl(Statement) ||
        containsConditionalExecution(Statement))
      return {0, 0, false, true};
    if (const auto *Compound = dyn_cast<CompoundStmt>(Statement)) {
      GeometricFlow Result{1u, 0, false, false};
      for (const Stmt *Child : Compound->body())
        Result = geometricSequence(Result, geometricFlow(Child, Rank));
      return Result;
    }
    if (const auto *If = dyn_cast<IfStmt>(Statement)) {
      if (overflowGuardExits(If, Rank))
        return {1u << 1, 0, true, false};
      GeometricFlow Prefix = geometricSequence(
          geometricFlow(If->getInit(), Rank),
          geometricFlow(If->getConditionVariableDeclStmt(), Rank));
      Prefix = geometricSequence(Prefix, geometricFlow(If->getCond(), Rank));
      GeometricFlow Then = geometricFlow(If->getThen(), Rank);
      GeometricFlow Else = geometricFlow(If->getElse(), Rank);
      GeometricFlow Arms{Then.FallMasks | Else.FallMasks,
                         Then.BackMasks | Else.BackMasks,
                         Then.Exits || Else.Exits,
                         Then.Invalid || Else.Invalid};
      return geometricSequence(Prefix, Arms);
    }
    if (const auto *Label = dyn_cast<LabelStmt>(Statement))
      return geometricFlow(Label->getSubStmt(), Rank);
    if (isa<ContinueStmt>(Statement))
      return {0, 1u, false, false};
    if (isa<BreakStmt>(Statement) || isa<ReturnStmt>(Statement))
      return {0, 0, true, false};
    if (isa<GotoStmt>(Statement) || isa<IndirectGotoStmt>(Statement) ||
        isa<SwitchStmt>(Statement))
      return {0, 0, false, true};
    if (isa<ForStmt>(Statement) || isa<WhileStmt>(Statement) ||
        isa<DoStmt>(Statement))
      return {geometricMutation(Statement, Rank) ? 1u << 3 : 1u,
              0, false, false};
    unsigned Mutation = geometricMutation(Statement, Rank);
    return {1u << Mutation, 0, false, false};
  }

  bool guardedGeometricAscent(const Stmt *Loop, const Expr *Condition,
                              const Stmt *Body) const {
    /* A positive integer rank doubled only while rank < a stable bound is
     * a finite ascending rank when every backedge first establishes
     * rank <= TYPE_MAX/2.  The multiplication is then representable and
     * strictly increases rank.  geometricFlow requires that guard and one
     * exact doubling on every backedge; mutations on return/break paths do
     * not matter because those paths never execute the multiplication. */
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(
        ignore(Condition));
    if (!Comparison || Comparison->getOpcode() != BO_LT)
      return false;
    const auto *Rank = dyn_cast_or_null<VarDecl>(
        value(Comparison->getLHS()));
    const Expr *Bound = Comparison->getRHS();
    const auto *BoundVariable = dyn_cast_or_null<VarDecl>(value(Bound));
    if (!Rank || !Rank->hasLocalStorage() ||
        !BoundVariable ||
        !(isa<ParmVarDecl>(BoundVariable) ||
          BoundVariable->hasLocalStorage()) ||
        !Rank->getType()->isIntegerType() ||
        Rank->getType().isVolatileQualified() ||
        BoundVariable->getType().isVolatileQualified() ||
        Rank->getType().getCanonicalType().getUnqualifiedType() !=
            Comparison->getLHS()->getType().getCanonicalType()
                .getUnqualifiedType() ||
        Rank->getType().getCanonicalType().getUnqualifiedType() !=
            Bound->getType().getCanonicalType().getUnqualifiedType() ||
        addressTaken(Current->getBody(), Rank) ||
        addressTaken(Current->getBody(), BoundVariable) ||
        !positiveAtLoopEntry(Loop, Rank) ||
        !stableBound(Bound, Body, nullptr))
      return false;
    GeometricFlow Result = geometricFlow(Body, Rank);
    unsigned Backedges = Result.FallMasks | Result.BackMasks;
    return !Result.Invalid && Backedges && Backedges == (1u << 2);
  }

  enum RankMutationOutcome : unsigned {
    FallRankClean = 1,
    FallRankChanged = 2,
    BackRankClean = 4,
    BackRankChanged = 8,
    ExitsAfterRankMutation = 16,
  };

  struct RankMutationFlow {
    unsigned Outcomes;
    bool Invalid;
  };

  static bool rankMutationFlowUnsupported(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (isa<AsmStmt>(Statement) || isa<GotoStmt>(Statement) ||
        isa<IndirectGotoStmt>(Statement) || isa<StmtExpr>(Statement))
      return true;
    for (const Stmt *Child : Statement->children())
      if (rankMutationFlowUnsupported(Child))
        return true;
    return false;
  }

  static RankMutationFlow rankMutationSequence(RankMutationFlow First,
                                               RankMutationFlow Second) {
    if (First.Invalid || Second.Invalid)
      return {0, true};
    unsigned Result = First.Outcomes &
        (BackRankClean | BackRankChanged | ExitsAfterRankMutation);
    if (First.Outcomes & FallRankClean)
      Result |= Second.Outcomes;
    if (First.Outcomes & FallRankChanged) {
      if (Second.Outcomes & (FallRankClean | FallRankChanged))
        Result |= FallRankChanged;
      if (Second.Outcomes & (BackRankClean | BackRankChanged))
        Result |= BackRankChanged;
      if (Second.Outcomes & ExitsAfterRankMutation)
        Result |= ExitsAfterRankMutation;
    }
    return {Result, false};
  }

  static RankMutationFlow rankMutationFlow(const Stmt *Statement,
                                           const Progress &Rank) {
    if (!Statement)
      return {FallRankClean, false};
    if (rankMutationFlowUnsupported(Statement))
      return {0, true};
    if (const auto *Compound = dyn_cast<CompoundStmt>(Statement)) {
      RankMutationFlow Result{FallRankClean, false};
      for (const Stmt *Child : Compound->body())
        Result = rankMutationSequence(Result,
                                      rankMutationFlow(Child, Rank));
      return Result;
    }
    if (const auto *If = dyn_cast<IfStmt>(Statement)) {
      RankMutationFlow Prefix = rankMutationSequence(
          rankMutationFlow(If->getInit(), Rank),
          rankMutationFlow(If->getConditionVariableDeclStmt(), Rank));
      Prefix = rankMutationSequence(Prefix,
                                    rankMutationFlow(If->getCond(), Rank));
      RankMutationFlow Then = rankMutationFlow(If->getThen(), Rank);
      RankMutationFlow Else = rankMutationFlow(If->getElse(), Rank);
      RankMutationFlow Arms{Then.Outcomes | Else.Outcomes,
                            Then.Invalid || Else.Invalid};
      return rankMutationSequence(Prefix, Arms);
    }
    if (const auto *Label = dyn_cast<LabelStmt>(Statement))
      return rankMutationFlow(Label->getSubStmt(), Rank);
    if (isa<ContinueStmt>(Statement))
      return {BackRankClean, false};
    if (isa<BreakStmt>(Statement) || isa<ReturnStmt>(Statement))
      return {ExitsAfterRankMutation, false};
    if (isa<GotoStmt>(Statement) || isa<SwitchStmt>(Statement))
      return {0, true};
    if (isa<ForStmt>(Statement) || isa<WhileStmt>(Statement) ||
        isa<DoStmt>(Statement))
      return mutation(Statement, Rank) == Mutation::None
                 ? RankMutationFlow{FallRankClean, false}
                 : RankMutationFlow{FallRankChanged, false};
    return mutation(Statement, Rank) == Mutation::None
               ? RankMutationFlow{FallRankClean, false}
               : RankMutationFlow{FallRankChanged, false};
  }

  static bool rankUnmodifiedOnBackedges(const Stmt *Body,
                                        const Progress &Rank) {
    RankMutationFlow Result = rankMutationFlow(Body, Rank);
    return !Result.Invalid && Result.Outcomes != 0 &&
           !(Result.Outcomes & (FallRankChanged | BackRankChanged));
  }

  struct PairFlow {
    /* Bit N means a path reaches this control edge after progressing the
     * subset N of the two ranks. */
    unsigned FallMasks;
    unsigned BackMasks;
    bool Exits;
    bool Invalid;
  };

  static unsigned combineMasks(unsigned First, unsigned Second,
                               bool &Repeated) {
    unsigned Result = 0;
    for (unsigned A = 0; A != 4; ++A)
      if (First & (1u << A))
        for (unsigned B = 0; B != 4; ++B) {
          if (Second & (1u << B)) {
            Repeated |= (A & B) != 0;
            Result |= 1u << (A | B);
          }
        }
    return Result;
  }

  static PairFlow pairSequence(PairFlow First, PairFlow Second) {
    if (First.Invalid || Second.Invalid)
      return {0, 0, false, true};
    bool Repeated = false;
    unsigned Fall = combineMasks(First.FallMasks, Second.FallMasks,
                                 Repeated);
    unsigned Back = First.BackMasks |
        combineMasks(First.FallMasks, Second.BackMasks, Repeated);
    return {Fall, Back, First.Exits || (First.FallMasks && Second.Exits),
            Repeated};
  }

  static bool containsConditionalExecution(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (isa<ConditionalOperator>(Statement))
      return true;
    if (const auto *Binary = dyn_cast<BinaryOperator>(Statement))
      if (Binary->isLogicalOp())
        return true;
    for (const Stmt *Child : Statement->children())
      if (containsConditionalExecution(Child))
        return true;
    return false;
  }

  static bool containsAsm(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (isa<AsmStmt>(Statement))
      return true;
    for (const Stmt *Child : Statement->children())
      if (containsAsm(Child))
        return true;
    return false;
  }

  static bool containsEmbeddedLabel(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (isa<LabelStmt>(Statement) || isa<CaseStmt>(Statement) ||
        isa<DefaultStmt>(Statement))
      return true;
    for (const Stmt *Child : Statement->children())
      if (containsEmbeddedLabel(Child))
        return true;
    return false;
  }

  static bool containsUnevaluatedOrEmbeddedControl(const Stmt *Statement) {
    if (!Statement)
      return false;
    /* RecursiveASTVisitor exposes expression children which C does not
     * necessarily evaluate (sizeof/_Alignof, nonselected generic/choose
     * arms).  A GNU statement expression can likewise hide branches below
     * an otherwise atomic outer expression.  The paired path-mask walk does
     * not model those constructs, so they cannot contribute paired progress. */
    if (isa<UnaryExprOrTypeTraitExpr>(Statement) ||
        isa<GenericSelectionExpr>(Statement) || isa<ChooseExpr>(Statement) ||
        isa<StmtExpr>(Statement))
      return true;
    for (const Stmt *Child : Statement->children())
      if (containsUnevaluatedOrEmbeddedControl(Child))
        return true;
    return false;
  }

  static unsigned progressOccurrences(const Stmt *Statement,
                                      const Progress &Expected) {
    if (!Statement)
      return 0;
    if (const auto *Expression = dyn_cast<Expr>(Statement))
      if (std::optional<Progress> Change = progress(Expression))
        if (sameRank(*Change, Expected) &&
            Change->Kind == Expected.Kind)
          return 1;
    unsigned Result = 0;
    for (const Stmt *Child : Statement->children()) {
      Result += progressOccurrences(Child, Expected);
      if (Result > 1)
        return Result;
    }
    return Result;
  }

  static PairFlow pairFlow(const Stmt *Statement, const Progress &First,
                           const Progress &Second) {
    if (!Statement)
      return {1u, 0, false, false};
    if (containsAsm(Statement) ||
        containsUnevaluatedOrEmbeddedControl(Statement))
      return {0, 0, false, true};
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain)) {
        if (Binary->getOpcode() == BO_Comma)
          return pairSequence(pairFlow(Binary->getLHS(), First, Second),
                              pairFlow(Binary->getRHS(), First, Second));
        if (Binary->isLogicalOp()) {
          PairFlow Left = pairFlow(Binary->getLHS(), First, Second);
          PairFlow Both = pairSequence(
              Left, pairFlow(Binary->getRHS(), First, Second));
          return {Left.FallMasks | Both.FallMasks,
                  Left.BackMasks | Both.BackMasks,
                  Left.Exits || Both.Exits,
                  Left.Invalid || Both.Invalid};
        }
      }
      if (const auto *Conditional =
              dyn_cast_or_null<ConditionalOperator>(Plain)) {
        PairFlow Prefix = pairFlow(Conditional->getCond(), First, Second);
        PairFlow True = pairFlow(Conditional->getTrueExpr(), First, Second);
        PairFlow False = pairFlow(Conditional->getFalseExpr(), First, Second);
        PairFlow Arms{True.FallMasks | False.FallMasks,
                      True.BackMasks | False.BackMasks,
                      True.Exits || False.Exits,
                      True.Invalid || False.Invalid};
        return pairSequence(Prefix, Arms);
      }
      /* Do not flatten conditionally evaluated updates hidden inside a
       * larger expression: the ordinary mutation walk deliberately loses
       * that path correlation. */
      if (containsConditionalExecution(Plain))
        return {0, 0, false, true};
    }
    if (const auto *Compound = dyn_cast<CompoundStmt>(Statement)) {
      PairFlow Result{1u, 0, false, false};
      for (const Stmt *Child : Compound->body())
        Result = pairSequence(Result, pairFlow(Child, First, Second));
      return Result;
    }
    if (const auto *If = dyn_cast<IfStmt>(Statement)) {
      PairFlow Prefix = pairSequence(
          pairFlow(If->getInit(), First, Second),
          pairFlow(If->getConditionVariableDeclStmt(), First, Second));
      Prefix = pairSequence(Prefix,
                            pairFlow(If->getCond(), First, Second));
      PairFlow Then = pairFlow(If->getThen(), First, Second);
      PairFlow Else = pairFlow(If->getElse(), First, Second);
      PairFlow Arms{Then.FallMasks | Else.FallMasks,
                    Then.BackMasks | Else.BackMasks,
                    Then.Exits || Else.Exits,
                    Then.Invalid || Else.Invalid};
      return pairSequence(Prefix, Arms);
    }
    if (const auto *Label = dyn_cast<LabelStmt>(Statement))
      return pairFlow(Label->getSubStmt(), First, Second);
    if (isa<ContinueStmt>(Statement))
      return {0, 1u, false, false};
    if (isa<BreakStmt>(Statement) || isa<ReturnStmt>(Statement))
      return {0, 0, true, false};
    if (isa<ForStmt>(Statement) || isa<WhileStmt>(Statement) ||
        isa<DoStmt>(Statement))
      return mutation(Statement, First) == Mutation::None &&
                     mutation(Statement, Second) == Mutation::None
                 ? PairFlow{1u, 0, false, false}
                 : PairFlow{0, 0, false, true};
    if (isa<GotoStmt>(Statement) || isa<SwitchStmt>(Statement))
      return {0, 0, false, true};
    if (containsConditionalExecution(Statement))
      return {0, 0, false, true};
    unsigned FirstOccurrences = progressOccurrences(Statement, First);
    unsigned SecondOccurrences = progressOccurrences(Statement, Second);
    if (FirstOccurrences > 1 || SecondOccurrences > 1)
      return {0, 0, false, true};
    /* Clang represents unevaluated builtin arguments as ordinary call
     * children (`__builtin_constant_p(a++)` is the important example).
     * Do not infer progress nested anywhere inside a call expression. */
    if (containsCall(Statement) && (FirstOccurrences || SecondOccurrences))
      return {0, 0, false, true};
    Mutation FirstMutation = mutation(Statement, First);
    Mutation SecondMutation = mutation(Statement, Second);
    if (FirstMutation == Mutation::Bad || SecondMutation == Mutation::Bad)
      return {0, 0, false, true};
    unsigned Mask = (FirstMutation == Mutation::Good ? 1u : 0u) |
                    (SecondMutation == Mutation::Good ? 2u : 0u);
    return {1u << Mask, 0, false, false};
  }

  static void collectProgress(const Stmt *Statement,
                              std::vector<Progress> &Result) {
    if (!Statement)
      return;
    if (const auto *Expression = dyn_cast<Expr>(Statement))
      if (std::optional<Progress> Change = progress(Expression)) {
        bool Seen = false;
        for (Progress &Existing : Result)
          if (sameRank(Existing, *Change) &&
              Existing.Kind == Change->Kind) {
            /* Prefer the context-free unit update as the candidate rank.
             * mutation() and the pointer-direction audit still validate
             * every additional update on each reachable backedge. */
            if (!Existing.UnitStep && Change->UnitStep)
              Existing = *Change;
            Seen = true;
          }
        if (!Seen)
          Result.push_back(*Change);
        return;
      }
    for (const Stmt *Child : Statement->children())
      collectProgress(Child, Result);
  }

  static bool writesVariable(const Stmt *Statement, const ValueDecl *Variable) {
    if (!Statement)
      return false;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain))
        if ((Unary->isIncrementDecrementOp() ||
             Unary->getOpcode() == UO_AddrOf) &&
            value(Unary->getSubExpr()) == Variable)
          return true;
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain))
        if (Binary->isAssignmentOp() && value(Binary->getLHS()) == Variable)
          return true;
    }
    for (const Stmt *Child : Statement->children())
      if (writesVariable(Child, Variable))
        return true;
    return false;
  }

  static bool containsCall(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (isa<CallExpr>(Statement))
      return true;
    for (const Stmt *Child : Statement->children())
      if (containsCall(Child))
        return true;
    return false;
  }

  bool containsImpureCall(const Stmt *Statement) const {
    if (!Statement)
      return false;
    if (const auto *Call = dyn_cast<CallExpr>(Statement)) {
      const FunctionDecl *Callee = Call->getDirectCallee();
      /* A pure/const predicate cannot change a scalar rank, its bound, or
       * the object reached by a cursor.  Its own execution is covered by
       * the ordinary call-graph and loop obligations, so it is sound to
       * use the caller's comparison exactly as if the predicate had been
       * written inline.  Indirect and unannotated calls remain opaque. */
      if (!Callee ||
          (!Callee->hasAttr<PureAttr>() && !Callee->hasAttr<ConstAttr>() &&
           !ReadonlyFunctions.contains(Callee)))
        return true;
    }
    for (const Stmt *Child : Statement->children())
      if (containsImpureCall(Child))
        return true;
    return false;
  }

  static bool containsStateMutation(const Stmt *Statement) {
    if (!Statement)
      return false;
    if (const auto *Unary = dyn_cast<UnaryOperator>(Statement))
      if (Unary->isIncrementDecrementOp())
        return true;
    if (const auto *Binary = dyn_cast<BinaryOperator>(Statement))
      if (Binary->isAssignmentOp())
        return true;
    for (const Stmt *Child : Statement->children())
      if (containsStateMutation(Child))
        return true;
    return false;
  }

  static bool knownDeallocator(const CallExpr *Call) {
    const FunctionDecl *Callee = Call ? Call->getDirectCallee() : nullptr;
    return Callee &&
           (Callee->getName() == "free" || Callee->getName() == "__free");
  }

  bool containsMemberInvalidatingCall(const Stmt *Statement) const {
    if (!Statement)
      return false;
    /* A successful free cannot mutate a live object which carries a member
     * bound.  If its argument aliases that object, the next bound read is a
     * use after lifetime and the execution has already left defined C.  Keep
     * every other call conservative, including realloc-like calls, and still
     * inspect a known deallocator's argument for nested unknown calls. */
    if (const auto *Call = dyn_cast<CallExpr>(Statement)) {
      const FunctionDecl *Callee = Call->getDirectCallee();
      if (!knownDeallocator(Call) &&
          (!Callee ||
           (!Callee->hasAttr<PureAttr>() && !Callee->hasAttr<ConstAttr>() &&
            !ReadonlyFunctions.contains(Callee))))
        return true;
    }
    for (const Stmt *Child : Statement->children())
      if (containsMemberInvalidatingCall(Child))
        return true;
    return false;
  }

  enum CallFlowOutcome : unsigned {
    FallWithoutCall = 1,
    FallWithCall = 2,
    BackWithoutCall = 4,
    BackWithCall = 8,
    ExitWithoutCall = 16,
    ExitWithCall = 32,
  };

  struct CallFlow {
    unsigned Outcomes;
    bool Invalid;
  };

  static unsigned afterCall(unsigned Outcomes) {
    unsigned Result = 0;
    if (Outcomes & (FallWithoutCall | FallWithCall))
      Result |= FallWithCall;
    if (Outcomes & (BackWithoutCall | BackWithCall))
      Result |= BackWithCall;
    if (Outcomes & (ExitWithoutCall | ExitWithCall))
      Result |= ExitWithCall;
    return Result;
  }

  static CallFlow callSequence(CallFlow First, CallFlow Second) {
    if (First.Invalid || Second.Invalid)
      return {0, true};
    unsigned Result =
        First.Outcomes &
        (BackWithoutCall | BackWithCall | ExitWithoutCall | ExitWithCall);
    if (First.Outcomes & FallWithoutCall)
      Result |= Second.Outcomes;
    if (First.Outcomes & FallWithCall)
      Result |= afterCall(Second.Outcomes);
    return {Result, false};
  }

  static CallFlow callFlow(const Stmt *Statement) {
    if (!Statement)
      return {FallWithoutCall, false};
    if (const auto *Compound = dyn_cast<CompoundStmt>(Statement)) {
      CallFlow Result{FallWithoutCall, false};
      for (const Stmt *Child : Compound->body())
        Result = callSequence(Result, callFlow(Child));
      return Result;
    }
    if (const auto *If = dyn_cast<IfStmt>(Statement)) {
      CallFlow Prefix = callSequence(callFlow(If->getInit()),
                                     callFlow(If->getConditionVariableDeclStmt()));
      Prefix = callSequence(Prefix, callFlow(If->getCond()));
      CallFlow Then = callFlow(If->getThen());
      CallFlow Else = callFlow(If->getElse());
      CallFlow Branches{Then.Outcomes | Else.Outcomes,
                        Then.Invalid || Else.Invalid};
      return callSequence(Prefix, Branches);
    }
    if (const auto *Label = dyn_cast<LabelStmt>(Statement))
      return callFlow(Label->getSubStmt());
    if (isa<ContinueStmt>(Statement))
      return {BackWithoutCall, false};
    if (isa<BreakStmt>(Statement))
      return {ExitWithoutCall, false};
    if (const auto *Return = dyn_cast<ReturnStmt>(Statement))
      return callSequence(callFlow(Return->getRetValue()),
                          {ExitWithoutCall, false});
    if (isa<ForStmt>(Statement) || isa<WhileStmt>(Statement) ||
        isa<DoStmt>(Statement)) {
      /* A nested loop has its own control targets.  If it contains a call,
       * conservatively assume that call can return and the nested loop can
       * then fall through to this loop's backedge. */
      return containsCall(Statement)
                 ? CallFlow{FallWithoutCall | FallWithCall, false}
                 : CallFlow{FallWithoutCall, false};
    }
    if (isa<GotoStmt>(Statement) || isa<SwitchStmt>(Statement))
      return {0, true};
    return containsCall(Statement)
               ? CallFlow{FallWithoutCall | FallWithCall, false}
               : CallFlow{FallWithoutCall, false};
  }

  static bool callCanReachBackedge(const Stmt *Body) {
    CallFlow Result = callFlow(Body);
    return Result.Invalid ||
           (Result.Outcomes & (FallWithCall | BackWithCall));
  }

  static bool addressTaken(const Stmt *Statement,
                           const ValueDecl *Variable) {
    if (!Statement)
      return false;
    if (const auto *Unary = dyn_cast<UnaryOperator>(Statement))
      if (Unary->getOpcode() == UO_AddrOf &&
          value(Unary->getSubExpr()) == Variable)
        return true;
    for (const Stmt *Child : Statement->children())
      if (addressTaken(Child, Variable))
        return true;
    return false;
  }

  static bool directMemberOfBase(const Expr *Expression,
                                 const ValueDecl *Base) {
    const auto *Member = dyn_cast_or_null<MemberExpr>(ignore(Expression));
    return Member && value(Member->getBase()) == Base;
  }

  static bool exportsMemberBase(const Stmt *Statement,
                                const ValueDecl *Base) {
    if (!Statement)
      return false;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      /* Ordinary scalar/member loads and stores through Base are exactly
       * what a restrict-qualified base is for.  Taking a member's address,
       * however, exports a pointer based on Base and lets a callee mutate the
       * rank legitimately, so it must remain unproved. */
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain))
        if (Unary->getOpcode() == UO_AddrOf &&
            directMemberOfBase(Unary->getSubExpr(), Base))
          return true;
      if (directMemberOfBase(Plain, Base))
        return false;
      if (const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Plain))
        if (Reference->getDecl() == Base)
          return true;
    }
    for (const Stmt *Child : Statement->children())
      if (exportsMemberBase(Child, Base))
        return true;
    return false;
  }

  bool restrictedMemberBaseIsClosed(const VarDecl *Base) const {
    /* A restrict-qualified parameter gives the needed object-identity
     * invariant: once the loop modifies a member through Base, a defined C
     * execution cannot have an opaque call reach the same object through a
     * globally-created alias.  Still reject every function which exports
     * Base itself (including copies, casts, &Base, &Base->member and call
     * arguments); those expressions create a legitimate Base-derived path
     * by which the call could reset the rank. */
    return Base && isa<ParmVarDecl>(Base) && Base->getType().isRestrictQualified() &&
           Current && !exportsMemberBase(Current->getBody(), Base);
  }

  bool pairedConditionValuesAreLocal(const Stmt *Statement) const {
    if (!Statement || !Current)
      return true;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      /* This first paired lemma intentionally covers scalar locals and
       * parameters only.  A member/global bound can have aliases which are
       * not created in the current function and therefore cannot be closed
       * by its local escape walk. */
      if (isa<MemberExpr>(Plain))
        return false;
      if (const auto *Reference = dyn_cast<DeclRefExpr>(Plain))
        if (const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl()))
          if (!(isa<ParmVarDecl>(Variable) || Variable->hasLocalStorage()) ||
              addressTaken(Current->getBody(), Variable))
            return false;
    }
    for (const Stmt *Child : Statement->children())
      if (!pairedConditionValuesAreLocal(Child))
        return false;
    return true;
  }

  static bool memberOf(const Expr *Expression, const ValueDecl *Field) {
    const auto *Member = dyn_cast_or_null<MemberExpr>(ignore(Expression));
    return Member && Member->getMemberDecl() == Field;
  }

  // Mirrors writesVariable() exactly, but matches a struct/union FIELD
  // (any `Base->Field` or `Base.Field`) instead of a single ValueDecl.
  // Matching on field identity, not the specific base expression, is
  // deliberately coarser: it can't tell two same-named fields on unrelated
  // objects apart, so a write to an unconnected object's field returns a
  // conservative true. That only costs precision, never soundness -- it
  // can never miss an actual write to the field this checker relies on as
  // unchanging.
  static bool writesMember(const Stmt *Statement, const ValueDecl *Field) {
    if (!Statement)
      return false;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain))
        if ((Unary->isIncrementDecrementOp() || Unary->getOpcode() == UO_AddrOf) &&
            memberOf(Unary->getSubExpr(), Field))
          return true;
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain))
        if (Binary->isAssignmentOp() && memberOf(Binary->getLHS(), Field))
          return true;
    }
    for (const Stmt *Child : Statement->children())
      if (writesMember(Child, Field))
        return true;
    return false;
  }

  // A loop bound of the shape `base->field` or `base.field`, where `base`
  // is a plain parameter or local, is stable across the loop when: the
  // base is never reseated or handed somewhere that could overwrite it
  // (writesVariable/aliasedWrite, as for the plain-variable case above);
  // nothing writes `*base` wholesale or passes `base` to a call that
  // could reach back through it (writesThroughAlias -- vacuous for a
  // dot base since that's a struct, not a pointer, which is correct
  // since aliasedWrite already covers an escaped struct local); and no
  // expression assigns through a member with the same field identity
  // (writesMember, coarse but sound as documented above).
  //
  // A member reached through anything but a single plain base variable
  // (another member expression, a call result, a subscript) is left
  // unrecognized and falls through to "false": there's no local var to
  // run the escape checks against.
  bool memberStable(const MemberExpr *Member, const Stmt *Body,
                    const Expr *Increment) const {
    const ValueDecl *Field = Member->getMemberDecl();
    const ValueDecl *BaseDecl = value(Member->getBase());
    if (!Field || !BaseDecl || Member->getType().isVolatileQualified())
      return false;
    const auto *BaseVar = dyn_cast<VarDecl>(BaseDecl);
    if (!BaseVar || BaseVar->getType().isVolatileQualified() || !Current)
      return false;
    /* A call need not receive BaseVar to mutate the same object: a parameter
     * may alias globally reachable storage, and a local object's address may
     * have escaped before the loop.  Only the separately checked read-only
     * summary (and lifetime-only deallocators) closes that route. */
    if (containsAsm(Body) || containsAsm(Increment) ||
        containsMemberInvalidatingCall(Body) ||
        containsMemberInvalidatingCall(Increment))
      return false;
    if (writesVariable(Body, BaseVar) || writesVariable(Increment, BaseVar) ||
        aliasedWrite(BaseVar, Body))
      return false;
    if (Member->isArrow() &&
        (writesThroughAlias(Body, BaseVar) || writesThroughAlias(Increment, BaseVar)))
      return false;
    return !writesMember(Body, Field) && !writesMember(Increment, Field);
  }

  static bool addressOf(const Expr *Expression, const ValueDecl *Variable) {
    const auto *Unary = dyn_cast_or_null<UnaryOperator>(ignore(Expression));
    return Unary && Unary->getOpcode() == UO_AddrOf &&
           value(Unary->getSubExpr()) == Variable;
  }

  static void collectAliases(const Stmt *Statement, const ValueDecl *Variable,
                             std::vector<const ValueDecl *> &Aliases) {
    if (!Statement)
      return;
    if (const auto *Declaration = dyn_cast<DeclStmt>(Statement))
      for (const Decl *Item : Declaration->decls())
        if (const auto *Alias = dyn_cast<VarDecl>(Item))
          if (addressOf(Alias->getInit(), Variable))
            Aliases.push_back(Alias);
    if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(
            ignore(dyn_cast_or_null<Expr>(Statement))))
      if (Binary->isAssignmentOp() && addressOf(Binary->getRHS(), Variable))
        if (const ValueDecl *Alias = value(Binary->getLHS()))
          Aliases.push_back(Alias);
    for (const Stmt *Child : Statement->children())
      collectAliases(Child, Variable, Aliases);
  }

  static bool writesThroughAlias(const Stmt *Statement,
                                 const ValueDecl *Alias,
                                 bool CallsAreWrites = true) {
    if (!Statement)
      return false;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      const Expr *Plain = ignore(Expression);
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain)) {
        const auto *Target =
            dyn_cast_or_null<UnaryOperator>(ignore(Unary->getSubExpr()));
        if (Unary->isIncrementDecrementOp() && Target &&
            Target->getOpcode() == UO_Deref &&
            value(Target->getSubExpr()) == Alias)
          return true;
      }
      if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain)) {
        const auto *Target =
            dyn_cast_or_null<UnaryOperator>(ignore(Binary->getLHS()));
        if (Binary->isAssignmentOp() && Target &&
            Target->getOpcode() == UO_Deref &&
            value(Target->getSubExpr()) == Alias)
          return true;
      }
      if (CallsAreWrites) {
        if (const auto *Call = dyn_cast_or_null<CallExpr>(Plain))
          for (const Expr *Argument : Call->arguments())
            if (value(Argument) == Alias)
              return true;
      }
    }
    for (const Stmt *Child : Statement->children())
      if (writesThroughAlias(Child, Alias, CallsAreWrites))
        return true;
    return false;
  }

  bool aliasedWrite(const ValueDecl *Variable, const Stmt *Body) const {
    std::vector<const ValueDecl *> Aliases;
    collectAliases(Current->getBody(), Variable, Aliases);
    for (const ValueDecl *Alias : Aliases)
      if (writesThroughAlias(Body, Alias))
        return true;
    return false;
  }

  bool validRankVariable(const Progress &Change, const Stmt *Body,
                         const Expr *Increment = nullptr) const {
    if (const auto *Field = dyn_cast<FieldDecl>(Change.Variable)) {
      const auto *Base = dyn_cast_or_null<VarDecl>(Change.Base);
      bool ClosedRestrictedBase = restrictedMemberBaseIsClosed(Base);
      return !Change.VolatileAccess && !Field->getType().isVolatileQualified() &&
             Base && !Base->getType().isVolatileQualified() && Current &&
             !containsAsm(Body) && !containsAsm(Increment) &&
             (!Base->getType().isRestrictQualified() ||
              ClosedRestrictedBase) &&
             ((!callCanReachBackedge(Body) && !containsCall(Increment)) ||
              (!containsImpureCall(Body) &&
               !containsImpureCall(Increment)) ||
              ClosedRestrictedBase) &&
             !writesVariable(Body, Base) && !aliasedWrite(Base, Body) &&
             !mentionsFieldThroughOtherBase(Body, Change) &&
             !mentionsFieldThroughOtherBase(Increment, Change) &&
             (!Base->getType()->isPointerType() ||
              !writesThroughAlias(Body, Base, false));
    }
    const auto *Variable = dyn_cast<VarDecl>(Change.Variable);
    if (!Variable || Variable->getType().isVolatileQualified() || !Current)
      return false;
    if (!(isa<ParmVarDecl>(Variable) || Variable->hasLocalStorage())) {
      if (Variable->getFormalLinkage() != Linkage::Internal ||
          containsCall(Body) || containsCall(Increment))
        return false;
    } else if ((containsCall(Body) || containsCall(Increment)) &&
               addressTaken(Current->getBody(), Variable)) {
      return false;
    }
    return !aliasedWrite(Variable, Body);
  }

  static bool mentionsFieldThroughOtherBase(const Stmt *Statement,
                                            const Progress &Rank) {
    if (!Statement)
      return false;
    if (const auto *Member = dyn_cast<MemberExpr>(Statement))
      if (Member->getMemberDecl() == Rank.Variable &&
          value(Member->getBase()) != Rank.Base)
        return true;
    for (const Stmt *Child : Statement->children())
      if (mentionsFieldThroughOtherBase(Child, Rank))
        return true;
    return false;
  }

  bool pointerObjectDistanceRank(const Progress &Rank,
                                 const Expr *Condition,
                                 const Stmt *Body,
                                 const Expr *Increment) const {
    if (!Rank.Variable->getType()->isPointerType() ||
        containsAsm(Condition) || containsAsm(Body) || containsAsm(Increment) ||
        mutation(Condition, Rank) != Mutation::None ||
        hasPotentiallyReversingPointerStep(Body, Rank) ||
        hasPotentiallyReversingPointerStep(Increment, Rank))
      return false;
    if (!isa<FieldDecl>(Rank.Variable))
      return true;
    /* A member cursor may have aliases established before the loop.  Trust
     * calls only when their read-only contract closes that route, and reject
     * even a conservative mention of this field through another base: it
     * could cancel, reset, or backtrack the candidate cursor. */
    return !containsImpureCall(Body) && !containsImpureCall(Increment) &&
           !mentionsFieldThroughOtherBase(Condition, Rank) &&
           !mentionsFieldThroughOtherBase(Body, Rank) &&
           !mentionsFieldThroughOtherBase(Increment, Rank);
  }

  bool hasPotentiallyReversingPointerStep(const Stmt *Statement,
                                          const Progress &Rank) const {
    if (!Statement)
      return false;
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      if (std::optional<Progress> Change = progress(Expression)) {
        if (sameRank(*Change, Rank) && Change->DynamicStep) {
          /* An unsigned delta is nonnegative.  A signed delta can reverse
           * the syntactic +=/-= direction and cancel the selected pointer
           * rank unless the closed-callsite summary proves it positive. */
          if (!Change->GuardedStep ||
              !Change->GuardedStep->getType()->isUnsignedIntegerType()) {
            if (!admissibleProgress(*Change))
              return true;
          }
        }
      }
    }
    for (const Stmt *Child : Statement->children())
      if (hasPotentiallyReversingPointerStep(Child, Rank))
        return true;
    return false;
  }

  bool signedFiniteDomainRank(const Progress &Rank,
                              const Expr *Condition,
                              const Stmt *Body,
                              const Expr *Increment) const {
    /* A unit, directed update of a signed C integer cannot occur on
     * infinitely many defined backedges.  Its finite value domain is the
     * rank: execution either exits first or the update overflows, at which
     * point it was already outside the defined C executions for which this
     * proof is responsible.  Restrict this to ++/--: even a constant
     * compound step can be computed in an unsigned type (`i += 1u`) and
     * converted back to signed, which may cycle without signed-overflow UB.
     * This is deliberately not an unsigned theorem (wrapping is defined
     * there), nor a dynamic-step theorem (the step may be zero or reverse
     * direction). */
    QualType Type = Rank.Variable->getType();
    /* Integer promotions make signed char/short updates narrow back to the
     * lvalue type.  An out-of-range narrowing is implementation-defined,
     * rather than signed-overflow UB, and can therefore cycle. */
    const auto *Field = dyn_cast<FieldDecl>(Rank.Variable);
    return (!Field || !Field->isBitField()) &&
           Type->isSignedIntegerType() && !Type->isEnumeralType() &&
           Context.getIntWidth(Type) >= Context.getIntWidth(Context.IntTy) &&
           Rank.UnaryStep && Rank.UnitStep && !Rank.DynamicStep &&
           !Rank.GuardedStep &&
           !Rank.RequiresNonzeroCondition &&
           !containsAsm(Condition) && !containsAsm(Body) &&
           !containsAsm(Increment) &&
           mutation(Condition, Rank) == Mutation::None &&
           mutation(Increment, Rank) == Mutation::None &&
           progressOccurrences(Body, Rank) == 1;
  }

  bool stableBound(const Expr *Expression, const Stmt *Body,
                   const Expr *Increment) const {
    if (!Expression)
      return false;
    Expr::EvalResult Constant;
    if (Expression->EvaluateAsInt(Constant, Context))
      return true;
    const Expr *Plain = ignore(Expression);
    if (const auto *Cast = dyn_cast_or_null<CastExpr>(Plain))
      return stableBound(Cast->getSubExpr(), Body, Increment);
    if (const auto *Reference = dyn_cast_or_null<DeclRefExpr>(Plain)) {
      const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl());
      if (!Variable || Variable->getType().isVolatileQualified() || !Current)
        return false;
      if (!(isa<ParmVarDecl>(Variable) || Variable->hasLocalStorage())) {
        if (Variable->getFormalLinkage() != Linkage::Internal ||
            containsCall(Body) || containsCall(Increment))
          return false;
      } else if ((containsCall(Body) || containsCall(Increment)) &&
                 addressTaken(Current->getBody(), Variable)) {
        return false;
      }
      return !aliasedWrite(Variable, Body) &&
             !writesVariable(Body, Variable) &&
             !writesVariable(Increment, Variable);
    }
    if (const auto *Member = dyn_cast_or_null<MemberExpr>(Plain))
      return memberStable(Member, Body, Increment);
    if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Plain)) {
      /* A second pointer can alias the pointee without being derived from
       * this spelling.  Local syntactic escape tracking is insufficient to
       * prove `*p` stable, and volatile pointees make the issue explicit. */
      if (Unary->getOpcode() == UO_Deref)
        return false;
      if (Unary->isIncrementDecrementOp() || Unary->getOpcode() == UO_AddrOf)
        return false;
      return stableBound(Unary->getSubExpr(), Body, Increment);
    }
    if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(Plain)) {
      if (Binary->isAssignmentOp() || Binary->isCommaOp() ||
          Binary->isLogicalOp())
        return false;
      return stableBound(Binary->getLHS(), Body, Increment) &&
             stableBound(Binary->getRHS(), Body, Increment);
    }
    return false;
  }

  bool maximumFitsRank(const llvm::APSInt &BoundMaximum,
                       const ValueDecl *Variable,
                       bool AllowEqual) const {
    QualType VariableType = Variable->getType();
    if (!VariableType->isIntegerType())
      return false;
    llvm::APSInt Maximum = llvm::APSInt::getMaxValue(
        Context.getIntWidth(VariableType),
        VariableType->isUnsignedIntegerOrEnumerationType());
    int Comparison = llvm::APSInt::compareValues(BoundMaximum, Maximum);
    return AllowEqual ? Comparison <= 0 : Comparison < 0;
  }

  bool boundFitsRank(const Expr *Bound, const ValueDecl *Variable,
                     bool AllowEqual) const {
    Expr::EvalResult Constant;
    if (Bound->EvaluateAsInt(Constant, Context))
      return maximumFitsRank(Constant.Val.getInt(), Variable, AllowEqual);
    const Expr *Plain = ignore(Bound);
    if (!Plain || !Plain->getType()->isIntegerType())
      return false;
    QualType BoundType = Plain->getType();
    llvm::APSInt BoundMaximum = llvm::APSInt::getMaxValue(
        Context.getIntWidth(BoundType),
        BoundType->isUnsignedIntegerOrEnumerationType());
    return maximumFitsRank(BoundMaximum, Variable, AllowEqual);
  }

  bool belowTypeMaximum(const Expr *Bound, const ValueDecl *Variable) const {
    return boundFitsRank(Bound, Variable, false);
  }

  static bool nullTerminatedParameter(const FunctionDecl *Function,
                                      unsigned Argument) {
    if (!Function)
      return false;
    for (const FunctionDecl *Redeclaration : Function->redecls()) {
      if (Argument >= Redeclaration->getNumParams())
        continue;
      for (const AnnotateAttr *Attribute :
           Redeclaration->getParamDecl(Argument)->specific_attrs<AnnotateAttr>())
        if (Attribute->getAnnotation() == "withtok:null_terminated")
          return true;
    }
    return false;
  }

  bool trustedSentinelLength(const FunctionDecl *Function) const {
    /* strlen/wcslen return the number of elements before a terminator that
     * their parameter contract says exists in a valid finite C object.  The
     * terminator therefore occupies the following element, so that count is
     * strictly below the maximum of its size_t-like return domain.  Identity
     * comes from clang's standard builtin table in standalone fixtures, or
     * from this project's actual public declaration when -fno-builtin is in
     * force; a same-named user function is not enough.  A visible replacement
     * definition is rejected outright: inspecting only its return expressions
     * would be unsound (a negative signed value can convert to SIZE_MAX), while
     * the standard/header declaration is the existing semantic contract used
     * by cross-translation-unit calls. */
    if (!Function || !nullTerminatedParameter(Function, 0))
      return false;
    StringRef DeclaredName = Function->getName();
    if (DeclaredName != "strlen" && DeclaredName != "wcslen")
      return false;
    unsigned BuiltinID = Function->getBuiltinID();
    bool CompilerBuiltin = BuiltinID &&
        Context.BuiltinInfo.getName(BuiltinID) == DeclaredName;
    bool ProjectDeclaration = false;
    for (const FunctionDecl *Redeclaration : Function->redecls()) {
      StringRef Header = SM.getFilename(
          SM.getExpansionLoc(Redeclaration->getLocation()));
      ProjectDeclaration |=
          (DeclaredName == "strlen" && Header == "include/string.h") ||
          (DeclaredName == "wcslen" && Header == "include/wchar.h");
    }
    if (!CompilerBuiltin && !ProjectDeclaration)
      return false;
    return !Function->getDefinition();
  }

  bool sentinelLengthSnapshot(const Expr *Expression,
                              const ValueDecl *Rank,
                              std::vector<const VarDecl *> &Seen) const {
    /* Carry the fact only through address-untaken, never-written automatic
     * locals of exactly the rank's arithmetic type.  This admits direct
     * snapshots and same-type copies without turning casts, arithmetic, or
     * mutable aliases into range facts. */
    const auto *Snapshot = dyn_cast_or_null<VarDecl>(value(Expression));
    if (!Snapshot || !Current || !Snapshot->hasLocalStorage() ||
        Snapshot->getType().isVolatileQualified() || !Snapshot->hasInit() ||
        Snapshot->getType().getCanonicalType().getUnqualifiedType() !=
            Rank->getType().getCanonicalType().getUnqualifiedType() ||
        addressTaken(Current->getBody(), Snapshot) ||
        writesVariable(Current->getBody(), Snapshot) ||
        llvm::is_contained(Seen, Snapshot))
      return false;
    Seen.push_back(Snapshot);
    const Expr *Initializer = ignore(Snapshot->getInit());
    if (const auto *Call = dyn_cast_or_null<CallExpr>(Initializer)) {
      const FunctionDecl *Callee = Call->getDirectCallee();
      return Callee && Call->getNumArgs() == 1 &&
             trustedSentinelLength(Callee) &&
             Callee->getReturnType().getCanonicalType().getUnqualifiedType() ==
                 Snapshot->getType().getCanonicalType().getUnqualifiedType();
    }
    return sentinelLengthSnapshot(Initializer, Rank, Seen);
  }

  bool sentinelLengthSnapshot(const Expr *Expression,
                              const ValueDecl *Rank) const {
    std::vector<const VarDecl *> Seen;
    return sentinelLengthSnapshot(Expression, Rank, Seen);
  }

  bool belowTypeMaximumAfterConversion(
      const Expr *Bound, const ValueDecl *Variable) const {
    const Expr *Source = ignore(Bound);
    if (!Source)
      return false;
    QualType SourceType = Source->getType();
    QualType ConvertedType = Bound->getType();
    if (SourceType->isSignedIntegerOrEnumerationType() &&
        ConvertedType->isUnsignedIntegerOrEnumerationType()) {
      /* A negative signed value converted to the unsigned comparison
       * domain can become its maximum: -1 is exactly UINT_MAX.  That is
       * harmless for strict `<`, but `rank <= UINT_MAX; rank++` wraps.
       * Accept this conversion only when the source is a known
       * nonnegative constant; arbitrary signed bounds include -1. */
      Expr::EvalResult Constant;
      if (!Source->EvaluateAsInt(Constant, Context) ||
          Constant.Val.getInt().isNegative())
        return false;
    }
    return belowTypeMaximum(Bound, Variable) ||
           sentinelLengthSnapshot(Bound, Variable);
  }

  bool atMostTypeMaximum(const Expr *Bound,
                         const ValueDecl *Variable) const {
    return boundFitsRank(Bound, Variable, true);
  }

  bool aboveTypeMinimum(const Expr *Bound, const ValueDecl *Variable) const {
    QualType VariableType = Variable->getType();
    if (!VariableType->isIntegerType())
      return false;
    llvm::APSInt Minimum = llvm::APSInt::getMinValue(
        Context.getIntWidth(VariableType),
        VariableType->isUnsignedIntegerOrEnumerationType());
    Expr::EvalResult Constant;
    if (Bound->EvaluateAsInt(Constant, Context))
      return llvm::APSInt::compareValues(Constant.Val.getInt(), Minimum) > 0;
    const Expr *Plain = ignore(Bound);
    if (!Plain || !Plain->getType()->isIntegerType())
      return false;
    QualType BoundType = Plain->getType();
    llvm::APSInt BoundMinimum = llvm::APSInt::getMinValue(
        Context.getIntWidth(BoundType),
        BoundType->isUnsignedIntegerOrEnumerationType());
    return llvm::APSInt::compareValues(BoundMinimum, Minimum) > 0;
  }

  bool affineOn(const Expr *Expression, const Progress &Rank,
                const Stmt *Body, const Expr *Increment) const {
    Expression = ignore(Expression);
    if (rankAccess(Expression, Rank))
      return true;
    const auto *Binary = dyn_cast_or_null<BinaryOperator>(Expression);
    if (!Binary || Binary->getOpcode() != BO_Add)
      return false;
    if (rankAccess(Binary->getLHS(), Rank))
      return stableBound(Binary->getRHS(), Body, Increment);
    return rankAccess(Binary->getRHS(), Rank) &&
           stableBound(Binary->getLHS(), Body, Increment);
  }

  bool guardsUnsignedStep(BinaryOperatorKind Opcode, const Expr *Bound,
                          const Progress &Change) const {
    if (!Change.GuardedStep)
      return true;
    /* For `n -= K`, an unsigned backedge is safe exactly when the taken
     * condition establishes n >= K.  Keep this deliberately narrow: both
     * K and the lower bound must be integer constant expressions, and use
     * only the direct inclusive spelling.  This covers chunked countdowns
     * such as `while (n >= sizeof word) n -= sizeof word` without accepting
     * the wrapping `while (n) n -= 2`. */
    if (Opcode != BO_GE)
      return false;
    Expr::EvalResult BoundValue;
    Expr::EvalResult StepValue;
    if (!Bound->EvaluateAsInt(BoundValue, Context) ||
        !Change.GuardedStep->EvaluateAsInt(StepValue, Context))
      return false;
    return llvm::APSInt::compareValues(BoundValue.Val.getInt(),
                                       StepValue.Val.getInt()) >= 0;
  }

  bool strictComparison(const Expr *Condition, const Progress &Change,
                        const Stmt *Body, const Expr *Increment,
                        bool DirectRank = false) const {
    if (Change.RequiresNonzeroCondition || Change.DynamicStep ||
        (Change.Kind == ProgressKind::Up && Change.GuardedStep))
      return false;
    Condition = ignore(Condition);
    if (const auto *Logical = dyn_cast_or_null<BinaryOperator>(Condition)) {
      if (Logical->getOpcode() == BO_LAnd)
        return strictComparison(Logical->getLHS(), Change, Body, Increment,
                                DirectRank) ||
               strictComparison(Logical->getRHS(), Change, Body, Increment,
                                DirectRank);
      /* For A || B, either arm can keep the loop running.  Both therefore
       * need the same rank; accepting one arm makes
       * `i < n || keep_running` a false proof. */
      if (Logical->getOpcode() == BO_LOr)
        return strictComparison(Logical->getLHS(), Change, Body, Increment,
                                DirectRank) &&
               strictComparison(Logical->getRHS(), Change, Body, Increment,
                                DirectRank);
      bool Left = DirectRank
                      ? rankAccess(Logical->getLHS(), Change)
                      : affineOn(Logical->getLHS(), Change, Body, Increment);
      bool Right = DirectRank
                       ? rankAccess(Logical->getRHS(), Change)
                       : affineOn(Logical->getRHS(), Change, Body, Increment);
      if (Change.Kind == ProgressKind::Up)
        return (Left &&
                stableBound(Logical->getRHS(), Body, Increment) &&
                ((Logical->getOpcode() == BO_LT &&
                  (!Change.Variable->getType()->isUnsignedIntegerType() ||
                   atMostTypeMaximum(Logical->getRHS(), Change.Variable))) ||
                 (Logical->getOpcode() == BO_LE &&
                  (!Change.Variable->getType()->isUnsignedIntegerType() ||
                   belowTypeMaximumAfterConversion(
                       Logical->getRHS(), Change.Variable))))) ||
               (Right &&
                stableBound(Logical->getLHS(), Body, Increment) &&
                ((Logical->getOpcode() == BO_GT &&
                  (!Change.Variable->getType()->isUnsignedIntegerType() ||
                   atMostTypeMaximum(Logical->getLHS(), Change.Variable))) ||
                 (Logical->getOpcode() == BO_GE &&
                  (!Change.Variable->getType()->isUnsignedIntegerType() ||
                   belowTypeMaximumAfterConversion(
                       Logical->getLHS(), Change.Variable)))));
      if (Change.Kind == ProgressKind::Down)
        return (Left &&
                stableBound(Logical->getRHS(), Body, Increment) &&
                guardsUnsignedStep(Logical->getOpcode(), Logical->getRHS(),
                                   Change) &&
                (Logical->getOpcode() == BO_GT ||
                 (Logical->getOpcode() == BO_GE &&
                  (Change.Variable->getType()->isSignedIntegerType() ||
                   aboveTypeMinimum(Logical->getRHS(), Change.Variable))))) ||
               (Right &&
                stableBound(Logical->getLHS(), Body, Increment) &&
                guardsUnsignedStep(
                    BinaryOperator::reverseComparisonOp(
                        Logical->getOpcode()),
                    Logical->getLHS(), Change) &&
                (Logical->getOpcode() == BO_LT ||
                 (Logical->getOpcode() == BO_LE &&
                  (Change.Variable->getType()->isSignedIntegerType() ||
                   aboveTypeMinimum(Logical->getLHS(), Change.Variable)))));
    }
    return false;
  }

  bool sameDomainUnitUpperBound(const Expr *Condition,
                                const Progress &Change) const {
    if (!Change.UnitStep || Change.Kind != ProgressKind::Up ||
        !Change.Variable->getType()->isIntegerType() ||
        mutation(Condition, Change) != Mutation::None)
      return false;
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(
        ignore(Condition));
    if (!Comparison)
      return false;
    const Expr *RankOperand = nullptr;
    const Expr *Bound = nullptr;
    bool Inclusive = false;
    if (rankAccess(Comparison->getLHS(), Change) &&
        (Comparison->getOpcode() == BO_LT ||
         Comparison->getOpcode() == BO_LE)) {
      RankOperand = Comparison->getLHS();
      Bound = Comparison->getRHS();
      Inclusive = Comparison->getOpcode() == BO_LE;
    } else if (rankAccess(Comparison->getRHS(), Change) &&
               (Comparison->getOpcode() == BO_GT ||
                Comparison->getOpcode() == BO_GE)) {
      RankOperand = Comparison->getRHS();
      Bound = Comparison->getLHS();
      Inclusive = Comparison->getOpcode() == BO_GE;
    } else {
      return false;
    }
    if (!RankOperand->getType()->isIntegerType() ||
        !Bound->getType()->isIntegerType())
      return false;
    QualType RankComparisonType = RankOperand->getType().getCanonicalType()
                                      .getUnqualifiedType();
    QualType BoundComparisonType = Bound->getType().getCanonicalType()
                                       .getUnqualifiedType();
    if (RankComparisonType != BoundComparisonType)
      return false;
    /* The condition is reevaluated before every backedge.  If every value
     * the upper operand can contribute fits in the rank's own arithmetic
     * domain, a taken `rank < bound` proves rank != TYPE_MAX.  Unit `++`
     * is therefore representable and strictly advances even when the bound
     * is live, aliased, or changed by a callback.  `<=` needs the stronger
     * strict-below-maximum fact because equality also takes the backedge. */
    return Inclusive ? belowTypeMaximumAfterConversion(Bound, Change.Variable)
                     : atMostTypeMaximum(Bound, Change.Variable);
  }

  static bool initializesRankToZero(const Stmt *Initializer,
                                    const Progress &Change) {
    if (const auto *Declaration = dyn_cast_or_null<DeclStmt>(Initializer)) {
      if (!Declaration->isSingleDecl())
        return false;
      const auto *Variable =
          dyn_cast<VarDecl>(Declaration->getSingleDecl());
      return Variable == Change.Variable && Variable->hasInit() &&
             zeroInteger(Variable->getInit());
    }
    const auto *Assignment = dyn_cast_or_null<BinaryOperator>(
        ignore(dyn_cast_or_null<Expr>(Initializer)));
    return Assignment && Assignment->getOpcode() == BO_Assign &&
           rankAccess(Assignment->getLHS(), Change) &&
           zeroInteger(Assignment->getRHS());
  }

  bool constantStride(const Expr *Increment, const Progress &Change,
                      llvm::APSInt &Step) const {
    const Expr *Plain = ignore(Increment);
    const Expr *StepExpression = nullptr;
    QualType ComputationType;
    if (const auto *Compound =
            dyn_cast_or_null<CompoundAssignOperator>(Plain)) {
      if (Compound->getOpcode() != BO_AddAssign ||
          !rankAccess(Compound->getLHS(), Change))
        return false;
      StepExpression = Compound->getRHS();
      ComputationType = Compound->getComputationResultType();
    } else if (const auto *Assignment =
                   dyn_cast_or_null<BinaryOperator>(Plain)) {
      const auto *Addition = dyn_cast_or_null<BinaryOperator>(
          ignore(Assignment->getRHS()));
      if (Assignment->getOpcode() != BO_Assign ||
          !rankAccess(Assignment->getLHS(), Change) || !Addition ||
          Addition->getOpcode() != BO_Add ||
          !rankAccess(Addition->getLHS(), Change))
        return false;
      StepExpression = Addition->getRHS();
      ComputationType = Addition->getType();
    }
    if (!StepExpression ||
        ComputationType.getCanonicalType().getUnqualifiedType() !=
            Change.Variable->getType().getCanonicalType().getUnqualifiedType())
      return false;
    Expr::EvalResult Value;
    if (!StepExpression->EvaluateAsInt(Value, Context) ||
        Value.Val.getInt().isNegative() || Value.Val.getInt().isZero() ||
        !maximumFitsRank(Value.Val.getInt(), Change.Variable, true))
      return false;
    Step = Value.Val.getInt();
    return true;
  }

  static bool multipliedByStep(const Expr *Expression,
                               const llvm::APInt &Step,
                               QualType RankType, ASTContext &Context) {
    const auto *Product = dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    if (!Product || Product->getOpcode() != BO_Mul ||
        Product->getType().getCanonicalType().getUnqualifiedType() !=
            RankType.getCanonicalType().getUnqualifiedType())
      return false;
    auto Matches = [&](const Expr *Factor) {
      Expr::EvalResult Value;
      if (!Factor->EvaluateAsInt(Value, Context) ||
          Value.Val.getInt().isNegative())
        return false;
      return Value.Val.getInt().zextOrTrunc(Step.getBitWidth()) ==
             Step;
    };
    return Matches(Product->getLHS()) || Matches(Product->getRHS());
  }

  bool strideBoundIsReachable(const Expr *Bound,
                              const Progress &Change,
                              const llvm::APInt &Step,
                              const llvm::APInt &MaximumReachable) const {
    Expr::EvalResult Constant;
    if (Bound->EvaluateAsInt(Constant, Context)) {
      if (Constant.Val.getInt().isNegative())
        return false;
      llvm::APInt BoundValue = Constant.Val.getInt().zextOrTrunc(
          MaximumReachable.getBitWidth());
      return BoundValue.ule(MaximumReachable);
    }
    if (MaximumReachable.isAllOnes())
      return true;
    /* A power-of-two stride divides the unsigned arithmetic modulus.  An
     * exact product by that stride therefore remains in the rank's residue
     * class even if the product wraps.  Starting at zero then reaches the
     * bound exactly, before the update itself could wrap. */
    if (!Step.isPowerOf2())
      return false;
    const auto *Variable = dyn_cast_or_null<VarDecl>(value(Bound));
    return Variable && Variable->hasInit() &&
           !Variable->getType().isVolatileQualified() && Current &&
           !addressTaken(Current->getBody(), Variable) &&
           !writesVariable(Current->getBody(), Variable) &&
           multipliedByStep(Variable->getInit(), Step,
                            Change.Variable->getType(), Context);
  }

  bool guardedConstantStrideAscent(const Stmt *Loop,
                                   const Expr *Condition,
                                   const Stmt *Body,
                                   const Expr *Increment,
                                   const Progress &Change) const {
    /* For an unsigned rank starting at zero, a constant stride is finite
     * under a strict upper bound when either the entire bound domain lies
     * below the last representable value in the rank's residue class, or
     * the stable bound is itself proved to have that residue.  This avoids
     * treating `i < bound` alone as sufficient: with stride two and an odd
     * maximum bound, i wraps and repeats forever. */
    const auto *For = dyn_cast_or_null<ForStmt>(Loop);
    const auto *Rank = dyn_cast_or_null<VarDecl>(Change.Variable);
    if (!For || !Rank || Change.Kind != ProgressKind::Up ||
        Change.UnitStep || Change.DynamicStep || !Change.GuardedStep ||
        !Rank->hasLocalStorage() ||
        !Rank->getType()->isUnsignedIntegerType() ||
        Rank->getType().isVolatileQualified() || !Current ||
        addressTaken(Current->getBody(), Rank) ||
        containsAsm(Body) ||
        containsEmbeddedLabel(Body) ||
        !initializesRankToZero(For->getInit(), Change) ||
        !validRankVariable(Change, Body, Increment) ||
        mutation(Body, Change) != Mutation::None)
      return false;
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(
        ignore(Condition));
    const Expr *RankOperand = nullptr;
    const Expr *Bound = nullptr;
    if (Comparison && Comparison->getOpcode() == BO_LT &&
        rankAccess(Comparison->getLHS(), Change)) {
      RankOperand = Comparison->getLHS();
      Bound = Comparison->getRHS();
    } else if (Comparison && Comparison->getOpcode() == BO_GT &&
               rankAccess(Comparison->getRHS(), Change)) {
      RankOperand = Comparison->getRHS();
      Bound = Comparison->getLHS();
    } else {
      return false;
    }
    const auto *BoundVariable = dyn_cast_or_null<VarDecl>(value(Bound));
    QualType RankType = Rank->getType().getCanonicalType().getUnqualifiedType();
    if (!RankOperand->getType()->isIntegerType() ||
        !Bound->getType()->isIntegerType() ||
        RankOperand->getType().getCanonicalType().getUnqualifiedType() !=
            RankType ||
        Bound->getType().getCanonicalType().getUnqualifiedType() != RankType ||
        (BoundVariable &&
         (!(isa<ParmVarDecl>(BoundVariable) ||
            BoundVariable->hasLocalStorage()) ||
          BoundVariable->getType().isVolatileQualified() ||
          addressTaken(Current->getBody(), BoundVariable))) ||
        !stableBound(Bound, Body, Increment))
      return false;
    llvm::APSInt StepValue;
    if (!constantStride(Increment, Change, StepValue))
      return false;
    unsigned Width = Context.getIntWidth(Rank->getType());
    llvm::APInt Step = StepValue.zextOrTrunc(Width);
    llvm::APInt Maximum = llvm::APInt::getMaxValue(Width);
    llvm::APInt MaximumReachable = Maximum - Maximum.urem(Step);
    return strideBoundIsReachable(Bound, Change, Step, MaximumReachable);
  }

  struct DerivedAffine {
    Progress Rank;
    const VarDecl *Child;
  };

  static void collectDerivedAffine(const Stmt *Statement,
                                   std::vector<DerivedAffine> &Result) {
    if (!Statement)
      return;
    if (const auto *Binary = dyn_cast_or_null<BinaryOperator>(
            ignore(dyn_cast_or_null<Expr>(Statement)))) {
      const auto *Rank = dyn_cast_or_null<VarDecl>(value(Binary->getLHS()));
      const auto *Child = dyn_cast_or_null<VarDecl>(value(Binary->getRHS()));
      if (Binary->getOpcode() == BO_Assign && Rank && Child && Rank != Child &&
          Rank->getType()->isUnsignedIntegerType() &&
          Rank->getType().getCanonicalType().getUnqualifiedType() ==
              Child->getType().getCanonicalType().getUnqualifiedType()) {
        bool Seen = false;
        for (const DerivedAffine &Existing : Result)
          Seen |= Existing.Rank.Variable == Rank && Existing.Child == Child;
        if (!Seen)
          Result.push_back({makeProgress(Rank, ProgressKind::Up, nullptr,
                                         Binary->getLHS()),
                            Child});
      }
    }
    for (const Stmt *Child : Statement->children())
      collectDerivedAffine(Child, Result);
  }

  static const Expr *doubleProductOf(const Expr *Expression,
                                     const ValueDecl *Rank) {
    const auto *Product =
        dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    if (!Product || Product->getOpcode() != BO_Mul)
      return nullptr;
    const Expr *RankFactor = nullptr;
    if (const auto *Literal =
            dyn_cast_or_null<IntegerLiteral>(ignore(Product->getLHS()));
        Literal && Literal->getValue() == 2)
      RankFactor = Product->getRHS();
    else if (const auto *Literal =
                 dyn_cast_or_null<IntegerLiteral>(ignore(Product->getRHS()));
             Literal && Literal->getValue() == 2)
      RankFactor = Product->getLHS();
    return RankFactor && value(RankFactor) == Rank ? Product : nullptr;
  }

  static bool initializesDerivedChild(const Expr *Expression,
                                      const DerivedAffine &Candidate) {
    const auto *Assignment =
        dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    if (!Assignment || Assignment->getOpcode() != BO_Assign ||
        value(Assignment->getLHS()) != Candidate.Child)
      return false;
    const auto *Addition =
        dyn_cast_or_null<BinaryOperator>(ignore(Assignment->getRHS()));
    if (!Addition || Addition->getOpcode() != BO_Add)
      return false;
    const Expr *ProductExpression = nullptr;
    if (unitInteger(Addition->getLHS()))
      ProductExpression = Addition->getRHS();
    else if (unitInteger(Addition->getRHS()))
      ProductExpression = Addition->getLHS();
    const Expr *Product =
        doubleProductOf(ProductExpression, Candidate.Rank.Variable);
    if (!Product)
      return false;
    QualType RankType = Candidate.Rank.Variable->getType().getCanonicalType()
                            .getUnqualifiedType();
    return Assignment->getLHS()->getType().getCanonicalType()
                   .getUnqualifiedType() == RankType &&
           Addition->getType().getCanonicalType().getUnqualifiedType() ==
               RankType &&
           Product->getType().getCanonicalType().getUnqualifiedType() ==
               RankType;
  }

  static bool commitsDerivedChild(const Expr *Expression,
                                  const DerivedAffine &Candidate) {
    const auto *Assignment =
        dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    return Assignment && Assignment->getOpcode() == BO_Assign &&
           value(Assignment->getLHS()) == Candidate.Rank.Variable &&
           value(Assignment->getRHS()) == Candidate.Child;
  }

  const Expr *strictHalfBound(const Expr *Condition,
                              const Progress &Rank) const {
    Condition = ignore(Condition);
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(Condition);
    if (!Comparison)
      return nullptr;
    if (Comparison->getOpcode() == BO_LAnd) {
      if (const Expr *Bound = strictHalfBound(Comparison->getLHS(), Rank))
        return Bound;
      return strictHalfBound(Comparison->getRHS(), Rank);
    }
    const Expr *Half = nullptr;
    if (Comparison->getOpcode() == BO_LT &&
        rankAccess(Comparison->getLHS(), Rank))
      Half = Comparison->getRHS();
    else if (Comparison->getOpcode() == BO_GT &&
             rankAccess(Comparison->getRHS(), Rank))
      Half = Comparison->getLHS();
    const auto *Division =
        dyn_cast_or_null<BinaryOperator>(ignore(Half));
    const auto *Divisor = Division
        ? dyn_cast_or_null<IntegerLiteral>(ignore(Division->getRHS()))
        : nullptr;
    if (!Division || Division->getOpcode() != BO_Div || !Divisor ||
        Divisor->getValue() != 2)
      return nullptr;
    QualType RankType = Rank.Variable->getType().getCanonicalType()
                            .getUnqualifiedType();
    if (Comparison->getLHS()->getType().getCanonicalType()
            .getUnqualifiedType() != RankType ||
        Comparison->getRHS()->getType().getCanonicalType()
            .getUnqualifiedType() != RankType ||
        Division->getType().getCanonicalType().getUnqualifiedType() !=
            RankType ||
        Division->getLHS()->getType().getCanonicalType()
                .getUnqualifiedType() != RankType)
      return nullptr;
    return Division->getLHS();
  }

  static bool derivedPlusOne(const Expr *Expression,
                             const DerivedAffine &Candidate) {
    const auto *Addition =
        dyn_cast_or_null<BinaryOperator>(ignore(Expression));
    return Addition && Addition->getOpcode() == BO_Add &&
           ((value(Addition->getLHS()) == Candidate.Child &&
             unitInteger(Addition->getRHS())) ||
            (value(Addition->getRHS()) == Candidate.Child &&
             unitInteger(Addition->getLHS())));
  }

  bool guardedDerivedIncrement(const Expr *Condition,
                               const DerivedAffine &Candidate,
                               const ValueDecl *Bound) const {
    Condition = ignore(Condition);
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(Condition);
    if (!Comparison)
      return false;
    if (Comparison->getOpcode() == BO_LAnd)
      return guardedDerivedIncrement(Comparison->getLHS(), Candidate, Bound) ||
             guardedDerivedIncrement(Comparison->getRHS(), Candidate, Bound);
    const Expr *Addition = nullptr;
    const Expr *Upper = nullptr;
    if (Comparison->getOpcode() == BO_LT) {
      Addition = Comparison->getLHS();
      Upper = Comparison->getRHS();
    } else if (Comparison->getOpcode() == BO_GT) {
      Addition = Comparison->getRHS();
      Upper = Comparison->getLHS();
    } else {
      return false;
    }
    QualType RankType = Candidate.Rank.Variable->getType().getCanonicalType()
                            .getUnqualifiedType();
    return value(Upper) == Bound && derivedPlusOne(Addition, Candidate) &&
           Addition->getType().getCanonicalType().getUnqualifiedType() ==
               RankType &&
           Upper->getType().getCanonicalType().getUnqualifiedType() ==
               RankType;
  }

  struct DerivedFlow {
    /* Stages are empty, initialized, initialized+unit, done, unit-only,
     * and commit-only.  The latter two retain invalid branch order until
     * sequence composition can reject it. */
    unsigned FallStages;
    unsigned BackStages;
    bool Exits;
    bool Invalid;
  };

  static unsigned combineDerivedStages(unsigned First, unsigned Second,
                                       bool &Invalid) {
    unsigned Result = 0;
    for (unsigned A = 0; A != 6; ++A)
      if (First & (1u << A))
        for (unsigned B = 0; B != 6; ++B)
          if (Second & (1u << B)) {
            unsigned Combined;
            if (A == 0)
              Combined = B;
            else if (B == 0)
              Combined = A;
            else if (A == 1 && B == 4)
              Combined = 2;
            else if ((A == 1 || A == 2) && B == 5)
              Combined = 3;
            else {
              Invalid = true;
              continue;
            }
            Result |= 1u << Combined;
          }
    return Result;
  }

  static DerivedFlow derivedSequence(DerivedFlow First,
                                     DerivedFlow Second) {
    if (First.Invalid || Second.Invalid)
      return {0, 0, false, true};
    bool Invalid = false;
    unsigned Fall = combineDerivedStages(First.FallStages,
                                         Second.FallStages, Invalid);
    unsigned Back = First.BackStages |
        combineDerivedStages(First.FallStages, Second.BackStages, Invalid);
    return {Fall, Back, First.Exits ||
                              (First.FallStages && Second.Exits),
            Invalid};
  }

  DerivedFlow derivedFlow(const Stmt *Statement,
                          const DerivedAffine &Candidate,
                          const ValueDecl *Bound,
                          bool GuardedUnitAllowed = false) const {
    if (!Statement)
      return {1u, 0, false, false};
    if (containsAsm(Statement) ||
        containsUnevaluatedOrEmbeddedControl(Statement))
      return {0, 0, false, true};
    if (const auto *Compound = dyn_cast<CompoundStmt>(Statement)) {
      DerivedFlow Result{1u, 0, false, false};
      for (const Stmt *Child : Compound->body())
        Result = derivedSequence(
            Result,
            derivedFlow(Child, Candidate, Bound, GuardedUnitAllowed));
      return Result;
    }
    if (const auto *If = dyn_cast<IfStmt>(Statement)) {
      if (writesVariable(If->getCond(), Candidate.Rank.Variable) ||
          writesVariable(If->getCond(), Candidate.Child) ||
          writesVariable(If->getCond(), Bound))
        return {0, 0, false, true};
      DerivedFlow Prefix = derivedSequence(
          derivedFlow(If->getInit(), Candidate, Bound, GuardedUnitAllowed),
          derivedFlow(If->getConditionVariableDeclStmt(), Candidate, Bound,
                      GuardedUnitAllowed));
      bool ThenAllowsUnit = GuardedUnitAllowed ||
          guardedDerivedIncrement(If->getCond(), Candidate, Bound);
      DerivedFlow Then =
          derivedFlow(If->getThen(), Candidate, Bound, ThenAllowsUnit);
      DerivedFlow Else =
          derivedFlow(If->getElse(), Candidate, Bound, GuardedUnitAllowed);
      DerivedFlow Arms{Then.FallStages | Else.FallStages,
                       Then.BackStages | Else.BackStages,
                       Then.Exits || Else.Exits,
                       Then.Invalid || Else.Invalid};
      return derivedSequence(Prefix, Arms);
    }
    if (const auto *Label = dyn_cast<LabelStmt>(Statement))
      return derivedFlow(Label->getSubStmt(), Candidate, Bound,
                         GuardedUnitAllowed);
    if (isa<ContinueStmt>(Statement))
      return {0, 1u, false, false};
    if (isa<BreakStmt>(Statement) || isa<ReturnStmt>(Statement))
      return {0, 0, true, false};
    if (isa<GotoStmt>(Statement) || isa<SwitchStmt>(Statement))
      return {0, 0, false, true};
    if (isa<ForStmt>(Statement) || isa<WhileStmt>(Statement) ||
        isa<DoStmt>(Statement))
      return writesVariable(Statement, Candidate.Rank.Variable) ||
                     writesVariable(Statement, Candidate.Child) ||
                     writesVariable(Statement, Bound)
                 ? DerivedFlow{0, 0, false, true}
                 : DerivedFlow{1u, 0, false, false};
    if (const auto *Expression = dyn_cast<Expr>(Statement)) {
      if (initializesDerivedChild(Expression, Candidate))
        return {1u << 1, 0, false, false};
      if (commitsDerivedChild(Expression, Candidate))
        return {1u << 5, 0, false, false};
      if (std::optional<Progress> Change = progress(Expression))
        if (Change->Variable == Candidate.Child &&
            Change->Kind == ProgressKind::Up && Change->UnitStep)
          return GuardedUnitAllowed
                     ? DerivedFlow{1u << 4, 0, false, false}
                     : DerivedFlow{0, 0, false, true};
    }
    return writesVariable(Statement, Candidate.Rank.Variable) ||
                   writesVariable(Statement, Candidate.Child) ||
                   writesVariable(Statement, Bound)
               ? DerivedFlow{0, 0, false, true}
               : DerivedFlow{1u, 0, false, false};
  }

  bool pretestedBody(const Stmt *Body) const {
    if (!Body)
      return false;
    DynTypedNodeList Parents = Context.getParents(*Body);
    return Parents.size() == 1 && !Parents[0].get<DoStmt>();
  }

  bool guardedDerivedAffineAscent(const Expr *Condition, const Stmt *Body,
                                  const Expr *Increment,
                                  const DerivedAffine &Candidate) const {
    const auto *Rank = dyn_cast<VarDecl>(Candidate.Rank.Variable);
    if (!Rank || Increment || !pretestedBody(Body) || !Current ||
        Rank->getType().isVolatileQualified() ||
        Candidate.Child->getType().isVolatileQualified() ||
        !(isa<ParmVarDecl>(Rank) || Rank->hasLocalStorage()) ||
        !Candidate.Child->hasLocalStorage() ||
        containsStateMutation(Condition) ||
        addressTaken(Current->getBody(), Rank) ||
        addressTaken(Current->getBody(), Candidate.Child) ||
        !validRankVariable(Candidate.Rank, Body))
      return false;
    const Expr *BoundExpression = strictHalfBound(Condition, Candidate.Rank);
    const auto *Bound = dyn_cast_or_null<VarDecl>(value(BoundExpression));
    if (!Bound || Bound == Rank || Bound == Candidate.Child ||
        !Bound->getType()->isUnsignedIntegerType() ||
        Bound->getType().getCanonicalType().getUnqualifiedType() !=
            Rank->getType().getCanonicalType().getUnqualifiedType() ||
        Bound->getType().isVolatileQualified() ||
        !(isa<ParmVarDecl>(Bound) || Bound->hasLocalStorage()) ||
        addressTaken(Current->getBody(), Bound) ||
        !stableBound(BoundExpression, Body, nullptr))
      return false;
    DerivedFlow Result = derivedFlow(Body, Candidate, Bound);
    unsigned BackedgeStages = Result.FallStages | Result.BackStages;
    return !Result.Invalid && (BackedgeStages || Result.Exits) &&
           !(BackedgeStages & ~(1u << 3));
  }

  static bool sentinelRead(const Stmt *Statement, const Progress &Rank) {
    if (!Statement)
      return false;
    if (const auto *Unary = dyn_cast<UnaryOperator>(Statement)) {
      if (Unary->getOpcode() == UO_Deref &&
          basedOn(Unary->getSubExpr(), Rank))
        return true;
    }
    if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(Statement)) {
      if (basedOn(Subscript->getBase(), Rank) ||
          basedOn(Subscript->getIdx(), Rank))
        return true;
    }
    if (const auto *Member = dyn_cast<MemberExpr>(Statement)) {
      if (Member->isArrow() && basedOn(Member->getBase(), Rank))
        return true;
    }
    for (const Stmt *Child : Statement->children())
      if (sentinelRead(Child, Rank))
        return true;
    return false;
  }

  bool sentinelDomainCannotCycle(const Progress &Rank) const {
    QualType Type = Rank.Variable->getType();
    if (Type->isPointerType() || Type->isSignedIntegerType())
      return true;
    if (!Type->isUnsignedIntegerType())
      return false;
    /* A dereference does not itself keep an unsigned index from wrapping.
     * Finite-object reasoning supplies a rank only when the index domain is
     * at least as wide as size_t: then every representable object runs out
     * of valid element offsets before the induction value can cycle.  A
     * narrower index needs an independently proved strict scalar bound;
     * strictComparison() is tried before this sentinel fallback. */
    llvm::APSInt ObjectExtentMaximum = llvm::APSInt::getMaxValue(
        Context.getIntWidth(Context.getSizeType()), true);
    return maximumFitsRank(ObjectExtentMaximum, Rank.Variable, true);
  }

  bool comparisonExcludesZero(BinaryOperatorKind Opcode,
                              const Expr *RankExpression,
                              const Expr *Bound, bool Truth) const {
    if (!BinaryOperator::isComparisonOp(Opcode) ||
        !RankExpression->getType()->isIntegerType())
      return false;
    Expr::EvalResult BoundValue;
    if (!Bound->EvaluateAsInt(BoundValue, Context))
      return false;
    llvm::APSInt Zero(
        llvm::APInt::getZero(Context.getIntWidth(RankExpression->getType())),
        RankExpression->getType()->isUnsignedIntegerOrEnumerationType());
    int Comparison = llvm::APSInt::compareValues(Zero,
                                                  BoundValue.Val.getInt());
    bool ZeroSatisfies;
    switch (Opcode) {
    case BO_EQ: ZeroSatisfies = Comparison == 0; break;
    case BO_NE: ZeroSatisfies = Comparison != 0; break;
    case BO_LT: ZeroSatisfies = Comparison < 0; break;
    case BO_LE: ZeroSatisfies = Comparison <= 0; break;
    case BO_GT: ZeroSatisfies = Comparison > 0; break;
    case BO_GE: ZeroSatisfies = Comparison >= 0; break;
    default: return false;
    }
    return ZeroSatisfies != Truth;
  }

  bool rankNonzeroWhen(const Expr *Condition, const Progress &Rank,
                       bool Truth) const {
    Condition = ignore(Condition);
    if (!Condition)
      return false;
    if (rankAccess(Condition, Rank))
      return Truth;
    if (const auto *Unary = dyn_cast<UnaryOperator>(Condition)) {
      if (Unary->getOpcode() == UO_LNot)
        return rankNonzeroWhen(Unary->getSubExpr(), Rank, !Truth);
    }
    const auto *Binary = dyn_cast<BinaryOperator>(Condition);
    if (!Binary)
      return false;
    if (Binary->getOpcode() == BO_LAnd) {
      if (Truth)
        return rankNonzeroWhen(Binary->getLHS(), Rank, true) ||
               rankNonzeroWhen(Binary->getRHS(), Rank, true);
      return rankNonzeroWhen(Binary->getLHS(), Rank, false) &&
             rankNonzeroWhen(Binary->getRHS(), Rank, false);
    }
    if (Binary->getOpcode() == BO_LOr) {
      if (Truth)
        return rankNonzeroWhen(Binary->getLHS(), Rank, true) &&
               rankNonzeroWhen(Binary->getRHS(), Rank, true);
      return rankNonzeroWhen(Binary->getLHS(), Rank, false) ||
             rankNonzeroWhen(Binary->getRHS(), Rank, false);
    }
    bool RankLeft = rankAccess(Binary->getLHS(), Rank);
    bool RankRight = rankAccess(Binary->getRHS(), Rank);
    if (!RankLeft && !RankRight)
      return false;
    if (RankLeft)
      return comparisonExcludesZero(Binary->getOpcode(), Binary->getLHS(),
                                    Binary->getRHS(), Truth);
    return comparisonExcludesZero(
        BinaryOperator::reverseComparisonOp(Binary->getOpcode()),
        Binary->getRHS(), Binary->getLHS(), Truth);
  }

  static bool exitsBeforeBackedge(const Stmt *Statement) {
    CallFlow Result = callFlow(Statement);
    return !Result.Invalid && Result.Outcomes != 0 &&
           !(Result.Outcomes &
             (FallWithoutCall | FallWithCall |
              BackWithoutCall | BackWithCall));
  }

  enum DescentFact : unsigned {
    StepNonnegative = 1,
    StepNonzero = 2,
    StepPositive = 4,
    StepAtMostRank = 8,
  };

  static bool sameScalarAccess(const Expr *Left, const Expr *Right) {
    Left = ignore(Left);
    Right = ignore(Right);
    const auto *LeftMember = dyn_cast_or_null<MemberExpr>(Left);
    const auto *RightMember = dyn_cast_or_null<MemberExpr>(Right);
    if (LeftMember || RightMember)
      return LeftMember && RightMember &&
             LeftMember->getMemberDecl() == RightMember->getMemberDecl() &&
             value(LeftMember->getBase()) == value(RightMember->getBase());
    return value(Left) && value(Left) == value(Right);
  }

  static const Expr *strictAscentBound(const Expr *Condition,
                                       const Progress &Rank) {
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(
        ignore(Condition));
    if (!Comparison)
      return nullptr;
    if (Comparison->getOpcode() == BO_LT &&
        rankAccess(Comparison->getLHS(), Rank))
      return Comparison->getRHS();
    if (Comparison->getOpcode() == BO_GT &&
        rankAccess(Comparison->getRHS(), Rank))
      return Comparison->getLHS();
    return nullptr;
  }

  static bool distanceFromRank(const Expr *Expression, const Expr *Bound,
                               const Progress &Rank) {
    const auto *Difference = dyn_cast_or_null<BinaryOperator>(
        ignore(Expression));
    return Difference && Difference->getOpcode() == BO_Sub &&
           sameScalarAccess(Difference->getLHS(), Bound) &&
           rankAccess(Difference->getRHS(), Rank);
  }

  static unsigned distanceFacts(const Expr *Condition, bool Truth,
                                const Expr *Bound, const Progress &Rank,
                                const ValueDecl *Step) {
    Condition = ignore(Condition);
    if (!Condition)
      return 0;
    if (const auto *Unary = dyn_cast<UnaryOperator>(Condition))
      if (Unary->getOpcode() == UO_LNot)
        return distanceFacts(Unary->getSubExpr(), !Truth, Bound, Rank, Step);
    const auto *Binary = dyn_cast<BinaryOperator>(Condition);
    if (!Binary)
      return 0;
    if (Binary->getOpcode() == BO_LAnd) {
      unsigned Left = distanceFacts(Binary->getLHS(), Truth, Bound,
                                    Rank, Step);
      unsigned Right = distanceFacts(Binary->getRHS(), Truth, Bound,
                                     Rank, Step);
      return Truth ? Left | Right : Left & Right;
    }
    if (Binary->getOpcode() == BO_LOr) {
      unsigned Left = distanceFacts(Binary->getLHS(), Truth, Bound,
                                    Rank, Step);
      unsigned Right = distanceFacts(Binary->getRHS(), Truth, Bound,
                                     Rank, Step);
      return Truth ? Left & Right : Left | Right;
    }
    bool StepLeft = integerSource(Binary->getLHS()) == Step;
    bool StepRight = integerSource(Binary->getRHS()) == Step;
    if (StepLeft && distanceFromRank(Binary->getRHS(), Bound, Rank)) {
      if ((Truth && (Binary->getOpcode() == BO_LT ||
                     Binary->getOpcode() == BO_LE)) ||
          (!Truth && (Binary->getOpcode() == BO_GT ||
                      Binary->getOpcode() == BO_GE)))
        return StepAtMostRank;
    } else if (StepRight &&
               distanceFromRank(Binary->getLHS(), Bound, Rank)) {
      if ((Truth && (Binary->getOpcode() == BO_GT ||
                     Binary->getOpcode() == BO_GE)) ||
          (!Truth && (Binary->getOpcode() == BO_LT ||
                      Binary->getOpcode() == BO_LE)))
        return StepAtMostRank;
    }
    return 0;
  }

  static unsigned descentFacts(const Expr *Condition, bool Truth,
                               const Progress &Rank,
                               const ValueDecl *Step) {
    Condition = ignore(Condition);
    if (!Condition)
      return 0;
    if (integerSource(Condition) == Step)
      return Truth ? StepNonzero : 0;
    if (const auto *Unary = dyn_cast<UnaryOperator>(Condition))
      if (Unary->getOpcode() == UO_LNot)
        return descentFacts(Unary->getSubExpr(), !Truth, Rank, Step);
    const auto *Binary = dyn_cast<BinaryOperator>(Condition);
    if (!Binary)
      return 0;
    if (Binary->getOpcode() == BO_LAnd) {
      unsigned Left = descentFacts(Binary->getLHS(), Truth, Rank, Step);
      unsigned Right = descentFacts(Binary->getRHS(), Truth, Rank, Step);
      return Truth ? Left | Right : Left & Right;
    }
    if (Binary->getOpcode() == BO_LOr) {
      unsigned Left = descentFacts(Binary->getLHS(), Truth, Rank, Step);
      unsigned Right = descentFacts(Binary->getRHS(), Truth, Rank, Step);
      return Truth ? Left & Right : Left | Right;
    }
    bool StepLeft = integerSource(Binary->getLHS()) == Step;
    bool StepRight = integerSource(Binary->getRHS()) == Step;
    bool ZeroLeft = zeroInteger(Binary->getLHS());
    bool ZeroRight = zeroInteger(Binary->getRHS());
    unsigned Facts = 0;
    if (StepLeft && ZeroRight) {
      switch (Binary->getOpcode()) {
      case BO_EQ: if (!Truth) Facts |= StepNonzero; break;
      case BO_NE: if (Truth) Facts |= StepNonzero; break;
      case BO_GT: if (Truth) Facts |= StepPositive; break;
      case BO_GE: if (Truth) Facts |= StepNonnegative; break;
      case BO_LT: if (!Truth) Facts |= StepNonnegative; break;
      case BO_LE: if (!Truth) Facts |= StepPositive; break;
      default: break;
      }
    } else if (StepRight && ZeroLeft) {
      switch (Binary->getOpcode()) {
      case BO_EQ: if (!Truth) Facts |= StepNonzero; break;
      case BO_NE: if (Truth) Facts |= StepNonzero; break;
      case BO_LT: if (Truth) Facts |= StepPositive; break;
      case BO_LE: if (Truth) Facts |= StepNonnegative; break;
      case BO_GT: if (!Truth) Facts |= StepNonnegative; break;
      case BO_GE: if (!Truth) Facts |= StepPositive; break;
      default: break;
      }
    }
    if (StepLeft && rankAccess(Binary->getRHS(), Rank)) {
      if ((Truth && (Binary->getOpcode() == BO_LT ||
                     Binary->getOpcode() == BO_LE)) ||
          (!Truth && (Binary->getOpcode() == BO_GT ||
                      Binary->getOpcode() == BO_GE)))
        Facts |= StepAtMostRank;
    } else if (StepRight && rankAccess(Binary->getLHS(), Rank)) {
      if ((Truth && (Binary->getOpcode() == BO_GT ||
                     Binary->getOpcode() == BO_GE)) ||
          (!Truth && (Binary->getOpcode() == BO_LT ||
                      Binary->getOpcode() == BO_LE)))
        Facts |= StepAtMostRank;
    }
    return Facts;
  }

  bool preservesPositiveValue(const Expr *Expression,
                              const ValueDecl *Source) const {
    Expression = Expression ? Expression->IgnoreParens() : nullptr;
    if (const auto *Cast = dyn_cast_or_null<CastExpr>(Expression)) {
      QualType From = Cast->getSubExpr()->getType();
      QualType To = Cast->getType();
      if (!From->isIntegerType() || !To->isIntegerType())
        return false;
      unsigned FromWidth = Context.getIntWidth(From);
      unsigned ToWidth = Context.getIntWidth(To);
      bool Preserved = To->isUnsignedIntegerType()
                           ? ToWidth >= FromWidth
                           : (From->isSignedIntegerType()
                                  ? ToWidth >= FromWidth
                                  : ToWidth > FromWidth);
      return Preserved &&
             preservesPositiveValue(Cast->getSubExpr(), Source);
    }
    return value(Expression) == Source;
  }

  bool samePositiveIntegerConstant(const Expr *Left,
                                   const Expr *Right,
                                   QualType RankType) const {
    if (!Left || !Right || !Left->getType()->isIntegerType() ||
        !Right->getType()->isIntegerType())
      return false;
    Expr::EvalResult LeftValue;
    Expr::EvalResult RightValue;
    if (!Left->EvaluateAsInt(LeftValue, Context) ||
        !Right->EvaluateAsInt(RightValue, Context) ||
        !LeftValue.Val.getInt().isStrictlyPositive())
      return false;
    llvm::APSInt Maximum = llvm::APSInt::getMaxValue(
        Context.getIntWidth(RankType), true);
    return llvm::APSInt::compareValues(LeftValue.Val.getInt(),
                                       RightValue.Val.getInt()) == 0 &&
           llvm::APSInt::compareValues(LeftValue.Val.getInt(), Maximum) <= 0;
  }

  bool clampedStepInitializer(const VarDecl *Step,
                              const Progress &Rank) const {
    if (!Step->getInit() || containsCall(Step->getInit()) ||
        !Rank.Variable->getType()->isUnsignedIntegerType() ||
        Step->getType().getCanonicalType().getUnqualifiedType() !=
            Rank.Variable->getType().getCanonicalType().getUnqualifiedType())
      return false;
    const auto *Choice =
        dyn_cast_or_null<ConditionalOperator>(ignore(Step->getInit()));
    QualType ChoiceType = Choice ? Choice->getType() : QualType();
    if (!Choice || !ChoiceType->isUnsignedIntegerType() ||
        Context.getIntWidth(ChoiceType) <
            Context.getIntWidth(Rank.Variable->getType()))
      return false;
    const auto *Comparison =
        dyn_cast_or_null<BinaryOperator>(ignore(Choice->getCond()));
    if (!Comparison || !BinaryOperator::isComparisonOp(
                           Comparison->getOpcode()))
      return false;

    const Expr *ConstantArm = nullptr;
    const Expr *ConstantBound = nullptr;
    bool RankWhenTrue = false;
    bool RankLeft = rankAccess(Comparison->getLHS(), Rank);
    bool RankRight = rankAccess(Comparison->getRHS(), Rank);
    if (rankAccess(Choice->getTrueExpr(), Rank)) {
      ConstantArm = Choice->getFalseExpr();
      RankWhenTrue = true;
    } else if (rankAccess(Choice->getFalseExpr(), Rank)) {
      ConstantArm = Choice->getTrueExpr();
    } else {
      return false;
    }
    BinaryOperatorKind Opcode = Comparison->getOpcode();
    if (RankWhenTrue && RankLeft &&
        (Opcode == BO_LT || Opcode == BO_LE))
      ConstantBound = Comparison->getRHS();
    else if (RankWhenTrue && RankRight &&
             (Opcode == BO_GT || Opcode == BO_GE))
      ConstantBound = Comparison->getLHS();
    else if (!RankWhenTrue && RankLeft &&
             (Opcode == BO_GT || Opcode == BO_GE))
      ConstantBound = Comparison->getRHS();
    else if (!RankWhenTrue && RankRight &&
             (Opcode == BO_LT || Opcode == BO_LE))
      ConstantBound = Comparison->getLHS();
    else
      return false;
    return samePositiveIntegerConstant(ConstantArm, ConstantBound,
                                       Rank.Variable->getType());
  }

  bool bodyHasGuardedDynamicDescent(const Expr *Condition, const Stmt *Body,
                                    const Progress &Rank) const {
    const auto *Step = dyn_cast_or_null<VarDecl>(Rank.DynamicStep);
    const auto *RankVariable = dyn_cast_or_null<VarDecl>(Rank.Variable);
    const auto *Compound = dyn_cast_or_null<CompoundStmt>(Body);
    if (!Step || !RankVariable || !Compound ||
        Step->getType().isVolatileQualified() ||
        !(isa<ParmVarDecl>(Step) || Step->hasLocalStorage()) ||
        !(isa<ParmVarDecl>(RankVariable) || RankVariable->hasLocalStorage()) ||
        addressTaken(Current->getBody(), Step) ||
        addressTaken(Current->getBody(), RankVariable) ||
        writesVariable(Body, Step) || aliasedWrite(Step, Body))
      return false;
    QualType RankType = RankVariable->getType().getCanonicalType()
                            .getUnqualifiedType();
    QualType StepExpressionType = Rank.GuardedStep->getType()
                                      .getCanonicalType()
                                      .getUnqualifiedType();
    if (RankType != StepExpressionType ||
        !preservesPositiveValue(Rank.GuardedStep, Step))
      return false;
    bool Defined = false;
    unsigned Facts = 0;
    for (const Stmt *Child : Compound->body()) {
      if (const auto *Declaration = dyn_cast<DeclStmt>(Child)) {
        for (const Decl *Item : Declaration->decls())
          if (Item == Step) {
            if (!Step->getInit())
              return false;
            Defined = true;
            Facts = clampedStepInitializer(Step, Rank) &&
                            rankNonzeroWhen(Condition, Rank, true)
                        ? StepPositive | StepAtMostRank
                        : 0;
          }
        continue;
      }
      if (!Defined)
        continue;
      if (const auto *Guard = dyn_cast<IfStmt>(Child)) {
        if (Guard->getInit() || Guard->getConditionVariableDeclStmt())
          return false;
        /* A call in a later condition cannot modify either unescaped local
         * scalar (checked above).  It may fail to return, but if it does
         * return the initializer's clamp facts remain true.  Such a call
         * cannot establish new facts, so simply skip it here. */
        if (containsCall(Guard->getCond()))
          continue;
        if (exitsBeforeBackedge(Guard->getThen()))
          Facts |= descentFacts(Guard->getCond(), false, Rank, Step);
        else if (Guard->getElse() && exitsBeforeBackedge(Guard->getElse()))
          Facts |= descentFacts(Guard->getCond(), true, Rank, Step);
      }
      if (const auto *Expression = dyn_cast<Expr>(Child)) {
        std::optional<Progress> Change = progress(Expression);
        if (Change && sameRank(*Change, Rank) &&
            Change->DynamicStep == Step) {
          bool Positive = (Facts & StepPositive) ||
              ((Facts & StepNonzero) &&
               (Step->getType()->isUnsignedIntegerType() ||
                (Facts & StepNonnegative)));
          return Positive && (Facts & StepAtMostRank);
        }
      }
    }
    return false;
  }

  bool bodyHasGuardedDynamicAscent(const Expr *Condition, const Stmt *Body,
                                   const Expr *Increment,
                                   const Progress &Rank) const {
    const auto *Step = dyn_cast_or_null<VarDecl>(Rank.DynamicStep);
    const auto *RankVariable = dyn_cast_or_null<VarDecl>(Rank.Variable);
    const auto *Compound = dyn_cast_or_null<CompoundStmt>(Body);
    const Expr *Bound = strictAscentBound(Condition, Rank);
    if (!Step || !RankVariable || !Compound || !Bound ||
        Step->getType().isVolatileQualified() ||
        !(isa<ParmVarDecl>(Step) || Step->hasLocalStorage()) ||
        !(isa<ParmVarDecl>(RankVariable) || RankVariable->hasLocalStorage()) ||
        addressTaken(Current->getBody(), Step) ||
        addressTaken(Current->getBody(), RankVariable) ||
        writesVariable(Body, Step) || aliasedWrite(Step, Body) ||
        !stableBound(Bound, Body, Increment))
      return false;
    QualType RankType = RankVariable->getType().getCanonicalType()
                            .getUnqualifiedType();
    QualType BoundType = Bound->getType().getCanonicalType()
                             .getUnqualifiedType();
    QualType StepExpressionType = Rank.GuardedStep->getType()
                                      .getCanonicalType()
                                      .getUnqualifiedType();
    if (RankType != BoundType || RankType != StepExpressionType ||
        !preservesPositiveValue(Rank.GuardedStep, Step))
      return false;
    bool Defined = false;
    unsigned Facts = 0;
    for (const Stmt *Child : Compound->body()) {
      if (const auto *Declaration = dyn_cast<DeclStmt>(Child)) {
        for (const Decl *Item : Declaration->decls())
          if (Item == Step) {
            if (!Step->getInit())
              return false;
            Defined = true;
            Facts = 0;
          }
        continue;
      }
      if (!Defined)
        continue;
      if (const auto *Guard = dyn_cast<IfStmt>(Child)) {
        if (Guard->getInit() || Guard->getConditionVariableDeclStmt() ||
            containsCall(Guard->getCond()))
          return false;
        bool ContinuingTruth;
        if (exitsBeforeBackedge(Guard->getThen()))
          ContinuingTruth = false;
        else if (Guard->getElse() &&
                 exitsBeforeBackedge(Guard->getElse()))
          ContinuingTruth = true;
        else
          continue;
        Facts |= descentFacts(Guard->getCond(), ContinuingTruth,
                              Rank, Step);
        Facts |= distanceFacts(Guard->getCond(), ContinuingTruth,
                               Bound, Rank, Step);
      }
      if (const auto *Expression = dyn_cast<Expr>(Child)) {
        std::optional<Progress> Change = progress(Expression);
        if (Change && sameRank(*Change, Rank) &&
            Change->Kind == ProgressKind::Up &&
            Change->DynamicStep == Step) {
          bool Positive = (Facts & StepPositive) ||
              ((Facts & StepNonzero) &&
               (Step->getType()->isUnsignedIntegerType() ||
                (Facts & StepNonnegative)));
          return Positive && (Facts & StepAtMostRank);
        }
      }
    }
    return false;
  }

  bool bodyHasGuardedDynamicPointerProgress(const Stmt *Body,
                                            const Progress &Rank) const {
    const auto *Step = dyn_cast_or_null<VarDecl>(Rank.DynamicStep);
    const auto *RankVariable = dyn_cast_or_null<VarDecl>(Rank.Variable);
    const auto *Compound = dyn_cast_or_null<CompoundStmt>(Body);
    if (!Step || !RankVariable || !Compound ||
        !RankVariable->getType()->isPointerType() ||
        !Step->getType()->isUnsignedIntegerType() ||
        Step->getType().isVolatileQualified() ||
        !(isa<ParmVarDecl>(Step) || Step->hasLocalStorage()) ||
        !(isa<ParmVarDecl>(RankVariable) || RankVariable->hasLocalStorage()) ||
        addressTaken(Current->getBody(), Step) ||
        addressTaken(Current->getBody(), RankVariable) ||
        writesVariable(Body, Step) || aliasedWrite(Step, Body) ||
        !Rank.GuardedStep ||
        !preservesPositiveValue(Rank.GuardedStep, Step))
      return false;
    bool Defined = false;
    unsigned Facts = 0;
    for (const Stmt *Child : Compound->body()) {
      if (const auto *Declaration = dyn_cast<DeclStmt>(Child)) {
        for (const Decl *Item : Declaration->decls())
          if (Item == Step) {
            if (!Step->getInit())
              return false;
            Defined = true;
            Facts = 0;
          }
        continue;
      }
      if (!Defined)
        continue;
      if (const auto *Guard = dyn_cast<IfStmt>(Child)) {
        if (Guard->getInit() || Guard->getConditionVariableDeclStmt() ||
            containsCall(Guard->getCond()))
          return false;
        if (exitsBeforeBackedge(Guard->getThen()))
          Facts |= descentFacts(Guard->getCond(), false, Rank, Step);
        else if (Guard->getElse() && exitsBeforeBackedge(Guard->getElse()))
          Facts |= descentFacts(Guard->getCond(), true, Rank, Step);
      }
      if (const auto *Expression = dyn_cast<Expr>(Child)) {
        std::optional<Progress> Change = progress(Expression);
        if (Change && sameRank(*Change, Rank) &&
            Change->Kind == Rank.Kind && Change->DynamicStep == Step)
          return (Facts & StepNonzero) != 0;
      }
    }
    return false;
  }

  bool bodyHasDominatingNonzeroGuard(const Stmt *Body,
                                     const Progress &Rank) const {
    const auto *Compound = dyn_cast_or_null<CompoundStmt>(Body);
    if (!Compound)
      return false;
    for (const Stmt *Child : Compound->body()) {
      if (const auto *Guard = dyn_cast<IfStmt>(Child)) {
        if (Guard->getInit() || Guard->getConditionVariableDeclStmt() ||
            containsCall(Guard->getCond()) ||
            mutation(Guard->getCond(), Rank) != Mutation::None)
          return false;
        if (exitsBeforeBackedge(Guard->getThen()) &&
            rankNonzeroWhen(Guard->getCond(), Rank, false))
          return true;
        return Guard->getElse() && exitsBeforeBackedge(Guard->getElse()) &&
               rankNonzeroWhen(Guard->getCond(), Rank, true);
      }
      /* Only straight-line, call-free, rank-preserving declarations or
       * expressions may precede the guard.  In particular a decrement,
       * conditional bypass, continue, or goto prevents domination. */
      Flow Prefix = flow(Child, Rank);
      if (containsCall(Child) || Prefix.Invalid ||
          Prefix.Outcomes != FallWithoutProgress)
        return false;
    }
    return false;
  }

  bool sentinelCondition(const Expr *Condition, const Progress &Change) const {
    Condition = ignore(Condition);
    if (mutation(Condition, Change) != Mutation::None ||
        (isa<FieldDecl>(Change.Variable) &&
         mentionsFieldThroughOtherBase(Condition, Change)))
      return false;
    if (Change.RequiresNonzeroCondition)
      return rankNonzeroWhen(Condition, Change, true);
    if (const auto *Logical = dyn_cast_or_null<BinaryOperator>(Condition)) {
      if (Logical->getOpcode() == BO_LAnd)
        return sentinelCondition(Logical->getLHS(), Change) ||
               sentinelCondition(Logical->getRHS(), Change);
      if (Logical->getOpcode() == BO_LOr)
        return sentinelCondition(Logical->getLHS(), Change) &&
               sentinelCondition(Logical->getRHS(), Change);
    }
    /* A nonzero integer condition paired with a strict integer descent is
     * a scalar rank for both unsigned and signed values.  For signed
     * subtraction from a negative value, the only alternative to reaching
     * zero is signed overflow, so no infinite *defined* C execution is
     * admitted.  nonzeroWhen() also handles `n != 0` and conjunctions while
     * deliberately requiring both arms of a disjunction to imply nonzero. */
    bool SentinelSafeStep = !Change.GuardedStep ||
        (Change.Variable->getType()->isPointerType() &&
         Change.DynamicStep && admissibleProgress(Change));
    if (SentinelSafeStep && Change.Kind == ProgressKind::Down &&
        Change.Variable->getType()->isIntegerType() &&
        rankNonzeroWhen(Condition, Change, true))
      return true;
    /* A load through the induction variable supplies an object-distance
     * rank only when that induction domain cannot cycle before exhausting
     * the object.  Pointer and signed overflow leave defined C execution;
     * sufficiently wide unsigned indices exhaust every possible object.
     * Narrow unsigned indices require the explicit scalar bound handled
     * above, because their modular arithmetic can revisit the same bytes. */
    return SentinelSafeStep && sentinelDomainCannotCycle(Change) &&
           sentinelRead(Condition, Change);
  }

  static bool constantFalse(const Expr *Condition, ASTContext &Context) {
    if (!Condition)
      return false;
    Expr::EvalResult Result;
    return Condition->EvaluateAsInt(Result, Context) &&
           Result.Val.getInt().isZero();
  }

  static std::optional<Progress> conditionCountdown(const Expr *Condition) {
    Condition = ignore(Condition);
    auto Decremented = [](const Expr *Expression)
        -> std::optional<Progress> {
      const auto *Unary = dyn_cast_or_null<UnaryOperator>(ignore(Expression));
      if (!Unary || !Unary->isDecrementOp())
        return std::nullopt;
      const ValueDecl *Variable = value(Unary->getSubExpr());
      if (!Variable)
        return std::nullopt;
      const auto *Member = dyn_cast_or_null<MemberExpr>(
          ignore(Unary->getSubExpr()));
      const ValueDecl *Base = Member ? value(Member->getBase()) : nullptr;
      return makeProgress(Variable, ProgressKind::Down, Base,
                          Unary->getSubExpr(), nullptr, false, true);
    };
    if (std::optional<Progress> Change = Decremented(Condition))
      return Change;
    const auto *Comparison = dyn_cast_or_null<BinaryOperator>(Condition);
    if (!Comparison)
      return std::nullopt;
    std::optional<Progress> Left = Decremented(Comparison->getLHS());
    std::optional<Progress> Right = Decremented(Comparison->getRHS());
    if (Left && zeroInteger(Comparison->getRHS()) &&
        (Comparison->getOpcode() == BO_GT ||
         Comparison->getOpcode() == BO_NE))
      return Left;
    if (Right && zeroInteger(Comparison->getLHS()) &&
        (Comparison->getOpcode() == BO_LT ||
         Comparison->getOpcode() == BO_NE))
      return Right;
    return std::nullopt;
  }

  struct SMTPathStep {
    const Stmt *Statement = nullptr;
    const Expr *Condition = nullptr;
    bool Truth = false;
  };

  /* Exact paths are ready for a literal transition consumer.  Havoced paths
   * deliberately quantify an unsupported value and remain a sound
   * over-approximation for UNSAT proofs.  Unsupported paths contain an effect
   * whose state has no representation yet and must not be consumed by a
   * general transition solver. */
  enum class TransitionSupport {
    Exact,
    Havoced,
    Unsupported,
  };

  struct SMTPath {
    std::vector<SMTPathStep> Steps;
    const CFGBlock *BackedgeSource = nullptr;
    const CFGBlock *Header = nullptr;
    TransitionSupport Support = TransitionSupport::Exact;
  };

  /* A header-to-header CFG path represented independently of the current
   * strict-rank query.  All paths in a candidate share a Z3 context, and thus
   * share the same pre/post symbols.  Per-iteration temporaries and havoced
   * values are existentially bound rather than silently becoming stable
   * header state. */
  class TransitionIR {
  public:
    struct StateSlot {
      std::string Identity;
      z3::expr Before;
      z3::expr After;
    };

  private:
    ASTContext &AST;
    z3::context &Z;
    z3::solver Solver;
    std::map<const ValueDecl *, z3::expr> Values;
    std::map<const ValueDecl *, z3::expr> InitialValues;
    std::set<const ValueDecl *> StateDeclarations;
    std::set<const ValueDecl *> TransientDeclarations;
    std::vector<StateSlot> State;
    std::vector<z3::expr> DomainFacts;
    std::vector<z3::expr> EntryFacts;
    std::vector<z3::expr> PathFacts;
    std::vector<z3::expr> PostFacts;
    std::vector<z3::expr> Definedness;
    std::vector<z3::expr> Existentials;
    const CFGBlock *BackedgeSource = nullptr;
    const CFGBlock *Header = nullptr;
    TransitionSupport Support = TransitionSupport::Exact;
    unsigned Fresh = 0;
    bool Valid = true;
    bool Finalized = false;

    static std::string decimal(const llvm::APInt &Value, bool Signed) {
      llvm::SmallString<64> Buffer;
      Value.toString(Buffer, 10, Signed);
      return std::string(Buffer);
    }

    z3::expr integer(const llvm::APInt &Value, bool Signed = false) {
      return Z.int_val(decimal(Value, Signed).c_str());
    }

    z3::expr powerOfTwo(unsigned Width) {
      llvm::APInt Value(Width + 1, 1);
      Value <<= Width;
      return integer(Value);
    }

    bool addQueryAssertion(const z3::expr &Assertion) {
      /* Every assertion reaches Z3 through this choke point.  A malformed
       * translation is loss of proof, never a solver assertion or an
       * accidentally strengthened formula. */
      if (!Assertion.is_bool()) {
        Valid = false;
        return false;
      }
      Solver.add(Assertion);
      return true;
    }

    bool addBaseAssertion(const z3::expr &Assertion,
                          std::vector<z3::expr> &Facts) {
      if (!addQueryAssertion(Assertion))
        return false;
      Facts.push_back(Assertion);
      return true;
    }

    bool recordRelationAssertion(const z3::expr &Assertion,
                                 std::vector<z3::expr> &Facts) {
      if (!Assertion.is_bool()) {
        Valid = false;
        return false;
      }
      Facts.push_back(Assertion);
      return true;
    }

    bool integerType(QualType Type) const {
      return !Type.isNull() &&
             (Type->isIntegerType() || Type->isEnumeralType());
    }

    bool signedType(QualType Type) const {
      return Type->isSignedIntegerOrEnumerationType();
    }

    bool addTypeBounds(const z3::expr &Value, QualType Type,
                       bool AddToQuery = true) {
      if (!integerType(Type) || !Value.is_int()) {
        Valid = false;
        return false;
      }
      unsigned Width = AST.getIntWidth(Type);
      z3::expr Limit = powerOfTwo(Width);
      if (signedType(Type)) {
        z3::expr Half = powerOfTwo(Width - 1);
        z3::expr Bounds = Value >= -Half && Value < Half;
        return AddToQuery ? addBaseAssertion(Bounds, DomainFacts)
                          : recordRelationAssertion(Bounds, DomainFacts);
      }
      z3::expr Bounds = Value >= 0 && Value < Limit;
      return AddToQuery ? addBaseAssertion(Bounds, DomainFacts)
                        : recordRelationAssertion(Bounds, DomainFacts);
    }

    std::optional<z3::expr> convert(z3::expr Value, QualType Type,
                                    bool SignedArithmetic = false) {
      if (!integerType(Type) || !Value.is_int()) {
        Valid = false;
        return std::nullopt;
      }
      unsigned Width = AST.getIntWidth(Type);
      z3::expr Limit = powerOfTwo(Width);
      if (!signedType(Type))
        return z3::mod(Value, Limit);
      z3::expr Half = powerOfTwo(Width - 1);
      if (SignedArithmetic) {
        z3::expr Obligation = Value >= -Half && Value < Half;
        if (!Obligation.is_bool()) {
          Valid = false;
          return std::nullopt;
        }
        Definedness.push_back(Obligation);
        return Value;
      }
      z3::expr Bits = z3::mod(Value, Limit);
      return z3::ite(Bits >= Half, Bits - Limit, Bits);
    }

    std::string symbolName(StringRef Prefix, const void *Identity) {
      std::string Result;
      llvm::raw_string_ostream Out(Result);
      Out << Prefix << '_' << reinterpret_cast<uintptr_t>(Identity);
      return Out.str();
    }

    std::optional<z3::expr> scalar(const ValueDecl *Declaration) {
      if (!Declaration || !integerType(Declaration->getType())) {
        Valid = false;
        return std::nullopt;
      }
      /* A FieldDecl's declared type does not encode a bit-field's storage
       * width.  Treating it as the full declared integer type would erase
       * the narrowing performed by every store and can turn a real modular
       * cycle into apparent signed-overflow termination. */
      if (const auto *Field = dyn_cast<FieldDecl>(Declaration);
          Field && Field->isBitField()) {
        Support = TransitionSupport::Unsupported;
        return std::nullopt;
      }
      auto Found = Values.find(Declaration);
      if (Found != Values.end())
        return Found->second;
      z3::expr Symbol =
          Z.int_const(symbolName("v", Declaration).c_str());
      if (!addTypeBounds(Symbol, Declaration->getType()))
        return std::nullopt;
      Values.emplace(Declaration, Symbol);
      InitialValues.emplace(Declaration, Symbol);
      if (!TransientDeclarations.count(Declaration)) {
        StateDeclarations.insert(Declaration);
      } else {
        Existentials.push_back(Symbol);
        if (Support == TransitionSupport::Exact)
          Support = TransitionSupport::Havoced;
      }
      return Symbol;
    }

    std::optional<z3::expr> freshValue(QualType Type, StringRef Prefix) {
      std::string Name = (Prefix + llvm::Twine('_') +
                          llvm::Twine(Fresh++)).str();
      z3::expr Symbol = Z.int_const(Name.c_str());
      if (!addTypeBounds(Symbol, Type))
        return std::nullopt;
      Existentials.push_back(Symbol);
      return Symbol;
    }

    std::optional<z3::expr> call(const CallExpr *Call) {
      if (!integerType(Call->getType())) {
        Valid = false;
        return std::nullopt;
      }
      std::optional<z3::expr> Result = freshValue(Call->getType(), "call");
      if (Result && Support == TransitionSupport::Exact)
        Support = TransitionSupport::Havoced;
      return Result;
    }

  public:
    explicit TransitionIR(ASTContext &AST, z3::context &Z,
                          const SMTPath &Path,
                          const std::set<const ValueDecl *> &Slice)
        : AST(AST), Z(Z), Solver(Z), BackedgeSource(Path.BackedgeSource),
          Header(Path.Header), Support(Path.Support) {
      z3::params Parameters(Z);
      Parameters.set("timeout", 100u);
      Solver.set(Parameters);
      for (const ValueDecl *Declaration : Slice)
        if (!scalar(Declaration))
          break;
    }

    std::optional<z3::expr> expression(const Expr *Expression) {
      if (!Expression) {
        Valid = false;
        return std::nullopt;
      }
      Expression = Expression->IgnoreParens();
      Expr::EvalResult Constant;
      if (Expression->EvaluateAsInt(Constant, AST))
        return integer(Constant.Val.getInt(),
                       !Constant.Val.getInt().isUnsigned());
      if (const auto *Cast = dyn_cast<CastExpr>(Expression)) {
        std::optional<z3::expr> Inner = expression(Cast->getSubExpr());
        if (!Inner)
          return std::nullopt;
        if (Cast->getCastKind() == CK_LValueToRValue ||
            Cast->getCastKind() == CK_NoOp)
          return Inner;
        if (!integerType(Cast->getType())) {
          Valid = false;
          return std::nullopt;
        }
        QualType SourceType = Cast->getSubExpr()->getType();
        if (Cast->getCastKind() == CK_IntegralCast && integerType(SourceType)) {
          unsigned SourceWidth = AST.getIntWidth(SourceType);
          unsigned TargetWidth = AST.getIntWidth(Cast->getType());
          /* Mathematical integers already represent a value-preserving
           * widening conversion.  Avoid introducing a modulo/ite spelling
           * which is equivalent only after type bounds are considered and
           * needlessly obscures repeated finite-state transitions. */
          if (TargetWidth > SourceWidth &&
              (signedType(Cast->getType()) || !signedType(SourceType)))
            return Inner;
        }
        return convert(*Inner, Cast->getType());
      }
      if (const auto *Reference = dyn_cast<DeclRefExpr>(Expression))
        return scalar(dyn_cast<ValueDecl>(Reference->getDecl()));
      if (const auto *Literal = dyn_cast<IntegerLiteral>(Expression))
        return integer(Literal->getValue());
      if (const auto *Character = dyn_cast<CharacterLiteral>(Expression))
        return Z.int_val(Character->getValue());
      if (const auto *Call = dyn_cast<CallExpr>(Expression))
        return call(Call);
      if (const auto *Unary = dyn_cast<UnaryOperator>(Expression)) {
        std::optional<z3::expr> Operand = expression(Unary->getSubExpr());
        if (!Operand)
          return std::nullopt;
        if (Unary->getOpcode() == UO_Plus)
          return Operand;
        if (Unary->getOpcode() == UO_Minus)
          return convert(-*Operand, Unary->getType(),
                         signedType(Unary->getType()));
        if (Unary->getOpcode() == UO_LNot) {
          z3::expr Result = z3::ite(*Operand == 0, Z.int_val(1),
                                    Z.int_val(0));
          return Result;
        }
        Valid = false;
        return std::nullopt;
      }
      const auto *Binary = dyn_cast<BinaryOperator>(Expression);
      if (!Binary || Binary->isAssignmentOp()) {
        Valid = false;
        return std::nullopt;
      }
      if (Binary->getOpcode() == BO_LAnd ||
          Binary->getOpcode() == BO_LOr ||
          Binary->isComparisonOp()) {
        std::optional<z3::expr> Boolean = condition(Binary);
        if (!Boolean)
          return std::nullopt;
        return z3::ite(*Boolean, Z.int_val(1), Z.int_val(0));
      }
      std::optional<z3::expr> Left = expression(Binary->getLHS());
      std::optional<z3::expr> Right = expression(Binary->getRHS());
      if (!Left || !Right)
        return std::nullopt;
      z3::expr Raw = *Left + *Right;
      switch (Binary->getOpcode()) {
      case BO_Add: Raw = *Left + *Right; break;
      case BO_Sub: Raw = *Left - *Right; break;
      case BO_Mul: Raw = *Left * *Right; break;
      default:
        Valid = false;
        return std::nullopt;
      }
      return convert(Raw, Binary->getType(),
                     signedType(Binary->getType()));
    }

    std::optional<z3::expr> condition(const Expr *Condition) {
      if (!Condition) {
        Valid = false;
        return std::nullopt;
      }
      Condition = Condition->IgnoreParenImpCasts();
      if (const auto *Unary = dyn_cast<UnaryOperator>(Condition)) {
        if (Unary->getOpcode() == UO_LNot) {
          std::optional<z3::expr> Inner = condition(Unary->getSubExpr());
          if (!Inner)
            return std::nullopt;
          return !*Inner;
        }
      }
      if (const auto *Binary = dyn_cast<BinaryOperator>(Condition)) {
        if (Binary->getOpcode() == BO_LAnd ||
            Binary->getOpcode() == BO_LOr) {
          std::optional<z3::expr> Left = condition(Binary->getLHS());
          std::optional<z3::expr> Right = condition(Binary->getRHS());
          if (!Left || !Right)
            return std::nullopt;
          return Binary->getOpcode() == BO_LAnd ? *Left && *Right
                                                : *Left || *Right;
        }
        if (Binary->isComparisonOp()) {
          std::optional<z3::expr> Left = expression(Binary->getLHS());
          std::optional<z3::expr> Right = expression(Binary->getRHS());
          if (!Left || !Right)
            return std::nullopt;
          switch (Binary->getOpcode()) {
          case BO_EQ: return *Left == *Right;
          case BO_NE: return *Left != *Right;
          case BO_LT: return *Left < *Right;
          case BO_LE: return *Left <= *Right;
          case BO_GT: return *Left > *Right;
          case BO_GE: return *Left >= *Right;
          default: break;
          }
        }
      }
      std::optional<z3::expr> Value = expression(Condition);
      if (!Value || !Value->is_int()) {
        Valid = false;
        return std::nullopt;
      }
      return *Value != 0;
    }

    bool assertEntryCondition(const Expr *Condition, bool Truth) {
      std::optional<z3::expr> Formula = condition(Condition);
      return Formula && addBaseAssertion(Truth ? *Formula : !*Formula,
                                         EntryFacts);
    }

    bool assertPathCondition(const Expr *Condition, bool Truth) {
      std::optional<z3::expr> Formula = condition(Condition);
      return Formula && addBaseAssertion(Truth ? *Formula : !*Formula,
                                         PathFacts);
    }

    bool apply(const Stmt *Statement) {
      if (!Statement)
        return true;
      if (const auto *Declaration = dyn_cast<DeclStmt>(Statement)) {
        for (const Decl *Item : Declaration->decls()) {
          const auto *Variable = dyn_cast<VarDecl>(Item);
          if (!Variable || !integerType(Variable->getType()))
            continue;
          TransientDeclarations.insert(Variable);
          StateDeclarations.erase(Variable);
          if (!Variable->getInit()) {
            if (!scalar(Variable))
              return false;
            continue;
          }
          std::optional<z3::expr> Initializer =
              expression(Variable->getInit());
          std::optional<z3::expr> Converted;
          if (Initializer)
            Converted = convert(*Initializer, Variable->getType());
          if (!Converted) {
            /* Havocing an unsupported initializer enlarges the transition
             * relation.  It may lose a proof, but cannot manufacture one. */
            Valid = true;
            Converted = freshValue(Variable->getType(), "havoc");
            if (Converted && Support == TransitionSupport::Exact)
              Support = TransitionSupport::Havoced;
          }
          if (!Converted)
            return false;
          if (!InitialValues.count(Variable)) {
            z3::expr Initial =
                Z.int_const(symbolName("v", Variable).c_str());
            if (!addTypeBounds(Initial, Variable->getType()))
              return false;
            InitialValues.emplace(Variable, Initial);
            Existentials.push_back(Initial);
          }
          Values.insert_or_assign(Variable, *Converted);
        }
        return Valid;
      }
      const auto *Expression = dyn_cast<Expr>(Statement);
      Expression = Expression ? Expression->IgnoreParenImpCasts() : nullptr;
      if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Expression)) {
        if (!Unary->isIncrementDecrementOp())
          return true;
        const ValueDecl *Variable = TotalityVisitor::value(Unary->getSubExpr());
        std::optional<z3::expr> Old = scalar(Variable);
        if (!Old)
          return false;
        z3::expr Raw = Unary->isIncrementOp() ? *Old + 1 : *Old - 1;
        QualType ComputationType = Variable->getType();
        if (AST.getIntWidth(ComputationType) <
            AST.getIntWidth(AST.IntTy))
          ComputationType = AST.getPromotedIntegerType(ComputationType);
        std::optional<z3::expr> Computed =
            convert(Raw, ComputationType, signedType(ComputationType));
        std::optional<z3::expr> Updated;
        if (Computed &&
            AST.hasSameUnqualifiedType(ComputationType, Variable->getType()))
          Updated = Computed;
        else if (Computed)
          Updated = convert(*Computed, Variable->getType());
        if (!Updated)
          return false;
        Values.insert_or_assign(Variable, *Updated);
        return Valid;
      }
      const auto *Binary = dyn_cast_or_null<BinaryOperator>(Expression);
      if (!Binary || !Binary->isAssignmentOp())
        return true;
      const ValueDecl *Variable = TotalityVisitor::value(Binary->getLHS());
      if (!Variable || !integerType(Variable->getType())) {
        Support = TransitionSupport::Unsupported;
        return true;
      }
      if (!InitialValues.count(Variable)) {
        z3::expr Initial = Z.int_const(symbolName("v", Variable).c_str());
        if (!addTypeBounds(Initial, Variable->getType()))
          return false;
        InitialValues.emplace(Variable, Initial);
      }
      if (!TransientDeclarations.count(Variable))
        StateDeclarations.insert(Variable);
      std::optional<z3::expr> Updated;
      if (Binary->getOpcode() == BO_Assign) {
        bool SavedValid = Valid;
        std::optional<z3::expr> Right = expression(Binary->getRHS());
        if (Right)
          Updated = convert(*Right, Variable->getType());
        if (!Updated) {
          Valid = SavedValid;
          Updated = freshValue(Variable->getType(), "havoc");
          if (Updated && Support == TransitionSupport::Exact)
            Support = TransitionSupport::Havoced;
        }
      } else if (const auto *Compound =
                     dyn_cast<CompoundAssignOperator>(Binary)) {
        std::optional<z3::expr> Old = scalar(Variable);
        std::optional<z3::expr> Right = expression(Binary->getRHS());
        if (!Old || !Right)
          return false;
        z3::expr Raw = *Old + *Right;
        switch (Binary->getOpcode()) {
        case BO_AddAssign: Raw = *Old + *Right; break;
        case BO_SubAssign: Raw = *Old - *Right; break;
        case BO_MulAssign: Raw = *Old * *Right; break;
        default:
          Valid = false;
          return false;
        }
        std::optional<z3::expr> Computed = convert(
            Raw, Compound->getComputationResultType(),
            signedType(Compound->getComputationResultType()));
        if (Computed &&
            AST.hasSameUnqualifiedType(Compound->getComputationResultType(),
                                       Variable->getType()))
          Updated = Computed;
        else if (Computed)
          Updated = convert(*Computed, Variable->getType());
      }
      if (!Updated) {
        Valid = false;
        return false;
      }
      Values.insert_or_assign(Variable, *Updated);
      return Valid;
    }

    std::optional<z3::expr> initial(const ValueDecl *Variable) {
      if (!scalar(Variable))
        return std::nullopt;
      return InitialValues.find(Variable)->second;
    }

    std::optional<z3::expr> current(const ValueDecl *Variable) {
      return scalar(Variable);
    }

    void markUnsupported() { Support = TransitionSupport::Unsupported; }

    bool finalize() {
      if (Finalized)
        return Valid;
      Finalized = true;
      for (const ValueDecl *Declaration : StateDeclarations) {
        auto Before = InitialValues.find(Declaration);
        auto Current = Values.find(Declaration);
        if (Before == InitialValues.end() || Current == Values.end()) {
          Valid = false;
          return false;
        }
        z3::expr After =
            Z.int_const(symbolName("post", Declaration).c_str());
        if (!addTypeBounds(After, Declaration->getType(), false))
          return false;
        if (!recordRelationAssertion(After == Current->second, PostFacts))
          return false;
        State.push_back(
            {symbolName("slot", Declaration), Before->second, After});
      }
      return Valid;
    }

    z3::expr conjunction(const std::vector<z3::expr> &Facts) {
      z3::expr Result = Z.bool_val(true);
      for (const z3::expr &Fact : Facts)
        Result = Result && Fact;
      return Result;
    }

    z3::expr entryPredicate() { return conjunction(EntryFacts); }

    z3::expr exactRelation() {
      z3::expr Result = conjunction(DomainFacts) && conjunction(EntryFacts) &&
                        conjunction(PathFacts) && conjunction(PostFacts);
      for (const z3::expr &Obligation : Definedness)
        Result = Result && Obligation;
      if (!Existentials.empty()) {
        z3::expr_vector Bound(Z);
        for (const z3::expr &Symbol : Existentials)
          Bound.push_back(Symbol);
        Result = z3::exists(Bound, Result);
      }
      return Result;
    }

    const std::vector<StateSlot> &stateSlice() const { return State; }
    TransitionSupport support() const { return Support; }
    const CFGBlock *backedgeSource() const { return BackedgeSource; }
    const CFGBlock *header() const { return Header; }
    bool wellFormed() {
      return Valid && Finalized && BackedgeSource && Header &&
             entryPredicate().is_bool() && exactRelation().is_bool();
    }

    bool disprovesStrictProgress(const z3::expr &Before,
                                 const z3::expr &After,
                                 ProgressKind Kind) {
      if (!Valid || !Before.is_int() || !After.is_int())
        return true;
      /* Signed arithmetic definedness is an obligation, not an axiom.  It
       * must follow from the path formula before it may participate in a
       * termination proof. */
      for (const z3::expr &Obligation : Definedness) {
        Solver.push();
        bool Added = addQueryAssertion(!Obligation);
        z3::check_result Result = Added ? Solver.check() : z3::unknown;
        Solver.pop();
        if (!Added || Result != z3::unsat)
          return true;
        if (!addQueryAssertion(Obligation))
          return true;
      }
      z3::expr Failure = Kind == ProgressKind::Up ? After <= Before
                                                  : After >= Before;
      if (!addQueryAssertion(Failure) || !Valid)
        return true;
      return Solver.check() != z3::unsat;
    }
  };

  static bool scalarCFGStatement(const Stmt *Statement) {
    if (isa<DeclStmt>(Statement))
      return true;
    const auto *Expression = dyn_cast<Expr>(Statement);
    Expression = Expression ? Expression->IgnoreParenImpCasts() : nullptr;
    if (const auto *Unary = dyn_cast_or_null<UnaryOperator>(Expression))
      return Unary->isIncrementDecrementOp();
    const auto *Binary = dyn_cast_or_null<BinaryOperator>(Expression);
    return Binary && Binary->isAssignmentOp();
  }

  static void collectTransitionState(
      const Stmt *Statement, std::set<const ValueDecl *> &References,
      std::set<const ValueDecl *> &PerIterationDeclarations) {
    if (!Statement)
      return;
    if (const auto *Declaration = dyn_cast<DeclStmt>(Statement))
      for (const Decl *Item : Declaration->decls())
        if (const auto *Variable = dyn_cast<VarDecl>(Item))
          PerIterationDeclarations.insert(Variable);
    if (const auto *Reference = dyn_cast<DeclRefExpr>(Statement)) {
      const auto *Declaration = dyn_cast<ValueDecl>(Reference->getDecl());
      if (Declaration && (Declaration->getType()->isIntegerType() ||
                          Declaration->getType()->isEnumeralType()))
        References.insert(Declaration);
    }
    for (const Stmt *Child : Statement->children())
      collectTransitionState(Child, References, PerIterationDeclarations);
  }

  struct SMTLoopTransitions {
    std::vector<SMTPath> Paths;
    std::set<const ValueDecl *> Slice;
  };

  void collectSMTPaths(const CFGBlock *Block, const CFGBlock *Header,
                       SMTPath Path, std::set<const CFGBlock *> Visiting,
                       std::vector<SMTPath> &Paths, bool &Unsupported) const {
    if (Unsupported || Paths.size() >= 256) {
      Unsupported = true;
      return;
    }
    if (Block == Header) {
      Path.Header = Header;
      Paths.push_back(std::move(Path));
      return;
    }
    if (!Block || !Visiting.insert(Block).second) {
      /* A nested cycle needs its own summary before it can participate in
       * an enclosing transition relation. */
      Unsupported = true;
      return;
    }
    for (const CFGElement &Element : *Block)
      if (std::optional<CFGStmt> Item = Element.getAs<CFGStmt>()) {
        const Stmt *Statement = Item->getStmt();
        if (scalarCFGStatement(Statement)) {
          Path.Steps.push_back({Statement, nullptr, false});
        } else if (const auto *Expression = dyn_cast<Expr>(Statement)) {
          if (Expression->HasSideEffects(Context))
            Path.Support = TransitionSupport::Unsupported;
        }
      }

    const Stmt *Terminator = Block->getTerminatorStmt();
    if (Terminator && (isa<SwitchStmt>(Terminator) ||
                       isa<IndirectGotoStmt>(Terminator))) {
      Unsupported = true;
      return;
    }
    const Expr *Branch = Block->getLastCondition();
    unsigned Index = 0;
    for (const CFGBlock *Successor : Block->succs()) {
      SMTPath Next = Path;
      if (Branch)
        Next.Steps.push_back({nullptr, Branch, Index == 0});
      if (Successor == Header)
        Next.BackedgeSource = Block;
      collectSMTPaths(Successor, Header, std::move(Next), Visiting,
                      Paths, Unsupported);
      ++Index;
    }
  }

  std::optional<SMTLoopTransitions>
  collectSMTLoopTransitions(const Stmt *Loop, const Expr *Condition) const {
    if (!CurrentCFG || isa<DoStmt>(Loop))
      return std::nullopt;
    const CFGBlock *Header = nullptr;
    for (const CFGBlock *Block : *CurrentCFG)
      if (Block->getTerminatorStmt() == Loop) {
        Header = Block;
        break;
      }
    if (!Header || Header->succ_size() != 2)
      return std::nullopt;
    const CFGBlock *BodyEntry = *Header->succ_begin();
    SMTLoopTransitions Result;
    bool Unsupported = false;
    collectSMTPaths(BodyEntry, Header, {}, {}, Result.Paths, Unsupported);
    if (Unsupported || Result.Paths.empty())
      return std::nullopt;
    std::set<const ValueDecl *> PerIterationDeclarations;
    collectTransitionState(Condition, Result.Slice, PerIterationDeclarations);
    for (const SMTPath &Path : Result.Paths)
      for (const SMTPathStep &Step : Path.Steps) {
        collectTransitionState(Step.Statement, Result.Slice,
                               PerIterationDeclarations);
        collectTransitionState(Step.Condition, Result.Slice,
                               PerIterationDeclarations);
      }
    for (const ValueDecl *Declaration : PerIterationDeclarations)
      Result.Slice.erase(Declaration);
    return Result;
  }

  std::unique_ptr<TransitionIR>
  emitTransitionIR(z3::context &Z, const Expr *Condition, const SMTPath &Path,
                   const std::set<const ValueDecl *> &Slice) const {
    auto Result = std::make_unique<TransitionIR>(Context, Z, Path, Slice);
    if (Condition && !Result->assertEntryCondition(Condition, true))
      return nullptr;
    for (const SMTPathStep &Step : Path.Steps) {
      if ((Step.Statement && containsImpureCall(Step.Statement)) ||
          (Step.Condition && containsImpureCall(Step.Condition)))
        Result->markUnsupported();
      if (Step.Statement && !Result->apply(Step.Statement))
        return nullptr;
      if (Step.Condition &&
          !Result->assertPathCondition(Step.Condition, Step.Truth))
        return nullptr;
    }
    if (!Result->finalize() || !Result->wellFormed())
      return nullptr;
    return Result;
  }

  bool stableSMTConditionInputs(const Stmt *Statement,
                                const ValueDecl *Rank,
                                const Stmt *Body,
                                const Expr *Increment) const {
    if (!Statement)
      return true;
    if (const auto *Reference = dyn_cast<DeclRefExpr>(Statement)) {
      const auto *Variable = dyn_cast<VarDecl>(Reference->getDecl());
      if (Variable && Variable != Rank && Variable->getType()->isIntegerType()) {
        if (writesVariable(Body, Variable) ||
            writesVariable(Increment, Variable))
          return false;
        bool HasCalls = containsCall(Body) || containsCall(Increment);
        if (HasCalls && addressTaken(Current->getBody(), Variable))
          return false;
        if (HasCalls && !(isa<ParmVarDecl>(Variable) ||
                          Variable->hasLocalStorage()))
          return false;
      }
    }
    for (const Stmt *Child : Statement->children())
      if (!stableSMTConditionInputs(Child, Rank, Body, Increment))
        return false;
    return true;
  }

  bool z3StrictScalarRank(const Stmt *Loop, const Expr *Condition,
                          const Expr *Increment, const Stmt *Body) const {
    if (!CurrentCFG)
      return false;
    if (isa<DoStmt>(Loop))
      return false;
    if (containsStateMutation(Condition))
      return false;
    if (containsImpureCall(Condition))
      return false;
    if (containsAsm(Body) || containsAsm(Increment))
      return false;
    std::vector<Progress> Collected;
    collectProgress(Increment, Collected);
    collectProgress(Body, Collected);
    std::vector<Progress> Candidates;
    for (const Progress &Candidate : Collected) {
      const auto *Variable = dyn_cast<VarDecl>(Candidate.Variable);
      if (!Variable || !Variable->getType()->isIntegerType())
        continue;
      if (!(isa<ParmVarDecl>(Variable) || Variable->hasLocalStorage()))
        continue;
      if (addressTaken(Current->getBody(), Variable) ||
          !validRankVariable(Candidate, Body, Increment))
        continue;
      if (!stableSMTConditionInputs(Condition, Variable, Body, Increment))
        continue;
      Candidates.push_back(Candidate);
    }
    if (Candidates.empty())
      return false;
    std::optional<SMTLoopTransitions> Transitions =
        collectSMTLoopTransitions(Loop, Condition);
    if (!Transitions)
      return false;

    for (const Progress &Candidate : Candidates) {
      const auto *Variable = dyn_cast<VarDecl>(Candidate.Variable);
      assert(Variable && "eligible scalar rank has a variable");
      bool AllStrict = true;
      z3::context TransitionContext;
      for (const SMTPath &Path : Transitions->Paths) {
        try {
          std::unique_ptr<TransitionIR> Query = emitTransitionIR(
              TransitionContext, Condition, Path, Transitions->Slice);
          if (!Query) {
            AllStrict = false;
            break;
          }
          std::optional<z3::expr> Before = Query->initial(Variable);
          std::optional<z3::expr> After = Query->current(Variable);
          if (!Before || !After ||
              Query->disprovesStrictProgress(*Before, *After, Candidate.Kind)) {
            AllStrict = false;
            break;
          }
        } catch (const z3::exception &) {
          AllStrict = false;
          break;
        }
      }
      if (AllStrict)
        return true;
    }
    return false;
  }

  bool z3FiniteScalarTotality(const Stmt *Loop, const Expr *Condition,
                              const Expr *Increment, const Stmt *Body) const {
    /* A path of N transitions in a transition system with N states contains
     * a repeated state, and therefore a reachable cycle.  Conversely, every
     * reachable cycle supplies paths of arbitrary length.  Asking whether an
     * N-edge path exists is consequently an exact finite-state termination
     * test; it does not assume or synthesize a monotone rank.
     *
     * Formula construction is exponential in the sum of state widths.  The
     * experimental 12-bit ceiling permits 4096 copies of every backedge and
     * was not an acceptable per-loop production cost.  Eight bits caps each
     * query at 256 copies; larger slices conservatively use the other proof
     * engines. */
    constexpr unsigned StateBitCap = 8;
    if (!CurrentCFG || isa<DoStmt>(Loop) || containsStateMutation(Condition) ||
        containsImpureCall(Condition) || containsAsm(Body) ||
        containsAsm(Increment))
      return false;
    std::optional<SMTLoopTransitions> Description =
        collectSMTLoopTransitions(Loop, Condition);
    if (!Description)
      return false;
    unsigned StateBits = 0;
    for (const ValueDecl *Declaration : Description->Slice) {
      QualType Type = Declaration->getType();
      if ((!Type->isIntegerType() && !Type->isEnumeralType()) ||
          Type.isVolatileQualified())
        return false;
      unsigned Width = Context.getIntWidth(Type);
      if (Width > StateBitCap - StateBits)
        return false;
      StateBits += Width;
    }

    try {
      z3::context Z;
      std::vector<std::unique_ptr<TransitionIR>> Backedges;
      for (const SMTPath &Path : Description->Paths) {
        std::unique_ptr<TransitionIR> Transition =
            emitTransitionIR(Z, Condition, Path, Description->Slice);
        if (!Transition || Transition->support() != TransitionSupport::Exact)
          return false;
        Backedges.push_back(std::move(Transition));
      }
      if (Backedges.empty())
        return false;
      const std::vector<TransitionIR::StateSlot> &Slots =
          Backedges.front()->stateSlice();
      for (const auto &Backedge : Backedges) {
        const auto &OtherSlots = Backedge->stateSlice();
        if (OtherSlots.size() != Slots.size())
          return false;
        for (size_t I = 0; I < Slots.size(); ++I)
          if (OtherSlots[I].Identity != Slots[I].Identity ||
              !z3::eq(OtherSlots[I].Before, Slots[I].Before) ||
              !z3::eq(OtherSlots[I].After, Slots[I].After))
            return false;
      }

      z3::expr Union = Z.bool_val(false);
      for (const auto &Backedge : Backedges)
        Union = Union || Backedge->exactRelation();
      if (!Union.is_bool())
        return false;

      unsigned StateCount = 1u << StateBits;
      std::vector<std::vector<z3::expr>> Timeline;
      Timeline.reserve(StateCount + 1);
      for (unsigned Step = 0; Step <= StateCount; ++Step) {
        std::vector<z3::expr> Values;
        Values.reserve(Slots.size());
        for (size_t I = 0; I < Slots.size(); ++I) {
          std::string Name;
          llvm::raw_string_ostream Out(Name);
          Out << "halt_" << reinterpret_cast<uintptr_t>(Loop) << '_' << Step
              << '_' << I;
          Values.push_back(Z.int_const(Out.str().c_str()));
        }
        Timeline.push_back(std::move(Values));
      }

      z3::solver Solver(Z);
      z3::params Parameters(Z);
      Parameters.set("timeout", 200u);
      Solver.set(Parameters);
      z3::expr_vector EntryFrom(Z), EntryTo(Z);
      for (size_t I = 0; I < Slots.size(); ++I) {
        EntryFrom.push_back(Slots[I].Before);
        EntryTo.push_back(Timeline[0][I]);
      }
      z3::expr Entry = Backedges.front()->entryPredicate();
      if (!EntryFrom.empty())
        Entry = Entry.substitute(EntryFrom, EntryTo);
      if (!Entry.is_bool())
        return false;
      Solver.add(Entry);

      for (unsigned Step = 0; Step < StateCount; ++Step) {
        z3::expr_vector From(Z), To(Z);
        for (size_t I = 0; I < Slots.size(); ++I) {
          From.push_back(Slots[I].Before);
          To.push_back(Timeline[Step][I]);
          From.push_back(Slots[I].After);
          To.push_back(Timeline[Step + 1][I]);
        }
        z3::expr Edge = Union;
        if (!From.empty())
          Edge = Edge.substitute(From, To);
        if (!Edge.is_bool())
          return false;
        Solver.add(Edge);
      }
      return Solver.check() == z3::unsat;
    } catch (const z3::exception &) {
      return false;
    }
  }

  bool z3ReachableCycleAbsence(const Stmt *Loop, const Expr *Condition,
                               const Expr *Increment, const Stmt *Body) const {
    /* Spacer computes the least fixed point of Reach and nonempty Path.
     * Deriving Bad means that some state reachable from the loop-entry
     * predicate has a nonempty path back to itself.  Therefore only UNSAT of
     * Bad proves termination.  SAT, unknown, timeout, or a transition which
     * is not exact all conservatively leave the loop unproved.
     *
     * Keep this deliberately shallow.  It complements the exact 8-bit
     * completeness query without making every unresolved production loop pay
     * for a general CHC search. */
    constexpr size_t StateSlotCap = 1;
    constexpr size_t BackedgeCap = 4;
    constexpr size_t PathStepCap = 24;
    if (!CurrentCFG || isa<DoStmt>(Loop) || containsStateMutation(Condition) ||
        containsImpureCall(Condition) || containsImpureCall(Body) ||
        containsImpureCall(Increment) || containsAsm(Body) ||
        containsAsm(Increment))
      return false;
    /* Reject obviously multi-state or non-scalar loops before enumerating
     * CFG paths.  This cheap lexical slice is only a routing filter; the
     * authoritative path-derived slice below must still independently pass
     * every Exact check. */
    std::set<const ValueDecl *> LexicalSlice;
    std::set<const ValueDecl *> PerIterationDeclarations;
    collectTransitionState(Condition, LexicalSlice, PerIterationDeclarations);
    collectTransitionState(Body, LexicalSlice, PerIterationDeclarations);
    collectTransitionState(Increment, LexicalSlice, PerIterationDeclarations);
    for (const ValueDecl *Declaration : PerIterationDeclarations)
      LexicalSlice.erase(Declaration);
    if (LexicalSlice.size() != 1)
      return false;
    const ValueDecl *LexicalState = *LexicalSlice.begin();
    QualType LexicalType = LexicalState->getType();
    if ((!LexicalType->isIntegerType() && !LexicalType->isEnumeralType()) ||
        LexicalType.isVolatileQualified() ||
        Context.getIntWidth(LexicalType) < 32)
      return false;
    if (const auto *Field = dyn_cast<FieldDecl>(LexicalState);
        Field && Field->isBitField())
      return false;
    std::optional<SMTLoopTransitions> Description =
        collectSMTLoopTransitions(Loop, Condition);
    if (!Description || Description->Slice.empty() ||
        Description->Slice.size() > StateSlotCap ||
        Description->Paths.size() > BackedgeCap)
      return false;
    for (const SMTPath &Path : Description->Paths) {
      if (Path.Steps.size() > PathStepCap)
        return false;
      for (const ValueDecl *Declaration : Description->Slice) {
        QualType Type = Declaration->getType();
        if ((!Type->isIntegerType() && !Type->isEnumeralType()) ||
            Type.isVolatileQualified())
          return false;
      }
    }

    try {
      z3::context Z;
      std::vector<std::unique_ptr<TransitionIR>> Backedges;
      for (const SMTPath &Path : Description->Paths) {
        std::unique_ptr<TransitionIR> Transition =
            emitTransitionIR(Z, Condition, Path, Description->Slice);
        if (!Transition || Transition->support() != TransitionSupport::Exact)
          return false;
        Backedges.push_back(std::move(Transition));
      }
      if (Backedges.empty())
        return false;
      const std::vector<TransitionIR::StateSlot> &Slots =
          Backedges.front()->stateSlice();
      if (Slots.empty() || Slots.size() > StateSlotCap)
        return false;
      for (const auto &Backedge : Backedges) {
        const auto &OtherSlots = Backedge->stateSlice();
        if (OtherSlots.size() != Slots.size())
          return false;
        for (size_t I = 0; I < Slots.size(); ++I)
          if (OtherSlots[I].Identity != Slots[I].Identity ||
              !z3::eq(OtherSlots[I].Before, Slots[I].Before) ||
              !z3::eq(OtherSlots[I].After, Slots[I].After))
            return false;
      }

      z3::sort_vector StateSorts(Z), PathSorts(Z);
      for (size_t I = 0; I < Slots.size(); ++I) {
        StateSorts.push_back(Z.int_sort());
        PathSorts.push_back(Z.int_sort());
      }
      for (size_t I = 0; I < Slots.size(); ++I)
        PathSorts.push_back(Z.int_sort());
      z3::func_decl Reach =
          Z.function("totality_reach", StateSorts, Z.bool_sort());
      z3::func_decl Path =
          Z.function("totality_path", PathSorts, Z.bool_sort());
      z3::func_decl Bad =
          Z.function("totality_cycle", 0, nullptr, Z.bool_sort());

      z3::fixedpoint Fixedpoint(Z);
      z3::params Parameters(Z);
      Parameters.set("engine", "spacer");
      /* Multiple backedges require Spacer to discover a disjunctive
       * invariant and consistently need more than the single-edge budget in
       * the fixture corpus.  They are already capped at four paths. */
      Parameters.set("timeout", Backedges.size() > 1 ? 50u : 20u);
      Fixedpoint.set(Parameters);
      Fixedpoint.register_relation(Reach);
      Fixedpoint.register_relation(Path);
      Fixedpoint.register_relation(Bad);

      z3::expr_vector Pre(Z), Post(Z), Start(Z), PrePost(Z), StartPre(Z),
          StartPost(Z), StartPrePost(Z);
      for (size_t I = 0; I < Slots.size(); ++I) {
        std::string PreName = "chc_pre_" + std::to_string(I);
        std::string PostName = "chc_post_" + std::to_string(I);
        std::string StartName = "chc_start_" + std::to_string(I);
        Pre.push_back(Z.int_const(PreName.c_str()));
        Post.push_back(Z.int_const(PostName.c_str()));
        Start.push_back(Z.int_const(StartName.c_str()));
        PrePost.push_back(Pre.back());
        StartPost.push_back(Start.back());
        StartPrePost.push_back(Start.back());
      }
      for (size_t I = 0; I < Slots.size(); ++I) {
        PrePost.push_back(Post[I]);
        StartPre.push_back(Start[I]);
        StartPrePost.push_back(Pre[I]);
      }
      for (size_t I = 0; I < Slots.size(); ++I)
        StartPre.push_back(Pre[I]);
      for (size_t I = 0; I < Slots.size(); ++I) {
        StartPost.push_back(Post[I]);
        StartPrePost.push_back(Post[I]);
      }

      auto Quantify = [&](const z3::expr_vector &Variables,
                          const z3::expr &Rule) {
        return Variables.empty() ? Rule : z3::forall(Variables, Rule);
      };
      auto AddRule = [&](z3::expr Rule, const char *Name) {
        if (!Rule.is_bool())
          return false;
        Fixedpoint.add_rule(Rule, Z.str_symbol(Name));
        return true;
      };
      auto Substitute = [&](z3::expr Formula, const z3::expr_vector &Before,
                            const z3::expr_vector &After) {
        z3::expr_vector From(Z), To(Z);
        for (size_t I = 0; I < Slots.size(); ++I) {
          From.push_back(Slots[I].Before);
          To.push_back(Before[I]);
          From.push_back(Slots[I].After);
          To.push_back(After[I]);
        }
        return Formula.substitute(From, To);
      };

      z3::expr Entry = Backedges.front()->entryPredicate();
      z3::expr_vector EntryFrom(Z);
      for (const auto &Slot : Slots)
        EntryFrom.push_back(Slot.Before);
      Entry = Entry.substitute(EntryFrom, Pre);
      z3::expr EntryRule = Quantify(Pre, z3::implies(Entry, Reach(Pre)));
      if (!Entry.is_bool() || !AddRule(EntryRule, "entry"))
        return false;

      for (size_t EdgeIndex = 0; EdgeIndex < Backedges.size(); ++EdgeIndex) {
        z3::expr Edge =
            Substitute(Backedges[EdgeIndex]->exactRelation(), Pre, Post);
        if (!Edge.is_bool())
          return false;
        z3::expr ReachRule =
            Quantify(PrePost, z3::implies(Reach(Pre) && Edge, Reach(Post)));
        z3::expr PathBaseRule =
            Quantify(PrePost, z3::implies(Reach(Pre) && Edge, Path(PrePost)));
        z3::expr PathStepRule = Quantify(
            StartPrePost, z3::implies(Path(StartPre) && Edge, Path(StartPost)));
        std::string ReachName = "reach_" + std::to_string(EdgeIndex);
        std::string BaseName = "path_base_" + std::to_string(EdgeIndex);
        std::string StepName = "path_step_" + std::to_string(EdgeIndex);
        if (!AddRule(ReachRule, ReachName.c_str()) ||
            !AddRule(PathBaseRule, BaseName.c_str()) ||
            !AddRule(PathStepRule, StepName.c_str()))
          return false;
      }

      z3::expr_vector SameState(Z);
      for (size_t I = 0; I < Slots.size(); ++I)
        SameState.push_back(Start[I]);
      for (size_t I = 0; I < Slots.size(); ++I)
        SameState.push_back(Start[I]);
      z3::expr CycleRule = Quantify(Start, z3::implies(Path(SameState), Bad()));
      if (!AddRule(CycleRule, "cycle"))
        return false;
      z3::expr Query = Bad();
      if (!Query.is_bool())
        return false;
      return Fixedpoint.query(Query) == z3::unsat;
    } catch (const z3::exception &) {
      return false;
    }
  }

  bool admissibleProgress(const Progress &Change) const {
    if (!Change.DynamicStep ||
        !Change.Variable->getType()->isPointerType())
      return true;
    const auto *Step = dyn_cast<ParmVarDecl>(Change.DynamicStep);
    return Step && PositiveParameters.contains(Step) &&
           preservesPositiveValue(Change.GuardedStep, Step);
  }

  /* True for Expression's type when a constant of that type equal to zero
   * -- a null pointer, or a plain zero -- is exactly the "not there"
   * sentinel a small accessor returns to mean "stop". */
  static bool zeroSentinelConstant(const Expr *Expression, ASTContext &Ctx) {
    if (!Expression)
      return false;
    if (Expression->getType()->isPointerType())
      return Expression->isNullPointerConstant(
                 Ctx, Expr::NPC_ValueDependentIsNotNull) != Expr::NPCK_NotNull;
    Expr::EvalResult Result;
    return Expression->EvaluateAsInt(Result, Ctx) &&
           Result.Val.getInt().isZero();
  }

  /* True when Left and Right are both compile-time constants of the same
   * value -- either the same integer, or both a null pointer constant.
   * Used to recognize a caller-written `accessor(...) != SENTINEL` whose
   * SENTINEL is literally the same value the accessor's own ternary
   * returns to mean "stop". */
  static bool sameConstant(const Expr *Left, const Expr *Right,
                           ASTContext &Ctx) {
    if (!Left || !Right)
      return false;
    if (Left->getType()->isPointerType() || Right->getType()->isPointerType())
      return zeroSentinelConstant(Left, Ctx) && zeroSentinelConstant(Right, Ctx);
    Expr::EvalResult LeftValue, RightValue;
    return Left->EvaluateAsInt(LeftValue, Ctx) &&
           Right->EvaluateAsInt(RightValue, Ctx) &&
           llvm::APSInt::compareValues(LeftValue.Val.getInt(),
                                       RightValue.Val.getInt()) == 0;
  }

  /* True when some leaf of Expression is a reference to one of Callee's
   * own parameters -- i.e. Expression cannot be reused verbatim outside
   * Callee's body without first being substituted. */
  static bool referencesParameter(const Expr *Expression,
                                  const FunctionDecl *Callee) {
    if (!Expression)
      return false;
    if (const auto *Reference = dyn_cast<DeclRefExpr>(Expression)) {
      const auto *Parameter = dyn_cast<ParmVarDecl>(Reference->getDecl());
      return Parameter && Parameter->getDeclContext() == Callee;
    }
    for (const Stmt *Child : Expression->children())
      if (const auto *ChildExpr = dyn_cast_or_null<Expr>(Child))
        if (referencesParameter(ChildExpr, Callee))
          return true;
    return false;
  }

  /* ---- Bounded truthiness-preserving call inlining ----------------------
   *
   * loopProof()'s shape matchers (strictComparison(), sentinelCondition(),
   * etc., below) pattern-match the loop condition's own AST directly.  A
   * small read-only accessor -- `while (peek(c) && ...)` where peek()
   * reads `c->pos`/`c->len` internally -- hides exactly the comparison
   * those matchers look for behind an opaque CallExpr, even once
   * containsImpureCall() has already proved, via ReadonlyFunctionFacts,
   * that the call itself cannot touch the rank, its bound, or the
   * sentinel object.  substituteLeaf()/substituteTruthy() splice such an
   * accessor's own `return <expr>;` body into the condition, substituting
   * the callee's parameters for the call's actual arguments, so the
   * matchers below see the comparison exactly as if it had been written
   * inline.
   *
   * Every rewrite performed is an exact identity for C's truth value,
   * never a heuristic approximation: &&, ||, and unary ! keep their own
   * short-circuit meaning with a substituted operand, a comparison keeps
   * its exact shape, and `cond ? value : 0` (or the mirrored
   * `cond ? 0 : value`) becomes `cond && value` (or `!cond && value`)
   * only because C already evaluates the ternary that way -- the zero arm
   * is reached exactly when the substituted subexpression is not.  A
   * shape outside this grammar -- a callee with more than the one return
   * statement, a general ternary whose neither arm is a constant zero, a
   * nested call whose own arguments would need rewriting -- is left
   * exactly as it was: the call stays opaque and loopProof() falls back
   * to its ordinary "unproved" verdict, which is always sound. */

  const Expr *substituteLeaf(const Expr *Expression, const FunctionDecl *Callee,
                             const CallExpr *Call) const {
    if (!Expression)
      return nullptr;
    if (const auto *Paren = dyn_cast<ParenExpr>(Expression))
      return substituteLeaf(Paren->getSubExpr(), Callee, Call);
    if (const auto *Cast = dyn_cast<ImplicitCastExpr>(Expression))
      return substituteLeaf(Cast->getSubExpr(), Callee, Call);
    /* A narrowing/reinterpreting cast (`(unsigned char)lx->src[lx->pos]`)
     * changes only how the leaf's bit pattern is read back, never which
     * memory location or field it names -- the one thing every matcher
     * fed this leaf actually inspects -- so it is dropped the same as an
     * implicit one rather than aborting the substitution. */
    if (const auto *Cast = dyn_cast<CStyleCastExpr>(Expression))
      return substituteLeaf(Cast->getSubExpr(), Callee, Call);
    if (const auto *Reference = dyn_cast<DeclRefExpr>(Expression)) {
      const auto *Parameter = dyn_cast<ParmVarDecl>(Reference->getDecl());
      if (!Parameter || Parameter->getDeclContext() != Callee)
        return Expression;
      unsigned Index = Parameter->getFunctionScopeIndex();
      return Index < Call->getNumArgs() ? Call->getArg(Index) : nullptr;
    }
    if (const auto *Member = dyn_cast<MemberExpr>(Expression)) {
      const Expr *Base = substituteLeaf(Member->getBase(), Callee, Call);
      if (!Base)
        return nullptr;
      if (Base == Member->getBase())
        return Expression;
      return MemberExpr::CreateImplicit(
          Context, const_cast<Expr *>(Base), Member->isArrow(),
          Member->getMemberDecl(), Member->getType(), Member->getValueKind(),
          Member->getObjectKind());
    }
    if (const auto *Subscript = dyn_cast<ArraySubscriptExpr>(Expression)) {
      const Expr *Base = substituteLeaf(Subscript->getBase(), Callee, Call);
      const Expr *Index = substituteLeaf(Subscript->getIdx(), Callee, Call);
      if (!Base || !Index)
        return nullptr;
      if (Base == Subscript->getBase() && Index == Subscript->getIdx())
        return Expression;
      return new (Context.Allocate(sizeof(ArraySubscriptExpr),
                                   alignof(ArraySubscriptExpr)))
          ArraySubscriptExpr(const_cast<Expr *>(Base),
                             const_cast<Expr *>(Index), Subscript->getType(),
                             Subscript->getValueKind(),
                             Subscript->getObjectKind(), SourceLocation());
    }
    if (const auto *Unary = dyn_cast<UnaryOperator>(Expression)) {
      if (Unary->getOpcode() != UO_Deref && Unary->getOpcode() != UO_LNot)
        return referencesParameter(Expression, Callee) ? nullptr : Expression;
      const Expr *Sub = substituteLeaf(Unary->getSubExpr(), Callee, Call);
      if (!Sub)
        return nullptr;
      if (Sub == Unary->getSubExpr())
        return Expression;
      return UnaryOperator::Create(
          Context, const_cast<Expr *>(Sub), Unary->getOpcode(),
          Unary->getType(), Unary->getValueKind(), Unary->getObjectKind(),
          Unary->getOperatorLoc(), Unary->canOverflow(),
          Unary->getFPOptionsOverride());
    }
    return referencesParameter(Expression, Callee) ? nullptr : Expression;
  }

  const Expr *substituteTruthy(const Expr *Expression,
                               const FunctionDecl *Callee,
                               const CallExpr *Call) const {
    if (!Expression)
      return nullptr;
    if (const auto *Paren = dyn_cast<ParenExpr>(Expression))
      return substituteTruthy(Paren->getSubExpr(), Callee, Call);
    if (const auto *Cast = dyn_cast<ImplicitCastExpr>(Expression))
      return substituteTruthy(Cast->getSubExpr(), Callee, Call);
    if (const auto *Cast = dyn_cast<CStyleCastExpr>(Expression))
      return substituteTruthy(Cast->getSubExpr(), Callee, Call);
    if (const auto *Unary = dyn_cast<UnaryOperator>(Expression)) {
      if (Unary->getOpcode() == UO_LNot) {
        const Expr *Sub = substituteTruthy(Unary->getSubExpr(), Callee, Call);
        if (!Sub)
          return nullptr;
        if (Sub == Unary->getSubExpr())
          return Expression;
        return UnaryOperator::Create(
            Context, const_cast<Expr *>(Sub), UO_LNot, Unary->getType(),
            Unary->getValueKind(), Unary->getObjectKind(),
            Unary->getOperatorLoc(), false, Unary->getFPOptionsOverride());
      }
    }
    if (const auto *Binary = dyn_cast<BinaryOperator>(Expression)) {
      if (Binary->getOpcode() == BO_LAnd || Binary->getOpcode() == BO_LOr) {
        const Expr *Left = substituteTruthy(Binary->getLHS(), Callee, Call);
        const Expr *Right = substituteTruthy(Binary->getRHS(), Callee, Call);
        if (!Left || !Right)
          return nullptr;
        if (Left == Binary->getLHS() && Right == Binary->getRHS())
          return Expression;
        return BinaryOperator::Create(
            Context, const_cast<Expr *>(Left), const_cast<Expr *>(Right),
            Binary->getOpcode(), Binary->getType(), Binary->getValueKind(),
            Binary->getObjectKind(), Binary->getOperatorLoc(),
            Binary->getFPFeatures());
      }
      if (Binary->isComparisonOp()) {
        const Expr *Left = substituteLeaf(Binary->getLHS(), Callee, Call);
        const Expr *Right = substituteLeaf(Binary->getRHS(), Callee, Call);
        if (!Left || !Right)
          return nullptr;
        if (Left == Binary->getLHS() && Right == Binary->getRHS())
          return Expression;
        return BinaryOperator::Create(
            Context, const_cast<Expr *>(Left), const_cast<Expr *>(Right),
            Binary->getOpcode(), Binary->getType(), Binary->getValueKind(),
            Binary->getObjectKind(), Binary->getOperatorLoc(),
            Binary->getFPFeatures());
      }
      return referencesParameter(Expression, Callee) ? nullptr : Expression;
    }
    if (const auto *Conditional = dyn_cast<ConditionalOperator>(Expression)) {
      const Expr *TrueExpr = Conditional->getTrueExpr();
      const Expr *FalseExpr = Conditional->getFalseExpr();
      bool TrueIsZero = zeroSentinelConstant(TrueExpr, Context);
      bool FalseIsZero = zeroSentinelConstant(FalseExpr, Context);
      /* Exactly one arm must be the constant "stop" value: an ordinary
       * two-sided ternary does not reduce to a single conjunction. */
      if (TrueIsZero == FalseIsZero)
        return referencesParameter(Expression, Callee) ? nullptr : Expression;
      const Expr *Cond =
          substituteTruthy(Conditional->getCond(), Callee, Call);
      const Expr *Survivor =
          substituteTruthy(FalseIsZero ? TrueExpr : FalseExpr, Callee, Call);
      if (!Cond || !Survivor)
        return nullptr;
      if (!FalseIsZero)
        Cond = UnaryOperator::Create(
            Context, const_cast<Expr *>(Cond), UO_LNot, Context.IntTy,
            VK_PRValue, OK_Ordinary, Conditional->getQuestionLoc(), false,
            FPOptionsOverride());
      return BinaryOperator::Create(
          Context, const_cast<Expr *>(Cond), const_cast<Expr *>(Survivor),
          BO_LAnd, Context.IntTy, VK_PRValue, OK_Ordinary,
          Conditional->getQuestionLoc(), FPOptionsOverride());
    }
    return substituteLeaf(Expression, Callee, Call);
  }

  /* Callee is bounded-inlinable exactly when its definition is visible in
   * this translation unit and its entire body is one `return <expr>;` --
   * the one shape simple enough that inlining it can never hide a loop, a
   * second statement's side effect, or unbounded recursion. */
  const Expr *expandCall(const CallExpr *Call) const {
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee)
      return nullptr;
    const FunctionDecl *Definition = Callee->getDefinition();
    if (!Definition)
      return nullptr;
    const auto *CalleeBody =
        dyn_cast_or_null<CompoundStmt>(Definition->getBody());
    if (!CalleeBody || CalleeBody->size() != 1)
      return nullptr;
    const auto *Return = dyn_cast<ReturnStmt>(*CalleeBody->body_begin());
    if (!Return || !Return->getRetValue())
      return nullptr;
    return substituteTruthy(Return->getRetValue(), Definition, Call);
  }

  /* Handles a caller-written `accessor(...) == K` / `accessor(...) != K`
   * where accessor's own body is `return cond ? A : K;` (or the mirrored
   * `cond ? K : A`) for that very same constant K -- the shape a
   * peekc()-style accessor uses to signal "nothing left" with an explicit
   * sentinel return value instead of relying on truthiness.  The K arm is
   * reached exactly when Cond is not, so the comparison is an exact
   * rewrite to a plain && or || of Cond (or its negation) with the
   * surviving arm's own comparison against K -- never an approximation of
   * what the accessor actually returns. */
  const Expr *expandComparisonCall(const CallExpr *Call,
                                   BinaryOperatorKind Opcode,
                                   const Expr *Constant) const {
    if (Opcode != BO_EQ && Opcode != BO_NE)
      return nullptr;
    const FunctionDecl *Callee = Call->getDirectCallee();
    if (!Callee)
      return nullptr;
    const FunctionDecl *Definition = Callee->getDefinition();
    if (!Definition)
      return nullptr;
    const auto *CalleeBody =
        dyn_cast_or_null<CompoundStmt>(Definition->getBody());
    if (!CalleeBody || CalleeBody->size() != 1)
      return nullptr;
    const auto *Return = dyn_cast<ReturnStmt>(*CalleeBody->body_begin());
    if (!Return || !Return->getRetValue())
      return nullptr;
    const auto *Conditional =
        dyn_cast<ConditionalOperator>(ignore(Return->getRetValue()));
    if (!Conditional)
      return nullptr;
    const Expr *TrueExpr = Conditional->getTrueExpr();
    const Expr *FalseExpr = Conditional->getFalseExpr();
    bool TrueMatches = sameConstant(TrueExpr, Constant, Context);
    bool FalseMatches = sameConstant(FalseExpr, Constant, Context);
    if (TrueMatches == FalseMatches)
      return nullptr;
    const Expr *Cond = substituteTruthy(Conditional->getCond(), Definition, Call);
    const Expr *Survivor = substituteLeaf(FalseMatches ? TrueExpr : FalseExpr,
                                          Definition, Call);
    if (!Cond || !Survivor)
      return nullptr;
    const Expr *SurvivorComparison = BinaryOperator::Create(
        Context, const_cast<Expr *>(Survivor), const_cast<Expr *>(Constant),
        Opcode, Context.IntTy, VK_PRValue, OK_Ordinary,
        Conditional->getQuestionLoc(), FPOptionsOverride());
    bool NegateCond = (Opcode == BO_NE) ? TrueMatches : FalseMatches;
    if (NegateCond)
      Cond = UnaryOperator::Create(
          Context, const_cast<Expr *>(Cond), UO_LNot, Context.IntTy,
          VK_PRValue, OK_Ordinary, Conditional->getQuestionLoc(), false,
          FPOptionsOverride());
    return BinaryOperator::Create(
        Context, const_cast<Expr *>(Cond), const_cast<Expr *>(SurvivorComparison),
        Opcode == BO_NE ? BO_LAnd : BO_LOr, Context.IntTy, VK_PRValue,
        OK_Ordinary, Conditional->getQuestionLoc(), FPOptionsOverride());
  }

  /* Top-level condition rewrite: recurses through &&, ||, !, and
   * "assign-and-test" (`(v = call()) && ...`, whose value for truthiness
   * purposes is exactly the assigned call's own value) looking for a bare
   * call to expand.  Anything else -- including a call this deep down
   * that expandCall() declines -- is left exactly as written, so this
   * always returns a condition at least as provable as the original. */
  const Expr *expandConditionCalls(const Expr *Condition) const {
    if (!Condition)
      return Condition;
    if (const auto *Paren = dyn_cast<ParenExpr>(Condition))
      return expandConditionCalls(Paren->getSubExpr());
    if (const auto *Cast = dyn_cast<ImplicitCastExpr>(Condition))
      return expandConditionCalls(Cast->getSubExpr());
    if (const auto *Unary = dyn_cast<UnaryOperator>(Condition)) {
      if (Unary->getOpcode() == UO_LNot) {
        const Expr *Sub = expandConditionCalls(Unary->getSubExpr());
        if (Sub == Unary->getSubExpr())
          return Condition;
        return UnaryOperator::Create(
            Context, const_cast<Expr *>(Sub), UO_LNot, Unary->getType(),
            Unary->getValueKind(), Unary->getObjectKind(),
            Unary->getOperatorLoc(), false, Unary->getFPOptionsOverride());
      }
      return Condition;
    }
    if (const auto *Binary = dyn_cast<BinaryOperator>(Condition)) {
      if (Binary->getOpcode() == BO_LAnd || Binary->getOpcode() == BO_LOr) {
        const Expr *Left = expandConditionCalls(Binary->getLHS());
        const Expr *Right = expandConditionCalls(Binary->getRHS());
        if (Left == Binary->getLHS() && Right == Binary->getRHS())
          return Condition;
        return BinaryOperator::Create(
            Context, const_cast<Expr *>(Left), const_cast<Expr *>(Right),
            Binary->getOpcode(), Binary->getType(), Binary->getValueKind(),
            Binary->getObjectKind(), Binary->getOperatorLoc(),
            Binary->getFPFeatures());
      }
      if (Binary->getOpcode() == BO_Assign)
        return expandConditionCalls(Binary->getRHS());
      if (Binary->getOpcode() == BO_EQ || Binary->getOpcode() == BO_NE) {
        const auto *LeftCall = dyn_cast<CallExpr>(ignore(Binary->getLHS()));
        const auto *RightCall = dyn_cast<CallExpr>(ignore(Binary->getRHS()));
        const Expr *Expanded = nullptr;
        if (LeftCall && !RightCall)
          Expanded = expandComparisonCall(LeftCall, Binary->getOpcode(),
                                          Binary->getRHS());
        else if (RightCall && !LeftCall)
          Expanded = expandComparisonCall(RightCall, Binary->getOpcode(),
                                          Binary->getLHS());
        if (Expanded)
          return Expanded;
      }
      return Condition;
    }
    if (const auto *Call = dyn_cast<CallExpr>(Condition)) {
      const Expr *Expanded = expandCall(Call);
      return Expanded ? Expanded : Condition;
    }
    return Condition;
  }

  std::string loopProof(const Stmt *Loop, const Expr *Condition,
                        const Expr *Increment, const Stmt *Body,
                        bool ConditionBeforeBody) const {
    if (constantFalse(Condition, Context))
      return "constant-false";
    /* Without an explicit total/pure call summary, a call made while
     * deciding whether to take the backedge can both fail to return and
     * mutate globally reachable rank or bound state. */
    if (containsImpureCall(Condition))
      return "unproved";
    /* Every call remaining in Condition is now known pure/const/readonly.
     * Splice in the body of any small accessor whose own shape the
     * matchers below could otherwise not see through -- see
     * expandConditionCalls() above. */
    Condition = expandConditionCalls(Condition);
    if (ConditionBeforeBody && !Increment &&
        branchCompleteIntervalDescent(Condition, Body))
      return "strict-scalar-rank";
    if (ConditionBeforeBody && !Increment &&
        guardedGeometricAscent(Loop, Condition, Body))
      return "strict-scalar-rank";
    /* `while (n--)` and `for (...; n-- > 0; ...)` perform their strict
     * descent in the condition, before every taken iteration.  The final
     * false test may itself wrap an unsigned n, but there is no following
     * backedge, so that cannot create a cycle. */
    if (std::optional<Progress> Change = conditionCountdown(Condition)) {
      if (Change->Variable->getType()->isIntegerType() &&
          validRankVariable(*Change, Body, Increment) &&
          mutation(Body, *Change) == Mutation::None)
        return "strict-scalar-rank";
    }
    if (std::optional<Progress> Change = progress(Increment)) {
      if (!admissibleProgress(*Change))
        return "unproved";
      /* The for increment is on every backedge, but an additional body
       * mutation could cancel it or turn the effective step into a
       * sentinel-skipping/wrapping step. */
      Mutation BodyMutation = mutation(Body, *Change);
      if (guardedConstantStrideAscent(Loop, Condition, Body, Increment,
                                      *Change))
        return "strict-scalar-rank";
      if (sameDomainUnitUpperBound(Condition, *Change) &&
          isa<VarDecl>(Change->Variable) &&
          (isa<ParmVarDecl>(Change->Variable) ||
           cast<VarDecl>(Change->Variable)->hasLocalStorage()) &&
          !addressTaken(Current->getBody(), Change->Variable) &&
          validRankVariable(*Change, Body, Increment) &&
          rankUnmodifiedOnBackedges(Body, *Change))
        return "strict-scalar-rank";
      /* An additional same-direction unit step cannot invalidate a signed
       * induction rank: either the comparison is reached after finitely
       * many steps, or the addition overflows and the execution was already
       * outside C's defined domain.  Keep rejecting it for unsigned ranks,
       * where wrapping is defined and can make the loop genuinely cycle. */
      if (!validRankVariable(*Change, Body, Increment) ||
          (BodyMutation != Mutation::None &&
           !(BodyMutation == Mutation::Good &&
             (Change->Variable->getType()->isSignedIntegerType() ||
              Change->Variable->getType()->isPointerType()))))
        return "unproved";
      if (strictComparison(Condition, *Change, Body, Increment))
        return "strict-scalar-rank";
      /* Defined C pointer arithmetic is confined to an array object and its
       * one-past position.  A pointer which advances on every backedge
       * therefore has a finite object-distance rank even when the loop's
       * exit test is spelled in the body rather than in its condition. */
      if (pointerObjectDistanceRank(*Change, Condition, Body, Increment))
        return "sentinel-distance-rank";
      if (sentinelCondition(Condition, *Change))
        return "sentinel-distance-rank";
      return "unproved";
    }
    /* A comma expression is the normal spelling of a multi-variable for
     * increment (`i++, j--`).  progress() intentionally describes one
     * scalar, so collect each candidate and prove the one used by the loop
     * condition.  mutation() still rejects cancellation of that candidate.
     */
    std::vector<Progress> IncrementCandidates;
    collectProgress(Increment, IncrementCandidates);
    for (const Progress &Change : IncrementCandidates) {
      if (!admissibleProgress(Change))
        continue;
      Mutation BodyMutation = mutation(Body, Change);
      if (guardedConstantStrideAscent(Loop, Condition, Body, Increment,
                                      Change))
        return "strict-scalar-rank";
      if (sameDomainUnitUpperBound(Condition, Change) &&
          isa<VarDecl>(Change.Variable) &&
          (isa<ParmVarDecl>(Change.Variable) ||
           cast<VarDecl>(Change.Variable)->hasLocalStorage()) &&
          !addressTaken(Current->getBody(), Change.Variable) &&
          validRankVariable(Change, Body, Increment) &&
          progressOccurrences(Increment, Change) == 1 &&
          mutation(Increment, Change) == Mutation::Good &&
          rankUnmodifiedOnBackedges(Body, Change))
        return "strict-scalar-rank";
      if (progressOccurrences(Increment, Change) != 1 ||
          !validRankVariable(Change, Body, Increment) ||
          mutation(Increment, Change) != Mutation::Good ||
          (BodyMutation != Mutation::None &&
           !(BodyMutation == Mutation::Good &&
             (Change.Variable->getType()->isSignedIntegerType() ||
              Change.Variable->getType()->isPointerType()))))
        continue;
      if (strictComparison(Condition, Change, Body, Increment))
        return "strict-scalar-rank";
      if (pointerObjectDistanceRank(Change, Condition, Body, Increment))
        return "sentinel-distance-rank";
      if (sentinelCondition(Condition, Change))
        return "sentinel-distance-rank";
    }
    std::vector<DerivedAffine> DerivedCandidates;
    collectDerivedAffine(Body, DerivedCandidates);
    for (const DerivedAffine &Candidate : DerivedCandidates)
      if (guardedDerivedAffineAscent(Condition, Body, Increment, Candidate))
        return "strict-scalar-rank";
    std::vector<Progress> Candidates;
    collectProgress(Body, Candidates);
    for (const Progress &Change : Candidates) {
      bool GuardedPointerProgress =
          Change.DynamicStep && Change.Variable->getType()->isPointerType() &&
          bodyHasGuardedDynamicPointerProgress(Body, Change);
      if ((!admissibleProgress(Change) && !GuardedPointerProgress) ||
          !validRankVariable(Change, Body, Increment) ||
          !bodyGuaranteesProgress(Body, Change, Condition, Loop))
        continue;
      if (strictComparison(Condition, Change, Body, Increment))
        return "strict-scalar-rank";
      if (Change.DynamicStep && Change.Kind == ProgressKind::Down &&
          bodyHasGuardedDynamicDescent(Condition, Body, Change))
        return "strict-scalar-rank";
      if (Change.DynamicStep && Change.Kind == ProgressKind::Up &&
          bodyHasGuardedDynamicAscent(Condition, Body, Increment, Change))
        return "strict-scalar-rank";
      if (pointerObjectDistanceRank(Change, Condition, Body, Increment))
        return "sentinel-distance-rank";
      if (signedFiniteDomainRank(Change, Condition, Body, Increment))
        return "strict-scalar-rank";
      if (!Condition && Change.UnitStep &&
          Change.Kind == ProgressKind::Down &&
          Change.Variable->getType()->isIntegerType()) {
        Progress UnitChange = Change;
        UnitChange.UnitOnly = true;
        if (bodyGuaranteesProgress(Body, UnitChange, Condition, Loop) &&
            bodyHasDominatingNonzeroGuard(Body, UnitChange))
          return "strict-scalar-rank";
      }
      if (sentinelCondition(Condition, Change))
        return "sentinel-distance-rank";
    }
    /* Exact finite-state unrolling is deliberately the final scalar
     * fallback: the bounded query is more expensive than the local proof
     * families above, and is needed only when no simpler certificate was
     * recognized. */
    if (z3FiniteScalarTotality(Loop, Condition, Increment, Body))
      return "finite-state-transition";
    if (z3StrictScalarRank(Loop, Condition, Increment, Body))
      return "strict-scalar-rank";
    if (z3ReachableCycleAbsence(Loop, Condition, Increment, Body))
      return "reachable-cycle-absence";
    /* A merge-style loop can consume either of two finite inputs on a
     * given pass.  Neither cursor is a rank by itself, but the sum of their
     * remaining distances strictly decreases when every backedge advances
     * at least one and neither ever retreats.  Keep this to while/do bodies
     * for now: a for-loop continue edge reaches its increment and needs a
     * separate composition rule. */
    /* Condition-side mutation can reset either rank or move either bound;
     * restricting every participating value to an unescaped local closes
     * the pointer-to-pointer and globally-created-alias holes which the
     * deliberately shallow alias walker cannot see. */
    if (!Increment && !containsStateMutation(Condition) &&
        pairedConditionValuesAreLocal(Condition)) {
      for (size_t I = 0; I < Candidates.size(); ++I) {
        const Progress &First = Candidates[I];
        if (!admissibleProgress(First) ||
            !isa<VarDecl>(First.Variable) ||
            First.Kind != ProgressKind::Up ||
            addressTaken(Current->getBody(), First.Variable) ||
            !validRankVariable(First, Body) ||
            mutation(Condition, First) != Mutation::None ||
            !strictComparison(Condition, First, Body, nullptr, true))
          continue;
        for (size_t J = I + 1; J < Candidates.size(); ++J) {
          const Progress &Second = Candidates[J];
          if (!admissibleProgress(Second) ||
              !isa<VarDecl>(Second.Variable) ||
              Second.Kind != ProgressKind::Up || sameRank(First, Second) ||
              addressTaken(Current->getBody(), Second.Variable) ||
              !validRankVariable(Second, Body) ||
              mutation(Condition, Second) != Mutation::None ||
              !strictComparison(Condition, Second, Body, nullptr, true))
            continue;
          PairFlow Result = pairFlow(Body, First, Second);
          unsigned BackedgeMasks = Result.FallMasks | Result.BackMasks;
          if (!Result.Invalid && (BackedgeMasks || Result.Exits) &&
              !(BackedgeMasks & 1u))
            return "paired-scalar-rank";
        }
      }
    }
    return "unproved";
  }

  void loop(StringRef Kind, const Stmt *Statement, const Expr *Condition,
            const Expr *Increment, const Stmt *Body) const {
    if (!Current)
      return;
    llvm::outs() << "L\t" << key(Current) << '\t'
                 << file(Statement->getBeginLoc()) << '\t'
                 << line(Statement->getBeginLoc()) << '\t' << Kind << '\t'
                 << loopProof(Statement, Condition, Increment, Body,
                              Kind != "do") << '\t'
                 << text(Statement) << '\n';
  }

public:
  TotalityVisitor(ASTContext &Context,
                  const ReadonlyFunctionFacts &ReadonlyFunctions,
                  const PositiveParameterFacts &PositiveParameters)
      : Context(Context), SM(Context.getSourceManager()),
        ReadonlyFunctions(ReadonlyFunctions),
        PositiveParameters(PositiveParameters) {}

  bool TraverseFunctionDecl(FunctionDecl *Function) {
    if (!Function->isThisDeclarationADefinition() ||
        !SM.isWrittenInMainFile(SM.getExpansionLoc(Function->getLocation())))
      return true;
    const FunctionDecl *Saved = Current;
    Current = Function;
    CurrentCFG = CFG::buildCFG(Function, Function->getBody(), &Context,
                               CFG::BuildOptions());
    /* Twice the real parameter count reserves one virtual "field
     * progress" slot per parameter -- see fieldProgressRelation() and
     * callRelations() -- immediately after the real ones, at index
     * NumParams+K for real parameter K.  lint-totality.py never assigns
     * either half of the index space a meaning; it only needs an upper
     * bound to validate indices against and a consistent size-change
     * matrix to compose, both of which this doubled count still is. */
    llvm::outs() << "F\t" << key(Function) << '\t'
                 << file(Function->getLocation()) << '\t'
                 << line(Function->getLocation()) << '\t'
                 << (Function->isNoReturn() ? "noreturn" : "returns") << '\t'
                 << 2 * Function->getNumParams() << '\n';
    RecursiveASTVisitor<TotalityVisitor>::TraverseStmt(Function->getBody());
    CurrentCFG.reset();
    Current = Saved;
    return true;
  }

  bool VisitCallExpr(CallExpr *Call) {
    if (!Current)
      return true;
    const FunctionDecl *Callee = Call->getDirectCallee();
    llvm::outs() << (Callee ? "C\t" : "I\t") << key(Current) << '\t';
    if (Callee)
      llvm::outs() << key(Callee);
    else
      llvm::outs() << text(Call->getCallee());
    llvm::outs() << '\t' << file(Call->getExprLoc()) << '\t'
                 << line(Call->getExprLoc()) << '\t'
                 << (Callee ? callRelations(Call, Callee) : "-") << '\n';
    return true;
  }

  bool VisitForStmt(ForStmt *Loop) {
    loop("for", Loop, Loop->getCond(), Loop->getInc(), Loop->getBody());
    return true;
  }

  bool VisitWhileStmt(WhileStmt *Loop) {
    loop("while", Loop, Loop->getCond(), nullptr, Loop->getBody());
    return true;
  }

  bool VisitDoStmt(DoStmt *Loop) {
    loop("do", Loop, Loop->getCond(), nullptr, Loop->getBody());
    return true;
  }
};

class TotalityConsumer : public ASTConsumer {
public:
  void HandleTranslationUnit(ASTContext &Context) override {
    ReadonlyFunctionFacts ReadonlyFunctions(Context);
    PositiveParameterFacts PositiveParameters(Context);
    TotalityVisitor(Context, ReadonlyFunctions, PositiveParameters)
        .TraverseDecl(Context.getTranslationUnitDecl());
  }
};

class TotalityAction : public PluginASTAction {
protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &,
                                                 StringRef) override {
    return std::make_unique<TotalityConsumer>();
  }

  bool ParseArgs(const CompilerInstance &,
                 const std::vector<std::string> &) override {
    return true;
  }

  ActionType getActionType() override { return AddAfterMainAction; }
};

} // namespace

static FrontendPluginRegistry::Add<TotalityAction>
    X("ntlibc-totality", "emit ntlibc totality proof inputs");
