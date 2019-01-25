//===- unittest/AST/ASTImporterGenericRedeclTest.cpp - AST import test ----===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Type-parameterized tests for the correct import of redecl chains.
//
//===----------------------------------------------------------------------===//

#include "ASTImporterFixtures.h"

namespace clang {
namespace ast_matchers {

using internal::BindableMatcher;

struct Function {
  using DeclTy = FunctionDecl;
  static constexpr auto *Prototype = "void X();";
  static constexpr auto *Definition = "void X() {}";
  BindableMatcher<Decl> getPattern() {
    return functionDecl(hasName("X"), unless(isImplicit()));
  }
};

struct Class {
  using DeclTy = CXXRecordDecl;
  static constexpr auto *Prototype = "class X;";
  static constexpr auto *Definition = "class X {};";
  BindableMatcher<Decl> getPattern() {
    return cxxRecordDecl(hasName("X"), unless(isImplicit()));
  }
};

struct Variable {
  using DeclTy = VarDecl;
  static constexpr auto *Prototype = "extern int X;";
  static constexpr auto *Definition = "int X;";
  BindableMatcher<Decl> getPattern() { return varDecl(hasName("X")); }
};

struct FunctionTemplate {
  using DeclTy = FunctionTemplateDecl;
  static constexpr auto *Prototype = "template <class T> void X();";
  static constexpr auto *Definition =
      R"(
      template <class T> void X() {};
      // Explicit instantiation is a must because of -fdelayed-template-parsing:
      template void X<int>();
      )";
  BindableMatcher<Decl> getPattern() {
    return functionTemplateDecl(hasName("X"), unless(isImplicit()));
  }
};

struct ClassTemplate {
  using DeclTy = ClassTemplateDecl;
  static constexpr auto *Prototype = "template <class T> class X;";
  static constexpr auto *Definition = "template <class T> class X {};";
  BindableMatcher<Decl> getPattern() {
    return classTemplateDecl(hasName("X"), unless(isImplicit()));
  }
};

struct FunctionTemplateSpec {
  using DeclTy = FunctionDecl;
  static constexpr auto *Prototype =
      R"(
      // Proto of the primary template.
      template <class T>
      void X();
      // Proto of the specialization.
      template <>
      void X<int>();
      )";
  static constexpr auto *Definition =
      R"(
      // Proto of the primary template.
      template <class T>
      void X();
      // Specialization and definition.
      template <>
      void X<int>() {}
      )";
  BindableMatcher<Decl> getPattern() {
    return functionDecl(hasName("X"), isExplicitTemplateSpecialization());
  }
};

struct ClassTemplateSpec {
  using DeclTy = ClassTemplateSpecializationDecl;
  static constexpr auto *Prototype =
    R"(
    template <class T> class X;
    template <> class X<int>;
    )";
  static constexpr auto *Definition =
    R"(
    template <class T> class X;
    template <> class X<int> {};
    )";
  BindableMatcher<Decl> getPattern() {
    return classTemplateSpecializationDecl(hasName("X"), unless(isImplicit()));
  }
};

template <typename TypeParam>
struct RedeclChain : ASTImporterOptionSpecificTestBase {

  using DeclTy = typename TypeParam::DeclTy;
  std::string getPrototype() { return TypeParam::Prototype; }
  std::string getDefinition() { return TypeParam::Definition; }
  BindableMatcher<Decl> getPattern() const { return TypeParam().getPattern(); }

  void CheckPreviousDecl(Decl *To0, Decl *To1) {
    ASSERT_NE(To0, To1);
    ASSERT_EQ(&To0->getASTContext(), &To1->getASTContext());

    auto *ToTU = To0->getTranslationUnitDecl();

    // Templates.
    if (auto *ToT0 = dyn_cast<TemplateDecl>(To0)) {
      EXPECT_EQ(To1->getPreviousDecl(), To0);
      auto *ToT1 = cast<TemplateDecl>(To1);
      ASSERT_TRUE(ToT0->getTemplatedDecl());
      ASSERT_TRUE(ToT1->getTemplatedDecl());
      EXPECT_EQ(ToT1->getTemplatedDecl()->getPreviousDecl(),
                ToT0->getTemplatedDecl());
      return;
    }

    // Specializations.
    if (auto *From0F = dyn_cast<FunctionDecl>(To0)) {
      auto *To0F = cast<FunctionDecl>(To0);
      if (From0F->getTemplatedKind() ==
          FunctionDecl::TK_FunctionTemplateSpecialization) {
        EXPECT_EQ(To0->getCanonicalDecl(), To1->getCanonicalDecl());
        // There may be a hidden fwd spec decl before a spec decl.
        // In that case the previous visible decl can be reached through that
        // invisible one.
        EXPECT_THAT(To0,
                    testing::AnyOf(To1->getPreviousDecl(),
                                   To1->getPreviousDecl()->getPreviousDecl()));
        auto *TemplateD = FirstDeclMatcher<FunctionTemplateDecl>().match(
            ToTU, functionTemplateDecl());
        auto *FirstSpecD = *(TemplateD->spec_begin());
        EXPECT_EQ(FirstSpecD->getCanonicalDecl(), To0F->getCanonicalDecl());
        return;
      }
    }

    // The rest: Classes, Functions, etc.
    EXPECT_EQ(To1->getPreviousDecl(), To0);
  }

  void
  TypedTest_PrototypeShouldBeImportedAsAPrototypeWhenThereIsNoDefinition() {
    Decl *FromTU = getTuDecl(getPrototype(), Lang_CXX);
    auto *FromD = FirstDeclMatcher<DeclTy>().match(FromTU, getPattern());
    ASSERT_FALSE(FromD->isThisDeclarationADefinition());

    Decl *ImportedD = Import(FromD, Lang_CXX);
    Decl *ToTU = ImportedD->getTranslationUnitDecl();

    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 1u);
    auto *ToD = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(ImportedD == ToD);
    EXPECT_FALSE(ToD->isThisDeclarationADefinition());
    if (auto *ToT = dyn_cast<TemplateDecl>(ToD))
      EXPECT_TRUE(ToT->getTemplatedDecl());
  }

  void TypedTest_DefinitionShouldBeImportedAsADefinition() {
    Decl *FromTU = getTuDecl(getDefinition(), Lang_CXX);
    auto *FromD = FirstDeclMatcher<DeclTy>().match(FromTU, getPattern());
    ASSERT_TRUE(FromD->isThisDeclarationADefinition());

    Decl *ImportedD = Import(FromD, Lang_CXX);
    Decl *ToTU = ImportedD->getTranslationUnitDecl();

    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 1u);
    auto *ToD = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(ToD->isThisDeclarationADefinition());
    if (auto *ToT = dyn_cast<TemplateDecl>(ToD))
      EXPECT_TRUE(ToT->getTemplatedDecl());
  }

  void TypedTest_ImportPrototypeAfterImportedPrototype() {
    Decl *FromTU = getTuDecl(getPrototype() + getPrototype(), Lang_CXX);
    auto *From0 = FirstDeclMatcher<DeclTy>().match(FromTU, getPattern());
    auto *From1 = LastDeclMatcher<DeclTy>().match(FromTU, getPattern());
    ASSERT_FALSE(From0->isThisDeclarationADefinition());
    ASSERT_FALSE(From1->isThisDeclarationADefinition());

    Decl *Imported0 = Import(From0, Lang_CXX);
    Decl *Imported1 = Import(From1, Lang_CXX);
    Decl *ToTU = Imported0->getTranslationUnitDecl();

    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 2u);
    auto *To0 = FirstDeclMatcher<DeclTy>().match(ToTU, getPattern());
    auto *To1 = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(Imported0 == To0);
    EXPECT_TRUE(Imported1 == To1);
    EXPECT_FALSE(To0->isThisDeclarationADefinition());
    EXPECT_FALSE(To1->isThisDeclarationADefinition());

    CheckPreviousDecl(To0, To1);
  }

  void TypedTest_ImportDefinitionAfterImportedPrototype() {
    Decl *FromTU = getTuDecl(getPrototype() + getDefinition(), Lang_CXX);
    auto *From0 = FirstDeclMatcher<DeclTy>().match(FromTU, getPattern());
    auto *From1 = LastDeclMatcher<DeclTy>().match(FromTU, getPattern());
    ASSERT_FALSE(From0->isThisDeclarationADefinition());
    ASSERT_TRUE(From1->isThisDeclarationADefinition());

    Decl *Imported0 = Import(From0, Lang_CXX);
    Decl *Imported1 = Import(From1, Lang_CXX);
    Decl *ToTU = Imported0->getTranslationUnitDecl();

    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 2u);
    auto *To0 = FirstDeclMatcher<DeclTy>().match(ToTU, getPattern());
    auto *To1 = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(Imported0 == To0);
    EXPECT_TRUE(Imported1 == To1);
    EXPECT_FALSE(To0->isThisDeclarationADefinition());
    EXPECT_TRUE(To1->isThisDeclarationADefinition());

    CheckPreviousDecl(To0, To1);
  }

  void TypedTest_ImportPrototypeAfterImportedDefinition() {
    Decl *FromTU = getTuDecl(getDefinition() + getPrototype(), Lang_CXX);
    auto *From0 = FirstDeclMatcher<DeclTy>().match(FromTU, getPattern());
    auto *From1 = LastDeclMatcher<DeclTy>().match(FromTU, getPattern());
    ASSERT_TRUE(From0->isThisDeclarationADefinition());
    ASSERT_FALSE(From1->isThisDeclarationADefinition());

    Decl *Imported0 = Import(From0, Lang_CXX);
    Decl *Imported1 = Import(From1, Lang_CXX);
    Decl *ToTU = Imported0->getTranslationUnitDecl();

    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 2u);
    auto *To0 = FirstDeclMatcher<DeclTy>().match(ToTU, getPattern());
    auto *To1 = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(Imported0 == To0);
    EXPECT_TRUE(Imported1 == To1);
    EXPECT_TRUE(To0->isThisDeclarationADefinition());
    EXPECT_FALSE(To1->isThisDeclarationADefinition());

    CheckPreviousDecl(To0, To1);
  }

  void TypedTest_ImportPrototypes() {
    Decl *FromTU0 = getTuDecl(getPrototype(), Lang_CXX, "input0.cc");
    Decl *FromTU1 = getTuDecl(getPrototype(), Lang_CXX, "input1.cc");
    auto *From0 = FirstDeclMatcher<DeclTy>().match(FromTU0, getPattern());
    auto *From1 = FirstDeclMatcher<DeclTy>().match(FromTU1, getPattern());
    ASSERT_FALSE(From0->isThisDeclarationADefinition());
    ASSERT_FALSE(From1->isThisDeclarationADefinition());

    Decl *Imported0 = Import(From0, Lang_CXX);
    Decl *Imported1 = Import(From1, Lang_CXX);
    Decl *ToTU = Imported0->getTranslationUnitDecl();

    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 2u);
    auto *To0 = FirstDeclMatcher<DeclTy>().match(ToTU, getPattern());
    auto *To1 = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(Imported0 == To0);
    EXPECT_TRUE(Imported1 == To1);
    EXPECT_FALSE(To0->isThisDeclarationADefinition());
    EXPECT_FALSE(To1->isThisDeclarationADefinition());

    CheckPreviousDecl(To0, To1);
  }

  void TypedTest_ImportDefinitions() {
    Decl *FromTU0 = getTuDecl(getDefinition(), Lang_CXX, "input0.cc");
    Decl *FromTU1 = getTuDecl(getDefinition(), Lang_CXX, "input1.cc");
    auto *From0 = FirstDeclMatcher<DeclTy>().match(FromTU0, getPattern());
    auto *From1 = FirstDeclMatcher<DeclTy>().match(FromTU1, getPattern());
    ASSERT_TRUE(From0->isThisDeclarationADefinition());
    ASSERT_TRUE(From1->isThisDeclarationADefinition());

    Decl *Imported0 = Import(From0, Lang_CXX);
    Decl *Imported1 = Import(From1, Lang_CXX);
    Decl *ToTU = Imported0->getTranslationUnitDecl();

    EXPECT_EQ(Imported0, Imported1);
    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 1u);
    auto *To0 = FirstDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(Imported0 == To0);
    EXPECT_TRUE(To0->isThisDeclarationADefinition());
    if (auto *ToT0 = dyn_cast<TemplateDecl>(To0))
      EXPECT_TRUE(ToT0->getTemplatedDecl());
  }

  void TypedTest_ImportDefinitionThenPrototype() {
    Decl *FromTU0 = getTuDecl(getDefinition(), Lang_CXX, "input0.cc");
    Decl *FromTU1 = getTuDecl(getPrototype(), Lang_CXX, "input1.cc");
    auto *FromDef = FirstDeclMatcher<DeclTy>().match(FromTU0, getPattern());
    auto *FromProto = FirstDeclMatcher<DeclTy>().match(FromTU1, getPattern());
    ASSERT_TRUE(FromDef->isThisDeclarationADefinition());
    ASSERT_FALSE(FromProto->isThisDeclarationADefinition());

    Decl *ImportedDef = Import(FromDef, Lang_CXX);
    Decl *ImportedProto = Import(FromProto, Lang_CXX);
    Decl *ToTU = ImportedDef->getTranslationUnitDecl();

    EXPECT_NE(ImportedDef, ImportedProto);
    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 2u);
    auto *ToDef = FirstDeclMatcher<DeclTy>().match(ToTU, getPattern());
    auto *ToProto = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(ImportedDef == ToDef);
    EXPECT_TRUE(ImportedProto == ToProto);
    EXPECT_TRUE(ToDef->isThisDeclarationADefinition());
    EXPECT_FALSE(ToProto->isThisDeclarationADefinition());

    CheckPreviousDecl(ToDef, ToProto);
  }

  void TypedTest_ImportPrototypeThenDefinition() {
    Decl *FromTU0 = getTuDecl(getPrototype(), Lang_CXX, "input0.cc");
    Decl *FromTU1 = getTuDecl(getDefinition(), Lang_CXX, "input1.cc");
    auto *FromProto = FirstDeclMatcher<DeclTy>().match(FromTU0, getPattern());
    auto *FromDef = FirstDeclMatcher<DeclTy>().match(FromTU1, getPattern());
    ASSERT_TRUE(FromDef->isThisDeclarationADefinition());
    ASSERT_FALSE(FromProto->isThisDeclarationADefinition());

    Decl *ImportedProto = Import(FromProto, Lang_CXX);
    Decl *ImportedDef = Import(FromDef, Lang_CXX);
    Decl *ToTU = ImportedDef->getTranslationUnitDecl();

    EXPECT_NE(ImportedDef, ImportedProto);
    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 2u);
    auto *ToProto = FirstDeclMatcher<DeclTy>().match(ToTU, getPattern());
    auto *ToDef = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(ImportedDef == ToDef);
    EXPECT_TRUE(ImportedProto == ToProto);
    EXPECT_TRUE(ToDef->isThisDeclarationADefinition());
    EXPECT_FALSE(ToProto->isThisDeclarationADefinition());

    CheckPreviousDecl(ToProto, ToDef);
  }

  void TypedTest_WholeRedeclChainIsImportedAtOnce() {
    Decl *FromTU = getTuDecl(getPrototype() + getDefinition(), Lang_CXX);
    auto *FromD = // Definition
        LastDeclMatcher<DeclTy>().match(FromTU, getPattern());
    ASSERT_TRUE(FromD->isThisDeclarationADefinition());

    Decl *ImportedD = Import(FromD, Lang_CXX);
    Decl *ToTU = ImportedD->getTranslationUnitDecl();

    // The whole redecl chain is imported at once.
    EXPECT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 2u);
    EXPECT_TRUE(cast<DeclTy>(ImportedD)->isThisDeclarationADefinition());
  }

  void TypedTest_ImportPrototypeThenProtoAndDefinition() {
    {
      Decl *FromTU = getTuDecl(getPrototype(), Lang_CXX, "input0.cc");
      auto *FromD = FirstDeclMatcher<DeclTy>().match(FromTU, getPattern());
      Import(FromD, Lang_CXX);
    }
    {
      Decl *FromTU =
          getTuDecl(getPrototype() + getDefinition(), Lang_CXX, "input1.cc");
      auto *FromD = FirstDeclMatcher<DeclTy>().match(FromTU, getPattern());
      Import(FromD, Lang_CXX);
    }

    Decl *ToTU = ToAST->getASTContext().getTranslationUnitDecl();

    ASSERT_EQ(DeclCounter<DeclTy>().match(ToTU, getPattern()), 3u);
    DeclTy *ProtoD = FirstDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_FALSE(ProtoD->isThisDeclarationADefinition());

    DeclTy *DefinitionD = LastDeclMatcher<DeclTy>().match(ToTU, getPattern());
    EXPECT_TRUE(DefinitionD->isThisDeclarationADefinition());

    EXPECT_TRUE(DefinitionD->getPreviousDecl());
    EXPECT_FALSE(
        DefinitionD->getPreviousDecl()->isThisDeclarationADefinition());

    CheckPreviousDecl(ProtoD, DefinitionD->getPreviousDecl());
  }
};

#define ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(BaseTemplate, TypeParam,       \
                                                TestCase)                      \
  using BaseTemplate##TypeParam = BaseTemplate<TypeParam>;                     \
  TEST_P(BaseTemplate##TypeParam, TestCase) { TypedTest_##TestCase(); }

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, Function,
    PrototypeShouldBeImportedAsAPrototypeWhenThereIsNoDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, Class,
    PrototypeShouldBeImportedAsAPrototypeWhenThereIsNoDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, Variable,
    PrototypeShouldBeImportedAsAPrototypeWhenThereIsNoDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, FunctionTemplate,
    PrototypeShouldBeImportedAsAPrototypeWhenThereIsNoDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, ClassTemplate,
    PrototypeShouldBeImportedAsAPrototypeWhenThereIsNoDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, FunctionTemplateSpec,
    PrototypeShouldBeImportedAsAPrototypeWhenThereIsNoDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, ClassTemplateSpec,
    PrototypeShouldBeImportedAsAPrototypeWhenThereIsNoDefinition)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, Function, DefinitionShouldBeImportedAsADefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, Class, DefinitionShouldBeImportedAsADefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, Variable, DefinitionShouldBeImportedAsADefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, FunctionTemplate, DefinitionShouldBeImportedAsADefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, ClassTemplate, DefinitionShouldBeImportedAsADefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, FunctionTemplateSpec, DefinitionShouldBeImportedAsADefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(
    RedeclChain, ClassTemplateSpec, DefinitionShouldBeImportedAsADefinition)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        ImportPrototypeAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Class,
                                        ImportPrototypeAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        ImportPrototypeAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        ImportPrototypeAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplate,
                                        ImportPrototypeAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        ImportPrototypeAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplateSpec,
                                        ImportPrototypeAfterImportedPrototype)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        ImportDefinitionAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Class,
                                        ImportDefinitionAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        ImportDefinitionAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        ImportDefinitionAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplate,
                                        ImportDefinitionAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        ImportDefinitionAfterImportedPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplateSpec,
                                        ImportDefinitionAfterImportedPrototype)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        ImportPrototypeAfterImportedDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Class,
                                        ImportPrototypeAfterImportedDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        ImportPrototypeAfterImportedDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        ImportPrototypeAfterImportedDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplate,
                                        ImportPrototypeAfterImportedDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        ImportPrototypeAfterImportedDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplateSpec,
                                        ImportPrototypeAfterImportedDefinition)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        ImportPrototypes)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Class, ImportPrototypes)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        ImportPrototypes)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        ImportPrototypes)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplate,
                                        ImportPrototypes)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        ImportPrototypes)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplateSpec,
                                        ImportPrototypes)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        ImportDefinitions)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Class, ImportDefinitions)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        ImportDefinitions)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        ImportDefinitions)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplate,
                                        ImportDefinitions)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        ImportDefinitions)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplateSpec,
                                        ImportDefinitions)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        ImportDefinitionThenPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Class,
                                        ImportDefinitionThenPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        ImportDefinitionThenPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        ImportDefinitionThenPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplate,
                                        ImportDefinitionThenPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        ImportDefinitionThenPrototype)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplateSpec,
                                        ImportDefinitionThenPrototype)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        ImportPrototypeThenDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Class,
                                        ImportPrototypeThenDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        ImportPrototypeThenDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        ImportPrototypeThenDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplate,
                                        ImportPrototypeThenDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        ImportPrototypeThenDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, ClassTemplateSpec,
                                        ImportPrototypeThenDefinition)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        WholeRedeclChainIsImportedAtOnce)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        WholeRedeclChainIsImportedAtOnce)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        WholeRedeclChainIsImportedAtOnce)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        WholeRedeclChainIsImportedAtOnce)

ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Function,
                                        ImportPrototypeThenProtoAndDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, Variable,
                                        ImportPrototypeThenProtoAndDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplate,
                                        ImportPrototypeThenProtoAndDefinition)
ASTIMPORTER_INSTANTIATE_TYPED_TEST_CASE(RedeclChain, FunctionTemplateSpec,
                                        ImportPrototypeThenProtoAndDefinition)

INSTANTIATE_TEST_CASE_P(ParameterizedTests, RedeclChainFunction,
                        DefaultTestValuesForRunOptions, );
INSTANTIATE_TEST_CASE_P(ParameterizedTests, RedeclChainClass,
                        DefaultTestValuesForRunOptions, );
INSTANTIATE_TEST_CASE_P(ParameterizedTests, RedeclChainVariable,
                        DefaultTestValuesForRunOptions, );
INSTANTIATE_TEST_CASE_P(ParameterizedTests, RedeclChainFunctionTemplate,
                        DefaultTestValuesForRunOptions, );
INSTANTIATE_TEST_CASE_P(ParameterizedTests, RedeclChainClassTemplate,
                        DefaultTestValuesForRunOptions, );
INSTANTIATE_TEST_CASE_P(ParameterizedTests, RedeclChainFunctionTemplateSpec,
                        DefaultTestValuesForRunOptions, );
INSTANTIATE_TEST_CASE_P(ParameterizedTests, RedeclChainClassTemplateSpec,
                        DefaultTestValuesForRunOptions, );

} // end namespace ast_matchers
} // end namespace clang
