//===- unittest/AST/ASTImporterFixtures.cpp - AST unit test support -------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "ASTImporterFixtures.h"

#include "clang/AST/ASTImporter.h"
#include "clang/AST/ASTImporterLookupTable.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Tooling/Tooling.h"

namespace clang {
namespace ast_matchers {

void createVirtualFileIfNeeded(ASTUnit *ToAST, StringRef FileName,
                               std::unique_ptr<llvm::MemoryBuffer> &&Buffer) {
  assert(ToAST);
  ASTContext &ToCtx = ToAST->getASTContext();
  auto *OFS = static_cast<vfs::OverlayFileSystem *>(
      ToCtx.getSourceManager().getFileManager().getVirtualFileSystem().get());
  auto *MFS =
      static_cast<vfs::InMemoryFileSystem *>(OFS->overlays_begin()->get());
  MFS->addFile(FileName, 0, std::move(Buffer));
}

void createVirtualFileIfNeeded(ASTUnit *ToAST, StringRef FileName,
                                      StringRef Code) {
  return createVirtualFileIfNeeded(ToAST, FileName,
                                   llvm::MemoryBuffer::getMemBuffer(Code));
}

ASTImporterTestBase::TU::TU(StringRef Code, StringRef FileName, ArgVector Args)
    : Code(Code), FileName(FileName),
      Unit(tooling::buildASTFromCodeWithArgs(this->Code, Args, this->FileName)),
      TUDecl(Unit->getASTContext().getTranslationUnitDecl()) {
  Unit->enableSourceFileDiagnostics();
}

void ASTImporterTestBase::TU::lazyInitImporter(
    ASTImporterLookupTable &LookupTable, ASTUnit *ToAST) {
  assert(ToAST);
  if (!Importer) {
    Importer.reset(new ASTImporter(
        &LookupTable, ToAST->getASTContext(), ToAST->getFileManager(),
        Unit->getASTContext(), Unit->getFileManager(), false));
  }
  assert(&ToAST->getASTContext() == &Importer->getToContext());
  createVirtualFileIfNeeded(ToAST, FileName, Code);
}

Decl *ASTImporterTestBase::TU::import(ASTImporterLookupTable &LookupTable,
                                      ASTUnit *ToAST, Decl *FromDecl) {
  lazyInitImporter(LookupTable, ToAST);
  if (auto ImportedOrErr = Importer->Import(FromDecl))
    return *ImportedOrErr;
  else {
    llvm::consumeError(ImportedOrErr.takeError());
    return nullptr;
  }
}

QualType ASTImporterTestBase::TU::import(ASTImporterLookupTable &LookupTable,
                                         ASTUnit *ToAST, QualType FromType) {
  lazyInitImporter(LookupTable, ToAST);
  if (auto ImportedOrErr = Importer->Import(FromType))
    return *ImportedOrErr;
  else {
    llvm::consumeError(ImportedOrErr.takeError());
    return QualType{};
  }
}

ASTImporterTestBase::TU::~TU() {}

void ASTImporterTestBase::lazyInitLookupTable(TranslationUnitDecl *ToTU) {
  assert(ToTU);
  if (LookupTablePtr)
    return;
  LookupTablePtr = llvm::make_unique<ASTImporterLookupTable>(*ToTU);
}

void ASTImporterTestBase::lazyInitToAST(Language ToLang, StringRef ToSrcCode,
                                        StringRef FileName) {
  if (ToAST)
    return;
  ArgVector ToArgs = getArgVectorForLanguage(ToLang);
  // Source code must be a valid live buffer through the tests lifetime.
  ToCode = ToSrcCode;
  // Build the AST from an empty file.
  ToAST = tooling::buildASTFromCodeWithArgs(ToCode, ToArgs, FileName);
  ToAST->enableSourceFileDiagnostics();
  lazyInitLookupTable(ToAST->getASTContext().getTranslationUnitDecl());
}

ASTImporterTestBase::TU *ASTImporterTestBase::findFromTU(Decl *From) {
  // Create a virtual file in the To Ctx which corresponds to the file from
  // which we want to import the `From` Decl. Without this source locations
  // will be invalid in the ToCtx.
  auto It = std::find_if(FromTUs.begin(), FromTUs.end(), [From](const TU &E) {
    return E.TUDecl == From->getTranslationUnitDecl();
  });
  assert(It != FromTUs.end());
  return &*It;
}

std::tuple<Decl *, Decl *>
ASTImporterTestBase::getImportedDecl(StringRef FromSrcCode, Language FromLang,
                                     StringRef ToSrcCode, Language ToLang,
                                     StringRef Identifier) {
  ArgVector FromArgs = getArgVectorForLanguage(FromLang),
            ToArgs = getArgVectorForLanguage(ToLang);

  FromTUs.emplace_back(FromSrcCode, InputFileName, FromArgs);
  TU &FromTU = FromTUs.back();

  assert(!ToAST);
  lazyInitToAST(ToLang, ToSrcCode, OutputFileName);

  ASTContext &FromCtx = FromTU.Unit->getASTContext();

  IdentifierInfo *ImportedII = &FromCtx.Idents.get(Identifier);
  assert(ImportedII && "Declaration with the given identifier "
                       "should be specified in test!");
  DeclarationName ImportDeclName(ImportedII);
  SmallVector<NamedDecl *, 1> FoundDecls;
  FromCtx.getTranslationUnitDecl()->localUncachedLookup(ImportDeclName,
                                                        FoundDecls);

  assert(FoundDecls.size() == 1);

  Decl *Imported =
      FromTU.import(*LookupTablePtr, ToAST.get(), FoundDecls.front());

  assert(Imported);
  return std::make_tuple(*FoundDecls.begin(), Imported);
}

TranslationUnitDecl *ASTImporterTestBase::getTuDecl(StringRef SrcCode,
                                                    Language Lang,
                                                    StringRef FileName) {
  assert(std::find_if(FromTUs.begin(), FromTUs.end(), [FileName](const TU &E) {
           return E.FileName == FileName;
         }) == FromTUs.end());

  ArgVector Args = getArgVectorForLanguage(Lang);
  FromTUs.emplace_back(SrcCode, FileName, Args);
  TU &Tu = FromTUs.back();

  return Tu.TUDecl;
}

TranslationUnitDecl *ASTImporterTestBase::getToTuDecl(StringRef ToSrcCode,
                                                      Language ToLang) {
  ArgVector ToArgs = getArgVectorForLanguage(ToLang);
  assert(!ToAST);
  lazyInitToAST(ToLang, ToSrcCode, OutputFileName);
  return ToAST->getASTContext().getTranslationUnitDecl();
}

Decl *ASTImporterTestBase::Import(Decl *From, Language ToLang) {
  lazyInitToAST(ToLang, "", OutputFileName);
  TU *FromTU = findFromTU(From);
  assert(LookupTablePtr);
  return FromTU->import(*LookupTablePtr, ToAST.get(), From);
}

QualType ASTImporterTestBase::ImportType(QualType FromType, Decl *TUDecl,
                                         Language ToLang) {
  lazyInitToAST(ToLang, "", OutputFileName);
  TU *FromTU = findFromTU(TUDecl);
  assert(LookupTablePtr);
  return FromTU->import(*LookupTablePtr, ToAST.get(), FromType);
}

ASTImporterTestBase::~ASTImporterTestBase() {
  if (!::testing::Test::HasFailure())
    return;

  for (auto &Tu : FromTUs) {
    assert(Tu.Unit);
    llvm::errs() << "FromAST:\n";
    Tu.Unit->getASTContext().getTranslationUnitDecl()->dump();
    llvm::errs() << "\n";
  }
  if (ToAST) {
    llvm::errs() << "ToAST:\n";
    ToAST->getASTContext().getTranslationUnitDecl()->dump();
  }
}

} // end namespace ast_matchers
} // end namespace clang
