//===--- CrossTranslationUnit.cpp - -----------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
//  This file implements the CrossTranslationUnit interface.
//
//===----------------------------------------------------------------------===//
#include "clang/CrossTU/CrossTranslationUnit.h"
#include "clang/AST/ASTImporter.h"
#include "clang/AST/Decl.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/CrossTU/CrossTUDiagnostic.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendDiagnostic.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Index/USRGeneration.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>
#include <sstream>

namespace llvm {
// Same as Triple's equality operator, but we check a field only if that is
// known in both instances.
bool hasEqualKnownFields(const Triple &Lhs, const Triple &Rhs) {
  return ((Lhs.getArch() != Triple::UnknownArch &&
           Rhs.getArch() != Triple::UnknownArch)
              ? Lhs.getArch() == Rhs.getArch()
              : true) &&
         ((Lhs.getSubArch() != Triple::NoSubArch &&
           Rhs.getSubArch() != Triple::NoSubArch)
              ? Lhs.getSubArch() == Rhs.getSubArch()
              : true) &&
         ((Lhs.getVendor() != Triple::UnknownVendor &&
           Rhs.getVendor() != Triple::UnknownVendor)
              ? Lhs.getVendor() == Rhs.getVendor()
              : true) &&
         ((Lhs.getOS() != Triple::UnknownOS && Rhs.getOS() != Triple::UnknownOS)
              ? Lhs.getOS() == Rhs.getOS()
              : true) &&
         ((Lhs.getEnvironment() != Triple::UnknownEnvironment &&
           Rhs.getEnvironment() != Triple::UnknownEnvironment)
              ? Lhs.getEnvironment() == Rhs.getEnvironment()
              : true) &&
         ((Lhs.getObjectFormat() != Triple::UnknownObjectFormat &&
           Rhs.getObjectFormat() != Triple::UnknownObjectFormat)
              ? Lhs.getObjectFormat() == Rhs.getObjectFormat()
              : true);
}
}

namespace clang {
namespace cross_tu {

namespace {
#define DEBUG_TYPE "CrossTranslationUnit"
STATISTIC(NumGetCTUCalled, "The # of getCTUDefinition function called");
STATISTIC(NumNoUnit, "The # of getCTUDefinition NoUnit");
STATISTIC(
    NumNotInOtherTU,
    "The # of getCTUDefinition called but the function is not in other TU");
STATISTIC(NumGetCTUSuccess, "The # of getCTUDefinition successfully return the "
                            "requested function's body");
STATISTIC(NumUnsupportedNodeFound, "The # of imports when the ASTImporter "
                                   "encountered an unsupported AST Node");
STATISTIC(NumNameConflicts, "The # of imports when the ASTImporter "
                            "encountered an ODR error");
STATISTIC(NumTripleMismatch, "The # of triple mismatches");
STATISTIC(NumLangMismatch, "The # of language mismatches");

// FIXME: This class is will be removed after the transition to llvm::Error.
class IndexErrorCategory : public std::error_category {
public:
  const char *name() const noexcept override { return "clang.index"; }

  std::string message(int Condition) const override {
    switch (static_cast<index_error_code>(Condition)) {
    case index_error_code::unspecified:
      return "An unknown error has occurred.";
    case index_error_code::missing_index_file:
      return "The index file is missing.";
    case index_error_code::invalid_index_format:
      return "Invalid index file format.";
    case index_error_code::multiple_definitions:
      return "Multiple definitions in the index file.";
    case index_error_code::missing_definition:
      return "Missing definition from the index file.";
    case index_error_code::failed_import:
      return "Failed to import the definition.";
    case index_error_code::failed_to_get_external_ast:
      return "Failed to load external AST source.";
    case index_error_code::failed_to_generate_usr:
      return "Failed to generate USR.";
    case index_error_code::triple_mismatch:
      return "Triple mismatch";
    case index_error_code::lang_mismatch:
      return "Language mismatch";
    }
    llvm_unreachable("Unrecognized index_error_code.");
  }
};

static llvm::ManagedStatic<IndexErrorCategory> Category;
} // end anonymous namespace

char IndexError::ID;

void IndexError::log(raw_ostream &OS) const {
  OS << Category->message(static_cast<int>(Code)) << '\n';
}

std::error_code IndexError::convertToErrorCode() const {
  return std::error_code(static_cast<int>(Code), *Category);
}

llvm::Expected<llvm::StringMap<std::string>>
parseCrossTUIndex(StringRef IndexPath, StringRef CrossTUDir) {
  std::ifstream ExternalFnMapFile(IndexPath);
  if (!ExternalFnMapFile)
    return llvm::make_error<IndexError>(index_error_code::missing_index_file,
                                        IndexPath.str());

  llvm::StringMap<std::string> Result;
  std::string Line;
  unsigned LineNo = 1;
  while (std::getline(ExternalFnMapFile, Line)) {
    const size_t Pos = Line.find(" ");
    if (Pos > 0 && Pos != std::string::npos) {
      StringRef LineRef{Line};
      StringRef FunctionLookupName = LineRef.substr(0, Pos);
      if (Result.count(FunctionLookupName))
        return llvm::make_error<IndexError>(
            index_error_code::multiple_definitions, IndexPath.str(), LineNo);
      StringRef FileName = LineRef.substr(Pos + 1);
      SmallString<256> FilePath = CrossTUDir;
      llvm::sys::path::append(FilePath, FileName);
      Result[FunctionLookupName] = FilePath.str().str();
    } else
      return llvm::make_error<IndexError>(
          index_error_code::invalid_index_format, IndexPath.str(), LineNo);
    LineNo++;
  }
  return Result;
}

std::string
createCrossTUIndexString(const llvm::StringMap<std::string> &Index) {
  std::ostringstream Result;
  for (const auto &E : Index)
    Result << E.getKey().str() << " " << E.getValue() << '\n';
  return Result.str();
}

CrossTranslationUnitContext::CrossTranslationUnitContext(CompilerInstance &CI)
    : CI(CI), Context(CI.getASTContext()) {}

CrossTranslationUnitContext::~CrossTranslationUnitContext() {}

std::string CrossTranslationUnitContext::getLookupName(const NamedDecl *ND) {
  SmallString<128> DeclUSR;
  bool Ret = index::generateUSRForDecl(ND, DeclUSR); (void)Ret;
  assert(!Ret && "Unable to generate USR");
  return DeclUSR.str();
}

/// Recursively visits the function decls of a DeclContext, and looks up a
/// function based on USRs.
const FunctionDecl *
CrossTranslationUnitContext::findFunctionInDeclContext(const DeclContext *DC,
                                                       StringRef LookupFnName) {
  assert(DC && "Declaration Context must not be null");
  for (const Decl *D : DC->decls()) {
    const auto *SubDC = dyn_cast<DeclContext>(D);
    if (SubDC)
      if (const auto *FD = findFunctionInDeclContext(SubDC, LookupFnName))
        return FD;

    const auto *ND = dyn_cast<FunctionDecl>(D);
    const FunctionDecl *ResultDecl;
    if (!ND || !ND->hasBody(ResultDecl))
      continue;
    if (getLookupName(ResultDecl) != LookupFnName)
      continue;
    return ResultDecl;
  }
  return nullptr;
}

llvm::Expected<const FunctionDecl *>
CrossTranslationUnitContext::getCrossTUDefinition(const FunctionDecl *FD,
                                                  StringRef CrossTUDir,
                                                  StringRef IndexName,
                                                  bool DisplayCTUProgress) {
  assert(FD && "FD is missing, bad call to this function!");
  assert(!FD->hasBody() && "FD has a definition in current translation unit!");
  ++NumGetCTUCalled;
  const std::string LookupFnName = getLookupName(FD);
  if (LookupFnName.empty())
    return llvm::make_error<IndexError>(
        index_error_code::failed_to_generate_usr);
  llvm::Expected<ASTUnit *> ASTUnitOrError =
      loadExternalAST(LookupFnName, CrossTUDir, IndexName, DisplayCTUProgress);
  if (!ASTUnitOrError) {
    ++NumNoUnit;
    return ASTUnitOrError.takeError();
  }
  ASTUnit *Unit = *ASTUnitOrError;
  if (!Unit) {
    ++NumNoUnit;
    return llvm::make_error<IndexError>(
        index_error_code::failed_to_get_external_ast);
  }
  assert(&Unit->getFileManager() ==
         &Unit->getASTContext().getSourceManager().getFileManager());
  const auto& TripleTo = Context.getTargetInfo().getTriple();
  const auto& TripleFrom = Unit->getASTContext().getTargetInfo().getTriple();
  // The imported AST had been generated for a different target
  // TODO use equality operator. Note, for some unknown reason when we do
  // in-memory/on-the-fly CTU (i.e when the compilation db is given) some
  // parts of the triple in the loaded ASTContext can be unknown while the
  // very same parts in the target ASTContext are known. Thus we check for
  // the known parts only.
  if (!hasEqualKnownFields(TripleTo, TripleFrom)) {
    // TODO pass the SourceLocation of the CallExpression for more precise
    // diagnostics
    Context.getDiagnostics().Report(diag::err_ctu_incompat_triple)
        << Unit->getMainFileName() << TripleTo.str() << TripleFrom.str();
    ++NumTripleMismatch;
    return llvm::make_error<IndexError>(index_error_code::triple_mismatch);
  }
  const auto& LangTo = Context.getLangOpts();
  const auto& LangFrom = Unit->getASTContext().getLangOpts();

  // We do not support CTU across languages (C vs C++).
  if (LangTo.CPlusPlus != LangFrom.CPlusPlus) {
    ++NumLangMismatch;
    return llvm::make_error<IndexError>(index_error_code::lang_mismatch);
  }

  // If CPP dialects are different then return with error.
  //
  // Consider this STL code:
  //   template<typename _Alloc>
  //     struct __alloc_traits
  //   #if __cplusplus >= 201103L
  //     : std::allocator_traits<_Alloc>
  //   #endif
  //     { // ...
  //     };
  // This class template would create ODR errors during merging the two units,
  // since in one translation unit the class template has a base class, however
  // in the other unit it has none.
  if (LangTo.CPlusPlus11 != LangFrom.CPlusPlus11 ||
      LangTo.CPlusPlus14 != LangFrom.CPlusPlus14 ||
      LangTo.CPlusPlus17 != LangFrom.CPlusPlus17 ||
      LangTo.CPlusPlus2a != LangFrom.CPlusPlus2a) {
    ++NumLangMismatch;
    return llvm::make_error<IndexError>(index_error_code::lang_mismatch);
  }

  TranslationUnitDecl *TU = Unit->getASTContext().getTranslationUnitDecl();
  if (const FunctionDecl *ResultDecl =
          findFunctionInDeclContext(TU, LookupFnName))
    return importDefinition(ResultDecl);
  return llvm::make_error<IndexError>(index_error_code::failed_import);
}

void CrossTranslationUnitContext::emitCrossTUDiagnostics(const IndexError &IE) {
  switch (IE.getCode()) {
  case index_error_code::missing_index_file:
    Context.getDiagnostics().Report(diag::err_fe_error_opening)
        << IE.getFileName() << "required by the CrossTU functionality";
    break;
  case index_error_code::invalid_index_format:
    Context.getDiagnostics().Report(diag::err_fnmap_parsing)
        << IE.getFileName() << IE.getLineNum();
    break;
  case index_error_code::multiple_definitions:
    Context.getDiagnostics().Report(diag::err_multiple_def_index)
        << IE.getLineNum();
    break;
  default:
    break;
  }
}

llvm::Expected<ASTUnit *> CrossTranslationUnitContext::loadExternalAST(
    StringRef LookupName, StringRef CrossTUDir, StringRef IndexName,
    bool DisplayCTUProgress) {
  // FIXME: The current implementation only supports loading functions with
  //        a lookup name from a single translation unit. If multiple
  //        translation units contains functions with the same lookup name an
  //        error will be returned.
  ASTUnit *Unit = nullptr;
  auto FnUnitCacheEntry = FunctionASTUnitMap.find(LookupName);
  if (FnUnitCacheEntry == FunctionASTUnitMap.end()) {
    if (FunctionFileMap.empty()) {
      SmallString<256> IndexFile = CrossTUDir;
      if (llvm::sys::path::is_absolute(IndexName))
        IndexFile = IndexName;
      else
        llvm::sys::path::append(IndexFile, IndexName);
      llvm::Expected<llvm::StringMap<std::string>> IndexOrErr =
          parseCrossTUIndex(IndexFile, CrossTUDir);
      if (IndexOrErr)
        FunctionFileMap = *IndexOrErr;
      else
        return IndexOrErr.takeError();
    }

    auto It = FunctionFileMap.find(LookupName);
    if (It == FunctionFileMap.end()) {
      ++NumNotInOtherTU;
      return llvm::make_error<IndexError>(index_error_code::missing_definition);
    }
    StringRef ASTFileName = It->second;
    auto ASTCacheEntry = FileASTUnitMap.find(ASTFileName);
    if (ASTCacheEntry == FileASTUnitMap.end()) {
      IntrusiveRefCntPtr<DiagnosticOptions> DiagOpts = new DiagnosticOptions();
      TextDiagnosticPrinter *DiagClient =
          new TextDiagnosticPrinter(llvm::errs(), &*DiagOpts);
      IntrusiveRefCntPtr<DiagnosticIDs> DiagID(new DiagnosticIDs());
      IntrusiveRefCntPtr<DiagnosticsEngine> Diags(
          new DiagnosticsEngine(DiagID, &*DiagOpts, DiagClient));

      std::unique_ptr<ASTUnit> LoadedUnit(ASTUnit::LoadFromASTFile(
          ASTFileName, CI.getPCHContainerOperations()->getRawReader(),
          ASTUnit::LoadEverything, Diags, CI.getFileSystemOpts()));
      Unit = LoadedUnit.get();
      FileASTUnitMap[ASTFileName] = std::move(LoadedUnit);
      if (DisplayCTUProgress) {
        llvm::errs() << "ANALYZE (CTU loaded AST for source file): "
                     // Drop the ".ast" extension.
                     << ASTFileName.drop_back(4) << "\n";
      }
    } else {
      Unit = ASTCacheEntry->second.get();
    }
    FunctionASTUnitMap[LookupName] = Unit;
  } else {
    Unit = FnUnitCacheEntry->second;
  }
  return Unit;
}

llvm::Expected<const FunctionDecl *>
CrossTranslationUnitContext::importDefinition(const FunctionDecl *FD) {
  assert(FD->hasBody() && "Functions to be imported should have body.");

  ASTImporter &Importer = getOrCreateASTImporter(FD->getASTContext());
  auto ToDeclOrError = Importer.Import(FD);
  if (!ToDeclOrError) {
    handleAllErrors(ToDeclOrError.takeError(),
                    [&](const ImportError &IE) {
                      switch (IE.Error) {
                      case ImportError::NameConflict:
                        ++NumNameConflicts;
                        break;
                      case ImportError::UnsupportedConstruct:
                        ++NumUnsupportedNodeFound;
                        break;
                      case ImportError::Unknown:
                        llvm_unreachable("Unknown import error happened.");
                        break;
                      }
                    });
    return llvm::make_error<IndexError>(index_error_code::failed_import);
  }
  auto *ToDecl = cast<FunctionDecl>(*ToDeclOrError);
  assert(ToDecl->hasBody());
  ++NumGetCTUSuccess;
  return ToDecl;
}

void CrossTranslationUnitContext::lazyInitLookupTable(
    TranslationUnitDecl *ToTU) {
  if (LookupTable)
    return;
  LookupTable = llvm::make_unique<ASTImporterLookupTable>(*ToTU);
}

ASTImporter &
CrossTranslationUnitContext::getOrCreateASTImporter(ASTContext &From) {
  auto I = ASTUnitImporterMap.find(From.getTranslationUnitDecl());
  if (I != ASTUnitImporterMap.end())
    return *I->second;
  lazyInitLookupTable(Context.getTranslationUnitDecl());
  ASTImporter *NewImporter = new ASTImporter(
      LookupTable.get(), Context, Context.getSourceManager().getFileManager(), From,
      From.getSourceManager().getFileManager(), false);
  ASTUnitImporterMap[From.getTranslationUnitDecl()].reset(NewImporter);
  return *NewImporter;
}

} // namespace cross_tu
} // namespace clang
