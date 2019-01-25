//===- ClangDisplayContext.cpp ------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===--------------------------------------------------------------------===//
//
// Clang tool which generates and outputs an issue string 
// from the location (line, column number) of the issue. 
// The format of the string is similar to the Static Analyzer's GetIssueString
// function's result, defined in lib/StaticAnalyzer/Core/IssueHash.cpp.
//
//===--------------------------------------------------------------------===//

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/ExprCXX.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/StaticAnalyzer/Core/IssueHash.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/Signals.h"

using namespace llvm;
using namespace clang;
using namespace clang::tooling;

static cl::OptionCategory ClangDispContCategory("clang-disp-context options");

static cl::list<unsigned> Lines(
    "line",
    cl::desc("Line number of the issue's position. \n"),
    cl::cat(ClangDispContCategory), cl::OneOrMore);

static cl::list<unsigned> Columns(
    "column",
    cl::desc("Column number of the issue's position. \n"),
    cl::cat(ClangDispContCategory), cl::OneOrMore);

class DisplayContextConsumer : public ASTConsumer {
public:
  DisplayContextConsumer(ASTContext &Context) : Ctx(Context) {}

  void HandleTranslationUnit(ASTContext &Ctx) override {
    if (!Ctx.getDiagnostics().hasErrorOccurred()) {
      for (unsigned i = 0; i != Lines.size(); ++i) {
        Line = Lines[i];
        Column = Columns[i];
        setIssueStringToDefault();
        handleDecl(Ctx.getTranslationUnitDecl());
        outs() << IssueString << "\n";
      }
    }
  }

private:
  template <typename T> 
  bool checkIfInteresting(const T *N);
  void handleDecl(const Decl *D);
  void handleStmt(const Stmt *S);
  bool setEnclosingDecl(const Decl *D);
  void setIssueString(const std::string &S);
  void setIssueStringToDefault();
  
  ASTContext &Ctx;
  FullSourceLoc IssueLoc;
  std::string IssueString;
  const Decl *EnclosingDecl;

  unsigned Line;
  unsigned Column;
};

template <typename T>
bool DisplayContextConsumer::checkIfInteresting(const T *Node) {
  // Nodes are only interesting if they contain the line with the issue.
  if (!Node)
    return false;

  if (!Ctx.getSourceManager().isInMainFile(Node->getLocStart()))
    return false;

  FullSourceLoc L1 = Ctx.getFullLoc(Node->getLocStart());
  FullSourceLoc L2 = 
    Ctx.getFullLoc(Lexer::getLocForEndOfToken(Node->getLocEnd(), 0,
                          Ctx.getSourceManager(), Ctx.getLangOpts()));
  
  if (!L1.isValid() || !L2.isValid())
    return false;

  if (Line == L1.getExpansionLineNumber() && 
      Line == L2.getExpansionLineNumber())
    return Column <= L2.getExpansionColumnNumber() &&
           L1.getExpansionColumnNumber() <= Column;

  return Line <= L2.getExpansionLineNumber() &&
         L1.getExpansionLineNumber() <= Line;
}

void DisplayContextConsumer::handleDecl(const Decl *D) {
  if (!D)
    return;

  if (const auto *TD = dyn_cast<TemplateDecl>(D))
    D = TD->getTemplatedDecl();
  
  if (const auto *DC = dyn_cast<DeclContext>(D)) {
    for (const Decl *D : DC->decls()) {
      if (!checkIfInteresting<Decl>(D))
        continue;

      handleDecl(D);
      return;
    }
  }
  
  if (!setEnclosingDecl(D))
    return;

  IssueLoc = Ctx.getFullLoc(D->getLocation()).getExpansionLoc();
  
  handleStmt(D->getBody());
  
  if (!IssueLoc.isValid() || IssueLoc.getExpansionLineNumber() != Line)
    return;

  setIssueString(GetIssueString(Ctx.getSourceManager(), IssueLoc, "",
                                "", EnclosingDecl, Ctx.getLangOpts()));
}

void DisplayContextConsumer::handleStmt(const Stmt *S) {
  if (!checkIfInteresting<Stmt>(S))
    return;

  IssueLoc = Ctx.getFullLoc(S->getLocStart()).getExpansionLoc();
  
  if (const LambdaExpr *LE = dyn_cast<LambdaExpr>(S))
    EnclosingDecl = LE->getCallOperator();

  for (const Stmt *Child : S->children())
    handleStmt(Child);
}

bool DisplayContextConsumer::setEnclosingDecl(const Decl *D) {
  // If the issue is located in a ValueDecl which is not
  // a FunctionDecl, traverse up until the enclosing context is found.
  // This function aims to solve issues especially with VarDecls.
  while (isa<ValueDecl>(D) && !isa<FunctionDecl>(D)) {
    D = dyn_cast<Decl>(D->getDeclContext());
  }
  EnclosingDecl = D;
  return EnclosingDecl->getLocation().isValid();
}

void DisplayContextConsumer::setIssueString(const std::string &SAIssue) {
  // Since Location is provided as a range, the IssueString from Clang SA
  // has to be modified by replacing the column number, and removing
  // the first and last '$' delimeters (CheckerName and BugType not provided).
  // Original function definition is in lib/StaticAnalyzer/Core/IssueHash.cpp,
  // if that changes, this function might not provide satisfactory results.
  Regex Rx(R"(\$[0-9]+\$)");
  IssueString = Rx.sub("$" + Twine(Column).str() + "$",
                       SAIssue.substr(1, SAIssue.size() - 2));
}

void DisplayContextConsumer::setIssueStringToDefault() {
  IssueString.clear();
  raw_string_ostream IS(IssueString);
  IS << "Line " << Line << " and column "
     << Column << " do not specify an issue.";
}

class DisplayContextAction : public ASTFrontendAction {
protected:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef) {
    std::unique_ptr<ASTConsumer> PFC(
        new DisplayContextConsumer(CI.getASTContext()));
    return PFC;
  }
};

int main(int argc, const char **argv) {
  sys::PrintStackTraceOnErrorSignal(argv[0], false);
  PrettyStackTraceProgram X(argc, argv);

  const char *Overview = "\n This tool generates and prints an issue string "
                         "(similar to Clang Static Analyzer's IssueString) "
                         "from the position of the issue in the source. \n";
  CommonOptionsParser OptionsParser(argc, argv, ClangDispContCategory,
                                    cl::Required, Overview);

  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());
  
  if (Lines.size() != Columns.size()) {
    errs() << "Number of lines and columns must be the same. \n";
    return 1;
  }

  return Tool.run(newFrontendActionFactory<DisplayContextAction>().get());
}

