#include "ClangSACheckers.h"
#include "clang/AST/ExprObjC.h"
#include "clang/AST/ExprOpenMP.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerHelpers.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include <utility>
using namespace clang;
using namespace ento;
using namespace loc;

#include "MemFuncsIdentification.h"

namespace {


class DoubleFreeChecker : public Checker<check::PostCall,
                                           check::PreCall,
                                           check::Location,
                                           eval::Assume> {
  std::unique_ptr<BuiltinBug> BT_null;
  std::unique_ptr<BugType> DoubleFreeBugType;
  std::unique_ptr<BugType> uafBugType;

  void reportDoubleFree(SymbolRef MemDescSym,
                         const CallEvent &Call,
                         CheckerContext &C) const;
  void reportNullDefBug(ProgramStateRef State, const Stmt *S,
                                   CheckerContext &C,SymbolRef Sym) const;
  
  void reportUseAfterFree(SVal mem,const Stmt *stmt,
                                          CheckerContext &C) const;

  mutable MemFuncsUtility MemUtility;
public:
  DoubleFreeChecker();
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                        CheckerContext &) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  ProgramStateRef evalAssume(ProgramStateRef state, SVal Cond,
                            bool Assumption) const;

  static void AddDerefSource(raw_ostream &os,
                             SmallVectorImpl<SourceRange> &Ranges,
                             const Expr *Ex, const ProgramState *state,
                             const LocationContext *LCtx,
                             bool loadedFrom = false);
  class DoubleFreeBugVisitor final : public BugReporterVisitor {

   public:
  SymbolRef Sym;
  DoubleFreeBugVisitor(SymbolRef s):Sym(s){}
  std::shared_ptr<PathDiagnosticPiece> VisitNode(const ExplodedNode *N,
                                                   const ExplodedNode *PrevN,
                                                   BugReporterContext &BRC,
                                                   BugReport &BR) override;
  void Profile(llvm::FoldingSetNodeID &ID) const override {
      return;
    }
  std::shared_ptr<PathDiagnosticPiece>
    getEndPath(BugReporterContext &BRC, const ExplodedNode *EndPathNode,
               BugReport &BR) override {
      PathDiagnosticLocation L =
        PathDiagnosticLocation::createEndOfPath(EndPathNode,
                                                BRC.getSourceManager());
      // Do not add the statement itself as a range in case of leak.
      return std::make_shared<PathDiagnosticEventPiece>(L, BR.getDescription(),
                                                         false);
    }
};


};

} // end anonymous namespace

// The state of the checker is a map from tracked stream symbols to their
// state. Let's store it in the ProgramState.
REGISTER_SET_WITH_PROGRAMSTATE(FreedMemSymSet,SymbolRef) 
REGISTER_SET_WITH_PROGRAMSTATE(AllocMemSymSet,SymbolRef) 
REGISTER_MAP_WITH_PROGRAMSTATE(ReallocMap,SymbolRef,SymbolRef)
REGISTER_SET_WITH_PROGRAMSTATE(MallocUsedSet,SymbolRef)
std::shared_ptr<PathDiagnosticPiece> DoubleFreeChecker::DoubleFreeBugVisitor::VisitNode(const ExplodedNode *N,
                                                   const ExplodedNode *PrevN,
                                                   BugReporterContext &BRC,
                                                   BugReport &BR)
                                                   {
  ProgramStateRef state = N->getState();
  ProgramStateRef statePrev = PrevN->getState();
  const Stmt *S = PathDiagnosticLocation::getStmt(N);
  if(!S)
    return nullptr;
  PathDiagnosticLocation  Pos = PathDiagnosticLocation(S, BRC.getSourceManager(),
                                 N->getLocationContext());
  StringRef Msg;
  StackHintGeneratorForSymbol *StackHint = nullptr;
  if(state->contains<FreedMemSymSet>(Sym) && !statePrev->contains<FreedMemSymSet>(Sym))
  {
    Msg = "memory is freed!";
    StackHint = new StackHintGeneratorForSymbol(Sym,
                                                  "function free memory!");
  }
  else if(state->contains<AllocMemSymSet>(Sym) && !statePrev->contains<AllocMemSymSet>(Sym))
  {
    Msg = "memory is allocated!";
    StackHint = new StackHintGeneratorForSymbol(Sym,
                                                  "function allocate memory!");
  }
  else{
    return nullptr;
  }
  return std::make_shared<PathDiagnosticEventPiece>(Pos, Msg, true, StackHint);

}
void
DoubleFreeChecker::AddDerefSource(raw_ostream &os,
                                   SmallVectorImpl<SourceRange> &Ranges,
                                   const Expr *Ex,
                                   const ProgramState *state,
                                   const LocationContext *LCtx,
                                   bool loadedFrom) {
  Ex = Ex->IgnoreParenLValueCasts();
  switch (Ex->getStmtClass()) {
    default:
      break;
    case Stmt::DeclRefExprClass: {
      const DeclRefExpr *DR = cast<DeclRefExpr>(Ex);
      if (const VarDecl *VD = dyn_cast<VarDecl>(DR->getDecl())) {
        os << " (" << (loadedFrom ? "loaded from" : "from")
           << " variable '" <<  VD->getName() << "')";
        Ranges.push_back(DR->getSourceRange());
      }
      break;
    }
    case Stmt::MemberExprClass: {
      const MemberExpr *ME = cast<MemberExpr>(Ex);
      os << " (" << (loadedFrom ? "loaded from" : "via")
         << " field '" << ME->getMemberNameInfo() << "')";
      SourceLocation L = ME->getMemberLoc();
      Ranges.push_back(SourceRange(L, L));
      break;
    }
    case Stmt::ObjCIvarRefExprClass: {
      const ObjCIvarRefExpr *IV = cast<ObjCIvarRefExpr>(Ex);
      os << " (" << (loadedFrom ? "loaded from" : "via")
         << " ivar '" << IV->getDecl()->getName() << "')";
      SourceLocation L = IV->getLocation();
      Ranges.push_back(SourceRange(L, L));
      break;
    }
  }
}
void DoubleFreeChecker::reportNullDefBug(ProgramStateRef State, const Stmt *S,
                                   CheckerContext &C,SymbolRef Sym) const {
  // Generate an error node.
  ExplodedNode *N = C.generateNonFatalErrorNode(State);
  if (!N)
    return;

  // We know that 'location' cannot be non-null.  This is what
  // we call an "explicit" null dereference.


  SmallString<100> buf;
  llvm::raw_svector_ostream os(buf);

  SmallVector<SourceRange, 2> Ranges;

  switch (S->getStmtClass()) {
  case Stmt::ArraySubscriptExprClass: {
    os << "Array access";
    const ArraySubscriptExpr *AE = cast<ArraySubscriptExpr>(S);
    AddDerefSource(os, Ranges, AE->getBase()->IgnoreParenCasts(),
                   State.get(), N->getLocationContext());
    os << " results in a null pointer dereference";
    break;
  }
  case Stmt::OMPArraySectionExprClass: {
    os << "Array access";
    const OMPArraySectionExpr *AE = cast<OMPArraySectionExpr>(S);
    AddDerefSource(os, Ranges, AE->getBase()->IgnoreParenCasts(),
                   State.get(), N->getLocationContext());
    os << " results in a null pointer dereference";
    break;
  }
  case Stmt::UnaryOperatorClass: {
    os << "Dereference of null pointer";
    const UnaryOperator *U = cast<UnaryOperator>(S); 
    \
    AddDerefSource(os, Ranges, U->getSubExpr()->IgnoreParens(),
                   State.get(), N->getLocationContext(), true);
    break;
  }
  case Stmt::MemberExprClass: {
    const MemberExpr *M = cast<MemberExpr>(S);
    if (M->isArrow() || bugreporter::isDeclRefExprToReference(M->getBase())) {
      os << "Access to field '" << M->getMemberNameInfo()
         << "' results in a dereference of a null pointer";
      AddDerefSource(os, Ranges, M->getBase()->IgnoreParenCasts(),
                     State.get(), N->getLocationContext(), true);
    }
    break;
  }
  case Stmt::ObjCIvarRefExprClass: {
    const ObjCIvarRefExpr *IV = cast<ObjCIvarRefExpr>(S);
    os << "Access to instance variable '" << *IV->getDecl()
       << "' results in a dereference of a null pointer";
    AddDerefSource(os, Ranges, IV->getBase()->IgnoreParenCasts(),
                   State.get(), N->getLocationContext(), true);
    break;
  }
  default:
    break;
  }

  auto report = llvm::make_unique<BugReport>(
      *BT_null, buf.empty() ? BT_null->getDescription() : StringRef(buf), N);

  bugreporter::trackNullOrUndefValue(N, bugreporter::getDerefExpr(S), *report);

  for (SmallVectorImpl<SourceRange>::iterator
       I = Ranges.begin(), E = Ranges.end(); I!=E; ++I)
    report->addRange(*I);
  report->addVisitor(llvm::make_unique<DoubleFreeBugVisitor>(Sym));
  C.emitReport(std::move(report));
}

DoubleFreeChecker::DoubleFreeChecker()
{
  // Initialize the bug types.
  DoubleFreeBugType.reset(
      new BugType(this, "wjq-Double free", "Unix Mem Alloc API Error"));
   BT_null.reset(new BuiltinBug(this, "wjq-Dereference of null pointer"));
  uafBugType.reset(
      new BugType(this,"wjq-use after free","Unix Mem Alloc API Error"));
}
bool mustBeZero(ProgramStateRef State,SymbolRef Sym)
{
  if(!State || !Sym)
    return false;
  ConstraintManager &CMgr = State->getConstraintManager();
  ConditionTruthVal truth = CMgr.isNull(State, Sym);
  return truth.isConstrainedTrue();
}

bool canBeZero(CheckerContext &C,SymbolRef Sym)
{
  if(!Sym)
    return true;
  SValBuilder & svalbuilder = C.getSValBuilder();
  SVal s = svalbuilder.makeSymbolVal(Sym);
  DefinedOrUnknownSVal val = s.castAs<DefinedOrUnknownSVal>();
  ProgramStateRef state = C.getState();

  ProgramStateRef notNullState, nullState;
  std::tie(notNullState, nullState) = state->assume(val);
  return (bool)nullState;
}

ProgramStateRef freeMem(ProgramStateRef State,SymbolRef FreedMemDesc)
{
  if(!FreedMemDesc)
      return State;
  if(State->contains<AllocMemSymSet>(FreedMemDesc))
  {
    State = State->remove<AllocMemSymSet>(FreedMemDesc);
  }
  State = State->add<FreedMemSymSet>(FreedMemDesc);
  return State;
}
ProgramStateRef allocateMem(ProgramStateRef State,SymbolRef Sym)
{
  if(!Sym)
    return State;
  if(State->contains<FreedMemSymSet>(Sym))
  {
    State = State->remove<FreedMemSymSet>(Sym);
  }
  State = State->add<AllocMemSymSet>(Sym);
  return State;
}
void DoubleFreeChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
  if(!Call.getDecl())
    return;
  if(!Call.getDecl()->isFunctionOrFunctionTemplate ())
    return;                                   
  if (Call.getDecl()->getAsFunction()->hasBody())
    return;
  ProgramStateRef State = C.getState();
  if (WJQ_FUNC *func = MemUtility.isAllocFunction(Call))
  {

    SymbolRef MemDesc = Call.getReturnValue().getAsSymbol();
    if (!MemDesc)
      return;
    State = allocateMem(State,MemDesc);
  }
  if (WJQ_FUNC *func = MemUtility.isReallocFunction(Call))
  {

      SymbolRef RetMemDesc = Call.getReturnValue().getAsSymbol();
      SymbolRef FreedMemDesc = Call.getArgSVal(func->pointerarg_index).getAsSymbol();
      if(!RetMemDesc || !FreedMemDesc)
        return;
      State = State->set<ReallocMap>(FreedMemDesc,RetMemDesc);
      State = allocateMem(State,RetMemDesc);
      State = freeMem(State,FreedMemDesc);
      delete func;
  }
  if (WJQ_FUNC *func = MemUtility.isFreeFunction(Call))
  {
    SymbolRef MemDesc = Call.getArgSVal(func->pointerarg_index).getAsSymbol();
    if (!MemDesc)
      return;
    if(State->contains<FreedMemSymSet>(MemDesc))
    {
      reportDoubleFree(MemDesc,Call,C);
      return;
    }
    State = freeMem(State,MemDesc);
    delete func;
  }
  C.addTransition(State);
}


void DoubleFreeChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {

  return;
}
ProgramStateRef DoubleFreeChecker::evalAssume(ProgramStateRef state,
                                              SVal Cond,
                                              bool Assumption) const {
                                                
    ReallocMapTy RM = state->get<ReallocMap>();
    for (ReallocMapTy::iterator I = RM.begin(), E = RM.end(); I != E; ++I) {
      if(mustBeZero(state,I.getData()))
      {
        state = allocateMem(state,I.getKey());
        state = state->remove<ReallocMap>(I.getKey());
      }
    }
    return state;
}

bool isFreedMem(CheckerContext &C,SVal &s,SymbolRef *base)
{
  SymbolRef Sym = s.getLocSymbolInBase();
  if(!Sym)
    return false;
  if (base)
    *base = Sym;
  bool hasSym= C.getState()->contains<FreedMemSymSet>(Sym);
  return hasSym;
}
bool isAllocatedMem(CheckerContext &C,SVal &s,SymbolRef *base)
{
  SymbolRef Sym = s.getLocSymbolInBase();
  if(!Sym)
    return false;
  if (base)
    *base = Sym;
  bool hasSym= C.getState()->contains<AllocMemSymSet>(Sym);
  return hasSym;
}
void DoubleFreeChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                        CheckerContext &C) const
                        {
  SymbolRef base;
  ProgramStateRef state = C.getState();
  bool isfreed = isFreedMem(C,Loc,nullptr);
  if(isfreed)
  {
    reportUseAfterFree(Loc,S,C);
  }
  if(state->contains<MallocUsedSet>(base))
    return;
  bool isAllocated = isAllocatedMem(C,Loc,&base);
  if (isAllocated && canBeZero(C,base))
  {
    state->add<MallocUsedSet>(base);
    reportNullDefBug(C.getState(),S,C,base);
  }

}


void DoubleFreeChecker::reportDoubleFree(SymbolRef MemDescSym,
                                            const CallEvent &Call,
                                            CheckerContext &C) const {
  // We reached a bug, stop exploring the path here by generating a sink.
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;

  // Generate the report.
  auto R = llvm::make_unique<BugReport>(*DoubleFreeBugType,
      "Freeing a previously free mem region", ErrNode);
  R->addRange(Call.getSourceRange());
  R->markInteresting(MemDescSym);
  R->addVisitor(llvm::make_unique<DoubleFreeBugVisitor>(MemDescSym));
  C.emitReport(std::move(R));
}
void DoubleFreeChecker::reportUseAfterFree(SVal mem,
                                          const Stmt *stmt,
                                          CheckerContext &C) const{
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;
  auto R = llvm::make_unique<BugReport>(*DoubleFreeBugType,
      "using a freed memory", ErrNode);
  R->addRange(stmt->getSourceRange());
  R->markInteresting(mem);
  
  R->addVisitor(llvm::make_unique<DoubleFreeBugVisitor>(mem.getAsSymbol()));
  C.emitReport(std::move(R));
                                          
}



void ento::registerDoubleFreeChecker(CheckerManager &mgr) {
  mgr.registerChecker<DoubleFreeChecker>();
}
