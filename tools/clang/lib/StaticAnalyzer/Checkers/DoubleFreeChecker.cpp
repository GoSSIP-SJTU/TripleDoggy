//==---DoubleFreeChecker.cpp ------------------------------*- C++ -*-==//
//
//
// This file is distributed under the Apache Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This checker checks double-free,use after free(UAF),memory leak vulnerabilities.
//
//===----------------------------------------------------------------------===//


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
typedef SmallVector<SymbolRef, 2> SymbolVector;

class DoubleFreeChecker : public Checker<check::PostCall,
                                           check::PreCall,
                                           check::DeadSymbols,
                                           check::Location,
                                           check::Bind,
                                           check::PointerEscape> {

  std::unique_ptr<BugType> DoubleFreeBugType;
  std::unique_ptr<BugType> LeakBugType;
  std::unique_ptr<BugType> uafBugType;
  
  void reportDoubleFree(SymbolRef MemDescSym,
                         const CallEvent &Call,
                         CheckerContext &C) const;

  void reportLeaks(ArrayRef<SymbolRef> LeakedMems, CheckerContext &C,
                   ExplodedNode *ErrNode) const;
  void reportUseAfterFree(SVal mem,const Stmt *stmt,
                                          CheckerContext &C) const;
  bool guaranteedNotToFreeMem(const CallEvent &Call) const;
  mutable MemFuncsUtility MemUtility;
public:
  DoubleFreeChecker();
  void checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                        CheckerContext &) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;

  void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const ;
  /// Stop tracking addresses which escape.
  ProgramStateRef checkPointerEscape(ProgramStateRef State,
                                    const InvalidatedSymbols &Escaped,
                                    const CallEvent *Call,
                                    PointerEscapeKind Kind) const;
};

} // end anonymous namespace

SymbolRef gs;
// record the value of arguments of memory free functions and its corresponding memory region.
using MyMemRegionRef = const MemRegion *;
REGISTER_SET_WITH_PROGRAMSTATE(FreedMemRegionSet,MyMemRegionRef)
REGISTER_SET_WITH_PROGRAMSTATE(FreedMemSymSet,SymbolRef)
// record the return value of memory allocate functions.
REGISTER_SET_WITH_PROGRAMSTATE(AllocMemSymSet,SymbolRef) 
REGISTER_MAP_WITH_PROGRAMSTATE(ReallocMap,SymbolRef,SVal)    //realloc  free val -> return val
REGISTER_MAP_WITH_PROGRAMSTATE(ReallocRetValStat,SymbolRef,bool) // realloc return val can be non-zero? true->can  false->can't


DoubleFreeChecker::DoubleFreeChecker()
{
  // Initialize the bug types.
  DoubleFreeBugType.reset(
      new BugType(this, "wjq-Double free", "Unix Mem Alloc API Error"));
  LeakBugType.reset(
      new BugType(this, "wjq-Resource Leak", "Unix Mem Alloc API Error"));
  uafBugType.reset(
      new BugType(this,"wjq-use after free","Unix Mem Alloc API Error"));
  // Sinks are higher importance bugs as well as calls to assert() or exit(0).
  LeakBugType->setSuppressOnSink(true);
}
/*
record the return value of memory allocate function.
In particular, the return value and argument of reallocate function 
should be treated since some CVEs are caused by this way.
*/
static bool canBeNonZero(SymbolRef Sym, ProgramStateRef State) {

    ConstraintManager &CMgr = State->getConstraintManager();
    ConditionTruthVal OpenFailed = CMgr.isNull(State, Sym);
    return !OpenFailed.isConstrainedTrue();
}
void DoubleFreeChecker::checkPostCall(const CallEvent &Call,
                                        CheckerContext &C) const {
/*
  if (MemUtility.isMallocFunction(Call))
  {
      // Get the symbolic value corresponding to the memory handle.
    SymbolRef MemDesc = Call.getReturnValue().getAsSymbol();
    if (!MemDesc)
      return;
    ProgramStateRef State = C.getState();
    State = State->add<AllocMemSymSet>(MemDesc);
    C.addTransition(State);
  }
  */
 
  if(MemUtility.isReallocFunction(Call))
  {
    ProgramStateRef State = C.getState();
    SVal realloc_size = Call.getArgSVal(1);
    SymbolRef freeMemDesc = Call.getArgSVal(0).getAsSymbol();
    SVal retMemDesc = Call.getReturnValue();
    SymbolRef retMemDescs = retMemDesc.getAsSymbol();
    State = State->set<ReallocMap>(freeMemDesc,retMemDesc);
    State = State->set<ReallocRetValStat>(retMemDescs,true);
    
    C.addTransition(State);
  }
}
/*
if the symbol value being freed is in the freed memory set, report a warning.
Add the symbol value to the freed memory set, remove the same symbol value from
allocated memory set.
*/

void DoubleFreeChecker::checkPreCall(const CallEvent &Call,
                                       CheckerContext &C) const {
  
 
  if (MemUtility.isFreeFunction(Call))
  {
      // Get the symbolic value corresponding to the memory handle.
    SymbolRef MemDesc = Call.getArgSVal(0).getAsSymbol();
    if (!MemDesc)
      return;
    ProgramStateRef State = C.getState();
    
    if(State->contains<FreedMemSymSet>(MemDesc))
    {
      reportDoubleFree(MemDesc,Call,C);
    }
    if(State->contains<ReallocMap>(MemDesc))
    {
      //retv_stat == true -> return value can be non zero
      const SymbolRef retv = State->get<ReallocMap>(MemDesc)->getAsSymbol();
      bool tmp = canBeNonZero(retv,State);
      bool retv_stat = State->get<ReallocRetValStat>(retv);
      if(tmp)
      {
          reportDoubleFree(MemDesc,Call,C);
      }
    }

/*
    if(State->contains<AllocMemSymSet>(MemDesc))
    {
      State = State->remove<AllocMemSymSet>(MemDesc);
    }
*/
    MyMemRegionRef memReigon = Call.getArgSVal(0).getAsRegion();
    if(memReigon)
      State = State->add<FreedMemRegionSet>(memReigon);
    
    // Generate the next transition, in which the stream is closed.
    State = State->add<FreedMemSymSet>(MemDesc);
    C.addTransition(State);
  }
  /*
  else if(MemUtility.isSpecialFunction(Call))
  {
    ProgramStateRef State = C.getState();
    ProgramStateRef trueState, falseState;
    SValBuilder &svbuilder = C.getSValBuilder();
    
    DefinedOrUnknownSVal s = Call.getArgSVal(0).castAs<DefinedOrUnknownSVal>();
    std::tie(trueState, falseState) = State->assume(s);
    if(trueState)
    {
        //llvm::outs() << "true state!\n";
    }
    if (falseState)
    {
        //llvm::outs() << "false state!\n";
    }
  }
  */
  
  
}


/*
Because the symbolic execution engine can not reason about the situation that
the allocated memory is returned to the caller via the arguments, we manually remove 
it out of the allocated memory set since the caller may free it outside.
*/
void DoubleFreeChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const 
{
  return;
  ProgramStateRef state = C.getState();
  SymbolRef MemDesc = Val.getAsSymbol();
  if(!state->contains<AllocMemSymSet>(MemDesc))
    return;
  MyMemRegionRef targetMemRegion = Loc.getAsRegion();
  //state = state->remove<AllocMemSymSet>(MemDesc);
  
  if(!targetMemRegion->hasGlobalsOrParametersStorage()&&
     !targetMemRegion->hasStackStorage()&&
     !targetMemRegion->hasStackNonParametersStorage())
  {
    state = state->remove<AllocMemSymSet>(MemDesc);
  }

  C.addTransition(state);
  return;
}

void DoubleFreeChecker::checkDeadSymbols(SymbolReaper &SymReaper,
                                           CheckerContext &C) const 
{
  ProgramStateRef State = C.getState();
  ReallocRetValStatTy reallocastat = State->get<ReallocRetValStat>();
  for (ReallocRetValStatTy::iterator I = reallocastat.begin(),
                             E = reallocastat.end(); I != E; ++I) {
    SymbolRef Sym = I->first;
    bool IsSymDead = SymReaper.isDead(Sym);

    if(!IsSymDead)
       continue;
     llvm::outs() << "hahaha\n";
    if (!canBeNonZero(Sym,State))
    {
       llvm::outs() << "hello\n";
       State->set<ReallocRetValStat>(Sym,false);
    }
     

    // Remove the dead symbol from the streams map.
    
  }
  C.addTransition(State);
}

bool isFreedMem(CheckerContext &C,SVal &s)
{
  MyMemRegionRef targetMemRegion = s.getAsRegion();
  if(!targetMemRegion)
      return false;
  ProgramStateRef state = C.getState();
  FreedMemRegionSetTy freedMems = state->get<FreedMemRegionSet>();
  for(FreedMemRegionSetTy::iterator I = freedMems.begin(),E = freedMems.end();
      I!=E; ++I)
    {
      MyMemRegionRef storedMemRegion = *I;
      
      if(targetMemRegion->isSubRegionOf(storedMemRegion))
      {
        return true;
      }
      
     /*
     if(storedMemRegion == targetMemRegion->getBaseRegion())
     {
        return true;
     }
     */
       
    } 
  return false;     
}
void DoubleFreeChecker::checkLocation(SVal Loc, bool IsLoad, const Stmt *S,
                        CheckerContext &C) const
                        {
  bool isfreed = isFreedMem(C,Loc);
  if(isfreed)
  {
    reportUseAfterFree(Loc,S,C);
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
  C.emitReport(std::move(R));
}
void DoubleFreeChecker::reportUseAfterFree(SVal mem,
                                          const Stmt *stmt,
                                          CheckerContext &C) const{
  ExplodedNode *ErrNode = C.generateErrorNode();
  // If we've already reached this node on another path, return.
  if (!ErrNode)
    return;
  auto R = llvm::make_unique<BugReport>(*uafBugType,
      "using a freed memory", ErrNode);
  R->addRange(stmt->getSourceRange());
  R->markInteresting(mem);
  C.emitReport(std::move(R));
                                          
}

void DoubleFreeChecker::reportLeaks(ArrayRef<SymbolRef> LeakedMems,
                                      CheckerContext &C,
                                      ExplodedNode *ErrNode) const {
  // Attach bug reports to the leak node.
  // TODO: Identify the leaked file descriptor.
  for (SymbolRef LeakedMem : LeakedMems) {
    auto R = llvm::make_unique<BugReport>(*LeakBugType,
        "allocate memory is never freed; potential resource leak", ErrNode);
    R->markInteresting(LeakedMem);
    C.emitReport(std::move(R));
  }
}

bool DoubleFreeChecker::guaranteedNotToFreeMem(const CallEvent &Call) const{
  // If it's not in a system header, assume it might close a file.
  if (!Call.isInSystemHeader())
    return false;

  // Handle cases where we know a buffer's /address/ can escape.
  if (Call.argumentsMayEscape())
    return false;

  // Note, even though fclose closes the file, we do not list it here
  // since the checker is modeling the call.

  return true;
}

// If the pointer we are tracking escaped, do not track the symbol as
// we cannot reason about it anymore.
ProgramStateRef
DoubleFreeChecker::checkPointerEscape(ProgramStateRef State,
                                        const InvalidatedSymbols &Escaped,
                                        const CallEvent *Call,
                                        PointerEscapeKind Kind) const {
  return State;
  // If we know that the call cannot close a file, there is nothing to do.
  if (Kind == PSK_EscapeOnBind && guaranteedNotToFreeMem(*Call)) {
    return State;
  }

  for (InvalidatedSymbols::const_iterator I = Escaped.begin(),
                                          E = Escaped.end();
                                          I != E; ++I) {
    SymbolRef Sym = *I;

    // The symbol escaped. Optimistically, assume that the corresponding file
    // handle will be closed somewhere else.
    State = State->remove<FreedMemSymSet>(Sym);
  }
  return State;
} 

void ento::registerDoubleFreeChecker(CheckerManager &mgr) {
  mgr.registerChecker<DoubleFreeChecker>();
}
