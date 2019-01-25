//----------------NewDereferenceChecker.cpp------------------===//
//
//
// This file is distributed under the Apache Open Source
// License. See LICENSE.TXT for details.
//
//
//===--------------------------------------------------------===//
//this checker implements a new nullpointer-dereference algorithm,
//which can reduce the false positive compared with the Dereference checker.
//===--------------------------------------------------------===//



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

#include "MemFuncsIdentification.h"
using namespace clang;
using namespace ento;
using namespace loc;
namespace {
class NewDereferenceChecker
    : public Checker< check::Location,
                      check::Bind,
                      EventDispatcher<ImplicitNullDerefEvent>,
                      check::PostCall,
                      check::PreCall> {
  mutable std::unique_ptr<BuiltinBug> BT_null;
  mutable std::unique_ptr<BuiltinBug> BT_undef;
  mutable std::unique_ptr<BugType> BT_nullarg;
  mutable MemFuncsUtility MemUtility;
  mutable DefaultBool strict_check; // assume unknow funtion be unsafe
  void reportBug(ProgramStateRef State, const Stmt *S, CheckerContext &C) const;

public:
  NewDereferenceChecker();
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  void checkLocation(SVal location, bool isLoad, const Stmt* S,
                     CheckerContext &C) const;
  void checkBind(SVal L, SVal V, const Stmt *S, CheckerContext &C) const;

  static void AddDerefSource(raw_ostream &os,
                             SmallVectorImpl<SourceRange> &Ranges,
                             const Expr *Ex, const ProgramState *state,
                             const LocationContext *LCtx,
                             bool loadedFrom = false);
  

};
}  // end anonymous namespace

/*
  Use this set to record each return value of memory allocate function.
  Then when a memory location is accessed, we check the set to see if the
  memory reigion is in this set. If so, check null-dereference vulnerability, if not,
  we assume the access is always secure.
*/
using MyMemRegionRef = const MemRegion *;
REGISTER_SET_WITH_PROGRAMSTATE(AllocMemSet,MyMemRegionRef) 


/*
  check if the accessed memory is in the the set of record memory.
  first, retrieve the memory reigon of the accessed memroy
  then, iterate the set, invoke "isSubRegionOf" to inspect if the given
  reigon is the subregion of the record reigon
*/
bool isAllocMem(CheckerContext &C,SVal &s)
{
  MyMemRegionRef targetMemRegion = s.getAsRegion();
  if(!targetMemRegion)
    return false;
  ProgramStateRef state = C.getState();
  AllocMemSetTy allocMems = state->get<AllocMemSet>();
  for(AllocMemSetTy::iterator I = allocMems.begin(),E = allocMems.end();
      I!=E; ++I)
    {
      MyMemRegionRef storedMemRegion = *I;
      if(targetMemRegion->isSubRegionOf(storedMemRegion))
      {
        return true;
      }
    } 
  return false;     
} 

/*
  if it is a memory allocate function, record the returned memory region
*/
void NewDereferenceChecker::checkPostCall(const CallEvent &Call, 
                                      CheckerContext &C) const {
  /*
    if the call is a kind of memory allocate function, record the return value
    to facilitate the later checker.
  */
 
  if(!MemUtility.isMallocFunction(Call))
    return;
  SVal retval = Call.getReturnValue();
  MyMemRegionRef memReigon = retval.getAsRegion();
  if(!memReigon)
    return ;
  
  ProgramStateRef State = C.getState();
  State = State->add<AllocMemSet>(memReigon);
  C.addTransition(State);
}
/*
  config file: each line list a memory allocate function name
*/
NewDereferenceChecker::NewDereferenceChecker()
{
  this->strict_check = false;
  BT_nullarg.reset(new BugType(this, "wjq-null-pointer arg","nullability"));
  BT_null.reset(new BuiltinBug(this, "wjq-Dereference of null pointer"));  
  BT_undef.reset(new BuiltinBug(this, "wjq-Dereference of undefined pointer value")); 
}

/*
  one policy used here:
  in strict mode, we assume every undefined is secure, which means each pointer passed
  to this function will be checked befored used.
  first check if the function is defined.if not, return. the engine will step into the function
  in none-strict mode, the fucntion will be ingored.
*/

void NewDereferenceChecker::checkPreCall(const CallEvent &Call, 
                                  CheckerContext &C) const {
  
  //in strict mode, we assume undefined function as unsecure.
  if (!strict_check)
    return;
    //if the function has defined, step into the function to do the check.
  const Decl * decl = Call.getDecl();
  if(!decl)
    return;
  const FunctionDecl *func_decl = decl->getAsFunction();
  if(!func_decl)
    return;
  if(func_decl->doesThisDeclarationHaveABody())
    return;

    //iterate the args of the function to see if one of the arg is contained in the set.
    //if one arg is contained in the set, do contrain solver on this arg to see if it can
    //be null. if so, emit a bug.

  unsigned int num_args = Call.getNumArgs();
  ProgramStateRef State = C.getState();
  for(unsigned i=0;i<num_args;i++)
  {
    SVal argVal = Call.getArgSVal(i); 
    bool present = isAllocMem(C,argVal);
    if(present)
    {
      DefinedOrUnknownSVal location = Call.getArgSVal(i).castAs<DefinedOrUnknownSVal>();
      ProgramStateRef notNullState, nullState;
      std::tie(notNullState, nullState) = State->assume(location);
      if(nullState)
      {
        SVal argval = Call.getArgSVal(i);
        State = State->remove<AllocMemSet>(argval.getAsRegion());
        ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
        if (!ErrNode)
          return;
        auto Report = llvm::make_unique<BugReport>(
          *BT_nullarg, "null pointer arg", ErrNode);
        Report->addRange(Call.getSourceRange());
        C.emitReport(std::move(Report));
      }
     
    } 
  }
   C.addTransition(State);
}

void
NewDereferenceChecker::AddDerefSource(raw_ostream &os,
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

static const Expr *getDereferenceExpr(const Stmt *S, bool IsBind=false){
  const Expr *E = nullptr;

  // Walk through lvalue casts to get the original expression
  // that syntactically caused the load.
  if (const Expr *expr = dyn_cast<Expr>(S))
    E = expr->IgnoreParenLValueCasts();

  if (IsBind) {
    const VarDecl *VD;
    const Expr *Init;
    std::tie(VD, Init) = parseAssignment(S);
    if (VD && Init)
      E = Init; 
  }
  return E;
}

static bool suppressReport(const Expr *E) {
  // Do not report dereferences on memory in non-default address spaces.
  return E->getType().getQualifiers().hasAddressSpace();
}

void NewDereferenceChecker::reportBug(ProgramStateRef State, const Stmt *S,
                                   CheckerContext &C) const {
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

  C.emitReport(std::move(report));
}

void NewDereferenceChecker::checkLocation(SVal l, bool isLoad, const Stmt* S,
                                       CheckerContext &C) const {
  
  if (l.isUndef()) {
    if (ExplodedNode *N = C.generateErrorNode()) {


      auto report =
          llvm::make_unique<BugReport>(*BT_undef, BT_undef->getDescription(), N);
      bugreporter::trackNullOrUndefValue(N, bugreporter::getDerefExpr(S),
                                         *report);
      C.emitReport(std::move(report));
    }
    return;
  }
  //checker if the memory is obtained from a memory allocate function.
  //do not do the check if the ponter points to other memory other than obtained from
  //memory allocate function.
  bool present = isAllocMem(C,l);
  if(!present)
    return;

  DefinedOrUnknownSVal location = l.castAs<DefinedOrUnknownSVal>();

  // Check for null dereferences.
  if (!location.getAs<Loc>())
    return;

  ProgramStateRef state = C.getState();

  ProgramStateRef notNullState, nullState;
  std::tie(notNullState, nullState) = state->assume(location);

  // The explicit NULL case.
  if (nullState) {   
    //if (!notNullState) {
      state = state->remove<AllocMemSet>(l.getAsRegion());
      const Expr *expr = getDereferenceExpr(S);
      if (!suppressReport(expr)) {
        reportBug(nullState, expr, C); 
      //}
    }

    // Otherwise, we have the case where the location could either be
    // null or not-null.  Record the error node as an "implicit" null
    // dereference.
    
    if (ExplodedNode *N = C.generateSink(nullState, C.getPredecessor())) {
      ImplicitNullDerefEvent event = {l, isLoad, N, &C.getBugReporter(),
                                      true};
      dispatchEvent(event);
    }
    
  }

  // From this point forward, we know that the location is not null.
  C.addTransition(state);
}

void NewDereferenceChecker::checkBind(SVal L, SVal V, const Stmt *S,
                                   CheckerContext &C) const {
  // If we're binding to a reference, check if the value is known to be null.
  if (V.isUndef())
    return;
  bool present = isAllocMem(C,V);
  if(!present)
    return;
  const MemRegion *MR = L.getAsRegion();
  const TypedValueRegion *TVR = dyn_cast_or_null<TypedValueRegion>(MR);
  if (!TVR)
    return;

  if (!TVR->getValueType()->isReferenceType())
    return;

  ProgramStateRef State = C.getState();

  ProgramStateRef StNonNull, StNull;
  std::tie(StNonNull, StNull) = State->assume(V.castAs<DefinedOrUnknownSVal>());

  if (StNull) { 
    if (!StNonNull) {
      const Expr *expr = getDereferenceExpr(S, /*IsBind=*/true);
      if (!suppressReport(expr)) {
        reportBug(StNull, expr, C);
        return;
      }
    }

    // At this point the value could be either null or non-null.
    // Record this as an "implicit" null dereference.
    
    if (ExplodedNode *N = C.generateSink(StNull, C.getPredecessor())) {
      ImplicitNullDerefEvent event = {V, true, N,
                                      &C.getBugReporter(),
                                      true};
      dispatchEvent(event);
    }
    C.addTransition(State);
  }

  // Unlike a regular null dereference, initializing a reference with a
  // dereferenced null pointer does not actually cause a runtime exception in
  // Clang's implementation of references.
  //
  //   int &r = *p; // safe??
  //   if (p != NULL) return; // uh-oh
  //   r = 5; // trap here
  //
  // The standard says this is invalid as soon as we try to create a "null
  // reference" (there is no such thing), but turning this into an assumption
  // that 'p' is never null will not match our actual runtime behavior.
  // So we do not record this assumption, allowing us to warn on the last line
  // of this example.
  //
  // We do need to add a transition because we may have generated a sink for
  // the "implicit" null dereference.
  C.addTransition(State, this);
}

void ento::registerNewDereferenceChecker(CheckerManager &mgr) {
  mgr.registerChecker<NewDereferenceChecker>();
}
