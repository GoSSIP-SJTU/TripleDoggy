//==---OverFlowChecker.cpp ------------------------------*- C++ -*-==//
//
//
// This file is distributed under the Apache Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This checker checks integer overflow vulnerability, including mathematic operation
// overflow, integer conversion overflow.
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
#include <vector>
#include "MemFuncsIdentification.h"
#include "IoFuncsIdentification.h"
using namespace clang;
using namespace ento;

/*
Represent the integer range recording to the integer type.
*/
class IntegerRange
{
    public:
    llvm::APSInt max;
    llvm::APSInt min;
    IntegerRange(const llvm::APSInt MAX,const llvm::APSInt MIN):max(MAX),min(MIN)
    {
        //max = (*MAX).extend(128);
        //min = (*MIN).extend(128);
    };
};
namespace
{
    class OverFlowChecker : public Checker<check::PreCall,
                                           check::PostCall,
                                           check::Bind,
                                           check::PreStmt<ArraySubscriptExpr>,
                                           check::PostStmt<BinaryOperator>,
                                           check::PreStmt<ReturnStmt>,
                                           check::ASTDecl<VarDecl>,
                                           check::BeginFunction> {
    Log *log;
    mutable SymbolRef debugsym;
    mutable IOFuncsUtility ioutility;
    mutable MemFuncsUtility memutility;
    mutable std::unique_ptr<BuiltinBug> BT_overflow;
    mutable std::vector<const VarDecl *> globalVarDecls;
    void reportReturnVOverFlow(CheckerContext &C,SVal &s,const SourceRange &range) const  ;
    void reportIndexOverFlow(CheckerContext &C,SVal &s,const SourceRange &range) const  ;
    void reportArgOverFlow(CheckerContext &C,SVal &s,const SourceRange &range) const  ;
    void reportConversionOverFlow(CheckerContext &C,SVal &s,const SourceRange &range) const;
    IntegerRange*  getTypeRange(const QualType &type,CheckerContext &C) const;
    const QualType& getWilderType(const QualType &l, const QualType &r,CheckerContext &C) const;
    const QualType getUnsignedType(const QualType &type,CheckerContext &C) const;
    public:
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
    void checkPreStmt(const ArraySubscriptExpr *DS, CheckerContext &C) const;
    void checkPostStmt(const BinaryOperator *DS, CheckerContext &C) const;
    void checkBeginFunction(CheckerContext &C) const;
    void checkASTDecl(const VarDecl *D, AnalysisManager &Mgr, BugReporter &BR) const;
    void checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &) const;
    void checkPreStmt(const ReturnStmt *DS, CheckerContext &C) const ;
    
    OverFlowChecker();
    ~OverFlowChecker();
    };
}

/*
Record the result of a mathematic operation and its corresponding contrain.
For instance:
void test(unsinged int a, unsigned int b)
{
    unsigned c = a + b;
}
when the symbolic execution engine reach the mathematic operation, a+b, we record
symbol value of a+b, and the condition that cause overflow. Here we record
a+b -> (a > a+b || b > a+b) .if the condition can be true, than it may be an overflow.
The next time the symbolic value being used, we check the condition again, if the condition
hold, we report a warning.
*/
REGISTER_MAP_WITH_PROGRAMSTATE(SymBolContrains,SymbolRef,SymbolRef)



OverFlowChecker::OverFlowChecker()
{
    log = new Log();
    BT_overflow.reset(new BuiltinBug(this, "integer overflow","overflow"));
}
OverFlowChecker::~OverFlowChecker()
{
    delete log;
}

void OverFlowChecker::reportReturnVOverFlow(CheckerContext &C,SVal &s,const SourceRange &range) const
{
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
        return;
    auto Report = llvm::make_unique<BugReport>(*BT_overflow, "return value overflow", ErrNode);
    Report->addRange(range);
    Report->markInteresting(s);
    C.emitReport(std::move(Report));
}
void OverFlowChecker::reportIndexOverFlow(CheckerContext &C,SVal &s,const SourceRange &range) const 
{
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
        return;
    auto Report = llvm::make_unique<BugReport>(*BT_overflow, "index can be corrupt", ErrNode);
    Report->addRange(range);
    Report->markInteresting(s);
    C.emitReport(std::move(Report));
}
void OverFlowChecker::reportArgOverFlow(CheckerContext &C,SVal &s,const SourceRange &range) const
{
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
        return;
    auto Report = llvm::make_unique<BugReport>(*BT_overflow, "argument can be corrupt", ErrNode);
    Report->addRange(range);
    Report->markInteresting(s);
    C.emitReport(std::move(Report));
}
void OverFlowChecker::reportConversionOverFlow(CheckerContext &C,SVal &s,const SourceRange &range) const
{
    ExplodedNode *ErrNode = C.generateNonFatalErrorNode();
    if (!ErrNode)
        return;
    auto Report = llvm::make_unique<BugReport>(*BT_overflow, "conversion overflow", ErrNode);
    Report->addRange(range);
    Report->markInteresting(s);
    C.emitReport(std::move(Report));
}


/*
check whether the given constrain can be true in the given context or not.
*/
bool passConstrain(CheckerContext &C,const SymbolRef constrain)
{
    if(!constrain)
        return true;
    ProgramStateRef state = C.getState();
    SValBuilder &svbuilder = C.getSValBuilder();
    ProgramStateRef trueState, falseState;
    DefinedOrUnknownSVal s = svbuilder.makeSymbolVal(constrain).castAs<DefinedOrUnknownSVal>();
    if(s.isUnknown())
    {
        return true;
    }
    std::tie(trueState, falseState) = state->assume(s);
   // s.dump();
    if(trueState)
    {
        return false;
    }
    return true;
}
/*
Build a symbol with the given lvalue ,opcode, rvalue.
Because one side can be a constant value, we must treat them specially.
*/
SymbolRef builtResSymbol(SVal lv,BinaryOperator::Opcode op,SVal rv,QualType type,CheckerContext &C)
{
    if(lv.isUnknown() || rv.isUnknown())
        return nullptr;
    ProgramStateRef state = C.getState();
    SymbolManager & symmanager = C.getSymbolManager();
    SValBuilder &svbuilder = C.getSValBuilder();
    SymbolRef  resv;
    const llvm::APSInt * lvint = svbuilder.getKnownValue(state,lv);
    const llvm::APSInt * rvint = svbuilder.getKnownValue(state,rv);
    if(lvint && rvint)
        return nullptr;
    if(lvint && !rvint)
        resv = symmanager.getIntSymExpr(*lvint,op,rv.getAsSymbol(),type);
    if(!lvint && rvint)
        resv = symmanager.getSymIntExpr(lv.getAsSymbol(),op,*rvint,type);
    if(!lvint && !rvint)
    {
        resv = symmanager.getSymSymExpr(lv.getAsSymbol(),op,rv.getAsSymbol(),type);
    }  
    return resv;
}
/*
Build a symbol with the given lvalue ,opcode, rvalue with type extension.
for instance:
  unsigned int a,b;
  b + c;
can be extened to (long long)((long long)b + (long long)c)
*/
SymbolRef builtExtResSymbol(SVal lv,BinaryOperator::Opcode op,SVal rv,QualType lt,QualType rt,QualType rett, CheckerContext &C)
{
    if(lv.isUnknown() || rv.isUnknown())
        return nullptr;
    ProgramStateRef state = C.getState();
    SymbolManager & symmanager = C.getSymbolManager();
    SValBuilder &svbuilder = C.getSValBuilder();
    ASTContext &astctx = C.getASTContext();
    SymbolRef  resv;
    const llvm::APSInt * lvint = svbuilder.getKnownValue(state,lv);
    const llvm::APSInt * rvint = svbuilder.getKnownValue(state,rv);
    if(lvint && rvint)
        return nullptr;
    if(lvint && !rvint)
    {
        SymbolRef extrv = symmanager.getCastSymbol(rv.getAsSymbol(),rt,rett);
        resv = symmanager.getIntSymExpr(*lvint,op,extrv,rett);
    }
    if(!lvint && rvint)
    {
        SymbolRef extlv = symmanager.getCastSymbol(lv.getAsSymbol(),lt,rett);
        resv = symmanager.getSymIntExpr(extlv,op,*rvint,rett);
    }
    if(!lvint && !rvint)
    {
        SymbolRef extlv = symmanager.getCastSymbol(lv.getAsSymbol(),lt,rett);
        SymbolRef extrv = symmanager.getCastSymbol(rv.getAsSymbol(),rt,rett);
        resv = symmanager.getSymSymExpr(extlv,op,extrv,rett);
    }
    resv = symmanager.getCastSymbol(resv,rett,rett);
    return resv;
}

void OverFlowChecker::checkPostStmt(const BinaryOperator *DS, CheckerContext &C) const
{
    BinaryOperator::Opcode op = DS->getOpcode();
    if(op == BO_Add || op == BO_Sub || op ==  BO_Mul)
    {
        ProgramStateRef state = C.getState();
        SValBuilder &svbuilder = C.getSValBuilder();
        SymbolManager & symmanager = C.getSymbolManager();
        ASTContext &astctx = C.getASTContext();
        Expr *l = DS->getLHS()->IgnoreCasts();
        Expr *r = DS->getRHS()->IgnoreCasts();
        SVal lv = C.getSVal(DS->getLHS());
        SVal rv = C.getSVal(DS->getRHS());
        const Type *lt = l->getType().getTypePtr();
        const Type *rt = r->getType().getTypePtr();
        if(!lt->isIntegerType() || !rt->isIntegerType())
            return;
        if(!state->isTainted(lv) && !state->isTainted(rv))
            return;
        QualType neqt = astctx.BoolTy;
        QualType resty = getWilderType(l->getType(),r->getType(),C);

        SymbolRef originalresv = builtResSymbol(lv,DS->getOpcode(),rv,DS->getType(),C);

        if(!originalresv)
            return;
        if(lt->isUnsignedIntegerType() && rt->isUnsignedIntegerType())
        {
            SymbolRef extresv = builtResSymbol(lv,DS->getOpcode(),rv,resty,C);
            
            SymbolRef  neqv1 = builtResSymbol(lv,BO_GT,svbuilder.makeSymbolVal(extresv),neqt,C);
            SymbolRef  neqv2 = builtResSymbol(rv,BO_GT,svbuilder.makeSymbolVal(extresv),neqt,C);
            if(!neqv1 || !neqv2)
                return;
            SymbolRef  neqv = symmanager.getSymSymExpr(neqv1,BO_Or,neqv2,neqt);
            
            //if(!passConstrain(C,neqv))
            {
                state = state->set<SymBolContrains>(originalresv,neqv);
            }      
        }
        SymbolRef extresv = builtExtResSymbol(lv,DS->getOpcode(),rv,l->getType(),r->getType(),astctx.Int128Ty,C);
        if(!extresv)
            return;
        if(lt->isSignedIntegerType() && rt->isSignedIntegerType())
        {
            IntegerRange *range = getTypeRange(resty,C);
            if(!range)
                return;
            SymbolRef  neqv1 = symmanager.getSymIntExpr(extresv,BO_GT,range->max,neqt);
            SymbolRef  neqv2 = symmanager.getSymIntExpr(extresv,BO_LT,range->min,neqt);
            SymbolRef  neqv = symmanager.getSymSymExpr(neqv1,BO_Or,neqv2,neqt);
            //if(!passConstrain(C,neqv))
            {
                state = state->set<SymBolContrains>(originalresv,neqv);
            }  
        }
        if((lt->isUnsignedIntegerType() && rt->isSignedIntegerType()) ||
           (lt->isSignedIntegerType() && rt->isUnsignedIntegerType()))
        {
            IntegerRange *range = getTypeRange(getUnsignedType(resty,C),C);
            if(!range)
                return;
            SymbolRef  neqv = symmanager.getSymIntExpr(extresv,BO_GT,range->max,neqt);
            //if(!passConstrain(C,neqv))
            {
                state = state->set<SymBolContrains>(originalresv,neqv);
            }  
        }
        C.addTransition(state);

    }
} 
/*
Check to see whether the given symbol can less than zero with the given type.
*/
//#define MAX_CONVERSIONSYMBOL_COMPLEXITY 3
bool canLessThanZero(CheckerContext &C,const SVal& sym,QualType type,bool checkType)
{
    if(sym.isUnknown())
        return false;
    ProgramStateRef state = C.getState();
    SymbolManager & symmanager = C.getSymbolManager();
    SValBuilder &svbuilder = C.getSValBuilder();
    ASTContext &astctx = C.getASTContext();
    uint64_t width = astctx.getTypeSize(type);
    const llvm::APSInt *lvint = svbuilder.getKnownValue(state,sym);
    if(lvint)
    {
        /*
        llvm::APSInt v(width,false);
        v = lvint->getExtValue();
        llvm::outs() << "constant\n";
        return v < 0;
        */
       return false;
    }
    if(checkType)
    {
        if(!sym.getAsSymbol()->getType().getTypePtr()->isSignedIntegerType())
            return false;
    }
    //if(sym.getAsSymbol()->computeComplexity() > MAX_CONVERSIONSYMBOL_COMPLEXITY);
        //return false;
    SymbolRef resv = symmanager.getCastSymbol(sym.getAsSymbol(),type,astctx.Int128Ty);
    SymbolRef  neqv = symmanager.getSymIntExpr(resv,BO_LT,llvm::APSInt::get(0),astctx.BoolTy);
    return !passConstrain(C,neqv);
}
////////////
void OverFlowChecker::checkBind(SVal Loc, SVal Val, const Stmt *S, CheckerContext &C) const 
{
    if(S->getStmtClass() != 24)
        return;
    const CastExpr* exp = (const CastExpr*)S;
    if(!exp->getType().getTypePtr()->isUnsignedIntegerType())
        return;
    if(canLessThanZero(C,Val,exp->getType(),true))
    {
        reportConversionOverFlow(C,Val,S->getSourceRange());
    }
}
void OverFlowChecker::checkPreStmt(const ReturnStmt *DS, CheckerContext &C) const 
{
    const FunctionDecl * funcdecl = C.getCurrentAnalysisDeclContext()->getDecl()->getAsFunction();
    if (!funcdecl->getReturnType().getTypePtr()->isUnsignedIntegerType())
        return;
    const Expr* expv = DS->getRetValue();
    SVal s = C.getSVal(expv);
    if(canLessThanZero(C,s,expv->getType(),false))
    {
        reportReturnVOverFlow(C,s,DS->getSourceRange());
    }
}
void OverFlowChecker::checkPreStmt(const ArraySubscriptExpr *DS, CheckerContext &C) const 
{
    ProgramStateRef state = C.getState();
    const Expr *idxexp = DS->getIdx();
    SVal idx = C.getSVal(idxexp);
    if(state->contains<SymBolContrains>(idx.getAsSymbol()))
    {
        const SymbolRef * constrain = state->get<SymBolContrains>(idx.getAsSymbol());
        if(!passConstrain(C,*constrain))
        {
            reportIndexOverFlow(C,idx,DS->getSourceRange());
        }
    }
}

void OverFlowChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const 
{
    if(memutility.isMallocFunction(Call))
    {
        unsigned index = 0;
        ProgramStateRef state = C.getState();
        ArrayRef<ParmVarDecl *> args = Call.parameters();
        for(CallEvent::param_type_iterator it = Call.param_type_begin();
              it != Call.param_type_end();
              it++)
        {
            if((*it).getTypePtr()->isIntegerType())
            {
                SVal argv = Call.getArgSVal(index);
                //llvm::outs() << "enterA\n";
                if(state->contains<SymBolContrains>(argv.getAsSymbol()))
                {
                    //llvm::outs() << "enterB\n";
                    const SymbolRef * constrain = state->get<SymBolContrains>(argv.getAsSymbol());
                    //(*constrain)->dump();
                    if(!passConstrain(C,*constrain))
                    {
                        reportArgOverFlow(C,argv,Call.getSourceRange());
                    }
                }
            }
            index++;
        }     
    }
}


const QualType& OverFlowChecker::getWilderType(const QualType &l, const QualType &r,CheckerContext &C) const
{
    ASTContext &astctx = C.getASTContext();
    uint64_t lwidth = astctx.getTypeSize(l);
    uint64_t rwidth = astctx.getTypeSize(r);
    return lwidth > rwidth ? l:r;
}
const QualType OverFlowChecker::getUnsignedType(const QualType &type,CheckerContext &C) const
{
    ASTContext &astctx = C.getASTContext();
    uint64_t   width = astctx.getTypeSize(type);
    return astctx.getIntTypeForBitwidth(width,false);
}
IntegerRange*  OverFlowChecker::getTypeRange(const QualType &type,CheckerContext &C) const
{
    ASTContext &astctx = C.getASTContext();
    uint64_t width = astctx.getTypeSize(type);
    bool isunsigned;
    
    if(type.getTypePtr()->isSignedIntegerType())
    {
        isunsigned = false;
    }
    else if(type.getTypePtr()->isUnsignedIntegerType())
    {
        isunsigned = true;
    }
    else
    {
        return nullptr;
    }
    llvm::APSInt max = llvm::APSInt::getMaxValue(width,isunsigned);
    llvm::APSInt min = llvm::APSInt::getMinValue(width,isunsigned);
    return new IntegerRange(max,min);
}                       


void OverFlowChecker::checkBeginFunction(CheckerContext &C) const
{
    if(!C.inTopFrame())
        return;
    ProgramStateRef state = C.getState();
    StoreManager & store = C.getStoreManager();
    Store s = state->getStore();
    const FunctionDecl * funcdecl = C.getCurrentAnalysisDeclContext()->getDecl()->getAsFunction();
    unsigned argnum = funcdecl->getNumParams();
    for(unsigned i =0; i < argnum; i++)
    {
        const ParmVarDecl *pdecl = funcdecl->getParamDecl(i);
        const Loc loc = store.getLValueVar(pdecl,C.getLocationContext());
        SVal v = store.getBinding(s,loc);
        state = state->addTaint(v);
    }
    for(const VarDecl * decl : globalVarDecls)
    {
        const Loc loc = store.getLValueVar(decl,C.getLocationContext());
        SVal v = store.getBinding(s,loc);
        state = state->addTaint(v);
    }
    C.addTransition(state);
}

void OverFlowChecker::checkASTDecl(const VarDecl *D, AnalysisManager &Mgr, BugReporter &BR) const
{
    if(D->hasGlobalStorage())
    {
    	globalVarDecls.push_back(D);
    }
}
void OverFlowChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const 
{
    ProgramStateRef state = C.getState();
    const Decl * decl = Call.getDecl();
    if(!decl)
        return;
    const FunctionDecl *func_decl = decl->getAsFunction();
    if(!func_decl)
        return;
    StoreManager & store = C.getStoreManager();
    Store s = state->getStore();
    if(IOFUNCS* iofunc = ioutility.getIOFuncInfo(Call))
    {
        if(iofunc->isRetOutputBuf())
        {
            state = state->addTaint(Call.getReturnValue());
        }
        if(iofunc->hasArgOutputBuf())
        {
            int argindex = iofunc->getBufIndex();
            if(iofunc->ismultiArgBuf())
            {
                unsigned argnum = Call.getNumArgs();
                for(unsigned i=argindex;i<argnum;i++)
                {
                    Loc loc = Call.getArgSVal(i).castAs<Loc>();
                    SVal v = store.getBinding(s,loc);
                    state = state->addTaint(v);
                }
            }
            else 
            {
                Loc loc = Call.getArgSVal(argindex).castAs<Loc>();
                SVal v = store.getBinding(s,loc);
                state = state->addTaint(v);
            }
        }
    }
    else if(!func_decl->doesThisDeclarationHaveABody())
    {
        state = state->addTaint(Call.getReturnValue());
        unsigned argnum = Call.getNumArgs();
        for(unsigned i = 0;i < argnum;i++)
        {
            const Expr * expv = Call.getArgExpr(i);
            if(!expv)
                continue;
            if(expv->getType().getTypePtr()->isAnyPointerType())
            {
                Loc loc = Call.getArgSVal(i).castAs<Loc>();
                SVal v = store.getBinding(s,loc);
                state = state->addTaint(v);
            }
        }
    }
    C.addTransition(state);
}
void ento::registerOverFlowChecker(CheckerManager &mgr) {
  mgr.registerChecker<OverFlowChecker>();
}
