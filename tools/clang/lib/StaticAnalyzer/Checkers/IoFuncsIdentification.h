
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <iostream>
#include <vector>
using namespace clang;
using namespace ento;
using namespace loc;
/*
indicate whether the return value or the arguments should be tainted.
variable: multiple arguments should be tainted. if set, all the arguemts
followed should be tainted.
*/
struct IOFUNCS{
    std::string name;
    bool hasArgBuf;
    bool variable;
    union{
        int bufIdx;
        int bufStartIdx;
    };
    bool isRetBuf;
    IOFUNCS(std::string funcname,bool argBuf, bool variable_length, int idx,bool retBuf)
    {
        name = funcname;
        hasArgBuf = argBuf;
        variable = variable_length;
        bufIdx = idx;
        isRetBuf = retBuf;
    }
    bool isCalled(std::string s)
    {
        return name==s;
    }
    bool isRetOutputBuf()
    {
        return isRetBuf;
    }
    bool hasArgOutputBuf()
    {
        return hasArgBuf;
    }
    bool ismultiArgBuf()
    {
        return variable;
    }
    int getBufIndex()
    {
        return bufIdx;
    }
};
class IOFuncsUtility
{
    std::vector<IOFUNCS> funcs;
    std::string getFunctionNameFromCall(const CallEvent &event)
    {
        const Decl * decl = event.getDecl();
        if(!decl)
        return "";
        const FunctionDecl *func_decl = decl->getAsFunction();
        if(!func_decl)
        return "";
        std::string func_name = func_decl->getQualifiedNameAsString();
        return func_name;
    }
    public:
    IOFuncsUtility()
    {
        /*
        since all the standard IO function are well defined,
        put all standard IO functions to the pre-defined set.
        */
        funcs.push_back(IOFUNCS("scanf",true,true,1,false));
        funcs.push_back(IOFUNCS("wscanf",true,true,1,false));
        funcs.push_back(IOFUNCS("sscanf",true,true,2,false));
        funcs.push_back(IOFUNCS("fscanf",true,true,2,false));
        funcs.push_back(IOFUNCS("fwscanf",true,true,2,false));

        funcs.push_back(IOFUNCS("fread",true,false,0,false));


        funcs.push_back(IOFUNCS("gets",true,false,0,true));
        funcs.push_back(IOFUNCS("_getws",true,false,0,true));
        funcs.push_back(IOFUNCS("fgets",true,false,0,true));
        funcs.push_back(IOFUNCS("fgetws",true,false,0,true));


        funcs.push_back(IOFUNCS("_getch",false,true,1,true));
        funcs.push_back(IOFUNCS("_getche",false,true,1,true));
        funcs.push_back(IOFUNCS("getc",false,true,1,true));
        funcs.push_back(IOFUNCS("getwc",false,true,1,true));
        funcs.push_back(IOFUNCS("getchar",false,true,1,true));
        funcs.push_back(IOFUNCS("getwchar",false,true,1,true));
        funcs.push_back(IOFUNCS("fgetc",false,true,1,true));
        funcs.push_back(IOFUNCS("fgetwc",false,true,1,true));
        funcs.push_back(IOFUNCS("_fgetchar",false,true,1,true));
        funcs.push_back(IOFUNCS("_fgetwchar",false,true,1,true));
    }
    IOFUNCS* getIOFuncInfo(const CallEvent &C)
    {

        std::string funcname = getFunctionNameFromCall(C);
        for(std::vector<IOFUNCS>::iterator it = funcs.begin(); it!= funcs.end(); it++)
        {
            if(it->isCalled(funcname))
            {
                return new IOFUNCS(*it);
            }
        }
        return nullptr;
    }
};