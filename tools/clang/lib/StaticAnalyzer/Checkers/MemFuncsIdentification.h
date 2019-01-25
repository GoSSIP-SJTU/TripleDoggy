
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <iostream>
#include <stdlib.h>
using namespace clang;
using namespace ento;
using namespace loc;
#define MEM_ALLOC_CONFIG_FILENAME "/home/loccs/memmallocfuncs.txt"
#define MEM_FREE_CONFIG_FILENAME "/home/loccs/memfreefuncs.txt"
#define MEM_REALLOC_CONFIG_FILENAME "/home/loccs/memreallocfuncs.txt"
#define MEM_LOGFILENAME "/home/loccs/log.txt"
struct WJQ_FUNC
{
  std::string function_name;
  int sizearg_index;
  int pointerarg_index;
};

void super_split(const std::string& s, const std::string& c,std::vector<std::string> &v)
{
    std::string::size_type pos1, pos2;
    size_t len = s.length();
    pos2 = s.find(c);
    pos1 = 0;
    while(std::string::npos != pos2)
    {
        v.emplace_back(s.substr(pos1, pos2-pos1));
 
        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if(pos1 != len)
        v.emplace_back(s.substr(pos1));
}
void parse_func_configfile(std::vector<WJQ_FUNC> & list,std::string line)
{
  WJQ_FUNC tmp;
  std::vector<std::string> t ;
  super_split(line," ",t);
  tmp.function_name = t[0];
  tmp.sizearg_index = atoi(t[1].c_str());
  tmp.pointerarg_index = atoi(t[2].c_str());
  list.push_back(tmp);
}
class MemFuncsUtility
{
  private:
  std::fstream mem_alloc_file;
  std::fstream mem_free_file;
  std::fstream mem_realloc_file;
  std::vector<WJQ_FUNC> memallocfuncs;
  std::vector<WJQ_FUNC> memfreefuncs;
  std::vector<WJQ_FUNC> memreallocfuncs;
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
  MemFuncsUtility()
  {
    mem_alloc_file.open(MEM_ALLOC_CONFIG_FILENAME);
    std::string readline;
    while (getline(mem_alloc_file, readline)) //each line represena a memoryallocate function name 
    {
      parse_func_configfile(memallocfuncs,readline);
    }
    mem_alloc_file.close();
    mem_free_file.open(MEM_FREE_CONFIG_FILENAME);
    while (getline(mem_free_file, readline)) //each line represena a memoryallocate function name 
    {
      parse_func_configfile(memfreefuncs,readline);
    }
    mem_free_file.close();
    mem_realloc_file.open(MEM_REALLOC_CONFIG_FILENAME);
    while (getline(mem_realloc_file, readline)) //each line represena a memoryallocate function name 
    {
      parse_func_configfile(memreallocfuncs,readline);
    }
    mem_realloc_file.close();
  }
  WJQ_FUNC* isFreeFunction(const CallEvent &event)
  {
    const Decl * decl = event.getDecl();
    const FunctionDecl * fdecl = decl->getAsFunction();
    ArrayRef< ParmVarDecl * > argdecls = fdecl->parameters();
    std::string func_name = getFunctionNameFromCall(event);
    for(WJQ_FUNC func : memfreefuncs)
    {
      if(func.function_name == func_name)
      {
          int num_args = argdecls.size ();
          if(func.pointerarg_index < num_args )
          {
            if (argdecls[func.pointerarg_index]->getOriginalType().getTypePtr()->isAnyPointerType())
              return new WJQ_FUNC(func);
          }
          break;
      } 
    }
    return nullptr;
  }
    WJQ_FUNC* isAllocFunction(const CallEvent &event)
  {
    const Decl * decl = event.getDecl();
    const FunctionDecl * fdecl = decl->getAsFunction();
    if (!fdecl ->getReturnType().getTypePtr()->isAnyPointerType())
      return nullptr;
    ArrayRef< ParmVarDecl * > argdecls = fdecl->parameters();
    std::string func_name = getFunctionNameFromCall(event);
    // just compare the function name
    for(WJQ_FUNC func : memallocfuncs)
    {
      if(func.function_name == func_name)
      {
          int num_args = argdecls.size ();
          if(func.sizearg_index < num_args )
          {
            if (argdecls[func.sizearg_index]->getOriginalType().getTypePtr()->isIntegerType())
              return new WJQ_FUNC(func);
          }
          break;
      } 
    }
    return nullptr;
  }
    WJQ_FUNC* isReallocFunction(const CallEvent &event)
  {
    const Decl * decl = event.getDecl();
    const FunctionDecl * fdecl = decl->getAsFunction();
    ArrayRef< ParmVarDecl * > argdecls = fdecl->parameters();
    std::string func_name = getFunctionNameFromCall(event);
    // just compare the function name
    for(WJQ_FUNC func : memreallocfuncs)
    {
      if(func.function_name == func_name)
      {
          int num_args = argdecls.size ();
          if(func.sizearg_index < num_args && func.pointerarg_index < num_args)
          {
            if ((argdecls[func.sizearg_index]->getOriginalType()->isIntegerType()) &&
               (argdecls[func.pointerarg_index]->getOriginalType().getTypePtr()->isAnyPointerType()))
              return new WJQ_FUNC(func);
          }
          break;
      } 
    }
    return nullptr;
  }
};
