
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <iostream>

#include "log.h"
using namespace clang;
using namespace ento;
using namespace loc;


#define MEM_ALLOC_CONFIG_FILENAME "/home/loccs/memallocfuncs.txt"
#define MEM_FREE_CONFIG_FILENAME "/home/loccs/memfreefuncs.txt"
#define MEM_REALLOC_CONFIG_FILENAME "/home/loccs/memreallocfuncs.txt"
#define MEM_LOGFILENAME "/home/loccs/log.txt"
/*
MemFuncsUtility is used to check whether a function is memory allocate function
or a memory free function since most librarys implement their own memory functions
*/
class MemFuncsUtility
{
  private:
  std::fstream mem_alloc_file;
  std::fstream mem_free_file;
  std::fstream mem_realloc_file;
  std::vector<std::string> memallocfuns;
  std::vector<std::string> memfreefuns;
  std::vector<std::string> memreallocfuns;
  Log *log;
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
  /*
  check if the function is in the set that represent the special treat functions
  */
  bool isKnownMallocFunction(std::string &func_name)
  {
    // just compare the function name
    for(std::string name:memallocfuns)
    {
      if(name == func_name)
          return true;
    }
    return false;
  }
  public:
  ~MemFuncsUtility()
  {
    delete log;
  }
  /*
  read specified function from configuration file.
  */
  MemFuncsUtility()
  {
    log = new Log(MEM_LOGFILENAME);
    mem_alloc_file.open(MEM_ALLOC_CONFIG_FILENAME);
    std::string readline;
    /*
    each line represent a memoryallocate function name
    */
    while (getline(mem_alloc_file, readline))  
    {
      memallocfuns.push_back(readline);
    }
    mem_alloc_file.close();
    mem_free_file.open(MEM_FREE_CONFIG_FILENAME);
    while (getline(mem_free_file, readline)) 
    {
      memfreefuns.push_back(readline);
    }
    mem_free_file.close();
    mem_realloc_file.open(MEM_REALLOC_CONFIG_FILENAME);
    while (getline(mem_realloc_file, readline)) 
    {
      memreallocfuns.push_back(readline);
    }
    mem_realloc_file.close();
  }
  bool isFreeFunction(const CallEvent &event)
  {
    std::string func_name = getFunctionNameFromCall(event);
    // just compare the function name
    for(std::string name:memfreefuns)
    {
      if(name == func_name)
      {
        return true;
      } 
    }
    return false;
  }
  bool isReallocFunction(const CallEvent &event)
  {
    
      std::string func_name = getFunctionNameFromCall(event);
      for(std::string name:memreallocfuns)
      {
        if (func_name == name)
        {
          return true;
        }
      }
      return false;
  }
  bool isSpecialFunction(const CallEvent &event)
  {
    std::string func_name = getFunctionNameFromCall(event);
    if (func_name == "wjq")
    {
      return true;
    }
    return false;
  }

/*
  Here we depend on several heuristics to determine whether a function is a memory 
  allocate function or not:
  1. the return type must be a pointer type but can not be a function pointer
  2. the return type must be void pointer or a structure or class pointer
  3. the number of args must be less than MAX_ALLOCFUNC_NUMARGS.
  4. each arg type of the function must be integer.
  In addtion, some known memory allocate funtion must be specifically treated. for
  instance, malloc,calloc.
*/
//now we define the max number of args 3, an empirical result. 
//maybe changed in future work.
#define MAX_ALLOCFUNC_NUMARGS 3
bool isMallocFunction(const CallEvent &event)
{
  /*
    first we checker if the function is a known memory allocate funtion.
    if so, return true.
  */
  std::string func_name = getFunctionNameFromCall(event);
  return isKnownMallocFunction(func_name);
  if(isKnownMallocFunction(func_name))
  {
    return true;
  }
    
  const Type *rettype =  event.getResultType().getTypePtr();
  if(!rettype)
    return false;
  if(!rettype->isAnyPointerType()||
     rettype->isFunctionPointerType())
    return false;
  if(!rettype->getPointeeOrArrayElementType()->isStructureOrClassType() &&
     !rettype->isVoidPointerType()
    )
    return false;
  unsigned int num_args = event.getNumArgs();
  if(num_args > MAX_ALLOCFUNC_NUMARGS)
    return false;
  //iterate each parameter to see if type is integer type.
  for(CallEvent::param_type_iterator it = event.param_type_begin();
      it != event.param_type_end();
      it++)
      {
        if(!(*it).getTypePtr()->isIntegerType())
          return false;
      }
    //llvm::outs() << func_name << "\n";
    return true;
  }
  

};

