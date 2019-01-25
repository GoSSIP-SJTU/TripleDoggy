#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>

#define DEFAULT_LOG_FILENAME "/home/loccs/log.txt"

/*
simple wrapper of file operation.
*/
class Log
{
    llvm::raw_ostream *out;
    public:
    
    Log(std::string filename = DEFAULT_LOG_FILENAME,bool trancate = true )
    {
        std::error_code EC;
        if (!trancate)
            out = new llvm::raw_fd_ostream(filename, EC, llvm::sys::fs::F_Append);
        else
            out = new llvm::raw_fd_ostream(filename, EC, llvm::sys::fs::F_None);
    }
    ~Log()
    {
        delete out;
    }
    llvm::raw_ostream& getStream()
    {
        return *(this->out);
    }
    void stdlog(const char *con)
    {
        llvm::outs() << con;
    }
    void logLine(std::string &con)
    {   
        *out << con << "\n";
    }
    void logLine(const char *con)
    {   
        *out << std::string(con) << "\n";
    }
    void logRaw(std::string &con)
    {
        *out << con ;
    }
    void logRaw(const char *con)
    {
        *out << std::string(con);
    }
    void swline()
    {
        *out <<  "\n";
    }
};


