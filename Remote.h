#ifndef __REMOTE_HEADER__ 
#define __REMOTE_HEADER__ 

namespace Remote 
{ 
    namespace Allocate 
    { 
        void*    Alloc( HANDLE hProcess, size_t Size ); 
        void*    Commit( HANDLE hProcess, void* Data, size_t Size ); 
        void    Free( HANDLE hProcess, void* Data, size_t Size ); 
    }; 

    HANDLE    GetRemoteProcessHandleA( char *pszProcessName ); 
    HMODULE GetRemoteModuleHandleA( HANDLE hProcess, const char *szModule ); 
    HMODULE RemoteLoadLibraryA( HANDLE hProcess, char *pszLibraryPath ); 
    FARPROC GetRemoteProcAddress( HANDLE hProcess, char *pszModuleName, char *pszProcName ); 
}; 


#endif //__REMOTE_HEADER__  
