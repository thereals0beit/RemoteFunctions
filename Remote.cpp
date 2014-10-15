#include "stdafx.h" 
#include "Remote.h" 

namespace Remote 
{ 
    namespace Allocate 
    { 
        void* Alloc( HANDLE hProcess, size_t Size ) 
        { 
            return VirtualAllocEx( hProcess, NULL, Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ); 
        } 

        void* Commit( HANDLE hProcess, void* Data, size_t Size ) 
        { 
            void* AllocatedPointer = Alloc( hProcess, Size ); 

            if( AllocatedPointer ) 
            { 
                if( WriteProcessMemory( hProcess, AllocatedPointer, Data, Size, NULL ) == TRUE ) 
                { 
                    return AllocatedPointer; 
                } 
                 
                Free( hProcess, AllocatedPointer, Size ); 
            } 

            return NULL; 
        } 

        void Free( HANDLE hProcess, void* Data, size_t Size ) 
        { 
            VirtualFreeEx( hProcess, Data, Size, MEM_RELEASE ); 
        } 
    }; 

    HANDLE GetRemoteProcessHandleA( char *pszProcessName ) 
    { 
        HANDLE tlh = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL ); 

        PROCESSENTRY32 proEntry; 
         
        proEntry.dwSize = sizeof( PROCESSENTRY32 ); 

        Process32First( tlh, &proEntry ); 
        do 
        { 
            if( _stricmp( pszProcessName, proEntry.szExeFile ) == 0 ) 
            { 
                CloseHandle( tlh ); 

                return OpenProcess( PROCESS_ALL_ACCESS, FALSE, proEntry.th32ProcessID ); 
            } 
        } 
        while( Process32Next( tlh, &proEntry ) ); 

        CloseHandle( tlh ); 

        return INVALID_HANDLE_VALUE; 
    } 

    HMODULE GetRemoteModuleHandleA( HANDLE hProcess, const char *szModule ) 
    { 
        HANDLE tlh = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, GetProcessId( hProcess ) ); 

        MODULEENTRY32 modEntry; 
         
        modEntry.dwSize = sizeof( MODULEENTRY32 ); 

        Module32First( tlh, &modEntry ); 
        do 
        { 
            if( _stricmp( szModule, modEntry.szModule ) == 0 ) 
            { 
                CloseHandle( tlh ); 

                return modEntry.hModule; 
            } 
        } 
        while( Module32Next( tlh, &modEntry ) ); 

        CloseHandle( tlh ); 

        return NULL; 
    } 

    HMODULE RemoteLoadLibraryA( HANDLE hProcess, char *pszLibraryPath ) 
    { 
        unsigned long ulReturnValue = NULL; 

        if( pszLibraryPath ) 
        { 
            FARPROC fpLoadLibraryARemote = GetRemoteProcAddress( hProcess, "Kernel32.dll", "LoadLibraryA" ); 

            if( fpLoadLibraryARemote ) 
            { 
                void* AllocatedResult = Allocate::Alloc( hProcess, sizeof( unsigned long ) ); 
                void* CommitedLibName = Allocate::Commit( hProcess, pszLibraryPath, strlen( pszLibraryPath ) + 1 ); 

                if( CommitedLibName ) 
                { 
                    unsigned char LoadLibraryAThreadBuffer[ 22 ] = 
                    { 
                        0x68, 0x00, 0x00, 0x00, 0x00,         //push lib name 
                        0xB8, 0x00, 0x00, 0x00, 0x00,        //mov eax, LoadLibraryA 
                        0xFF, 0xD0,                         //call eax 
                        0xA3, 0x00, 0x00, 0x00, 0x00,         //mov result, eax 
                        0x33, 0xC0,                         //xor eax, eax (eax = 0) 
                        0xC2, 0x04, 0x00                     //retn 4 
                    }; 

                    *( unsigned long* )( LoadLibraryAThreadBuffer + 0x01 ) = ( unsigned long ) CommitedLibName; 
                    *( unsigned long* )( LoadLibraryAThreadBuffer + 0x06 ) = ( unsigned long ) fpLoadLibraryARemote; 
                    *( unsigned long* )( LoadLibraryAThreadBuffer + 0x0D ) = ( unsigned long ) AllocatedResult; 

                    void* RemoteBufferToWrite = Allocate::Commit( hProcess, LoadLibraryAThreadBuffer, sizeof( LoadLibraryAThreadBuffer ) ); 

                    if( RemoteBufferToWrite ) 
                    { 
                        HANDLE hSpawnedThread = CreateRemoteThread( hProcess, 0, 0, ( LPTHREAD_START_ROUTINE ) RemoteBufferToWrite, 0, 0, 0 ); 

                        WaitForSingleObject( hSpawnedThread, INFINITE ); // Async.. 

                        ReadProcessMemory( hProcess, AllocatedResult, &ulReturnValue, sizeof( unsigned long ), NULL ); 

                        Allocate::Free( hProcess, RemoteBufferToWrite, sizeof( LoadLibraryAThreadBuffer ) ); 
                    } 

                    Allocate::Free( hProcess, CommitedLibName, strlen( pszLibraryPath ) + 1 ); 
                } 
            } 
        } 

        return reinterpret_cast< HMODULE >( ulReturnValue ); 
    } 

    FARPROC GetRemoteProcAddress( HANDLE hProcess, char *pszModuleName, char *pszProcName ) 
    { 
        FARPROC fpReturnValue = NULL; 
         
        HMODULE hLocalKernel = GetModuleHandleA( "Kernel32.dll" ); 

        if( hLocalKernel ) 
        { 
            HMODULE hRemoteKernel = GetRemoteModuleHandleA( hProcess, "Kernel32.dll" ); 

            if( hRemoteKernel ) 
            { 
                unsigned long RemoteGetProcAddress =  
                    ( unsigned long ) hRemoteKernel + ( unsigned long )( ( unsigned long ) GetProcAddress - ( unsigned long ) hLocalKernel ); 

                void* ResultOfGetProcAddress = Allocate::Alloc( hProcess, sizeof( unsigned long ) ); 

                void* CommitedProcName = Allocate::Commit( hProcess, pszProcName, strlen( pszProcName ) + 1 ); 

                if( ResultOfGetProcAddress && CommitedProcName ) 
                { 
                    unsigned char GetProcAddressThreadBuffer[ 27 ] = 
                    { 
                        0x68, 0x00, 0x00, 0x00, 0x00,         //push proc name 
                        0x68, 0x00, 0x00, 0x00, 0x00,         //push module address 
                        0xB8, 0x00, 0x00, 0x00, 0x00,        //mov eax, GetProcAddress 
                        0xFF, 0xD0,                         //call eax 
                        0xA3, 0x00, 0x00, 0x00, 0x00,         //mov result, eax 
                        0x33, 0xC0,                         //xor eax, eax (eax = 0) 
                        0xC2, 0x04, 0x00                     //retn 4 
                    }; 

                    *( unsigned long* )( GetProcAddressThreadBuffer + 0x01 ) = ( unsigned long ) CommitedProcName; 
                    *( unsigned long* )( GetProcAddressThreadBuffer + 0x06 ) = ( unsigned long ) hRemoteKernel; 
                    *( unsigned long* )( GetProcAddressThreadBuffer + 0x0B ) = ( unsigned long ) RemoteGetProcAddress; 
                    *( unsigned long* )( GetProcAddressThreadBuffer + 0x12 ) = ( unsigned long ) ResultOfGetProcAddress; 

                    void* RemoteBufferToWrite = Allocate::Commit( hProcess, GetProcAddressThreadBuffer, sizeof( GetProcAddressThreadBuffer ) ); 

                    if( RemoteBufferToWrite ) 
                    { 
                        HANDLE hSpawnedThread = CreateRemoteThread( hProcess, 0, 0, ( LPTHREAD_START_ROUTINE ) RemoteBufferToWrite, 0, 0, 0 ); 

                        WaitForSingleObject( hSpawnedThread, INFINITE ); // Async.. 

                        ReadProcessMemory( hProcess, ResultOfGetProcAddress, &fpReturnValue, sizeof( unsigned long ), NULL ); 

                        Allocate::Free( hProcess, RemoteBufferToWrite, sizeof( GetProcAddressThreadBuffer ) ); 
                    } 
                } 

                if( ResultOfGetProcAddress ) 
                { 
                    Allocate::Free( hProcess, ResultOfGetProcAddress, sizeof( unsigned long ) ); 
                } 

                if( CommitedProcName ) 
                { 
                    Allocate::Free( hProcess, CommitedProcName, strlen( pszProcName ) + 1 ); 
                } 

            } 
        } 

        return fpReturnValue; 
    } 
};  
