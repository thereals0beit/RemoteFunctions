#include "stdafx.h" 
#include "Remote.h" 

DWORD WINAPI lpThreadForSpaceBar( LPVOID lpParam ) 
{ 
    while( ( GetAsyncKeyState( VK_SPACE ) & 1 ) == 0 ) 
    { 
        Sleep( 100 ); 
    } 

    return 0; 
} 

int _tmain(int argc, _TCHAR* argv[]) 
{ 
    HANDLE hCalculator = Remote::GetRemoteProcessHandleA( "calc.exe" ); 

    if( hCalculator != INVALID_HANDLE_VALUE ) 
    { 
        FARPROC RemoteLoadLibraryA = Remote::GetRemoteProcAddress( hCalculator, "Kernel32.dll", "LoadLibraryA" ); 

        if( RemoteLoadLibraryA ) 
        { 
            printf( "LoadLibraryA Address is [0x%X]\n", RemoteLoadLibraryA ); 
        } 
        else 
        { 
            printf( "LoadLibraryA Address was not found..\n" ); 
        } 

        HMODULE hRemoteUser32 = Remote::RemoteLoadLibraryA( hCalculator, "User32.dll" ); 

        if( hRemoteUser32 ) 
        { 
            printf( "USER32.DLL Address is [0x%X][0x%X]\n", hRemoteUser32, GetModuleHandleA( "User32.dll" ) ); 
        } 
        else 
        { 
            printf( "USER32.DLL was not found..\n" ); 
        } 

        CloseHandle( hCalculator ); // Remember to close the handle from OpenProcess 
    } 
    else 
    { 
        printf( "Error opening process: INVALID_HANDLE_VALUE\n" ); 
    } 

    printf( "Press the space bar to continue...\n" ); 

    WaitForSingleObject( CreateThread( 0, 0, lpThreadForSpaceBar, 0, 0, 0 ), INFINITE ); 

    return 0; 
}  
