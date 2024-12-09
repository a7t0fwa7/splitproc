// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /TP step2.cpp /link /DLL /out:step2.dll /SUBSYSTEM:CONSOLE /MACHINE:x64

#include "dll.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

typedef unsigned __int64 QWORD;
HANDLE log_file = NULL;
DWORD bytesWritten = 0;
DWORD bytesRead = 0;
BOOL verbose_output = TRUE;
DWORD target_proc_pid = 0;
DWORD bufferSize = 1024; // won't be more
char msg[1024];

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
		log_file = CreateFileA("split.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // create the log
		if (log_file != INVALID_HANDLE_VALUE)
		{
			SetFilePointer(log_file, 0, NULL, FILE_END);
		}
	}

	HANDLE pid_file = CreateFileA("split.pid", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(pid_file==INVALID_HANDLE_VALUE)
	{
		log_msg("Cannot open PID file. Exiting.\n");
		if(verbose_output) CloseHandle(log_file);	
		return FALSE;
	}
	ReadFile(pid_file,&target_proc_pid,sizeof(target_proc_pid),&bytesRead,NULL);
	CloseHandle(pid_file);
	
    if (!target_proc_pid) {		
        log_msg("Process PID not found in the log.\n");
		if(verbose_output) CloseHandle(log_file);
        return FALSE;
    }
	else
	{
		snprintf(msg,sizeof(msg),"PID found (step2) in the log: %d\n",target_proc_pid);
		log_msg(msg);		
	
		// Now, conduct phase 1 of the injection process, save the result.
		HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, target_proc_pid);
		if (!hProcess) {
			log_msg("Failed to open the target process.\n");
			printf("LAST ERROR: %d",GetLastError());
			return FALSE;
		}
		LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, bufferSize, 
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!remoteBuffer) {
			log_msg("Failed to allocate memory in target process.\n");
			CloseHandle(hProcess);
			return 0;
		}	
		snprintf(msg,sizeof(msg),"Remote buffer allocated (ext2): %p\n",remoteBuffer);
		log_msg(msg);			
		QWORD ptrAsInt = (QWORD)remoteBuffer;
		// now, save the address into a new file
		HANDLE ptr_file = CreateFileA("split.buff_addr", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);		
		WriteFile(ptr_file,&ptrAsInt,sizeof(QWORD),&bytesWritten, NULL); // save the PID value into the file
		CloseHandle(ptr_file);		
		
		if(verbose_output) CloseHandle(log_file);	
	}
    return 0;
}