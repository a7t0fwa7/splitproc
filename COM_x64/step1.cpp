// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /TP step1.cpp /link /DLL /out:step1.dll /SUBSYSTEM:CONSOLE /MACHINE:x64

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
char msg[1024];

void log_msg(const char * line)
{
	if(verbose_output) WriteFile(log_file,line,strlen(line),&bytesWritten, NULL);
}

DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }
    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
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
	char proc_name[MAX_PATH];
	HANDLE proc_name_file = CreateFileA("proc.name", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(proc_name_file==INVALID_HANDLE_VALUE)
	{	
		log_msg("Cannot open the process name file (step1). Exiting.\n");		
		return FALSE;
	}		
	ReadFile(proc_name_file,&proc_name,MAX_PATH,&bytesRead,NULL);
	CloseHandle(proc_name_file);	
	
    DWORD pid = GetProcessIdByName(proc_name);
    if (!pid) {		
        log_msg("Process not found.\n");
		if(verbose_output) CloseHandle(log_file);
        return FALSE;
    }
	else
	{
		snprintf(msg,sizeof(msg),"PID found: %d\n",pid);
		log_msg(msg);		
		if(verbose_output) CloseHandle(log_file);	
		HANDLE pid_file = CreateFileA("split.pid", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);		
		WriteFile(pid_file,&pid,sizeof(pid),&bytesWritten, NULL); // save the PID value into a file
		CloseHandle(pid_file);
	}
    return TRUE;
}