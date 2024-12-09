// Compile with:
// "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /MT /EHsc /Fe:server.exe server.cpp ole32.lib oleaut32.lib

#include <windows.h>
#include <iostream>
#include "splitproc.h"

HANDLE log_file = NULL;
DWORD bytesWritten = 0;
DWORD bytesRead = 0;
BOOL verbose_output = TRUE;
char msg[1024];

void log_msg(const char * line)
{
	if(verbose_output) WriteFile(log_file,line,strlen(line),&bytesWritten, NULL);
}

void load_step()
{
	split_command command_step;
	// check if step exists	
	// read it from file		
	HANDLE step_file = CreateFileA("split.step", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(step_file==INVALID_HANDLE_VALUE)
	{	
		log_msg("Cannot open PTR file. Exiting.\n");		
		return;
	}		
	DWORD val = 0;
	ReadFile(step_file,&val,sizeof(DWORD),&bytesRead,NULL);
	CloseHandle(step_file);	
	
	snprintf(msg,sizeof(msg),"Loaded step value: %d\n",val);
	log_msg(msg);

	command_step=static_cast<split_command>(val);
	switch(command_step)
	{
        case split_command::GET_PID:
            std::cout << "GET_PID invoked." << std::endl;
			LoadLibrary("step1.dll");
            break;		
        case split_command::ALLOCATE_MEM:
            std::cout << "ALLOCATE_MEM invoked." << std::endl;
			LoadLibrary("step2.dll");
            break;
        case split_command::GENERATE_OPCODE:
            std::cout << "GENERATE_OPCODE invoked." << std::endl;
			LoadLibrary("step3.dll");
            break;
        case split_command::WRITE_MEM:
            std::cout << "WRITE_MEM invoked." << std::endl;
			LoadLibrary("step4.dll");
            break;
        case split_command::MEM_EXECUTABLE:
            std::cout << "MEM_EXECUTABLE invoked." << std::endl;
			LoadLibrary("step5.dll");
            break;
        case split_command::THREAD_TRIGGER:
            std::cout << "TRIGGER_THREAD ivoked." << std::endl;
			LoadLibrary("step6.dll");
            break;
		default:
			std::cout << "Unexpected command."<<std::endl;
	}
}
int main()
{
    // Initialize COM library
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        std::wcerr << L"Failed to initialize COM library. Error code: " << std::hex << hr << std::endl;
        return hr;
    }
	if(verbose_output)
	{
		log_file = CreateFileA("split.log", GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // create the log
		if (log_file != INVALID_HANDLE_VALUE)
		{
			SetFilePointer(log_file, 0, NULL, FILE_END);
		}
	}
    load_step();
    // Cleanup
    CoUninitialize();
    std::wcout << L"Server shutting down." << std::endl;
    return 0;
}