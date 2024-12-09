// c:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
// cl.exe /D_USRDLL /D_WINDLL /MT /Tc deploy.cpp /link /DLL /out:deploy.dll /SUBSYSTEM:WINDOWS /MACHINE:x64
#include "dll.h"
#include <windows.h>
#include <iostream>
#include <vector>

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"advapi32.lib")

void CreateRegistrySetup() 
{
    HKEY hKey;
    LONG lRes;
    const char* subKey = "Software\\Classes\\CLSID\\{B0A7E410-1F7C-4B1A-8E0B-0A0C6D7E1234}";
    const char* localServerKey = "LocalServer32";

    // Get the current executable path
    char exePath[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, exePath, MAX_PATH);
    if (len == 0) {
        std::cerr << "Failed to get executable path. Error: " << GetLastError() << std::endl;
        return;
    }
    // Extract just the directory from the full path
    std::string exeDir = exePath;
	
    size_t lastBackslash = exeDir.find_last_of("\\/");
    if (lastBackslash != std::string::npos) {
        exeDir = exeDir.substr(0, lastBackslash + 1); // Include the backslash
    } else {
        std::cerr << "Unexpected executable path format." << std::endl;
        return;
    }
	std::string serverPath = exeDir + "server.exe";
    // Create or open the key
    lRes = RegCreateKeyEx(HKEY_CURRENT_USER, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    if (lRes != ERROR_SUCCESS) {
        std::cerr << "Failed to create or open the registry key. Error code: " << lRes << std::endl;
        return;
    }

    // Set the "SplitProc" string value
    lRes = RegSetValueEx(hKey, NULL, 0, REG_SZ, (BYTE*)"SplitProc", strlen("SplitProc") + 1);
    if (lRes != ERROR_SUCCESS) {
        std::cerr << "Failed to set SplitProc value. Error code: " << lRes << std::endl;
        RegCloseKey(hKey);
        return;
    }

    // Create the LocalServer32 subkey
    HKEY hSubKey;
    lRes = RegCreateKeyEx(hKey, localServerKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hSubKey, NULL);
    if (lRes == ERROR_SUCCESS) {
        // Set the default value for LocalServer32 to the path of the executable
        lRes = RegSetValueEx(hSubKey, NULL, 0, REG_SZ, (BYTE*)serverPath.c_str() , strlen(serverPath.c_str()) + 1);
        if (lRes != ERROR_SUCCESS) {
            std::cerr << "Failed to set LocalServer32 path. Error code: " << lRes << std::endl;
        }
        RegCloseKey(hSubKey);
    } else {
        std::cerr << "Failed to create LocalServer32 subkey. Error code: " << lRes << std::endl;
    }

    // Don't forget to close the main key
    RegCloseKey(hKey);

    if (lRes == ERROR_SUCCESS) {
        std::cout << "Registry keys and values created successfully!" << std::endl;
    }	
}
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	if(ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		CreateRegistrySetup();
	}
}
