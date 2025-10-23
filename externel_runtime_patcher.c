//info:
// ONLY FOR 64 BIT EXE'S...
// compile commadn: gcc -m64 c.c -o eternalPatcher x64.exe -lpsapi
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <psapi.h>

#define PATCH_FILE "patches.1337"

// Enable debug privilege for process access
BOOL EnableDebugPrivilege() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(token);
        return FALSE;
    }

    CloseHandle(token);
    return TRUE;
}

// Elevate to admin with UAC prompt if needed
void EnsureAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE token = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    if (!isAdmin) {
        char selfPath[MAX_PATH];
        GetModuleFileNameA(NULL, selfPath, MAX_PATH);
        
        SHELLEXECUTEINFOA sei = {0};
        sei.cbSize = sizeof(sei);
        sei.lpVerb = "runas";
        sei.lpFile = selfPath;
        sei.nShow = SW_NORMAL;
        
        if (ShellExecuteExA(&sei)) {
            exit(0);
        }
        else {
            printf("[!] Failed to elevate: %d\n", GetLastError());
        }
    }
}

// Find process ID by executable name
DWORD FindProcessId(const char *exeName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Snapshot error: %d\n", GetLastError());
        return 0;
    }
    
    if (!Process32First(snapshot, &pe32)) {
        printf("[!] Process32First error: %d\n", GetLastError());
        CloseHandle(snapshot);
        return 0;
    }
    
    do {
        if (_stricmp(pe32.szExeFile, exeName) == 0) {
            DWORD pid = pe32.th32ProcessID;
            CloseHandle(snapshot);
            return pid;
        }
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
    return 0;
}

// Get module base address
ULONGLONG GetModuleBaseAddress(DWORD pid, const char *moduleName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    
    ULONGLONG baseAddress = 0;
    if (Module32First(snapshot, &moduleEntry)) {
        do {
            if (_stricmp(moduleEntry.szModule, moduleName) == 0) {
                baseAddress = (ULONGLONG)moduleEntry.modBaseAddr;
                break;
            }
        } while (Module32Next(snapshot, &moduleEntry));
    }
    
    CloseHandle(snapshot);
    return baseAddress;
}

// Apply patches from file to process
void ApplyPatches(HANDLE hProcess, ULONGLONG baseAddress, const char *filePath) {
    FILE *file = fopen(filePath, "r");
    if (!file) {
        printf("[!] Couldn't open %s: %d\n", filePath, GetLastError());
        return;
    }

    char line[256];
    int lineNum = 0;
    int patchesApplied = 0;
    
    // Skip first line (EXE name)
    if (!fgets(line, sizeof(line), file)) {
        printf("[!] Empty patch file\n");
        fclose(file);
        return;
    }
    
    printf("\n[+] Applying patches (base: 0x%llX):\n", baseAddress);
    printf("RVA            | Full Address      | Original -> Patched | Status\n");
    printf("-----------------------------------------------------------------\n");
    
    while (fgets(line, sizeof(line), file)) {
        lineNum++;
        if (line[0] == ';' || line[0] == '\n' || line[0] == '\r') continue;
        
        // Parse: 000000000007E786:E8->90
        unsigned long long rva;
        char origByteStr[16] = {0};
        char newByteStr[16] = {0};
        int colonPos = -1, arrowPos = -1;
        
        // Find colon and arrow positions
        for (int i = 0; line[i] && i < 64; i++) {
            if (line[i] == ':') colonPos = i;
            if (line[i] == '-' && line[i+1] == '>') arrowPos = i;
        }
        
        if (colonPos < 0 || arrowPos < 0 || arrowPos <= colonPos) {
            printf("[!] Line %d: Invalid format\n", lineNum);
            continue;
        }
        
        // Extract RVA
        char addrStr[32] = {0};
        strncpy(addrStr, line, colonPos);
        rva = strtoull(addrStr, NULL, 16);
        
        // Calculate full address
        ULONGLONG fullAddress = baseAddress + rva;
        
        // Extract original and new byte values
        strncpy(origByteStr, line + colonPos + 1, arrowPos - colonPos - 1);
        strncpy(newByteStr, line + arrowPos + 2, 2);
        
        // Convert hex strings to bytes
        BYTE origByte = (BYTE)strtoul(origByteStr, NULL, 16);
        BYTE newByte = (BYTE)strtoul(newByteStr, NULL, 16);
        
        // Read current byte from process
        BYTE currentByte;
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hProcess, (LPCVOID)fullAddress, &currentByte, 1, &bytesRead)) {
            DWORD err = GetLastError();
            printf("0x%-12llX | 0x%-12llX | Error reading: %d\n", rva, fullAddress, err);
            continue;
        }
        
        // Apply patch
        SIZE_T bytesWritten;
        if (WriteProcessMemory(hProcess, (LPVOID)fullAddress, &newByte, 1, &bytesWritten)) {
            if (currentByte == origByte) {
                printf("0x%-12llX | 0x%-12llX | %02X -> %02X   | Patched ✓\n", 
                       rva, fullAddress, origByte, newByte);
                patchesApplied++;
            }
            else {
                printf("0x%-12llX | 0x%-12llX | %02X -> %02X   | Patched (was %02X) ⚠\n", 
                       rva, fullAddress, origByte, newByte, currentByte);
                patchesApplied++;
            }
        }
        else {
            DWORD err = GetLastError();
            printf("0x%-12llX | 0x%-12llX | %02X -> %02X   | Failed: %d\n", 
                   rva, fullAddress, origByte, newByte, err);
        }
    }
    
    fclose(file);
    printf("\n[+] Applied %d patches\n", patchesApplied);
}

// Extract EXE name from patch file
void GetTargetExeFromFile(char *targetExe) {
    FILE *file = fopen(PATCH_FILE, "r");
    if (!file) {
        strcpy(targetExe, "Raxis Xitters.exe");
        return;
    }
    
    if (fgets(targetExe, MAX_PATH, file)) {
        // Clean up the target EXE name
        char *start = targetExe;
        char *end = targetExe + strlen(targetExe);
        
        // Skip leading non-alphanumeric characters
        while (*start && !isalnum(*start)) start++;
        
        // Remove trailing whitespace
        while (end > start && isspace(*(end-1))) end--;
        *end = '\0';
        
        // Remove any file path
        char *lastSep = strrchr(start, '\\');
        if (!lastSep) lastSep = strrchr(start, '/');
        if (lastSep) start = lastSep + 1;
        
        // Copy cleaned name
        strcpy(targetExe, start);
    }
    else {
        strcpy(targetExe, "target.exe");
    }
    
    fclose(file);
}

// Start the target executable
BOOL StartTargetExe(const char *exeName) {
    printf("[~] Target not found in process...\n");
    
    // Build command to start the executable
    char command[512];
    sprintf(command, "start \"\" /B \"%s\" > nul 2>&1", exeName);
    
    // Try to start the executable
    if (system(command) != 0) {
        printf("[!] Failed to start %s\n", exeName);
        printf("[!] Command: %s\n", command);
        return FALSE;
    }
    
   printf("[~] Starting %s...\n", exeName);
    for (int i = 4; i > 0; i--) {
        printf("%d... ", i);
        Sleep(2000);
    }
    printf("\n");
    
    return TRUE;
}

int main() {
    EnsureAdmin();  // Auto-elevate to admin
    SetConsoleTitle("Made By TheGreen >_"); // removing credit is not a good thing haha...
    printf("\n===== Eternal Runtime Patcher v4.3 =====");
    printf("\n[+] Patch file: %s\n", PATCH_FILE);
    
    // Enable debug privilege for protected processes
    if (EnableDebugPrivilege()) {
    } else {
        printf("[!] Failed to enable debug privilege: %d\n", GetLastError());
    }
    
    // Get target EXE name from patch file
    char targetExe[MAX_PATH] = {0};
    GetTargetExeFromFile(targetExe);
    printf("[+] Target EXE: %s\n", targetExe);
    
    DWORD pid = 0;
    int attempts = 3;
    
    // Try to find process multiple times
    while (attempts-- > 0) {
        if ((pid = FindProcessId(targetExe))) {
            printf("[+] Found %s with PID: %lu\n", targetExe, pid);
            break;
        }else{
        printf("[~] Waiting for %s...\n", targetExe);
        Sleep(1000);
        break;
        }
    }
    
    // If process not found, start it
    if (!pid) {
        if (StartTargetExe(targetExe)) {
            // Give it extra time to start
            Sleep(4000);
            attempts = 10;
            while (attempts-- > 0) {
                if ((pid = FindProcessId(targetExe))) {
                    printf("[+] Found %s with PID: %lu\n", targetExe, pid);
                    break;
                }
                printf("[~] Waiting for %s to start...\n", targetExe);
                Sleep(1000);
            }
        }
    }
    
    if (!pid) {
        printf("\n[!] %s not found in process list\n", targetExe);
        printf("[!] Make sure it's running!\n");
        printf("\n===== Operation failed =====\n");
        printf("Press ENTER to exit...");
        getchar();
        return 1;
    }
    
    // Get module base address
    ULONGLONG baseAddress = GetModuleBaseAddress(pid, targetExe);
    if (baseAddress == 0) {
        printf("[!] Failed to get base address: %d\n", GetLastError());
        printf("[!] Using default base address 0x140000000\n");
        baseAddress = 0x140000000;  // Typical base address for 64-bit executables
    }
    else {
        printf("[+] Base address: 0x%llX\n", baseAddress);
    }
    
    // Open process with full access
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | 
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );
    
    if (!hProcess) {
        DWORD err = GetLastError();
        printf("\n[!] Couldn't open process: %d", err);
        printf("\n[!] Try running as Administrator\n");
        printf("\n===== Operation failed =====\n");
        printf("Press ENTER to exit...");
        getchar();
        return 1;
    }
    
    ApplyPatches(hProcess, baseAddress, PATCH_FILE);
    CloseHandle(hProcess);

Sleep(444);

         MessageBox(
    NULL,
    "Cracked By <YOUR_NAME>...",
    "Made By TheGreen >_",
    MB_OK | MB_ICONINFORMATION | MB_SYSTEMMODAL
);

    printf("\n===== Operation complete =====\n");
    printf("Press ENTER to exit...");
    getchar();
    return 0;
}
