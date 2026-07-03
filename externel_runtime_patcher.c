//info:
// compile: gcc -m64 patcher.c -o patcher.exe -lpsapi

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>
#include <stdlib.h>

// Enable debug privilege
void EnableDebug() {
    HANDLE token;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    TOKEN_PRIVILEGES tp;
    LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);
}

// Run as admin
void RunAsAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    if (!isAdmin) {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        SHELLEXECUTEINFOA sei = { sizeof(sei), "runas", path, NULL, NULL, SW_NORMAL };
        if (ShellExecuteExA(&sei)) exit(0);
    }
}

// Clean string
void Clean(char* str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) str[--len] = 0;
    if (len >= 2 && str[0] == '"' && str[len - 1] == '"') {
        memmove(str, str + 1, len - 2);
        str[len - 2] = 0;
    }
}

// Find module by name and get its base address
ULONGLONG FindModuleBase(HANDLE hProcess, const char* moduleName) {
    HMODULE modules[1024];
    DWORD needed;
    char name[MAX_PATH];

    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        return 0;
    }

    int count = needed / sizeof(HMODULE);

    // If they entered a number, use that index
    if (isdigit(moduleName[0])) {
        int index = atoi(moduleName);
        if (index >= 0 && index < count) {
            return (ULONGLONG)modules[index];
        }
        return 0;
    }

    // Search by name (case insensitive)
    for (int i = 0; i < count; i++) {
        if (GetModuleBaseNameA(hProcess, modules[i], name, sizeof(name))) {
            if (_stricmp(name, moduleName) == 0) {
                return (ULONGLONG)modules[i];
            }
            // Also check if moduleName is part of the filename (e.g., "x.dll" matches "x.dll")
            char* lowerName = _strdup(name);
            char* lowerSearch = _strdup(moduleName);
            for (char* p = lowerName; *p; p++) *p = tolower(*p);
            for (char* p = lowerSearch; *p; p++) *p = tolower(*p);
            if (strstr(lowerName, lowerSearch) || strstr(lowerSearch, lowerName)) {
                free(lowerName);
                free(lowerSearch);
                return (ULONGLONG)modules[i];
            }
            free(lowerName);
            free(lowerSearch);
        }
    }

    return 0;
}

// List all modules
void ListModules(HANDLE hProcess) {
    HMODULE modules[1024];
    DWORD needed;
    char name[MAX_PATH];

    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        printf("[!] Cannot enumerate modules\n");
        return;
    }

    int count = needed / sizeof(HMODULE);
    printf("\n[+] Loaded modules:\n");
    printf("----------------------------------------\n");

    for (int i = 0; i < count; i++) {
        if (GetModuleBaseNameA(hProcess, modules[i], name, sizeof(name))) {
            printf("  [%d] 0x%016llX - %s\n", i, (ULONGLONG)modules[i], name);
        }
    }
    printf("----------------------------------------\n");
}

// Patch memory with error details
BOOL PatchMemory(HANDLE hProcess, LPVOID address, BYTE oldByte, BYTE newByte) {
    BYTE current;
    SIZE_T read;

    // Try to read first
    if (!ReadProcessMemory(hProcess, address, &current, 1, &read)) {
        DWORD err = GetLastError();
        if (err == 299) {
            // ERROR_PARTIAL_COPY - try to commit the memory first
            DWORD oldProtect;
            if (VirtualProtectEx(hProcess, address, 1, PAGE_READWRITE, &oldProtect)) {
                // Memory is now committed
            }
            // Try reading again
            if (!ReadProcessMemory(hProcess, address, &current, 1, &read)) {
                return FALSE;
            }
        }
        else {
            return FALSE;
        }
    }

    // Change protection
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    // Write patch
    SIZE_T written;
    BOOL result = WriteProcessMemory(hProcess, address, &newByte, 1, &written);

    // Restore protection
    VirtualProtectEx(hProcess, address, 1, oldProtect, &oldProtect);

    return result && (written == 1);
}

int main() {
    RunAsAdmin();
    EnableDebug();

    printf("\n====================================\n");
    printf("   RUNTIME PATCHER - EXE/DLL\n");
    printf("====================================\n\n");

    // Get PID
    DWORD pid = 0;
    printf("Enter PID: ");
    scanf("%lu", &pid);
    getchar();

    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("\n[!] Cannot open process %lu (Error: %d)\n", pid, GetLastError());
        printf("\nPress ENTER to exit...");
        getchar();
        return 1;
    }

    printf("[+] Process opened successfully!\n");

    // List modules
    ListModules(hProcess);

    // Get module name or index
    char moduleName[256] = { 0 };
    printf("\nEnter module name or number to patch (e.g., x.dll or 5): ");
    fgets(moduleName, sizeof(moduleName), stdin);
    Clean(moduleName);

    // Find module base
    ULONGLONG baseAddress = FindModuleBase(hProcess, moduleName);
    if (!baseAddress) {
        printf("[!] Module not found: %s\n", moduleName);
        CloseHandle(hProcess);
        printf("\nPress ENTER to exit...");
        getchar();
        return 1;
    }

    printf("[+] Base address of '%s': 0x%llX\n", moduleName, baseAddress);

    // Get patch file
    char patchFile[MAX_PATH] = { 0 };
    printf("Drag and drop patch file: ");
    fgets(patchFile, MAX_PATH, stdin);
    Clean(patchFile);

    if (GetFileAttributesA(patchFile) == INVALID_FILE_ATTRIBUTES) {
        printf("\n[!] Patch file not found: %s\n", patchFile);
        CloseHandle(hProcess);
        printf("\nPress ENTER to exit...");
        getchar();
        return 1;
    }

    // Read patch file
    FILE* file = fopen(patchFile, "r");
    if (!file) {
        printf("[!] Cannot read patch file\n");
        CloseHandle(hProcess);
        printf("\nPress ENTER to exit...");
        getchar();
        return 1;
    }

    // Skip first line (EXE name)
    char line[256];
    fgets(line, sizeof(line), file);
    printf("\n[+] Patch file is for: %s", line);
    printf("[+] Patching module: %s\n", moduleName);
    printf("[+] Base address: 0x%llX\n", baseAddress);

    printf("\n[+] Applying patches:\n");
    printf("----------------------------------------\n");

    int patched = 0;
    int failed = 0;

    // Parse and apply patches
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == ';' || line[0] == '\n' || line[0] == '\r') continue;

        unsigned long long rva;
        char old[3], new[3];

        if (sscanf(line, "%llx:%2s->%2s", &rva, old, new) == 3) {
            ULONGLONG address = baseAddress + rva;
            BYTE oldByte = (BYTE)strtoul(old, NULL, 16);
            BYTE newByte = (BYTE)strtoul(new, NULL, 16);

            if (PatchMemory(hProcess, (LPVOID)address, oldByte, newByte)) {
                printf("  [+] 0x%08llX -> %02X (was %02X)\n", rva, newByte, oldByte);
                patched++;
            }
            else {
                DWORD err = GetLastError();
                printf("  [!] 0x%08llX -> FAILED (err: %d)\n", rva, err);
                failed++;
            }
        }
    }

    fclose(file);
    CloseHandle(hProcess);

    printf("\n[+] Patched: %d | Failed: %d\n", patched, failed);
    printf("\n====================================\n");
    printf("  DONE!\n");
    printf("====================================\n");

    printf("\nPress ENTER to exit...");
    getchar();
    return 0;
}
