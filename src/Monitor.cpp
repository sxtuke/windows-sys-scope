#include "../include/Monitor.h"
#include "../include/NtStructs.h"
#include <iostream>
#include <iomanip>
#include <vector>

KernelMonitor::KernelMonitor() {
    hNtDll = nullptr;
    pNtQuerySystemInformation = nullptr;
    
    EnableDebugPrivilege();
    InitializeNtDll();
}

KernelMonitor::~KernelMonitor() {
    if (hNtDll) {
        FreeLibrary(hNtDll);
        hNtDll = nullptr;
    }
}

bool KernelMonitor::InitializeNtDll() {
    hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) {
        hNtDll = LoadLibraryW(L"ntdll.dll");
    }

    if (hNtDll) {
        pNtQuerySystemInformation = GetProcAddress(hNtDll, "NtQuerySystemInformation");
        return pNtQuerySystemInformation != nullptr;
    }
    return false;
}

bool KernelMonitor::IsInitialized() const {
    return pNtQuerySystemInformation != nullptr;
}

bool KernelMonitor::EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    return result;
}

void KernelMonitor::EnumerateProcesses() {
    if (!IsInitialized()) {
        std::cerr << "[-] Error: NtQuerySystemInformation is not loaded.\n";
        return;
    }

    auto NtQuerySystemInfo = reinterpret_cast<PNT_QUERY_SYSTEM_INFORMATION>(pNtQuerySystemInformation);
    ULONG bufferSize = 1024 * 1024; 
    std::vector<BYTE> buffer(bufferSize);
    NTSTATUS status;

    while ((status = NtQuerySystemInfo(SystemProcessInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &bufferSize)) == STATUS_INFO_LENGTH_MISMATCH) {
        buffer.resize(bufferSize);
    }

    if (NT_SUCCESS(status)) {
        auto pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data());
        
        std::cout << "\n[+] Level Process Enumeration:\n";
        std::cout << std::left << std::setw(10) << "PID" 
                  << std::setw(15) << "Threads" 
                  << "Process Name\n";
        std::cout << "--------------------------------------------------\n";

        while (true) {
            std::wstring procName = pProcessInfo->ImageName.Buffer ? pProcessInfo->ImageName.Buffer : L"System Idle Process";
            ULONG pid = HandleToULong(pProcessInfo->UniqueProcessId);
            ULONG threads = pProcessInfo->NumberOfThreads;

            std::wcout << std::left << std::setw(10) << pid 
                       << std::setw(15) << threads 
                       << procName << L"\n";

            if (pProcessInfo->NextEntryOffset == 0) break;
            
            pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
                reinterpret_cast<PUCHAR>(pProcessInfo) + pProcessInfo->NextEntryOffset
            );
        }
    } else {
        std::cerr << "[-] Failed to enumerate processes. NTSTATUS: 0x" << std::hex << status << "\n";
    }
}

void KernelMonitor::EnumerateHandles(ULONG_PTR targetProcessId) {
    if (!IsInitialized()) return;

    auto NtQuerySystemInfo = reinterpret_cast<PNT_QUERY_SYSTEM_INFORMATION>(pNtQuerySystemInformation);
    ULONG bufferSize = 1024 * 1024 * 8; 
    std::vector<BYTE> buffer(bufferSize);
    NTSTATUS status;

    // Dinamik tampon boyutlandırması
    while ((status = NtQuerySystemInfo(SystemExtendedHandleInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &bufferSize)) == STATUS_INFO_LENGTH_MISMATCH) {
        buffer.resize(bufferSize + (1024 * 1024));
    }

    if (NT_SUCCESS(status)) {
        auto pHandleInfo = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.data());
        
        std::cout << "\n[+] Enumerating System Handles " 
                  << (targetProcessId != 0 ? "(Filtered by PID: " + std::to_string(targetProcessId) + ")" : "(All)") << ":\n";
        std::cout << "Total Handles Found OS-Wide: " << pHandleInfo->NumberOfHandles << "\n";
        std::cout << "--------------------------------------------------\n";
        
        ULONG_PTR displayCount = 0;
        
        for (ULONG_PTR i = 0; i < pHandleInfo->NumberOfHandles; i++) {
            auto& handle = pHandleInfo->Handles[i];
            
            if (targetProcessId != 0 && handle.UniqueProcessId != targetProcessId) 
                continue;

            std::cout << "  PID: " << std::setw(6) << handle.UniqueProcessId 
                      << " | Handle: 0x" << std::hex << std::setw(6) << handle.HandleValue 
                      << " | ObjectPtr: 0x" << std::setw(16) << handle.Object 
                      << " | TypeIndex: " << std::dec << handle.ObjectTypeIndex << "\n";
            
            displayCount++;
            
            if (displayCount >= 25 && targetProcessId == 0) {
                std::cout << "  ... (Output truncated to prevent console flooding. Provide a specific PID to see more) ...\n";
                break;
            }
        }
    } else {
        std::cerr << "[-] Failed to enumerate handles. NTSTATUS: 0x" << std::hex << status << "\n";
    }
}
