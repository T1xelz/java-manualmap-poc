#include <Windows.h>

// Freestanding x86 fixture: no CRT, no static TLS, no C++ exceptions, no SEH.
// It exercises the reference's x86 feature set only: manual mapping, HIGHLOW
// relocations, imports, DllMain and the configured reason/reserved values.

extern "C" __declspec(dllexport) volatile DWORD MmAttached = 0;
// An initialized absolute pointer forces a HIGHLOW relocation when the image
// cannot be mapped at its preferred base.
extern "C" __declspec(dllexport) volatile DWORD* MmAttachedPointer = &MmAttached;

struct MmResults32 {
    DWORD magic;
    DWORD pass;
    DWORD fail;
    DWORD reason;
    DWORD reserved;
    DWORD relocOk;
    DWORD importOk;
    DWORD moduleOk;
    DWORD failMask;
};

extern "C" __declspec(dllexport) MmResults32 MmResultsData = {0x4D4D5445};

static DWORD g_pass;
static DWORD g_fail;
static DWORD g_failMask;

static void check(DWORD test, bool ok) {
    if (ok) {
        ++g_pass;
    } else {
        ++g_fail;
        g_failMask |= 1u << test;
    }
}

static void signalAttached() {
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\ManualMapFixtureAttached");
    if (event) {
        SetEvent(event);
        CloseHandle(event);
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved) {
    MmResultsData.reason = reason;
    MmResultsData.reserved = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(reserved));
    if (reason != DLL_PROCESS_ATTACH) {
        signalAttached();
        return TRUE;
    }
    DWORD pid = GetCurrentProcessId();
    *MmAttachedPointer = pid;
    MmResultsData.relocOk = (MmAttachedPointer == &MmAttached) ? 1 : 0;
    MmResultsData.importOk = (MmAttached == pid) ? 1 : 0;
    MmResultsData.moduleOk = (GetModuleHandleW(L"kernel32.dll") != nullptr) ? 1 : 0;
    check(0, MmResultsData.relocOk == 1);
    check(1, MmResultsData.importOk == 1);
    check(2, MmResultsData.moduleOk == 1);
    MmResultsData.pass = g_pass;
    MmResultsData.fail = g_fail;
    MmResultsData.failMask = g_failMask;
    signalAttached();
    return TRUE;
}
