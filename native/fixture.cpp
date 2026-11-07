#include <Windows.h>

// A relocation is guaranteed by this initialized absolute pointer.
extern "C" __declspec(dllexport) volatile DWORD MmAttached = 0;
extern "C" __declspec(dllexport) volatile DWORD* MmAttachedPointer = &MmAttached;

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        *MmAttachedPointer = GetCurrentProcessId();
        HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, L"Local\\ManualMapFixtureAttached");
        if (event) {
            SetEvent(event);
            CloseHandle(event);
        }
    }
    return TRUE;
}
