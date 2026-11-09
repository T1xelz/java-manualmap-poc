#include <Windows.h>

extern "C" void HostMain() {
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, L"Local\\ManualMapFixtureAttached");
    if (!event) {
        ExitProcess(2);
    }
    DWORD result = WaitForSingleObject(event, 60000);
    CloseHandle(event);
    // Give the Java mapper time to finish setting section protections before exiting.
    Sleep(2000);
    ExitProcess(result == WAIT_OBJECT_0 ? 0 : 3);
}
