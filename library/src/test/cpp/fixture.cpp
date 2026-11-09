#include <Windows.h>
#include <exception>
#include <stdexcept>
#include <string>
#include <string.h>

// Force the linker to emit the TLS directory even at /O2.
#pragma comment(linker, "/INCLUDE:_tls_used")

#ifndef EH_MODE_LABEL
#define EH_MODE_LABEL "unknown"
#endif

// A relocation is guaranteed by this initialized absolute pointer.
extern "C" __declspec(dllexport) volatile DWORD MmAttached = 0;
extern "C" __declspec(dllexport) volatile DWORD* MmAttachedPointer = &MmAttached;

struct MmResults {
    DWORD magic;
    DWORD pass;
    DWORD fail;
    DWORD reason;
    DWORD reserved;
    DWORD tlsCallbacks;
    DWORD tlsMain;
    DWORD tlsMainAfter;
    DWORD tlsWorker;
    DWORD tlsIsolated;
    DWORD threadAttach;
    DWORD failMask;
};

extern "C" __declspec(dllexport) MmResults MmResultsData = {0x4D4D5445};

static LONG g_pass;
static LONG g_fail;
static DWORD g_tlsCallbacks;
static volatile LONG g_threadAttach;
static DWORD g_currentTest = 0xFFFFFFFFu;
static DWORD g_testIndex;
static DWORD g_failMask;

// Accessed through TEB.ThreadLocalStoragePointer[_tls_index]; requires the
// injector to hand ntdll a valid module entry before any DLL code runs.
thread_local int g_tlsCounter = 0x1234;
thread_local char g_tlsBuffer[64] = "tls-ok";

static void check(bool ok) {
    if (ok) {
        InterlockedIncrement(&g_pass);
    } else {
        InterlockedIncrement(&g_fail);
        if (g_currentTest < 32) {
            g_failMask |= 1u << g_currentTest;
        }
    }
}

// ---------------------------------------------------------------------------
// Exception test types
// ---------------------------------------------------------------------------
struct ExcBase {
    int magic;
    char tag[32];
    ExcBase(int m, const char* t) : magic(m) {
        lstrcpyA(tag, t);
    }
    virtual ~ExcBase() {}
    virtual const char* name() const { return "ExcBase"; }
};

struct ExcDerived : ExcBase {
    int extra;
    ExcDerived(int m, const char* t, int e) : ExcBase(m, t), extra(e) {}
    const char* name() const override { return "ExcDerived"; }
};

struct NonCopyExc {
    int x;
    NonCopyExc(int v) : x(v) {}
    NonCopyExc(const NonCopyExc&) = default;
};

struct DtorMarker {
    int* flag;
    DtorMarker(int* f) : flag(f) { *f = 0; }
    ~DtorMarker() { *flag = 1; }
};

static void __declspec(noinline) ThrowInt() { throw 42; }
static void __declspec(noinline) ThrowStdRE() { throw std::runtime_error("re-ok"); }
static void __declspec(noinline) ThrowCustomBase() { throw ExcBase(0xB16B16, "base"); }
static void __declspec(noinline) ThrowCustomDerived() { throw ExcDerived(0xDEAD, "derived", 99); }
static void __declspec(noinline) ThrowString() { throw std::string("string-exc"); }
static void __declspec(noinline) ThrowNonCopy() { throw NonCopyExc(777); }
static void __declspec(noinline) DeepB() { ThrowStdRE(); }
static void __declspec(noinline) DeepA() { DeepB(); }
static void __declspec(noinline) DeepStart() { DeepA(); }

// Exported so an external caller could invoke it; C++ linkage on purpose.
// Under /EHsc an `extern "C"` callee is assumed not to throw (C4297), which
// makes a throwing export undefined behaviour rather than an injector test.
__declspec(dllexport) void MmThrow(int kind) {
    switch (kind) {
        case 0: throw 123;
        case 1: throw std::runtime_error("exported-re");
        case 2: throw ExcDerived(0xC0FFEE, "exp", 1);
        default: throw std::string("exp-str");
    }
}

// ---------------------------------------------------------------------------
// C++ exception tests, one check per scenario
// ---------------------------------------------------------------------------
static void TestThrowInt() {
    bool ok = false;
    try {
        ThrowInt();
    } catch (int value) {
        ok = value == 42;
    }
    check(ok);
}

static void TestStdException() {
    bool ok = false;
    try {
        ThrowStdRE();
    } catch (const std::exception& error) {
        ok = strcmp(error.what(), "re-ok") == 0;
    }
    check(ok);
}

static void TestCustomCaughtByValue() {
    bool ok = false;
    try {
        ThrowCustomBase();
    } catch (ExcBase error) {
        ok = error.magic == 0xB16B16;
    }
    check(ok);
}

static void TestCustomCaughtByRef() {
    bool ok = false;
    try {
        ThrowCustomDerived();
    } catch (const ExcBase& error) {
        ok = error.magic == 0xDEAD && strcmp(error.name(), "ExcDerived") == 0;
    }
    check(ok);
}

static void TestCatchDerivedFromBase() {
    bool ok = false;
    try {
        ThrowCustomDerived();
    } catch (const ExcDerived& error) {
        ok = error.extra == 99;
    } catch (const ExcBase&) {
        ok = false;
    }
    check(ok);
}

static void TestWrongTypeFallsThrough() {
    bool caughtInt = false;
    bool caughtOuter = false;
    try {
        try {
            ThrowStdRE();
        } catch (int) {
            caughtInt = true;
        }
    } catch (const std::exception&) {
        caughtOuter = true;
    }
    check(!caughtInt && caughtOuter);
}

static void TestCatchAll() {
    bool ok = false;
    try {
        ThrowString();
    } catch (...) {
        ok = true;
    }
    check(ok);
}

static void TestRethrow() {
    bool ok = false;
    try {
        try {
            ThrowStdRE();
        } catch (const std::exception&) {
            throw;
        }
    } catch (const std::runtime_error& error) {
        ok = strcmp(error.what(), "re-ok") == 0;
    }
    check(ok);
}

static void TestCurrentException() {
    bool ok = false;
    std::exception_ptr pointer;
    try {
        ThrowStdRE();
    } catch (...) {
        pointer = std::current_exception();
    }
    try {
        if (pointer) {
            std::rethrow_exception(pointer);
        }
    } catch (const std::runtime_error& error) {
        ok = strcmp(error.what(), "re-ok") == 0;
    }
    check(ok);
}

static void TestDeepUnwind() {
    bool ok = false;
    try {
        DeepStart();
    } catch (const std::runtime_error& error) {
        ok = strcmp(error.what(), "re-ok") == 0;
    }
    check(ok);
}

static void TestStackUnwindCallsDtors() {
    int destructed = -1;
    try {
        DtorMarker marker(&destructed);
        ThrowInt();
    } catch (int) {
    }
    check(destructed == 1);
}

static void TestNonCopyLike() {
    bool ok = false;
    try {
        ThrowNonCopy();
    } catch (const NonCopyExc& error) {
        ok = error.x == 777;
    }
    check(ok);
}

static void TestFromLambda() {
    bool ok = false;
    auto lambda = []() { throw std::runtime_error("from-lambda"); };
    try {
        lambda();
    } catch (const std::exception& error) {
        ok = strcmp(error.what(), "from-lambda") == 0;
    }
    check(ok);
}

static void TestFromLambdaIndirect() {
    bool ok = false;
    auto lambda = []() -> void { throw ExcDerived(0xBEEF, "lam", 7); };
    void (*function)() = *(+lambda);
    try {
        function();
    } catch (const ExcBase& error) {
        ok = error.magic == 0xBEEF && strcmp(error.name(), "ExcDerived") == 0;
    }
    check(ok);
}

static void TestSequentialDispatch() {
    bool ok = true;
    void (*functions[])() = {ThrowInt, ThrowStdRE, ThrowCustomBase};
    try {
        for (int i = 0; i < 3; ++i) {
            try {
                functions[i]();
            } catch (int value) {
                if (value != 42) {
                    throw;
                }
            } catch (const std::exception&) {
            } catch (const ExcBase& error) {
                if (error.magic != 0xB16B16) {
                    throw;
                }
            }
        }
    } catch (...) {
        ok = false;
    }
    check(ok);
}

static void TestNestedTry() {
    bool ok = false;
    try {
        try {
            try {
                ThrowStdRE();
            } catch (int) {
                ok = false;
            }
        } catch (const std::runtime_error& error) {
            ok = error.what() != nullptr;
        }
    } catch (...) {
        ok = false;
    }
    check(ok);
}

static void TestNestedExceptionObject() {
    bool ok = false;
    try {
        try {
            ThrowStdRE();
        } catch (...) {
            std::throw_with_nested(std::runtime_error("outer"));
        }
    } catch (const std::exception& error) {
        if (strcmp(error.what(), "outer") == 0) {
            try {
                std::rethrow_if_nested(error);
            } catch (const std::runtime_error& inner) {
                ok = strcmp(inner.what(), "re-ok") == 0;
            }
        }
    }
    check(ok);
}

static void TestExportedInt() {
    bool ok = false;
    try {
        MmThrow(0);
    } catch (int value) {
        ok = value == 123;
    }
    check(ok);
}

static void TestExportedStd() {
    bool ok = false;
    try {
        MmThrow(1);
    } catch (const std::exception& error) {
        ok = strcmp(error.what(), "exported-re") == 0;
    }
    check(ok);
}

static void TestExportedDerived() {
    bool ok = false;
    try {
        MmThrow(2);
    } catch (const ExcBase& error) {
        ok = error.magic == 0xC0FFEE;
    }
    check(ok);
}

static void TestExportedString() {
    bool ok = false;
    try {
        MmThrow(3);
    } catch (const std::string& text) {
        ok = text == "exp-str";
    }
    check(ok);
}

// ---------------------------------------------------------------------------
// SEH tests
// ---------------------------------------------------------------------------
static int ReadBad() {
    volatile int* pointer = reinterpret_cast<volatile int*>(static_cast<uintptr_t>(0xDEADBEEF));
    return *pointer;
}

static int DivBy(int a, int b) {
    return a / b;
}

static void TestSehAccessViolation() {
    bool ok = false;
    DWORD code = 0;
    __try {
        ReadBad();
    } __except (code = GetExceptionCode(),
                code == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        ok = true;
    }
    check(ok && code == EXCEPTION_ACCESS_VIOLATION);
}

static void TestSehDivZero() {
    bool ok = false;
    __try {
        volatile int zero = 0;
        volatile int result = DivBy(5, zero);
        (void) result;
    } __except (GetExceptionCode() == EXCEPTION_INT_DIVIDE_BY_ZERO ? EXCEPTION_EXECUTE_HANDLER
                                                                   : EXCEPTION_CONTINUE_SEARCH) {
        ok = true;
    }
    check(ok);
}

#if defined(EH_MODE_EHA)
static void TestCatchDotsCatchesSeh() {
    bool ok = false;
    try {
        ReadBad();
    } catch (...) {
        ok = true;
    }
    check(ok);
}
#endif

// ---------------------------------------------------------------------------
// Thread tests: TLS isolation plus throw/catch from a secondary thread
// ---------------------------------------------------------------------------
static DWORD WINAPI worker(LPVOID) {
    // ntdll allocates this thread's block from the TLS template, but TLS
    // callbacks of a manually mapped module are not in the loader's module
    // list, so no DLL_THREAD_ATTACH fires here: the value is the template.
    DWORD initial = static_cast<DWORD>(g_tlsCounter);
    g_tlsCounter = 0x5678;
    strcpy_s(g_tlsBuffer, "worker");
    MmResultsData.tlsWorker = initial;
    MmResultsData.tlsIsolated = (initial == 0x1234 && g_tlsCounter == 0x5678) ? 1 : 0;

    bool threw = false;
    try {
        ThrowCustomDerived();
    } catch (const ExcBase& error) {
        threw = error.magic == 0xDEAD;
    } catch (...) {
        threw = false;
    }
    int destructed = -1;
    try {
        auto lambda = [&]() {
            DtorMarker marker(&destructed);
            throw std::runtime_error("thread-lambda");
        };
        lambda();
    } catch (const std::exception& error) {
        threw = threw && strcmp(error.what(), "thread-lambda") == 0 && destructed == 1;
    }
    check(threw);
    return 0;
}

static void NTAPI tlsCallback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_tlsCounter++;
        g_tlsCallbacks++;
    } else if (reason == DLL_THREAD_ATTACH) {
        g_tlsCounter++;
        InterlockedIncrement(&g_threadAttach);
    }
}

#pragma section(".CRT$XLB", long, read)
extern "C" __declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK g_tlsCallbackEntry = tlsCallback;

// Wraps a test in SEH so an uncaught exception becomes a logged failure
// instead of killing the host process.
static void runTest(void (*test)()) {
    g_currentTest = g_testIndex++;
    __try {
        test();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        check(false);
    }
    g_currentTest = 0xFFFFFFFFu;
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
    *MmAttachedPointer = GetCurrentProcessId();
    MmResultsData.tlsCallbacks = g_tlsCallbacks;
    MmResultsData.tlsMain = static_cast<DWORD>(g_tlsCounter);
    check(g_tlsCallbacks == 1);
    check(g_tlsCounter == 0x1235);
    check(strcmp(g_tlsBuffer, "tls-ok") == 0);

    runTest(TestThrowInt);
    runTest(TestStdException);
    runTest(TestCustomCaughtByValue);
    runTest(TestCustomCaughtByRef);
    runTest(TestCatchDerivedFromBase);
    runTest(TestWrongTypeFallsThrough);
    runTest(TestCatchAll);
    runTest(TestRethrow);
    runTest(TestCurrentException);
    runTest(TestDeepUnwind);
    runTest(TestStackUnwindCallsDtors);
    runTest(TestNonCopyLike);
    runTest(TestFromLambda);
    runTest(TestFromLambdaIndirect);
    runTest(TestSequentialDispatch);
    runTest(TestNestedTry);
    runTest(TestNestedExceptionObject);
    runTest(TestSehAccessViolation);
    runTest(TestSehDivZero);
#if defined(EH_MODE_EHA)
    runTest(TestCatchDotsCatchesSeh);
#endif
    runTest(TestExportedInt);
    runTest(TestExportedStd);
    runTest(TestExportedDerived);
    runTest(TestExportedString);

    HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    if (thread) {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
        check(MmResultsData.tlsIsolated == 1);
    } else {
        check(false);
    }
    check(g_tlsCounter == 0x1235);
    check(strcmp(g_tlsBuffer, "tls-ok") == 0);
    MmResultsData.tlsMainAfter = static_cast<DWORD>(g_tlsCounter);
    MmResultsData.threadAttach = static_cast<DWORD>(g_threadAttach);
    MmResultsData.pass = static_cast<DWORD>(g_pass);
    MmResultsData.fail = static_cast<DWORD>(g_fail);
    MmResultsData.failMask = g_failMask;
    signalAttached();
    return TRUE;
}
