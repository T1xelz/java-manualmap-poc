#include <Windows.h>
#include <intrin.h>

// Extracted as .text: keep all state in the context; use only indirect API calls.
struct MmContext {
    BYTE* image;
    HMODULE(WINAPI* loadLibrary)(LPCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, LPCSTR);
    BOOLEAN(WINAPI* addFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    BOOLEAN(WINAPI* deleteFunctionTable)(PRUNTIME_FUNCTION);
    DWORD status;
    DWORD lastError;
    DWORD(WINAPI* getLastError)();
    LONG(NTAPI* handleTlsData)(void*, int);
    void* cxxThrowStub;
    void* rtlPcTrampoline;
    DWORD reason;
    DWORD flags;
    DWORD warning;
    DWORD reserved32;
    void* reserved;
};

static_assert(sizeof(MmContext) == 104, "Java/C++ context layout mismatch");

static constexpr DWORD kSehSupport = 1;
static constexpr DWORD kTlsSupport = 2;
static constexpr DWORD kWarnUnwind = 1;
static constexpr DWORD kWarnTls = 2;

static bool isCxxThrowName(const char* name) {
    return name[0] == '_' && name[1] == 'C' && name[2] == 'x' && name[3] == 'x'
        && name[4] == 'T' && name[5] == 'h' && name[6] == 'r' && name[7] == 'o'
        && name[8] == 'w' && name[9] == 'E' && name[10] == 'x' && name[11] == 'c'
        && name[12] == 'e' && name[13] == 'p' && name[14] == 't' && name[15] == 'i'
        && name[16] == 'o' && name[17] == 'n' && name[18] == '\0';
}

static bool isRtlPcToFileHeaderName(const char* name) {
    return name[0] == 'R' && name[1] == 't' && name[2] == 'l' && name[3] == 'P'
        && name[4] == 'c' && name[5] == 'T' && name[6] == 'o' && name[7] == 'F'
        && name[8] == 'i' && name[9] == 'l' && name[10] == 'e' && name[11] == 'H'
        && name[12] == 'e' && name[13] == 'a' && name[14] == 'd' && name[15] == 'e'
        && name[16] == 'r' && name[17] == '\0';
}

extern "C" DWORD WINAPI ManualMapShellcode(MmContext* context) {
    BYTE* base = context->image;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto& optional = nt->OptionalHeader;
    ULONGLONG delta = reinterpret_cast<ULONGLONG>(base) - optional.ImageBase;
    if (delta != 0) {
        auto directory = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (directory.Size == 0) {
            context->status = 2;
            return 2;
        }
        DWORD offset = 0;
        while (offset < directory.Size) {
            if (directory.Size - offset < sizeof(IMAGE_BASE_RELOCATION)) {
                context->status = 3;
                return 3;
            }
            auto block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + directory.VirtualAddress + offset);
            if (block->SizeOfBlock < 8 || block->SizeOfBlock > directory.Size - offset || (block->SizeOfBlock & 1)) {
                context->status = 3;
                return 3;
            }
            auto entries = reinterpret_cast<WORD*>(block + 1);
            DWORD count = (block->SizeOfBlock - 8) / 2;
            for (DWORD i = 0; i < count; ++i) {
                WORD type = entries[i] >> 12;
                if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }
                ULONGLONG rva = static_cast<ULONGLONG>(block->VirtualAddress) + (entries[i] & 0xFFF);
                if (type != IMAGE_REL_BASED_DIR64 || rva + 8 > optional.SizeOfImage) {
                    context->status = 3;
                    return 3;
                }
                *reinterpret_cast<ULONGLONG*>(base + rva) += delta;
            }
            offset += block->SizeOfBlock;
        }
    }
    auto imports = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imports.Size != 0) {
        bool terminated = false;
        for (DWORD offset = 0; offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= imports.Size;
                offset += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            auto descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + imports.VirtualAddress + offset);
            if (descriptor->Name == 0) {
                terminated = true;
                break;
            }
            if (descriptor->Name >= optional.SizeOfImage) {
                context->status = 4;
                return 4;
            }
            HMODULE module = context->loadLibrary(reinterpret_cast<LPCSTR>(base + descriptor->Name));
            if (!module) {
                context->lastError = context->getLastError();
                context->status = 4;
                return 4;
            }
            DWORD lookupRva = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk : descriptor->FirstThunk;
            DWORD writeRva = descriptor->FirstThunk;
            for (ULONGLONG i = 0;; ++i) {
                if (lookupRva + i * 8 + 8 > optional.SizeOfImage || writeRva + i * 8 + 8 > optional.SizeOfImage) {
                    context->status = 5;
                    return 5;
                }
                ULONGLONG thunk = *reinterpret_cast<ULONGLONG*>(base + lookupRva + i * 8);
                if (thunk == 0) {
                    break;
                }
                LPCSTR name;
                if (IMAGE_SNAP_BY_ORDINAL64(thunk)) {
                    name = reinterpret_cast<LPCSTR>(IMAGE_ORDINAL64(thunk));
                } else {
                    if (thunk + 3 < thunk || thunk + 3 > optional.SizeOfImage) {
                        context->status = 5;
                        return 5;
                    }
                    name = reinterpret_cast<LPCSTR>(base + thunk + 2);
                }
                FARPROC function;
                if (context->cxxThrowStub && !IMAGE_SNAP_BY_ORDINAL64(thunk) && isCxxThrowName(name)) {
                    function = reinterpret_cast<FARPROC>(context->cxxThrowStub);
                } else if (context->rtlPcTrampoline && !IMAGE_SNAP_BY_ORDINAL64(thunk) && isRtlPcToFileHeaderName(name)) {
                    function = reinterpret_cast<FARPROC>(context->rtlPcTrampoline);
                } else {
                    function = context->getProcAddress(module, name);
                }
                if (!function) {
                    context->lastError = context->getLastError();
                    context->status = 5;
                    return 5;
                }
                *reinterpret_cast<FARPROC*>(base + writeRva + i * 8) = function;
            }
        }
        if (!terminated) {
            context->status = 4;
            return 4;
        }
    }
    auto exceptions = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    auto functions = reinterpret_cast<PRUNTIME_FUNCTION>(base + exceptions.VirtualAddress);
    bool unwindFailed = false;
    if (context->flags & kSehSupport) {
        if (exceptions.Size != 0) {
            if (exceptions.Size % sizeof(RUNTIME_FUNCTION) != 0
                    || !context->addFunctionTable(functions, exceptions.Size / sizeof(RUNTIME_FUNCTION),
                            reinterpret_cast<DWORD64>(base))) {
                unwindFailed = true;
            }
        }
        if (context->cxxThrowStub) {
            auto stub = reinterpret_cast<BYTE*>(context->cxxThrowStub);
            if (!context->addFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(stub + 0xA0), 1,
                    reinterpret_cast<DWORD64>(stub))) {
                unwindFailed = true;
            }
        }
    }
    if (context->flags & kTlsSupport) {
        auto tls = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tls.Size != 0) {
            auto directory = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(base + tls.VirtualAddress);
            if (context->handleTlsData) {
                BYTE fake[0x200];
                __stosb(fake, 0, sizeof(fake));
                *reinterpret_cast<void**>(fake + 0x30) = base;
                *reinterpret_cast<DWORD*>(fake + 0x40) = optional.SizeOfImage;
                LONG tlsStatus = context->handleTlsData(fake, 1);
                if (tlsStatus < 0) {
                    context->warning |= kWarnTls;
                }
            } else {
                context->warning |= kWarnTls;
            }
            auto callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(directory->AddressOfCallBacks);
            for (; callbacks && *callbacks; ++callbacks) {
                (*callbacks)(base, DLL_PROCESS_ATTACH, nullptr);
            }
        }
    }
    if (unwindFailed) {
        context->warning |= kWarnUnwind;
    }
    if (optional.AddressOfEntryPoint != 0) {
        auto entry = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(base + optional.AddressOfEntryPoint);
        if (!entry(reinterpret_cast<HINSTANCE>(base), context->reason, context->reserved)) {
            if (context->reason == DLL_PROCESS_ATTACH) {
                if ((context->flags & kSehSupport) && exceptions.Size != 0) {
                    context->deleteFunctionTable(functions);
                }
                context->status = 7;
                return 7;
            }
        }
    }
    context->status = 1;
    return 0;
}
