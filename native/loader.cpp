#include <Windows.h>

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
};

static_assert(sizeof(MmContext) == 56, "Java/C++ context layout mismatch");

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
                FARPROC function = context->getProcAddress(module, name);
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
    if (exceptions.Size != 0 && (exceptions.Size % sizeof(RUNTIME_FUNCTION) != 0
            || !context->addFunctionTable(functions, exceptions.Size / sizeof(RUNTIME_FUNCTION), reinterpret_cast<DWORD64>(base)))) {
        context->status = 6;
        return 6;
    }
    auto tls = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls.Size != 0) {
        auto directory = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(base + tls.VirtualAddress);
        auto callbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(directory->AddressOfCallBacks);
        if (callbacks) {
            for (; *callbacks; ++callbacks) {
                (*callbacks)(base, DLL_PROCESS_ATTACH, nullptr);
            }
        }
    }
    if (optional.AddressOfEntryPoint != 0) {
        auto entry = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(base + optional.AddressOfEntryPoint);
        if (!entry(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, nullptr)) {
            if (exceptions.Size != 0) {
                context->deleteFunctionTable(functions);
            }
            context->status = 7;
            return 7;
        }
    }
    context->status = 1;
    return 0;
}
