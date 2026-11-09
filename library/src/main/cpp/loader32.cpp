#include <Windows.h>

// Extracted as .text: keep all state in the context; call only through it.
// x86 parity with the reference: relocations and imports only, no TLS and
// no SEH/unwind registration.
struct MmContext32 {
    BYTE* image;
    HMODULE(WINAPI* loadLibrary)(LPCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, LPCSTR);
    DWORD status;
    DWORD lastError;
    DWORD(WINAPI* getLastError)();
    DWORD reason;
    DWORD warning;
    DWORD reserved;
};

static_assert(sizeof(MmContext32) == 36, "Java/C++ x86 context layout mismatch");

static constexpr DWORD kWarnTls = 4;

extern "C" DWORD WINAPI ManualMapShellcode32(MmContext32* context) {
    BYTE* base = context->image;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto& optional = nt->OptionalHeader;
    DWORD delta = reinterpret_cast<DWORD>(base) - optional.ImageBase;
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
                DWORD rva = block->VirtualAddress + (entries[i] & 0xFFF);
                if (type != IMAGE_REL_BASED_HIGHLOW || rva + 4 > optional.SizeOfImage) {
                    context->status = 3;
                    return 3;
                }
                *reinterpret_cast<DWORD*>(base + rva) += delta;
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
            for (DWORD i = 0;; ++i) {
                DWORD lookup = lookupRva + i * 4;
                DWORD write = writeRva + i * 4;
                if (lookup + 4 > optional.SizeOfImage || write + 4 > optional.SizeOfImage) {
                    context->status = 5;
                    return 5;
                }
                DWORD thunk = *reinterpret_cast<DWORD*>(base + lookup);
                if (thunk == 0) {
                    break;
                }
                LPCSTR name;
                if (IMAGE_SNAP_BY_ORDINAL32(thunk)) {
                    name = reinterpret_cast<LPCSTR>(IMAGE_ORDINAL32(thunk));
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
                *reinterpret_cast<FARPROC*>(base + write) = function;
            }
        }
        if (!terminated) {
            context->status = 4;
            return 4;
        }
    }
    if (optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0) {
        // The reference disables static TLS for x86; report instead of lying.
        context->warning |= kWarnTls;
    }
    if (optional.AddressOfEntryPoint != 0) {
        auto entry = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(base + optional.AddressOfEntryPoint);
        if (!entry(reinterpret_cast<HINSTANCE>(base), context->reason,
                reinterpret_cast<LPVOID>(context->reserved))) {
            if (context->reason == DLL_PROCESS_ATTACH) {
                context->status = 7;
                return 7;
            }
        }
    }
    context->status = 1;
    return 0;
}
