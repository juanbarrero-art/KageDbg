// KageDbg — extension de depurador (cdb/WinDbg) para investigacion de syscalls y EDR.
// Inspecciona ntdll en el proceso depurado: tabla Nt* -> SSN (sort-by-VA),
// deteccion de hooks inline en stubs, y gadgets syscall;ret.
//
// Copyright 2026 juanbarrero-art
// Licencia: Apache-2.0 (ver LICENSE)
#include <windows.h>
#include <winnt.h>
#include <dbgeng.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define KAGE_EXPORT extern "C" __declspec(dllexport)

#define KAGE_MAX_EXPORTS 4096
#define KAGE_NAME_MAX 128

typedef struct _KAGE_EXPORT_ENTRY {
    ULONG64 Addr;
    char    Name[KAGE_NAME_MAX];
} KAGE_EXPORT_ENTRY;

static IDebugSymbols    *g_Sym = NULL;
static IDebugControl    *g_Ctrl = NULL;
static IDebugDataSpaces *g_Dat = NULL;

KAGE_EXPORT HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags);
KAGE_EXPORT HRESULT CALLBACK DebugExtensionUninitialize(void);
KAGE_EXPORT HRESULT CALLBACK kage(PDEBUG_CLIENT Client, PCSTR Args);

static BOOL ReadMem(ULONG64 Addr, PVOID Buf, ULONG Size)
{
    ULONG Read = 0;
    if (g_Dat == NULL) return FALSE;
    return g_Dat->ReadVirtual(Addr, Buf, Size, &Read) == S_OK && Read == Size;
}

static void Out(PCSTR Fmt, ...)
{
    char Buf[1024];
    va_list Ap;
    if (g_Ctrl == NULL) return;
    va_start(Ap, Fmt);
    vsprintf_s(Buf, sizeof(Buf), Fmt, Ap);
    va_end(Ap);
    g_Ctrl->Output(DEBUG_OUTCTL_ALL_CLIENTS, "%s\n", Buf);
}

static BOOL GetModuleBase(PCSTR Module, ULONG64 *Base)
{
    ULONG Index = 0;
    if (g_Sym == NULL) return FALSE;
    return g_Sym->GetModuleByModuleName(Module, 0, &Index, Base) == S_OK;
}

// Recolecta exports "Nt*" (nombre + direccion). Devuelve el numero.
static ULONG CollectNtExports(ULONG64 Base, KAGE_EXPORT_ENTRY *Arr, ULONG Max)
{
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS Nt;
    IMAGE_EXPORT_DIRECTORY Exp;
    ULONG i;
    ULONG Count = 0;
    ULONG64 ExpRva;

    if (!ReadMem(Base, &Dos, sizeof(Dos)) || Dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    if (!ReadMem(Base + Dos.e_lfanew, &Nt, sizeof(Nt)) || Nt.Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    ExpRva = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (ExpRva == 0) {
        return 0;
    }
    if (!ReadMem(Base + ExpRva, &Exp, sizeof(Exp))) {
        return 0;
    }
    for (i = 0; i < Exp.NumberOfNames && Count < Max; i++) {
        DWORD NameRva = 0;
        WORD  Ord = 0;
        DWORD FuncRva = 0;
        char  Name[KAGE_NAME_MAX];

        if (!ReadMem(Base + Exp.AddressOfNames + i * 4, &NameRva, 4)) break;
        if (!ReadMem(Base + Exp.AddressOfNameOrdinals + i * 2, &Ord, 2)) break;
        if (!ReadMem(Base + Exp.AddressOfFunctions + (DWORD)Ord * 4, &FuncRva, 4)) break;
        if (NameRva == 0 || FuncRva == 0) continue;
        memset(Name, 0, sizeof(Name));
        if (!ReadMem(Base + NameRva, Name, sizeof(Name) - 1)) continue;

        if (!(Name[0] == 'N' && Name[1] == 't' && Name[2] >= 'A' && Name[2] <= 'Z')) {
            continue;
        }
        Arr[Count].Addr = Base + FuncRva;
        strncpy_s(Arr[Count].Name, sizeof(Arr[Count].Name), Name, _TRUNCATE);
        Count++;
    }
    return Count;
}

static int CompareByAddr(const void *A, const void *B)
{
    ULONG64 X = ((const KAGE_EXPORT_ENTRY *)A)->Addr;
    ULONG64 Y = ((const KAGE_EXPORT_ENTRY *)B)->Addr;
    if (X < Y) return -1;
    if (X > Y) return 1;
    return 0;
}

static void CmdStubs(PCSTR Module)
{
    static KAGE_EXPORT_ENTRY Arr[KAGE_MAX_EXPORTS];
    ULONG64 Base = 0;
    ULONG64 End = 0;
    ULONG Count, i;
    ULONG Clean = 0, Jmp = 0, JmpInside = 0, Other = 0;

    if (!GetModuleBase(Module, &Base)) {
        Out("kage: no se encontro el modulo '%s'.", Module);
        return;
    }
    {
        IMAGE_DOS_HEADER Dos;
        IMAGE_NT_HEADERS Nt;
        if (ReadMem(Base, &Dos, sizeof(Dos)) && ReadMem(Base + Dos.e_lfanew, &Nt, sizeof(Nt))) {
            End = Base + Nt.OptionalHeader.SizeOfImage;
        }
    }
    Count = CollectNtExports(Base, Arr, KAGE_MAX_EXPORTS);
    Out("kage stubs: %s base=%p  exports Nt*=%u", Module, (void *)Base, Count);
    for (i = 0; i < Count; i++) {
        BYTE B[8] = { 0 };
        if (!ReadMem(Arr[i].Addr, B, sizeof(B))) continue;
        if (B[0] == 0x4C && B[1] == 0x8B && B[2] == 0xD1 && B[3] == 0xB8) {
            Clean++; /* stub de syscall real: mov r10,rcx; mov eax,ssn */
        } else if (B[0] == 0xE9) {
            int Rel = *(int *)(B + 1);
            ULONG64 Tgt = Arr[i].Addr + 5 + Rel;
            BOOL In = (Tgt >= Base && Tgt < End);
            Jmp++;
            if (In) JmpInside++;
            Out("  JMP  %-40s %p -> %p  (%s)", Arr[i].Name, (void *)Arr[i].Addr,
                (void *)Tgt, In ? "dentro de ntdll" : "FUERA de ntdll (posible hook/forwarder)");
        } else if (B[0] == 0xFF && B[1] == 0x25) {
            int Disp = *(int *)(B + 2);
            ULONG64 Slot = Arr[i].Addr + 6 + Disp;
            ULONG64 Tgt = 0;
            BOOL In;
            ReadMem(Slot, &Tgt, 8);
            In = (Tgt >= Base && Tgt < End);
            Jmp++;
            if (In) JmpInside++;
            Out("  JMP* %-40s %p -> %p  (%s)", Arr[i].Name, (void *)Arr[i].Addr,
                (void *)Tgt, In ? "dentro de ntdll" : "FUERA de ntdll (posible hook)");
        } else {
            Other++;
        }
    }
    Out("kage stubs: clean=%u  jmp=%u (dentro ntdll=%u)  otros=%u  de %u.",
        Clean, Jmp, JmpInside, Other, Count);
    Out("kage stubs: un jmp FUERA de ntdll sugiere hook inline; dentro suele ser export no-syscall.");
}

static void CmdNt(PCSTR Module)
{
    static KAGE_EXPORT_ENTRY Arr[KAGE_MAX_EXPORTS];
    ULONG64 Base = 0;
    ULONG Count, i;

    if (!GetModuleBase(Module, &Base)) {
        Out("kage: no se encontro el modulo '%s'.", Module);
        return;
    }
    Count = CollectNtExports(Base, Arr, KAGE_MAX_EXPORTS);
    qsort(Arr, Count, sizeof(KAGE_EXPORT_ENTRY), CompareByAddr);
    Out("kage nt: tabla %s Nt* -> SSN (indice en orden de direccion)", Module);
    for (i = 0; i < Count; i++) {
        Out("  0x%03X  %-44s %p", i, Arr[i].Name, (void *)Arr[i].Addr);
    }
    Out("kage nt: %u exports Nt*.", Count);
}

static void CmdSsn(PCSTR Name, PCSTR Module)
{
    static KAGE_EXPORT_ENTRY Arr[KAGE_MAX_EXPORTS];
    ULONG64 Base = 0;
    ULONG Count, i;

    if (Name == NULL || Name[0] == 0) {
        Out("kage: uso: !kage ssn <NtName> [module]");
        return;
    }
    if (!GetModuleBase(Module, &Base)) {
        Out("kage: no se encontro el modulo '%s'.", Module);
        return;
    }
    Count = CollectNtExports(Base, Arr, KAGE_MAX_EXPORTS);
    qsort(Arr, Count, sizeof(KAGE_EXPORT_ENTRY), CompareByAddr);
    for (i = 0; i < Count; i++) {
        if (_stricmp(Arr[i].Name, Name) == 0) {
            Out("kage ssn: %s -> SSN 0x%03X (%u)  addr=%p", Name, i, i, (void *)Arr[i].Addr);
            return;
        }
    }
    Out("kage ssn: '%s' no encontrado en %s.", Name, Module);
}

static void CmdGadget(PCSTR Module)
{
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS Nt;
    ULONG64 Base = 0;
    WORD s;
    ULONG64 TextBase = 0;
    DWORD TextSize = 0;
    DWORD Found = 0;
    DWORD i;

    if (!GetModuleBase(Module, &Base)) {
        Out("kage: no se encontro el modulo '%s'.", Module);
        return;
    }
    if (!ReadMem(Base, &Dos, sizeof(Dos)) || !ReadMem(Base + Dos.e_lfanew, &Nt, sizeof(Nt))) {
        Out("kage: headers ilegibles.");
        return;
    }
    {
        IMAGE_SECTION_HEADER Sec;
        ULONG64 SecAddr = Base + Dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                          Nt.FileHeader.SizeOfOptionalHeader;
        for (s = 0; s < Nt.FileHeader.NumberOfSections; s++) {
            if (!ReadMem(SecAddr + (ULONG64)s * sizeof(IMAGE_SECTION_HEADER), &Sec, sizeof(Sec))) break;
            if (Sec.Name[0] == '.' && Sec.Name[1] == 't' && Sec.Name[2] == 'e' &&
                Sec.Name[3] == 'x' && Sec.Name[4] == 't') {
                TextBase = Base + Sec.VirtualAddress;
                TextSize = Sec.Misc.VirtualSize;
                break;
            }
        }
    }
    if (TextBase == 0 || TextSize == 0 || TextSize > (32u * 1024u * 1024u)) {
        Out("kage gadget: .text ausente o demasiado grande.");
        return;
    }
    Out("kage gadget: escaneando .text de %s (%p, %u bytes) buscando 0F 05 C3", Module,
        (void *)TextBase, (unsigned)TextSize);
    {
        BYTE *Text = (BYTE *)malloc(TextSize);
        ULONG Read = 0;
        if (Text == NULL) {
            Out("kage gadget: sin memoria.");
            return;
        }
        if (g_Dat->ReadVirtual(TextBase, Text, TextSize, &Read) != S_OK) {
            Read = 0;
        }
        for (i = 0; i + 3 <= Read; i++) {
            if (Text[i] == 0x0F && Text[i + 1] == 0x05 && Text[i + 2] == 0xC3) {
                if (Found < 16) {
                    Out("  gadget @ %p", (void *)(TextBase + i));
                }
                Found++;
            }
        }
        free(Text);
    }
    Out("kage gadget: %u gadgets syscall;ret en .text.", Found);
}

static void CmdHelp(void)
{
    Out("KageDbg — research debugger extension");
    Out("  !kage stubs [module]   : lista stubs Nt* y detecta hooks inline (E9/FF25)");
    Out("  !kage nt [module]      : tabla Nt* -> SSN (sort-by-VA)");
    Out("  !kage ssn <name> [mod] : resuelve el SSN de un Nt* por nombre");
    Out("  !kage gadget [module]  : busca gadgets syscall;ret en .text");
    Out("  (module por defecto: ntdll)");
}

KAGE_EXPORT HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    *Version = DEBUG_EXTENSION_VERSION(1, 0);
    *Flags = 0;
    return S_OK;
}

KAGE_EXPORT HRESULT CALLBACK DebugExtensionUninitialize(void)
{
    return S_OK;
}

KAGE_EXPORT HRESULT CALLBACK kage(PDEBUG_CLIENT Client, PCSTR Args)
{
    char Cmd[32] = { 0 };
    char Arg1[KAGE_NAME_MAX] = { 0 };
    char Mod[64] = "ntdll";
    int n = 0;

    if (Client->QueryInterface(__uuidof(IDebugSymbols), (void **)&g_Sym) != S_OK ||
        Client->QueryInterface(__uuidof(IDebugControl), (void **)&g_Ctrl) != S_OK ||
        Client->QueryInterface(__uuidof(IDebugDataSpaces), (void **)&g_Dat) != S_OK) {
        if (g_Sym) g_Sym->Release();
        if (g_Ctrl) g_Ctrl->Release();
        if (g_Dat) g_Dat->Release();
        return E_FAIL;
    }

    if (Args != NULL) {
        n = sscanf_s(Args, "%31s %127s %63s", Cmd, (unsigned)sizeof(Cmd),
                     Arg1, (unsigned)sizeof(Arg1), Mod, (unsigned)sizeof(Mod));
    }
    if (n <= 0) {
        CmdHelp();
    } else if (_stricmp(Cmd, "stubs") == 0) {
        CmdStubs((n >= 2 && Arg1[0]) ? Arg1 : "ntdll");
    } else if (_stricmp(Cmd, "nt") == 0) {
        CmdNt((n >= 2 && Arg1[0]) ? Arg1 : "ntdll");
    } else if (_stricmp(Cmd, "ssn") == 0) {
        CmdSsn(Arg1, (n >= 3 && Mod[0]) ? Mod : "ntdll");
    } else if (_stricmp(Cmd, "gadget") == 0) {
        CmdGadget((n >= 2 && Arg1[0]) ? Arg1 : "ntdll");
    } else {
        CmdHelp();
    }

    g_Sym->Release();
    g_Ctrl->Release();
    g_Dat->Release();
    g_Sym = NULL;
    g_Ctrl = NULL;
    g_Dat = NULL;
    return S_OK;
}
