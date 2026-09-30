// KageDbg — extension de depurador (cdb/WinDbg) para investigacion de syscalls y EDR.
// Inspecciona el proceso depurado: tabla Nt* -> SSN, deteccion de hooks (inline e IAT),
// gadgets syscall;ret, imports/exports, modulos y busqueda de patrones.
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
#define KAGE_MAX_BYTES  64

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

static BOOL GetModuleRange(ULONG64 Base, ULONG64 *End)
{
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS Nt;
    if (!ReadMem(Base, &Dos, sizeof(Dos)) || Dos.e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    if (!ReadMem(Base + Dos.e_lfanew, &Nt, sizeof(Nt)) || Nt.Signature != IMAGE_NT_SIGNATURE) return FALSE;
    *End = Base + Nt.OptionalHeader.SizeOfImage;
    return TRUE;
}

// Recolecta exports (nombre + direccion). OnlyNt: solo "Nt*".
static ULONG CollectExports(ULONG64 Base, KAGE_EXPORT_ENTRY *Arr, ULONG Max, BOOL OnlyNt)
{
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS Nt;
    IMAGE_EXPORT_DIRECTORY Exp;
    ULONG i, Count = 0;
    ULONG64 ExpRva;

    if (!ReadMem(Base, &Dos, sizeof(Dos)) || Dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (!ReadMem(Base + Dos.e_lfanew, &Nt, sizeof(Nt)) || Nt.Signature != IMAGE_NT_SIGNATURE) return 0;
    ExpRva = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (ExpRva == 0 || !ReadMem(Base + ExpRva, &Exp, sizeof(Exp))) return 0;

    for (i = 0; i < Exp.NumberOfNames && Count < Max; i++) {
        DWORD NameRva = 0, FuncRva = 0;
        WORD Ord = 0;
        char Name[KAGE_NAME_MAX];
        if (!ReadMem(Base + Exp.AddressOfNames + i * 4, &NameRva, 4)) break;
        if (!ReadMem(Base + Exp.AddressOfNameOrdinals + i * 2, &Ord, 2)) break;
        if (!ReadMem(Base + Exp.AddressOfFunctions + (DWORD)Ord * 4, &FuncRva, 4)) break;
        if (NameRva == 0 || FuncRva == 0) continue;
        memset(Name, 0, sizeof(Name));
        if (!ReadMem(Base + NameRva, Name, sizeof(Name) - 1)) continue;
        if (OnlyNt) {
            if (!(Name[0] == 'N' && Name[1] == 't' && Name[2] >= 'A' && Name[2] <= 'Z')) continue;
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
    return (X < Y) ? -1 : (X > Y) ? 1 : 0;
}

// Clasifica el prologo de una funcion: 0=clean stub, 1=jmp, 2=otro. Devuelve destino (jmp).
static int ClassifyPrologue(ULONG64 Addr, ULONG64 ModuleBase, ULONG64 ModuleEnd, ULONG64 *Target)
{
    BYTE B[8] = { 0 };
    *Target = 0;
    if (!ReadMem(Addr, B, sizeof(B))) return 2;
    if (B[0] == 0x4C && B[1] == 0x8B && B[2] == 0xD1 && B[3] == 0xB8) return 0;
    if (B[0] == 0xE9) {
        *Target = Addr + 5 + *(int *)(B + 1);
        return 1;
    }
    if (B[0] == 0xFF && B[1] == 0x25) {
        ULONG64 Slot = Addr + 6 + *(int *)(B + 2);
        ReadMem(Slot, Target, 8);
        return 1;
    }
    return 2;
}

static void CmdStubs(PCSTR Module)
{
    static KAGE_EXPORT_ENTRY Arr[KAGE_MAX_EXPORTS];
    ULONG64 Base = 0, End = 0;
    ULONG Count, i, Clean = 0, Jmp = 0, JmpInside = 0, Other = 0;

    if (!GetModuleBase(Module, &Base)) { Out("kage: modulo '%s' no encontrado.", Module); return; }
    GetModuleRange(Base, &End);
    Count = CollectExports(Base, Arr, KAGE_MAX_EXPORTS, TRUE);
    Out("kage stubs: %s base=%p exports Nt*=%u", Module, (void *)Base, Count);
    for (i = 0; i < Count; i++) {
        ULONG64 Tgt = 0;
        int C = ClassifyPrologue(Arr[i].Addr, Base, End, &Tgt);
        if (C == 0) { Clean++; }
        else if (C == 1) {
            BOOL In = (Tgt >= Base && Tgt < End);
            Jmp++; if (In) JmpInside++;
            Out("  JMP %-38s %p -> %p (%s)", Arr[i].Name, (void *)Arr[i].Addr, (void *)Tgt,
                In ? "dentro" : "FUERA (posible hook)");
        } else { Other++; }
    }
    Out("kage stubs: clean=%u jmp=%u(dentro=%u) otros=%u de %u", Clean, Jmp, JmpInside, Other, Count);
}

static void CmdNt(PCSTR Module)
{
    static KAGE_EXPORT_ENTRY Arr[KAGE_MAX_EXPORTS];
    ULONG64 Base = 0;
    ULONG Count, i;
    if (!GetModuleBase(Module, &Base)) { Out("kage: modulo '%s' no encontrado.", Module); return; }
    Count = CollectExports(Base, Arr, KAGE_MAX_EXPORTS, TRUE);
    qsort(Arr, Count, sizeof(KAGE_EXPORT_ENTRY), CompareByAddr);
    Out("kage nt: tabla %s Nt* -> SSN (indice por direccion)", Module);
    for (i = 0; i < Count; i++) Out("  0x%03X  %-44s %p", i, Arr[i].Name, (void *)Arr[i].Addr);
    Out("kage nt: %u exports Nt*.", Count);
}

static void CmdSsn(PCSTR Name, PCSTR Module)
{
    static KAGE_EXPORT_ENTRY Arr[KAGE_MAX_EXPORTS];
    ULONG64 Base = 0;
    ULONG Count, i;
    if (Name == NULL || Name[0] == 0) { Out("kage: uso: !kage ssn <NtName> [module]"); return; }
    if (!GetModuleBase(Module, &Base)) { Out("kage: modulo '%s' no encontrado.", Module); return; }
    Count = CollectExports(Base, Arr, KAGE_MAX_EXPORTS, TRUE);
    qsort(Arr, Count, sizeof(KAGE_EXPORT_ENTRY), CompareByAddr);
    for (i = 0; i < Count; i++) {
        if (_stricmp(Arr[i].Name, Name) == 0) {
            Out("kage ssn: %s -> SSN 0x%03X (%u) addr=%p", Name, i, i, (void *)Arr[i].Addr);
            return;
        }
    }
    Out("kage ssn: '%s' no encontrado en %s.", Name, Module);
}

static void CmdExport(PCSTR Module, PCSTR Name)
{
    static KAGE_EXPORT_ENTRY Arr[KAGE_MAX_EXPORTS];
    ULONG64 Base = 0;
    ULONG Count, i;
    if (Name == NULL || Name[0] == 0) { Out("kage: uso: !kage export <module> <name>"); return; }
    if (!GetModuleBase(Module, &Base)) { Out("kage: modulo '%s' no encontrado.", Module); return; }
    Count = CollectExports(Base, Arr, KAGE_MAX_EXPORTS, FALSE);
    for (i = 0; i < Count; i++) {
        if (_stricmp(Arr[i].Name, Name) == 0) {
            Out("kage export: %s!%s = %p", Module, Name, (void *)Arr[i].Addr);
            return;
        }
    }
    Out("kage export: %s!%s no encontrado.", Module, Name);
}

static BOOL IsSystemModuleName(PCSTR Name)
{
    /* Forwarders/sistema: apisets y DLLs de Windows (kernel32->kernelbase, ->ntdll...). */
    static const PCSTR SysDlls[] = {
        "api-ms-win-", "ext-ms-", "ntdll", "kernel32", "kernelbase", "user32", "gdi32",
        "advapi32", "combase", "win32u", "ole32", "oleaut32", "sechost", "rpcrt4", "msvcrt",
        "ucrtbase", "shcore", "shlwapi", "shell32", "cfgmgr32", "powrprof", "bcryptprimitives",
        NULL
    };
    const char *Base;
    int i;

    if (strstr(Name, "\\System32\\") || strstr(Name, "\\SysWOW64\\") || strstr(Name, "\\WinSxS\\")) {
        return TRUE;
    }
    Base = strrchr(Name, '\\');
    Base = (Base != NULL) ? Base + 1 : Name;
    for (i = 0; SysDlls[i] != NULL; i++) {
        if (_strnicmp(Base, SysDlls[i], (size_t)strlen(SysDlls[i])) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static void ModuleOfAddr(ULONG64 Addr, char *Out, size_t OutSz)
{
    ULONG Index = 0, N = 0;
    ULONG64 Base = 0;
    strcpy_s(Out, OutSz, "?");
    if (g_Sym->GetModuleByOffset(Addr, 0, &Index, &Base) == S_OK) {
        g_Sym->GetModuleNames(Index, 0, Out, (ULONG)OutSz - 1, &N, NULL, 0, NULL, NULL, 0, NULL);
    }
}

static void CmdHooks(PCSTR Extra)
{
    static const PCSTR Interest[] = { "ntdll", "kernel32", "kernelbase", "win32u", "user32", "advapi32",
                                      "ws2_32", "gdi32", "ole32", "combase", NULL };
    static KAGE_EXPORT_ENTRY Arr[KAGE_MAX_EXPORTS];
    int m;
    (void)Extra;
    Out("kage hooks: detecta jmp a OTRO modulo (resuelve el destino; los forwarders a");
    Out("           System32/KERNELBASE son normales; destino raro = sospechoso)");
    for (m = 0; Interest[m] != NULL; m++) {
        ULONG64 Base = 0, End = 0;
        ULONG Count, i, Clean = 0, Susp = 0, Fwd = 0;
        if (!GetModuleBase(Interest[m], &Base)) continue;
        if (!GetModuleRange(Base, &End)) continue;
        Count = CollectExports(Base, Arr, KAGE_MAX_EXPORTS, FALSE);
        for (i = 0; i < Count; i++) {
            ULONG64 Tgt = 0;
            int C = ClassifyPrologue(Arr[i].Addr, Base, End, &Tgt);
            if (C == 0) { Clean++; continue; }
            if (C == 1 && !(Tgt >= Base && Tgt < End)) {
                char ModName[MAX_PATH];
                ModuleOfAddr(Tgt, ModName, sizeof(ModName));
                if (IsSystemModuleName(ModName)) {
                    Fwd++;
                } else {
                    Susp++;
                    Out("  SOSPECHOSO %s!%s @ %p -> %p (%s)", Interest[m], Arr[i].Name,
                        (void *)Arr[i].Addr, (void *)Tgt, ModName);
                }
            }
        }
        Out("  %-12s exports=%u clean=%u forwarders=%u sospechosos=%u",
            Interest[m], Count, Clean, Fwd, Susp);
    }
}

static void CmdIat(PCSTR Module)
{
    ULONG64 Base = 0;
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS Nt;
    ULONG64 ImpRva;
    ULONG d = 0;

    if (!GetModuleBase(Module, &Base)) { Out("kage: modulo '%s' no encontrado.", Module); return; }
    if (!ReadMem(Base, &Dos, sizeof(Dos)) || !ReadMem(Base + Dos.e_lfanew, &Nt, sizeof(Nt))) {
        Out("kage: headers ilegibles."); return;
    }
    ImpRva = Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (ImpRva == 0) { Out("kage iat: %s sin imports.", Module); return; }
    Out("kage iat: imports de %s", Module);
    for (;;) {
        IMAGE_IMPORT_DESCRIPTOR Desc;
        char DllName[KAGE_NAME_MAX] = { 0 };
        ULONG64 ThunkRva, ThunkAddr;
        int shown = 0;
        if (!ReadMem(Base + ImpRva + d * sizeof(Desc), &Desc, sizeof(Desc))) break;
        if (Desc.Name == 0 && Desc.FirstThunk == 0) break;
        ReadMem(Base + Desc.Name, DllName, sizeof(DllName) - 1);
        Out("  DLL: %s", DllName);
        ThunkRva = Desc.OriginalFirstThunk ? Desc.OriginalFirstThunk : Desc.FirstThunk;
        ThunkAddr = Base + ThunkRva;
        for (;;) {
            ULONG64 Thunk = 0;
            if (!ReadMem(ThunkAddr, &Thunk, 8) || Thunk == 0) break;
            if ((Thunk & 0x8000000000000000ull) == 0) {
                WORD Hint = 0;
                char Fn[KAGE_NAME_MAX] = { 0 };
                ReadMem(Base + Thunk, &Hint, 2);
                ReadMem(Base + Thunk + 2, Fn, sizeof(Fn) - 1);
                if (shown < 24) { Out("      %s", Fn); }
                shown++;
            } else {
                if (shown < 24) { Out("      #%llu (ordinal)", Thunk & 0xFFFF); }
                shown++;
            }
            ThunkAddr += 8;
            if (shown > 1024) break;
        }
        if (shown > 24) Out("      ... (%d total)", shown);
        d++;
        if (d > 256) break;
    }
}

static int HexToBytes(PCSTR Hex, BYTE *Out, int Max)
{
    int n = 0;
    int hi = -1;
    for (; *Hex; Hex++) {
        char c = *Hex;
        int v;
        if (c == ' ' || c == '\t') continue;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        else return -1;
        if (hi < 0) { hi = v; }
        else { if (n >= Max) break; Out[n++] = (BYTE)((hi << 4) | v); hi = -1; }
    }
    return (hi < 0) ? n : -1;
}

static void CmdFind(PCSTR Module, PCSTR Hex)
{
    ULONG64 Base = 0, End = 0;
    BYTE Pat[KAGE_MAX_BYTES];
    int PatLen;
    BYTE *Img;
    DWORD Size;
    DWORD i, Found = 0;

    if (Module == NULL || Hex == NULL) { Out("kage: uso: !kage find <module> <hexbytes>"); return; }
    if (!GetModuleBase(Module, &Base)) { Out("kage: modulo '%s' no encontrado.", Module); return; }
    if (!GetModuleRange(Base, &End)) { Out("kage: rango ilegible."); return; }
    PatLen = HexToBytes(Hex, Pat, KAGE_MAX_BYTES);
    if (PatLen <= 0) { Out("kage find: patron hex invalido."); return; }
    Size = (DWORD)(End - Base);
    if (Size == 0 || Size > (32u * 1024u * 1024u)) { Out("kage find: tamano no soportado."); return; }
    Img = (BYTE *)malloc(Size);
    if (Img == NULL) { Out("kage find: sin memoria."); return; }
    if (g_Dat->ReadVirtual(Base, Img, Size, &i) != S_OK) { i = 0; }
    for (i = 0; i + (DWORD)PatLen <= Size; i++) {
        if (memcmp(Img + i, Pat, PatLen) == 0) {
            if (Found < 16) Out("  match @ %p (= %s+0x%X)", (void *)(Base + i), Module, i);
            Found++;
        }
    }
    free(Img);
    Out("kage find: %u coincidencias de %d bytes en %s.", Found, PatLen, Module);
}

static void CmdModules(void)
{
    ULONG Loaded = 0, Unloaded = 0, i;
    if (g_Sym->GetNumberModules(&Loaded, &Unloaded) != S_OK) { Out("kage: no se pudo listar modulos."); return; }
    Out("kage modules: %u cargados", Loaded);
    for (i = 0; i < Loaded; i++) {
        ULONG64 Base = 0;
        char Name[MAX_PATH] = { 0 };
        ULONG N = 0;
        if (g_Sym->GetModuleByIndex(i, &Base) != S_OK) continue;
        g_Sym->GetModuleNames(i, 0, Name, sizeof(Name) - 1, &N, NULL, 0, NULL, NULL, 0, NULL);
        Out("  %p  %s", (void *)Base, Name);
    }
}

static BOOL SectionNameIsText(const BYTE Name[8])
{
    return (Name[0] == '.' && Name[1] == 't' && Name[2] == 'e' && Name[3] == 'x' && Name[4] == 't');
}

static void CmdGadget(PCSTR Module)
{
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS Nt;
    ULONG64 Base = 0, TextBase = 0;
    WORD s;
    DWORD TextSize = 0, Found = 0, i;

    if (!GetModuleBase(Module, &Base)) { Out("kage: modulo '%s' no encontrado.", Module); return; }
    if (!ReadMem(Base, &Dos, sizeof(Dos)) || !ReadMem(Base + Dos.e_lfanew, &Nt, sizeof(Nt))) {
        Out("kage: headers ilegibles."); return;
    }
    {
        IMAGE_SECTION_HEADER Sec;
        ULONG64 SecAddr = Base + Dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                          Nt.FileHeader.SizeOfOptionalHeader;
        for (s = 0; s < Nt.FileHeader.NumberOfSections; s++) {
            if (!ReadMem(SecAddr + (ULONG64)s * sizeof(IMAGE_SECTION_HEADER), &Sec, sizeof(Sec))) break;
            if (SectionNameIsText(Sec.Name)) {
                TextBase = Base + Sec.VirtualAddress;
                TextSize = Sec.Misc.VirtualSize;
                break;
            }
        }
    }
    if (TextBase == 0 || TextSize == 0 || TextSize > (32u * 1024u * 1024u)) {
        Out("kage gadget: .text ausente o demasiado grande."); return;
    }
    Out("kage gadget: escaneando .text de %s (%p, %u bytes) buscando 0F 05 C3",
        Module, (void *)TextBase, (unsigned)TextSize);
    {
        BYTE *Text = (BYTE *)malloc(TextSize);
        ULONG Read = 0;
        if (Text == NULL) { Out("kage gadget: sin memoria."); return; }
        if (g_Dat->ReadVirtual(TextBase, Text, TextSize, &Read) != S_OK) Read = 0;
        for (i = 0; i + 3 <= Read; i++) {
            if (Text[i] == 0x0F && Text[i + 1] == 0x05 && Text[i + 2] == 0xC3) {
                if (Found < 16) Out("  gadget @ %p", (void *)(TextBase + i));
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
    Out("  !kage stubs [mod]          : stubs Nt* y deteccion de hooks inline");
    Out("  !kage nt [mod]             : tabla Nt* -> SSN (sort-by-VA)");
    Out("  !kage ssn <name> [mod]     : SSN de un Nt* por nombre");
    Out("  !kage export <mod> <name>  : resolver un export");
    Out("  !kage iat <mod>            : imports de un modulo");
    Out("  !kage hooks                : hooks inline en modulos clave");
    Out("  !kage gadget [mod]         : gadgets syscall;ret en .text");
    Out("  !kage find <mod> <hex>     : buscar patron de bytes");
    Out("  !kage modules              : modulos cargados");
    Out("  (module por defecto: ntdll)");
}

KAGE_EXPORT HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
    *Version = DEBUG_EXTENSION_VERSION(1, 0);
    *Flags = 0;
    return S_OK;
}

KAGE_EXPORT HRESULT CALLBACK DebugExtensionUninitialize(void) { return S_OK; }

KAGE_EXPORT HRESULT CALLBACK kage(PDEBUG_CLIENT Client, PCSTR Args)
{
    char Cmd[32] = { 0 }, A1[KAGE_NAME_MAX] = { 0 }, A2[KAGE_NAME_MAX] = { 0 };
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
        n = sscanf_s(Args, "%31s %127s %127s", Cmd, (unsigned)sizeof(Cmd),
                     A1, (unsigned)sizeof(A1), A2, (unsigned)sizeof(A2));
    }
    if (n <= 0) CmdHelp();
    else if (_stricmp(Cmd, "help") == 0) CmdHelp();
    else if (_stricmp(Cmd, "stubs") == 0) CmdStubs((n >= 2 && A1[0]) ? A1 : "ntdll");
    else if (_stricmp(Cmd, "nt") == 0) CmdNt((n >= 2 && A1[0]) ? A1 : "ntdll");
    else if (_stricmp(Cmd, "ssn") == 0) CmdSsn(A1, (n >= 3 && A2[0]) ? A2 : "ntdll");
    else if (_stricmp(Cmd, "export") == 0) CmdExport((n >= 2 && A1[0]) ? A1 : "ntdll", A2);
    else if (_stricmp(Cmd, "iat") == 0) CmdIat((n >= 2 && A1[0]) ? A1 : "ntdll");
    else if (_stricmp(Cmd, "hooks") == 0) CmdHooks(A1);
    else if (_stricmp(Cmd, "gadget") == 0) CmdGadget((n >= 2 && A1[0]) ? A1 : "ntdll");
    else if (_stricmp(Cmd, "find") == 0) CmdFind(A1, A2);
    else if (_stricmp(Cmd, "modules") == 0) CmdModules();
    else CmdHelp();

    g_Sym->Release(); g_Ctrl->Release(); g_Dat->Release();
    g_Sym = NULL; g_Ctrl = NULL; g_Dat = NULL;
    return S_OK;
}
