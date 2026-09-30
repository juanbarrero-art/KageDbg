# KageDbg

> Extensión de depurador (cdb / WinDbg) para **investigación de syscalls y EDR** en Windows x64.
> Inspecciona `ntdll` del proceso depurado: **tabla `Nt*` → SSN**, **detección de hooks inline**
> en stubs, y **gadgets `syscall;ret`**.

[![Platform](https://img.shields.io/badge/platform-Windows%20x64-blue)]()
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

`KageDbg` convierte el debugger en una herramienta de análisis de la capa de syscalls: útil para
research de evasión, *detection engineering*, análisis de malware y estudio de la resolución de
SSN entre builds de Windows.

## Comandos

| Comando | Descripción |
|---|---|
| `!kage nt [module]` | Tabla **`Nt*` → SSN** ordenando los exports por dirección virtual (el índice = SSN). |
| `!kage ssn <name> [module]` | Resuelve el **SSN** de un `Nt*` concreto por nombre. |
| `!kage stubs [module]` | Lista stubs `Nt*` y clasifica el prólogo (clean / `jmp` dentro / fuera). |
| `!kage hooks` | **Detecta hooks inline** en módulos clave, resolviendo el módulo destino (separa forwarders legítimos de sospechosos). |
| `!kage iat <module>` | Vuelca la **tabla de imports** (dependencias y funciones). |
| `!kage export <module> <name>` | **Resuelve un export** a su dirección. |
| `!kage gadget [module]` | Busca gadgets **`syscall;ret`** (`0F 05 C3`) en `.text`. |
| `!kage find <module> <hex>` | **Busca un patrón de bytes** (hex) en la imagen. |
| `!kage modules` | Lista los **módulos cargados** con su base. |
| `!kage iathooks <module>` | **Detección de IAT hooks** (entradas redirigidas a módulos no-sistema). |
| `!kage dis <addr\|symbol> [n]` | Desensambla y **anota el SSN** si es un stub de syscall. |
| `!kage syscall <ssn> [module]` | **Inverso**: SSN → nombre. |
| `!kage dump <file.csv> [module]` | Exporta la tabla `Nt*` → SSN a **CSV** (baseline por build). |
| `!kage peb` | Muestra **TEB/PEB** actuales. |
| `!kage help` | Ayuda. |

`module` por defecto: `ntdll`.

## Casos de uso

- **Research de syscalls / SSN**: `!kage nt` y `!kage ssn NtClose` dan la tabla y el SSN real de la
  build, sin escribir código.
- **Detección / EDR**: `!kage hooks` y `!kage stubs` muestran qué funciones tienen el prólogo
  alterado, distinguiendo forwarding legítimo (kernel32→kernelbase) de hooks de terceros.
- **Análisis de malware**: `!kage iat <mod>` (dependencias), `!kage find <mod> <hex>` (firma de
  bytes), `!kage modules` (mapa de módulos), `!kage export` (resolución de símbolos).
- **Exploit / gadget hunting**: `!kage gadget` localiza `syscall;ret` en ntdll.

## Requisitos

- Windows x64.
- Windows SDK (headers `DbgEng.h`, `DbgEng.Lib`).
- MSVC (Build Tools) para compilar.
- `cdb`/`WinDbg` para usar la extensión.

## Compilar

```
build.cmd
```
Genera `bin\kagedbg.dll`.

## Uso (cdb)

```
cdbX64  <tu_target.exe>
0:000> .load bin\kagedbg.dll
0:000> !kage help
0:000> !kage stubs
0:000> !kage nt
0:000> !kage ssn NtClose
0:000> !kage gadget
```

### Salida de ejemplo

```
0:000> !kage stubs
kage stubs: ntdll base=00007FFC483E0000  exports Nt*=490
  JMP  NtGetTickCount       00007FFC48544AC0 -> 00007FFC48525570  (dentro de ntdll)
  JMP  NtQuerySystemTime    00007FFC485418F0 -> 00007FFC484CD060  (dentro de ntdll)
kage stubs: clean=488  jmp=2 (dentro ntdll=2)  otros=0  de 490.
kage stubs: un jmp FUERA de ntdll sugiere hook inline; dentro suele ser export no-syscall.

0:000> !kage ssn NtClose
kage ssn: NtClose -> SSN 0x00F (15)  addr=00007FFC48540F90

0:000> !kage gadget
kage gadget: escaneando .text de ntdll (00007FFC483E1000, 1482908 bytes) buscando 0F 05 C3
  gadget @ 00007FFC48540FA2
  ...
kage gadget: N gadgets syscall;ret en .text.
```

> Nota: `clean` = stub de syscall real (`4C 8B D1 B8`). `jmp` = prólogo `E9`/`FF 25`;
> si el destino cae **fuera** de ntdll es un **hook inline**; dentro suele ser un export no-syscall
> (p. ej. `NtQuerySystemTime` hace `jmp Rtl...`). Así se evitan falsos positivos.

## Cómo funciona

- Enumeración de exports `Nt*` leyendo el **directorio de export** del módulo (vía `dbgeng`).
- **SSN**: ordena los `Nt*` por dirección virtual; el índice es el SSN (invariante de Windows
  moderno, técnica *sort-by-address*).
- **Hooks**: lee los 2 primeros bytes de cada stub; `E9` (`jmp rel32`) o `FF 25`
  (`jmp qword ptr [rip+..]`) indican hook inline.
- **Gadgets**: escanea `.text` buscando `0F 05 C3`.

## Alcance

Herramienta **de análisis** (solo lectura sobre el proceso depurado). No modifica el objetivo.
Pensada para investigación, defensa y educación.

## Licencia

Apache-2.0 — ver [LICENSE](LICENSE).

## Autor

juanbarrero-art
