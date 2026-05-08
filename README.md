# Whitestar Loader — Ghidra ROM Loader for Sega/Stern Whitestar

A [Ghidra](https://ghidra-sre.org/) extension that loads Sega/Stern Whitestar game ROMs
and builds a complete, navigable memory map — including banked ROM overlays, I/O register
labels, and interrupt vector stubs.

CPU rom only, loading of DMD and sound rom is not supported yet.

---

## Overview

Whitestar pinball machines (Baywatch through Stern era) use a **Motorola MC6809E** CPU
running at 2 MHz with a 64 KB address space. Game ROMs use the SE128 format: up to
32 × 16 KiB banked pages plus a fixed 32 KiB system ROM. ROMs come in three sizes:
128 KiB, 256 KiB, and 512 KiB.

The last 32 KiB of the ROM image is always mapped at `0x8000–0xFFFF`. The remaining pages
are bank-switched into the 16 KiB window at `0x4000–0x7FFF` by writing a bank number
(bits D0–D4) to the `WS_BANK_SELECT` register at `0x3200`.

---

## Memory Map

The loader creates the following Ghidra memory blocks:

| Block | Address range | Size | Permissions | Volatile | Description |
|---|---|---|---|---|---|
| `RAM` | `0x0000–0x1DFF` | 7.5 KiB | R/W | No | Battery-backed SRAM |
| `RAM_PROT` | `0x1E00–0x1FFF` | 512 B | R/W | No | Coin-door write-protected SRAM |
| `IO` | `0x2000–0x3FFF` | 8 KiB | R/W | **Yes** | I/O register space |
| `ROM_BANK_XX` | `0x4000–0x7FFF` | 16 KiB each | R/X | No | Banked ROM overlays (one per page) |
| `ROM_SYSTEM` | `0x8000–0xFFFF` | 32 KiB | R/X | No | Fixed system ROM (last 32 KiB of file) |

### Block notes

**`RAM_PROT`** reads always succeed; writes are blocked by hardware only when the
coin-door memory-protect flag is set at runtime. Ghidra models it as a normal R/W block.

**`IO`** is marked volatile so that Ghidra's decompiler and analyzer treat all register
reads as side-effecting.

**`ROM_SYSTEM`** is read-only/executable. Writes to the ROM area (`0x4000–0xFFFF`) are
silently discarded by the hardware.

### Banked ROM page numbering

The `WS_BANK_SELECT` register value maps directly to a 16 KiB page in the ROM file
(`bank_value × 16 KiB`). Overlay blocks are named `ROM_BANK_XX` where `XX` is the
bank-select value in hex.

| ROM size | Total pages | Banked overlays |
|---|---|---|
| 128 KiB | 8 | `ROM_BANK_00` – `ROM_BANK_05` (6 pages) |
| 256 KiB | 16 | `ROM_BANK_00` – `ROM_BANK_0D` (14 pages) |
| 512 KiB | 32 | `ROM_BANK_00` – `ROM_BANK_1D` (30 pages) |

---

## Labels Applied

### I/O registers (`0x2000–0x3FFF`)

All documented hardware registers are labelled with a `ByteDataType`:

| Address | Name | Direction | Description |
|---|---|---|---|
| `0x2000` | `WS_SOL_HIGH_CURRENT_A` | R/W | High-current solenoid bank A |
| `0x2001` | `WS_SOL_HIGH_CURRENT_B` | R/W | High-current solenoid bank B |
| `0x2002` | `WS_SOL_LOW_CURRENT` | R/W | Low-current solenoid outputs |
| `0x2003` | `WS_FLASH_LAMPS` | R/W | Flash lamp drivers |
| `0x2006` | `WS_AUX_OUT` | W | Auxiliary data latch (J2 connector) |
| `0x2007` | `WS_AUX_IN` | R | Auxiliary data input (J3 connector) |
| `0x2008` | `WS_LAMP_COL_STROBE` | R/W | Lamp matrix column strobe, low byte |
| `0x2009` | `WS_LAMP_COL_HIGH` | R/W | Lamp matrix column strobe, high byte |
| `0x200A` | `WS_LAMP_ROW` | R/W | Lamp matrix row driver data |
| `0x200B` | `WS_GI_AUX` | W | GI relay control and auxiliary strobe lines |
| `0x3000` | `WS_DEDICATED_SWITCH` | R | Flipper and service button inputs (active-low) |
| `0x3100` | `WS_DIP_SWITCH` | R | SW300 DIP switch — country/region (active-low) |
| `0x3200` | `WS_BANK_SELECT` | W | ROM bank select (D0–D4) + diagnostic LED (D7) |
| `0x3300` | `WS_SW_COL_STROBE` | W | Switch matrix column select |
| `0x3400` | `WS_SW_ROW_INPUT` | R | Switch matrix row return |
| `0x3406` | `WS_GI_LAMP_0` | R/W | GI lamp bank 0 |
| `0x3407` | `WS_GI_LAMP_1` | R/W | GI lamp bank 1 |
| `0x3500` | `WS_DMD_IE` | R | Sound/DMD board data input latch (PLIN) |
| `0x3600` | `WS_DMD_DATA` | W | DMD command data latch |
| `0x3601` | `WS_DMD_RESET` | W | DMD board reset strobe |
| `0x3700` | `WS_DMD_STATUS` | R | DMD and sound board status word |
| `0x3800` | `WS_SOUND_CMD` | W | Sound board command port |
| `0x3801` | `WS_SOUND_CMD_UNK` | W | Secondary sound board write (no-op) |

### Interrupt vectors (`0xFFF0–0xFFFE`)

Each 6809 vector slot is typed as a `Pointer16` and labelled
(`VEC_RESET`, `VEC_NMI`, `VEC_SWI`, `VEC_IRQ`, `VEC_FIRQ`, `VEC_SWI2`, `VEC_SWI3`,
`VEC_RESERVED`). A Ghidra function stub (`<name>_ISR`) is created at the target address
of each vector that points into a mapped memory block.

The `VEC_RESET` target is also registered as the program **entry point**.

---

## Loader Options

| Option | Default | Description |
|---|---|---|
| **Create banked ROM overlays** | ✅ On | Creates one `ROM_BANK_XX` overlay per banked page |

Disable overlays for a quick analysis pass on the fixed system ROM only.

---

## ROM Validity

The loader accepts files whose size is exactly 128 KiB, 256 KiB, or 512 KiB. After
loading, the Ghidra message log reports the ROM size and page layout.

---

## Requirements

| Requirement | Version |
|---|---|
| [Ghidra](https://ghidra-sre.org/) | **12.0.4** |
| Java | 21 (bundled with Ghidra) |

---

## Building

Use the Gradle wrapper bundled with Ghidra.

**1. Compile and package:**

```bash
env GHIDRA_INSTALL_DIR=~/ghidra_12.0.4_PUBLIC \
  ~/ghidra_12.0.4_PUBLIC/support/gradle/gradlew build
# → dist/ghidra_12.0.4_PUBLIC_<date>_ghidra_whitestar_loader.zip
```

**2. Install in Ghidra:**

In Ghidra's project manager: *File → Install Extensions* → select the zip from `dist/`.
Restart Ghidra when prompted.

---

## Usage

1. Open Ghidra and create or open a project.
2. Drag a Whitestar ROM file (`.bin`, `.rom`, or any extension) onto the project window,
   or use *File → Import File*.
3. Ghidra will auto-detect the Whitestar format via the file size check and propose
   **Whitestar ROM Loader** with `6809:BE:16:default` (Motorola 6809, big-endian).
4. Adjust the import options as needed, then click **OK**.
5. Open the imported program in the CodeBrowser and run **Auto Analyze** to disassemble
   the system ROM. Each banked overlay (`ROM_BANK_XX`) can be analysed separately.

---
