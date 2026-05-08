/* ###
 * IP: GHIDRA
 * Copyright 2026 Martin Akesson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package whitestar;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Sega/Stern Whitestar game ROMs (SE128 format).
 *
 * <p>Whitestar machines use a Motorola MC6809E CPU at 2 MHz with a 64 KB address
 * space. ROMs come in three sizes: 128 KiB, 256 KiB, or 512 KiB, each divided
 * into 16 KiB pages. The last 32 KiB of the ROM is always mapped at
 * {@code 0x8000–0xFFFF} (the "fixed" system ROM). Additional 16 KiB pages are
 * bank-switched into the window at {@code 0x4000–0x7FFF} via the
 * {@code WS_BANK_SELECT} register at {@code 0x3200} (bits D0–D4, banks 0–31).
 *
 * <p>Each banked page is created as a Ghidra overlay block at {@code 0x4000–0x7FFF},
 * named {@code ROM_BANK_XX} where {@code XX} is the bank-select value written to
 * {@code WS_BANK_SELECT} in hex ({@code 00–1D} for a 512 KiB ROM).
 */
public class WhitestarLoader extends AbstractLibrarySupportLoader {

	// ── Valid ROM sizes ───────────────────────────────────────────────────────

	private static final long ROM_SIZE_128K = 0x0002_0000L;
	private static final long ROM_SIZE_256K = 0x0004_0000L;
	private static final long ROM_SIZE_512K = 0x0008_0000L;

	private static final long[] VALID_SIZES = {
		ROM_SIZE_128K, ROM_SIZE_256K, ROM_SIZE_512K
	};

	// ── ROM layout constants ──────────────────────────────────────────────────

	private static final int BANK_SIZE = 0x4000; // 16 KiB per banked page

	// ── CPU address map ───────────────────────────────────────────────────────

	private static final long RAM_START         = 0x0000L;
	private static final long RAM_SIZE_BYTES    = 0x1E00L; // 7.5 KiB
	private static final long RAM_PROT_START    = 0x1E00L;
	private static final long RAM_PROT_SIZE     = 0x0200L; // 512 B, coin-door write-protected
	private static final long IO_START          = 0x2000L;
	private static final long IO_SIZE           = 0x2000L; // 8 KiB, 0x2000–0x3FFF
	private static final long BANKED_ROM_START  = 0x4000L;
	private static final long SYSTEM_ROM_START  = 0x8000L;
	private static final long SYSTEM_ROM_SIZE   = 0x8000L; // 32 KiB

	// ── 6809 interrupt vector table	// ── Checksum fields in the system ROM ────────────────────────────

	private static final long ADDR_CHECKSUM_DELTA = 0xFFEEL;

le (0xFFF0–0xFFFE) ───────────────────────────

	/** Each entry: { cpu_address, label_name } */
	private static final Object[][] VECTORS = {
		{ 0xFFF0L, "VEC_RESERVED" },
		{ 0xFFF2L, "VEC_SWI3"    },
		{ 0xFFF4L, "VEC_SWI2"    },
		{ 0xFFF6L, "VEC_FIRQ"    },
		{ 0xFFF8L, "VEC_IRQ"     },
		{ 0xFFFAL, "VEC_SWI"     },
		{ 0xFFFCL, "VEC_NMI"     },
		{ 0xFFFEL, "VEC_RESET"   },
	};

	// ── I/O register definitions ──────────────────────────────────────────────

	/**
	 * Whitestar I/O registers.
	 * Each entry: { cpu_address, register_name }
	 * Addresses cover the range 0x2000–0x3FFF (the IO block).
	 */
	private static final Object[][] IO_REGISTERS = {
		// Solenoid outputs (0x2000–0x2003) — R/W
		{ 0x2000L, "WS_SOL_HIGH_CURRENT_A" },
		{ 0x2001L, "WS_SOL_HIGH_CURRENT_B" },
		{ 0x2002L, "WS_SOL_LOW_CURRENT"    },
		{ 0x2003L, "WS_FLASH_LAMPS"        },
		// Auxiliary I/O (0x2006–0x2007)
		{ 0x2006L, "WS_AUX_OUT"            }, // W: auxiliary data latch (J2 connector)
		{ 0x2007L, "WS_AUX_IN"             }, // R: auxiliary data input (J3 connector)
		// Lamp matrix (0x2008–0x200B) — R/W
		{ 0x2008L, "WS_LAMP_COL_STROBE"    }, // column strobe low byte
		{ 0x2009L, "WS_LAMP_COL_HIGH"      }, // column strobe high byte
		{ 0x200AL, "WS_LAMP_ROW"           }, // row driver data
		{ 0x200BL, "WS_GI_AUX"            }, // W: GI relay + auxiliary strobe lines
		// Switch and control (0x3000–0x3407)
		{ 0x3000L, "WS_DEDICATED_SWITCH"   }, // R: flipper and service button inputs
		{ 0x3100L, "WS_DIP_SWITCH"         }, // R: SW300 DIP switch (country/region)
		{ 0x3200L, "WS_BANK_SELECT"        }, // W: ROM bank select + diagnostic LED
		{ 0x3300L, "WS_SW_COL_STROBE"      }, // W: switch matrix column select
		{ 0x3400L, "WS_SW_ROW_INPUT"       }, // R: switch matrix row return
		{ 0x3406L, "WS_GI_LAMP_0"          }, // R/W: GI lamp bank 0
		{ 0x3407L, "WS_GI_LAMP_1"          }, // R/W: GI lamp bank 1
		// DMD and sound communication (0x3500–0x3801)
		{ 0x3500L, "WS_DMD_IE"             }, // R: sound/DMD board data input latch (PLIN)
		{ 0x3600L, "WS_DMD_DATA"           }, // W: DMD command data latch
		{ 0x3601L, "WS_DMD_RESET"          }, // W: DMD board reset strobe
		{ 0x3700L, "WS_DMD_STATUS"         }, // R: DMD and sound board status
		{ 0x3800L, "WS_SOUND_CMD"          }, // W: sound board command port
		{ 0x3801L, "WS_SOUND_CMD_UNK"      }, // W: secondary sound board write (no-op)
	};

	// ── Known RAM locations ───────────────────────────────────────────────────

	/** Selected OS-level RAM symbols from wpc_games reverse-engineering work. */
	private static final Object[][] RAM_LABELS = {
		// Checksum fields in system ROM
		{ ADDR_CHECKSUM_DELTA, WordDataType.dataType, "CHECKSUM_DELTA"},
	};

	// ── Loader options ────────────────────────────────────────────────────────

	private static final String OPT_CREATE_OVERLAYS = "Create banked ROM overlays";

	// ─────────────────────────────────────────────────────────────────────────
	// AbstractLoader overrides
	// ─────────────────────────────────────────────────────────────────────────

	@Override
	public String getName() {
		return "Whitestar ROM Loader";
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 100;
	}

	/**
	 * Accept only files whose size matches one of the three valid Whitestar ROM sizes.
	 * Returns a single load spec targeting the Motorola 6809 big-endian 16-bit
	 * language/compiler pair used by all Whitestar hardware.
	 */
	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		long fileLen = provider.length();
		for (long size : VALID_SIZES) {
			if (fileLen == size) {
				loadSpecs.add(new LoadSpec(this, 0,
					new LanguageCompilerSpecPair("6809:BE:16:default", "default"), true));
				break;
			}
		}
		return loadSpecs;
	}

	/**
	 * Build the complete Whitestar memory map and populate labels.
	 *
	 * <p>Memory layout created:
	 * <ul>
	 *   <li>RAM (0x0000–0x1DFF) — 7.5 KiB battery-backed SRAM, R/W</li>
	 *   <li>RAM_PROT (0x1E00–0x1FFF) — 512 B coin-door write-protected RAM, R/W</li>
	 *   <li>IO (0x2000–0x3FFF) — 8 KiB I/O register space, volatile R/W</li>
	 *   <li>ROM_BANK_XX overlays at 0x4000–0x7FFF — one per banked page, R/X</li>
	 *   <li>ROM_SYSTEM (0x8000–0xFFFF) — last 32 KiB of the ROM file, R/X</li>
	 * </ul>
	 */
	@Override
	protected void load(Program program, Loader.ImporterSettings settings)
			throws CancelledException, IOException {

		ByteProvider provider = settings.provider();
		List<Option> options  = settings.options();
		MessageLog log        = settings.log();
		TaskMonitor monitor   = settings.monitor();

		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		long romSize = provider.length();
		int pageCount = (int) (romSize / BANK_SIZE);

		try {
			monitor.setMessage("Loading Whitestar ROM system region…");
			createSystemRomBlock(api, provider, romSize, log);

			monitor.setMessage("Creating RAM blocks…");
			createRamBlocks(api, log);

			monitor.setMessage("Creating I/O block…");
			createIoBlock(api, log);

			boolean createOverlays = getBoolOption(options, OPT_CREATE_OVERLAYS, true);
			if (createOverlays) {
				monitor.setMessage("Creating banked ROM overlays…");
				createBankedOverlays(api, provider, pageCount, monitor, log);
			}

			monitor.setMessage("Applying I/O register labels…");
			applyIoLabels(api, log);

			monitor.setMessage("Applying interrupt vector labels…");
			applyVectorLabels(api, log);

			monitor.setMessage("Setting entry point…");
			setEntryPoint(api, log);

			logRomInfo(romSize, pageCount, log);
			monitor.setMessage("Whitestar ROM loaded successfully.");

		} catch (CancelledException e) {
			throw e;
		} catch (Exception e) {
			log.appendException(e);
			throw new IOException("Failed to load Whitestar ROM: " + e.getMessage(), e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = new ArrayList<>();
		list.add(new Option(OPT_CREATE_OVERLAYS, Boolean.TRUE));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec,
			List<Option> options, Program program) {
		return null;
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Private helpers – block creation
	// ─────────────────────────────────────────────────────────────────────────

	/** Load the last 32 KiB of the ROM file into 0x8000–0xFFFF. */
	private void createSystemRomBlock(FlatProgramAPI api, ByteProvider provider,
			long romSize, MessageLog log) throws Exception {
		byte[] sysBytes = provider.readBytes(romSize - SYSTEM_ROM_SIZE, SYSTEM_ROM_SIZE);
		MemoryBlock block = api.createMemoryBlock(
			"ROM_SYSTEM", api.toAddr(SYSTEM_ROM_START), sysBytes, false);
		block.setPermissions(true, false, true); // R/X — writes are silently discarded by hardware
	}

	/** Create the 7.5 KiB base RAM block and the 512 B write-protected RAM block. */
	private void createRamBlocks(FlatProgramAPI api, MessageLog log) throws Exception {
		MemoryBlock ram = api.createMemoryBlock(
			"RAM", api.toAddr(RAM_START), (InputStream) null, RAM_SIZE_BYTES, false);
		ram.setPermissions(true, true, false);

		// Reads always succeed; writes are blocked by hardware when coin door is closed.
		MemoryBlock ramProt = api.createMemoryBlock(
			"RAM_PROT", api.toAddr(RAM_PROT_START), (InputStream) null, RAM_PROT_SIZE, false);
		ramProt.setPermissions(true, true, false);
	}

	/** Create a single volatile 8 KiB block covering the entire 0x2000–0x3FFF I/O window. */
	private void createIoBlock(FlatProgramAPI api, MessageLog log) throws Exception {
		MemoryBlock io = api.createMemoryBlock(
			"IO", api.toAddr(IO_START), (InputStream) null, IO_SIZE, false);
		io.setPermissions(true, true, false);
		io.setVolatile(true);
	}

	/**
	 * Create one Ghidra overlay block per banked ROM page.
	 *
	 * <p>The bank select register ({@code WS_BANK_SELECT}, {@code 0x3200}) maps directly
	 * to the ROM file: bank value {@code N} maps to file offset {@code N × 16 KiB}.
	 * The last two pages of the file form the fixed system ROM and are not overlaid.
	 * Overlay names are {@code ROM_BANK_XX} where {@code XX} is the bank select value
	 * in hex (e.g. {@code ROM_BANK_00}…{@code ROM_BANK_1D} for a 512 KiB ROM).
	 */
	private void createBankedOverlays(FlatProgramAPI api, ByteProvider provider,
			int pageCount, TaskMonitor monitor, MessageLog log) throws Exception {
		int bankedPages = pageCount - 2; // last 2 pages = fixed system ROM
		for (int bank = 0; bank < bankedPages; bank++) {
			monitor.checkCancelled();
			String name = String.format("ROM_BANK_%02X", bank);
			long fileOffset = (long) bank * BANK_SIZE;
			byte[] bankBytes = provider.readBytes(fileOffset, BANK_SIZE);
			MemoryBlock block = api.createMemoryBlock(
				name, api.toAddr(BANKED_ROM_START), bankBytes, true);
			block.setPermissions(true, false, true); // R/X — writes discarded by hardware
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Private helpers – symbol application
	// ─────────────────────────────────────────────────────────────────────────

	/** Apply labels for every known Whitestar I/O register. */
	private void applyIoLabels(FlatProgramAPI api, MessageLog log) {
		for (Object[] reg : IO_REGISTERS) {
			long addr = (Long) reg[0];
			String name = (String) reg[1];
			try {
				api.createLabel(api.toAddr(addr), name, true);
				api.createData(api.toAddr(addr), ByteDataType.dataType);
			} catch (Exception e) {
				log.appendMsg("WhitestarLoader",
					"Could not create label " + name + ": " + e.getMessage());
			}
		}
	}

	/** Apply labels for the known OS-level RAM symbols. */
	private void applyRamLabels(FlatProgramAPI api, MessageLog log) {
		for (Object[] entry : RAM_LABELS) {
			long addr = (Long) entry[0];
			DataType type = (DataType) entry[1];
			String name = (String) entry[2];
			try {
				api.createLabel(api.toAddr(addr), name, true);
				api.createData(api.toAddr(addr), type);
			} catch (Exception e) {
				log.appendMsg("WhitestarLoader", "Could not create RAM label " + name + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Label each 6809 interrupt vector as a 16-bit pointer and create a function
	 * at the target address named after the vector.
	 */
	private void applyVectorLabels(FlatProgramAPI api, MessageLog log) {
		for (Object[] vec : VECTORS) {
			long vecAddr = (Long) vec[0];
			String vecName = (String) vec[1];
			try {
				Address addr = api.toAddr(vecAddr);
				api.createLabel(addr, vecName, true);
				api.createData(addr, Pointer16DataType.dataType);

				// Read the 2-byte big-endian target address
				byte[] bytes = api.getBytes(addr, 2);
				int target = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
				Address targetAddr = api.toAddr(target);
				if (api.getMemoryBlock(targetAddr) != null &&
						api.getFunctionAt(targetAddr) == null) {
					api.createFunction(targetAddr, vecName + "_ISR");
				}
			} catch (Exception e) {
				log.appendMsg("WhitestarLoader",
					"Could not create vector " + vecName + ": " + e.getMessage());
			}
		}
	}

	/**
	 * Read the RESET vector (0xFFFE) from the fixed ROM and register that address
	 * as the program entry point.
	 */
	private void setEntryPoint(FlatProgramAPI api, MessageLog log) {
		try {
			byte[] bytes = api.getBytes(api.toAddr(0xFFFEL), 2);
			int resetTarget = ((bytes[0] & 0xFF) << 8) | (bytes[1] & 0xFF);
			Address entry = api.toAddr(resetTarget);
			api.addEntryPoint(entry);
			if (api.getFunctionAt(entry) == null) {
				api.createFunction(entry, "entry");
			}
		} catch (Exception e) {
			log.appendMsg("WhitestarLoader", "Could not set entry point: " + e.getMessage());
		}
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Private helpers – diagnostics
	// ─────────────────────────────────────────────────────────────────────────

	/** Log ROM metadata (size, page layout) to the message log. */
	private void logRomInfo(long romSize, int pageCount, MessageLog log) {
		log.appendMsg("WhitestarLoader",
			String.format("ROM size: %d KiB  |  %d pages (%d banked + 2 fixed)",
				romSize / 1024, pageCount, pageCount - 2));
	}

	// ─────────────────────────────────────────────────────────────────────────
	// Utility
	// ─────────────────────────────────────────────────────────────────────────

	private static boolean getBoolOption(List<Option> options, String name, boolean defaultVal) {
		if (options == null) return defaultVal;
		for (Option opt : options) {
			if (name.equals(opt.getName())) {
				Object val = opt.getValue();
				if (val instanceof Boolean) return (Boolean) val;
			}
		}
		return defaultVal;
	}
}
