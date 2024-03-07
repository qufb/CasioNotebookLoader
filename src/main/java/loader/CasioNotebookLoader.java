/* ###
 * IP: GHIDRA
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
package loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Formatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.OptionDialog;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.Option;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.AddressLabelInfo;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class CasioNotebookLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "Casio Notebook Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, false);

		Set<String> knownHashes = Set.of(
			"d5b6677ab4e0d3f84e5769e89e8f3d101f98f848", // cfx9850.bin
			"1d1aa38205eec7aba3ed6bef7389767e38afe075", // cfx9850b.bin
			"7cde6074758b5ae474b4eb3ee7396dbfb481ddcf", // r27v802d-34.lsi2
			"f9a63db3d048da0954cab052690deb01ec384b22"  // d23c8000xgx-c64.lsi5
		);
		byte[] bytes = provider.readBytes(0, provider.length());
		byte[] hashBytes;
		try {
			hashBytes = MessageDigest.getInstance("SHA-1").digest(bytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		String hash;
		try (Formatter formatter = new Formatter()) {
			for (byte b : hashBytes) {
				formatter.format("%02x", b);
			}
			hash = formatter.toString();
		}
		boolean isLoaded = knownHashes.stream().anyMatch(knownHash -> knownHash.equalsIgnoreCase(hash));
		if (isLoaded) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("HCD62121:BE:16:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider,
			LoadSpec loadSpec,
			List<Option> options,
			Program program,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		InputStream cpuRomStream = null;

		File cpuRomFile = new File("/tmp/hcd62121.bin");
		if (cpuRomFile.isFile()) {
			cpuRomStream = new FileInputStream(cpuRomFile);
			monitor.setMessage(String.format("Loading CPU ROM @ %s", cpuRomFile));
		} else {
            int choice = OptionDialog.showOptionNoCancelDialog(
                null,
                "CPU ROM mapping",
                "Load CPU ROM file?",
                "Yes",
                "No (Just create empty mapping)",
                OptionDialog.QUESTION_MESSAGE
            );
            if (choice == OptionDialog.OPTION_ONE) {
                GhidraFileChooser chooser = new GhidraFileChooser(null);
                chooser.setTitle("Open CPU ROM file");
                File file = chooser.getSelectedFile(true);
                if (file != null) {
                    cpuRomStream = new FileInputStream(file);
                }
            }
        }

		InputStream romStream = provider.getInputStream(0);
		long bank_size = 0x10000L;
		createSegment(fpa, cpuRomStream, "CPU_ROM",   "ram:0000:0000", 0x08000L, true, false, true, true, log);
		createSegment(fpa, null,         "VIDEO_RAM", "ram:0008:0000", 0x00800L, true, true, false, true, log);
		createSegment(fpa, null,         "EXT_10",    "ram:0010:0000", 0x10000L, true, true, false, true, log);
		createSegment(fpa, null,         "EXT_11",    "ram:0011:0000", 0x10000L, true, true, false, true, log);
		for (int i = 0; i < 0x10; i++) {
			createSegment(fpa, provider.getInputStream(Math.min(romStream.available(), bank_size * i)),
					"ROM_" + String.format("%02d", i), String.format("ram:00%02x:0000", 0x20 + i), bank_size, true, false, true, false, log);
			if (romStream.available() <= bank_size * (i + 1)) {
				break;
			}
		}
		createSegment(fpa, null, "WORK_RAM", "ram:0040:0000", 0x08000L, true, true, false, true, log);
		createSegment(fpa, null, "DISP_RAM", "ram:0060:0000", 0x00800L, true, true, false, true, log);
		createSegment(fpa, null, "EXT_E1",   "ram:00e1:0000", 0x10000L, true, true, false, true, log);

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	private void createSegment(FlatProgramAPI fpa,
			InputStream stream,
			String name,
			String address,
			long size,
			boolean read,
			boolean write,
			boolean execute,
			boolean volatil,
			MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.getAddressFactory().getAddress(address), stream, size, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedData(FlatProgramAPI fpa,
			Program program,
			String address,
			String name,
			DataType type,
			MessageLog log) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(fpa.toAddr(address));
			} else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(fpa.toAddr(address));
			} else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(fpa.toAddr(address));
			}
			program.getSymbolTable().createLabel(fpa.getAddressFactory().getAddress(address), name, SourceType.IMPORTED);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedArray(FlatProgramAPI fpa,
			Program program,
			long address,
			String name,
			int numElements,
			DataType type,
			MessageLog log) {
		try {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type, type.getLength());
			arrayCmd.applyTo(program);
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private void createMirrorSegment(Memory memory,
			FlatProgramAPI fpa,
			String name,
			long src,
			long dst,
			long size,
			MessageLog log) {
		MemoryBlock block;
		Address baseAddress = fpa.toAddr(src);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(dst), baseAddress, size, false);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead(baseBlock.isRead());
			block.setWrite(baseBlock.isWrite());
			block.setExecute(baseBlock.isExecute());
			block.setVolatile(baseBlock.isVolatile());
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createMirrorSegment(Memory memory,
			FlatProgramAPI fpa,
			String name,
			long src,
			long dst,
			long size,
			int rwx,
			MessageLog log) {
		MemoryBlock block;
		Address baseAddress = fpa.toAddr(src);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(dst), baseAddress, size, false);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead((rwx & 0b100) != 0);
			block.setWrite((rwx & 0b010) != 0);
			block.setExecute((rwx & 0b001) != 0);
			block.setVolatile(baseBlock.isVolatile());
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
