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
//Finds undefined functions by searching for common 
//byte patterns used by compilers for function entry points.
//
//Only Intel GCC, Windows, and PowerPC are currently
//handled.
//
//Please feel free to change this script and add
//different byte patterns.
//
//When the byte pattern is found, the instructions 
//will be disassembled and a function will be created.
//
//Please note: this will NOT find all undefined functions!
//@category Functions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class Create_UDF_Functions extends GhidraScript {

	@Override
	public void run() throws Exception {
		boolean doIT =
			askYesNo("Find and Create Functions?", "Would you like find and create functions?");
		if (!doIT) {
			return;
		}

		long expectedPattern = 0xe7f000f0e12fff1eL;  //udf #num; bx lr
				
		Address address = currentProgram.getMinAddress();
		while (true) {
			if (monitor.isCancelled()) {
				break;
			}

			Data nextUndefined =
				currentProgram.getListing().getUndefinedDataAfter(address, monitor);
			if (nextUndefined == null) {
				break;
			}
			Address undefinedAddress = nextUndefined.getMinAddress();

			MemoryBlock block = currentProgram.getMemory().getBlock(undefinedAddress);
			if (!block.isExecute()) {
				address = undefinedAddress;
				continue;
			}

			try {
				
				long actualValue = currentProgram.getMemory().getLong(undefinedAddress, true) & 0xffff00ffffffffffL;
				
				if (expectedPattern == actualValue) {
					disassemble(undefinedAddress);
					createFunction(undefinedAddress, null);
					address = undefinedAddress.add(1);
				}
				else {
					address = undefinedAddress;
				}
			} catch (Exception e) {
				address = undefinedAddress;
				continue;
			}
		}
	}
}
