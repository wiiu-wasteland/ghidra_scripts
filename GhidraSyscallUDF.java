//Find syscalls via undefined instruction
//@author rw
//@category ARM
//@keybinding
//@menupath
//@toolbar

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Vector;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;

class Memarea
{
	public long start, end;
	public String name;
	public Memarea(long start, long end, String name) {
		this.start = start;
		this.end = end;
		this.name = name;
	}
}

public class GhidraSyscallUDF extends GhidraScript {
    private HashMap<Integer, String> Syscalls = new HashMap<Integer, String>();
    private Vector<Memarea> Memareas = new Vector<Memarea>();
    
    /*public String getMemArea(Address address) {
    	long addr = address.getAddressableWordOffset();
    	for (Memarea m : Memareas) {
    		if (addr >= m.start && addr <= m.end) {
    			return m.name;
    		}
    	}
    	return null;
    }*/

    @Override
    protected void run() throws Exception {
        File file = askFile("Please specify a syscall definition file", "Select syscalls definition");
        println("Using " + file.getName() + " as syscalls description file");

        /*File file2 = askFile("Please specify a memarea definition file", "Select memarea definition");
        println("Using " + file2.getName() + " as memarea description file");*/

        BufferedReader br = new BufferedReader(new FileReader(file));
        for (String line = br.readLine(); line != null; line = br.readLine()) {
        	String[] fields = line.split(":");
            Syscalls.put(Integer.decode(fields[0]), fields[1]);
        }
        
        /*BufferedReader br2 = new BufferedReader(new FileReader(file2));
        for (String line = br2.readLine(); line != null; line = br2.readLine()) {
        	String[] fields = line.split(":");
        	Memareas.add(new Memarea(Long.decode(fields[0]), Long.decode(fields[1]), fields[2]));
        }*/
        
    	Memory memory = currentProgram.getMemory();
        FunctionIterator fnIter = currentProgram.getFunctionManager().getFunctions(true);
		while (fnIter.hasNext()) {
			Function function = fnIter.next();

			if (monitor.isCancelled()) {
				break;
			}
			
			Address instrAddr = function.getEntryPoint();
			int instrVal  = memory.getInt(instrAddr, true);
			int instr = instrVal & 0xffff00ff;
			if (instr != 0xE7F000F0) {
				continue;
			}
			int sysnum = (instrVal >>> 8) & 0xff;
			if (!Syscalls.containsKey(sysnum)) {
				continue;
			}
			
			String fnname;
			String sysname = Syscalls.get(sysnum);
			//String modname = getMemArea(instrAddr);
			//if (modname != null) {
			//	fnname = modname + "_K" + sysname;
			//} else {
				fnname = "IOS_" + sysname;
			//}
			
			println("Renaming: " + function.getName() + " -> " + fnname);
			
			function.setName(fnname, SourceType.DEFAULT);
		}
    }
}
