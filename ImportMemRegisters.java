import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.address.*;

public class ImportMemRegisters extends GhidraScript {
    @Override
    public void run() throws Exception {
    	

        File file = askFile("Please specify a registers definition file", "Select registers definition");
        println("Using " + file.getName() + " as registers definition file");

        BufferedReader br = new BufferedReader(new FileReader(file));
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        
        for (String line = br.readLine(); line != null; line = br.readLine()) {
        	String[] fields = line.split(" ");
        	Address s_addr = toAddr(Long.decode("0x" + fields[0]));
            Long s_size = Long.decode("0x" + fields[1]);
            String s_name = fields[2];
            
            DataType s_type = new UnsignedLongDataType();
            if (s_size == 2) {
            	s_type = new UnsignedShortDataType();
            }
            if (st.hasSymbol(s_addr)) {
            	Symbol[] sl_old = st.getSymbols(s_addr);
            	for (Symbol s_old : sl_old) {
            		s_old.delete();
            	}
            	
            }
            clearListing(s_addr, s_addr.add(s_size));
            createData(s_addr, s_type);
            createLabel(s_addr, s_name, true);
        }
        
        br.close();
    }
}
