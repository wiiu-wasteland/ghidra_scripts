//Import TMode from external file

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import ghidra.app.plugin.core.clear.ClearFlowAndRepairCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
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
import ghidra.program.model.address.*;

public class ImportExternalTModeDump extends GhidraScript {

    public void run() throws Exception {
        Register tmode = currentProgram.getProgramContext().getRegister("TMode"); 
        Listing lst = currentProgram.getListing(); 

    	File file = askFile("Please select an execution mode dump", "Select execution mode dump");
        println("Using " + file.getName() + " as execution mode dump");
        Address baseAddr = askAddress("Please select the execution mode dump starting address", "Select starting address");

        byte[] exeMode = new byte[(int) file.length()];
        InputStream is = new FileInputStream(file);
        is.read(exeMode);
        is.close();
        
        /* cleanup */
        for (int i = 0; i < exeMode.length; i++) {
        	boolean  dbg = false;
        	if (i == 0x0926a) {
        		dbg = true;
        	}
        	
        	int iSize = 0;
        	BigInteger tmodeValue = BigInteger.ZERO;
        	if (exeMode[i] == 1) {
        		tmodeValue = BigInteger.ZERO;
        		iSize = 4;
        	} else if (exeMode[i] == 2) {
        		tmodeValue = BigInteger.ONE;
        		iSize = 2;
        	} else {
        		continue;
        	}
        	
        	if (dbg) {
        		println("EXPECTED tmode: " + tmodeValue);
        		println("EXPECTED iSize: " + iSize);
        	}
        	
            Address refAddr = baseAddr.add(i); 
            if (!currentProgram.getMemory().contains(refAddr)) 
            {
            	if (dbg) {
            		println("ADDR not in current program");
            	}
               continue; 
            }
            
            boolean okay = false;
            Instruction instr = lst.getInstructionAt(refAddr);
            if (instr != null) {
            	if (dbg) {
            		println("INSTR present");
            	}
            	if (instr.getBytes().length == iSize) {
            		//println("Correct size at " + refAddr);
            		okay = true;
            	} else {
            		println(refAddr + " : " + instr.getBytes().length + " -> " + iSize);
            	}
            }
            
            if (okay) {
            	continue;
            }


           // if TMode was wrong but there is code here, 
           // clear the flow so we can disassemble it in the right mode 
           /*if (!lst.isUndefined(refAddr, refAddr.add(iSize))) 
           { 
        	  println("Removing wrong existing TMode for address " + refAddr);
        	  for (int q = 0; q < iSize; q++) {
        		  ClearFlowAndRepairCmd cmd = new ClearFlowAndRepairCmd(refAddr.add(q), true, true, false); 
                  runCommand(cmd); 
        	  }
           }
     	  clearListing(refAddr, refAddr.add(iSize));*/
        }
        
        /* apply new TMode 
        
        for (int i = 0; i < exeMode.length; i++) {
        	int iSize = 0;
        	BigInteger tmodeValue = BigInteger.ZERO;
        	if (exeMode[i] == 1) {
        		tmodeValue = BigInteger.ZERO;
        		iSize = 4;
        	} else if (exeMode[i] == 2) {
        		tmodeValue = BigInteger.ONE;
        		iSize = 2;
        	} else {
        		continue;
        	}
        	
            Address refAddr = baseAddr.add(i); 
            if (!currentProgram.getMemory().contains(refAddr)) 
            { 
               continue; 
            }

            // Check current TMode at referenced address 
            BigInteger currVal = 
               currentProgram.getProgramContext().getValue(tmode, refAddr, false); 
            // If the TMode isn't set correctly, fix it here 
            if (currVal == null || currVal.compareTo(tmodeValue) != 0) 
            { 
               println("Setting TMode for address " + refAddr);
               currentProgram.getProgramContext().setValue( 
                       tmode, 
                       refAddr, 
                       refAddr.add(iSize), 
                       tmodeValue); 
            } 

        }*/
        

        /* apply new TMode
        
        for (int i = 0; i < exeMode.length; i++) {
        	int iSize = 0;
        	BigInteger tmodeValue = BigInteger.ZERO;
        	if (exeMode[i] == 1) {
        		tmodeValue = BigInteger.ZERO;
        		iSize = 4;
        	} else if (exeMode[i] == 2) {
        		tmodeValue = BigInteger.ONE;
        		iSize = 2;
        	} else {
        		continue;
        	}
        	
            Address refAddr = baseAddr.add(i); 
            if (!currentProgram.getMemory().contains(refAddr)) 
            { 
               continue; 
            }

            if (lst.isUndefined(refAddr, refAddr)) 
            { 
               disassemble(refAddr); 
            }
        } */
    }

}
