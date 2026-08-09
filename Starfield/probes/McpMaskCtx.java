//@category MCP
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.OperandType;

import java.util.LinkedHashMap;
import java.util.Map;

public class McpMaskCtx extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Which immediate value to hunt for context; default 0x1fffff. Override via first script arg.
        long target = 0x200000L;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0) {
            target = Long.decode(args[0].trim());
        }

        // Discover distinct functions containing this immediate as a pure (non-address) operand.
        LinkedHashMap<Function,Boolean> funcs = new LinkedHashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            int nOps = ins.getNumOperands();
            for (int i = 0; i < nOps; i++) {
                int ot = ins.getOperandType(i);
                boolean isMem = OperandType.isAddress(ot) || OperandType.isDynamic(ot);
                if (isMem) continue; // skip address-displacement uses
                for (Object o : ins.getOpObjects(i)) {
                    if (o instanceof Scalar && ((Scalar) o).getUnsignedValue() == target) {
                        Function f = getFunctionContaining(ins.getAddress());
                        if (f != null) funcs.put(f, Boolean.TRUE);
                    }
                }
            }
        }

        println("=== MASK CONTEXT for 0x" + Long.toHexString(target) + "  distinctFuncs=" + funcs.size() + " ===");
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        di.setSimplificationStyle("decompile");
        String hex = "0x" + Long.toHexString(target);
        for (Function f : funcs.keySet()) {
            DecompileResults res = di.decompileFunction(f, 90, monitor);
            println("----- " + f.getName() + " @ " + f.getEntryPoint());
            if (res == null || !res.decompileCompleted()) {
                println("   DECOMP FAILED");
                continue;
            }
            String c = res.getDecompiledFunction().getC();
            boolean shift43 = c.contains(">> 0x2b");
            boolean flag42 = c.contains("0x40000000000") || c.contains("0x80000000000") || c.contains("0x80000200000");
            boolean plus8 = c.contains("param_1[1]") || c.contains("+ 8)") || c.contains("+ 1;");
            boolean shift21 = c.contains(">> 0x15");
            boolean shl21 = c.contains("<< 0x15");
            boolean callsLookup = c.contains("1428d0ff0") || c.contains("1428d0e40") || c.contains("1428d1090");
            println("   FLAGS: shift43(refcount3)=" + shift43 + " flagbits(refcount)=" + flag42
                    + " shift21=" + shift21 + " shl21(handleConstruct?)=" + shl21 + " callsHandleMgr=" + callsLookup);
            // Print each source line mentioning the target hex, with the previous line for context.
            String[] lines = c.split("\n");
            for (int i = 0; i < lines.length; i++) {
                if (lines[i].contains(hex)) {
                    if (i > 0) println("     | " + lines[i-1].trim());
                    println("     > " + lines[i].trim());
                }
            }
        }
        di.dispose();
        println("MASKCTX DONE");
    }
}
