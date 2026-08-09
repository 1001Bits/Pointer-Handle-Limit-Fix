//@category MCP
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.lang.OperandType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class McpScalar2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Target immediates relevant to handle decode / cap raise
        long[] targets = {
            0x1fffffL,    // stock index mask (also refcount mask -- TRAP)
            0x200000L,    // stock generation unit (1<<21)
            0xffe00000L,  // stock generation mask
            0x3fffffL,    // widened index mask candidate (22 bits)
            0x1ffffeL,    // near-variant
            0x200001L,    // near-variant
            0xffc00000L   // widened generation mask candidate
        };

        // Buckets
        ArrayList<String> immHits = new ArrayList<>();   // pure immediate operand (real candidates)
        ArrayList<String> addrHits = new ArrayList<>();  // scalar inside a memory/address operand (addressing noise)
        Map<String,Integer> immByMnem = new HashMap<>();
        Map<String,Integer> addrByMnem = new HashMap<>();
        Map<String,Integer> addrFuncSet = new HashMap<>();

        int immCount = 0, addrCount = 0;

        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            int nOps = ins.getNumOperands();
            for (int i = 0; i < nOps; i++) {
                int ot = ins.getOperandType(i);
                Object[] objs = ins.getOpObjects(i);
                for (Object o : objs) {
                    if (!(o instanceof Scalar)) continue;
                    long v = ((Scalar) o).getUnsignedValue();
                    boolean match = false;
                    for (long t : targets) { if (v == t) { match = true; break; } }
                    if (!match) continue;

                    // Is this scalar a pure immediate, or a displacement inside a memory ref?
                    boolean isMemoryOperand = OperandType.isAddress(ot) || OperandType.isDynamic(ot);
                    // A pure immediate operand: scalar and NOT part of an address/dynamic (memory) operand.
                    boolean isImmediate = OperandType.isScalar(ot) && !isMemoryOperand;

                    Function f = getFunctionContaining(ins.getAddress());
                    String fn = f == null ? "?" : f.getName() + "@" + f.getEntryPoint();
                    String mnem = ins.getMnemonicString();
                    String line = String.format("0x%08x  %s  %s  fn=%s", v, ins.getAddress(), ins.toString(), fn);

                    if (isImmediate) {
                        immHits.add(line);
                        immByMnem.merge(mnem, 1, Integer::sum);
                        immCount++;
                    } else {
                        addrHits.add(line);
                        addrByMnem.merge(mnem, 1, Integer::sum);
                        addrFuncSet.merge(fn, 1, Integer::sum);
                        addrCount++;
                    }
                }
            }
        }

        println("=== IMMEDIATE-OPERAND HITS (real handle/refcount candidates) count=" + immCount + " ===");
        for (String s : immHits) println(s);
        println("");
        println("=== IMMEDIATE HISTOGRAM BY MNEMONIC ===");
        for (Map.Entry<String,Integer> e : immByMnem.entrySet()) println("  " + e.getKey() + " = " + e.getValue());
        println("");
        println("=== ADDRESS-DISPLACEMENT HITS (addressing / far-field, mostly OTHER) count=" + addrCount + " ===");
        println("  distinct functions with such displacement = " + addrFuncSet.size());
        println("  histogram by mnemonic:");
        for (Map.Entry<String,Integer> e : addrByMnem.entrySet()) println("    " + e.getKey() + " = " + e.getValue());
        println("");
        println("=== ADDRESS-DISPLACEMENT: NON-LEA subset (worth a glance) ===");
        for (String s : addrHits) {
            if (!s.contains("LEA ")) println(s);
        }
        println("SCALAR2 DONE immCount=" + immCount + " addrCount=" + addrCount);
    }
}
