// @category BinExport
// For each target address, find all code locations that reference it,
// AND extract what address each referencing instruction points to.
//
// This captures the complete xref picture:
//   target_addr -> [(from_addr, referenced_addr, ref_type), ...]
//
// For the new binary, we use the from_addr (mapped via BinDiff) to find
// the instruction, then read what address IT references -- that's our answer.
//
// Input: text file with "NAME 0xADDR" per line
// Output: JSON with xref details
//
// Usage (headless) — either after -import (second -postScript after BinExport), or legacy:
//   analyzeHeadless PROJECT_DIR PROJECT_NAME -import binary.exe \
//     -postScript ExportViaReflection.java out.BinExport \
//     -postScript ExtractReferences.java input.txt output.json \
//     -scriptPath /path/to/ghidra
//   analyzeHeadless PROJECT_DIR PROJECT_NAME -process binary.exe -noanalysis \
//     -postScript ExtractReferences.java input.txt output.json

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;

import java.io.*;
import java.util.*;

public class ExtractReferences extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("Usage: ExtractReferences.java <input.txt> <output.json>");
            return;
        }

        String inputPath = args[0];
        String outputPath = args[1];

        println("ExtractReferences: reading from " + inputPath);

        // Read targets: "NAME 0xADDR" per line
        List<String[]> targets = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new FileReader(inputPath));
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] parts = line.split("\\s+");
            if (parts.length >= 2) {
                targets.add(new String[]{parts[0], parts[1]});
            }
        }
        reader.close();
        println("  Loaded " + targets.size() + " targets");

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();

        StringBuilder json = new StringBuilder("{\n");
        final int[] totalXrefs = {0};

        for (int i = 0; i < targets.size(); i++) {
            String name = targets.get(i)[0];
            String addrStr = targets.get(i)[1];
            long targetLong = Long.parseUnsignedLong(addrStr.replace("0x", "").replace("0X", ""), 16);
            Address targetAddr = space.getAddress(targetLong);

            if (i > 0) json.append(",\n");
            json.append(String.format("  \"%s\": {\n", name));
            json.append(String.format("    \"address\": \"0x%X\",\n", targetLong));
            json.append("    \"xrefs\": [");

            final boolean[] first = {true};
            ReferenceManagerUtil.forEachReferenceTo(refMgr, targetAddr, ref -> {
                Address fromAddr = ref.getFromAddress();
                String refType = ref.getReferenceType().getName();

                // Get the instruction at the from address
                Instruction instr = listing.getInstructionAt(fromAddr);
                String mnemonic = instr != null ? instr.getMnemonicString() : "unknown";
                String operands = instr != null ? instr.toString().substring(mnemonic.length()).trim() : "";

                // Get all references FROM this instruction (what addresses it touches)
                Reference[] fromRefs = instr != null ? instr.getReferencesFrom() : new Reference[0];
                StringBuilder refsFromJson = new StringBuilder("[");
                boolean firstFrom = true;
                for (Reference fromRef : fromRefs) {
                    if (!firstFrom) refsFromJson.append(", ");
                    refsFromJson.append(String.format("\"0x%X\"", fromRef.getToAddress().getOffset()));
                    firstFrom = false;
                }
                refsFromJson.append("]");

                if (!first[0]) {
                    json.append(",");
                }
                json.append(String.format("\n      {\"from\": \"0x%X\", \"type\": \"%s\", " +
                        "\"mnemonic\": \"%s\", \"refs_from\": %s}",
                        fromAddr.getOffset(), refType, mnemonic, refsFromJson));
                first[0] = false;
                totalXrefs[0]++;
            });

            json.append("\n    ]\n  }");

            if ((i + 1) % 50 == 0) {
                println("  Progress: " + (i + 1) + "/" + targets.size() +
                        " (" + totalXrefs[0] + " xrefs)");
            }
        }

        json.append("\n}\n");

        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));
        writer.print(json.toString());
        writer.close();

        println("ExtractReferences: " + totalXrefs[0] + " xrefs for " + targets.size() +
                " targets -> " + outputPath);
    }
}
