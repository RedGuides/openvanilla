// @category BinExport
// Extract cross-references for a list of target addresses.
//
// Input: text file with one hex address per line (e.g., 0x140DDB608)
// Output: JSON file mapping each address to its xref locations
//
// Usage (headless):
//   analyzeHeadless PROJECT_DIR PROJECT_NAME -process binary.exe \
//     -noanalysis -postScript ExtractXrefs.java input_addrs.txt output_xrefs.json

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;

import java.io.*;
import java.util.*;

public class ExtractXrefs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            printerr("Usage: ExtractXrefs.java <input_addrs.txt> <output_xrefs.json>");
            return;
        }

        String inputPath = args[0];
        String outputPath = args[1];

        println("ExtractXrefs: reading addresses from " + inputPath);

        // Read target addresses
        List<Long> targets = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new FileReader(inputPath));
        String line;
        while ((line = reader.readLine()) != null) {
            line = line.trim();
            if (line.startsWith("0x") || line.startsWith("0X")) {
                targets.add(Long.parseUnsignedLong(line.substring(2), 16));
            }
        }
        reader.close();
        println("  Loaded " + targets.size() + " target addresses");

        // Get reference manager
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        AddressFactory addrFactory = currentProgram.getAddressFactory();
        AddressSpace defaultSpace = addrFactory.getDefaultAddressSpace();

        // For each target, find all xrefs TO it
        StringBuilder json = new StringBuilder("{\n");
        final int[] found = {0};
        int total = 0;

        for (int i = 0; i < targets.size(); i++) {
            long targetAddr = targets.get(i);
            Address addr = defaultSpace.getAddress(targetAddr);

            if (i > 0) json.append(",\n");
            json.append(String.format("  \"0x%X\": [", targetAddr));

            final boolean[] first = {true};
            ReferenceManagerUtil.forEachReferenceTo(refMgr, addr, ref -> {
                Address fromAddr = ref.getFromAddress();
                if (!first[0]) {
                    json.append(", ");
                }
                json.append(String.format("\"0x%X\"", fromAddr.getOffset()));
                first[0] = false;
                found[0]++;
            });
            json.append("]");
            total++;

            if ((i + 1) % 100 == 0) {
                println("  Progress: " + (i + 1) + "/" + targets.size() +
                        " (" + found[0] + " xrefs found)");
            }
        }

        json.append("\n}\n");

        // Write output
        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));
        writer.print(json.toString());
        writer.close();

        println("ExtractXrefs: wrote " + found[0] + " xrefs for " + total +
                " addresses to " + outputPath);
    }
}
