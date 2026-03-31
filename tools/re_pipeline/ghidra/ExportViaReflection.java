// @category BinExport
// Headless BinExport script for Ghidra.
//
// Works around OSGi classloader isolation by loading BinExport.jar
// via URLClassLoader with Ghidra's own classloader as parent.
//
// Usage (headless):
//   analyzeHeadless PROJECT_DIR PROJECT_NAME \
//     -import binary.exe \
//     -postScript ExportViaReflection.java /path/to/output.BinExport \
//     -scriptPath /path/to/this/directory

import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.Exporter;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;

public class ExportViaReflection extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args.length > 0 ? args[0] : "/tmp/bindiff/output/export.BinExport";

        File jarFile = new File("/opt/ghidra/Extensions/Ghidra/BinExport/lib/BinExport.jar");
        if (!jarFile.exists()) {
            printerr("BinExport.jar not found at: " + jarFile);
            return;
        }
        println("Loading BinExport from: " + jarFile);

        ClassLoader ghidraClassLoader = ghidra.app.util.exporter.Exporter.class.getClassLoader();
        URLClassLoader loader = new URLClassLoader(
            new URL[]{jarFile.toURI().toURL()},
            ghidraClassLoader
        );

        Class<?> exporterClass = loader.loadClass("com.google.security.binexport.BinExportExporter");
        Exporter exporter = (Exporter) exporterClass.getDeclaredConstructor().newInstance();
        println("Exporter loaded: " + exporter.getName());

        File outFile = new File(outputPath);
        println("Exporting to: " + outputPath);
        boolean result = exporter.export(outFile, currentProgram, currentProgram.getMemory(), monitor);

        if (result) {
            println("SUCCESS: " + outputPath + " (" + outFile.length() + " bytes)");
        } else {
            printerr("FAILED: export returned false");
        }
    }
}
