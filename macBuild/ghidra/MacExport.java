// Bounded static exporter, using the same Ghidra APIs as IndagoExport.java.
// The selected input is imported by Ghidra; no target instructions are executed.
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
import com.google.gson.stream.JsonWriter;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class MacExport extends HeadlessScript {
    private String hex(Address value) { return "0x" + Long.toHexString(value.getOffset()); }

    private int writeIndex(FunctionIterator iterator, JsonWriter writer) throws Exception {
        int count = 0;
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            writer.beginObject();
            writer.name("name").value(function.getName());
            // External addresses live in a different address space; keep its
            // prefix rather than presenting an import as an executable address.
            writer.name("address").value(function.isExternal() ?
                function.getEntryPoint().toString() : hex(function.getEntryPoint()));
            writer.name("external").value(function.isExternal());
            writer.endObject();
            ++count;
        }
        return count;
    }

    // The initial preview and on-demand requests share exactly the same export format.
    private JsonObject exportFunction(Function f, DecompInterface decompiler) throws Exception {
        JsonObject item = new JsonObject();
        item.addProperty("name", f.getName());
        item.addProperty("address", hex(f.getEntryPoint()));
        item.addProperty("signature", f.getSignature().getPrototypeString());
        DecompileResults result = decompiler.decompileFunction(f, 10, monitor);
        boolean complete = result.decompileCompleted() && result.getDecompiledFunction() != null;
        String code = complete ? result.getDecompiledFunction().getC() : "";
        boolean truncated = code.length() > 32768;
        item.addProperty("code", truncated ? code.substring(0, 32768) : code);
        item.addProperty("decompile_ok", complete);
        item.addProperty("code_truncated", truncated);
        item.addProperty("diagnostic", result.getErrorMessage());
        JsonArray assembly = new JsonArray();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (instructions.hasNext() && assembly.size() < 2048 && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            JsonObject row = new JsonObject();
            row.addProperty("address", hex(instruction.getAddress()));
            row.addProperty("text", instruction.toString());
            StringBuilder bytes = new StringBuilder();
            for (byte value : instruction.getBytes()) bytes.append(String.format("%02x", value & 255));
            row.addProperty("bytes", bytes.toString());
            // This exporter has no token-to-address mapping. The UI must
            // say "containing function", never invent exact line links.
            row.addProperty("code_line", -1);
            assembly.add(row);
        }
        boolean instructionsTruncated = instructions.hasNext();
        item.add("assembly", assembly);
        item.addProperty("assembly_truncated", instructionsTruncated);
        return item;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 && args.length != 2) throw new IllegalArgumentException("Expected export filename and optional function address");
        String architecture = currentProgram.getLanguage().getProcessor().toString();
        if (!architecture.equals("AARCH64")) throw new IllegalArgumentException("ARM64 input required");
        JsonObject report = new JsonObject();
        report.addProperty("schema", "indago.mac-analysis.v1");
        report.addProperty("architecture", architecture);
        report.addProperty("language", currentProgram.getLanguageID().toString());
        report.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        report.addProperty("ghidra_version", Application.getApplicationVersion());
        // Report what the running JVM actually allows, independently of the
        // requested setting recorded by the launcher. This is not current usage.
        report.addProperty("java_max_heap_bytes", Runtime.getRuntime().maxMemory());
        report.addProperty("input_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("image_base", hex(currentProgram.getImageBase()));
        report.addProperty("analysis_timed_out", analysisTimeoutOccurred());
        if (args.length == 2) {
            // The launcher opens the saved program read-only with analysis off.
            // A missing/external address must never silently select another function.
            Function selected = getFunctionAt(toAddr(args[1]));
            if (selected == null || selected.isExternal())
                throw new IllegalArgumentException("No internal function at requested address");
            DecompInterface decompiler = new DecompInterface();
            try {
                if (!decompiler.openProgram(currentProgram))
                    throw new IllegalStateException(decompiler.getLastMessage());
                report.addProperty("schema", "indago.mac-function.v1");
                report.addProperty("target_executed", false);
                report.add("function", exportFunction(selected, decompiler));
                monitor.checkCancelled();
                Files.writeString(Path.of(args[0]), new Gson().toJson(report), StandardCharsets.UTF_8);
            } finally { decompiler.dispose(); }
            return;
        }
        boolean partial = analysisTimeoutOccurred();
        JsonArray functions = new JsonArray();
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram))
                throw new IllegalStateException(decompiler.getLastMessage());
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && functions.size() < 256 && !monitor.isCancelled()) {
                Function f = iterator.next();
                if (f.isExternal()) continue;
                JsonObject item = exportFunction(f, decompiler);
                partial |= !item.get("decompile_ok").getAsBoolean() ||
                    item.get("code_truncated").getAsBoolean() || item.get("assembly_truncated").getAsBoolean();
                functions.add(item);
            }
            report.addProperty("functions_truncated", iterator.hasNext());
            partial |= iterator.hasNext() || monitor.isCancelled();
        } finally { decompiler.dispose(); }
        // Stream the complete name/address index separately from detailed code.
        // It has no function-count cap and does not share the code report's
        // output budget. Analysis timeouts can still limit what Ghidra discovers.
        Path index = Path.of(args[0]).resolveSibling("functions.json");
        int indexed;
        try (JsonWriter writer = new JsonWriter(Files.newBufferedWriter(index, StandardCharsets.UTF_8))) {
            writer.beginArray();
            FunctionManager manager = currentProgram.getFunctionManager();
            indexed = writeIndex(manager.getFunctions(true), writer);
            indexed += writeIndex(manager.getExternalFunctions(), writer);
            writer.endArray();
        }
        report.addProperty("function_index_count", indexed);
        report.addProperty("function_index_complete", true);
        report.addProperty("details_truncated", report.get("functions_truncated").getAsBoolean());
        report.addProperty("functions_truncated", false);
        report.add("functions", functions);
        report.addProperty("partial", partial);
        report.addProperty("target_executed", false);
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(report);
        if (json.length() > 12 * 1024 * 1024) throw new IllegalStateException("Export exceeds output budget");
        Files.writeString(Path.of(args[0]), json, StandardCharsets.UTF_8);
    }
}
