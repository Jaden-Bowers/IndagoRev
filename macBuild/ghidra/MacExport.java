// Bounded static exporter, using the same Ghidra APIs as IndagoExport.java.
// The selected input is imported by Ghidra; no target instructions are executed.
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class MacExport extends HeadlessScript {
    private String hex(Address value) { return "0x" + Long.toHexString(value.getOffset()); }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Expected export filename");
        String architecture = currentProgram.getLanguage().getProcessor().toString();
        if (!architecture.equals("AARCH64")) throw new IllegalArgumentException("ARM64 input required");
        JsonObject report = new JsonObject();
        report.addProperty("schema", "indago.mac-analysis.v1");
        report.addProperty("architecture", architecture);
        report.addProperty("language", currentProgram.getLanguageID().toString());
        report.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        report.addProperty("ghidra_version", Application.getApplicationVersion());
        report.addProperty("input_sha256", currentProgram.getExecutableSHA256());
        report.addProperty("image_base", hex(currentProgram.getImageBase()));
        report.addProperty("analysis_timed_out", analysisTimeoutOccurred());
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
                partial |= !complete || truncated || instructionsTruncated;
                functions.add(item);
            }
            report.addProperty("functions_truncated", iterator.hasNext());
            partial |= iterator.hasNext() || monitor.isCancelled();
        } finally { decompiler.dispose(); }
        report.add("functions", functions);
        report.addProperty("partial", partial);
        report.addProperty("target_executed", false);
        String json = new GsonBuilder().setPrettyPrinting().create().toJson(report);
        if (json.length() > 12 * 1024 * 1024) throw new IllegalStateException("Export exceeds output budget");
        Files.writeString(Path.of(args[0]), json, StandardCharsets.UTF_8);
    }
}
