// Basic bounded Ghidra exporter for the IndagoRev development prototype.

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class IndagoExport extends GhidraScript {
    private static String quote(String value) {
        if (value == null) return "null";
        StringBuilder result = new StringBuilder("\"");
        for (int index = 0; index < value.length(); ++index) {
            char ch = value.charAt(index);
            switch (ch) {
                case '\"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\b': result.append("\\b"); break;
                case '\f': result.append("\\f"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (ch < 0x20) result.append(String.format("\\u%04x", (int) ch));
                    else result.append(ch);
            }
        }
        return result.append('\"').toString();
    }

    private static String hex(Address address) {
        return address == null ? null : String.format("0x%x", address.getOffset());
    }

    private static String bytes(Instruction instruction) {
        StringBuilder result = new StringBuilder();
        try {
            for (byte value : instruction.getBytes()) {
                result.append(String.format("%02x", value & 0xff));
            }
        } catch (Exception ignored) {
            // Preserve the instruction with an empty byte field when memory is unavailable.
        }
        return result.toString();
    }

    private String decompile(DecompInterface decompiler, Function function, int timeout) {
        try {
            DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null) return null;
            return result.getDecompiledFunction().getC();
        } catch (Exception ignored) {
            return null;
        }
    }

    private void writeCalls(PrintWriter out, Function function) {
        List<String> calls = new ArrayList<>();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            for (Reference reference : instruction.getReferencesFrom()) {
                if (!reference.getReferenceType().isCall()) continue;
                calls.add("{\"site\":" + quote(hex(instruction.getAddress())) +
                    ",\"target\":" + quote(hex(reference.getToAddress())) +
                    ",\"kind\":" + quote(reference.getReferenceType().toString()) + "}");
            }
        }
        Collections.sort(calls);
        for (int index = 0; index < calls.size(); ++index) {
            out.print("        " + calls.get(index));
            out.println(index + 1 == calls.size() ? "" : ",");
        }
    }

    private void writeFunction(PrintWriter out, Function function, DecompInterface decompiler,
                               int maxInstructions, int maxDecompileChars, int timeout) {
        String c = decompile(decompiler, function, timeout);
        boolean decompileTruncated = c != null && c.length() > maxDecompileChars;
        if (decompileTruncated) c = c.substring(0, maxDecompileChars);
        out.println("    {");
        out.println("      \"entry\": " + quote(hex(function.getEntryPoint())) + ",");
        out.println("      \"name\": " + quote(function.getName()) + ",");
        out.println("      \"signature\": " + quote(function.getSignature().getPrototypeString()) + ",");
        out.println("      \"body_min\": " + quote(hex(function.getBody().getMinAddress())) + ",");
        out.println("      \"body_max\": " + quote(hex(function.getBody().getMaxAddress())) + ",");
        out.println("      \"decompile_ok\": " + (c != null) + ",");
        out.println("      \"decompile_truncated\": " + decompileTruncated + ",");
        out.println("      \"decompiled_c\": " + quote(c) + ",");
        out.println("      \"calls\": [");
        writeCalls(out, function);
        out.println("      ],");
        out.println("      \"xrefs_to\": [");
        List<String> xrefs = new ArrayList<>();
        ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (references.hasNext()) xrefs.add(hex(references.next().getFromAddress()));
        Collections.sort(xrefs);
        for (int index = 0; index < xrefs.size(); ++index) {
            out.print("        " + quote(xrefs.get(index)));
            out.println(index + 1 == xrefs.size() ? "" : ",");
        }
        out.println("      ],");
        out.println("      \"instructions\": [");
        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        int count = 0;
        while (instructions.hasNext() && count < maxInstructions && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            if (count != 0) out.println(",");
            out.print("        {\"address\":" + quote(hex(instruction.getAddress())) +
                ",\"bytes\":" + quote(bytes(instruction)) +
                ",\"mnemonic\":" + quote(instruction.getMnemonicString()) +
                ",\"text\":" + quote(instruction.toString()) + "}");
            ++count;
        }
        out.println();
        out.println("      ],");
        out.println("      \"instructions_truncated\": " + instructions.hasNext());
        out.print("    }");
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) throw new IllegalArgumentException(
            "usage: IndagoExport.java <output> [max-functions] [max-instructions] " +
            "[max-decompile-chars] [timeout-seconds]");
        File destination = new File(args[0]);
        int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 2048;
        int maxInstructions = args.length > 2 ? Integer.parseInt(args[2]) : 4096;
        int maxDecompileChars = args.length > 3 ? Integer.parseInt(args[3]) : 131072;
        int timeout = args.length > 4 ? Integer.parseInt(args[4]) : 30;
        if (destination.getParentFile() != null) destination.getParentFile().mkdirs();

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);
        List<Function> functions = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && functions.size() < maxFunctions && !monitor.isCancelled()) {
            Function function = iterator.next();
            if (!function.isExternal()) functions.add(function);
        }
        functions.sort(Comparator.comparingLong(item -> item.getEntryPoint().getOffset()));

        try (PrintWriter out = new PrintWriter(destination, "UTF-8")) {
            out.println("{");
            out.println("  \"schema\": \"indago.ghidra-export.v1\",");
            out.println("  \"program\": {");
            out.println("    \"format\": " + quote(currentProgram.getExecutableFormat()) + ",");
            out.println("    \"language\": " + quote(currentProgram.getLanguageID().toString()) + ",");
            out.println("    \"compiler\": " + quote(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + ",");
            out.println("    \"image_base\": " + quote(hex(currentProgram.getImageBase())) + ",");
            out.println("    \"executable_sha256\": " + quote(currentProgram.getExecutableSHA256()) + ",");
            out.println("    \"function_count\": " + functions.size());
            out.println("  },");
            out.println("  \"functions\": [");
            for (int index = 0; index < functions.size(); ++index) {
                writeFunction(out, functions.get(index), decompiler, maxInstructions, maxDecompileChars, timeout);
                out.println(index + 1 == functions.size() ? "" : ",");
            }
            out.println("  ],");
            out.println("  \"strings\": [");
            List<Data> strings = new ArrayList<>();
            DataIterator data = currentProgram.getListing().getDefinedData(true);
            while (data.hasNext()) {
                Data item = data.next();
                if (item.getValue() instanceof String) strings.add(item);
            }
            strings.sort(Comparator.comparingLong(item -> item.getAddress().getOffset()));
            for (int index = 0; index < strings.size(); ++index) {
                Data item = strings.get(index);
                out.print("    {\"address\":" + quote(hex(item.getAddress())) +
                    ",\"value\":" + quote(String.valueOf(item.getValue())) + "}");
                out.println(index + 1 == strings.size() ? "" : ",");
            }
            out.println("  ]");
            out.println("}");
        } finally {
            decompiler.dispose();
        }
    }
}
