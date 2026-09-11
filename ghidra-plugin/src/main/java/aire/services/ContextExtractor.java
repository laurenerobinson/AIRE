package aire.services;

import aire.model.SymbolContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Extracts a consistent evidence packet from Ghidra to feed the LLM.
 */
public class ContextExtractor {

    private static final int MAX_DECOMPILE_MS = 3000;
    private static final int MAX_DECOMP_CHARS = 12000;
    private static final int MAX_ASM_LINES = 40;
    private static final int MAX_STRINGS = 24;
    private static final int MAX_CALLEES = 25;
    private static final int MAX_CALLERS = 3;
    private static final int MAX_SYMBOLS = 20;

    public SymbolContext extract(Program program, Function function, TaskMonitor monitor) {
        SymbolContext ctx = new SymbolContext();

        ctx.functionName = function.getName();
        ctx.entryPoint = function.getEntryPoint().toString();
        ctx.signature = function.getPrototypeString(false, false);

        AddressSetView body = function.getBody();
        Listing listing = program.getListing();

        ctx.decompiledCode = safeDecompile(program, function, monitor);
        ctx.assemblySnippet = buildAsmSnippet(listing, body, monitor);
        fillInstructionAndBranchCounts(listing, body, ctx, monitor);
        ctx.basicBlockCount = countBasicBlocks(program, body, monitor);
        // 1C: branch ratio — high value signals parser / validator / dispatcher
        ctx.branchRatio = ctx.basicBlockCount > 0
                ? (double) ctx.branchCount / ctx.basicBlockCount
                : 0.0;
        extractReferencedArtifacts(program, listing, body, ctx, monitor);
        extractCallees(function, ctx, monitor);
        extractCallers(function, ctx, monitor);
        applyHeuristics(ctx);

        Msg.info(this, "[AIRE] Extracted context for " + ctx.functionName + ": " + ctx.shortSummary());
        return ctx;
    }

    private String safeDecompile(Program program, Function function, TaskMonitor monitor) {
        DecompInterface decomp = new DecompInterface();
        try {
            DecompileOptions options = new DecompileOptions();
            decomp.setOptions(options);
            decomp.toggleCCode(true);
            decomp.toggleSyntaxTree(false);

            if (!decomp.openProgram(program)) {
                return "";
            }

            DecompileResults results = decomp.decompileFunction(function, MAX_DECOMPILE_MS, monitor);
            if (results == null || !results.decompileCompleted()) {
                return "";
            }

            String c = results.getDecompiledFunction().getC();
            if (c == null) {
                return "";
            }
            c = c.trim();
            if (c.length() > MAX_DECOMP_CHARS) {
                // Hard cap: store at most MAX_DECOMP_CHARS characters.
                c = c.substring(0, MAX_DECOMP_CHARS) + "\n/* ... truncated ... */";
            }
            return c;
            // Note: prompt-time smart trimming (first-2/3 + last-1/3) is applied in
            // OllamaSuggestionProvider.smartTrimPromptDecompile() before the text enters
            // the prompt, keeping the function signature and return path in view.
        } catch (Exception e) {
            Msg.debug(this, "[AIRE] Decompile failed for " + function.getName() + ": " + e.getMessage());
            return "";
        } finally {
            decomp.dispose();
        }
    }

    private String buildAsmSnippet(Listing listing, AddressSetView body, TaskMonitor monitor) {
        StringBuilder sb = new StringBuilder();
        int lines = 0;

        try {
            for (Instruction ins : listing.getInstructions(body, true)) {
                monitor.checkCancelled();
                sb.append(ins.getAddress())
                        .append(": ")
                        .append(ins)
                        .append("\n");
                lines++;
                if (lines >= MAX_ASM_LINES) {
                    break;
                }
            }
        } catch (CancelledException e) {
            Msg.debug(this, "[AIRE] Assembly snippet generation cancelled");
        }

        return sb.toString().trim();
    }

    private void fillInstructionAndBranchCounts(Listing listing, AddressSetView body, SymbolContext ctx, TaskMonitor monitor) {
        int insnCount = 0;
        int branchCount = 0;
        int retCount = 0;
        int loopHints = 0;
        int callCount = 0;
        int compareHints = 0;

        try {
            for (Instruction ins : listing.getInstructions(body, true)) {
                monitor.checkCancelled();
                insnCount++;

                FlowType ft = ins.getFlowType();
                if (ft != null) {
                    if (ft.isCall()) {
                        callCount++;
                    }
                    if (ft.isJump() || ft.isConditional() || ft.isTerminal()) {
                        if (ft.isTerminal()) {
                            retCount++;
                        } else {
                            branchCount++;
                        }
                    }
                }

                String mnemonic = ins.getMnemonicString().toLowerCase();
                if (mnemonic.startsWith("cmp") || mnemonic.startsWith("test")) {
                    compareHints++;
                }
                for (Reference ref : ins.getReferencesFrom()) {
                    Address to = ref.getToAddress();
                    if (to != null && to.compareTo(ins.getAddress()) < 0 && ref.getReferenceType().isJump()) {
                        loopHints++;
                        break;
                    }
                }
            }
        } catch (CancelledException e) {
            Msg.debug(this, "[AIRE] Count extraction cancelled");
        }

        ctx.instructionCount = insnCount;
        ctx.branchCount = branchCount;
        ctx.returnCount = retCount;
        ctx.loopCount = loopHints;
        ctx.tags.put("call_count", Integer.toString(callCount));
        ctx.tags.put("compare_hint_count", Integer.toString(compareHints));
    }

    private int countBasicBlocks(Program program, AddressSetView body, TaskMonitor monitor) {
        try {
            BasicBlockModel bbm = new BasicBlockModel(program);
            CodeBlockIterator it = bbm.getCodeBlocksContaining(body, monitor);
            int count = 0;
            while (it.hasNext()) {
                monitor.checkCancelled();
                it.next();
                count++;
            }
            return count;
        } catch (CancelledException e) {
            return 0;
        } catch (Exception e) {
            Msg.debug(this, "[AIRE] Basic block count failed: " + e.getMessage());
            return 0;
        }
    }

    private void extractReferencedArtifacts(Program program, Listing listing, AddressSetView body, SymbolContext ctx,
                                            TaskMonitor monitor) {
        ReferenceManager refs = program.getReferenceManager();
        Memory memory = program.getMemory();
        Set<String> strings = new LinkedHashSet<>();
        Set<String> imports = new LinkedHashSet<>();

        try {
            for (Instruction ins : listing.getInstructions(body, true)) {
                monitor.checkCancelled();

                for (Reference ref : ins.getReferencesFrom()) {
                    Address to = ref.getToAddress();
                    if (to == null) {
                        continue;
                    }

                    addStringCandidate(listing.getDefinedDataAt(to), strings);
                    addStringCandidate(listing.getDataAt(to), strings);
                    if (memory.contains(to)) {
                        addStringCandidate(readStringData(listing, to), strings);
                    }

                    Function targetFn = listing.getFunctionContaining(to);
                    if (targetFn != null && !targetFn.equals(listing.getFunctionContaining(ins.getAddress()))) {
                        String fnName = targetFn.getName();
                        if (!isGenericLabel(fnName)) {
                            addUnique(ctx.referencedSymbols, fnName, MAX_SYMBOLS);
                        }
                        classifySymbol(fnName, imports);
                    }

                    String label = program.getSymbolTable().getPrimarySymbol(to) == null
                            ? null
                            : program.getSymbolTable().getPrimarySymbol(to).getName();
                    if (label != null && !isGenericLabel(label)) {
                        addUnique(ctx.referencedSymbols, label, MAX_SYMBOLS);
                        classifySymbol(label, imports);
                    }

                    for (Reference incoming : refs.getReferencesTo(to)) {
                        monitor.checkCancelled();
                        Address from = incoming.getFromAddress();
                        if (from == null) {
                            continue;
                        }
                        addStringCandidate(listing.getDefinedDataAt(from), strings);
                    }
                }

                Object[] objs = ins.getOpObjects(0);
                for (Object obj : objs) {
                    if (obj instanceof Scalar) {
                        long value = ((Scalar) obj).getUnsignedValue();
                        if (value > 0 && value < Long.MAX_VALUE) {
                            Address addr = toAddress(program, value);
                            if (addr != null) {
                                addStringCandidate(listing.getDefinedDataAt(addr), strings);
                            }
                        }
                    }
                }
            }
        } catch (CancelledException e) {
            Msg.debug(this, "[AIRE] Referenced artifact extraction cancelled");
        } catch (Exception e) {
            Msg.debug(this, "[AIRE] Referenced artifact extraction failed: " + e.getMessage());
        }

        try {
            for (Data d : listing.getDefinedData(body, true)) {
                monitor.checkCancelled();
                addStringCandidate(d, strings);
            }
        } catch (CancelledException e) {
            Msg.debug(this, "[AIRE] Local data scan cancelled");
        }

        for (String s : strings) {
            addUnique(ctx.referencedStrings, s, MAX_STRINGS);
        }
        for (String s : imports) {
            addUnique(ctx.referencedImports, s, MAX_SYMBOLS);
        }
    }

    private void extractCallees(Function function, SymbolContext ctx, TaskMonitor monitor) {
        try {
            Set<String> seen = new LinkedHashSet<>();
            int namedCalleeCount = 0;
            for (Function callee : function.getCalledFunctions(monitor)) {
                monitor.checkCancelled();
                if (callee == null) {
                    continue;
                }
                String name = callee.getName();
                if (name == null || name.isBlank()) {
                    continue;
                }
                // Skip generic auto-generated names — they dilute the signal.
                if (isGenericLabel(name)) {
                    continue;
                }
                if (seen.add(name)) {
                    addUnique(ctx.callees, name, MAX_CALLEES);
                    classifySymbol(name, importsForContext(ctx));
                    namedCalleeCount++;
                }
            }
            ctx.tags.put("named_callee_count", Integer.toString(namedCalleeCount));
        } catch (Exception e) {
            Msg.debug(this, "[AIRE] Callee extraction failed: " + e.getMessage());
        }
    }

    /**
     * Returns true for names that are auto-generated placeholders rather than meaningful symbols.
     * These should be excluded from the callees list to avoid polluting the LLM context.
     */
    private boolean isGenericLabel(String name) {
        if (name == null) {
            return true;
        }
        String n = name.toLowerCase();
        if (n.startsWith("sub_") || n.startsWith("fun_") || n.startsWith("unk_") || n.startsWith("loc_")) {
            return true;
        }
        // Pure hex address-like strings (e.g. "401234")
        if (n.matches("[0-9a-f]{4,}")) {
            return true;
        }
        return false;
    }

    private void extractCallers(Function function, SymbolContext ctx, TaskMonitor monitor) {
        try {
            Set<String> seen = new LinkedHashSet<>();
            for (Function caller : function.getCallingFunctions(monitor)) {
                monitor.checkCancelled();
                if (caller == null) {
                    continue;
                }
                String name = caller.getName();
                if (name == null || name.isBlank()) {
                    continue;
                }
                if (seen.add(name)) {
                    addUnique(ctx.callers, name, MAX_CALLERS);
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "[AIRE] Caller extraction failed: " + e.getMessage());
        }
    }

    private void applyHeuristics(SymbolContext ctx) {
        String decomp = lower(ctx.decompiledCode);
        String asm = lower(ctx.assemblySnippet);
        String callees = lower(String.join(" ", ctx.callees));
        String callers = lower(String.join(" ", ctx.callers));
        String strings = lower(String.join(" ", ctx.referencedStrings));
        String symbols = lower(String.join(" ", ctx.referencedSymbols));

        String all = decomp + "\n" + asm + "\n" + callees + "\n" + callers + "\n" + strings + "\n" + symbols;

        ctx.usesMemcpyLike = containsAny(all, "memcpy", "memmove", "bcopy");
        ctx.usesStrcmpLike = containsAny(all, "strcmp", "strncmp", "strcasecmp", "strncasecmp");
        ctx.usesMallocFreeLike = containsAny(all, "malloc", "calloc", "realloc", "free", "new ", " delete");

        ctx.usesFileIOLike = containsAny(all, "fopen", "fread", "fwrite", "fclose", "open(", "read(", "write(", "lseek", "stat");
        ctx.usesNetworkIOLike = containsAny(all, "socket", "connect", "accept", "bind", "listen", "recv", "send", "getsockopt", "setsockopt");
        ctx.usesCryptoLike = containsAny(all, "aes", "sha", "md5", "hmac", "rsa", "ecdh", "chacha", "poly1305", "crypt", "bcrypt");

        addImportIf(ctx, ctx.usesMemcpyLike, "memory_copy");
        addImportIf(ctx, ctx.usesStrcmpLike, "string_compare");
        addImportIf(ctx, ctx.usesMallocFreeLike, "allocation");
        addImportIf(ctx, ctx.usesFileIOLike, "file_io");
        addImportIf(ctx, ctx.usesNetworkIOLike, "network_io");
        addImportIf(ctx, ctx.usesCryptoLike, "crypto");
        addImportIf(ctx, containsAny(all, "json", "xml", "yaml", "protobuf"), "serialization");
        addImportIf(ctx, containsAny(all, "printf", "sprintf", "snprintf", "puts"), "format_output");
        addImportIf(ctx, containsAny(all, "scanf", "sscanf", "strtol", "atoi", "parse"), "parsing");
        addImportIf(ctx, containsAny(all, "mutex", "lock", "unlock", "criticalsection", "pthread"), "synchronization");

        if (ctx.loopCount > 0) {
            addImportIf(ctx, true, "looping");
        }
        int compareHints = parseTagInt(ctx, "compare_hint_count");
        if (compareHints >= 2) {
            addImportIf(ctx, true, "comparison_heavy");
        }
        int callCount = parseTagInt(ctx, "call_count");
        if (callCount >= 5) {
            addImportIf(ctx, true, "dispatcher_or_coordinator");
        }
    }

    private void addStringCandidate(Data data, Set<String> strings) {
        if (data == null || strings.size() >= MAX_STRINGS) {
            return;
        }

        Object value = null;
        try {
            value = data.getValue();
        } catch (Exception ignored) {
        }

        String s = null;
        if (value instanceof String) {
            s = (String) value;
        } else {
            String rep = data.getDefaultValueRepresentation();
            if (rep != null && looksLikeString(rep)) {
                s = rep;
            }
        }

        if (s != null) {
            strings.add(sanitizeString(s));
        }
    }

    private Data readStringData(Listing listing, Address address) {
        try {
            return listing.getDefinedDataContaining(address);
        } catch (Exception ignored) {
            return null;
        }
    }

    private Address toAddress(Program program, long value) {
        try {
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    private void classifySymbol(String symbol, Set<String> imports) {
        if (symbol == null) {
            return;
        }
        String s = symbol.toLowerCase();
        if (s.startsWith("fun_") || s.startsWith("sub_")) {
            return;
        }
        if (containsAny(s, "printf", "puts", "fprintf")) {
            imports.add("format_output");
        }
        if (containsAny(s, "str", "mem", "snprintf")) {
            imports.add("string_memory");
        }
        if (containsAny(s, "json", "xml", "yaml", "parse")) {
            imports.add("parsing");
        }
        if (containsAny(s, "socket", "recv", "send", "http", "ssl", "tls")) {
            imports.add("network_io");
        }
        if (containsAny(s, "open", "read", "write", "fopen", "fread", "fwrite", "close")) {
            imports.add("file_io");
        }
        if (containsAny(s, "aes", "sha", "hmac", "crypto", "rsa", "encrypt", "decrypt")) {
            imports.add("crypto");
        }
    }

    private Set<String> importsForContext(SymbolContext ctx) {
        return new LinkedHashSet<>(ctx.referencedImports) {
            @Override
            public boolean add(String s) {
                addUnique(ctx.referencedImports, s, MAX_SYMBOLS);
                return super.add(s);
            }
        };
    }

    private void addImportIf(SymbolContext ctx, boolean cond, String label) {
        if (cond) {
            addUnique(ctx.referencedImports, label, MAX_SYMBOLS);
        }
    }

    private void addUnique(java.util.List<String> dest, String value, int max) {
        if (value == null || value.isBlank() || dest.contains(value) || dest.size() >= max) {
            return;
        }
        dest.add(value);
    }

    private boolean looksLikeString(String rep) {
        if (rep == null || rep.length() < 3) {
            return false;
        }
        int printable = 0;
        for (int i = 0; i < rep.length(); i++) {
            char c = rep.charAt(i);
            if (c >= 32 && c <= 126) {
                printable++;
            }
        }
        double ratio = (double) printable / (double) rep.length();
        return ratio > 0.85;
    }

    private String sanitizeString(String s) {
        if (s == null) {
            return "";
        }
        s = s.replace("\n", " ").replace("\r", " ").trim();
        if ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'"))) {
            s = s.substring(1, s.length() - 1).trim();
        }
        if (s.length() > 160) {
            s = s.substring(0, 160) + "...";
        }
        return s;
    }

    private boolean containsAny(String haystack, String... needles) {
        for (String n : needles) {
            if (haystack.contains(n)) {
                return true;
            }
        }
        return false;
    }

    private String lower(String s) {
        return s == null ? "" : s.toLowerCase();
    }

    private int parseTagInt(SymbolContext ctx, String key) {
        try {
            return Integer.parseInt(ctx.tags.getOrDefault(key, "0"));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }
}
