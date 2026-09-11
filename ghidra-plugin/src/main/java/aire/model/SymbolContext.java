package aire.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Evidence packet passed to the LLM.
 * The richer (and more consistent) this context is, the better the naming accuracy and confidence calibration.
 */
public class SymbolContext {

    // ===== Identity =====
    public String functionName;
    public String entryPoint;
    public String signature;

    // ===== Decompiled / Disassembly Evidence =====
    public String decompiledCode;   // C-like decompiler output
    public String assemblySnippet;  // small assembly sample

    // ===== Call Graph Evidence =====
    public List<String> callees;    // functions called by this function
    public List<String> callers;    // optional: functions that call this one

    // ===== Data / String Evidence =====
    public List<String> referencedStrings;
    public List<String> referencedSymbols;
    public List<String> referencedImports; // inferred APIs/behaviors (memcpy, file_io, network_io, crypto, ...)

    // ===== Structural Evidence =====
    public int    basicBlockCount;
    public int    instructionCount;
    public int    loopCount;
    public int    branchCount;
    public int    returnCount;
    /** branchCount / basicBlockCount — high values suggest parsers/validators/dispatchers. */
    public double branchRatio;

    // ===== Heuristic Flags =====
    public boolean usesMemcpyLike;
    public boolean usesStrcmpLike;
    public boolean usesMallocFreeLike;
    public boolean usesFileIOLike;
    public boolean usesNetworkIOLike;
    public boolean usesCryptoLike;

    // ===== Extra metadata =====
    public Map<String, String> tags;
    public List<String> warnings;

    public SymbolContext() {
        this.decompiledCode = "";
        this.assemblySnippet = "";

        this.callees = new ArrayList<>();
        this.callers = new ArrayList<>();
        this.referencedStrings = new ArrayList<>();
        this.referencedSymbols = new ArrayList<>();
        this.referencedImports = new ArrayList<>();

        this.tags = new HashMap<>();
        this.warnings = new ArrayList<>();
    }

    public String shortSummary() {
        return "SymbolContext{" +
                "functionName='" + functionName + '\'' +
                ", entryPoint='" + entryPoint + '\'' +
                ", blocks=" + basicBlockCount +
                String.format(", branchRatio=%.2f", branchRatio) +
                ", insns=" + instructionCount +
                ", callees=" + (callees == null ? 0 : callees.size()) +
                ", strings=" + (referencedStrings == null ? 0 : referencedStrings.size()) +
                ", callers=" + (callers == null ? 0 : callers.size()) +
                '}';
    }
}
