package aire.services;

import aire.model.NameSuggestion;
import aire.model.SymbolContext;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.util.Msg;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ollama-backed suggestion provider.
 *
 * Uses a free-text CANDIDATE: response format rather than JSON schema enforcement.
 * Confidence is computed multiplicatively from the model's self-reported score and
 * objective evidence-quality signals derived from the extracted SymbolContext.
 *
 * Response flow:
 *   1. Primary call  →  parse CANDIDATE: lines  →  post-process
 *   2. If malformed  →  one retry with format reminder
 *   3. If retry also malformed  →  empty result with user-visible message
 *   INSUFFICIENT_EVIDENCE marker  →  empty result with manual-review message (no retry)
 */
public class OllamaSuggestionProvider implements SuggestionProvider {

    // ── Pattern for valid stored names ──────────────────────────────────────────
    private static final Pattern VALID_NAME = Pattern.compile("[a-z][a-z0-9_]{2,59}");

    // ── CANDIDATE: <name> | CONFIDENCE: <float> | REASON: <text> ───────────────
    private static final Pattern CANDIDATE_LINE = Pattern.compile(
            "CANDIDATE:\\s*([A-Za-z][A-Za-z0-9_]*)\\s*\\|\\s*CONFIDENCE:\\s*(\\d*\\.?\\d+)\\s*\\|\\s*REASON:\\s*(.+)",
            Pattern.CASE_INSENSITIVE);

    private static final String INSUFFICIENT_EVIDENCE_MARKER = "INSUFFICIENT_EVIDENCE";

    // ── Tuning constants ────────────────────────────────────────────────────────
    /** Minimum finalConfidence for a candidate to be accepted into results. */
    private static final double ACCEPTANCE_THRESHOLD    = 0.55;
    /** Characters of decompile passed to the prompt (smart-trimmed). */
    private static final int    MAX_DECOMP_CHARS_PROMPT = 3200;
    /** Characters of assembly passed to the prompt. */
    private static final int    MAX_ASM_CHARS_PROMPT    = 320;
    /** Items from each list passed to the prompt. */
    private static final int    MAX_LIST_ITEMS          = 8;

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(240);

    // ── Instance state ───────────────────────────────────────────────────────────
    private final String     baseUrl;
    private final String     model;
    private final HttpClient client;

    private boolean lastResultRecovered  = false;
    private String  lastResultMessage    = "";

    // Statistics logged per session for diagnostics
    private int requestCount             = 0;
    private int parsedSuccessCount       = 0;
    private int retrySuccessCount        = 0;
    private int insufficientEvidenceCount = 0;
    private int fallbackCount            = 0;
    private int malformedCount           = 0;

    // ── Inner: confidence breakdown ──────────────────────────────────────────────
    /**
     * Holds the three components of a candidate's confidence score and a human-readable
     * breakdown string that is stored in NameSuggestion.evidence for debuggability.
     */
    private static final class ConfidenceScore {
        final double modelScore;
        final double evidenceMultiplier;
        final double finalConfidence;

        ConfidenceScore(double rawModelScore, double rawMultiplier) {
            this.modelScore         = clamp(rawModelScore);
            this.evidenceMultiplier = Math.max(0.5, Math.min(1.5, rawMultiplier));
            this.finalConfidence    = clamp(this.modelScore * this.evidenceMultiplier);
        }

        /** One-liner included as an evidence bullet so it is visible in the UI panel. */
        String breakdown() {
            return String.format(Locale.ROOT,
                    "confidence: model=%.2f × mult=%.2f = %.2f",
                    modelScore, evidenceMultiplier, finalConfidence);
        }

        private static double clamp(double v) { return Math.max(0.0, Math.min(1.0, v)); }
    }

    // ── Constructor ──────────────────────────────────────────────────────────────

    public OllamaSuggestionProvider(String baseUrl, String model) {
        this.baseUrl = baseUrl;
        this.model   = model;
        this.client  = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .build();
    }

    // ── SuggestionProvider interface ─────────────────────────────────────────────

    @Override
    public List<NameSuggestion> suggest(SymbolContext ctx) throws Exception {
        requestCount++;
        lastResultRecovered = false;
        lastResultMessage   = "";

        // ── Primary attempt ──────────────────────────────────────────────────────
        String responseText = callModel(ctx, false);

        if (responseText.contains(INSUFFICIENT_EVIDENCE_MARKER)) {
            return handleInsufficientEvidence(ctx.functionName);
        }

        List<NameSuggestion> primary = parseResponse(responseText, ctx);
        List<NameSuggestion> result  = postProcess(primary, ctx);
        if (!result.isEmpty()) {
            parsedSuccessCount++;
            logStats("parsed_success");
            return result;
        }

        // ── One retry with format reminder (Phase 5: at most one retry) ──────────
        malformedCount++;
        Msg.warn(this, "[AIRE] No valid candidates from primary pass for '" + ctx.functionName
                + "'. Retrying with format reminder.");
        Msg.debug(this, "[AIRE] Primary raw output:\n" + truncateForLog(responseText));

        String retryText = callModel(ctx, true);

        if (retryText.contains(INSUFFICIENT_EVIDENCE_MARKER)) {
            return handleInsufficientEvidence(ctx.functionName);
        }

        List<NameSuggestion> retryParsed = parseResponse(retryText, ctx);
        List<NameSuggestion> retryResult = postProcess(retryParsed, ctx);
        if (!retryResult.isEmpty()) {
            retrySuccessCount++;
            lastResultMessage = "Suggestion recovered after malformed initial response.";
            logStats("retry_success");
            return retryResult;
        }

        // ── Both attempts failed — do NOT fabricate names (Phase 5) ─────────────
        fallbackCount++;
        lastResultRecovered = true;
        lastResultMessage   = "Could not parse suggestions from model output. "
                + "Consider using a model with better instruction-following "
                + "(e.g., gemma3:12b, mistral:7b, or qwen2.5:7b).";
        Msg.warn(this, "[AIRE] Fallback triggered for '" + ctx.functionName
                + "' — both attempts produced no parseable candidates.");
        Msg.debug(this, "[AIRE] Retry raw output:\n" + truncateForLog(retryText));
        logStats("fallback_no_candidates");
        maybeLogModelRecommendation();
        return Collections.emptyList();
    }

    /** Called when the model explicitly signals there is not enough evidence to name the function. */
    private List<NameSuggestion> handleInsufficientEvidence(String functionName) {
        insufficientEvidenceCount++;
        lastResultRecovered = true;
        lastResultMessage   = "Insufficient evidence for a confident suggestion. "
                + "Consider reviewing callee imports or string references manually.";
        Msg.info(this, "[AIRE] INSUFFICIENT_EVIDENCE returned for '" + functionName + "'.");
        logStats("insufficient_evidence");
        return Collections.emptyList();
    }

    @Override
    public String getStatus() {
        return baseUrl + " | model=" + model;
    }

    @Override
    public boolean wasLastResultRecovered() {
        return lastResultRecovered;
    }

    @Override
    public String getLastResultMessage() {
        return lastResultMessage == null ? "" : lastResultMessage;
    }

    // ── Model call (Phase 6: prompt length and key fields logged) ────────────────

    private String callModel(SymbolContext ctx, boolean isRetry) throws Exception {
        String prompt = buildPrompt(ctx, isRetry);

        JsonObject req = new JsonObject();
        req.addProperty("model",  model);
        req.addProperty("prompt", prompt);
        req.addProperty("stream", false);

        JsonObject options = new JsonObject();
        // Higher temperature for rich-evidence functions so names are more specific;
        // very low on retry to maximise format adherence.
        double temperature = isRetry ? 0.05
                : (evidenceStrength(ctx) >= 4 ? 0.30 : 0.20);
        options.addProperty("temperature",    temperature);
        options.addProperty("top_p",          isRetry ? 0.70 : 0.90);
        options.addProperty("repeat_penalty", 1.15);
        options.addProperty("num_predict",    isRetry ? 200 : 420);
        req.add("options", options);
        // No "format" key — free-text CANDIDATE: line protocol

        HttpRequest httpReq = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/generate"))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(req.toString()))
                .build();

        Msg.info(this, "[AIRE] Calling Ollama model=" + model
                + " isRetry=" + isRetry
                + " evidenceStrength=" + evidenceStrength(ctx)
                + " temperature=" + String.format(Locale.ROOT, "%.2f", temperature)
                + " promptLen=" + prompt.length());

        HttpResponse<String> resp;
        try {
            resp = client.send(httpReq, HttpResponse.BodyHandlers.ofString());
        } catch (HttpConnectTimeoutException e) {
            throw new IOException("Connection failure: timed out connecting to Ollama at " + baseUrl, e);
        } catch (HttpTimeoutException e) {
            throw new IOException("Generation timeout: Ollama did not finish within "
                    + REQUEST_TIMEOUT.toSeconds() + "s for model " + model, e);
        } catch (IOException e) {
            String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase(Locale.ROOT);
            if (msg.contains("connection refused") || msg.contains("failed to connect")) {
                throw new IOException("Connection failure: Ollama is not reachable at " + baseUrl, e);
            }
            throw e;
        }

        if (resp.statusCode() != 200) {
            String body      = resp.body() == null ? "" : resp.body();
            String bodyLower = body.toLowerCase(Locale.ROOT);
            if (bodyLower.contains("model") && bodyLower.contains("not found")) {
                throw new IOException("Model missing: " + model
                        + " is not available in Ollama. " + body);
            }
            throw new IOException("Backend error: Ollama HTTP " + resp.statusCode() + ": " + body);
        }

        String responseText = extractResponseText(resp.body());
        Msg.info(this,  "[AIRE] Raw response length=" + responseText.length());
        Msg.debug(this, "[AIRE] Raw model output:\n" + truncateForLog(responseText));
        return responseText;
    }

    // ── Prompt construction (Phase 2) ────────────────────────────────────────────

    private String buildPrompt(SymbolContext ctx, boolean isRetry) {
        // Apply smart trim: keep first 2/3 + last 1/3 of the target length
        // so both the function signature and the return path are visible.
        String decomp  = smartTrimPromptDecompile(safe(ctx.decompiledCode));
        String asm     = truncate(safe(ctx.assemblySnippet), MAX_ASM_CHARS_PROMPT);
        String callees = joinLimited(ctx.callees,            MAX_LIST_ITEMS);
        String callers = joinLimited(ctx.callers,            MAX_LIST_ITEMS);
        String strings = joinLimited(ctx.referencedStrings,  MAX_LIST_ITEMS);

        StringBuilder sb = new StringBuilder();

        sb.append("You are a binary reverse engineering assistant. Your job is to suggest function names\n");
        sb.append("based strictly on observable evidence from the decompiler and binary structure.\n\n");

        // ── Evidence block ────────────────────────────────────────────────────────
        sb.append("FUNCTION EVIDENCE:\n");
        sb.append("- Current name: ").append(safe(ctx.functionName)).append("\n");
        sb.append("- Signature: ").append(safe(ctx.signature)).append("\n");
        sb.append("- Basic blocks: ").append(ctx.basicBlockCount).append("\n");
        sb.append(String.format(Locale.ROOT,
                "- Branch ratio: %.2f  (high = parser/validator/dispatcher, low = wrapper/loader)\n",
                ctx.branchRatio));
        // Omit sections that are empty so the model is not misled by blank labels (Phase 2)
        if (!callees.isBlank()) {
            sb.append("- Callee imports: ").append(callees).append("\n");
        }
        if (!strings.isBlank()) {
            sb.append("- String references: ").append(strings).append("\n");
        }
        if (!callers.isBlank()) {
            sb.append("- Caller names: ").append(callers).append("\n");
        }
        sb.append("\n");

        // ── Decompiled / assembly code ────────────────────────────────────────────
        if (!decomp.isBlank()) {
            sb.append("DECOMPILED OUTPUT (truncated if long):\n```c\n")
              .append(decomp)
              .append("\n```\n\n");
        } else if (!asm.isBlank()) {
            sb.append("ASSEMBLY SNIPPET:\n```asm\n")
              .append(asm)
              .append("\n```\n\n");
        }

        // ── Instructions ──────────────────────────────────────────────────────────
        sb.append("INSTRUCTIONS:\n");
        sb.append("- Suggest 1 to 3 function names based ONLY on the evidence above.\n");
        sb.append("- Each name must be specific and behavioral. Do not use: helper, process, handle,\n");
        sb.append("  manage, doThing, subroutine, wrapper, or any similarly vague term.\n");
        sb.append("- If the evidence is insufficient to support a specific name, respond with:\n");
        sb.append("  INSUFFICIENT_EVIDENCE: <brief explanation of what is missing>\n");
        sb.append("- Otherwise format each suggestion EXACTLY as one line:\n");
        sb.append("  CANDIDATE: <snake_case_name> | CONFIDENCE: <0.0-1.0> | REASON: <one sentence citing specific evidence>\n");
        sb.append("- Return ONLY CANDIDATE lines or INSUFFICIENT_EVIDENCE. No other text.\n");

        if (isRetry) {
            sb.append("\nIMPORTANT: This is a retry. Your previous response could not be parsed.\n");
            sb.append("Follow the CANDIDATE: line format exactly — one line per suggestion, nothing else.\n");
        }

        Msg.debug(this, "[AIRE] Prompt built: length=" + sb.length()
                + " hasDecomp=" + !decomp.isBlank()
                + " calleeCount=" + ctx.callees.size()
                + " stringCount=" + ctx.referencedStrings.size()
                + " callerCount=" + ctx.callers.size());

        return sb.toString();
    }

    /**
     * Smart-trims decompile for the prompt: keeps first 2/3 and last 1/3 of the target
     * length. This preserves both the function signature (top) and the return path
     * (bottom), which carry the strongest naming signals. Logs when trimming fires.
     */
    private String smartTrimPromptDecompile(String code) {
        if (code == null || code.length() <= MAX_DECOMP_CHARS_PROMPT) {
            return code == null ? "" : code;
        }
        int firstPart = (MAX_DECOMP_CHARS_PROMPT * 2) / 3;          // ~2133 chars
        int lastPart  = MAX_DECOMP_CHARS_PROMPT - firstPart;         // ~1067 chars
        int trimmed   = code.length() - MAX_DECOMP_CHARS_PROMPT;
        Msg.info(this, "[AIRE] Decompile smart-trimmed: original=" + code.length()
                + " kept=" + MAX_DECOMP_CHARS_PROMPT
                + " dropped=" + trimmed + " chars");
        return code.substring(0, firstPart)
                + "\n/* ... [" + trimmed + " chars trimmed] ... */\n"
                + code.substring(code.length() - lastPart);
    }

    // ── Response parsing (Phase 4D: INSUFFICIENT_EVIDENCE checked first in suggest()) ─

    /**
     * Parses CANDIDATE: lines from the raw model output.
     * Applies the multiplicative confidence model immediately so each returned
     * NameSuggestion already carries its finalConfidence.
     */
    private List<NameSuggestion> parseResponse(String responseText, SymbolContext ctx) {
        List<NameSuggestion> out = new ArrayList<>();
        if (responseText == null || responseText.isBlank()) {
            return out;
        }

        double evidenceMult = computeEvidenceMultiplier(ctx);

        for (String line : responseText.split("\n")) {
            Matcher m = CANDIDATE_LINE.matcher(line.trim());
            if (!m.find()) {
                continue;
            }

            String rawName    = m.group(1).trim();
            double modelScore = parseDouble(m.group(2).trim(), 0.5);
            String reason     = cleanSentence(m.group(3).trim());

            String name = normalizeName(rawName);
            if (name.isBlank()) {
                continue;
            }

            ConfidenceScore score = new ConfidenceScore(modelScore, evidenceMult);

            NameSuggestion ns = new NameSuggestion();
            ns.name       = name;
            ns.confidence = score.finalConfidence;
            ns.reason     = reason;

            // Phase 6: breakdown stored in evidence so it is visible in the detail panel
            ns.evidence.add(score.breakdown());
            if (!ctx.callees.isEmpty()) {
                ns.evidence.add("calls: " + joinLimited(ctx.callees, 3));
            } else if (!ctx.referencedStrings.isEmpty()) {
                ns.evidence.add("strings: " + joinLimited(ctx.referencedStrings, 2));
            }

            Msg.debug(this, "[AIRE] Parsed: name=" + name + " " + score.breakdown()
                    + " reason=" + shorten(reason, 80));
            out.add(ns);
        }

        return out;
    }

    // ── Confidence scoring (Phase 3) ─────────────────────────────────────────────

    /**
     * Computes the evidence multiplier. Each signal contributes multiplicatively.
     * Result is clamped to [0.5, 1.5].
     *
     * Phase 3 specification:
     *   callees non-empty:         × 1.25
     *   strings non-empty:         × 1.20
     *   callers non-empty:         × 1.10
     *   basicBlockCount > 1:       × 1.05
     *   current name is FUN_/sub_: × 0.90  (no prior human signal)
     *   decompile under 100 chars: × 0.75  (thin evidence)
     */
    private double computeEvidenceMultiplier(SymbolContext ctx) {
        double m = 1.0;

        if (ctx.callees != null && !ctx.callees.isEmpty())           m *= 1.25;
        if (ctx.referencedStrings != null && !ctx.referencedStrings.isEmpty()) m *= 1.20;
        if (ctx.callers != null && !ctx.callers.isEmpty())           m *= 1.10;
        if (ctx.basicBlockCount > 1)                                  m *= 1.05;

        String fnName = ctx.functionName == null ? "" : ctx.functionName;
        if (fnName.toUpperCase(Locale.ROOT).startsWith("FUN_")
                || fnName.startsWith("sub_")
                || fnName.startsWith("fun_")) {
            m *= 0.90;
        }

        if (ctx.decompiledCode == null || ctx.decompiledCode.length() < 100) {
            m *= 0.75;
        }

        double result = Math.max(0.5, Math.min(1.5, m));
        Msg.debug(this, "[AIRE] evidenceMultiplier=" + String.format(Locale.ROOT, "%.3f", result)
                + " [callees=" + (ctx.callees == null ? 0 : ctx.callees.size())
                + " strings=" + (ctx.referencedStrings == null ? 0 : ctx.referencedStrings.size())
                + " callers=" + (ctx.callers == null ? 0 : ctx.callers.size())
                + " blocks=" + ctx.basicBlockCount
                + " decompLen=" + (ctx.decompiledCode == null ? 0 : ctx.decompiledCode.length())
                + "]");
        return result;
    }

    // ── Post-processing (Phase 4) ────────────────────────────────────────────────

    private List<NameSuggestion> postProcess(List<NameSuggestion> raw, SymbolContext ctx) {
        if (raw == null || raw.isEmpty()) {
            return Collections.emptyList();
        }

        // ── 4A: normalise + reject bad names ────────────────────────────────────
        List<NameSuggestion> accepted = new ArrayList<>();
        for (NameSuggestion ns : raw) {
            String rejection = rejectionReason(ns);
            if (rejection != null) {
                Msg.info(this, "[AIRE] Rejected '" + ns.name + "': " + rejection);
                continue;
            }
            // Phase 3: acceptance threshold
            if (ns.confidence < ACCEPTANCE_THRESHOLD) {
                Msg.info(this, "[AIRE] Below threshold: '" + ns.name + "'"
                        + String.format(Locale.ROOT, " conf=%.2f threshold=%.2f",
                                ns.confidence, ACCEPTANCE_THRESHOLD));
                continue;
            }
            // Additional context-alignment sanity check
            if (!alignsWithContext(ns, ctx)) {
                // Penalise but do not hard-reject: lower confidence by 15%
                double adjusted = ns.confidence * 0.85;
                Msg.info(this, "[AIRE] Misaligned domain claim: '" + ns.name
                        + String.format(Locale.ROOT, "' conf %.2f -> %.2f", ns.confidence, adjusted));
                ns.confidence = adjusted;
                if (ns.confidence < ACCEPTANCE_THRESHOLD) {
                    Msg.info(this, "[AIRE] Dropped after misalignment penalty: '" + ns.name + "'");
                    continue;
                }
            }
            accepted.add(ns);
            Msg.debug(this, "[AIRE] Accepted: '" + ns.name + "'"
                    + String.format(Locale.ROOT, " conf=%.2f", ns.confidence));
        }

        // Sort by confidence before dedup so we always keep the best of any near-duplicate group
        accepted.sort(Comparator.comparingDouble((NameSuggestion s) -> s.confidence).reversed());

        // ── 4B: smarter deduplication (Levenshtein ≤ 2 OR shared root) ──────────
        List<NameSuggestion> deduped = deduplicateCandidates(accepted);

        // ── 4C: semantic diversity — if all names share the same root concept, keep 1 ─
        deduped = enforceSemanticDiversity(deduped);

        if (deduped.size() > 3) {
            deduped = new ArrayList<>(deduped.subList(0, 3));
        }

        if (!accepted.isEmpty() && deduped.isEmpty()) {
            Msg.info(this, "[AIRE] All accepted candidates eliminated by dedup/diversity for '"
                    + ctx.functionName + "'");
        }

        return deduped;
    }

    /**
     * 4B — Removes near-duplicates from a confidence-sorted list.
     * Since the input is sorted descending, the first occurrence of any duplicate group
     * is always the highest-confidence one — we simply skip later duplicates.
     */
    private List<NameSuggestion> deduplicateCandidates(List<NameSuggestion> sorted) {
        List<NameSuggestion> result = new ArrayList<>();
        outer:
        for (NameSuggestion candidate : sorted) {
            for (NameSuggestion existing : result) {
                if (isNearDuplicate(existing.name, candidate.name)) {
                    Msg.info(this, "[AIRE] Near-dup: dropping '" + candidate.name
                            + "' (kept '" + existing.name + "')");
                    continue outer;
                }
            }
            result.add(candidate);
        }
        return result;
    }

    /**
     * 4C — If every surviving candidate reduces to the same semantic root concept,
     * keep only the highest-confidence one (they are not meaningfully diverse).
     */
    private List<NameSuggestion> enforceSemanticDiversity(List<NameSuggestion> candidates) {
        if (candidates.size() < 2) {
            return candidates;
        }
        String firstKey = semanticKey(candidates.get(0).name);
        boolean allSame = candidates.stream()
                .allMatch(s -> semanticKey(s.name).equals(firstKey));
        if (allSame) {
            Msg.info(this, "[AIRE] Semantic diversity: all candidates share root '" + firstKey
                    + "'; reducing to highest-confidence.");
            return Collections.singletonList(candidates.get(0)); // already sorted desc
        }
        return candidates;
    }

    private boolean isNearDuplicate(String a, String b) {
        if (a.equals(b)) return true;

        // Semantic key match (strips common verb-prefixes and noun-suffixes)
        String ka = semanticKey(a);
        String kb = semanticKey(b);
        if (!ka.isBlank() && ka.equals(kb)) return true;

        // Substring containment
        if (a.contains(b) || b.contains(a)) return true;

        // Levenshtein ≤ 2 (bounded to avoid O(n²) cost on very long names)
        if (a.length() <= 40 && b.length() <= 40 && levenshtein(a, b) <= 2) return true;

        // Root comparison after common English suffix stripping
        String ra = stripCommonSuffixes(a.replace("_", ""));
        String rb = stripCommonSuffixes(b.replace("_", ""));
        return !ra.isBlank() && ra.equals(rb);
    }

    /** Standard O(m × n) Levenshtein distance using a single-row DP array. */
    private int levenshtein(String a, String b) {
        int m = a.length();
        int n = b.length();
        int[] dp = new int[n + 1];
        for (int j = 0; j <= n; j++) dp[j] = j;
        for (int i = 1; i <= m; i++) {
            int prev = dp[0];
            dp[0] = i;
            for (int j = 1; j <= n; j++) {
                int temp = dp[j];
                if (a.charAt(i - 1) == b.charAt(j - 1)) {
                    dp[j] = prev;
                } else {
                    dp[j] = 1 + Math.min(prev, Math.min(dp[j], dp[j - 1]));
                }
                prev = temp;
            }
        }
        return dp[n];
    }

    /** Strips common English verb/noun suffixes for root-concept comparison. */
    private String stripCommonSuffixes(String word) {
        String w = word.toLowerCase(Locale.ROOT);
        for (String suffix : new String[]{"tion", "sion", "ing", "ize", "ise", "ion", "or", "er", "ed"}) {
            if (w.endsWith(suffix) && w.length() > suffix.length() + 3) {
                return w.substring(0, w.length() - suffix.length());
            }
        }
        return w;
    }

    // ── Name validation / generic detection (Phase 4A) ───────────────────────────

    private String rejectionReason(NameSuggestion ns) {
        if (ns == null || ns.name == null || ns.name.isBlank()) {
            return "blank";
        }
        // 4A: reject over 60 characters
        if (!VALID_NAME.matcher(ns.name).matches()) {
            return "invalid_format_or_too_long";
        }
        if (ns.name.equals("main") || ns.name.equals("entry") || ns.name.equals("function")) {
            return "reserved";
        }
        if (ns.name.startsWith("sub_") || ns.name.startsWith("fun_") || ns.name.startsWith("unk_")) {
            return "generic_prefix";
        }
        if (ns.name.chars().filter(ch -> ch == '_').count() > 5) {
            return "too_many_segments";
        }
        if (looksGeneric(ns.name)) {
            return "overly_generic";
        }
        return null;
    }

    /**
     * 4A — Returns true if the name is a placeholder with no domain specificity.
     * Exact blacklist + generic-prefix check + verb-with-trivial-noun pattern.
     */
    private boolean looksGeneric(String name) {
        if (name == null) return true;
        String n = lower(name);

        // Exact known-bad names (Phase 4A blocklist + previous additions)
        if (n.equals("process_data")   || n.equals("handle_data")   || n.equals("do_work")
         || n.equals("handler")        || n.equals("helper")         || n.equals("unknown")
         || n.equals("manager")        || n.equals("processor")      || n.equals("wrapper")
         || n.equals("subroutine")     || n.equals("generic_function")
         || n.equals("process_buffer") || n.equals("parse_data")
         || n.equals("manage_state")   || n.equals("invoke_function")
         || n.equals("run_function")   || n.equals("execute_function")
         || n.equals("perform_action") || n.equals("do_action")
         || n.equals("do_task")        || n.equals("run_task")
         || n.equals("do_operation")   || n.equals("perform_operation")
         || n.equals("update_state")   || n.equals("check_state")
         || n.equals("get_data")       || n.equals("set_data")
         || n.equals("process_input")  || n.equals("process_output")
         || n.equals("handle_request") || n.equals("handle_response")) {
            return true;
        }
        if (n.startsWith("func") || n.startsWith("sub_") || n.startsWith("fun_")) {
            return true;
        }
        // Verb + trivially generic noun (two-segment names only)
        if (n.matches("(process|handle|do|run|exec|execute|perform|manage|check|update|get|set)_[a-z0-9]+")) {
            String[] parts = n.split("_", 2);
            if (parts.length == 2) {
                String noun = parts[1];
                if (noun.matches("data|buffer|value|input|output|stuff|thing"
                        + "|item|info|result|content|payload|msg|obj|object|ptr|param|arg")) {
                    return true;
                }
            }
        }
        return false;
    }

    private String semanticKey(String name) {
        String n = lower(name);
        n = n.replaceAll("^(parse|decode|read|load|handle|process|extract|build|compute"
                + "|validate|match|verify|initialize|encrypt|decrypt|send|recv|connect)_", "");
        n = n.replaceAll("_(data|buffer|value|values|entry|entries|record|records"
                + "|message|file|service|context|packet|request|response)$", "");
        return n;
    }

    // ── Context alignment check ───────────────────────────────────────────────────

    /**
     * Returns false only when the candidate name claims a specific domain (crypto,
     * network, file) that the extracted context does NOT support — a likely hallucination.
     * Returns true in all other cases (including genuinely ambiguous ones).
     */
    private boolean alignsWithContext(NameSuggestion ns, SymbolContext ctx) {
        String name = lower(ns.name);

        // Positive fast-paths
        if (containsAny(name, "read", "write", "load", "save")    && ctx.usesFileIOLike)    return true;
        if (containsAny(name, "send", "recv", "connect", "packet") && ctx.usesNetworkIOLike) return true;
        if (containsAny(name, "encrypt", "decrypt", "hash", "sign","verify", "hmac", "aes", "sha")
                && ctx.usesCryptoLike) return true;
        if (containsAny(name, "malloc", "alloc", "free")           && ctx.usesMallocFreeLike) return true;
        if (containsAny(name, "copy", "move", "transfer")          && ctx.usesMemcpyLike)    return true;
        if (containsAny(name, "compare", "match", "equal")         && ctx.usesStrcmpLike)    return true;
        if (containsAny(name, "parse", "decode", "serialize", "format", "validate")) {
            String haystack = lower(ns.reason) + " "
                    + String.join(" ", safeList(ctx.referencedImports)) + " "
                    + String.join(" ", safeList(ctx.callees)) + " "
                    + String.join(" ", safeList(ctx.referencedStrings));
            return containsAny(haystack, "parse", "json", "xml", "format",
                    "validate", "string", "buffer", "message");
        }

        // Negative: domain keyword in name but flag is false → likely hallucination
        if (containsAny(name, "encrypt", "decrypt", "hash", "crypto", "aes", "sha", "hmac")
                && !ctx.usesCryptoLike)    return false;
        if (containsAny(name, "socket", "packet", "http", "ssl", "tls")
                && !ctx.usesNetworkIOLike) return false;
        if (containsAny(name, "read_file", "write_file", "open_file", "load_file")
                && !ctx.usesFileIOLike)    return false;

        return true; // cannot determine — do not penalise
    }

    // ── Evidence strength (used for temperature selection) ───────────────────────

    private int evidenceStrength(SymbolContext ctx) {
        int score = 0;
        if (ctx.decompiledCode != null && ctx.decompiledCode.length() > 80) {
            score += ctx.decompiledCode.length() > 400 ? 2 : 1;
        }
        if (ctx.referencedStrings  != null && !ctx.referencedStrings.isEmpty())  score++;
        if (ctx.callees            != null && !ctx.callees.isEmpty())            score += 2;
        if (ctx.referencedImports  != null && !ctx.referencedImports.isEmpty())  score++;
        if (ctx.loopCount > 0 || ctx.branchCount > 2 || ctx.basicBlockCount > 3) score++;
        return Math.min(score, 5);
    }

    // ── Logging (Phase 6) ────────────────────────────────────────────────────────

    private void logStats(String outcome) {
        Msg.info(this, "[AIRE] outcome=" + outcome
                + " stats{"
                + "requests="  + requestCount
                + " parsed="   + parsedSuccessCount
                + " retry_ok=" + retrySuccessCount
                + " insuff_ev="+ insufficientEvidenceCount
                + " fallback=" + fallbackCount
                + " malformed="+ malformedCount
                + "}");
    }

    private void maybeLogModelRecommendation() {
        if (malformedCount >= 3 && malformedCount * 2 >= requestCount) {
            Msg.warn(this, "[AIRE] Frequent malformed outputs for model '" + model
                    + "'. Consider a model with better instruction-following "
                    + "(e.g., gemma3:12b, mistral:7b, qwen2.5:7b).");
        }
    }

    // ── HTTP / response helpers ──────────────────────────────────────────────────

    private String extractResponseText(String httpBody) {
        try {
            JsonObject root = JsonParser.parseString(httpBody).getAsJsonObject();
            if (root.has("response") && !root.get("response").isJsonNull()) {
                return root.get("response").getAsString();
            }
        } catch (Exception ex) {
            Msg.warn(this, "[AIRE] Failed to parse Ollama HTTP body: " + ex.getMessage());
        }
        return httpBody == null ? "" : httpBody;
    }

    // ── String / numeric helpers ─────────────────────────────────────────────────

    private String normalizeName(String name) {
        if (name == null) return "";
        String n = name.trim().toLowerCase(Locale.ROOT);
        n = n.replaceAll("[^a-z0-9_]", "_");
        n = n.replaceAll("_+", "_");
        n = n.replaceAll("^_+", "");
        n = n.replaceAll("_+$", "");
        return n;
    }

    private String cleanSentence(String s) {
        if (s == null) return "";
        return s.replaceAll("\\s+", " ").trim();
    }

    private double parseDouble(String s, double fallback) {
        if (s == null) return fallback;
        try {
            return Double.parseDouble(s.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private String safe(String s) { return s == null ? "" : s; }

    private String truncate(String s, int max) {
        if (s == null || s.length() <= max) return s == null ? "" : s;
        return s.substring(0, max) + "\n/* ... truncated ... */";
    }

    private String truncateForLog(String s) {
        if (s == null || s.length() <= 3000) return s == null ? "" : s;
        return s.substring(0, 3000) + "\n/* ... truncated raw output ... */";
    }

    private String shorten(String s, int max) {
        if (s == null || s.length() <= max) return s == null ? "" : s;
        return s.substring(0, max - 3) + "...";
    }

    private String joinLimited(List<String> items, int maxItems) {
        if (items == null || items.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        int n = Math.min(items.size(), maxItems);
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            sb.append(items.get(i));
        }
        if (items.size() > maxItems) sb.append(", ...");
        return sb.toString();
    }

    private boolean containsAny(String haystack, String... needles) {
        for (String needle : needles) {
            if (haystack.contains(needle)) return true;
        }
        return false;
    }

    private String lower(String s) { return s == null ? "" : s.toLowerCase(Locale.ROOT); }

    private List<String> safeList(List<String> items) {
        return items == null ? List.of() : items;
    }
}
