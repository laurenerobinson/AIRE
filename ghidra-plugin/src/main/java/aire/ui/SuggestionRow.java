package aire.ui;

import aire.model.NameSuggestion;
import aire.model.SuggestionStatus;
import ghidra.program.model.listing.Function;

import java.util.ArrayList;
import java.util.List;

public class SuggestionRow {
    public final Function function;
    public List<NameSuggestion> suggestions = new ArrayList<>();
    public SuggestionStatus status = SuggestionStatus.NEW;
    public int selectedSuggestionIndex = -1;
    public boolean busy = false;
    public boolean backendUnavailable = false;
    public String statusMessage = "";

    public SuggestionRow(Function function) {
        this.function = function;
    }

    public String getTopName() {
        return suggestions.isEmpty() ? "" : suggestions.get(0).name;
    }

    public double getTopConfidence() {
        return suggestions.isEmpty() ? 0.0 : suggestions.get(0).confidence;
    }

    public NameSuggestion getSelectedSuggestion() {
        if (suggestions.isEmpty()) {
            return null;
        }
        if (selectedSuggestionIndex >= 0 && selectedSuggestionIndex < suggestions.size()) {
            return suggestions.get(selectedSuggestionIndex);
        }
        return suggestions.get(0);
    }

    public String getSelectedName() {
        NameSuggestion selected = getSelectedSuggestion();
        return selected == null ? "" : selected.name;
    }
}
