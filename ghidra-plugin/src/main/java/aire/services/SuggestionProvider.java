package aire.services;

import aire.model.NameSuggestion;
import aire.model.SymbolContext;
import java.util.List;

public interface SuggestionProvider {
    List<NameSuggestion> suggest(SymbolContext ctx) throws Exception;
    String getStatus();

    default boolean wasLastResultRecovered() {
        return false;
    }

    default String getLastResultMessage() {
        return "";
    }
}
