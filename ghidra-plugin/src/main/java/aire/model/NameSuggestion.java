package aire.model;

import java.util.ArrayList;
import java.util.List;

public class NameSuggestion {
    public String name;
    public double confidence;
    public String reason;
    public List<String> evidence = new ArrayList<>();
}
