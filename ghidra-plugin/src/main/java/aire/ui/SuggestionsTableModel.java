package aire.ui;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class SuggestionsTableModel extends AbstractTableModel {

    private final String[] cols = {"Function", "Entry", "Status", "Top Suggestion", "Conf"};
    private final List<SuggestionRow> rows = new ArrayList<>();

    public void setRows(List<SuggestionRow> r) {
        rows.clear();
        rows.addAll(r);
        fireTableDataChanged();
    }

    public SuggestionRow getRow(int idx) {
        return (idx >= 0 && idx < rows.size()) ? rows.get(idx) : null;
    }

    public void updateRow(int idx) {
        if (idx >= 0 && idx < rows.size()) {
            fireTableRowsUpdated(idx, idx);
        }
    }

    @Override public int getRowCount() { return rows.size(); }
    @Override public int getColumnCount() { return cols.length; }
    @Override public String getColumnName(int col) { return cols[col]; }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        SuggestionRow row = rows.get(rowIndex);
        switch (columnIndex) {
            case 0: return row.function.getName();
            case 1: return row.function.getEntryPoint().toString();
            case 2:
                if (row.busy) {
                    return "Loading";
                }
                if (row.backendUnavailable) {
                    return "Backend";
                }
                return row.status.toString();
            case 3:
                return row.getSelectedName();
            case 4:
                return row.getSelectedSuggestion() == null ? "" : String.format("%.2f", row.getSelectedSuggestion().confidence);
            default: return "";
        }
    }
}
