package aire;

import aire.model.NameSuggestion;
import aire.model.SuggestionStatus;
import aire.model.SymbolContext;
import aire.services.ContextExtractor;
import aire.services.SuggestionProvider;
import aire.ui.SuggestionRow;
import aire.ui.SuggestionsTableModel;
import docking.WindowPosition;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.ConnectException;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpTimeoutException;
import java.util.ArrayList;
import java.util.List;

public class AireSuggestionsProvider extends ComponentProviderAdapter {

    private static final Color BG_MAIN = new Color(0x1b, 0x1f, 0x24);
    private static final Color BG_SECTION = new Color(0x22, 0x27, 0x2e);
    private static final Color BG_CARD = new Color(0x2a, 0x30, 0x38);
    private static final Color BG_CARD_SELECTED = new Color(0x18, 0x4a, 0x63);
    private static final Color BG_CARD_APPLIED = new Color(0x1f, 0x5c, 0x3f);
    private static final Color FG_MAIN = new Color(0xe9, 0xec, 0xef);
    private static final Color FG_MUTED = new Color(0xae, 0xb6, 0xbf);
    private static final Color ACCENT = new Color(0x63, 0xc7, 0xff);
    private static final Color BORDER = new Color(0x4a, 0x54, 0x60);
    private static final Color BORDER_SELECTED = new Color(0x8d, 0xd9, 0xff);
    private static final Color BORDER_APPLIED = new Color(0x8e, 0xdf, 0xb4);
    private static final Color STATE_INFO = new Color(0x2b, 0x4d, 0x5f);
    private static final Color STATE_WARN = new Color(0x6a, 0x53, 0x20);
    private static final Color STATE_ERROR = new Color(0x6d, 0x2c, 0x2c);
    private static final int CARD_MIN_WIDTH = 220;
    private static final Border DETAILS_BORDER =
            new CompoundBorder(new LineBorder(BORDER, 1, true), new EmptyBorder(8, 10, 8, 10));

    private final PluginTool tool;
    private final ContextExtractor extractor;
    private final SuggestionProvider suggestionProvider;

    private final JPanel panel = new JPanel(new BorderLayout(0, 8));
    private final SuggestionsTableModel tableModel = new SuggestionsTableModel();
    private final JTable table = new JTable(tableModel);

    private final JButton refreshBtn = new JButton("Refresh");
    private final JButton suggestBtn = new JButton("Suggest");
    private final JButton applyBtn = new JButton("Apply");

    private final JLabel statusLabel = new JLabel();
    private final JLabel stateBanner = new JLabel("Ready.");
    private final JLabel suggestionsHeader = new JLabel("Suggestions");
    private final JLabel detailsHeader = new JLabel("Selected Suggestion");
    private final JPanel suggestionsPanel = new ViewportWidthPanel();
    private final JTextArea details = new JTextArea();
    private JSplitPane mainSplit;
    private JSplitPane lowerSplit;
    private boolean providerBusy = false;

    public AireSuggestionsProvider(PluginTool tool, ContextExtractor extractor, SuggestionProvider suggestionProvider) {
        super(tool, "A.I.R.E Suggestions", "AIRE");
        this.tool = tool;
        this.extractor = extractor;
        this.suggestionProvider = suggestionProvider;
        setTitle("A.I.R.E Suggestions");
        setWindowGroup("A.I.R.E");
        setWindowMenuGroup("A.I.R.E");
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setIntraGroupPosition(WindowPosition.RIGHT);

        buildUI();
        setVisible(true);
    }

    private void buildUI() {
        panel.setBorder(new EmptyBorder(8, 8, 8, 8));
        panel.setBackground(BG_MAIN);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        top.setBackground(BG_MAIN);
        top.add(refreshBtn);
        top.add(suggestBtn);
        top.add(applyBtn);

        statusLabel.setForeground(FG_MUTED);
        statusLabel.setText("Backend: " + suggestionProvider.getStatus());
        top.add(Box.createHorizontalStrut(12));
        top.add(statusLabel);
        panel.add(top, BorderLayout.NORTH);

        configureBanner();
        panel.add(stateBanner, BorderLayout.SOUTH);

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setRowHeight(26);
        table.setRowMargin(4);
        table.setIntercellSpacing(new Dimension(8, 4));
        table.setFillsViewportHeight(true);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setBackground(BG_SECTION);
        table.setForeground(FG_MAIN);
        table.setSelectionBackground(new Color(0x31, 0x46, 0x57));
        table.setSelectionForeground(FG_MAIN);
        table.setShowVerticalLines(false);
        table.getTableHeader().setReorderingAllowed(false);
        configureTableColumns();
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.getViewport().setBackground(BG_SECTION);
        tableScroll.setMinimumSize(new Dimension(280, 160));

        JComponent bottom = buildBottomPanel();
        mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottom);
        mainSplit.setResizeWeight(0.42);
        mainSplit.setBorder(null);
        mainSplit.setOneTouchExpandable(true);
        mainSplit.setContinuousLayout(true);
        bottom.setMinimumSize(new Dimension(320, 280));
        panel.add(mainSplit, BorderLayout.CENTER);

        refreshBtn.addActionListener(e -> refreshFunctions());
        suggestBtn.addActionListener(e -> suggestForSelected());
        applyBtn.addActionListener(e -> applySelectedSuggestion(false));

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            onFunctionSelectionChanged();
        });

        registerKeyActions();
        SwingUtilities.invokeLater(this::resetDividerLocations);

        details.setText("Click Refresh to load functions. Select one, then Suggest.");
        refreshControlState();
        renderSuggestionCards(null);
    }

    private void configureBanner() {
        stateBanner.setOpaque(true);
        stateBanner.setBackground(STATE_INFO);
        stateBanner.setForeground(FG_MAIN);
        stateBanner.setBorder(new EmptyBorder(6, 10, 6, 10));
    }

    private JComponent buildBottomPanel() {
        JPanel bottom = new JPanel(new BorderLayout(10, 0));
        bottom.setBackground(BG_MAIN);

        suggestionsHeader.setForeground(FG_MAIN);
        suggestionsHeader.setBorder(new EmptyBorder(0, 2, 6, 2));
        detailsHeader.setForeground(FG_MAIN);
        detailsHeader.setBorder(new EmptyBorder(0, 2, 6, 2));

        suggestionsPanel.setLayout(new BoxLayout(suggestionsPanel, BoxLayout.Y_AXIS));
        suggestionsPanel.setBackground(BG_MAIN);
        suggestionsPanel.setBorder(new EmptyBorder(4, 8, 4, 8));

        JScrollPane suggestionsScroll = new JScrollPane(suggestionsPanel);
        suggestionsScroll.setBorder(DETAILS_BORDER);
        suggestionsScroll.getViewport().setBackground(BG_MAIN);
        suggestionsScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        suggestionsScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        suggestionsScroll.setMinimumSize(new Dimension(280, 240));
        suggestionsScroll.getVerticalScrollBar().setUnitIncrement(20);

        JPanel suggestionWrapper = new JPanel(new BorderLayout());
        suggestionWrapper.setBackground(BG_MAIN);
        suggestionWrapper.add(suggestionsHeader, BorderLayout.NORTH);
        suggestionWrapper.add(suggestionsScroll, BorderLayout.CENTER);

        details.setEditable(false);
        details.setFocusable(false);
        details.setLineWrap(true);
        details.setWrapStyleWord(true);
        details.setRows(16);
        details.setBackground(BG_SECTION);
        details.setForeground(FG_MAIN);
        details.setFont(UIManager.getFont("Label.font"));
        details.setBorder(new EmptyBorder(10, 12, 10, 12));
        details.setCaretPosition(0);
        JScrollPane detailScroll = new JScrollPane(details);
        detailScroll.setBorder(DETAILS_BORDER);
        detailScroll.getViewport().setBackground(BG_SECTION);
        detailScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        detailScroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        detailScroll.setMinimumSize(new Dimension(460, 240));
        detailScroll.getVerticalScrollBar().setUnitIncrement(20);

        JPanel detailWrapper = new JPanel(new BorderLayout());
        detailWrapper.setBackground(BG_MAIN);
        detailWrapper.add(detailsHeader, BorderLayout.NORTH);
        detailWrapper.add(detailScroll, BorderLayout.CENTER);

        lowerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, suggestionWrapper, detailWrapper);
        lowerSplit.setResizeWeight(0.34);
        lowerSplit.setBorder(null);
        lowerSplit.setOneTouchExpandable(true);
        lowerSplit.setContinuousLayout(true);
        suggestionWrapper.setMinimumSize(new Dimension(280, 240));
        detailWrapper.setMinimumSize(new Dimension(460, 240));
        bottom.add(lowerSplit, BorderLayout.CENTER);
        return bottom;
    }

    private void resetDividerLocations() {
        if (mainSplit != null) {
            mainSplit.setDividerLocation(0.42);
        }
        if (lowerSplit != null) {
            lowerSplit.setDividerLocation(0.34);
        }
    }

    private void configureTableColumns() {
        table.getColumnModel().getColumn(0).setPreferredWidth(240);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(90);
        table.getColumnModel().getColumn(2).setMaxWidth(110);
        table.getColumnModel().getColumn(3).setPreferredWidth(180);
        table.getColumnModel().getColumn(4).setPreferredWidth(70);
        table.getColumnModel().getColumn(4).setMaxWidth(80);
    }

    private void registerKeyActions() {
        InputMap inputMap = panel.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap actionMap = panel.getActionMap();
        inputMap.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "aire.apply");
        actionMap.put("aire.apply", new AbstractAction() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                applySelectedSuggestion(false);
            }
        });
    }

    @Override
    public JComponent getComponent() {
        return panel;
    }

    private Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return null;
        }
        return pm.getCurrentProgram();
    }

    private void refreshFunctions() {
        Program program = getCurrentProgram();
        if (program == null) {
            setBanner("No program is open. Open or import a binary first.", STATE_WARN);
            details.setText("No program is open. Open or import a binary first.");
            return;
        }

        List<SuggestionRow> rows = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);

        int limit = 250;
        int count = 0;
        while (it.hasNext() && count < limit) {
            Function f = it.next();
            rows.add(new SuggestionRow(f));
            count++;
        }

        Msg.info(this, "[AIRE] Refresh loaded " + rows.size() + " functions");
        tableModel.setRows(rows);
        if (!rows.isEmpty()) {
            table.setRowSelectionInterval(0, 0);
        }
        setBanner("Loaded " + rows.size() + " functions.", STATE_INFO);
        details.setText("Loaded " + rows.size() + " functions.\nSelect one, then click Suggest.");
        onFunctionSelectionChanged();
    }

    private void suggestForSelected() {
        int idx = table.getSelectedRow();
        SuggestionRow row = tableModel.getRow(idx);
        if (row == null) {
            setBanner("Select a function row first.", STATE_WARN);
            details.setText("Select a function row first.");
            return;
        }

        Program program = getCurrentProgram();
        if (program == null) {
            setBanner("No program is open.", STATE_WARN);
            details.setText("No program is open.");
            return;
        }

        providerBusy = true;
        row.busy = true;
        row.backendUnavailable = false;
        row.status = SuggestionStatus.NEW;
        row.statusMessage = "Generating suggestions...";
        if (row.selectedSuggestionIndex < 0) {
            row.selectedSuggestionIndex = 0;
        }
        tableModel.updateRow(idx);
        setBanner("Generating suggestions for " + row.function.getName() + "...", STATE_INFO);
        suggestionsHeader.setText("Suggestions for " + row.function.getName());
        details.setText("Gathering context and querying the backend...");
        renderSuggestionCards(row);
        refreshControlState();

        Msg.info(this, "[AIRE] Generating suggestions for " + row.function.getName());
        Task task = new Task("A.I.R.E - Suggest Names", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    SymbolContext ctx = extractor.extract(program, row.function, monitor);
                    Msg.info(this, "[AIRE] Extracted context: " + ctx.shortSummary());
                    List<NameSuggestion> suggestions = suggestionProvider.suggest(ctx);

                    SwingUtilities.invokeLater(() -> {
                        boolean recovered = suggestionProvider.wasLastResultRecovered();
                        String providerMessage = suggestionProvider.getLastResultMessage();
                        row.busy = false;
                        row.backendUnavailable = false;
                        row.suggestions = suggestions;
                        row.selectedSuggestionIndex = suggestions.isEmpty() ? -1 : 0;
                        row.status = suggestions.isEmpty() ? SuggestionStatus.ERROR : SuggestionStatus.SUGGESTED;
                        if (recovered && !suggestions.isEmpty()) {
                            row.statusMessage = providerMessage.isBlank()
                                    ? "Partial suggestions recovered from malformed model output."
                                    : providerMessage;
                        }
                        else {
                            row.statusMessage = suggestions.isEmpty()
                                    ? (providerMessage.isBlank() ? "No strong suggestions returned." : providerMessage)
                                    : "Generated " + suggestions.size() + " suggestions.";
                        }
                        providerBusy = false;
                        tableModel.updateRow(idx);
                        Msg.info(this, "[AIRE] Rendered " + suggestions.size() + " suggestions for " + row.function.getName());
                        onFunctionSelectionChanged();
                        if (recovered && !suggestions.isEmpty()) {
                            setBanner("Partial suggestions recovered for " + row.function.getName() + ".", STATE_WARN);
                        }
                        else if (suggestions.isEmpty()) {
                            setBanner("No strong suggestions for " + row.function.getName() + ".", STATE_WARN);
                        }
                        else {
                            setBanner("Suggestions ready for " + row.function.getName() + ".", STATE_INFO);
                        }
                        refreshControlState();
                    });

                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        row.busy = false;
                        row.suggestions = new ArrayList<>();
                        row.selectedSuggestionIndex = -1;
                        row.status = SuggestionStatus.ERROR;
                        row.backendUnavailable = looksLikeBackendUnavailable(ex);
                        row.statusMessage = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
                        providerBusy = false;
                        tableModel.updateRow(idx);
                        Msg.error(this, "[AIRE] Suggestion generation failed for " + row.function.getName(), ex);
                        onFunctionSelectionChanged();
                        if (isModelMissingError(ex)) {
                            setBanner("Model missing. Pull or configure the Ollama model.", STATE_WARN);
                        }
                        else if (isGenerationTimeout(ex)) {
                            setBanner("Generation timed out. Try a faster model or retry after warm-up.", STATE_WARN);
                        }
                        else if (row.backendUnavailable) {
                            setBanner("Connection failure. Ollama is not reachable on localhost.", STATE_WARN);
                        }
                        else {
                            setBanner("Suggestion generation failed.", STATE_ERROR);
                        }
                        refreshControlState();
                    });
                }
            }
        };

        tool.execute(task);
    }

    private void applySelectedSuggestion(boolean silent) {
        int idx = table.getSelectedRow();
        SuggestionRow row = tableModel.getRow(idx);
        if (row == null) {
            setBanner("Select a function row first.", STATE_WARN);
            return;
        }
        if (row.busy || providerBusy) {
            setBanner("Wait for generation to finish before applying.", STATE_WARN);
            return;
        }

        NameSuggestion selected = row.getSelectedSuggestion();
        String newName = selected == null ? null : selected.name;
        if (newName == null || newName.isBlank()) {
            setBanner("No suggestion selected. Generate suggestions first.", STATE_WARN);
            return;
        }

        Program program = getCurrentProgram();
        if (program == null) {
            setBanner("No program is open.", STATE_WARN);
            return;
        }

        Msg.info(this, "[AIRE] Applying suggestion '" + newName + "' to " + row.function.getName());
        int tx = program.startTransaction("A.I.R.E Apply Suggestion");
        try {
            row.function.setName(newName, SourceType.USER_DEFINED);
            program.endTransaction(tx, true);
            row.status = SuggestionStatus.APPLIED;
            row.statusMessage = "Applied " + newName;
            tableModel.updateRow(idx);
            onFunctionSelectionChanged();
            setBanner("Applied suggestion: " + newName, new Color(0x1d, 0x55, 0x40));
            if (!silent) {
                Msg.info(this, "[AIRE] Applied rename to " + newName);
            }
        } catch (Exception ex) {
            program.endTransaction(tx, false);
            row.status = SuggestionStatus.ERROR;
            row.statusMessage = ex.getMessage() == null ? ex.getClass().getSimpleName() : ex.getMessage();
            tableModel.updateRow(idx);
            Msg.error(this, "[AIRE] Failed applying suggestion to " + row.function.getName(), ex);
            onFunctionSelectionChanged();
            setBanner("Failed to apply rename.", STATE_ERROR);
        }
    }

    private void onFunctionSelectionChanged() {
        int idx = table.getSelectedRow();
        SuggestionRow row = tableModel.getRow(idx);

        if (row == null) {
            suggestionsHeader.setText("Suggestions");
            details.setText("Select a function row.");
            renderSuggestionCards(null);
            refreshControlState();
            return;
        }

        suggestionsHeader.setText("Suggestions for " + row.function.getName());
        renderSuggestionCards(row);
        showSelectedDetails(row);
        refreshControlState();
    }

    private void renderSuggestionCards(SuggestionRow row) {
        suggestionsPanel.removeAll();

        if (row == null) {
            suggestionsPanel.add(buildEmptyState("Select a function to view suggestions.", FG_MUTED));
            finishSuggestionRender();
            return;
        }

        Msg.info(this, "[AIRE] Rendering cards for " + row.function.getName()
                + " busy=" + row.busy + " status=" + row.status
                + " selected=" + row.selectedSuggestionIndex
                + " count=" + row.suggestions.size());

        if (row.busy) {
            suggestionsPanel.add(buildStateCard("Loading suggestions...", "Extracting context and waiting on the model.", STATE_INFO));
            finishSuggestionRender();
            return;
        }

        if (row.backendUnavailable) {
            suggestionsPanel.add(buildStateCard("Backend unavailable", row.statusMessage, STATE_WARN));
            finishSuggestionRender();
            return;
        }

        if (row.status == SuggestionStatus.ERROR && isModelMissingMessage(row.statusMessage)) {
            suggestionsPanel.add(buildStateCard("Model missing", row.statusMessage, STATE_WARN));
            finishSuggestionRender();
            return;
        }

        if (row.status == SuggestionStatus.ERROR && isGenerationTimeoutMessage(row.statusMessage)) {
            suggestionsPanel.add(buildStateCard("Generation timeout", row.statusMessage, STATE_WARN));
            finishSuggestionRender();
            return;
        }

        if (row.statusMessage != null && row.statusMessage.toLowerCase().contains("partial suggestions recovered")) {
            suggestionsPanel.add(buildStateCard("Partial suggestions recovered", row.statusMessage, STATE_WARN));
            suggestionsPanel.add(Box.createVerticalStrut(8));
        }

        if (row.status == SuggestionStatus.ERROR && row.suggestions.isEmpty()) {
            suggestionsPanel.add(buildStateCard("Suggestion error", row.statusMessage, STATE_ERROR));
            finishSuggestionRender();
            return;
        }

        if (row.suggestions == null || row.suggestions.isEmpty()) {
            suggestionsPanel.add(buildStateCard("No suggestions yet", "Click Suggest to query the backend for this function.", BG_CARD));
            finishSuggestionRender();
            return;
        }

        for (int i = 0; i < row.suggestions.size(); i++) {
            NameSuggestion suggestion = row.suggestions.get(i);
            suggestionsPanel.add(buildSuggestionCard(row, i, suggestion));
            suggestionsPanel.add(Box.createVerticalStrut(8));
        }

        finishSuggestionRender();
    }

    private void finishSuggestionRender() {
        suggestionsPanel.revalidate();
        suggestionsPanel.repaint();
    }

    private JComponent buildEmptyState(String text, Color fg) {
        JTextArea label = createWrappedTextArea(text, fg, BG_MAIN);
        label.setBorder(new EmptyBorder(8, 8, 8, 8));
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private JPanel buildStateCard(String title, String subtitle, Color bg) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(bg);
        card.setBorder(new CompoundBorder(new LineBorder(BORDER, 1, true), new EmptyBorder(10, 12, 10, 12)));
        applyCardSizing(card);

        JTextArea titleLabel = createWrappedTextArea(title, FG_MAIN, bg);
        titleLabel.setFont(UIManager.getFont("Label.font").deriveFont(Font.BOLD));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(titleLabel);

        if (subtitle != null && !subtitle.isBlank()) {
            JTextArea subtitleLabel = createWrappedTextArea(subtitle, FG_MUTED, bg);
            subtitleLabel.setBorder(new EmptyBorder(6, 0, 0, 0));
            subtitleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
            card.add(subtitleLabel);
        }

        return card;
    }

    private JPanel buildSuggestionCard(SuggestionRow row, int idx, NameSuggestion suggestion) {
        boolean selected = row.selectedSuggestionIndex == idx || (row.selectedSuggestionIndex < 0 && idx == 0);
        boolean applied = row.status == SuggestionStatus.APPLIED && suggestion.name.equals(row.getSelectedName());
        boolean fallbackInferred = row.statusMessage != null && row.statusMessage.toLowerCase().contains("fallback inference");

        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setOpaque(true);
        card.setBackground(applied ? BG_CARD_APPLIED : (selected ? BG_CARD_SELECTED : BG_CARD));
        card.setBorder(new CompoundBorder(
                new LineBorder(applied ? BORDER_APPLIED : (selected ? BORDER_SELECTED : BORDER), 2, true),
                new EmptyBorder(10, 12, 10, 12)));
        card.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        applyCardSizing(card);

        JPanel top = new JPanel(new BorderLayout(8, 0));
        top.setOpaque(false);
        top.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea nameLabel = createWrappedTextArea(suggestion.name, FG_MAIN, card.getBackground());
        nameLabel.setFont(UIManager.getFont("Label.font").deriveFont(Font.BOLD));
        top.add(nameLabel, BorderLayout.CENTER);

        JLabel confidence = new JLabel(formatConfidence(suggestion.confidence));
        confidence.setForeground(ACCENT);
        top.add(confidence, BorderLayout.EAST);
        card.add(top);

        String selectedText = applied ? "Applied" : (selected ? "Selected" : "Click to select");
        String metaText = selectedText + "  |  " + summarizeEvidence(suggestion)
                + "  |  score " + String.format("%.2f", suggestion.confidence);
        if (fallbackInferred) {
            metaText = "Fallback inferred  |  " + metaText;
        }
        JTextArea meta = createWrappedTextArea(metaText, applied ? FG_MAIN : FG_MUTED, card.getBackground());
        meta.setBorder(new EmptyBorder(6, 0, 0, 0));
        meta.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(meta);

        String preview = buildCardPreview(suggestion);
        if (!preview.isBlank()) {
            JTextArea reason = createWrappedTextArea(preview, FG_MAIN, card.getBackground());
            reason.setBorder(new EmptyBorder(8, 0, 0, 0));
            reason.setAlignmentX(Component.LEFT_ALIGNMENT);
            card.add(reason);
        }

        MouseAdapter mouseAdapter = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (providerBusy || row.busy) {
                    return;
                }
                selectSuggestion(row, idx);
                if (e.getClickCount() >= 2 && SwingUtilities.isLeftMouseButton(e)) {
                    applySelectedSuggestion(true);
                }
            }
        };
        attachMouseListenerDeep(card, mouseAdapter);
        return card;
    }

    private void applyCardSizing(JComponent card) {
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.setMinimumSize(new Dimension(CARD_MIN_WIDTH, card.getMinimumSize().height));
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
    }

    private void selectSuggestion(SuggestionRow row, int idx) {
        if (row == null || row.suggestions == null || idx < 0 || idx >= row.suggestions.size()) {
            return;
        }
        row.selectedSuggestionIndex = idx;
        int tableIdx = table.getSelectedRow();
        tableModel.updateRow(tableIdx);
        Msg.info(this, "[AIRE] Selected suggestion index " + idx + " for " + row.function.getName());
        renderSuggestionCards(row);
        showSelectedDetails(row);
        refreshControlState();
    }

    private void showSelectedDetails(SuggestionRow row) {
        if (row == null) {
            details.setText("Select a function row.");
            detailsHeader.setText("Selected Suggestion");
            return;
        }

        detailsHeader.setText("Selected Suggestion");
        StringBuilder sb = new StringBuilder();
        sb.append("Function: ").append(row.function.getName()).append("\n");
        sb.append("Entry: ").append(row.function.getEntryPoint()).append("\n");
        sb.append("Status: ").append(row.busy ? "Loading" : row.status).append("\n");
        if (row.statusMessage != null && !row.statusMessage.isBlank()) {
            sb.append("State: ").append(row.statusMessage).append("\n");
        }

        NameSuggestion selected = row.getSelectedSuggestion();
        if (selected != null) {
            sb.append("\nSelected suggestion\n");
            sb.append("  Name: ").append(selected.name).append("\n");
            sb.append("  Confidence: ").append(formatConfidence(selected.confidence))
                    .append(" (score ").append(String.format("%.2f", selected.confidence)).append(")\n");
            if (selected.reason != null && !selected.reason.isBlank()) {
                sb.append("  Why: ").append(selected.reason).append("\n");
            }
            if (selected.evidence != null && !selected.evidence.isEmpty()) {
                sb.append("  Evidence:\n");
                int limit = Math.min(5, selected.evidence.size());
                for (int i = 0; i < limit; i++) {
                    sb.append("    - ").append(selected.evidence.get(i)).append("\n");
                }
            }
        }
        else if (row.busy) {
            sb.append("\nGenerating suggestions...");
        }
        else if (row.backendUnavailable) {
            sb.append("\nBackend unavailable. Check the model server and configuration.");
        }
        else if (row.suggestions.isEmpty()) {
            sb.append("\nNo suggestions yet.\nClick Suggest to query the backend.");
        }

        if (row.suggestions != null && !row.suggestions.isEmpty()) {
            sb.append("\nAll suggestions\n");
            for (int i = 0; i < row.suggestions.size(); i++) {
                NameSuggestion s = row.suggestions.get(i);
                String marker = (row.selectedSuggestionIndex == i) ? " -> " : "    ";
                sb.append(marker)
                        .append(i + 1).append(". ")
                        .append(s.name)
                        .append(" (").append(formatConfidence(s.confidence)).append(")\n");
            }
        }

        details.setText(sb.toString());
        details.setCaretPosition(0);
    }

    private void refreshControlState() {
        SuggestionRow row = tableModel.getRow(table.getSelectedRow());
        boolean hasRow = row != null;
        boolean rowBusy = hasRow && row.busy;
        boolean hasSelection = hasRow && row.getSelectedSuggestion() != null;

        refreshBtn.setEnabled(!providerBusy);
        suggestBtn.setEnabled(hasRow && !providerBusy && !rowBusy);
        applyBtn.setEnabled(hasSelection && !providerBusy && !rowBusy);
    }

    private void setBanner(String text, Color bg) {
        stateBanner.setText(text);
        stateBanner.setBackground(bg);
        stateBanner.setForeground(FG_MAIN);
    }

    private boolean looksLikeBackendUnavailable(Exception ex) {
        Throwable cur = ex;
        while (cur != null) {
            if (cur instanceof ConnectException || cur instanceof HttpConnectTimeoutException) {
                return true;
            }
            if (cur instanceof IOException && cur.getMessage() != null) {
                String msg = cur.getMessage().toLowerCase();
                if (msg.contains("connection refused") || msg.contains("timed out") || msg.contains("failed to connect")) {
                    return true;
                }
            }
            cur = cur.getCause();
        }
        return false;
    }

    private boolean isModelMissingError(Exception ex) {
        Throwable cur = ex;
        while (cur != null) {
            if (isModelMissingMessage(cur.getMessage())) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }

    private boolean isModelMissingMessage(String message) {
        if (message == null) {
            return false;
        }
        String msg = message.toLowerCase();
        return msg.contains("model missing") || (msg.contains("model") && msg.contains("not available"));
    }

    private boolean isGenerationTimeout(Exception ex) {
        Throwable cur = ex;
        while (cur != null) {
            if (cur instanceof HttpTimeoutException) {
                return true;
            }
            if (isGenerationTimeoutMessage(cur.getMessage())) {
                return true;
            }
            cur = cur.getCause();
        }
        return false;
    }

    private boolean isGenerationTimeoutMessage(String message) {
        if (message == null) {
            return false;
        }
        String msg = message.toLowerCase();
        return msg.contains("generation timeout") || msg.contains("did not finish within") || msg.contains("request timed out");
    }

    private String summarizeEvidence(NameSuggestion suggestion) {
        int count = suggestion.evidence == null ? 0 : suggestion.evidence.size();
        if (count == 0) {
            return "No evidence";
        }
        return count == 1 ? "1 signal" : count + " signals";
    }

    private String buildCardPreview(NameSuggestion suggestion) {
        StringBuilder sb = new StringBuilder();
        if (suggestion.reason != null && !suggestion.reason.isBlank()) {
            sb.append(shorten(suggestion.reason, 82));
        }
        if (suggestion.evidence != null && !suggestion.evidence.isEmpty()) {
            if (sb.length() > 0) {
                sb.append(" | ");
            }
            sb.append("Evidence: ").append(shorten(suggestion.evidence.get(0), 54));
        }
        return sb.toString().trim();
    }

    private String shorten(String text, int max) {
        if (text == null) {
            return "";
        }
        String normalized = text.replaceAll("\\s+", " ").trim();
        if (normalized.length() <= max) {
            return normalized;
        }
        return normalized.substring(0, max - 3) + "...";
    }

    private String formatConfidence(double confidence) {
        return String.format("%.0f%%", confidence * 100.0);
    }

    private JTextArea createWrappedTextArea(String text, Color fg, Color bg) {
        JTextArea area = new JTextArea(text == null ? "" : text);
        area.setEditable(false);
        area.setFocusable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setForeground(fg);
        area.setBackground(bg);
        area.setFont(UIManager.getFont("Label.font"));
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        return area;
    }

    private void attachMouseListenerDeep(Component component, MouseAdapter listener) {
        component.addMouseListener(listener);
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                attachMouseListenerDeep(child, listener);
            }
        }
    }

    private static class ViewportWidthPanel extends JPanel implements Scrollable {
        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 20;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return orientation == SwingConstants.VERTICAL ? visibleRect.height - 20 : visibleRect.width - 20;
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            return true;
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }
}
