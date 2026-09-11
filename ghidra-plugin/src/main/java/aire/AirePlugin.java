package aire;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = AirePluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "A.I.R.E MVP proof-of-life plugin",
    description = "Adds a Tools menu action and a dockable Suggestions panel stub."
)
public class AirePlugin extends ProgramPlugin {
    private static final String DEFAULT_OLLAMA_URL = "http://localhost:11434";
    private static final String DEFAULT_OLLAMA_MODEL = "gemma3:4b";

    private AireSuggestionsProvider provider;

    public AirePlugin(PluginTool tool) {
        super(tool);

        // Dockable panel (bonus)
        aire.services.SuggestionProvider providerImpl =
        new aire.services.OllamaSuggestionProvider(resolveBackendUrl(), resolveModelName());
        aire.services.ContextExtractor extractor = new aire.services.ContextExtractor();

        provider = new AireSuggestionsProvider(tool, extractor, providerImpl);


        createHelloAction();
    }

    private void createHelloAction() {
        DockingAction hello = new DockingAction("A.I.R.E Hello", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Msg.showInfo(this, tool.getToolFrame(), "A.I.R.E", "A.I.R.E loaded");
            }
        };

        hello.setMenuBarData(new MenuData(new String[] { "Tools", "A.I.R.E", "Hello" }, "AIRE"));
        tool.addAction(hello);
    }

    private static String resolveBackendUrl() {
        String prop = System.getProperty("aire.ollama.url");
        if (prop != null && !prop.isBlank()) {
            return prop.trim();
        }
        String env = System.getenv("AIRE_OLLAMA_URL");
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        return DEFAULT_OLLAMA_URL;
    }

    private static String resolveModelName() {
        String prop = System.getProperty("aire.ollama.model");
        if (prop != null && !prop.isBlank()) {
            return prop.trim();
        }
        String env = System.getenv("AIRE_OLLAMA_MODEL");
        if (env != null && !env.isBlank()) {
            return env.trim();
        }
        return DEFAULT_OLLAMA_MODEL;
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            provider.removeFromTool();
            provider = null;
        }
        super.dispose();
    }
}
