package aire;

import ghidra.framework.plugintool.util.PluginPackage;

/**
 * Registers a concrete plugin package so Ghidra can group A.I.R.E normally
 * instead of creating a stub package at runtime.
 */
public class AirePluginPackage extends PluginPackage {
    public static final String NAME = "A.I.R.E";

    public AirePluginPackage() {
        super(NAME, null, "AI-assisted reverse engineering tools", PluginPackage.FEATURE_PRIORITY);
    }
}
