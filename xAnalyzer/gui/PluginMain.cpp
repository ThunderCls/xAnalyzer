#include "PluginMain.h"
#include "QtPlugin.h"

int Plugin::handle;
HWND Plugin::hwndDlg;
int Plugin::hMenu;
int Plugin::hMenuDisasm;
int Plugin::hMenuDump;
int Plugin::hMenuStack;
int Plugin::hMenuGraph;
int Plugin::hMenuMemmap;
int Plugin::hMenuSymmod;

HUB_EXPIMP bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = AnalyzerHub::PluginVersionInt;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strcpy_s(initStruct->pluginName, AnalyzerHub::PluginName);

    Plugin::handle = initStruct->pluginHandle;

    // register plugin commands
    _plugin_registercommand(Plugin::handle, "xanal", QtPlugin::cbRunAnalysis, true);
    _plugin_registercommand(Plugin::handle, "xanalremove", QtPlugin::cbRemoveAnalysis, true);

    return QtPlugin::Init();
}

HUB_EXPIMP void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    Plugin::hwndDlg = setupStruct->hwndDlg;
    Plugin::hMenu = setupStruct->hMenu;
    Plugin::hMenuDisasm = setupStruct->hMenuDisasm;
    Plugin::hMenuDump = setupStruct->hMenuDump;
    Plugin::hMenuStack = setupStruct->hMenuStack;
    Plugin::hMenuGraph = setupStruct->hMenuGraph;
    Plugin::hMenuMemmap = setupStruct->hMenuMemmap;
    Plugin::hMenuSymmod = setupStruct->hMenuSymmod;
    GuiExecuteOnGuiThread(QtPlugin::Setup);
    QtPlugin::WaitForSetup();
}

HUB_EXPIMP bool plugstop()
{
    GuiExecuteOnGuiThread(QtPlugin::Stop);
    QtPlugin::WaitForStop();

    _plugin_unregistercommand(Plugin::handle, "xanal");
    _plugin_unregistercommand(Plugin::handle, "xanalremove");

    _plugin_menuclear(Plugin::hMenu);
    _plugin_menuclear(Plugin::hMenuDisasm);
    _plugin_menuclear(Plugin::hMenuStack);
    return true;
}
