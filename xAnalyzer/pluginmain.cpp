#include "pluginmain.h"
#include "plugin.h"

// Variables
const char *szprojectnameInfo = "\n" PLUGIN_NAME " " PLUGIN_VERSION_STR
								" Plugin by ThunderCls 2019\n"
								"Extended analysis for static code\n"
								"-> For latest release, issues, etc....\n"
								"-> For help type command \"xanal help\"\n"
								"-> code: http://github.com/ThunderCls/xAnalyzer\n"
								"-> blog: http://reversec0de.wordpress.com\n\n";

int pluginHandle;
HMODULE pluginHInstance;
HWND hwndDlg;
int hMenu;
int hMenuDisasm;
int hMenuDump;
int hMenuStack;
/*====================================================================================
pluginit - Called by debugger when plugin.dp32 is loaded - needs to be EXPORTED

Arguments: initStruct - a pointer to a PLUG_INITSTRUCT structure

Notes:     you must fill in the pluginVersion, sdkVersion and pluginName members.
The pluginHandle is obtained from the same structure - it may be needed in
other function calls.

you can call your own setup routine from within this function to setup
menus and commands, and pass the initStruct parameter to this function.

--------------------------------------------------------------------------------------*/
PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;

    return pluginInit(initStruct);
}

/*====================================================================================
plugstop - Called by debugger when the plugin.dp32 is unloaded - needs to be EXPORTED

Arguments: none

Notes:     perform cleanup operations here, clearing menus and other housekeeping

--------------------------------------------------------------------------------------*/
PLUG_EXPORT bool plugstop()
{
    return pluginStop();
}

/*====================================================================================
plugsetup - Called by debugger to initialize your plugins setup - needs to be EXPORTED

Arguments: setupStruct - a pointer to a PLUG_SETUPSTRUCT structure

Notes:     setupStruct contains useful handles for use within x64_dbg, mainly Qt
menu handles (which are not supported with win32 api) and the main window
handle with this information you can add your own menus and menu items
to an existing menu, or one of the predefined supported right click
context menus: hMenuDisam, hMenuDump & hMenuStack

plugsetup is called after pluginit.
--------------------------------------------------------------------------------------*/
PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    hMenuDisasm = setupStruct->hMenuDisasm;
    hMenuDump = setupStruct->hMenuDump;
    hMenuStack = setupStruct->hMenuStack;
	GuiAddLogMessage(szprojectnameInfo); // Add some info of the plugin to the log
    pluginSetup();
}

/*====================================================================================
Main entry function for a DLL file  - required.
--------------------------------------------------------------------------------------*/
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
)
{
	pluginHInstance = hinstDLL;
    return TRUE;
}
