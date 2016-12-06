#include "plugin.h"
#include "icons.h"
#include "xanalyzer.h"

enum
{
	MENU_ANALYZE,
	MENU_ANALYZE_EXT,
	MENU_ANALYZE_DISASM,
	MENU_ANALYZE_DISASM_EXT,
	MENU_ABOUT
};

/*====================================================================================
CBINITDEBUG - Called by debugger when a program is debugged - needs to be EXPORTED

Arguments: cbType
cbInfo - a pointer to a PLUG_CB_INITDEBUG structure.
The szFileName item contains name of file being debugged.

--------------------------------------------------------------------------------------*/
PLUG_EXPORT void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
{
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
}

PLUG_EXPORT void CBEXCEPTION(CBTYPE cbType, PLUG_CB_EXCEPTION* info)
{
}

PLUG_EXPORT void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
{
}

/*====================================================================================
CBSYSTEMBREAKPOINT - Called by debugger at system breakpoint - needs to be EXPORTED

Arguments: cbType
cbInfo - reserved

--------------------------------------------------------------------------------------*/
PLUG_EXPORT void CBSYSTEMBREAKPOINT(CBTYPE cbType, PLUG_CB_SYSTEMBREAKPOINT* info)
{
}

PLUG_EXPORT void CBBREAKPOINT(CBTYPE cbType, PLUG_CB_BREAKPOINT* bpInfo)
{
	OnBreakpoint(bpInfo);
}

/*====================================================================================
CBMENUENTRY - Called by debugger when a menu item is clicked - needs to be EXPORTED

Arguments: cbType
cbInfo - a pointer to a PLUG_CB_MENUENTRY structure. The hEntry contains
the resource id of menu item identifiers

Notes:     hEntry can be used to determine if the user has clicked on your plugins
menu item(s) and to do something in response to it.

--------------------------------------------------------------------------------------*/
PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	switch(info->hEntry)
    {
		case MENU_ANALYZE:
		case MENU_ANALYZE_DISASM:
			extendedAnal = false;
			DbgCmdExec("ExtendedAnalysis");
			break;
		case MENU_ANALYZE_EXT:
		case MENU_ANALYZE_DISASM_EXT:
			if (MessageBox(hwndDlg, "Do you wish to continue and analyze the entire code section?.\n\n"
				"Doing this may take some time to complete and amounts of RAM\n"
				"memory depending on the size of the section.",
				"Extended Analysis?", MB_ICONINFORMATION + MB_YESNO) == IDYES)
			{
				extendedAnal = true;
				DbgCmdExec("ExtendedAnalysis");
			}
			break;
		case MENU_ABOUT:
			MessageBox(hwndDlg, "---------------------------------------------------------\n"
				"\t                [ xAnalyzer ]\n"
				"                Extended analysis for static code \n\n"
				"                  Coded By: ThunderCls - 2016\n"
				"         http://github.com/ThunderCls/xAnalyzer\n"
				"              http://reversec0de.wordpress.com\n"
				"           Base code: APIInfo Plugin by mrfearless\n"
				"\n---------------------------------------------------------",
				PLUGIN_NAME, MB_ICONINFORMATION);
			break;
		default:
			break;
    }
}

//--------------------------------------------------------------------------------------
//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	_plugin_registercommand(pluginHandle, "ExtendedAnalysis", cbExtendedAnalysis, true);
    return true; //Return false to cancel loading the plugin.
}

//--------------------------------------------------------------------------------------
//Deinitialize your plugin data here (clearing menus optional).
bool pluginStop()
{
	_plugin_unregistercommand(pluginHandle, "ExtendedAnalysis");

    _plugin_menuclear(hMenu);
    _plugin_menuclear(hMenuDisasm);
    _plugin_menuclear(hMenuDump);
    _plugin_menuclear(hMenuStack);
    return true;
}

//--------------------------------------------------------------------------------------
//Do GUI/Menu related things here.
void pluginSetup()
{
	ICONDATA menu_icon;
	menu_icon.data = icon;
	menu_icon.size = sizeof(icon);

	// Plugin Menu
	_plugin_menuseticon(hMenu, &menu_icon);
	_plugin_menuaddentry(hMenu, MENU_ANALYZE, "&Normal analysis");
	_plugin_menuaddentry(hMenu, MENU_ANALYZE_EXT, "&Extended analysis");
	_plugin_menuaddseparator(hMenu);
	_plugin_menuaddentry(hMenu, MENU_ABOUT, "&About...");

	_plugin_menuseticon(hMenuDisasm, &menu_icon);
	_plugin_menuaddentry(hMenuDisasm, MENU_ANALYZE_DISASM, "&Normal analysis");
	_plugin_menuaddentry(hMenuDisasm, MENU_ANALYZE_DISASM_EXT, "&Extended analysis");

}
//--------------------------------------------------------------------------------------