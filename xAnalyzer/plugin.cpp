#include "plugin.h"
#include "icons.h"
#include "xanalyzer.h"
#include "resource.h"

/*====================================================================================
CBINITDEBUG - Called by debugger when a program is debugged - needs to be EXPORTED

Arguments: cbType
cbInfo - a pointer to a PLUG_CB_INITDEBUG structure.
The szFileName item contains name of file being debugged.

--------------------------------------------------------------------------------------*/
//PLUG_EXPORT void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
//{
//}
//
//PLUG_EXPORT void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
//{
//}
//
//PLUG_EXPORT void CBEXCEPTION(CBTYPE cbType, PLUG_CB_EXCEPTION* info)
//{
//}
//
//PLUG_EXPORT void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
//{
//}
//
//PLUG_EXPORT void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info)
//{
//}
//
//PLUG_EXPORT void CBLOADDLL(CBTYPE cbType, PLUG_CB_LOADDLL* info)
//{
//}
//
///*====================================================================================
//CBSYSTEMBREAKPOINT - Called by debugger at system breakpoint - needs to be EXPORTED
//
//Arguments: cbType
//cbInfo - reserved
//
//--------------------------------------------------------------------------------------*/
//PLUG_EXPORT void CBSYSTEMBREAKPOINT(CBTYPE cbType, PLUG_CB_SYSTEMBREAKPOINT* info)
//{
//}

/*PLUG_EXPORT void CBWINEVENT(CBTYPE cbType, PLUG_CB_WINEVENT* info)
{
	OnWinEvent(info);
}*/

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
	MSGBOXPARAMS mbp = { 0 };
	switch(info->hEntry)
    {
		// OPTIONS MENUS
		// ------------------------------------------------------------------------
		case MENU_ANALYZE_UNDEF:
			conf.undef_funtion_analysis = !conf.undef_funtion_analysis;
			SaveConfig();
			break;
		case MENU_ANALYZE_AUTO:
			conf.auto_analysis = !conf.auto_analysis;
			SaveConfig();
			break;
		case MENU_ANALYZE_EXT:
			if (conf.extended_analysis)
				conf.extended_analysis = false;
			else
			{
				if (MessageBox(hwndDlg, "By using this option the entire code section will be processed.\n"
					"Doing this may take some time to complete and amounts of RAM\n"
					"memory depending on the size of the section.\n\n"
					"Do you wish to continue?",
					"Extended Analysis?", MB_ICONINFORMATION + MB_YESNO) == IDYES)
				{
					conf.extended_analysis = true;
				}
			}
			SaveConfig();
			break;
		case MENU_ANALYZE_CLEAR_CMTS:
			conf.clear_usercomments = !conf.clear_usercomments;
			SaveConfig();
			break;
		case MENU_ANALYZE_CLEAR_LBLS:
			conf.clear_userlabels = !conf.clear_userlabels;
			SaveConfig();
			break;
		case MENU_ANALYZE_CLEAR_ACMTS:
			conf.clear_autocomments = !conf.clear_autocomments;
			SaveConfig();
			break;
		case MENU_ANALYZE_CLEAR_ALBLS:
			conf.clear_autolabels = !conf.clear_autolabels;
			SaveConfig();
			break;
		case MENU_ANALYZE_TRACK_UNDEF:
			conf.track_undef_functions = !conf.track_undef_functions;
			SaveConfig();
			break;
		case MENU_ABOUT:
 			ZeroMemory(&mbp, sizeof(MSGBOXPARAMS));
 			mbp.cbSize = sizeof(MSGBOXPARAMS);
 			mbp.hInstance = pluginHInstance;
 			mbp.lpszCaption = "About...";
 			mbp.lpszText = "[" PLUGIN_NAME " " PLUGIN_VERSION_STR"]\n"
 							"Extended analysis for static code \n\n"
 							"http://github.com/ThunderCls/xAnalyzer\n"
 							"Coded By : ThunderCls - 2018\n"
 							"Based on: APIInfo Plugin by mrfearless";
 			mbp.dwStyle = MB_USERICON | MB_OK;
 			mbp.lpszIcon = MAKEINTRESOURCE(IDI_ICON1);
 			MessageBoxIndirect(&mbp);
			break;
		
		// COMMANDS MENUS
		// ------------------------------------------------------------------------
		case MENU_ANALYZE_DISASM:
			DbgCmdExec("xanal exe");
			break;
		case MENU_ANALYZE_DISASM_FUNCT:
			DbgCmdExec("xanal function");
			break;
		case MENU_ANALYZE_DISASM_SELEC:
				DbgCmdExec("xanal selection");
			break;
		case MENU_REM_ANALYSIS_DISASM_SELEC:
			DbgCmdExec("xanalremove selection");
			break;
		case MENU_REM_ANALYSIS_DISASM_FUNCT:
			DbgCmdExec("xanalremove function");
			break;
		case MENU_REM_ANALYSIS_DISASM:
			DbgCmdExec("xanalremove exe");
			break;
		default:
			break;
    }
}

//--------------------------------------------------------------------------------------
//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	string faultyFile;
	string folder;
	int errorLine = -1;
	char message[MAX_COMMENT_SIZE] = "";

	GetCurrentDirectory(MAX_PATH, szCurrentDirectory);
	strcat_s(szCurrentDirectory, "\\");

	if (!LoadDefinitionFiles(folder, faultyFile, errorLine))
 	{
		if (errorLine != -1)
			sprintf_s(message, "[" PLUGIN_NAME "] Failed to load API definitions in file: \n%s - Line: %d\r\n"
 						"            Check the malformed file/line and try again...exiting plugin initialization!\r\n", faultyFile.c_str(), errorLine);
		else
			sprintf_s(message, "[" PLUGIN_NAME "] Failed to locate API definitions files.\r\n"
			"            Check that the folder: %s\r\n"
			"            and definition files are present and try again...exiting plugin initialization!\r\n", folder.c_str());

 		_plugin_logprintf(message);
 		return false;
 	}

	config_path = szCurrentDirectory + string("xanalyzer.ini");

	// this will make this functions to execute in a non gui thread
	_plugin_registercommand(pluginHandle, "xanal", cbExtendedAnalysis, true);
	_plugin_registercommand(pluginHandle, "xanalremove", cbExtendedAnalysisRemove, true);

    return true; //Return false to cancel loading the plugin.
}

//--------------------------------------------------------------------------------------
//Deinitialize your plugin data here (clearing menus optional).
bool pluginStop()
{
	_plugin_unregistercommand(pluginHandle, "xanal");
	_plugin_unregistercommand(pluginHandle, "xanalremove");

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
	ICONDATA anal_function_icon;
	ICONDATA anal_select_icon;
	ICONDATA anal_exe_icon;

	ICONDATA remove_exe_icon;
	ICONDATA remove_function_icon;
	ICONDATA remove_selection_icon;

	menu_icon.data = icon;
	menu_icon.size = sizeof(icon);

	anal_function_icon.data = anal_function;
	anal_function_icon.size = sizeof(anal_function);
	anal_exe_icon.data = anal_exe;
	anal_exe_icon.size = sizeof(anal_exe);
	anal_select_icon.data = anal_selection;
	anal_select_icon.size = sizeof(anal_selection);

	remove_exe_icon.data = exe_remove;
	remove_exe_icon.size = sizeof(exe_remove);
	remove_function_icon.data = function_remove;
	remove_function_icon.size = sizeof(function_remove);
	remove_selection_icon.data = selection_remove;
	remove_selection_icon.size = sizeof(selection_remove);

	LoadConfig();

	// plugin menu
	_plugin_menuseticon(hMenu, &menu_icon);
	_plugin_menuaddentry(hMenu, MENU_ANALYZE_AUTO, "&Automatic Analysis");
	_plugin_menuaddentry(hMenu, MENU_ANALYZE_EXT, "&Extended Analysis");
	_plugin_menuaddentry(hMenu, MENU_ANALYZE_UNDEF, "&Analyze Undefined Functions");
	_plugin_menuaddentry(hMenu, MENU_ANALYZE_TRACK_UNDEF, "&Function Smart Tracking");
	int clearprevmnu = _plugin_menuadd(hMenu, "Clear Previous Data");
	_plugin_menuaddentry(clearprevmnu, MENU_ANALYZE_CLEAR_CMTS, "User Comments");
	_plugin_menuaddentry(clearprevmnu, MENU_ANALYZE_CLEAR_LBLS, "User Labels");
	_plugin_menuaddentry(clearprevmnu, MENU_ANALYZE_CLEAR_ACMTS, "Auto Comments");	
	_plugin_menuaddentry(clearprevmnu, MENU_ANALYZE_CLEAR_ALBLS, "Auto Labels");
	_plugin_menuaddseparator(hMenu);
	_plugin_menuaddentry(hMenu, MENU_ABOUT, "&About...");
	
	// disasm window menu
	_plugin_menuseticon(hMenuDisasm, &menu_icon);
	_plugin_menuaddentry(hMenuDisasm, MENU_ANALYZE_DISASM_SELEC, "&Analyze Selection");
	_plugin_menuaddentry(hMenuDisasm, MENU_ANALYZE_DISASM_FUNCT, "&Analyze Function");
	_plugin_menuaddentry(hMenuDisasm, MENU_ANALYZE_DISASM, "&Analyze Executable");
	_plugin_menuaddseparator(hMenuDisasm);
	_plugin_menuaddentry(hMenuDisasm, MENU_REM_ANALYSIS_DISASM_SELEC, "&Remove analysis from selection");
	_plugin_menuaddentry(hMenuDisasm, MENU_REM_ANALYSIS_DISASM_FUNCT, "&Remove analysis from function");
	_plugin_menuaddentry(hMenuDisasm, MENU_REM_ANALYSIS_DISASM, "&Remove analysis from executable");

	// entries icons
	_plugin_menuentryseticon(pluginHandle, MENU_ANALYZE_DISASM_SELEC, &anal_select_icon);
	_plugin_menuentryseticon(pluginHandle, MENU_ANALYZE_DISASM_FUNCT, &anal_function_icon);
	_plugin_menuentryseticon(pluginHandle, MENU_ANALYZE_DISASM, &anal_exe_icon);
	_plugin_menuentryseticon(pluginHandle, MENU_REM_ANALYSIS_DISASM_SELEC, &remove_selection_icon);
	_plugin_menuentryseticon(pluginHandle, MENU_REM_ANALYSIS_DISASM_FUNCT, &remove_function_icon);
	_plugin_menuentryseticon(pluginHandle, MENU_REM_ANALYSIS_DISASM, &remove_exe_icon);

	// options state
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_EXT, conf.extended_analysis);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_UNDEF, conf.undef_funtion_analysis);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_AUTO, conf.auto_analysis);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_CLEAR_CMTS, conf.clear_usercomments);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_CLEAR_LBLS, conf.clear_userlabels);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_CLEAR_ACMTS, conf.clear_autocomments);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_CLEAR_ALBLS, conf.clear_autolabels);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_TRACK_UNDEF, conf.track_undef_functions);

}
//--------------------------------------------------------------------------------------