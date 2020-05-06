#include "AnalyzerHub.h"
#include "AnalyzerCore.h"
#include "Plugin.h"
#include <psapi.h>

/// <summary>
/// Main entry function for a DLL file  - required.
/// </summary>
/// <param name="hinstDLL"></param>
/// <param name="fdwReason"></param>
/// <param name="lpvReserved"></param>
/// <returns></returns>
BOOL WINAPI DllMain(
	_In_ HINSTANCE hinstDLL,
	_In_ DWORD     fdwReason,
	_In_ LPVOID    lpvReserved
	)
{
	return TRUE;
}


namespace AnalyzerHub
{
	AnalysisType analysisType;
	AnalyzerMode analyzerMode;
	PluginSettings pSettings;

	/// <summary>
	/// Launch a main analyzer class instance
	/// </summary>
	/// <param name="pAnalysisType"></param>
	/// <param name="pAnalyzerMode"></param>
	/// <returns></returns>
	HUB_EXPIMP void StartAnalyzer()
	{
		AnalyzerCore Analyzer;
		Analyzer.Run();
	}

	/// <summary>
	/// Get the module entry point address
	/// </summary>
	/// <param name="moduleName">Module name</param>
	/// <returns>Entry point address</returns>
	HUB_EXPIMP duint GetModuleEntryPoint(const char *moduleName)
	{
		MODULEINFO modInfo = { 0 };
		wchar_t moduleBaseName[MAX_MODULE_SIZE] = L"";

		HMODULE base = (HMODULE)DbgModBaseFromName(moduleName);
		if (!base)
		{
			return 0;
		}

		PROCESS_INFORMATION *pi = TitanGetProcessInformation();
		if (pi == nullptr)
		{
			return 0;
		}

		GetModuleBaseName(pi->hProcess, base, moduleBaseName, MAX_MODULE_SIZE);
		GetModuleInformation(pi->hProcess, GetModuleHandle(moduleBaseName), &modInfo, sizeof(MODULEINFO));

		return reinterpret_cast<duint>(modInfo.EntryPoint);
	}

	/// <summary>
	/// Get the core version of the plugin as an integer
	/// </summary>
	/// <returns></returns>
	HUB_EXPIMP int GetCoreVersionInt()
	{
		return AnalyzerHub::PluginVersionInt;
	}

	/// <summary>
	/// Get the core version of the plugin as a string
	/// </summary>
	/// <param name="versionString"></param>
	/// <returns></returns>
	HUB_EXPIMP void GetCoreVersionString(char *versionString)
	{
		strcpy_s(versionString, PLUGIN_VERSION_LEN, AnalyzerHub::PluginVersionStr.c_str());
	}

	/// <summary>
	/// Get the core name of the plugin
	/// </summary>
	/// <param name="nameString"></param>
	/// <returns></returns>
	HUB_EXPIMP void GetCorePluginName(char *nameString)
	{
		strcpy_s(nameString, PLUGIN_NAME_LEN, AnalyzerHub::PluginName.c_str());
	}
	
}