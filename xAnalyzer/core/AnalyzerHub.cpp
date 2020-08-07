#include "AnalyzerHub.h"
#include "AnalyzerCore.h"
#include "Plugin.h"
#include <psapi.h>
#include <ctime>
#include <string>

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
	AnalysisType analysisType = TypeNone;
	AnalyzerMode analyzerMode = ModeNone;
	PluginSettings pSettings = {};

	/// <summary>
	/// Launch a main analyzer class instance
	/// </summary>
	/// <param name="pAnalysisType"></param>
	/// <param name="pAnalyzerMode"></param>
	/// <returns></returns>
	HUB_EXPIMP void StartAnalyzer()
	{
		AnalyzerCore Analyzer;		
		switch (analyzerMode)
		{
			case ModeAnalyze:
				Analyzer.RunAnalysis();
				break;

			case ModeRemove:
				Analyzer.RemoveAnalysis();
				break;
			
			case ModeNone:
				break;
		}		
	}

	/// <summary>
	/// Get the core version of the plugin as an integer
	/// </summary>
	/// <returns></returns>
	HUB_EXPIMP int GetCoreVersionInt()
	{
		return PluginVersionInt;
	}

	/// <summary>
	/// Get the core version of the plugin as a string
	/// </summary>
	/// <param name="versionString"></param>
	/// <returns></returns>
	HUB_EXPIMP void GetCoreVersionString(char *versionString)
	{
		strcpy_s(versionString, PLUGIN_VERSION_LEN, PluginVersionStr);
	}

	/// <summary>
	/// Get the core name of the plugin
	/// </summary>
	/// <param name="nameString"></param>
	/// <returns></returns>
	HUB_EXPIMP void GetCorePluginName(char *nameString)
	{
		strcpy_s(nameString, PLUGIN_NAME_LEN, PluginName);
	}

	/*HUB_EXPIMP AnalysisType GetAnalysisType()
	{
		return analysisType;
	}

	HUB_EXPIMP AnalyzerMode GetAnalyzerMode()
	{
		return analyzerMode;
	}

	HUB_EXPIMP PluginSettings* GetHubSettings()
	{
		return &pSettings;
	}*/

	HUB_EXPIMP void SetAnalysisType(const AnalysisType pAnalysisType)
	{
		analysisType = pAnalysisType;
	}

	HUB_EXPIMP void SetAnalyzerMode(const AnalyzerMode pAnalyzerMode)
	{
		analyzerMode = pAnalyzerMode;
	}

	HUB_EXPIMP void SetHubSettings(const PluginSettings *ppSettings)
	{
		pSettings = *ppSettings;
	}
	
}