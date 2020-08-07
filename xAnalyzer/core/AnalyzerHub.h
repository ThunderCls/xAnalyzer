#pragma once

#ifndef ANALYZERHUB_H
#define ANALYZERHUB_H

#ifdef ANALYZERHUB_H
#define HUB_EXPIMP extern "C" __declspec(dllexport)
#else
#define HUB_EXPIMP extern "C" __declspec(dllimport)
#endif

#include "Plugin.h"
#include <memory>

//plugin data
#define PLUGIN_NAME_LEN 255
#define PLUGIN_VERSION_LEN 16

namespace AnalyzerHub
{
	const char* const PluginName = "xAnalyzer";
	const char* const PluginVersionStr = "3.0";
	const int PluginVersionInt = 3;

	typedef enum
	{
		TypeNone = 0,
		TypeSelection,
		TypeFunction,
		TypeSection
	}AnalysisType;
	extern AnalysisType analysisType;
	
	typedef enum
	{
		ModeNone = 0,
		ModeAnalyze,
		ModeRemove
	}AnalyzerMode;
	extern AnalyzerMode analyzerMode;
	
	typedef enum
	{
		TypeCommentNone = 0,
		TypeUserComment,
		TypeAutoComment
	}CommentType;

	typedef struct
	{		
		bool AutoAnalysis;
		bool PreliminaryAnalysis;
		bool UndefFunctions;
		bool ClearUsercomments;
		bool ClearAutocomments;
		bool ClearUserlabels;
		bool ClearAutolabels;
		CommentType AnnotationType;
	}PluginSettings;
	extern PluginSettings pSettings;
	
	// --------------------------------------------------------
	// plugin exported functions start
	// --------------------------------------------------------
	HUB_EXPIMP void StartAnalyzer();
	HUB_EXPIMP void GetCoreVersionString(char *versionString);
	HUB_EXPIMP int GetCoreVersionInt();
	HUB_EXPIMP void GetCorePluginName(char *nameString);
	HUB_EXPIMP void SetAnalysisType(AnalysisType pAnalysisType);
	HUB_EXPIMP void SetAnalyzerMode(AnalyzerMode pAnalyzerMode);
	HUB_EXPIMP void SetHubSettings(const PluginSettings *ppSettings);
	/*HUB_EXPIMP AnalysisType GetAnalysisType();
	HUB_EXPIMP AnalyzerMode GetAnalyzerMode();
	HUB_EXPIMP PluginSettings* GetHubSettings();*/	
	// --------------------------------------------------------
	// plugin exported functions end
	// --------------------------------------------------------


	// --------------------------------------------------------
	// plugin internal functions start
	// --------------------------------------------------------



	// --------------------------------------------------------
	// plugin internal functions end
	// --------------------------------------------------------

}

#endif