#pragma once

#ifndef ANALYZERHUB_H
#define ANALYZERHUB_H

#ifdef ANALYZERHUB_H
#define HUB_EXPIMP extern "C" __declspec(dllexport)
#else
#define HUB_EXPIMP extern "C" __declspec(dllimport)
#endif

#include "Plugin.h"

//plugin data
#define PLUGIN_NAME_LEN 255
#define PLUGIN_VERSION_LEN 16

namespace AnalyzerHub
{
	const std::string PluginName = "xAnalyzer";
	const std::string PluginVersionStr = "3.0";
	const int PluginVersionInt = 3;

	typedef enum
	{
		TypeNone = 0,
		TypeSelection,
		TypeFunction,
		TypeModule
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
		bool undeFunctions;
		bool autoAnalysis;
		bool extendedAnalysis;
		bool clearUsercomments;
		bool clearAutocomments;
		bool clearUserlabels;
		bool clearAutolabels;
		bool smartTrack;
		CommentType commentType;
	}PluginSettings;
	extern PluginSettings pSettings;
	
	// --------------------------------------------------------
	// plugin exported functions start
	// --------------------------------------------------------
	HUB_EXPIMP void StartAnalyzer();
	HUB_EXPIMP duint GetModuleEntryPoint(const char *modName);
	HUB_EXPIMP void GetCoreVersionString(char *versionString);
	HUB_EXPIMP int GetCoreVersionInt();
	HUB_EXPIMP void GetCorePluginName(char *nameString);

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