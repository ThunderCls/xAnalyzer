#pragma once

#ifndef ANALYZERCORE_H
#define ANALYZERCORE_H

#include "Plugin.h"
#include "AnalyzerHub.h"
#include "Analysis.h"

class AnalyzerCore
{
public:
	AnalyzerCore();
	~AnalyzerCore();

	void RunAnalysis();
	void RemoveAnalysis();
	
private:
	std::unique_ptr<Analysis> analysis;
	void BuildProperAnalysisObject();
	void ShowAnalysisSummary();
};

#endif
