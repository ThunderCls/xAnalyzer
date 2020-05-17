#include "AnalyzerCore.h"
#include "AnalyzerHub.h"
#include "Plugin.h"
#include "pe/PEParser.h"
#include "analysis/SelectionAnalysis.h"
#include "analysis/FunctionAnalysis.h"
#include "analysis/ModuleAnalysis.h"
#include <ctime>

AnalyzerCore::AnalyzerCore() = default;
AnalyzerCore::~AnalyzerCore() = default;

void AnalyzerCore::BuildProperAnalysisObject()
{
	switch (AnalyzerHub::analysisType)
	{
		case AnalyzerHub::TypeSelection:
			this->analysis = std::make_unique<SelectionAnalysis>();
			break;

		case AnalyzerHub::TypeFunction:
			this->analysis = std::make_unique<FunctionAnalysis>();
			break;

		case AnalyzerHub::TypeModule:
			this->analysis = std::make_unique<ModuleAnalysis>();
			break;

		case AnalyzerHub::TypeNone:
			this->analysis = nullptr;
			break;
	}
}

void AnalyzerCore::RunAnalysis()
{
	GuiAddLogMessage("[xAnalyzer]: Doing analysis, please wait...\r\n");
	clock_t start_t = clock();
	
	BuildProperAnalysisObject();
	if (this->analysis != nullptr)
	{
		this->analysis->RunAnalysis();
	}

	clock_t end_t = clock();
	std::string message("[xAnalyzer]: Analysis completed in " + std::to_string(static_cast<double>(end_t - start_t) / CLOCKS_PER_SEC) + " secs\r\n");
	GuiAddLogMessage(message.c_str());
	ShowAnalysisSummary();
	GuiAddStatusBarMessage(message.c_str());
}

void AnalyzerCore::RemoveAnalysis()
{
	GuiAddLogMessage("[xAnalyzer]: Removing analysis, please wait...\r\n");
	GuiAddStatusBarMessage("[xAnalyzer]: Removing analysis, please wait...\r\n");
	
	BuildProperAnalysisObject();
	if (this->analysis != nullptr)
	{
		this->analysis->RemoveAnalysis();
	}

	GuiAddLogMessage("[xAnalyzer]: Analysis removed successfully!\r\n");
	GuiAddStatusBarMessage("[xAnalyzer]: Analysis removed successfully!\r\n");
}

void AnalyzerCore::ShowAnalysisSummary()
{	
	// TODO: implement
	// Use Analysis::AnalysisReport
}


