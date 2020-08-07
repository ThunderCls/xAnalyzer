#pragma once

#include "Analysis.h"

class SectionAnalysis : public Analysis
{
public:
	SectionAnalysis(const char* exePath);
	virtual ~SectionAnalysis() = default;
	
	void RunAnalysis() override;
	void RemoveAnalysis() override;
	
private:
	void SetAnalysisRange();
	void RunDbgAnalysisCmds();
	bool RunPreliminaryAnalysis();
	void ProcessVbFunctionCalls(const duint startAddr, const duint size = 0);
};
