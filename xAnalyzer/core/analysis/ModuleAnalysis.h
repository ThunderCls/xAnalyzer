#pragma once

#include "Analysis.h"

class ModuleAnalysis : public Analysis
{
public:
	ModuleAnalysis();
	virtual ~ModuleAnalysis() = default;
	
	void RunAnalysis() override;
	void RemoveAnalysis() override;
	
private:
	void SetAnalysisRange();
	void RunDbgAnalysisCmds();
	void AnalyzeByteRange() override;
	void RunPreliminaryAnalysis();
	bool IsExecutablePacked();

	void ProcessVbFunctionCalls(const duint startAddr, const duint size = 0);
};
