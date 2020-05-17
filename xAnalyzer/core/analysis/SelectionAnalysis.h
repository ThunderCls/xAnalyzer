#pragma once
#include "Analysis.h"

class SelectionAnalysis : public Analysis
{
public:
	SelectionAnalysis();
	virtual ~SelectionAnalysis() = default;
	
	void RunAnalysis() override;
	void RemoveAnalysis() override;	
	
private:
	void SetAnalysisRange();
	void GetInstructionAddressRange(duint &startAddress, duint &endAddress, const duint startSelection, const duint endSelection);
	void ProcessVbFunctionCalls(const duint startAddr, const duint size = 0);
	void AnalyzeByteRange() override;
};
