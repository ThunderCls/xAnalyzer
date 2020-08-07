#pragma once
#include "Analysis.h"

class FunctionAnalysis : public Analysis
{
public:
	FunctionAnalysis(const char *exePath);
	virtual ~FunctionAnalysis() = default;
	
	void RunAnalysis() override;
	void RemoveAnalysis() override;
	
private:
	void SetAnalysisRange();
	void GetFunctionAddressRange(duint &startAddress, duint &endAddress, const duint selectedAddr);
	void ProcessVbFunctionCalls(const duint startAddr, const duint size = 0);
};
