#pragma once
#include "Analysis.h"

class FunctionAnalysis : public Analysis
{
public:
	FunctionAnalysis();
	~FunctionAnalysis();

	void RunAnalysis() override;
	void RemoveAnalysis() override;
	
private:
	void SetAnalysisRange() override;
	void GetFunctionAddressRange(duint &startAddress, duint &endAddress, const duint selectedAddr);
};
