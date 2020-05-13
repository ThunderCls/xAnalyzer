#pragma once
#include "Analysis.h"

class SelectionAnalysis : public Analysis
{
public:
	SelectionAnalysis();
	~SelectionAnalysis();	

	void RunAnalysis() override;
	void RemoveAnalysis() override;	
	
private:
	void SetAnalysisRange() override;
	void GetInstructionAddressRange(duint &startAddress, duint &endAddress, const duint startSelection, const duint endSelection);
};
