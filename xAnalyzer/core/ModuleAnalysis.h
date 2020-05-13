#pragma once

#include "Plugin.h"
#include "Analysis.h"

class ModuleAnalysis : public Analysis
{
public:
	ModuleAnalysis();
	~ModuleAnalysis();

	void RunAnalysis() override;
	void RemoveAnalysis() override;
	
private:
	void SetAnalysisRange() override;	
};
