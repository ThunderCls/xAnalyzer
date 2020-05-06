#pragma once

#ifndef ANALYZERCORE_H
#define ANALYZERCORE_H

#include "Plugin.h"

class AnalyzerCore
{
public:
	AnalyzerCore();
	~AnalyzerCore();

	void Run();
	
private:
	duint startAddress;
	duint endAddress;
	
	void GetAnalysisAddressRange();
	void Execute();
};

#endif
