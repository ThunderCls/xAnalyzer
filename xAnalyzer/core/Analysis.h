#pragma once

#include <windows.h>
#include <sstream>
#include "Plugin.h"
#include "AnalyzerHub.h"

class Analysis
{
public:
	Analysis();
	~Analysis();

	virtual void RemoveAnalysis();
	virtual void RunAnalysis();
	
protected:
	duint startAddress;
	duint endAddress;

	bool xRefsAnalysisDone;
	bool ctrlFlowAnalysisDone;
	bool exceptionDirectoryAnalysisDone;
	bool linearAnalysisDone;

	void RunFunctionAnalysis(const duint startAddress)
	{
		std::stringstream stream;
		stream << std::hex << startAddress;

		std::string cmd("analr " + stream.str());
		DbgCmdExecDirect(cmd.c_str());

		// this cmd erases the current references
		this->xRefsAnalysisDone = false;
		RunXRefsAnalysis();
	}

	void RunXRefsAnalysis()
	{
		if (!this->xRefsAnalysisDone)
		{
			DbgCmdExecDirect("analx");
			this->xRefsAnalysisDone = true;
		}
	}

	void RunCtrlFlowAnalysis()
	{
		if (!this->ctrlFlowAnalysisDone)
		{
			DbgCmdExecDirect("cfanal");
			this->ctrlFlowAnalysisDone = true;
		}
	}

	void RunExceptionDirectoryAnalysis()
	{
		if (!this->exceptionDirectoryAnalysisDone)
		{
			DbgCmdExecDirect("exanal");
			this->exceptionDirectoryAnalysisDone = true;
		}
	}

	void RunLinearAnalysis()
	{
		if (!this->linearAnalysisDone)
		{
			DbgCmdExecDirect("anal");
			this->linearAnalysisDone = true;
		}
	}

	virtual void RunPreliminaryAnalysis();
	virtual void SetAnalysisRange();

	bool IsProlog(const BASIC_INSTRUCTION_INFO *bii);
	bool IsEpilog(const BASIC_INSTRUCTION_INFO *bii);
};
