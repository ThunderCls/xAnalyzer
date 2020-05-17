#pragma once

#include <sstream>
#include "../Plugin.h"
#include "../utils/StringUtils.h"

class Analysis
{
public:
	Analysis();
	virtual void RemoveAnalysis() = 0;
	virtual void RunAnalysis() = 0;
	
protected:
	~Analysis() = default;

	std::string mainModuleName;
	duint startAddress;
	duint endAddress;

	typedef struct
	{
		int DefinedCalls;
		int UndefCalls;
		int VbFunctionCalls;
		int Loops;
		int TotalCommentsSet;
		int TotalLabelsSet;
	}AnalysisReport;
	
	bool IsVB;
	bool xRefsAnalysisDone;
	bool ctrlFlowAnalysisDone;
	bool exceptionDirectoryAnalysisDone;
	bool linearAnalysisDone;

	void RunFunctionAnalysis(const duint startAddress)
	{
		std::string cmd("analr " + StringUtils::ToHex(startAddress));
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

	void RemoveLoops(const duint startAddress = 0, const duint endAddress = 0);
	void RemoveArguments(const duint startAddress, const duint endAddress);
	void RemoveComments(const duint startAddress, const duint endAddress);
	void RemoveFunctions(const duint startAddress = 0, const duint endAddress = 0);
	void RemoveXRefs(const duint startAddress = 0, const duint endAddress = 0);
	
	bool IsProlog(const BASIC_INSTRUCTION_INFO *bii);
	bool IsEpilog(const BASIC_INSTRUCTION_INFO *bii);
	bool IsVisualBasic();
	
	virtual void AnalyzeByteRange() = 0;
};
