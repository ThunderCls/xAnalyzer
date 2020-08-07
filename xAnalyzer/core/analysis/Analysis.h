#pragma once

#include <sstream>
#include "../Plugin.h"
#include "../utils/StringUtils.h"
#include "../data/ApiDefinition.h"
#include "../data/DataAccess.h"
#include <stack>

class Analysis
{
public:
	typedef struct
	{
		int DefinedCalls;
		int UndefCalls;
		int VbFunctionCalls;
		int Loops;
		int TotalCommentsSet;
		int TotalLabelsSet;
	}AnalysisReport;

	typedef struct
	{
		duint startAddress;
		duint endAddress;
	}LoopInfo;
	
	Analysis(const char* exePath);
	~Analysis() = default;
	virtual void RemoveAnalysis() = 0;
	virtual void RunAnalysis() = 0;
	
protected:
	std::string mainModuleName;
	duint startAddress;
	duint endAddress;
	
	bool IsVB;
	bool xRefsAnalysisDone;
	bool ctrlFlowAnalysisDone;
	bool exceptionDirectoryAnalysisDone;
	bool linearAnalysisDone;

	//std::unordered_map<std::string, Utf8Ini*>::const_iterator apiDefPointer; // pointer to the current def file
	//std::unordered_map<std::string, Utf8Ini*> apiFiles; // map of main def files
	//std::unordered_map<std::string, Utf8Ini*> apiHFiles; // map of headers def files
	std::stack<LoopInfo> loopStack;

	typedef struct
	{
		duint address;
		DISASM_INSTR disasmInstr;
	}Parameter;
	
	std::stack<Parameter> parameterStack;
	DataAccess dataAccess;
	
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
#ifdef _WIN64
	void RunExceptionDirectoryAnalysis()
	{
		if (!this->exceptionDirectoryAnalysisDone)
		{
			DbgCmdExecDirect("exanal");
			this->exceptionDirectoryAnalysisDone = true;
		}
	}
#endif
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
	
	bool IsProlog(const BASIC_INSTRUCTION_INFO &instruction);
	bool IsEpilog(const BASIC_INSTRUCTION_INFO &instruction);
	bool IsVisualBasic();

	void ProcessCallInstruction(const std::string& mainModule, duint currentAddress, const BASIC_INSTRUCTION_INFO& instruction);
	void SelectArgumentsFromStack(int parameterCount, std::vector<Parameter>& args);
	void ProcessArgumentInstruction(const std::string& mainModule, duint currentAddress, const BASIC_INSTRUCTION_INFO& instruction);
	void ProcessJumpInstruction(duint currentAddress, duint functionStartAddress, const BASIC_INSTRUCTION_INFO& instruction);
	void AnalyzeBytesRange(const duint startRange, const duint endRange);
	std::string ExtractFunctionName(const char* callText);
	std::string GetFunctionModule(duint instructionAddr);
	int GetParameterIndex(int parameterNumber, const std::vector<Parameter> parameterVector);
	void SelectParameter(int parameterNumber, std::vector<Parameter>& parameterVector, Parameter& parameter);
	void SetComment(const Parameter& parameter, const ApiDefinition::DefParameter& defParameter, bool isCall = false);
	void SetFunctionDefinition(Script::Argument::ArgumentInfo& argument, const ApiDefinition apiDefinition, BASIC_INSTRUCTION_INFO instruction);
	bool IsValidParameter(const Parameter* parameter, int parameterCount);
};
