#include "Analysis.h"
#include "../AnalyzerHub.h"
#include "../entropy/Entropy.h"
#include "../AnalyzerCore.h"
#include "../data/ApiDefinition.h"
#include <regex>

Analysis::Analysis(const char* exePath)
{
	this->startAddress = 0;
	this->endAddress = 0;

	this->xRefsAnalysisDone = false;
	this->ctrlFlowAnalysisDone = false;
	this->exceptionDirectoryAnalysisDone = false;
	this->linearAnalysisDone = false;

	this->IsVB = IsVisualBasic();
	this->mainModuleName.assign(exePath);
}

void Analysis::RemoveLoops(const duint startAddress, const duint endAddress)
{
	duint loopStart = 0;
	duint loopEnd = 0;
	
	if (startAddress == 0 && endAddress == 0)
	{
		DbgCmdExecDirect("loopclear");
	}
	else
	{
		duint ptrIndex = startAddress;
		do
		{
			BASIC_INSTRUCTION_INFO bii;
			DbgDisasmFastAt(ptrIndex, &bii);

			DbgLoopGet(0, ptrIndex, &loopStart, &loopEnd);
			if (loopStart != 0)
			{
				DbgLoopDel(0, loopStart);
				ptrIndex = loopEnd; // jump to the end of the loop
				DbgDisasmFastAt(ptrIndex, &bii);
			}

			loopStart = 0;
			loopEnd = 0;
			ptrIndex += bii.size;
		} while (ptrIndex < endAddress);
	}
}

void Analysis::RemoveArguments(duint startAddress, duint endAddress)
{
	if (startAddress == 0 || endAddress == 0)
	{
		return;
	}

	Script::Argument::DeleteRange(startAddress, endAddress, true); // clear all arguments
}

void Analysis::RemoveComments(duint startAddress, duint endAddress)
{
	if (AnalyzerHub::pSettings.ClearUsercomments)
		DbgClearCommentRange(startAddress, endAddress + 1);
	if (AnalyzerHub::pSettings.ClearUserlabels)
		DbgClearLabelRange(startAddress, endAddress + 1);
	if (AnalyzerHub::pSettings.ClearAutocomments)
		DbgClearAutoCommentRange(startAddress, endAddress);	// clear autocomments (not user regular comments)
	if (AnalyzerHub::pSettings.ClearAutolabels)
		DbgClearAutoLabelRange(startAddress, endAddress); // clear autolabels (not user regular labels)
}

void Analysis::RemoveFunctions(const duint startAddress, const duint endAddress)
{
	if (startAddress == 0 && endAddress == 0)
	{
		Script::Function::Clear();
		//DbgCmdExecDirect("functionclear");
	}
	else
	{
		Script::Function::DeleteRange(startAddress, endAddress, true);
	}
}

void Analysis::RemoveXRefs(const duint startAddress, const duint endAddress)
{
	// x64dbg doesn't expose an XrefClear() or XrefDelRange() method
	// TODO: implement a workaround or modify the plugin sdk to export these functions
	//if (startAddress == 0 && endAddress == 0)
	//{
	//	Script::References::Clear();
	//}
	//else
	//{		
	//	Script::References::DeleteRange(startAddress, endAddress, true);
	//}
}

bool Analysis::IsVisualBasic()
{
	if (Script::Module::EntryFromName("msvbvm60") != 0)
	{
		return true;
	}
	
	if (Script::Module::EntryFromName("msvbvm50") != 0)
	{
		return true;
	}
	
	return false;
}

bool Analysis::IsProlog(const BASIC_INSTRUCTION_INFO &instruction)
{
	XREF_INFO xref;
	if (DbgXrefGet(instruction.addr, &xref) && xref.refcount > 0)
	{
		for (duint i = 0; i < xref.refcount; i++)
		{
			// at least one reference which is not a jump
			if (xref.references[i].type != XREF_JMP)
			{
				return true;
			}
		}
	}

	return false;
}

bool Analysis::IsEpilog(const BASIC_INSTRUCTION_INFO &instruction)
{
	const char* retInstruction = "ret";
	return (strncmp(instruction.instruction, retInstruction, sizeof(*retInstruction)) == 0);
}

void Analysis::AnalyzeBytesRange(const duint startRange, const duint endRange)
{
	std::string mainModule = StringUtils::FileFromPath(this->mainModuleName);
	duint functionStartAddress = 0;
	duint currentAddress = startRange;
	while (currentAddress <= endRange)
	{
		// TODO: implement/uncomment ?. Keep in mind locks for when using multi-threaded analysis
		//// PROGRESS PERCENTAGE UPDATE
		//// --------------------------------------------------------------------------------------
		//progress = (actual_progress * 100) / total_progress;
		//sprintf_s(progress_perc, _countof(progress_perc), "[xAnalyzer]: Doing extended analysis...%d%%\r\n", progress);
		//GuiAddStatusBarMessage(progress_perc);
		//// --------------------------------------------------------------------------------------
		
		BASIC_INSTRUCTION_INFO instruction;
		DbgDisasmFastAt(currentAddress, &instruction);
		bool isProlog = IsProlog(instruction);
		bool isEpilog = IsEpilog(instruction);

		if (instruction.call)
		{
			if (instruction.branch)
			{
				// -------------------------------------------------------------
				// CALL INSTRUCTION
				// -------------------------------------------------------------
				ProcessCallInstruction(mainModule, currentAddress, instruction);
			}
			else
			{
				// -------------------------------------------------------------
				// ARGUMENT INSTRUCTION
				// -------------------------------------------------------------
				ProcessArgumentInstruction(mainModule, currentAddress, instruction);
			}
		}
		else if (instruction.branch)
		{
			isProlog = false; // noot a prolog instruction (no jumps in prolog)
			// -------------------------------------------------------------
			// JMP INSTRUCTION
			// -------------------------------------------------------------
			ProcessJumpInstruction(currentAddress, functionStartAddress, instruction);
		}

		currentAddress += instruction.size;
		
	}
}

void Analysis::ProcessCallInstruction(const std::string& mainModule, const duint currentAddress, const BASIC_INSTRUCTION_INFO& instruction)
{
	// TODO: plugin api doesn't have functions to get autocomments/autolabels
	// if I implement the function in the plugin api I can use the code below
	// instead of the function GuiGetDisassembly which is performance  heavy

	/*DISASM_INSTR instr = { 0 };
	DbgDisasmAt(CurrentAddress, &instr);
	DbgGetAutoCommentAt(instr.arg->value, szDisasmText);*/

	char callGuiDisasmText[GUI_MAX_DISASSEMBLY_SIZE] = { 0 };

	// --------------------------------------------------------------------
	// This block of code changes when autolabels reading function is implemented in the plugin SDK
	// --------------------------------------------------------------------
	// instead of extracting the function name from the GUI line I could
	// just read the autolabel directly from the call/call+jmp destination 
	// without having to parse it
	GuiGetDisassembly(currentAddress, callGuiDisasmText);
	std::string functName = ExtractFunctionName(callGuiDisasmText); // extract the function name from the current line
	if (functName.empty())
	{
		char destDisasmText[GUI_MAX_DISASSEMBLY_SIZE] = { 0 };

		GuiGetDisassembly(instruction.addr, destDisasmText);
		functName = ExtractFunctionName(destDisasmText); // extract the function name from the call scheme: CALL -> JMP -> ? -> API
	}
	// --------------------------------------------------------------------

	if (!functName.empty())
	{
		BASIC_INSTRUCTION_INFO destInstruction;
		DbgDisasmFastAt(instruction.addr, &destInstruction);
		if (destInstruction.branch) // call => api/call => jump* => api
		{
			Script::Argument::ArgumentInfo argument = { 0 };
			argument.manual = true;
			argument.rvaEnd = currentAddress - Script::Module::BaseFromAddr(currentAddress);
			
			std::string searchModule = GetFunctionModule(instruction.addr);
			if (searchModule.empty())
				return;
			
			// if it's the main module search recursive
			bool recursive = mainModule == searchModule;
			ApiDefinition apiDefinition;
			if (dataAccess.FindApiDefinition(searchModule, functName, apiDefinition, recursive))
			{
				SetFunctionDefinition(argument, apiDefinition, instruction);
			}
			else
			{
				if (AnalyzerHub::pSettings.UndefFunctions)
				{
					// analyze undefined functions
					if (!recursive)
					{

					}
				}
			}
		}		
	}
}

void Analysis::SelectArgumentsFromStack(int parameterCount, std::vector<Parameter>& args)
{
	int currentParam = 0;
	while (!parameterStack.empty())
	{
		Parameter parameter = parameterStack.top(); // get last/first element
#ifndef _WIN64
		if (IsValidParameter(&parameter, parameterCount))
		{
#endif
			args.insert(args.begin() + currentParam, parameter);
			currentParam++;
#ifndef _WIN64
		}
#endif
		parameterStack.pop(); // remove element on top
	}
}

void Analysis::SetFunctionDefinition(Script::Argument::ArgumentInfo& argument, const ApiDefinition apiDefinition, BASIC_INSTRUCTION_INFO instruction)
{
	int parameterCount = apiDefinition.parameters.size();
	if (parameterCount == 0)
		return;

	// create the arguments list
	std::vector<Parameter> parameterVector;
	SelectArgumentsFromStack(parameterCount, parameterVector);
	if (parameterCount <= parameterVector.size()) // make sure we have enough in our stack to check for parameters
	{
		// TODO: increment the "defined calls" summary variable.
		argument.instructioncount = parameterCount + 1; // length of the argument + 1 including CALL
		int parameterNumber = 1;
		duint lowerMemoryRvaAddress = 0;
		argument.rvaStart = parameterVector[0].address - Script::Module::BaseFromAddr(parameterVector[0].address); // first argument line
		while (parameterNumber <= parameterCount)
		{
			Parameter parameter;
			SelectParameter(parameterNumber, parameterVector, parameter); // get arguments in order. 64 bits may have different argument order
			if (parameter.address > 0)
			{
				lowerMemoryRvaAddress = parameter.address - Script::Module::BaseFromAddr(parameter.address);
				if (lowerMemoryRvaAddress < argument.rvaStart)
				{
					argument.rvaStart = lowerMemoryRvaAddress;
				}

				if (apiDefinition.parameters.size() >= (parameterNumber - 1))
				{
					ApiDefinition::DefParameter defParameter = apiDefinition.parameters[parameterNumber - 1];
					SetComment(parameter, defParameter);
				}					
			}

			parameterNumber++;
		}

		Script::Argument::Add(&argument); // set arguments of current call
	}
}

void Analysis::SetComment(const Parameter& parameter, const ApiDefinition::DefParameter& defParameter, bool isCall)
{
	// TODO: increment the "total comments" summary variable.
	// procSummary.totalCommentsSet++; // get record of comments amount
	
	if (isCall) // set the API name definition comment
	{
		// TODO: choose the type of comment (auto/manual) to put according to the settings
		DbgSetCommentAt(parameter.address, defParameter.name.c_str());
		//DbgSetAutoCommentAt()
		return;
	}

	
}

// TODO: rethink this method to make it more efficient/better
void Analysis::SelectParameter(int parameterNumber, std::vector<Parameter>& parameterVector, Parameter& parameter)
{
	// NOTE: should include lower bits registers for R8, R9?
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/x64-architecture
	int removeParamIndex = 0;

#ifdef _WIN64
	switch (parameterNumber)
	{
	case 1:
		for (int parameterIndex = 0; parameterIndex < parameterVector.size(); parameterIndex++)
		{
			Parameter currentParam = parameterVector[parameterIndex];
			std::string parameterMnemonic = currentParam.disasmInstr.arg[0].mnemonic;
			if (parameterMnemonic.compare(0, 3, "rcx") == 0 ||
				parameterMnemonic.compare(0, 3, "ecx") == 0 ||
				parameterMnemonic.compare(0, 2, "cx") == 0 ||
				parameterMnemonic.compare(0, 2, "ch") == 0 ||
				parameterMnemonic.compare(0, 2, "cl") == 0)
			{
				parameter = currentParam;
				removeParamIndex = parameterIndex;
				break;
			}
		}
		break;
	case 2:
		for (int parameterIndex = 0; parameterIndex < parameterVector.size(); parameterIndex++)
		{
			Parameter currentParam = parameterVector[parameterIndex];
			std::string parameterMnemonic = currentParam.disasmInstr.arg[0].mnemonic;
			if (parameterMnemonic.compare(0, 3, "rdx") == 0 ||
				parameterMnemonic.compare(0, 3, "edx") == 0 ||
				parameterMnemonic.compare(0, 2, "dx") == 0 ||
				parameterMnemonic.compare(0, 2, "dh") == 0 ||
				parameterMnemonic.compare(0, 2, "dl") == 0)
			{
				parameter = currentParam;
				removeParamIndex = parameterIndex;
				break;
			}
		}
		break;
	case 3:
		for (int parameterIndex = 0; parameterIndex < parameterVector.size(); parameterIndex++)
		{
			Parameter currentParam = parameterVector[parameterIndex];
			std::string parameterMnemonic = currentParam.disasmInstr.arg[0].mnemonic;
			if (parameterMnemonic.compare(0, 2, "r8") == 0)
			{
				parameter = currentParam;
				removeParamIndex = parameterIndex;
				break;
			}
		}
		break;
	case 4:
		for (int parameterIndex = 0; parameterIndex < parameterVector.size(); parameterIndex++)
		{
			Parameter currentParam = parameterVector[parameterIndex];
			std::string parameterMnemonic = currentParam.disasmInstr.arg[0].mnemonic;
			if (parameterMnemonic.compare(0, 2, "r9") == 0)
			{
				parameter = currentParam;
				removeParamIndex = parameterIndex;
				break;
			}
		}
		break;
	default: // the rest of stack-related arguments
		// parse expression rsp+XXX and select the proper argument order: 
		// [rsp+20] -> 1
		// [rsp+28] -> 2
		// [rsp+30] -> 3
		// ...etc
		removeParamIndex = GetParameterIndex(parameterNumber, parameterVector);
		if (removeParamIndex >= parameterVector.size())
			removeParamIndex = 0;

		parameter = parameterVector[removeParamIndex];
		break;
	}

	// take out the parameter from list
	if (!parameterVector.empty())
	{
		parameterVector.erase(parameterVector.begin() + removeParamIndex); 
	}

#else

	// parse expression esp+XXX and select the proper argument order: 
	// [esp] -> 1
	// [esp+4] -> 2
	// [esp+8] -> 3
	// [esp+C] -> 4
	// ...etc
	duint index = GetParameterIndex(parameterNumber, parameterVector);
	if (index >= parameterVector.size())
		index = 0;

	parameter = parameterVector[index];

#endif
}

int Analysis::GetParameterIndex(int parameterNumber, const std::vector<Parameter> parameterVector)
{
	parameterNumber--; // set proper zero based index
	const std::regex re(R"(esp|rsp)\+(.*)"); // pattern like esp+xxx, rsp+xxx
	std::cmatch cm;
	
	for (int paramIndex = 0; paramIndex < parameterVector.size(); paramIndex++)
	{
		Parameter parameter = parameterVector[paramIndex];
		std::string paramMnemonic = parameter.disasmInstr.arg[0].mnemonic; // arg[0] is the destination/left side of instruction
		// TODO: add ebp support when using different types of calling conventions (stdcall with EBP) options
		bool foundmatch = std::regex_search(paramMnemonic.c_str(), cm, re);
		if (foundmatch && cm.size() == 2)
		{			
			// get value of displacement
			std::string stackDisplacementStr = cm[1].str().c_str(); // second group of regex contains the string value
			if (!stackDisplacementStr.empty())
			{
				duint stackDisplacementVal = StringUtils::ToInt(stackDisplacementStr);					
				if (stackDisplacementVal == parameterNumber * sizeof(duint)) // get displacement index
				{
					return paramIndex;
				}
			}
		}
	}

	// if not a stack pointer param then always return the current parameter order
	return parameterNumber;
}

#ifndef _WIN64
bool Analysis::IsValidParameter(const Parameter* parameter, int parameterCount)
{
	if (parameter->disasmInstr.argcount < 2)
	{
		return false;
	}
	
	std::string paramInstruction = parameter->disasmInstr.instruction;
	auto mov = paramInstruction.find("mov"); // mov instructions pass
	if (mov != std::string::npos)
	{
		return true;
	}
	
	std::string paramMnemonic = parameter->disasmInstr.arg[0].mnemonic; // arg[0] is the destination/left side of instruction
	// TODO: add ebp support when using different types of calling conventions (stdcall with EBP) options
	auto stackPtr = paramMnemonic.find("esp"); // esp based stack pointer pass
	if (stackPtr == std::string::npos)
	{
		return false;
	}

	auto ptrDisplacement = paramMnemonic.find("+");
	if (ptrDisplacement == std::string::npos)
	{
		return true; // no displacement
	}

	// get value of displacement
	std::string stackDisplacementStr = paramMnemonic.substr(ptrDisplacement, paramMnemonic.size());
	if (!stackDisplacementStr.empty())
	{
		duint stackDisplacementVal = StringUtils::ToInt(stackDisplacementStr);
		// displacement can't be greater than the amount of args space in stack
		if ((stackDisplacementVal + sizeof(duint)) / sizeof(duint) <= parameterCount)
			return true;
	}

	return false;
}
#endif

void Analysis::ProcessArgumentInstruction(const std::string& mainModule, duint currentAddress,
	const BASIC_INSTRUCTION_INFO& instruction)
{
	// TODO: implement
	// NOTE: Only for x86
	// process possible argument instruction according to the type of call convention selected in the options
	// Pascal/Visual C++/Std/Stack-Ebp, etc
	
	// NOTE: For x64 there's only one calling convention

	/*DISASM_INSTR parameter = { 0 };
	DbgDisasmAt(currentAddress, &parameter);
	parameterStack.push(parameter)*/
	
}

void Analysis::ProcessJumpInstruction(duint currentAddress, duint functionStartAddress, const BASIC_INSTRUCTION_INFO& instruction)
{
	// TODO: implement
	// ClearStack(stackInstructions); // Remove restriction of no jumps between arguments by commenting this line

	// loop detection
	// check if jmp instruction belongs to a loop block
	if (functionStartAddress != 0 && instruction.addr >= functionStartAddress && instruction.addr < currentAddress)
	{
		LoopInfo loop;
		loop.startAddress = instruction.addr;
		loop.endAddress = currentAddress;

		loopStack.push(loop);
	}
}

std::string Analysis::GetFunctionModule(duint instructionAddr)
{	
	const std::string vc = "msvcrxx";
	const std::string vcrt = "vcruntime";
	const std::string ucrt = "ucrtbase";

	char functModuleName[MAX_MODULE_SIZE] = { 0 };
	
	Script::Module::NameFromAddr(DbgGetBranchDestination(instructionAddr), functModuleName);
	std::string moduleName = StringUtils::FileFromPath(functModuleName, true);

	// check if vc++ runtime lib
	if (!moduleName.empty() && 
		moduleName.substr(0, 5) == vc ||
		moduleName == vcrt || moduleName == ucrt)
	{
		return vc;
	}

	return moduleName;
}



std::string Analysis::ExtractFunctionName(const char* callText)
{
	// TODO: implement with regex
	return "";
}
