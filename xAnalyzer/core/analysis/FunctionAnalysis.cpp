#include "FunctionAnalysis.h"
#include "../AnalyzerHub.h"

FunctionAnalysis::FunctionAnalysis()
{
	SetAnalysisRange();
}

void FunctionAnalysis::RunAnalysis()
{
	// TODO: implement
	RemoveAnalysis();
	if (AnalyzerHub::pSettings.UndefFunctions)
	{
		RunLinearAnalysis();
	}

	RunFunctionAnalysis(this->startAddress); // get function line and xrefs
	AnalyzeByteRange();
}

void FunctionAnalysis::AnalyzeByteRange()
{
	
}

void FunctionAnalysis::RemoveAnalysis()
{
	// TODO: implement
	RemoveLoops(this->startAddress, this->endAddress);
	RemoveArguments(this->startAddress, this->endAddress);
	RemoveComments(this->startAddress, this->endAddress);
	RemoveXRefs(this->startAddress, this->endAddress);
	RemoveFunctions(this->startAddress, this->endAddress);

	this->xRefsAnalysisDone = false;
	this->ctrlFlowAnalysisDone = false;
	this->exceptionDirectoryAnalysisDone = false;
	this->linearAnalysisDone = false;
	
	GuiUpdateDisassemblyView();
}

void FunctionAnalysis::SetAnalysisRange()
{
	GetFunctionAddressRange(this->startAddress, this->endAddress, Script::Gui::Disassembly::SelectionGetStart());
}

void FunctionAnalysis::GetFunctionAddressRange(duint &startAddress, duint &endAddress, const duint selectedAddr)
{
	duint start = 0;
	duint end = 0;

	RunXRefsAnalysis(); // get references for function boundaries detection

	duint addrPointer = selectedAddr;
	duint entryPoint = Script::Module::EntryFromAddr(selectedAddr);
	duint sectionStart = Script::Memory::GetBase(selectedAddr);

	do
	{
		BASIC_INSTRUCTION_INFO bii;
		DbgDisasmFastAt(addrPointer, &bii);

		if (start == 0)
		{
			// do backward disassembling (using xrefs) in order to find the beginning of the function
			// backtrace until a reference, ep or the beginning of the code section is reached
			if (IsProlog(&bii) || (addrPointer == entryPoint) || (addrPointer == sectionStart))
			{
				start = addrPointer;
				addrPointer = selectedAddr; // reset the pointer to the select address
			}
			else
			{
				addrPointer--;
			}
		}
		else
		{
			// do forward disassembling in order to find the end of the function
			if (IsEpilog(&bii))
			{
				end = addrPointer;
			}
			else
			{
				addrPointer += bii.size;
			}
		}

		memset(&bii, 0, sizeof(BASIC_INSTRUCTION_INFO));
	} while (start == 0 || end == 0);

	startAddress = start;
	endAddress = end;
}