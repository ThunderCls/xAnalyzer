#include "SelectionAnalysis.h"
#include "../AnalyzerCore.h"

SelectionAnalysis::SelectionAnalysis(const char *exePath) : Analysis(exePath)
{
	SetAnalysisRange();
}

void SelectionAnalysis::RunAnalysis()
{
	// TODO: implement
	RemoveAnalysis();
	if (AnalyzerHub::pSettings.UndefFunctions)
	{
		RunLinearAnalysis();
	}

	AnalyzeBytesRange(this->startAddress, this->endAddress);
}

void SelectionAnalysis::RemoveAnalysis()
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

void SelectionAnalysis::SetAnalysisRange()
{
	duint end = 0;
	duint start = 0;

	if (!Script::Gui::Disassembly::SelectionGet(&start, &end))
	{
		return;
	}

	GetInstructionAddressRange(this->startAddress, this->endAddress, start, end);
}

void SelectionAnalysis::GetInstructionAddressRange(duint &startAddress, duint &endAddress, const duint startSelection, const duint endSelection)
{
	if (startSelection == 0 || endSelection == 0)
	{
		return;
	}

	duint ptrIndex = startSelection;
	do
	{
		BASIC_INSTRUCTION_INFO bii;
		DbgDisasmFastAt(ptrIndex, &bii);

		if (ptrIndex + bii.size > endSelection)
			break;

		ptrIndex += bii.size;
	} while (ptrIndex < endSelection);

	startAddress = startSelection;
	endAddress = ptrIndex;
}