#include "SelectionAnalysis.h"

SelectionAnalysis::SelectionAnalysis()
{
	SetAnalysisRange();
}

void SelectionAnalysis::RunAnalysis()
{
	// TODO: implement
}

void SelectionAnalysis::RemoveAnalysis()
{
	// TODO: implement
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