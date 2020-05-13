#include "ModuleAnalysis.h"
#include "PEParser.h"

ModuleAnalysis::ModuleAnalysis()
{
	SetAnalysisRange();
}

void ModuleAnalysis::RunAnalysis()
{
	// TODO: implement
}

void ModuleAnalysis::RemoveAnalysis()
{
	// TODO: implement
}

void ModuleAnalysis::SetAnalysisRange()
{
	// TODO: test method for x64	
	char filePath[MAX_PATH] = {};
	if (!Script::Module::PathFromAddr(Script::Gui::Disassembly::SelectionGetStart(), filePath))
	{
		return;
	}

	PEParser pe(filePath);
	if (!pe.ReadPEData())
	{
		return;
	}

	pe.FindCodeSectionRange(this->startAddress, this->endAddress);
}

