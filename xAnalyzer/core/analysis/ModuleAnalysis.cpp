#include "ModuleAnalysis.h"
#include "../pe/PEParser.h"
#include <memory>
#include "../entropy/Entropy.h"
#include "../AnalyzerHub.h"

ModuleAnalysis::ModuleAnalysis()
{
	SetAnalysisRange();
}

/// <summary>
/// Launches internal x64dbg analysis commands
/// </summary>
void ModuleAnalysis::RunDbgAnalysisCmds()
{
	GuiAddStatusBarMessage("[xAnalyzer]: Launching analysis commands...\r\n");
	
	RunCtrlFlowAnalysis();
	RunExceptionDirectoryAnalysis();
	RunXRefsAnalysis();
	RunLinearAnalysis();

	GuiAddStatusBarMessage("[xAnalyzer]: Analysis commands completed!\r\n");
}


void ModuleAnalysis::RunAnalysis()
{
	// TODO: implement
	RemoveAnalysis();
	RunPreliminaryAnalysis();
	RunDbgAnalysisCmds();
	AnalyzeByteRange();
}

void ModuleAnalysis::AnalyzeByteRange()
{

}


void ModuleAnalysis::RemoveAnalysis()
{
	// TODO: implement
	RemoveLoops();
	RemoveArguments(this->startAddress, this->endAddress);
	RemoveComments(this->startAddress, this->endAddress);
	RemoveXRefs();
	RemoveFunctions();

	this->xRefsAnalysisDone = false;
	this->ctrlFlowAnalysisDone = false;
	this->exceptionDirectoryAnalysisDone = false;
	this->linearAnalysisDone = false;
	
	GuiUpdateDisassemblyView();
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

void ModuleAnalysis::RunPreliminaryAnalysis()
{
	// TODO: make a preliminar pe analysis
	// warn if
	// entrypoint is outside the code section
	// code compressed/high entropy
	// if other sections have IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE and ask if want to analyze those as well with the module analysis
	//
	//
	if(AnalyzerHub::pSettings.AnalyzeEntropy && IsExecutablePacked())
	{
		MessageBoxA(GuiGetWindowHandle(),
			"A high entropy has been found which could indicate a possible encrypted or packed executable",
			"High Entropy",
			MB_ICONINFORMATION + MB_OK);
	}
}

bool ModuleAnalysis::IsExecutablePacked()
{
	auto entropy = std::make_unique<Entropy>(this->mainModuleName);
	return entropy->IsPacked();
}