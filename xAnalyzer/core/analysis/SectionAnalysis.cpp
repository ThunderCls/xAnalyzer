#include "SectionAnalysis.h"
#include "../pe/PEParser.h"
#include <memory>
#include "../entropy/Entropy.h"
#include "../AnalyzerHub.h"

SectionAnalysis::SectionAnalysis(const char *exePath) : Analysis(exePath)
{
	SetAnalysisRange();
}

/// <summary>
/// Launches internal x64dbg analysis commands
/// </summary>
void SectionAnalysis::RunDbgAnalysisCmds()
{
	GuiAddStatusBarMessage("[xAnalyzer]: Launching analysis commands...\r\n");
	
	RunCtrlFlowAnalysis();
#ifdef _WIN64
	RunExceptionDirectoryAnalysis();
#endif
	RunXRefsAnalysis();
	RunLinearAnalysis();

	GuiAddStatusBarMessage("[xAnalyzer]: Analysis commands completed!\r\n");
}


void SectionAnalysis::RunAnalysis()
{
	// TODO: implement
	RemoveAnalysis();
	bool alteredExe = RunPreliminaryAnalysis();
	if (alteredExe && AnalyzerHub::pSettings.AutoAnalysis)
	{
		if (MessageBoxA(GuiGetWindowHandle(),
						"Possibly packed or encrypted executable, an automatic analysis could be useless at this point. "
						"Make sure you perform a manual analysis when the OEP is reached and the executable is unpacked. "
						"Do you want to continue regardless?",
				"Possible Useless Analysis", MB_ICONQUESTION + MB_YESNO) == IDNO)
			return;
	}

	RunDbgAnalysisCmds();

	// TODO: implement the multithreaded analysis here
	// TODO: implement progress message
	// sprintf_s(progress_perc, _countof(progress_perc), "[xAnalyzer]: Doing extended analysis...%d%%\r\n", progress);
	AnalyzeBytesRange(this->startAddress, this->endAddress);
}

void SectionAnalysis::RemoveAnalysis()
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

void SectionAnalysis::SetAnalysisRange()
{
	SELECTIONDATA selection;
	GuiSelectionGet(GUI_DISASSEMBLY, &selection);

	// get section start address
	this->startAddress = Script::Memory::GetBase(selection.start);
	// get section size
	this->endAddress = Script::Memory::GetSize(startAddress) + this->startAddress - 1;
}

bool SectionAnalysis::RunPreliminaryAnalysis()
{
	bool alteredExe = false;
	
	// check if the code is compressed/high entropy
	auto entropy = std::make_unique<Entropy>(this->mainModuleName);
	if (entropy->IsHigh())
	{
		MessageBoxA(GuiGetWindowHandle(),
			"A high entropy has been found which could indicate a possible encrypted or packed executable",
			"High Entropy",
			MB_ICONINFORMATION + MB_OK);
		alteredExe = true;
	}
	
	char filePath[MAX_PATH] = {};
	if (!Script::Module::GetMainModulePath(filePath))
	{
		return alteredExe;
	}

	PEParser pe(filePath);
	if (!pe.ReadPEData())
	{
		return alteredExe;
	}

	duint codeStart = 0;
	duint codeEnd = 0;
	if(!pe.CodeSection(codeStart, codeEnd))
	{
		return alteredExe;
	}

	// check if the entrypoint is outside the code section
	duint entryPoint = pe.EntryPoint();
	if (entryPoint < codeStart || entryPoint > codeEnd)
	{
		MessageBoxA(GuiGetWindowHandle(),
			"Entrypoint outside of the code section. This could indicate a possible packed or self-modifying executable",
			"Suspicious Entrypoint",
			MB_ICONWARNING + MB_OK);
		alteredExe = true;
	}

	// search for additional executable sections excluding the code section
	if (pe.ExecutableSections() > 0)
	{
		MessageBoxA(GuiGetWindowHandle(),
			"Additional executable sections found. This could indicate a possible packed or self-modifying executable",
			"Executable Sections",
			MB_ICONWARNING + MB_OK);
	}

	return alteredExe;
}