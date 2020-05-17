#include "Analysis.h"
#include "../AnalyzerHub.h"
#include "../entropy/Entropy.h"

Analysis::Analysis()
{
	this->startAddress = 0;
	this->endAddress = 0;

	this->xRefsAnalysisDone = false;
	this->ctrlFlowAnalysisDone = false;
	this->exceptionDirectoryAnalysisDone = false;
	this->linearAnalysisDone = false;

	this->IsVB = IsVisualBasic();
	
	char exePath[MAX_PATH] = { };
	Script::Module::GetMainModulePath(exePath);
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

bool Analysis::IsProlog(const BASIC_INSTRUCTION_INFO *bii)
{
	XREF_INFO xref;
	if (DbgXrefGet(bii->addr, &xref) && xref.refcount > 0)
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

bool Analysis::IsEpilog(const BASIC_INSTRUCTION_INFO *bii)
{
	const char* retInstruction = "ret";
	return (strncmp(bii->instruction, retInstruction, sizeof(*retInstruction)) == 0);
}