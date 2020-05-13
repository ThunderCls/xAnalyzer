#include "Analysis.h"

Analysis::Analysis()
{
	startAddress = 0;
	endAddress = 0;

	xRefsAnalysisDone = false;
	ctrlFlowAnalysisDone = false;
	exceptionDirectoryAnalysisDone = false;
	linearAnalysisDone = false;
}

void Analysis::RunPreliminaryAnalysis()
{
	// TODO: make a preliminar pe analysis
	// warn if
	// entrypoint is outside the code section
	// code compressed/high entropy
	// if other sections have IMAGE_SCN_CNT_CODE and IMAGE_SCN_MEM_EXECUTE and ask if want to analyze those as well with the module analysis
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