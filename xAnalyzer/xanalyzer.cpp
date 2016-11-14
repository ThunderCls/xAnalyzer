#include "xanalyzer.h"
#include <psapi.h>
#include <tchar.h>
#include <stack>

#pragma comment(lib, "Psapi.lib")

using namespace std;
using namespace Script;


// ------------------------------------------------------------------------------------

char szCurrentDirectory[MAX_PATH];
char szFindApiFiles[MAX_PATH];
char szAPIFunction[MAX_PATH];
char szApiFile[MAX_PATH];
char szAPIDefinition[MAX_PATH];
char szAPIFunctionParameter[MAX_COMMENT_SIZE];
char szDisasmText[GUI_MAX_DISASSEMBLY_SIZE];
stack <INSTRUCTIONSTACK*> IS;

// ------------------------------------------------------------------------------------
void OnBreakpoint(PLUG_CB_BREAKPOINT* bpInfo)
{
	Module::ModuleInfo mi;

	Module::InfoFromAddr(bpInfo->breakpoint->addr, &mi);
	if (mi.entry == bpInfo->breakpoint->addr) // if we hit the EP
	{
		DoExtendedAnalysis();
	}
}

// ------------------------------------------------------------------------------------
bool cbExtendedAnalysis(int argc, char* argv[])
{
	DoExtendedAnalysis();
	return true;
}

// ------------------------------------------------------------------------------------
// Extended analysis
// ------------------------------------------------------------------------------------
void DoExtendedAnalysis()
{
	//GuiAddLogMessage("FullAnalyzer: doing initial analysis, waiting...\r\n");
	GuiAddStatusBarMessage("xAnalyzer: doing initial analysis...\r\n");
	DbgCmdExecDirect("anal");
	DbgCmdExecDirect("exanal");
	DbgCmdExecDirect("analx");
	DbgCmdExecDirect("analadv"); // "analadv" command has an axception when executing over ntdll
	DbgCmdExecDirect("cfanal");
	GuiAddStatusBarMessage("xAnalyzer: initial analysis completed!\r\n");
	GuiAddStatusBarMessage("xAnalyzer: doing extended analysis...\r\n");
	GenAPIInfo();
	GuiAddStatusBarMessage("xAnalyzer: extended analysis completed!\r\n");
	//GuiAddLogMessage("FullAnalyzer: initial analysis completed!\r\n");
}

// ------------------------------------------------------------------------------------
// GenAPIInfo Main Procedure
// ------------------------------------------------------------------------------------
void GenAPIInfo()
{
	DWORD CurrentAddress;
	DWORD CallDestination;
	DWORD JmpDestination;
	BASIC_INSTRUCTION_INFO bii; // basic
	BASIC_INSTRUCTION_INFO cbii; // call destination
	DWORD dwEntry;
	DWORD dwExit;
	Argument::ArgumentInfo ai;
	
	char szAPIModuleName[MAX_MODULE_SIZE];
	char szAPIModuleNameSearch[MAX_MODULE_SIZE];
	char szAPIComment[MAX_COMMENT_SIZE];
	char szMainModule[MAX_MODULE_SIZE];

	ZeroMemory(szAPIModuleName, MAX_MODULE_SIZE);
	ZeroMemory(szAPIModuleNameSearch, MAX_MODULE_SIZE);
	ZeroMemory(szAPIComment, MAX_COMMENT_SIZE);
	ZeroMemory(szMainModule, MAX_MODULE_SIZE);
	ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
	ZeroMemory(&cbii, sizeof(BASIC_INSTRUCTION_INFO));

	char *vc = "msvcrt\0";

	DbgGetEntryExitPoints(&dwEntry, &dwExit);
	DbgClearAutoCommentRange(dwEntry, dwExit);	// clear ONLY autocomments (not user regular comments)
	GuiUpdateDisassemblyView();

	// get main module name for arguments struct
	Module::NameFromAddr(dwEntry, szMainModule);
	strcpy_s(ai.mod, szMainModule);

	CurrentAddress = dwEntry;
	while (CurrentAddress < dwExit)
	{
		INSTRUCTIONSTACK *inst = new INSTRUCTIONSTACK;
		
		DbgDisasmFastAt(CurrentAddress, &bii);
		if (bii.call == 1 && bii.branch == 1) //  we have call statement
		{
			GuiGetDisassembly(CurrentAddress, szDisasmText);
			inst->Address = CurrentAddress;
			if (Strip_x64dbg_calls(szDisasmText, szAPIFunction))
			{
				CallDestination = bii.addr;
				DbgDisasmFastAt(CallDestination, &cbii);
				if (cbii.branch == 1) // direct call/jump => api
				{
					JmpDestination = DbgGetBranchDestination(CallDestination);
					Module::NameFromAddr(JmpDestination, szAPIModuleName);
					TruncateString(szAPIModuleName, '.'); // strip .dll from module name

					// handle vc versioning dlls
					if (strncmp(szAPIModuleName, vc, 5) == 0)
						strcpy_s(szAPIModuleNameSearch, vc);
					else
						strcpy_s(szAPIModuleNameSearch, szAPIModuleName);

					if (!SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIFunction, szAPIDefinition))
					{
						lstrcpy(szAPIComment, szAPIModuleName); // if no definition found use "module:function"
						lstrcat(szAPIComment, ":");
						lstrcat(szAPIComment, szAPIFunction);
						//DbgSetAutoCommentAt(CurrentAddress, szAPIComment);
						SetAutoCommentIfCommentIsEmpty(inst, szAPIComment, true);
					}
					else
						//DbgSetAutoCommentAt(CurrentAddress, szAPIDefinition);
						SetAutoCommentIfCommentIsEmpty(inst, szAPIDefinition, true);

					// save data for the argument
					ai.manual = true;
					ai.rvaEnd = CurrentAddress - Module::BaseFromAddr(CurrentAddress); // call address is the last

					SetFunctionParams(&ai, szAPIModuleNameSearch);

					//ClearStack(IS); // reset instruction stack for the next call
					// avoid reseting here to allow nested calls
				}
				else
				{
					ZeroMemory(szAPIComment, MAX_COMMENT_SIZE); // clear comment buffer
					DbgGetLabelAt(CurrentAddress, SEG_DEFAULT, szAPIFunction);

					// skip arguments for internal functions calls
					inst->Address = CurrentAddress;
					lstrcat(szAPIComment, szAPIFunction);
					// set the argument values
					ai.manual = true;

					if (strncmp(szAPIFunction, "sub_", 4) == 0) // internal function call or sub
					{
						// internal subs
						// ---------------------------------------------------------------------
						// set the argument values
						int arg_rva = CurrentAddress - Module::BaseFromAddr(CurrentAddress);
						ai.rvaEnd = arg_rva;
						ai.instructioncount = 1;
						ai.rvaStart = arg_rva;
						Argument::Add(&ai);

						SetAutoCommentIfCommentIsEmpty(inst, szAPIComment, true);
						ClearStack(IS); // Clear stack after internal functions calls (subs)
					}
					else 
					{
						// indirect call or call/!jmp
						// ---------------------------------------------------------------------
						DWORD indirect = DbgValFromString(IndirectCallDirection(bii.instruction));
						if (indirect != -1)
						{
							Module::NameFromAddr(indirect, szAPIModuleName);
							TruncateString(szAPIModuleName, '.'); // strip .dll from module name

							// handle vc versioning dlls
							if (strncmp(szAPIModuleName, vc, 5) == 0)
								strcpy_s(szAPIModuleNameSearch, vc);
							else
								strcpy_s(szAPIModuleNameSearch, szAPIModuleName);

							// save data for the argument
							ai.rvaEnd = CurrentAddress - Module::BaseFromAddr(CurrentAddress); // call address is the last

							SetAutoCommentIfCommentIsEmpty(inst, szAPIComment, true);
							SetFunctionParams(&ai, szAPIModuleNameSearch);
						}
					}

					//ClearStack(IS); // reset instruction stack for the next call
					// avoid reseting here to allow nested calls
				}				
			}
		}
		else
		{
			if (bii.branch != 1) // push instructions
			{
				if (strncmp(bii.instruction, "push ", 5) == 0 &&
					strcmp((char*)(bii.instruction + 5), "ebp") != 0 &&
					strcmp((char*)(bii.instruction + 5), "esp") != 0 &&
					strcmp((char*)(bii.instruction + 5), "ds") != 0 &&
					strcmp((char*)(bii.instruction + 5), "es") != 0) // only push instruction / excluding unusual instructions
				{
					if (IS.size() < INSTRUCTIONSTACK_MAXSIZE)
					{
						inst->Address = CurrentAddress; // save address of push instruction
						strcpy_s(inst->Instruction, bii.instruction); // save instruction string
						IS.push(inst); // save push
					}
				}
				else if (strncmp(bii.instruction, "ret", 3) == 0)
					ClearStack(IS); // if end of function reset instruction stack for the next call
			}
		}

		CurrentAddress += bii.size;

		ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
		ZeroMemory(&cbii, sizeof(BASIC_INSTRUCTION_INFO));
	}

	ClearStack(IS);
	GuiUpdateDisassemblyView();
}

// ------------------------------------------------------------------------------------
// Gets entry point and exit point
// ------------------------------------------------------------------------------------
void DbgGetEntryExitPoints(DWORD *lpdwEntry, DWORD *lpdwExit)
{
	DWORD entry;
	duint start;
	duint end;
	char modname[MAX_MODULE_SIZE];
	Module::ModuleSectionInfo *modInfo = new Module::ModuleSectionInfo;


	entry = GetContextData(UE_CIP);
	Module::NameFromAddr(entry, modname);

	duint entryp = Module::EntryFromAddr(entry);

	int index = 0;
	while (SectionFromName(modname, index, modInfo))
	{
		start = modInfo->addr;
		end = start + modInfo->size;

		if (entryp >= start && entryp <= end) 
			break; // entry is into the section boundaries
		index++;
	}

	*lpdwEntry = start; // first address of section
	*lpdwExit = end; // last address of section
}

// ------------------------------------------------------------------------------------
// Set (push) params for the current call
// ------------------------------------------------------------------------------------
void SetFunctionParams(Argument::ArgumentInfo *ai, char *szAPIModuleName)
{
	DWORD CurrentParam;
	DWORD ParamCount;
	INSTRUCTIONSTACK *inst;

	ParamCount = GetFunctionParamCount(szAPIModuleName, szAPIFunction);
	if (ParamCount > 0) // make sure we are only checked for functions that are succesfully found in api file and have 1 or more parameters
	{
		if (ParamCount <= IS.size()) // make sure we have enough in our stack to check for parameters
 		{
			ai->instructioncount = ParamCount + 1; // lenght of the argument + 1 including CALL
			int tpushes = IS.size();

			CurrentParam = 1;
			while (CurrentParam <= ParamCount)
			{
				inst = IS.top(); // get last/first element
				
				if (CurrentParam == ParamCount)
				{
					ai->rvaStart = inst->Address - Module::BaseFromAddr(inst->Address); // the first saved argument
					Argument::Add(ai);
				}
				if (GetFunctionParam(szAPIModuleName, szAPIFunction, CurrentParam, szAPIFunctionParameter))
					SetAutoCommentIfCommentIsEmpty(inst, szAPIFunctionParameter, false);

				IS.pop(); // remove element on top
				CurrentParam++;
			}
		}
	}
	else if (ParamCount == 0) // add 1 param bracket when no arguments
	{
		ai->instructioncount = 1;
		ai->rvaStart = ai->rvaEnd;
		Argument::Add(ai);
	}
}

// ------------------------------------------------------------------------------------
// Strips out the brackets, underscores, full stops and @ symbols from calls : call <winbif._GetModuleHandleA@4> and returns just the api call : GetModuleHandle
// Returns true if succesful and lpszAPIFunction will contain the stripped api function name, otherwise false and lpszAPIFunction will be a null string
// ------------------------------------------------------------------------------------
bool Strip_x64dbg_calls(LPSTR lpszCallText, LPSTR lpszAPIFunction)
{
	int index = 0;
	int index_cpy = 0;

	while (lpszCallText[index] != '.' && lpszCallText[index] != '&') // 64bit have & in the api calls, so to check for that as well
	{
		if (lpszCallText[index] == 0)
		{
			*lpszAPIFunction = 0;
			return false;
		}

		index++;
	}

	++index; // jump over the . and the first _ if its there
	if (lpszCallText[index] == '_')
		index++;

	while (lpszCallText[index] != '@' && lpszCallText[index] != '>')
	{
		if (lpszCallText[index] == 0)
		{
			*lpszAPIFunction = 0;
			return false;
		}
		
		lpszAPIFunction[index_cpy] = lpszCallText[index];
		index++;
		index_cpy++;
	}

	lpszAPIFunction[index_cpy] = 0x00;
	return true;
}

// ------------------------------------------------------------------------------------
// Set Auto Comment only if a comment isnt already set
// ------------------------------------------------------------------------------------
void SetAutoCommentIfCommentIsEmpty(const INSTRUCTIONSTACK *inst, LPSTR CommentString, bool apiCALL)
{
	char szComment[MAX_COMMENT_SIZE] = { 0 };

	if (apiCALL)
	{
		// strip arguments from API name in CALLs
		TruncateString(CommentString, '(');
		//DbgSetAutoCommentAt(CommentAddress, CommentString);
		DbgSetCommentAt(inst->Address, CommentString);
	}
	else
	{
		if (DbgGetCommentAt(inst->Address, szComment))
		{
			if (lstrlen(szComment) != 0)
			{
				DbgClearAutoCommentRange(inst->Address, inst->Address); // Delete the prev comment 
				lstrcat(CommentString, " = ");
				lstrcat(CommentString, szComment);
			}
		}

		if (lstrlen(szComment) == 0)
		{
			// if no prev comment and is a push copy then the argument
			if (!apiCALL)
			{
				if (strncmp(inst->Instruction, "push ", 5) == 0 &&
					ishex((char*)(inst->Instruction + 5))) // only "push hexValues" instructions / excluding push memory, registers, etc
				{
					lstrcat(CommentString, " = ");
					lstrcat(CommentString, (char*)(inst->Instruction + 5));
				}
			}
		}		
		
		DbgSetAutoCommentAt(inst->Address, CommentString);
		//DbgSetAutoLabelAt(CommentAddress, CommentString);
	}
}

// ------------------------------------------------------------------------------------
// Search the.api file(.ini) - based on the module name, for the section that
// describes the api function, and return the definition value
// eg.Module = kernel32, api filename will be 'kernel32.api'
// ------------------------------------------------------------------------------------
bool SearchApiFileForDefinition(LPSTR lpszApiModule, LPSTR lpszApiFunction, LPSTR lpszApiDefinition)
{
	if (lpszApiModule == NULL && lpszApiFunction == NULL)
	{
		*lpszApiDefinition = 0;
		return false;
	}

	lstrcpy(szApiFile, szCurrentDirectory);
	lstrcat(szApiFile, "apis_def\\");
	lstrcat(szApiFile, lpszApiModule);
	lstrcat(szApiFile, ".api");

	int result = GetPrivateProfileString(lpszApiFunction, "@", ":", lpszApiDefinition, MAX_COMMENT_SIZE, szApiFile);
	if (result == 0 || result == 1) // just got nothing or the colon and nothing else
	{
		*lpszApiDefinition = 0;
		return false;
	}

	return true;
}

// ------------------------------------------------------------------------------------
// Returns parameters for function in.api file, or - 1 if not found
// ------------------------------------------------------------------------------------
int GetFunctionParamCount(LPSTR lpszApiModule, LPSTR lpszApiFunction)
{
	if (lpszApiModule == NULL && lpszApiFunction == NULL)
		return -1;

	lstrcpy(szApiFile, szCurrentDirectory);
	lstrcat(szApiFile, "apis_def\\");
	lstrcat(szApiFile, lpszApiModule);
	lstrcat(szApiFile, ".api");

	return GetPrivateProfileInt(lpszApiFunction, "ParamCount", 0, szApiFile);
}

// ------------------------------------------------------------------------------------
// Returns parameter type and name for a specified parameter of a function in a api file
// ------------------------------------------------------------------------------------
bool GetFunctionParam(LPSTR lpszApiModule, LPSTR lpszApiFunction, DWORD dwParamNo, LPSTR lpszApiFunctionParameter)
{
	const CHAR *v5;

	if (lpszApiModule == NULL && lpszApiFunction == NULL)
	{
		*lpszApiFunctionParameter = 0;
		return false;
	}

	lstrcpy(szApiFile, szCurrentDirectory);
	lstrcat(szApiFile, "apis_def\\");
	lstrcat(szApiFile, lpszApiModule);
	lstrcat(szApiFile, ".api");

	switch (dwParamNo)
	{
		case 1:
			v5 = "1";
			break;
		case 2:
			v5 = "2";
			break;
		case 3:
			v5 = "3";
			break;
		case 4:
			v5 = "4";
			break;
		case 5:
			v5 = "5";
			break;
		case 6:
			v5 = "6";
			break;
		case 7:
			v5 = "7";
			break;
		case 8:
			v5 = "8";
			break;
		case 9:
			v5 = "9";
			break;
		case 10:
			v5 = "10";
			break;
		case 11:
			v5 = "11";
			break;
		case 12:
			v5 = "12";
			break;
		case 13:
			v5 = "13";
			break;
		case 14:
			v5 = "14";
			break;
		case 15:
			v5 = "15";
			break;
		case 16:
			v5 = "16";
			break;
		case 17:
			v5 = "17";
			break;
		case 18:
			v5 = "18";
			break;
		case 19:
			v5 = "19";
			break;
		case 20:
			v5 = "20";
			break;
		case 21:
			v5 = "21";
			break;
		case 22:
			v5 = "22";
			break;
		case 23:
			v5 = "23";
			break;
		case 24:
			v5 = "24";
			break;
		default: // something > 24 params - gone wrong somewhere then
			*lpszApiFunctionParameter = 0;
			return false;
			break;
	}

	int result = GetPrivateProfileString(lpszApiFunction, v5, ":", lpszApiFunctionParameter, MAX_COMMENT_SIZE, szApiFile);
	if (result <= 1) // just got nothing or the colon and nothing else
	{
		*lpszApiFunctionParameter = 0;
		return false;
	}

	return true;
}

// ------------------------------------------------------------------------------------
// Returns true if the specified string is a valid hex value
// ------------------------------------------------------------------------------------
bool ishex(LPCTSTR str)
{
	int value;

	return (1 == sscanf_s(str, "%li", &value));
}

// ------------------------------------------------------------------------------------
// Returns true if the specified string is a valid hex value
// ------------------------------------------------------------------------------------
void TruncateString(LPSTR str, char value)
{
	char * pch;

	pch = strchr(str, value);
	if (pch != NULL)
		*pch = 0; // truncate at value
}

// ------------------------------------------------------------------------------------
// Return the indirection part of the instruction
// ------------------------------------------------------------------------------------
LPSTR IndirectCallDirection(LPSTR szInstruction)
{
	return strchr(szInstruction, '[');
}

// ------------------------------------------------------------------------------------
// clearing standard containers is swapping with an empty version of the container
// ------------------------------------------------------------------------------------
void ClearStack(stack<INSTRUCTIONSTACK*> &q)
{
	stack<INSTRUCTIONSTACK*> empty;
	swap(q, empty);
}