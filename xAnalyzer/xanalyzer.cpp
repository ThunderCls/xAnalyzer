#include "xanalyzer.h"
#include <psapi.h>
#include <tchar.h>
#include <stack>
#include <vector>

#pragma comment(lib, "Psapi.lib")

using namespace std;
using namespace Script;

// ------------------------------------------------------------------------------------

bool IsPrologCall = false; // control undefined calls on function prologues
duint addressFunctionStart = 0;
char szCurrentDirectory[MAX_PATH];
char szAPIFunction[MAX_PATH];
char szApiFile[MAX_PATH];
char szAPIFunctionParameter[MAX_COMMENT_SIZE];
char *vc = "msvcrt\0";
stack <INSTRUCTIONSTACK*> IS;
stack <LOOPSTACK*> LS;

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
	GuiAddLogMessage("[xAnalyzer]: doing analysis, waiting...\r\n");
	GuiAddStatusBarMessage("[xAnalyzer]: doing initial analysis...\r\n");

	// do some analysis algorithms to get as much extra info as possible
	DbgCmdExecDirect("cfanal");
	DbgCmdExecDirect("exanal");
	DbgCmdExecDirect("analx");
	DbgCmdExecDirect("anal");

	GuiAddStatusBarMessage("[xAnalyzer]: initial analysis completed!\r\n");
	GuiAddStatusBarMessage("[xAnalyzer]: doing extended analysis...\r\n");

	ExtraAnalysis(); // call my own function to get extended analysis

	GuiAddStatusBarMessage("[xAnalyzer]: extended analysis completed!\r\n");
	GuiAddLogMessage("[xAnalyzer]: analysis completed!\r\n");
}

// ------------------------------------------------------------------------------------
// GenAPIInfo Main Procedure
// ------------------------------------------------------------------------------------
void ExtraAnalysis()
{
	duint CurrentAddress;
	duint CallDestination;
	duint JmpDestination;
	BASIC_INSTRUCTION_INFO bii; // basic
	BASIC_INSTRUCTION_INFO cbii; // call destination
	duint dwEntry;
	duint dwExit;
	Argument::ArgumentInfo ai;
	
	char szAPIModuleName[MAX_MODULE_SIZE] = "";
	char szAPIModuleNameSearch[MAX_MODULE_SIZE] = "";
	char szAPIComment[MAX_COMMENT_SIZE] = "";
	char szMainModule[MAX_MODULE_SIZE] = "";
	char szDisasmText[GUI_MAX_DISASSEMBLY_SIZE] = "";
	char szJmpDisasmText[GUI_MAX_DISASSEMBLY_SIZE] = "";
	char szAPIDefinition[MAX_COMMENT_SIZE] = "";

	ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
	ZeroMemory(&cbii, sizeof(BASIC_INSTRUCTION_INFO));

	DbgGetEntryExitPoints(&dwEntry, &dwExit);
	DbgClearAutoCommentRange(dwEntry, dwExit);	// clear ONLY autocomments (not user regular comments)
	Argument::DeleteRange(dwEntry, dwExit, true); // clear all arguments
	DbgCmdExecDirect("loopclear"); // clear all prev loops
	GuiUpdateDisassemblyView();

	// get main module name for arguments struct
	Module::NameFromAddr(dwEntry, szMainModule);
	strcpy_s(ai.mod, szMainModule);

	CurrentAddress = dwEntry;
	while (CurrentAddress < dwExit)
	{
		INSTRUCTIONSTACK *inst = new INSTRUCTIONSTACK;
		inst->Address = CurrentAddress; // save address of instruction

		DbgDisasmFastAt(CurrentAddress, &bii);
		if (bii.call == 1 && bii.branch == 1) //  we have call statement
		{
			CallDestination = bii.addr;
			DbgDisasmFastAt(CallDestination, &cbii);
			GuiGetDisassembly(CurrentAddress, szDisasmText);
			GuiGetDisassembly(bii.addr, szJmpDisasmText); // Detect function name on call scheme: CALL -> JMP -> JMP -> API

			// save data for the argument
			ai.manual = true;
			ai.rvaEnd = CurrentAddress - Module::BaseFromAddr(CurrentAddress); // call address is the last		
			if (Strip_x64dbg_calls(szDisasmText, szAPIFunction) || (cbii.branch == 1 && Strip_x64dbg_calls(szJmpDisasmText, szAPIFunction)))
			{
				if (cbii.branch == 1) // direct call/jump => api
				{
					JmpDestination = DbgGetBranchDestination(CallDestination);
					Module::NameFromAddr(JmpDestination, szAPIModuleName);
					TruncateString(szAPIModuleName, '.'); // strip .dll from module name

					// handle different vc dll versions
					if (strncmp(szAPIModuleName, vc, 5) == 0)
						strcpy_s(szAPIModuleNameSearch, vc);
					else
						strcpy_s(szAPIModuleNameSearch, szAPIModuleName);

					bool recursive = (strncmp(szMainModule, szAPIModuleNameSearch, strlen(szAPIModuleNameSearch)) == 0); // if it's main module search recursive
					if (!SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIFunction, szAPIDefinition, recursive))
					{
						if (!recursive) // if it's the same module don't use "module:function"
						{
							strcpy_s(szAPIComment, szAPIModuleName); // if no definition found use "module:function"
							strcat_s(szAPIComment, ":");
							strcat_s(szAPIComment, szAPIFunction);
						}
						else
							strcpy_s(szAPIComment, szAPIFunction);

						if (SetSubParams(&ai)) // when no definition use generic arguments
							SetAutoCommentIfCommentIsEmpty(inst, szAPIComment, _countof(szAPIComment), true);
					}
					else
					{
						if (SetFunctionParams(&ai, szAPIModuleNameSearch)) // set arguments for defined function
							SetAutoCommentIfCommentIsEmpty(inst, szAPIDefinition, _countof(szAPIDefinition), true);
					}
				}
				else
				{
					DbgGetLabelAt(CurrentAddress, SEG_DEFAULT, szAPIFunction); // get label if any as function name
					if (strncmp(szAPIFunction, "sub_", 4) == 0) // internal function call or sub
					{
						// internal subs
						// ---------------------------------------------------------------------
						if(SetSubParams(&ai))
							SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, _countof(szAPIFunction), true);
					}
					else 
					{
						// indirect call or call/!jmp
						// ---------------------------------------------------------------------
						duint api = DbgValFromString(CallDirection(&bii).c_str());
						if (api > 0)
						{
							Module::NameFromAddr(api, szAPIModuleName);
							TruncateString(szAPIModuleName, '.'); // strip .dll from module name

							// handle vc dlls versions
							if (strncmp(szAPIModuleName, vc, 5) == 0)
								strcpy_s(szAPIModuleNameSearch, vc);
							else
								strcpy_s(szAPIModuleNameSearch, szAPIModuleName);

							bool recursive = (strncmp(szMainModule, szAPIModuleNameSearch, strlen(szAPIModuleNameSearch)) == 0);
							if (SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIFunction, szAPIDefinition, recursive)) // just to get the correct definition file .api
							{
								if(SetFunctionParams(&ai, szAPIModuleNameSearch))
									SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, _countof(szAPIFunction), true);
							}
							else
							{
								if(SetSubParams(&ai))
									SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, _countof(szAPIFunction), true);
							}

						}
						else if (*szAPIFunction) // in case it couldnt get the value try looking recursive
						{
							if (SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIFunction, szAPIDefinition, true)) // just to get the correct definition file .api
							{
								if(SetFunctionParams(&ai, szAPIModuleNameSearch))
									SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, _countof(szAPIFunction), true);
							}
							else  // in case of direct call with no definition just set the comment on it and set saved arguments
							{
								if(SetSubParams(&ai))
									SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, _countof(szAPIFunction), true);
							}
						}
					}
				}				
			}
		}
		else if (bii.branch != 1) // call arguments instructions
		{
			if (IsArgumentInstruction(&bii)) // only arguments instruction / excluding unusual instructions
			{
				if (IS.size() < INSTRUCTIONSTACK_MAXSIZE) // save instruction into stack
				{
					strcpy_s(inst->Instruction, bii.instruction); // save instruction string
					GetDestRegister(bii.instruction, inst->destRegister); // save destination registry
					IS.push(inst); // save instruction
				}
				else
					ClearStack(IS);
			}
			else if (IsProlog(&bii, CurrentAddress) || IsEpilog(&bii)) // reset instruction stack for the next call
				ClearStack(IS); 
		}
		else if (bii.call != 1 && bii.branch == 1) // if this is a jump then clear stack
		{
			ClearStack(IS);
			IsPrologCall = false; // no jumps in prolog so we're ok
			IsLoopJump(&bii, CurrentAddress); // check if jump is a loop
		}

		// save function prolog address as a reference for loops detection
		if (IsProlog(&bii, CurrentAddress))
		{
			addressFunctionStart = CurrentAddress;
			IsPrologCall = true;
		}
		if (IsEpilog(&bii)) // if end of function set function start to zero
		{
			addressFunctionStart = 0;
			SetFunctionLoops();
			ClearLoopStack(LS);
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
void DbgGetEntryExitPoints(duint *lpdwEntry, duint *lpdwExit)
{
	duint entry;
	duint start = 0;
	duint end = 0;
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
// Set params for the current call
// ------------------------------------------------------------------------------------
bool SetFunctionParams(Argument::ArgumentInfo *ai, char *szAPIModuleName)
{
	duint CurrentParam;
	duint ParamCount;
	INSTRUCTIONSTACK inst;

	ParamCount = GetFunctionParamCount(szAPIModuleName, szAPIFunction);
	if (ParamCount > 0) // make sure we are only checked for functions that are succesfully found in api file and have 1 or more parameters
	{
		if (ParamCount <= IS.size()) // make sure we have enough in our stack to check for parameters
 		{
			ai->instructioncount = ParamCount + 1; // lenght of the argument + 1 including CALL

			// create the arguments list
			vector <INSTRUCTIONSTACK*> argum(IS.size());
			CurrentParam = 0;
			while (!IS.empty())
			{ 
				argum[CurrentParam] = IS.top(); // get last/first element
				IS.pop(); // remove element on top

				CurrentParam++;
			}

			CurrentParam = 1;
			duint LowerMemoryRVAAddress = 0;
			ai->rvaStart = argum[0]->Address - Module::BaseFromAddr(argum[0]->Address); // first argument line
			while (CurrentParam <= ParamCount)
			{
				GetArgument(CurrentParam, argum, inst); // get arguments in order. 64 bits may have different argument order
				if (inst.Address > 0)
				{
					LowerMemoryRVAAddress = inst.Address - Module::BaseFromAddr(inst.Address);
					if (LowerMemoryRVAAddress < ai->rvaStart)
						ai->rvaStart = LowerMemoryRVAAddress;

					if (GetFunctionParam(szAPIModuleName, szAPIFunction, CurrentParam, szAPIFunctionParameter))
						SetAutoCommentIfCommentIsEmpty(&inst, szAPIFunctionParameter, _countof(szAPIFunctionParameter), false);
				}

				ZeroMemory(&inst, sizeof(INSTRUCTIONSTACK));
				CurrentParam++;
			}

			Argument::Add(ai); // set arguments of current call

			if (IsPrologCall)
				IsPrologCall = false;
			else
			{
				// put back to the stack the instructions not used
				duint startbak = 0; // if x64 
				duint endbak = 0;
#ifndef _WIN64
				startbak = argum.size() - 1; // if x86 save back only the unused instructions
				endbak = ParamCount - 1;
#endif // !_WIN64
				for (duint i = startbak; i > endbak; i--)
					IS.push(argum[i]);
				argum.clear();
			}

			return true;
		}
	}

	if (IsPrologCall)
	{
		ClearStack(IS);
		IsPrologCall = false;
	}

	return false;
}

// ------------------------------------------------------------------------------------
// Set params for the current call (sub)
// ------------------------------------------------------------------------------------
bool SetSubParams(Argument::ArgumentInfo *ai)
{
	duint ParamCount = 0;
	INSTRUCTIONSTACK inst;

	if (!IsPrologCall && !IS.empty())
	{
		// create the arguments list
		vector <INSTRUCTIONSTACK*> argum(IS.size());
		while (!IS.empty())
		{
			argum[ParamCount] = IS.top(); // get last/first element
			IS.pop(); // remove element on top

			ParamCount++;
		}

#ifdef _WIN64
		// In x64 can't be defined the amount of arguments of an unknown function or sub
		// so only four main arguments (RCX, RDX, R8, R9) will be displayed if there are more in stack
		if (ParamCount > 4)
			ParamCount = 4;
#endif // _WIN64

		duint CurrentParam = 1;
		duint LowerMemoryRVAAddress = 0;

		ai->instructioncount = ParamCount + 1; // lenght of the argument + 1 including CALL
		ai->rvaStart = argum[0]->Address - Module::BaseFromAddr(argum[0]->Address); // first argument line

		while (CurrentParam <= ParamCount)
		{
			GetArgument(CurrentParam, argum, inst); // get arguments in order. 64 bits may have different argument order				
			if (inst.Address > 0)
			{
				LowerMemoryRVAAddress = inst.Address - Module::BaseFromAddr(inst.Address);
				if (LowerMemoryRVAAddress < ai->rvaStart)
					ai->rvaStart = LowerMemoryRVAAddress;

				sprintf_s(szAPIFunctionParameter, _countof(szAPIFunctionParameter), "Arg%d", CurrentParam);
				SetAutoCommentIfCommentIsEmpty(&inst, szAPIFunctionParameter, _countof(szAPIFunctionParameter), false);
			}

			ZeroMemory(&inst, sizeof(INSTRUCTIONSTACK));
			CurrentParam++;
		}

		Argument::Add(ai); // set arguments of current call

		// put back to the stack the instructions not used
		duint startbak = 0; // if x64 
		duint endbak = 0;
#ifndef _WIN64
		startbak = argum.size() - 1; // if x86 save back only the unused instructions
		endbak = CurrentParam - 1;
#endif // _WIN64
 		for (duint i = startbak; i > endbak; i--)
 			IS.push(argum[i]);
 		argum.clear();

		return true;
	}

	if (IsPrologCall)
	{
		ClearStack(IS);
		IsPrologCall = false;
	}

	return false;
}

// ------------------------------------------------------------------------------------
// Strips out the brackets, underscores, full stops and @ symbols from calls : 
// call <winbif._GetModuleHandleA@4> and returns just the api call : GetModuleHandle
// Returns true if succesful and lpszAPIFunction will contain the stripped api function 
// name, otherwise false and lpszAPIFunction will be a null string
// ------------------------------------------------------------------------------------
bool Strip_x64dbg_calls(LPSTR lpszCallText, LPSTR lpszAPIFunction/*, bool findDynamic*/)
{
	int index = 0;
	int index_cpy = 0;
	char funct[MAX_MNEMONIC_SIZE] = "";

	// in case of undefined: CALL {REGISTER}, CALL {REGISTER + DISPLACEMENT}
	if (GetDynamicUndefinedCall(lpszCallText, funct))
	{
		sprintf_s(lpszAPIFunction, MAX_PATH, "sub_[%s]", funct);
		return true;
	}

	// parse the function: module.function
	// -------------------------------------------------------
	while (lpszCallText[index] != '.' && lpszCallText[index] != '&' && lpszCallText[index] != ':')
	{
		if (lpszCallText[index] == 0)
		{
			*lpszAPIFunction = 0;
			return false;
		}

		index++; // sub_undefined
	}

	++index; // jump over the "." or the "&"
	if (!isalpha(lpszCallText[index]) && !isdigit(lpszCallText[index])) // if not function name
	{
		while (lpszCallText[index] != '_' && lpszCallText[index] != '?' && lpszCallText[index] != '(' && lpszCallText[index] != '[') // get the initial bracket
		{
			if (lpszCallText[index] == 0)
			{
				*lpszAPIFunction = 0;
				return false;
			}

			index++;
		}
	}

	// delete all underscores left or other non letter or digits chars
	while (!isalpha(lpszCallText[index]) && !isdigit(lpszCallText[index]))
		index++;

	while (lpszCallText[index] != '@' && lpszCallText[index] != '>' && lpszCallText[index] != ')' && lpszCallText[index] != ']')
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

	// in case of undefined: CALL [0x007FF154]
	strcpy_s(funct, MAX_MNEMONIC_SIZE, lpszAPIFunction);
	if (ishex(funct) || HasRegister(funct))
		sprintf_s(lpszAPIFunction, MAX_PATH, "sub_[%s]", funct);

	return true;
}

// ------------------------------------------------------------------------------------
// Check if a given string has a register inside
// ------------------------------------------------------------------------------------
bool HasRegister(LPSTR reg)
{
	return(
#ifdef _WIN64
		// CALL {REGISTER}
		strncmp(reg, "rax", 3) == 0 ||
		strncmp(reg, "rcx", 3) == 0 ||
		strncmp(reg, "rdx", 3) == 0 ||
		strncmp(reg, "rbx", 3) == 0 ||
		strncmp(reg, "rsp", 3) == 0 ||
		strncmp(reg, "rbp", 3) == 0 ||
		strncmp(reg, "rsi", 3) == 0 ||
		strncmp(reg, "rdi", 3) == 0 ||
		strncmp(reg, "rip", 3) == 0 ||

		strncmp(reg, "r8", 2) == 0 ||
		strncmp(reg, "r9", 2) == 0 ||
		strncmp(reg, "r10", 3) == 0 ||
		strncmp(reg, "r11", 3) == 0 ||
		strncmp(reg, "r12", 3) == 0 ||
		strncmp(reg, "r13", 3) == 0 ||
		strncmp(reg, "r14", 3) == 0 ||
		strncmp(reg, "r15", 3) == 0);
#else
		// CALL {REGISTER}
		strncmp(reg, "eax", 3) == 0 ||
		strncmp(reg, "ecx", 3) == 0 ||
		strncmp(reg, "edx", 3) == 0 ||
		strncmp(reg, "ebx", 3) == 0 ||
		strncmp(reg, "esp", 3) == 0 ||
		strncmp(reg, "ebp", 3) == 0 ||
		strncmp(reg, "esi", 3) == 0 ||
		strncmp(reg, "edi", 3) == 0 ||
		strncmp(reg, "eip", 3) == 0);
#endif
}

// ------------------------------------------------------------------------------------
// for dynamic call schemes like:
// - CALL DWORD PTR [0x115934C]
// - CALL EAX, CALL RDX
// ------------------------------------------------------------------------------------
bool GetDynamicUndefinedCall(LPSTR lpszCallText, LPSTR dest)
{
	char *pch = NULL;

	pch = strchr(lpszCallText, ' ');
	if (pch != NULL)
	{
		pch++;
		if (HasRegister(pch))
		{
			strcpy_s(dest, MAX_MNEMONIC_SIZE, pch);
			return true;
		}
	}

	return false;
}

// ------------------------------------------------------------------------------------
// Set Auto Comment only if a comment isn't already set
// ------------------------------------------------------------------------------------
void SetAutoCommentIfCommentIsEmpty(INSTRUCTIONSTACK *inst, LPSTR CommentString, size_t CommentStringCount, bool apiCALL)
{
	char szComment[MAX_COMMENT_SIZE] = { 0 };

	if (apiCALL)
	{
		// strip arguments list from API name in CALLs
		TruncateString(CommentString, '(');
		DbgSetCommentAt(inst->Address, CommentString);
	}
	else
	{
		if (DbgGetCommentAt(inst->Address, szComment))
		{
			if (*szComment)
			{
				DbgClearAutoCommentRange(inst->Address, inst->Address); // Delete the prev comment 
				strcat_s(CommentString, CommentStringCount, " = ");
				strcat_s(CommentString, CommentStringCount, szComment);
			}
		}

		if (!*szComment)
		{
			// if no prev comment and is a push copy then the argument
			if (!apiCALL)
			{
				char *inst_source = GetInstructionSource(inst->Instruction);
				if (ishex(inst_source)) // get constants as value of argument / excluding push memory, registers, etc
				{
					strcat_s(CommentString, CommentStringCount, " = ");
					strcat_s(CommentString, CommentStringCount, inst_source);
				}
			}
		}		
		
		DbgSetAutoCommentAt(inst->Address, CommentString);
	}
}

// ------------------------------------------------------------------------------------
// Search the.api file(.ini) - based on the module name, for the section that
// describes the api function, and return the definition value
// eg.Module = kernel32, api filename will be 'kernel32.api'
// ------------------------------------------------------------------------------------
bool SearchApiFileForDefinition(LPSTR lpszApiModule, LPSTR lpszApiFunction, LPSTR lpszApiDefinition, bool recursive)
{
	bool success = false;

	if (lpszApiModule == NULL || lpszApiFunction == NULL)
	{
		*lpszApiDefinition = 0;
		return success;
	}

	strcpy_s(szApiFile, szCurrentDirectory);
	strcat_s(szApiFile, "apis_def\\");
	
	if (!recursive)
	{
		strcat_s(szApiFile, lpszApiModule);
		strcat_s(szApiFile, ".api");
		return GetApiFileDefinition(lpszApiFunction, lpszApiDefinition, szApiFile);
	}
	else
	{	// if recursive lookup throughout the entire directory of api definitions files
		char szFile[MAX_PATH] = { 0 };
		WIN32_FIND_DATA fd;

		strcpy_s(szFile, szApiFile);
		strcat_s(szFile, "*.*");

		HANDLE hFind = FindFirstFile(szFile, &fd);
		if (hFind != INVALID_HANDLE_VALUE)
		{
			do {
				// read all (real) files in current folder
				// , delete '!' read other 2 default folder . and ..
				if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
					strcpy_s(szFile, szApiFile);
					strcat_s(szFile, fd.cFileName);
					if (GetApiFileDefinition(lpszApiFunction, lpszApiDefinition, szFile))
					{
						success = true;
						strcpy_s(lpszApiModule, MAX_MODULE_SIZE, fd.cFileName); // save the correct file definition name
						TruncateString(lpszApiModule, '.'); // strip .api from file name
						break;
					}
				}
			} while (FindNextFile(hFind, &fd));
			FindClose(hFind);
		}
	}

	return success;
}

// ------------------------------------------------------------------------------------
// Returns true if the api function is found in the given definition file
// ------------------------------------------------------------------------------------
bool GetApiFileDefinition(LPSTR lpszApiFunction, LPSTR lpszApiDefinition, LPSTR szFile)
{
	duint result = GetPrivateProfileString(lpszApiFunction, "@", ":", lpszApiDefinition, MAX_COMMENT_SIZE, szFile);
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

	strcpy_s(szApiFile, szCurrentDirectory);
	strcat_s(szApiFile, "apis_def\\");
	strcat_s(szApiFile, lpszApiModule);
	strcat_s(szApiFile, ".api");

	return GetPrivateProfileInt(lpszApiFunction, "ParamCount", 0, szApiFile);
}

// ------------------------------------------------------------------------------------
// Returns parameter type and name for a specified parameter of a function in a api file
// ------------------------------------------------------------------------------------
bool GetFunctionParam(LPSTR lpszApiModule, LPSTR lpszApiFunction, duint dwParamNo, LPSTR lpszApiFunctionParameter)
{
	const string argument[] = { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24" };

	if (lpszApiModule == NULL || lpszApiFunction == NULL || dwParamNo > 24)
	{
		*lpszApiFunctionParameter = 0;
		return false;
	}

	strcpy_s(szApiFile, szCurrentDirectory);
	strcat_s(szApiFile, "apis_def\\");
	strcat_s(szApiFile, lpszApiModule);
	strcat_s(szApiFile, ".api");

	int result = GetPrivateProfileString(lpszApiFunction, argument[dwParamNo - 1].c_str(), ":", lpszApiFunctionParameter, MAX_COMMENT_SIZE, szApiFile);
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
	duint value;

	if (str != NULL)
		return (1 == sscanf_s(str, "%li", &value));

	return false;
}

// ------------------------------------------------------------------------------------
// Truncate a given string by the given char value
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
std::string CallDirection(BASIC_INSTRUCTION_INFO *bii)
{
	char mnemonic[MAX_MNEMONIC_SIZE * 4] = { "[" };
	char *pch;
#ifdef _WIN64
	if (*bii->memory.mnemonic) // indirect call
	{		
		strcat_s(mnemonic, bii->memory.mnemonic);
		strcat_s(mnemonic, "]");
		return mnemonic;
	}
#else
	pch = strchr(bii->instruction, '['); // indirect call
	if(pch != NULL)
		return pch;
#endif
	strcpy_s(mnemonic, bii->instruction); // direct call
	pch = strchr(mnemonic, ' ');
	if (pch != NULL)
	{
		pch++; // go over blank space
		return pch;
	}

	return "";
}

// ------------------------------------------------------------------------------------
// clearing standard containers is swapping with an empty version of the container
// ------------------------------------------------------------------------------------
void ClearStack(stack<INSTRUCTIONSTACK*> &q)
{
	stack<INSTRUCTIONSTACK*> empty;
	while (!q.empty())
	{
		delete q.top();
		q.pop();
	}
	swap(q, empty);
}

void ClearLoopStack(stack<LOOPSTACK*> &q)
{
	stack<LOOPSTACK*> empty;
	while (!q.empty())
	{
		delete q.top();
		q.pop();
	}
	swap(q, empty);
}

// ------------------------------------------------------------------------------------
// True if destination is a valid x64 valid argument register
// ------------------------------------------------------------------------------------
#ifdef _WIN64
bool IsArgumentRegister(const char *destination)
{
	return (
		// rcx
		strncmp(destination, "rcx", 3) == 0 ||
		strncmp(destination, "ecx", 3) == 0 ||
		strncmp(destination, "cx", 2) == 0 ||
		strncmp(destination, "ch", 2) == 0 ||
		strncmp(destination, "cl", 2) == 0 ||
		// rdx
		strncmp(destination, "rdx", 3) == 0 ||
		strncmp(destination, "edx", 3) == 0 ||
		strncmp(destination, "dx", 2) == 0 ||
		strncmp(destination, "dh", 2) == 0 ||
		strncmp(destination, "dl", 2) == 0 ||
		// r8
		strncmp(destination, "r8", 2) == 0 ||
		// r9
		strncmp(destination, "r9", 2) == 0 ||
		// stack argument (>4 args or XMM0, XMM1, XMM2, XMM3 included)
		strstr(destination, "[rsp + ") != NULL
		);
}
#endif

// ------------------------------------------------------------------------------------
// True if instruction is a valid argument instruction
// ------------------------------------------------------------------------------------
bool IsArgumentInstruction(const BASIC_INSTRUCTION_INFO *bii)
{
#ifdef _WIN64
	bool IsArgument = false;
	char *next_token = nullptr;
	char instruction[MAX_MNEMONIC_SIZE * 4] = { 0 };

	strcpy_s(instruction, bii->instruction);
	char *pch = strtok_s(instruction, ",", &next_token); // get the string of the left operand of the instruction
	if (pch != NULL)
	{
		if (strncmp(pch, "mov", 3) == 0 ||
			strncmp(pch, "lea", 3) == 0 ||
			strncmp(pch, "xor", 3) == 0 ||
			strncmp(pch, "or", 2) == 0 ||
			strncmp(pch, "and", 3) == 0)
		{
			char *reg = strstr(pch, " ");
			if (reg != NULL)
			{
				reg++; // go over blank space
				IsArgument = IsArgumentRegister(reg);
			}
		}
	}

	return IsArgument;

#else
	return (strncmp(bii->instruction, "push ", 5) == 0 &&
		strcmp((char*)(bii->instruction + 5), "ebp") != 0 &&
		strcmp((char*)(bii->instruction + 5), "esp") != 0 &&
		strcmp((char*)(bii->instruction + 5), "ds") != 0 &&
		strcmp((char*)(bii->instruction + 5), "es") != 0);
#endif
}

// ------------------------------------------------------------------------------------
// True if instruction is part of the function prolog
// ------------------------------------------------------------------------------------
bool IsProlog(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress)
{
	bool callRef = false;
	XREF_INFO info;
	
	if (DbgXrefGet(CurrentAddress, &info) && info.refcount > 0)
	{
		for (duint i = 0; i < info.refcount; i++)
		{
			if (info.references[i].type == XREF_CALL) // if it has at least one reference from a CALL
			{
				callRef = true; // it is a function start
				break;
			}
		}
	}

	return (
#ifdef _WIN64
		strncmp(bii->instruction, "sub rsp, ", 9) == 0 ||
		callRef);
#else
		strncmp(bii->instruction, "push ebp", 8) == 0 ||
		strncmp(bii->instruction, "enter 0", 7) == 0 ||
		callRef);
#endif
}

// ------------------------------------------------------------------------------------
// True if instruction is part of the function epilog
// ------------------------------------------------------------------------------------
bool IsEpilog(const BASIC_INSTRUCTION_INFO *bii)
{
	return (strncmp(bii->instruction, "ret", 3) == 0);
}

// ------------------------------------------------------------------------------------
// Breaks instruction into parts and give the destination argument
// ------------------------------------------------------------------------------------
char *GetInstructionSource(char *instruction)
{
#ifdef _WIN64
	char *ret = strstr(instruction, ",");
	if (ret != NULL)
	{
		ret++; // avoid comma
		if (ret[0] == ' ') // avoid blank space
			ret++;
	}

	return ret; // return trimmed instruction source
#else
	return instruction += 5; // for push {constant}
#endif
}

// ------------------------------------------------------------------------------------
// Gets the destination register in an arguments the instruction 
// ------------------------------------------------------------------------------------
void GetDestRegister(char *instruction, char *destRegister)
{
#ifdef _WIN64
	char *next_token = nullptr;

	char *pch = strtok_s(instruction, ",", &next_token); // get the string of the left operand of the instruction
	if (pch != NULL)
	{
		if (strstr(pch, "[rsp + ") != NULL) // check if the stack is the destination registry
			strcpy_s(destRegister, 5, "rsp");
		else
		{
			char *reg = strstr(pch, " ");
			if (reg != NULL)
			{
				reg++; // avoid blank space
				strcpy_s(destRegister, 5, reg);
			}
		}
	}
#else
	strcpy_s(destRegister, REGISTER_MAXSIZE, " ");
#endif
}

// ------------------------------------------------------------------------------------
// Gets the correct argument index from the stack 
// ------------------------------------------------------------------------------------
void GetArgument(duint CurrentParam, vector<INSTRUCTIONSTACK*> &arguments, INSTRUCTIONSTACK &arg)
{
#ifdef _WIN64
	int del_index = 0;

	switch (CurrentParam)
	{
	case 1:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i]->destRegister, "rcx", 3) == 0 ||
				strncmp(arguments[i]->destRegister, "ecx", 3) == 0 ||
				strncmp(arguments[i]->destRegister, "cx", 2) == 0 ||
				strncmp(arguments[i]->destRegister, "ch", 2) == 0 ||
				strncmp(arguments[i]->destRegister, "cl", 2) == 0)
			{
				arg = *arguments[i];
				del_index = i;
				break;
			}
		}
		break;
	case 2:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i]->destRegister, "rdx", 3) == 0 ||
				strncmp(arguments[i]->destRegister, "edx", 3) == 0 ||
				strncmp(arguments[i]->destRegister, "dx", 2) == 0 ||
				strncmp(arguments[i]->destRegister, "dh", 2) == 0 ||
				strncmp(arguments[i]->destRegister, "dl", 2) == 0)
			{
				arg = *arguments[i];
				del_index = i;
				break;
			}
		}
		break;
	case 3:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i]->destRegister, "r8", 2) == 0)
			{
				arg = *arguments[i];
				del_index = i;
				break;
			}
		}
		break;
	case 4:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i]->destRegister, "r9", 2) == 0)
			{
				arg = *arguments[i];
				del_index = i;
				break;
			}
		}
		break;
	default: // the rest of stack-related arguments
		arg = *arguments[0];
		del_index = 0;
		break;
	}

	if (arguments.size() > 0)
	{
		delete arguments[del_index];
		arguments.erase(arguments.begin() + del_index); // take out the parameter from list
	}
#else
	arg = *arguments[CurrentParam - 1]; // x86 doesn't have arguments order changes
#endif
}

// ------------------------------------------------------------------------------------
// Check if given jump is part of a loop
// ------------------------------------------------------------------------------------
void IsLoopJump(BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress)
{
	if (addressFunctionStart != 0 && bii->addr > addressFunctionStart && bii->addr < CurrentAddress)
	{
		LOOPSTACK *loop = new LOOPSTACK;
		loop->dwStartAddress = bii->addr;
		loop->dwEndAddress = CurrentAddress;

		LS.push(loop);
	}
}

// ------------------------------------------------------------------------------------
// Set all loops stored in the stack inside the current function
// (Loops are only allowed to be set from the outside to the inside, that's why the loops stack)
// ------------------------------------------------------------------------------------
void SetFunctionLoops()
{
	LOOPSTACK *loop;

	while (!LS.empty())
	{
		loop = LS.top();
		DbgLoopAdd(loop->dwStartAddress, loop->dwEndAddress);
		LS.pop();
	}
}