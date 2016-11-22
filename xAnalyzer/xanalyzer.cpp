#include "xanalyzer.h"
#include <psapi.h>
#include <tchar.h>
#include <stack>
#include <vector>

#pragma comment(lib, "Psapi.lib")

using namespace std;
using namespace Script;

// ------------------------------------------------------------------------------------

char szCurrentDirectory[MAX_PATH];
char szAPIFunction[MAX_PATH];
char szApiFile[MAX_PATH];
char szAPIFunctionParameter[MAX_COMMENT_SIZE];
stack <INSTRUCTIONSTACK*> IS;
char *vc = "msvcrt\0";

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
	//DbgCmdExecDirect("analadv"); // "analadv" command launch an axception when executing outside main module code in x86
	DbgCmdExecDirect("anal");

	GuiAddStatusBarMessage("[xAnalyzer]: initial analysis completed!\r\n");
	GuiAddStatusBarMessage("[xAnalyzer]: doing extended analysis...\r\n");

	GenAPIInfo(); // call my own function to get extended analysis

	GuiAddStatusBarMessage("[xAnalyzer]: extended analysis completed!\r\n");
	GuiAddLogMessage("[xAnalyzer]: analysis completed!\r\n");
}

// ------------------------------------------------------------------------------------
// GenAPIInfo Main Procedure
// ------------------------------------------------------------------------------------
void GenAPIInfo()
{
	duint CurrentAddress;
	duint CallDestination;
	duint JmpDestination;
	BASIC_INSTRUCTION_INFO bii; // basic
	BASIC_INSTRUCTION_INFO cbii; // call destination
	duint dwEntry;
	duint dwExit;
	Argument::ArgumentInfo ai;
	
	char szAPIModuleName[MAX_MODULE_SIZE];
	char szAPIModuleNameSearch[MAX_MODULE_SIZE];
	char szAPIComment[MAX_COMMENT_SIZE];
	char szMainModule[MAX_MODULE_SIZE];
	char szDisasmText[GUI_MAX_DISASSEMBLY_SIZE];
	char szAPIDefinition[MAX_PATH];

	ZeroMemory(szAPIModuleName, MAX_MODULE_SIZE);
	ZeroMemory(szAPIModuleNameSearch, MAX_MODULE_SIZE);
	ZeroMemory(szAPIComment, MAX_COMMENT_SIZE);
	ZeroMemory(szMainModule, MAX_MODULE_SIZE);
	ZeroMemory(szDisasmText, GUI_MAX_DISASSEMBLY_SIZE);
	ZeroMemory(szAPIDefinition, MAX_PATH);
	ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
	ZeroMemory(&cbii, sizeof(BASIC_INSTRUCTION_INFO));

	DbgGetEntryExitPoints(&dwEntry, &dwExit);
	DbgClearAutoCommentRange(dwEntry, dwExit);	// clear ONLY autocomments (not user regular comments)
	Argument::DeleteRange(dwEntry, dwExit, true); // clear all arguments
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
							lstrcpy(szAPIComment, szAPIModuleName); // if no definition found use "module:function"
							lstrcat(szAPIComment, ":");
							lstrcat(szAPIComment, szAPIFunction);
						}
						else
							lstrcpy(szAPIComment, szAPIFunction);

						SetAutoCommentIfCommentIsEmpty(inst, szAPIComment, true);
					}
					else
						SetAutoCommentIfCommentIsEmpty(inst, szAPIDefinition, true);

					// save data for the argument
					ai.manual = true;
					ai.rvaEnd = CurrentAddress - Module::BaseFromAddr(CurrentAddress); // call address is the last

					SetFunctionParams(&ai, szAPIModuleNameSearch);
				}
				else
				{
					DbgGetLabelAt(CurrentAddress, SEG_DEFAULT, szAPIFunction);
					// skip arguments for internal functions calls
					inst->Address = CurrentAddress;
					// set the argument values
					ai.manual = true;

					if (strncmp(szAPIFunction, "sub_", 4) == 0) // internal function call or sub
					{
						// internal subs
						// ---------------------------------------------------------------------
						// set the argument values
						duint arg_rva = CurrentAddress - Module::BaseFromAddr(CurrentAddress);
						ai.rvaEnd = arg_rva;
						ai.instructioncount = 1;
						ai.rvaStart = arg_rva;
						Argument::Add(&ai);

						SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, true);
						ClearStack(IS); // Clear stack after internal functions calls (subs)
					}
					else 
					{
						// indirect call or call/!jmp
						// ---------------------------------------------------------------------
						duint api = DbgValFromString(CallDirection(&bii));
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
							SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIFunction, szAPIDefinition, recursive); // get the correct file definition file
							
							// save data for the argument
							ai.rvaEnd = CurrentAddress - Module::BaseFromAddr(CurrentAddress); // call address is the last

							SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, true);
							SetFunctionParams(&ai, szAPIModuleNameSearch);
						}
						else if (strlen(szAPIFunction) != 0) // in case it couldnt get the value try looking recursive
						{
							if (SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIFunction, szAPIDefinition, true)) // try to get the correct file definition file
							{
								// save data for the argument
								ai.rvaEnd = CurrentAddress - Module::BaseFromAddr(CurrentAddress); // call address is the last

								SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, true);
								SetFunctionParams(&ai, szAPIModuleNameSearch);
							}
							else  // in case of direct call with no definition just set the comment on it
							{
								SetAutoCommentIfCommentIsEmpty(inst, szAPIFunction, true);
								ai.instructioncount = 1;
								ai.rvaEnd = CurrentAddress - Module::BaseFromAddr(CurrentAddress);
								ai.rvaStart = ai.rvaEnd;
								Argument::Add(&ai);
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
					inst->Address = CurrentAddress; // save address of argument instruction
					strcpy_s(inst->Instruction, bii.instruction); // save instruction string
					GetDestRegister(bii.instruction, inst->destRegister); // save destination registry
					IS.push(inst); // save instruction
				}
			}
			else if (IsProlog(&bii) || IsEpilog(&bii)) // reset instruction stack for the next call
				ClearStack(IS); 
		}
		else if (bii.call != 1 && bii.branch == 1) // if this is a jump then clear stack
		{
			ClearStack(IS);
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
			vector <INSTRUCTIONSTACK> arguments(IS.size());
			CurrentParam = 0;
			while (!IS.empty())
			{ 
				arguments[CurrentParam] = *IS.top(); // get last/first element
				IS.pop(); // remove element on top

				CurrentParam++;
			}

			CurrentParam = 1;
			duint LowerMemoryRVAAddress = 0;
			ai->rvaStart = arguments[0].Address - Module::BaseFromAddr(arguments[0].Address); // first argument line
			while (CurrentParam <= ParamCount)
			{
				GetArgument(CurrentParam, arguments, inst); // get arguments in order. 64 bits may have different argument order				
				LowerMemoryRVAAddress = inst.Address - Module::BaseFromAddr(inst.Address);
				if (LowerMemoryRVAAddress < ai->rvaStart)
					ai->rvaStart = LowerMemoryRVAAddress;					

				if (GetFunctionParam(szAPIModuleName, szAPIFunction, CurrentParam, szAPIFunctionParameter))
					SetAutoCommentIfCommentIsEmpty(&inst, szAPIFunctionParameter, false);

				CurrentParam++;
			}

			Argument::Add(ai); // set arguments of current call
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
// Strips out the brackets, underscores, full stops and @ symbols from calls : 
// call <winbif._GetModuleHandleA@4> and returns just the api call : GetModuleHandle
// Returns true if succesful and lpszAPIFunction will contain the stripped api function 
// name, otherwise false and lpszAPIFunction will be a null string
// ------------------------------------------------------------------------------------
bool Strip_x64dbg_calls(LPSTR lpszCallText, LPSTR lpszAPIFunction)
{
	int index = 0;
	int index_cpy = 0;

	while (lpszCallText[index] != '.' && lpszCallText[index] != '&' && lpszCallText[index] != ':')
	{
		if (lpszCallText[index] == 0)
		{
			*lpszAPIFunction = 0;
			return false;
		}

		index++;
	}

	++index; // jump over the "." or the "&"
	if (!isalpha(lpszCallText[index])) // if not Api name
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

	// delete all underscores left
	while (!isalpha(lpszCallText[index]))
		index++;

	while (lpszCallText[index] != '@' && lpszCallText[index] != '>' && lpszCallText[index] != ')')
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
// Set Auto Comment only if a comment isn't already set
// ------------------------------------------------------------------------------------
void SetAutoCommentIfCommentIsEmpty(INSTRUCTIONSTACK *inst, LPSTR CommentString, bool apiCALL)
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
				char *inst_source = GetInstructionSource(inst->Instruction);
				if (ishex(inst_source)) // get constants as value of argument / excluding push memory, registers, etc
				{
					lstrcat(CommentString, " = ");
					lstrcat(CommentString, inst_source);
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

	if (lpszApiModule == NULL && lpszApiFunction == NULL)
	{
		*lpszApiDefinition = 0;
		return success;
	}

	lstrcpy(szApiFile, szCurrentDirectory);
	lstrcat(szApiFile, "apis_def\\");
	
	if (!recursive)
	{
		lstrcat(szApiFile, lpszApiModule);
		lstrcat(szApiFile, ".api");
		return GetApiFileDefinition(lpszApiFunction, lpszApiDefinition, szApiFile);
	}
	else
	{	// if recursive lookup throughout the entire directory of api definitions files
		char szFile[MAX_PATH] = { 0 };
		WIN32_FIND_DATA fd;

		strcpy_s(szFile, szApiFile);
		lstrcat(szFile, "*.*");

		HANDLE hFind = FindFirstFile(szFile, &fd);
		if (hFind != INVALID_HANDLE_VALUE)
		{
			do {
				// read all (real) files in current folder
				// , delete '!' read other 2 default folder . and ..
				if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
					strcpy_s(szFile, szApiFile);
					lstrcat(szFile, fd.cFileName);
					if (GetApiFileDefinition(lpszApiFunction, lpszApiDefinition, szFile))
					{
						success = true;
						ZeroMemory(lpszApiModule, MAX_MODULE_SIZE);
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
	int result = GetPrivateProfileString(lpszApiFunction, "@", ":", lpszApiDefinition, MAX_COMMENT_SIZE, szFile);
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
bool GetFunctionParam(LPSTR lpszApiModule, LPSTR lpszApiFunction, duint dwParamNo, LPSTR lpszApiFunctionParameter)
{
	const string argument[] = { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24" };

	if (lpszApiModule == NULL || lpszApiFunction == NULL || dwParamNo > 24)
	{
		*lpszApiFunctionParameter = 0;
		return false;
	}

	lstrcpy(szApiFile, szCurrentDirectory);
	lstrcat(szApiFile, "apis_def\\");
	lstrcat(szApiFile, lpszApiModule);
	lstrcat(szApiFile, ".api");

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
	int value;

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
char *CallDirection(BASIC_INSTRUCTION_INFO *bii)
{
	char mnemonic[MAX_MNEMONIC_SIZE * 4] = { "[" };
	char *pch;
#ifdef _WIN64
	if (strlen(bii->memory.mnemonic) != 0) // indirect call
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

	return false;
}
#endif

// ------------------------------------------------------------------------------------
// True if instruction is a valid argument instruction
// ------------------------------------------------------------------------------------
bool IsArgumentInstruction(const BASIC_INSTRUCTION_INFO *bii)
{
#ifdef _WIN64
	bool IsArgument = false;
	char *next_token;
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
bool IsProlog(const BASIC_INSTRUCTION_INFO *bii)
{
	return (
#ifdef _WIN64
		strncmp(bii->instruction, "sub rsp, ", 9) == 0);
#else
		strncmp(bii->instruction, "push ebp", 8) == 0 ||
		strncmp(bii->instruction, "enter 0", 7) == 0);
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
	char *next_token;

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
void GetArgument(duint CurrentParam, vector<INSTRUCTIONSTACK> &arguments, INSTRUCTIONSTACK &arg)
{
#ifdef _WIN64
	int del_index = 0;

	switch (CurrentParam)
	{
	case 1:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i].destRegister, "rcx", 3) == 0 ||
				strncmp(arguments[i].destRegister, "ecx", 3) == 0 ||
				strncmp(arguments[i].destRegister, "cx", 2) == 0 ||
				strncmp(arguments[i].destRegister, "ch", 2) == 0 ||
				strncmp(arguments[i].destRegister, "cl", 2) == 0)
			{
				arg = arguments[i];
				del_index = i;
				break;
			}
		}
		break;
	case 2:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i].destRegister, "rdx", 3) == 0 ||
				strncmp(arguments[i].destRegister, "edx", 3) == 0 ||
				strncmp(arguments[i].destRegister, "dx", 2) == 0 ||
				strncmp(arguments[i].destRegister, "dh", 2) == 0 ||
				strncmp(arguments[i].destRegister, "dl", 2) == 0)
			{
				arg = arguments[i];
				del_index = i;
				break;
			}
		}
		break;
	case 3:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i].destRegister, "r8", 2) == 0)
			{
				arg = arguments[i];
				del_index = i;
				break;
			}
		}
		break;
	case 4:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i].destRegister, "r9", 2) == 0)
			{
				arg = arguments[i];
				del_index = i;
				break;
			}
		}
		break;
	default: // the rest of stack-related arguments
		arg = arguments[0];
		del_index = 0;
		break;
	}

	if (arguments.size() > 0)
		arguments.erase(arguments.begin() + del_index); // take out the parameter from list
#else
	arg = arguments[CurrentParam - 1]; // x86 doesn't have arguments order changes
#endif
}