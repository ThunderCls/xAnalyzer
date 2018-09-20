#include "xanalyzer.h"
#include "Shlwapi.h"
#include "ini.h"
#include "Utf8Ini/Utf8Ini.h"
#include <psapi.h>
#include <tchar.h>
#include <stack>
#include <vector>
#include <ctime>
#include <string>
#include <algorithm>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")

using namespace std;
using namespace Script;
using namespace Gui;

// global vars
// ------------------------------------------------------------------------------------
CONFIG conf; // confg file struct
PROCSUMMARY procSummary; // execution summary struct
bool selectionAnal = false; // analysis type flag
bool singleFunctionAnal = false; // analysis type flag
bool completeAnal = false; // analysis type flag
bool IsPrologCall = false; // control undefined calls on function prologues
duint addressFunctionStart = 0;
duint mEntryPoint = 0;
duint mSectionLowerLimit = 0;
string config_path;
string szAPIFunction;
string szOriginalCharsetAPIFunction; // bak of the original charset function name
char szCurrentDirectory[MAX_PATH] = "";
char szAPIFunctionParameter[MAX_COMMENT_SIZE] = "";
char *vc = "msvcrxx\0";
char *vcrt = "vcruntime\0";
char *ucrt = "ucrtbase\0";
stack <INSTRUCTIONSTACK*> stackInstructions; // global instructions stack
stack <LOOPSTACK*> stackLoops; // global loops instructions stack
vector <INSTRUCTIONSTACK*> vectorFunctPointer; // function pointers handling stack
unordered_map<string, Utf8Ini*>::const_iterator apiDefPointer; // pointer to the current def file
unordered_map<string, Utf8Ini*> apiFiles; // map of main def files
unordered_map<string, Utf8Ini*> apiHFiles; // map of headers def files
// ------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------
// Execute when a windows event is fired
// ------------------------------------------------------------------------------------
// void OnWinEvent(PLUG_CB_WINEVENT *info)
// {
// 	auto msg = info->message;
// 	if (msg->message == WM_KEYDOWN && info->result)
// 	{
// 		switch (msg->wParam)
// 		{
// 		case 'X':
// 		case 'x':			
// 			if ((GetAsyncKeyState(VK_LSHIFT) & 1) && (GetAsyncKeyState(VK_LCONTROL) & 1)) // analyze selection
// 			{
// 				if (IsMultipleSelection())
// 				{
// 					selectionAnal = true;
// 					DbgCmdExec("xanalyze");
// 				}
// 			}
// 			else if ((GetAsyncKeyState(VK_MENU) & 1) && (GetAsyncKeyState(VK_LCONTROL) & 1)) // analyze entire exe
//  			{
// 				completeAnal = true;
// 				DbgCmdExec("xanalyze");
//  			}
// 			else if (GetAsyncKeyState(VK_LCONTROL) & 1)	// analyze function
// 			{
// 				singleFunctionAnal = true;
// 				DbgCmdExec("xanalyze");
// 			}
// 		break;
// 		default:break;
// 		}
// 	}
// }

// ------------------------------------------------------------------------------------
// Executed when a BP is hitted 
// ------------------------------------------------------------------------------------
void OnBreakpoint(PLUG_CB_BREAKPOINT* bpInfo)
{
	Module::ModuleInfo mi;

	Module::InfoFromAddr(bpInfo->breakpoint->addr, &mi);
	// if we hit the EP with a dbg one-shot EP BP
	if (bpInfo->breakpoint->type == bp_normal &&
		mi.entry == bpInfo->breakpoint->addr &&	
		GetModuleEntryPoint(mi.name) == bpInfo->breakpoint->addr ||
		strcmp(bpInfo->breakpoint->name, "entry breakpoint") == 0)
	{
		if (conf.auto_analysis)
		{
			if (!FileDbExists())
				DbgCmdExec("xanal module");
			else
			{
				GuiAddLogMessage("[xAnalyzer]: Analysis retrieved from data base\r\n");
				GuiAddStatusBarMessage("[xAnalyzer]: Analysis retrieved from data base\r\n");
			}
		}
		else
		{
			GuiAddLogMessage("[xAnalyzer]: Automatic mode is deactivated...skipping automatic analysis\r\n");
			GuiAddStatusBarMessage("[xAnalyzer]: Automatic mode is deactivated...skipping automatic analysis\r\n");
		}
	}
}

//------------------------------------------------------------------------------------
// Extended analysis caller command "xanal" (this executes in a new thread)
// This handles the different arguments for the different types of analysis
//------------------------------------------------------------------------------------
bool cbExtendedAnalysis(int argc, char* argv[])
{
	 if (argc < 2)
		 return false;

	 if (strcmp(argv[1], "selection") == 0) // cmd "xanal selection"
	 {
		 if (IsMultipleSelection())
		 {
			 selectionAnal = true;
			 DoExtendedAnalysis();
			 return true;
		 }
		 else
			 return false;
	 }

	 if (strcmp(argv[1], "function") == 0) // cmd "xanal function"
	 {
		 singleFunctionAnal = true;
		 DoExtendedAnalysis();
		 return true;
	 }

	 if (strcmp(argv[1], "module") == 0) // cmd "xanal module"
	 {
		 completeAnal = true;
		 DoExtendedAnalysis();
		 return true;
	 }

	 if (strcmp(argv[1], "help") == 0) // cmd "xanal help"
	 {
		 DisplayHelp();
		 GuiAddStatusBarMessage("[xAnalyzer]: Check the log window in order to get an extended help text");
	 }

	 return true;
}

//------------------------------------------------------------------------------------
//Extended analysis remove caller  command "xanalremove" (this executes in a new thread)
// This handles the different arguments for the different types of analysis removal
//------------------------------------------------------------------------------------
bool cbExtendedAnalysisRemove(int argc, char* argv[])
{
	if (argc < 2)
		return false;

	if (strcmp(argv[1], "selection") == 0) // cmd "xanalremove selection"
	{
		if (IsMultipleSelection())
		{
			selectionAnal = true;
			RemoveAnalysis();
			return true;
		}
		else
			return false;
	}

	if (strcmp(argv[1], "function") == 0) // cmd "xanalremove function"
	{
		singleFunctionAnal = true;
		RemoveAnalysis();
		return true;
	}

	if (strcmp(argv[1], "module") == 0) // cmd "xanalremove module"
	{
		completeAnal = true;
		RemoveAnalysis();
		return true;
	}

	return true;
}

// ------------------------------------------------------------------------------------
// Removes the analysis in the given case
// ------------------------------------------------------------------------------------
void RemoveAnalysis()
{
	duint start = 0;
	duint end = 0;

	GuiAddLogMessage("[xAnalyzer]: Removing analysis, please wait...\r\n");
	DbgGetEntryExitPoints(&start, &end);
	if (start != 0 && end != 0)
		ClearPrevAnalysis(start, end);

	GuiAddLogMessage("[xAnalyzer]: Analysis removed successfully!\r\n");
	GuiAddStatusBarMessage("[xAnalyzer]: Analysis removed successfully!\r\n");
	ResetGlobals();
}

// ------------------------------------------------------------------------------------
// Extended analysis
// ------------------------------------------------------------------------------------
void DoExtendedAnalysis()
{
	clock_t start_t;
	clock_t end_t;
	char message[MAX_PATH] = "";

	GuiAddLogMessage("[xAnalyzer]: Doing analysis, please wait...\r\n");
	start_t = clock();

	// make complete x64dbg analysis if asked or if doing function analysis with
	// the undefined function analysis activated
	if (completeAnal)
		DoInitialAnalysis();
	ExtraAnalysis(); // call my own function to get extended analysis

	end_t = clock();
	sprintf_s(message, "[xAnalyzer]: Analysis completed in %f secs\r\n", (double)(end_t - start_t) / CLOCKS_PER_SEC); // elapsed time

	//GuiAddStatusBarMessage(message);
	GuiAddLogMessage(message);
	PrintExecLogSummary();
	GuiAddStatusBarMessage(message);
	ResetGlobals();
}

// ------------------------------------------------------------------------------------
// Full Extra Analysis Procedure
// ------------------------------------------------------------------------------------
void ExtraAnalysis()
{
	duint dwEntry = 0;
	duint dwExit = 0;
	clock_t start_t;
	clock_t end_t;
	char message[MAX_PATH] = "";

	GetAnalysisBoundaries(); // get the analysis lower address limit points
	DbgGetEntryExitPoints(&dwEntry, &dwExit);
	if (dwEntry != 0 && dwExit != 0)
	{
		ClearPrevAnalysis(dwEntry, dwExit);

		GuiAddLogMessage("[xAnalyzer]: Doing extended analysis...\r\n");
		GuiUpdateDisassemblyView();

		start_t = clock();
		// if a VB executable detect and label all dllfunctioncall stubs in the range
		if (IsVBExecutable())
			ProcessDllFunctionCalls(dwEntry, dwExit);

		AnalyzeBytesRange(dwEntry, dwExit);
		end_t = clock();

		sprintf_s(message, "[xAnalyzer]: Extended analysis completed in %f secs\r\n", (double)(end_t - start_t) / CLOCKS_PER_SEC); // elapsed time
		GuiUpdateDisassemblyView();
		GuiAddLogMessage(message);
	}
}

// ------------------------------------------------------------------------------------
// Analysis Procedure
// ------------------------------------------------------------------------------------
void AnalyzeBytesRange(duint dwEntry, duint dwExit)
{
	duint CallDestination = 0;
	duint JmpDestination = 0;
	duint CurrentAddress = 0;
	duint actual_progress = 0;
	duint progress = 0;
	BASIC_INSTRUCTION_INFO bii; // basic
	BASIC_INSTRUCTION_INFO cbii; // call destination
	Argument::ArgumentInfo ai;
	bool prolog = false;
	bool epilog = false;

	char szAPIModuleName[MAX_MODULE_SIZE] = "";
	char szAPIModuleNameSearch[MAX_MODULE_SIZE] = "";
	char szAPIComment[MAX_COMMENT_SIZE] = "";
	char szMainModule[MAX_MODULE_SIZE] = "";
	char szDisasmText[GUI_MAX_DISASSEMBLY_SIZE] = "";
	char szJmpDisasmText[GUI_MAX_DISASSEMBLY_SIZE] = "";
	char szAPIDefinition[MAX_COMMENT_SIZE] = "";
	char progress_perc[MAX_PATH] = "";

	// get main module name for arguments struct
	Module::NameFromAddr(dwEntry, szMainModule);
	strcpy_s(ai.mod, szMainModule);

	duint total_progress = dwExit - dwEntry;
	CurrentAddress = dwEntry;
	while (CurrentAddress <= dwExit)
	{
		// PROGRESS PERCENTAGE UPDATE
		// --------------------------------------------------------------------------------------
		progress = (actual_progress * 100) / total_progress;
		sprintf_s(progress_perc, _countof(progress_perc), "[xAnalyzer]: Doing extended analysis...%d%%\r\n", progress);
		GuiAddStatusBarMessage(progress_perc);
		// --------------------------------------------------------------------------------------

		// clean previous values
		ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
		ZeroMemory(&cbii, sizeof(BASIC_INSTRUCTION_INFO));
		szAPIFunction = ""; // clear prev api function name

		INSTRUCTIONSTACK *inst = new INSTRUCTIONSTACK;
		inst->Address = CurrentAddress; // save address of instruction

		DbgDisasmFastAt(CurrentAddress, &bii);
		prolog = IsProlog(&bii, CurrentAddress); // function prolog flag
		epilog = IsEpilog(&bii); // function epilog flag
		if (bii.call && bii.branch)
		{
			// --------------------------------------------------------------------------------------
			// CALL INSTRUCTION
			// --------------------------------------------------------------------------------------
			CallDestination = bii.addr;
			DbgDisasmFastAt(CallDestination, &cbii);
			GuiGetDisassembly(CurrentAddress, szDisasmText); // get the "as GUI" instruction text line
			GuiGetDisassembly(CallDestination, szJmpDisasmText); // Detect function name on call scheme: CALL -> JMP -> JMP -> API

			// save data for the argument
			ai.manual = true;
			ai.rvaEnd = CurrentAddress - Module::BaseFromAddr(CurrentAddress); // call address is the last		
			if (Strip_x64dbg_calls(szDisasmText) || (cbii.branch && Strip_x64dbg_calls(szJmpDisasmText)))
			{
				szOriginalCharsetAPIFunction = szAPIFunction;

				// Remove Stub suffix from function names if found
				auto stub = szAPIFunction.find("Stub");
				if (stub != std::string::npos)
					szAPIFunction = szAPIFunction.substr(0, stub);

				// transform charsets search
				if (szAPIFunction.back() == 'A' || szAPIFunction.back() == 'W')
					szAPIFunction.pop_back();

				if (cbii.branch) // direct call/jump => api
				{
					JmpDestination = DbgGetBranchDestination(CallDestination);
					Module::NameFromAddr(JmpDestination, szAPIModuleName); 
					TruncateString(szAPIModuleName, '.'); // strip .dll from module name

					// get the correct dll module name to lookup 
					GetModuleNameSearch(szAPIModuleName, szAPIModuleNameSearch);

					bool recursive = (strncmp(szMainModule, szAPIModuleNameSearch, strlen(szAPIModuleNameSearch)) == 0); // if it's the main module search recursive
					if (!SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIDefinition, recursive))
					{
						if (conf.undef_funtion_analysis)
						{
							if (!recursive) // if it's the same module don't use "module:function"
							{
								strcpy_s(szAPIComment, szAPIModuleName); // if no definition found use "module.function"
								strcat_s(szAPIComment, ".");
								strcat_s(szAPIComment, szAPIFunction.c_str());
							}
							else
								strcpy_s(szAPIComment, szAPIFunction.c_str());

							if (SetSubParams(&ai)) // when no definition use generic arguments
								SetAutoCommentIfCommentIsEmpty(inst, szAPIComment, _countof(szAPIComment), true);
						}
					}
					else
					{
						if (SetFunctionParams(&ai, szAPIModuleNameSearch)) // set arguments for defined function
							SetAutoCommentIfCommentIsEmpty(inst, szAPIDefinition, _countof(szAPIDefinition), true);
					}
				}
				else
				{
					char szLabelAPIFunction[MAX_COMMENT_SIZE] = "";
					char szFunctionName[MAX_COMMENT_SIZE] = "";
					DbgGetLabelAt(CurrentAddress, SEG_DEFAULT, szLabelAPIFunction); // get label if any as function name
					if (*szLabelAPIFunction)
						szAPIFunction = szLabelAPIFunction; // save the API function name
					else
						strcpy_s(szLabelAPIFunction, szAPIFunction.c_str());

					// track the stack of mov instructions to find the function pointer handler
					// predict function calls like: CALL {REGISTER}, CALL {REGISTER + DISPLACEMENT}, CALL {POINTER}
					if (conf.track_undef_functions && FindFunctionFromPointer(szDisasmText, szFunctionName) && SearchApiFileForDefinition(szFunctionName, szAPIDefinition, true))
					{
						if (SetFunctionParams(&ai, szFunctionName))
							SetAutoCommentIfCommentIsEmpty(inst, szLabelAPIFunction, _countof(szLabelAPIFunction), true);
					}
					else
					{
						if (strncmp(szLabelAPIFunction, "sub_", 4) == 0) // internal function call or sub
						{
							if (conf.undef_funtion_analysis)
							{
								// internal subs
								if (SetSubParams(&ai))
									SetAutoCommentIfCommentIsEmpty(inst, szLabelAPIFunction, _countof(szLabelAPIFunction), true);
							}
						}
						else
						{
							// indirect call or call/!jmp
							duint api = DbgValFromString(CallDirection(&bii).c_str());
							if (api > 0)
							{
								Module::NameFromAddr(api, szAPIModuleName);
								TruncateString(szAPIModuleName, '.'); // strip .dll from module name

								// get the correct dll module name to lookup 
								GetModuleNameSearch(szAPIModuleName, szAPIModuleNameSearch);

								bool recursive = (strncmp(szMainModule, szAPIModuleNameSearch, strlen(szAPIModuleNameSearch)) == 0);
								if (SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIDefinition, recursive)) // just to get the correct definition file .api
								{
									if (SetFunctionParams(&ai, szAPIModuleNameSearch))
										SetAutoCommentIfCommentIsEmpty(inst, szLabelAPIFunction, _countof(szLabelAPIFunction), true);
								}
								else if (conf.undef_funtion_analysis)
								{
									if (SetSubParams(&ai))
										SetAutoCommentIfCommentIsEmpty(inst, szLabelAPIFunction, _countof(szLabelAPIFunction), true);
								}

							}
							else if (*szLabelAPIFunction) // in case it couldn't get the value try looking recursive
							{
								if (SearchApiFileForDefinition(szAPIModuleNameSearch, szAPIDefinition, true)) // just to get the correct definition file .api
								{
									if (SetFunctionParams(&ai, szAPIModuleNameSearch))
										SetAutoCommentIfCommentIsEmpty(inst, szLabelAPIFunction, _countof(szLabelAPIFunction), true);
								}
								else if (conf.undef_funtion_analysis)// in case of direct call with no definition just set the comment on it and set saved arguments
								{
									if (SetSubParams(&ai))
										SetAutoCommentIfCommentIsEmpty(inst, szLabelAPIFunction, _countof(szLabelAPIFunction), true);
								}
							}
						}
					}
				}
			}

			// check if it was the first call after the function prolog
			if (IsPrologCall && conf.undef_funtion_analysis)
			{
				ClearStack(stackInstructions);
				IsPrologCall = false;
			}
		}
		// --------------------------------------------------------------------------------------
		// ARGUMENT INSTRUCTION
		// --------------------------------------------------------------------------------------
		else if (!bii.branch)
		{
			if (conf.track_undef_functions && IsMovFunctPointer(&bii, CurrentAddress)) // check possible function pointer handling
			{
				if (vectorFunctPointer.size() < INSTRUCTION_FUNCT_POINTER_MAXSIZE)
				{
					INSTRUCTIONSTACK *mov_inst = new INSTRUCTIONSTACK;
					memcpy_s(mov_inst, sizeof(INSTRUCTIONSTACK), inst, sizeof(INSTRUCTIONSTACK));
					GuiGetDisassembly(CurrentAddress, szDisasmText); // get the "as GUI" instruction text line (PERFORMANCE LOAD)

					strcpy_s(mov_inst->Instruction, bii.instruction); // save instruction string
					strcpy_s(mov_inst->GuiInstruction, szDisasmText); // save the gui instruction string
					DecomposeMovInstruction(mov_inst->GuiInstruction, mov_inst->DestinationRegister, mov_inst->SourceRegister);
					vectorFunctPointer.insert(vectorFunctPointer.begin(), mov_inst); // save instruction
				}
				else
					ClearVector(vectorFunctPointer);
			}

			if (IsArgumentInstruction(&bii, CurrentAddress)) // only arguments instruction / excluding unusual instructions
			{
				if (stackInstructions.size() < INSTRUCTIONSTACK_MAXSIZE) // save instruction into stack
				{
					GuiGetDisassembly(CurrentAddress, szDisasmText); // get the "as GUI" instruction text line (PERFORMANCE LOAD)

					strcpy_s(inst->Instruction, bii.instruction); // save instruction string
					strcpy_s(inst->GuiInstruction, szDisasmText); // save the gui instruction string
					strcpy_s(inst->SourceRegister, GetInstructionSource(bii.instruction));
					if (strcmp(inst->SourceRegister, "0x00") == 0) // get rid of double zeros
						inst->SourceRegister[1] = 0;
					GetDestinationRegister(bii.instruction, inst->DestinationRegister); // save destination registry
					stackInstructions.push(inst); // save instruction
				}
				else
					ClearStack(stackInstructions);
			}
			// reset instruction stack and function pointers stack for the next call if function ends
			else if (!selectionAnal && (prolog || epilog)) 
			{
				ClearStack(stackInstructions);
				ClearVector(vectorFunctPointer); // clear funct pointer stack after
			}
		}
		// --------------------------------------------------------------------------------------
		// JUMP INSTRUCTION
		// --------------------------------------------------------------------------------------
		else if (!bii.call && bii.branch) // if this is a jump then clear stack
		{
			ClearStack(stackInstructions); // Remove restriction of no jumps between arguments by commenting this line
			IsPrologCall = false; // no jumps in prolog so we're ok
			IsLoopJump(&bii, CurrentAddress); // check if jump is a loop
		}

		// --------------------------------------------------------------------------------------
		// PROLOG/EPILOG/LOOPS CONTROL FUNCTIONS
		// --------------------------------------------------------------------------------------
 		// save function prolog address as a reference for loops detection
		if (prolog || (selectionAnal && (CurrentAddress == dwEntry)))
 		{
 			addressFunctionStart = CurrentAddress;
			// if prolog/first selected line is a jump then process 
			// undefined first call IsPrologCall remains false
			if (!bii.branch)
 				IsPrologCall = true;
 		}
		// if end of function or selection set function start reference to zero
		if (epilog || (selectionAnal && (CurrentAddress == dwExit)))
		{
			addressFunctionStart = 0;
			SetFunctionLoops(); // setup loops for this block
			ClearLoopStack(stackLoops);
		}

		CurrentAddress += bii.size;
		actual_progress += bii.size;
	}

	ClearStack(stackInstructions);
	ClearLoopStack(stackLoops);
	ClearVector(vectorFunctPointer);
}

// ------------------------------------------------------------------------------------
// Gets entry point and exit point
// ------------------------------------------------------------------------------------
void DbgGetEntryExitPoints(duint *lpdwEntry, duint *lpdwExit)
{
	duint entry;
	char modname[MAX_MODULE_SIZE] = "";

	if (completeAnal)
	{
		// Analyze entire module section
		// -----------------------------------------------------
		Module::ModuleSectionInfo *modInfo = new Module::ModuleSectionInfo;
		entry = Disassembly::SelectionGetStart();
		Module::NameFromAddr(entry, modname);

		if (conf.extended_analysis)
			GetExtendedAnalysisRange(lpdwEntry, lpdwExit, entry, modname, modInfo);
		else
			GetRegularAnalysisRange(lpdwEntry, lpdwExit, modname);
		
		delete modInfo;
	}
	else
	{
		// Analyze single function
		// -----------------------------------------------------
		if (singleFunctionAnal)
		{
			char cmd[50] = "";

			DbgCmdExecDirect("analx"); // these are NEEDED references for detecting functions boundaries
			GetFunctionAnalysisRange(lpdwEntry, lpdwExit, Disassembly::SelectionGetStart());

			// Call a second time these functions for the next main analysis
			if (conf.undef_funtion_analysis)
				//DoInitialAnalysis(); // if undef function analysis setting then get as much info as possible
				DbgCmdExecDirect("anal"); // if wanted undef function get all subs names

			// create extra analysis for single function
			sprintf_s(cmd, "analr %X", *lpdwEntry);
			DbgCmdExecDirect(cmd); // this cmd will erase the current references
			DbgCmdExecDirect("analx"); // get all references again for detecting functions boundaries
		}

		// Analyze selection
		// -----------------------------------------------------
		if (selectionAnal)
		{
			if (conf.undef_funtion_analysis) // if analyze undefined functions option ON, get subs labels
				DbgCmdExecDirect("anal");
			GetDisasmRange(lpdwEntry, lpdwExit);
		}
	}
}

// ------------------------------------------------------------------------------------
// Gets the whole code section start/end addresses
// ------------------------------------------------------------------------------------
void GetExtendedAnalysisRange(duint *lpdwEntry, duint *lpdwExit, duint entry, char *modname, Module::ModuleSectionInfo *modInfo)
{
	duint start = 0;
	duint end = 0;

	// Process the entire code section
	duint entryp = Module::EntryFromAddr(entry);

	int index = 0;
	while (Module::SectionFromName(modname, index, modInfo))
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
// Gets the start/end addresses of the code section starting at the executable EP
// ------------------------------------------------------------------------------------
void GetRegularAnalysisRange(duint *lpdwEntry, duint *lpdwExit, char *modname)
{
	duint baseaddress;
	duint dwModSize;

	duint ep = GetModuleEntryPoint(modname);
	if (ep == 0)
		return;

	baseaddress = DbgMemFindBaseAddr(ep, &dwModSize);

	*lpdwEntry = ep;
	*lpdwExit = (dwModSize + baseaddress) - 0x2D;
}

// ------------------------------------------------------------------------------------
// Gets a module EP
// ------------------------------------------------------------------------------------
duint GetModuleEntryPoint(char *modname)
{
	HMODULE base;
	MODULEINFO modinfo = {0};
	PROCESS_INFORMATION *pi;

	// Process only STARTING in the Entrypoint to end of code section
	char modbasename[MAX_MODULE_SIZE] = "";

	base = (HMODULE)DbgModBaseFromName(modname);
	pi = TitanGetProcessInformation();
	if (pi == NULL)
		return 0;

	GetModuleBaseName(pi->hProcess, base, modbasename, MAX_MODULE_SIZE);
	GetModuleInformation(pi->hProcess, GetModuleHandle(modbasename), &modinfo, sizeof(MODULEINFO));

	return (duint)modinfo.EntryPoint;
}

// ------------------------------------------------------------------------------------
// Gets function boundaries from a selected address
// ------------------------------------------------------------------------------------
void GetFunctionAnalysisRange(duint *lpdwEntry, duint *lpdwExit, duint selectedAddr)
{
	bool finished = false;
	bool startFound = false;
	duint currentAddr;
	duint start = 0;
	duint end = 0;
	BASIC_INSTRUCTION_INFO bii; // basic

	ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));

	currentAddr = selectedAddr;
	while (!finished)
	{
		DbgDisasmFastAt(currentAddr, &bii);

		if (!startFound)
		{
			// make backward disassembling relying in the xrefs for the begining of the function
			// it'll backtrace until a byte reference is found or an EP or the begining of the code section is reached 
			if (IsProlog(&bii, currentAddr) || (currentAddr == mEntryPoint) || (currentAddr == mSectionLowerLimit))
			{
				startFound = true;
				start = currentAddr;
				currentAddr = selectedAddr + 1; // reset the pointer to the select address
			}
			currentAddr--;
		}
		else
		{
			if (IsEpilog(&bii))
			{
				finished = true;
				end = currentAddr;
			}
			currentAddr += bii.size;
		}

		ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
	}

	*lpdwEntry = start;
	*lpdwExit = end;
}

// ------------------------------------------------------------------------------------
// Gets the current analysis address limits
// ------------------------------------------------------------------------------------
void GetAnalysisBoundaries()
{
	duint entry;
	duint lpdwExit;
	char modname[MAX_MODULE_SIZE] = "";

	Module::ModuleSectionInfo *modInfo = new Module::ModuleSectionInfo;
	entry = Disassembly::SelectionGetStart();
	Module::NameFromAddr(entry, modname);
	mEntryPoint = Module::EntryFromAddr(entry); // gets the EP
	GetExtendedAnalysisRange(&mSectionLowerLimit, &lpdwExit, entry, modname, modInfo); // gets the first address of code section

	delete modInfo;
}

// ------------------------------------------------------------------------------------
// Set params for the current call
// ------------------------------------------------------------------------------------
bool SetFunctionParams(Argument::ArgumentInfo *ai, char *szAPIModuleName)
{
	duint CurrentParam;
	duint ParamCount;
	INSTRUCTIONSTACK inst;

	ParamCount = GetFunctionParamCount(szAPIModuleName, szAPIFunction.c_str());
	if (ParamCount > 0) // make sure we are only checked for functions that are succesfully found in api file and have 1 or more parameters
	{
		// create the arguments list
		vector <INSTRUCTIONSTACK*> argum;
		CurrentParam = 0;
		while (!stackInstructions.empty())
		{
			INSTRUCTIONSTACK *inst = stackInstructions.top(); // get last/first element
#ifndef _WIN64
			if (IsValidArgumentInstruction(inst, ParamCount))
			{
#endif
				argum.insert(argum.begin() + CurrentParam, inst);
				//argum[CurrentParam] = inst;
				CurrentParam++;
#ifndef _WIN64
			}
#endif
			stackInstructions.pop(); // remove element on top
		}

		if (ParamCount <= argum.size()) // make sure we have enough in our stack to check for parameters
 		{
			procSummary.defCallsDetected++; // get record of defined calls amount
			ai->instructioncount = ParamCount + 1; // lenght of the argument + 1 including CALL
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
					stackInstructions.push(argum[i]);
				argum.clear();
			}

			return true;
		}
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

	ZeroMemory(&inst, sizeof(INSTRUCTIONSTACK));
	if (!IsPrologCall && !stackInstructions.empty())
	{
		procSummary.undefCallsDetected++; // get record of undefined calls amount

		// create the arguments list
		vector <INSTRUCTIONSTACK*> argum(stackInstructions.size());
		while (!stackInstructions.empty())
		{
			argum[ParamCount] = stackInstructions.top(); // get last/first element
			stackInstructions.pop(); // remove element on top

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
			stackInstructions.push(argum[i]);
 		argum.clear();

		return true;
	}

	return false;
}

// ------------------------------------------------------------------------------------
// Strips out the brackets, underscores, full stops and @ symbols from calls : 
// call <winbif._GetModuleHandleA@4> and returns just the api call : GetModuleHandle
// Returns true if successful and lpszAPIFunction will contain the stripped api function 
// name, otherwise false and lpszAPIFunction will be a null string
// ------------------------------------------------------------------------------------
bool Strip_x64dbg_calls(LPSTR lpszCallText)
{
	int index_cpy = 0;
	char funct[MAX_COMMENT_SIZE] = "";
	char lpszAPIFunction[MAX_COMMENT_SIZE];

	// in case of undefined: CALL {REGISTER}, CALL {REGISTER + DISPLACEMENT}
	if (GetDynamicUndefinedCall(lpszCallText, funct))
	{
		sprintf_s(lpszAPIFunction, MAX_COMMENT_SIZE, "sub_[%s]", funct);
		szAPIFunction = lpszAPIFunction;
		return true;
	}

	string apiStr = StripFunctionNamePointer(lpszCallText, &index_cpy);
	if (apiStr == "")
	{
		char *functName = strchr(lpszCallText, ' '); // get the call content
		if (functName != NULL)
		{
			sprintf_s(lpszAPIFunction, MAX_COMMENT_SIZE, "sub_<%s>", ++functName);
			szAPIFunction = lpszAPIFunction;
			return true;
		}
		else
			szAPIFunction = "";
		
		return false;
	}

	strcpy_s(lpszAPIFunction, apiStr.c_str());

	// check if the current call has a params definition into parenthesis
	char *funct_parenthesis = strchr(lpszAPIFunction, '(');
	if (funct_parenthesis == NULL)
		lpszAPIFunction[index_cpy] = 0x00;
	else
	{
		lpszAPIFunction[index_cpy] = ')';
		lpszAPIFunction[index_cpy + 1] = 0x00;
	}

	// in case of undefined: CALL [0x007FF154]
	strcpy_s(funct, MAX_COMMENT_SIZE, lpszAPIFunction);
	if (IsHex(funct) || HasRegister(funct))
		sprintf_s(lpszAPIFunction, MAX_COMMENT_SIZE, "sub_[%s]", funct);

	szAPIFunction = lpszAPIFunction;
	return true;
}

// ------------------------------------------------------------------------------------
// Strips out the brackets, underscores, full stops and @ symbols from calls : 
// call <winbif._GetModuleHandleA@4> and returns just the api call : GetModuleHandle
// Returns the new stripped api function string if successful 
// otherwise a null string
// ------------------------------------------------------------------------------------
string StripFunctionNamePointer(char *lpszCallText, int *index_caller)
{
	int index = 0;
	int index_cpy = 0;
	char lpszAPIFunction[MAX_COMMENT_SIZE] = {0};

	// parse the function: module.function
	// -------------------------------------------------------
	while (lpszCallText[index] != '.' && lpszCallText[index] != '&' && lpszCallText[index] != ':')
	{
		if (lpszCallText[index] == 0)
			return "";

		index++; // sub_undefined
	}

	// jump over the "." and/or the "&"
	while (lpszCallText[index] == '.' || lpszCallText[index] == '&')
		index++;

	if (!isalpha(lpszCallText[index]) && !isdigit(lpszCallText[index])) // if not function name
	{
		while (lpszCallText[index] != '_' && lpszCallText[index] != '?' && lpszCallText[index] != '(' && lpszCallText[index] != '[') // get the initial bracket
		{
			if (lpszCallText[index] == 0)
				return "";
			
			index++;
		}
	}

	// delete all underscores left or other non letter or digits chars
	while (!isalpha(lpszCallText[index]) && !isdigit(lpszCallText[index]))
		index++;

	while (lpszCallText[index] != '@' && lpszCallText[index] != '>' && lpszCallText[index] != ')' && lpszCallText[index] != ']')
	{
		if (lpszCallText[index] == 0)
			return "";

		lpszAPIFunction[index_cpy] = lpszCallText[index];
		index++;
		index_cpy++;
	}

	if (index_caller)
		*index_caller = index_cpy;

	string funct = lpszAPIFunction;
	return funct;
}
// ------------------------------------------------------------------------------------
// Check if a given string has a register inside
// ------------------------------------------------------------------------------------
bool HasRegister(const char *reg)
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
			strcpy_s(dest, MAX_COMMENT_SIZE, pch);
			return true;
		}
	}

	return false;
}

/*string GetMemoryString(INSTRUCTIONSTACK *inst)
{
	string memString = "";
	string addrString = "";
	if (strncmp(inst->Instruction, "push", 4) == 0)
	{
		char *strPtr = nullptr;
		if ((strPtr = strchr(inst->DestinationRegister, '[')) != nullptr)
		{
			addrString = strPtr;
			if (addrString.back() == ']')
				addrString.pop_back();
		}
	}

	duint memAddr = hextoduint(addrString.c_str());
	if (Memory::IsValidPtr(memAddr))
	{
		duint memAddrPtr = Memory::ReadPtr(memAddr);
		char byteStr = 0;
		while ((byteStr = Memory::ReadByte(memAddrPtr)) != 0 && (Memory::ReadByte(++memAddrPtr) != 0))
		{
			memString += byteStr;
			memAddrPtr++;
		}
	}

	return memString;
}*/

// ------------------------------------------------------------------------------------
// Set Auto Comment only if a comment isn't already set
// ------------------------------------------------------------------------------------
void SetAutoCommentIfCommentIsEmpty(INSTRUCTIONSTACK *inst, char *CommentString, size_t CommentStringCount, bool apiCALL)
{
	char szComment[MAX_COMMENT_SIZE] = "";
	char szConstComment[MAX_COMMENT_SIZE] = "";
	bool isHeaderConst = false;

	if (apiCALL) // set the API name definition comment
	{
		DbgSetCommentAt(inst->Address, szOriginalCharsetAPIFunction.c_str());
		procSummary.totalCommentsSet++; // get record of comments amount
	}
	else // set the API param comment
	{
		isHeaderConst = IsHeaderConstant(CommentString, szConstComment, inst->SourceRegister, inst->GuiInstruction);

		// avoid BoF for longer comments than MAX_COMMENT_SIZE (FIXED!)
		duint spaceleft = MAX_COMMENT_SIZE - strlen(CommentString);
		if (spaceleft <= 1)
			return;

		//string memStr = "";
		if (DbgGetCommentAt(inst->Address, szComment)/* || (memStr = GetMemoryString(inst)) != ""*/)
		{
			/*if (!*szComment && memStr != "")
				strcpy_s(szComment, memStr.c_str());*/

			if (*szComment)
			{
				StripDbgCommentAddress(szComment); // get rid of the comment address id used by the dbg
				DbgClearAutoCommentRange(inst->Address, inst->Address); // Delete the prev comment 
				if ((strlen(szComment) + 10) <= spaceleft - 1) // avoid BoF for longer comments than MAX_COMMENT_SIZE (FIXED!)
				{
					if (isHeaderConst)
					{
						strcpy_s(CommentString, CommentStringCount, szConstComment);
						if (CommentString[strlen(CommentString) - 1] == ' ') // if comment is of the form "TYPE varName = "
							strcat_s(CommentString, CommentStringCount, szComment);
					}
					else
					{
						strcat_s(CommentString, CommentStringCount, " = ");
						strcat_s(CommentString, CommentStringCount, szComment);
					}
				}
			}
		}
		
		if (!*szComment)
		{
			// if no prev comment and is a push copy then the argument
			if (!apiCALL)
			{				
				char *nullstr = "NULL\0";
				string boolstr[] = { "TRUE", "FALSE" };

				if (inst->SourceRegister != NULL && ((strlen(inst->SourceRegister) + 10) <= spaceleft - 1)) // avoid BoF for longer comments than MAX_COMMENT_SIZE (FIXED!)
				{
					bool instHex = IsHex(inst->SourceRegister);
					string subName = StripFunctNameFromInst(inst->GuiInstruction);
					if (instHex) // get constants as value of argument / excluding push memory, registers, etc
						ToUpperHex(inst->SourceRegister);

					// check if param is an enum or flag
					if (isHeaderConst)
					{
						strcpy_s(CommentString, CommentStringCount, szConstComment);
						if (CommentString[strlen(CommentString) - 1] == ' ') // if the actual comment is like "TYPE varName = "
						{
							if (instHex || subName != "")
							{
								string paramType = ToUpper(CommentString);

								// resolve BOOL types
								if (strncmp(paramType.c_str(), "BOOL", 4) == 0)
								{
									if (strcmp(inst->SourceRegister, "0") == 0)
										sprintf_s(szConstComment, "%s%s", CommentString, boolstr[1].c_str());
									else
										sprintf_s(szConstComment, "%s%s", CommentString, boolstr[0].c_str());
								}
								else if (!IsNumericParam(paramType))
								{
									// resolve zero arguments values as NULL
									if (strcmp(inst->SourceRegister, "0") == 0)
										sprintf_s(szConstComment, "%s%s", CommentString, nullstr);
									else
									{
										if (subName != "") // if its using a sub function pointer as argument
											// show the function pointer in a friendly manner
											sprintf_s(szConstComment, "%s%s", CommentString, subName.c_str()); 
										else
											sprintf_s(szConstComment, "%s%s", CommentString, inst->SourceRegister);
									}
								}
								else
									sprintf_s(szConstComment, "%s%s", CommentString, inst->SourceRegister);

								strcpy_s(CommentString, CommentStringCount, szConstComment);
							}
						}
					}
					// param is a plain value
					else if (instHex || subName != "")
					{
						string paramType = ToUpper(CommentString);

						// resolve BOOL types
						if (strncmp(paramType.c_str(), "BOOL", 4) == 0)
						{
							if (strcmp(inst->SourceRegister, "0") == 0)
								sprintf_s(szConstComment, "%s = %s", CommentString, boolstr[1].c_str());
							else
								sprintf_s(szConstComment, "%s = %s", CommentString, boolstr[0].c_str());
						}
						else if (!IsNumericParam(paramType) && strcmp(inst->SourceRegister, "0") == 0)
							// resolve zero arguments values as NULL
							sprintf_s(szConstComment, "%s = %s", CommentString, nullstr);
						else
						{
							if (subName != "") // if its using a sub function pointer as argument
								// show the function pointer in a friendly manner
								sprintf_s(szConstComment, "%s = %s", CommentString, subName.c_str());
							else
								sprintf_s(szConstComment, "%s = %s", CommentString, inst->SourceRegister); // if no funct pointer just show the numeric  value
						}						

						strcpy_s(CommentString, CommentStringCount, szConstComment);
					}
				}
			}
		}		
		
		DbgSetAutoCommentAt(inst->Address, CommentString);
		//DbgSetCommentAt(inst->Address, CommentString); // debugging purposes
		procSummary.totalCommentsSet++; // get record of comments amount
	}
}

// ------------------------------------------------------------------------------------
// Extracts the function name of an argument instruction
// ------------------------------------------------------------------------------------
string StripFunctNameFromInst(char *instruction)
{
	string subName = "";
	if (strstr(instruction, "<") == nullptr)
		return "";

	char subPointerNameStripped[MAX_MNEMONIC_SIZE * 4] = "";
	char *subPointer = GetInstructionSource(instruction);
	char *subPointerName = strchr(subPointer, '<');
	if (*subPointerName)
	{
		duint index = 0;
		while (index < strlen(subPointerName))
		{
			subPointerNameStripped[index] = subPointerName[index];
			if (subPointerName[index] == '>')
				break;

			index++;
		}

		subName = subPointerNameStripped;
	}

	return subName;
}

// ------------------------------------------------------------------------------------
// Determine if the given parameter is a numeric type
// ------------------------------------------------------------------------------------
bool IsNumericParam(string paramType)
{
	string numericDataTypes[] = { "BYTE", "CHAR", "DWORD", "DWORDLONG", "DWORD32", "DWORD64",
		"FLOAT", "INT", "INT8", "INT16", "INT32", "INT64", "LONG", "LONGLONG", "LONG32", "LONG64",
		"QWORD", "SHORT", "UINT", "UINT8", "UINT16", "UINT32", "UINT64", "ULONG", "ULONGLONG", "ULONG32",
		"ULONG64", "USHORT", "WORD", "SIZE_T" };

	char szParam[MAX_PATH] = "";
	transform(paramType.begin(), paramType.end(), paramType.begin(), toupper);
	strcpy_s(szParam, paramType.c_str());
	TruncateString(szParam, ' ');

	for (auto typ : numericDataTypes)
	{ 
		if (strcmp(szParam, typ.c_str()) == 0)
			return true;
	}
	
	return false;
}

// ------------------------------------------------------------------------------------
// Returns true if instruction is a mov manipulating esp or ebp, excluding epilog, prolog
// otherwise returns false
// ------------------------------------------------------------------------------------
bool IsMovStack(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress)
{
	char instr[MAX_MNEMONIC_SIZE * 4];

	strcpy_s(instr, bii->instruction); // keep original instruction string unchanged
	auto isMovInstruction = strstr(instr, "mov") != nullptr;

	if (isMovInstruction && !IsProlog(bii, CurrentAddress) && !IsEpilog(bii)) // Is a mov instruction excluding prolog and epilog
	{
		char *next_token = NULL;
		auto movDestination = strtok_s(instr, ",", &next_token); // Get the left part of ,
		auto isMovDestinationEsp = strstr(movDestination, "[esp") != nullptr || strstr(movDestination, "esp") != nullptr;
		//auto isMovDestinationEbp = strstr(movDestination, "[ebp") != nullptr;

		if (movDestination != nullptr && (isMovDestinationEsp/* || isMovDestinationEbp*/)) // If instruction manipulate [esp*] it's valid
			return true;
	}

	return false;
}

// ------------------------------------------------------------------------------------
// Returns true if instruction is a mov manipulating a possible function pointer, excluding [ebp*], epilog and prolog
// otherwise returns false
// ------------------------------------------------------------------------------------
bool IsMovFunctPointer(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress)
{
	bool isMov = strstr(bii->instruction, "mov") != nullptr;

	// mov [ebp-x], FUNCTION  
	// call mov [ebp-x]
	// This instructions can be used as well
/*#ifdef _WIN64
	bool isMovEbp = strstr(bii->instruction, "[rbp") != nullptr;
#else
	bool isMovEbp = strstr(bii->instruction, "[ebp") != nullptr;
#endif*/
	return (isMov /*&& !isMovEbp */&& !IsProlog(bii, CurrentAddress) && !IsEpilog(bii)); // Is a mov instruction excluding prolog and epilog and ebp
}

// ------------------------------------------------------------------------------------
// Check if the current executable is a VB
// ------------------------------------------------------------------------------------
bool IsVBExecutable()
{
	duint entryVB6 = 0;
	duint entryVB5 = 0;

	entryVB6 = Module::EntryFromName("msvbvm60");
	entryVB5 = Module::EntryFromName("msvbvm50");
	return (entryVB6 != 0 || entryVB5 != 0);
}

// ------------------------------------------------------------------------------------
// Finds the VB DllFunctionCalls stubs in the specified range
// Based on: https://github.com/JohnTroony/Plugme-OllyDBGv1.0/blob/master/OllyVBHelper%20v0.1/ollyvbhelper.c
// ------------------------------------------------------------------------------------
void ProcessDllFunctionCalls(duint startAddr, duint size)
{
	Module::ModuleInfo mi;
	Module::ModuleSectionInfo msi;
	BASIC_INSTRUCTION_INFO bii;
	string DllFunctionCallPattern = "A1????????0BC07402FFE0"; // pattern of stub	

	// if no addr specified then process the whole code section
	if (startAddr == -1 || size == -1)
	{
		ZeroMemory(&mi, sizeof(Module::ModuleInfo));
		ZeroMemory(&msi, sizeof(Module::ModuleSectionInfo));

		Module::GetMainModuleInfo(&mi);
		Module::SectionFromName(mi.name, 0, &msi);

		// pass executable section address and its size
		LabelDllFunctionCalls(msi.addr, msi.size, DllFunctionCallPattern);
	}
	else
	{
		// walk the calls in the given range
		while (startAddr <= size)
		{
			ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
			DbgDisasmFastAt(startAddr, &bii);
			if (bii.call)
				LabelDllFunctionCalls(bii.addr, VB_STUB_SIZE, DllFunctionCallPattern); // size of 0x20 bytes for a single stub size

			startAddr += bii.size;
		}
	}
}

// ------------------------------------------------------------------------------------
// Label the VB DllFunctionCalls stubs with the API proper name in the given range
// ------------------------------------------------------------------------------------
void LabelDllFunctionCalls(duint rvaCodeSection, duint sectionSize, string DllFunctionCallPattern)
{
	char stubApiString[MAX_LABEL_SIZE] = "";
	char stubApiStringLabel[MAX_LABEL_SIZE] = "";

	duint ptrStub = 0;
	duint startRVA = rvaCodeSection;

	do{
		ptrStub = Pattern::FindMem(rvaCodeSection, sectionSize, DllFunctionCallPattern.c_str());
		if (ptrStub == 0 || ptrStub == -1)
			break;

		rvaCodeSection = ptrStub + VB_STUB_SIZE; // size of 0x20 bytes max for a single stub size
		duint ptrApi = 0;
		// Read Memory		
		if (DbgMemRead(ptrStub - VB_STUB_APISTR_POINTER, &ptrApi, sizeof(duint))) // read the api name string pointer
		{
			if (DbgMemRead(ptrApi, stubApiString, MAX_LABEL_SIZE)) // read the string
			{
				if (strlen(stubApiString) > 0)
				{
					strcpy_s(stubApiStringLabel, "[<");
					strcat_s(stubApiStringLabel, stubApiString);
					strcat_s(stubApiStringLabel, ">]");
					DbgSetAutoLabelAt(ptrStub, stubApiStringLabel);
					//DbgSetLabelAt(ptrStub, stubApiStringLabel); // debugging purposes
					procSummary.DllFunctionCallsDetected++; // get record of dllfunctioncalls stubs amount
					procSummary.totalLabelsSet++; // get record of labels amount
					ZeroMemory(stubApiStringLabel, MAX_LABEL_SIZE);
				}
			}
		}

		// recalculate section size
		sectionSize = sectionSize - (rvaCodeSection - startRVA);
		startRVA = rvaCodeSection;
	} while (ptrStub > 0);
}

// ------------------------------------------------------------------------------------
// Traverse the linked tree of headers return the correct base and defApiHFile
// ------------------------------------------------------------------------------------
void TraverseHFilesTree(string &base, string header, string &htype, char *lpszApiConstant, Utf8Ini *defApiHFile, bool getTypeDisplay)
{
	char szApiConstant[MAX_PATH] = "";
	char lpszHeaders[MAX_PATH] = "";
	char *next_token = NULL;
	unordered_map<string, Utf8Ini*>::const_iterator apiPointer; // pointer to the current def file

	string newBase = base;
	string newHtype = htype;
	Utf8Ini *newdefApiHFile = defApiHFile;
	strcpy_s(szApiConstant, lpszApiConstant);

	while (newBase != "")
	{
		GetConstantValue(szApiConstant, newBase.c_str()); // strip brackets if any
		if (*szApiConstant)
		{
			newBase = newdefApiHFile->GetValue(szApiConstant, "Base"); // search for the next constant in the same header file
			newHtype = newdefApiHFile->GetValue(szApiConstant, "Type"); // search for the next type in the same header file
			if (newBase == "" && header != "") 
			{	// search in the next header file
				strcpy_s(lpszHeaders, MAX_PATH, header.c_str());
				// search through the headers files for the constant
				char *token = strtok_s(lpszHeaders, ";", &next_token);
				while (token)
				{
					char singlefile[MAX_PATH] = "";
					strcpy_s(singlefile, token);
					TruncateString(singlefile, '.'); // strip the .api part

					apiPointer = apiFiles.find(singlefile); // saves pointer to correct def filename
					if (apiPointer != apiFiles.end())
					{
						newdefApiHFile = apiPointer->second; // overwrite the prev HFile with the correct
						newBase = newdefApiHFile->GetValue(szApiConstant, "Base"); // search for the next constant in the same header file
						if (newBase != "") // if base is found in the current header 
						{
							if (newdefApiHFile != NULL)
								defApiHFile = newdefApiHFile;
							break; // exit headers loop
						}
					}

					// advance to the next header file
					token = strtok_s(NULL, ";", &next_token);
				}

				header = newdefApiHFile->GetValue(szApiConstant, "Header"); // get new headers if any
			}

			if (getTypeDisplay) // walk the entire link chain
			{
				if (newBase != "")
				{
					strcpy_s(lpszApiConstant, MAX_PATH, szApiConstant);
					ZeroMemory(szApiConstant, MAX_PATH);
					base = newBase;
					htype = newHtype;
				}
			}
			else // get only the current given base
			{
				strcpy_s(lpszApiConstant, MAX_PATH, szApiConstant);
				ZeroMemory(szApiConstant, MAX_PATH);
				base = newBase;
				htype = newHtype;
				break;
			}
		}
	}
}

// ------------------------------------------------------------------------------------
// Determine if the given parameter is a constant (ENUM or FLAG)
// ------------------------------------------------------------------------------------
bool IsHeaderConstant(const char *CommentString, char *szComment, char *inst_source, char *gui_inst_source)
{
	char lpszHeaders[MAX_PATH] = "";
	char lpszApiConstant[MAX_PATH] = "";
	char szConstantComment[MAX_COMMENT_SIZE] = "";
	char valueIndex[MAX_PATH] = "";
	char *next_token = nullptr;
	bool found = false;
	bool result = false;
	bool instHex = false;
	bool instFunctPointer = false;
	duint instConst = 0;
	duint fileConst = 0;
	const int safety_chars = 5;

 	if (CommentString[0] == '[')
 	{
		// extract the constant identifier
		GetConstantValue(lpszApiConstant, CommentString);
		const char *ptrVarName = strchr(CommentString, ']');
		if (ptrVarName != NULL)
			ptrVarName++; // get the pointer to the var name

		if (inst_source != NULL)
		{
			if(instHex = IsHex(inst_source))
				instConst = hextoduint(inst_source);
		}

		if (gui_inst_source != NULL)
		{
			string subName = StripFunctNameFromInst(gui_inst_source);
			instFunctPointer = subName != "";
		}

		// get the headers files list where to search the constant
		Utf8Ini *defApiFile = apiDefPointer->second;
		string header = defApiFile->GetValue(szAPIFunction, "Header");
		if (header.length() == 0)
			return false;

		strcpy_s(lpszHeaders, MAX_PATH, header.c_str());
		// search through the headers files for the constant
		char *token = strtok_s(lpszHeaders, ";", &next_token);
		while (token || !found)
		{
			char singlefile[MAX_PATH] = "";
			strcpy_s(singlefile, token);
			TruncateString(singlefile, '.'); // strip the .api part

			auto search = apiHFiles.find(singlefile);
			if (search != apiHFiles.end())
			{
				Utf8Ini *defApiHFile = search->second;

				string base = defApiHFile->GetValue(lpszApiConstant, "Base");
				string htype = defApiHFile->GetValue(lpszApiConstant, "Type");
				string hheader = defApiHFile->GetValue(lpszApiConstant, "Header");
				if (base.length() != 0) // if this header file contains the constant
				{
					result = true;
					// Uncomment to get the final TypeDisplay to show as data type
 					string typeParam = defApiHFile->GetValue(lpszApiConstant, "TypeDisplay"); // if enum or flag already then take TypeDisplay value
 					if (typeParam == "")
 					{
 						TraverseHFilesTree(base, hheader, htype, lpszApiConstant, defApiHFile, true); // if not TypeDisplay walk the tree to get the correct base
						typeParam = base;
 					}

					strcpy_s(szComment, MAX_COMMENT_SIZE, typeParam.c_str());
					strcat_s(szComment, MAX_COMMENT_SIZE, ptrVarName);

					// only add '=' if there exist a numeric parameter or function pointer, otherwise just exit here
					if (instHex || instFunctPointer)
						strcat_s(szComment, MAX_COMMENT_SIZE, " = ");
					else
						break;

					// start testing the values and apply constant name accordingly
					string value;
					int index = 1;
					bool orOperator = false;
					do
					{
						sprintf_s(valueIndex, "Value%d", index);
						value = defApiHFile->GetValue(lpszApiConstant, valueIndex);
						if (value.length() != 0) // if value found
						{
							// check if value in def file is base16 or base10 to convert accordingly
							if (value[0] == '0' && value[1] == 'x')
								fileConst = stoul(value.c_str(), 0, 16);
							else
								fileConst = stoul(value.c_str());

							// if is Enum search the exact same values
							if (htype == "Enum")
							{
								if (orOperator) // enums only may be one single value at a time
									break;

								// check the state the Enum variable
								if (instConst == fileConst)
								{
									sprintf_s(valueIndex, "Const%d", index);
									string constant = defApiHFile->GetValue(lpszApiConstant, valueIndex);
									strcat_s(szConstantComment, MAX_COMMENT_SIZE, constant.c_str());
									orOperator = true;
								}
							}
							// if is Flag make bits testing
							else if (htype == "Flag")
							{
								// tests if all bits in fileConst are present in mask instConst
								if ((instConst & fileConst) == fileConst)
								{
									sprintf_s(valueIndex, "Const%d", index);
									string constant = defApiHFile->GetValue(lpszApiConstant, valueIndex);

									// if we got ALL ACCESS replace flags and get out
									if (constant.length() > 11 && constant.substr(constant.length() - 11) == "_ALL_ACCESS")
									// if (instConst == fileConst)
									{
										strcpy_s(szConstantComment, constant.c_str());
										break;
									}

									size_t chars_left = MAX_COMMENT_SIZE - (strlen(szConstantComment) + constant.length() + 5);
									// check length to avoid BoF
									if (chars_left >= safety_chars) // 5 chars left for safety
									{
										if (orOperator)
											strcat_s(szConstantComment, MAX_COMMENT_SIZE, " | ");

										strcat_s(szConstantComment, MAX_COMMENT_SIZE, constant.c_str());
									}
									orOperator = true;
								}
							}
						}
						else if (!*szConstantComment)// if no prev values found get the next constants in the headers tree
						{
							TraverseHFilesTree(base, hheader, htype, lpszApiConstant, defApiHFile);
							index = 0;
						}
						else
							base = "";

						index++;
					} while (base.length() != 0);
				}

				found = true;
			}

			// advance to the next header file
			token = strtok_s(NULL, ";", &next_token);
		}

		// check length to avoid BoF
		size_t chars_left = MAX_COMMENT_SIZE - (strlen(szComment) + safety_chars);
		if (chars_left >= (int)strlen(szConstantComment)) // 5 chars left for safety
			strcat_s(szComment, MAX_COMMENT_SIZE, szConstantComment);
		else
		{
			strcpy_s(&szConstantComment[chars_left], MAX_COMMENT_SIZE, "...\0");
			strcat_s(szComment, MAX_COMMENT_SIZE, szConstantComment);
		}
	}
	
	return result;
}

// ------------------------------------------------------------------------------------
// Strip the address identifier from the string
// ------------------------------------------------------------------------------------
void StripDbgCommentAddress(char *szComment)
{
	char lpszComment[MAX_COMMENT_SIZE] = "";
	char lpszCommentBak[MAX_COMMENT_SIZE] = "";
	bool found = false;
	char *token = NULL;

	char *ptrComment = szComment;
	if (ptrComment[0] == 0x01) // get rid of the '\1' preceding char
		ptrComment++;

	strcpy_s(lpszComment, ptrComment);
	strcpy_s(lpszCommentBak, ptrComment); // keep a backup to return required sanitized string
	
	// searches for " and '
	token = strchr(lpszComment, 0x27); // '
	if (token == NULL)
		token = strchr(lpszComment, 0x22); // "

	if (token != NULL)
	{
		ZeroMemory(szComment, MAX_COMMENT_SIZE);
		strcpy_s(szComment, MAX_COMMENT_SIZE, token);
		return;
	}

	strcpy_s(szComment, MAX_COMMENT_SIZE, lpszCommentBak);
}

// ------------------------------------------------------------------------------------
// Extracts the constant identifier from the string
// ------------------------------------------------------------------------------------
void GetConstantValue(char *lpszApiConstant, const char *CommentString)
{
	int index = 0;
	int indexConst = 0;

	ZeroMemory(lpszApiConstant, MAX_PATH);
	if (CommentString[indexConst] == '[')
		indexConst++;

	do{
		lpszApiConstant[index] = CommentString[indexConst];
		index++;
		indexConst++;
	} while (CommentString[indexConst] != ']' /*&& CommentString[indexConst] != ' ' */&& CommentString[indexConst] != '\0');
}

// ------------------------------------------------------------------------------------
// Search the.api file(.ini) - based on the module name, for the section that
// describes the api function, and return the definition value
// eg.Module = kernel32, api filename will be 'kernel32.api'
// ------------------------------------------------------------------------------------
bool SearchApiFileForDefinition(LPSTR lpszApiModule, LPSTR lpszApiDefinition, bool recursive)
{
	bool success = false;
	apiDefPointer = apiFiles.end(); // reset pointer to end

	if (lpszApiModule == NULL || szAPIFunction.length() == 0)
	{
		*lpszApiDefinition = 0;
		return success;
	}

	if (!recursive)
	{
		apiDefPointer = apiFiles.find(lpszApiModule); // saves pointer to correct def filename
		if (apiDefPointer != apiFiles.end())
		{
			Utf8Ini *defApiFile = apiDefPointer->second;			

			// lookup for the original name (A/W)
			string apiFunction = defApiFile->GetValue(szOriginalCharsetAPIFunction, "@");
			if (apiFunction == "")
				// if not found search for the standard
				apiFunction = defApiFile->GetValue(szAPIFunction, "@");
			else
				szAPIFunction = szOriginalCharsetAPIFunction; // save the correct name

			// check if key is found
			if (!apiFunction.empty())
			{
				// check if definition lies in another .api file
				string sourceModule = defApiFile->GetValue(apiFunction, "SourceModule");
				if (sourceModule.length() != 0)
				{
					size_t pos = sourceModule.find(".");
					string searchModule = sourceModule.substr(0, pos);
					apiDefPointer = apiFiles.find(searchModule); // saves pointer to correct def filename
					if (apiDefPointer != apiFiles.end())
						strcpy_s(lpszApiModule, MAX_MODULE_SIZE, apiDefPointer->first.c_str()); // save the correct file definition name

					// transform charsets search
					if (szAPIFunction.back() == 'A' || szAPIFunction.back() == 'W')
						szAPIFunction.pop_back();
				}
				
				strcpy_s(lpszApiDefinition, MAX_COMMENT_SIZE, apiFunction.c_str());
				success = true;
			}
		}
	}
	else
	{	// if recursive lookup throughout the entire directory of api definitions files
		for (const auto &api : apiFiles)
		{
			Utf8Ini *defApiFile = api.second;
			// lookup for the original name (A/W)
			string apiFunction = defApiFile->GetValue(szOriginalCharsetAPIFunction, "@");
			if (apiFunction == "")
				// if not found search for the standard
				apiFunction = defApiFile->GetValue(szAPIFunction, "@");
			else
				szAPIFunction = szOriginalCharsetAPIFunction; // save the correct name

			// check if key is found
			if (!apiFunction.empty())
			{
				// check if definition lies in another .api file
				string sourceModule = defApiFile->GetValue(apiFunction, "SourceModule");
				if (sourceModule.length() != 0)
				{
					size_t pos = sourceModule.find(".");
					string searchModule = sourceModule.substr(0, pos);
					apiDefPointer = apiFiles.find(searchModule); // saves pointer to correct def filename
					if (apiDefPointer != apiFiles.end())
						strcpy_s(lpszApiModule, MAX_MODULE_SIZE, apiDefPointer->first.c_str()); // save the correct file definition name

					// transform charsets search
					if (szAPIFunction.back() == 'A' || szAPIFunction.back() == 'W')
						szAPIFunction.pop_back();
				}
				else
				{
					apiDefPointer = apiFiles.find(api.first); // saves pointer to correct def filename
					strcpy_s(lpszApiModule, MAX_MODULE_SIZE, api.first.c_str()); // save the correct file definition name
				}

				strcpy_s(lpszApiDefinition, MAX_COMMENT_SIZE, apiFunction.c_str()); // save the API definition 
				success = true;
				break;
			}
		}
	}

	return success;
}

// ------------------------------------------------------------------------------------
// Returns parameters for function in.api file, or - 1 if not found
// ------------------------------------------------------------------------------------
int GetFunctionParamCount(LPSTR lpszApiModule, string lpszApiFunction)
{
	if (lpszApiModule == NULL || lpszApiFunction.length() == 0)
		return -1;

	if (apiDefPointer != apiFiles.end())
	{
		string params = apiDefPointer->second->GetValue(lpszApiFunction, "ParamCount");
		// check if key is found
		if (!params.empty() && IsHex(params.c_str()))
			return atoi(params.c_str());
	}

	return 0;
}

// ------------------------------------------------------------------------------------
// Returns parameter type and name for a specified parameter of a function in a api file
// ------------------------------------------------------------------------------------
bool GetFunctionParam(LPSTR lpszApiModule, string lpszApiFunction, duint dwParamNo, LPSTR lpszApiFunctionParameter)
{
	const string argument[] = { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24" };

	if (lpszApiModule == NULL || lpszApiFunction.length() == 0 || dwParamNo > 24)
	{
		*lpszApiFunctionParameter = 0;
		return false;
	}

	if (apiDefPointer != apiFiles.end())
	{
		string apiParameter = apiDefPointer->second->GetValue(lpszApiFunction, argument[dwParamNo - 1]);
		// check if key is found
		if (!apiParameter.empty())
		{
			strcpy_s(lpszApiFunctionParameter, MAX_COMMENT_SIZE, apiParameter.c_str()); // save the API parameter 
			return true;
		}
	}

	*lpszApiFunctionParameter = 0;
	return false;	
}

// ------------------------------------------------------------------------------------
// Returns true if the specified string is a valid hex value
// ------------------------------------------------------------------------------------
bool IsHex(const char *str)
{
	duint index = 0;

	// process negative values as valid hex
	if (str[0] == '-')
		return true;

	duint lenStr = strlen(str);
 	if (*str && !HasRegister(str)) 
 	{
		if (lenStr >= 3 && str[1] == 'x') // check if 0x prefix already exist
			str += 2; // skip the 0x prefix
		
		lenStr = strlen(str); // get the new len
		while (str[index] != '\n' && isxdigit(str[index]))
			index++;

		return (lenStr == index);
 	}
 
 	return false;
}

// ------------------------------------------------------------------------------------
// Returns the specified string to its valid DUINT value
// ------------------------------------------------------------------------------------
duint hextoduint(LPCTSTR str)
{
	duint value = 0;

	if (str != NULL)
		sscanf_s(str, "%li", &value);

	return value;
}
// ------------------------------------------------------------------------------------
// Truncate a given string by the given char value
// ------------------------------------------------------------------------------------
void TruncateString(LPSTR str, char value)
{
	char *pch;

	pch = strchr(str, value);
	if (pch != NULL)
		*pch = 0; // truncate at value
}

// ------------------------------------------------------------------------------------
// Make Hex value all UPPERCASE and strip the "0x" prefix
// ------------------------------------------------------------------------------------
void ToUpperHex(char *str)
{
	duint size = strlen(str);
	size++;

	string strArg = str;
	if (size > 2) // get rid of the 0x part
		strArg = strArg.substr(2, size - 2);

	transform(strArg.begin(), strArg.end(), strArg.begin(), toupper);
	strcpy_s(str, MAX_MNEMONIC_SIZE * 4, strArg.c_str());
}

// ------------------------------------------------------------------------------------
// Return a given string in an UPPERCASE copy
// ------------------------------------------------------------------------------------
string ToUpper(const char *str)
{
	string upperStr = str;
	transform(upperStr.begin(), upperStr.end(), upperStr.begin(), toupper);
	return upperStr;
}

// ------------------------------------------------------------------------------------
// Call x64dbg core analysis to get as much info as possible
// ------------------------------------------------------------------------------------
void DoInitialAnalysis()
{
	GuiAddStatusBarMessage("[xAnalyzer]: Doing initial analysis...\r\n");

	// do some analysis algorithms to get as much extra info as possible
	DbgCmdExecDirect("cfanal");
	DbgCmdExecDirect("exanal");
	DbgCmdExecDirect("analx");
	DbgCmdExecDirect("anal");

	// if a VB executable detect and label all dllfunctioncall stubs
	if (IsVBExecutable())
		ProcessDllFunctionCalls();

	GuiAddStatusBarMessage("[xAnalyzer]: Initial analysis completed!\r\n");
}

// ------------------------------------------------------------------------------------
// Clear previous analysis information
// ------------------------------------------------------------------------------------
void ClearPrevAnalysis(const duint dwEntry, const duint dwExit)
{
	// clear 
	if (completeAnal)
		DbgCmdExecDirect("loopclear"); // clear all prev loops
	else
		ClearLoopsRange(dwEntry, dwExit); // clear prev loops in the given range

	// check what prev data to clear
	if (conf.clear_usercomments)
		DbgClearCommentRange(dwEntry, dwExit + 1);
	if (conf.clear_userlabels)
		DbgClearLabelRange(dwEntry, dwExit + 1);
	if (conf.clear_autocomments)
		DbgClearAutoCommentRange(dwEntry, dwExit);	// clear autocomments (not user regular comments)
	if (conf.clear_autolabels)
		DbgClearAutoLabelRange(dwEntry, dwExit); // clear autolabels (not user regular labels)

	Argument::DeleteRange(dwEntry, dwExit, true); // clear all arguments
}

// ------------------------------------------------------------------------------------
// Get selected instructions range
// ------------------------------------------------------------------------------------
void GetDisasmRange(duint *selstart, duint *selend, duint raw_start, duint raw_end)
{
	duint start = 0;
	duint end = 0;
	BASIC_INSTRUCTION_INFO bii;

	if (raw_start == 0 || raw_end == 0)
	{
		start = Disassembly::SelectionGetStart();
		end = Disassembly::SelectionGetEnd();
	}
	else
	{
		start = raw_start;
		end = raw_end;
	}

	duint ptrIndex = start;
	do 
	{
		ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
		DbgDisasmFastAt(ptrIndex, &bii);

		if (ptrIndex + bii.size > end)
			break;

		ptrIndex += bii.size;		
	} while (ptrIndex < end);

	*selstart = start;
	*selend = ptrIndex;
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

void ClearVector(vector<INSTRUCTIONSTACK*> &q)
{
	while (!q.empty())
		q.pop_back();
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
		//strstr(destination, "[rbp - ") != NULL ||
		// stack argument (>4 args or XMM0, XMM1, XMM2, XMM3 included)
		strstr(destination, "rsp + ") != NULL
		);
}
#endif

// ------------------------------------------------------------------------------------
// True if instruction is a valid argument instruction
// ------------------------------------------------------------------------------------
bool IsArgumentInstruction(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress)
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
	auto validPushInstruction = strncmp(bii->instruction, "push ", 5) == 0 &&
		//strcmp((char*)(bii->instruction + 5), "ebp") != 0 &&  // push ebp, push esp instructions can be used as arguments for some function calls
		//strcmp((char*)(bii->instruction + 5), "bp") != 0 &&
		//strcmp((char*)(bii->instruction + 5), "esp") != 0 &&
		strcmp((char*)(bii->instruction + 5), "gs") != 0 && // exclude all the below registers
		strcmp((char*)(bii->instruction + 5), "es") != 0 &&
		strcmp((char*)(bii->instruction + 5), "cs") != 0 &&
		strcmp((char*)(bii->instruction + 5), "fs") != 0 &&
		strcmp((char*)(bii->instruction + 5), "ds") != 0 && 
		strcmp((char*)(bii->instruction + 5), "ss") != 0;

	return (validPushInstruction || IsMovStack(bii, CurrentAddress));
#endif
}

// ------------------------------------------------------------------------------------
// True if argument instruction is valid. Double check for MOV [ESP*], MOV [EBP*]
// ------------------------------------------------------------------------------------
#ifndef _WIN64
bool IsValidArgumentInstruction(INSTRUCTIONSTACK *inst, duint args_count)
{
	char *next_token = NULL;
	char instruction[MAX_MNEMONIC_SIZE * 4] = { 0 };

	if (strncmp(inst->Instruction, "mov", 3) != 0) // check only mov
		return true;

	strcpy_s(instruction, inst->Instruction);
	char *pch = strtok_s(instruction, ",", &next_token); // get the string of the left operand of the instruction
	if (pch != NULL)
	{
		TruncateString(pch, ']');

		if (strstr(pch, "esp") != NULL) // [ESP + N] or ESP
		{

			char *str_value = strchr(pch, '+'); 
			if (!str_value)
				return true; // no displacement
			else
			{
				str_value += 2;
				duint stack_displace_value = hextoduint(str_value);
				// displacement can't be greater than the amount of args space in stack
				if ((stack_displace_value + sizeof(duint)) / sizeof(duint) <= args_count)
					return true;
			}
		}
	}

	return false;
}
#endif

// ------------------------------------------------------------------------------------
// True if instruction is part of the function prolog
// ------------------------------------------------------------------------------------
bool IsProlog(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress)
{
	bool callRef = false;
	bool prologInstr = false;
	XREF_INFO info;
	
	if (DbgXrefGet(CurrentAddress, &info) && info.refcount > 0)
	{
		for (duint i = 0; i < info.refcount; i++)
		{
			if (info.references[i].type != /*== XREF_CALL*/XREF_JMP) // if it has at least one reference from a CALL/DATA
			{
				callRef = true; // it is a function start
				break;
			}
		}
	}

#ifdef _WIN64
	prologInstr = strncmp(bii->instruction, "sub rsp, ", 9) == 0;
#else
	prologInstr = strncmp(bii->instruction, "push ebp", 8) == 0 ||
				  strncmp(bii->instruction, "enter 0,", 8) == 0;
#endif
	return (prologInstr || callRef);
}

// ------------------------------------------------------------------------------------
// True if instruction is part of the function epilog
// ------------------------------------------------------------------------------------
bool IsEpilog(const BASIC_INSTRUCTION_INFO *bii)
{
	return (strncmp(bii->instruction, "ret", 3) == 0);
}

// ------------------------------------------------------------------------------------
// Breaks instruction into parts and give the source part
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
	// for push {constant}
	if (strncmp(instruction, "push ", 5) == 0)
		return instruction += 5; 
	// for mov instructions
	else if (strstr(instruction, "mov") != nullptr)
	{
		char *ret = strstr(instruction, ",");
		if (ret)
		{
			ret++; // avoid comma
			if (ret[0] == ' ') // avoid blank space
				ret++;
		}

		return ret;
	}

	return "";
#endif
}

// ------------------------------------------------------------------------------------
// Gets the destination and source part of a given instruction 
// ------------------------------------------------------------------------------------
void DecomposeMovInstruction(char *instruction, char *destination, char *source)
{
	char line[MAX_MNEMONIC_SIZE * 4] = "";
	char *next_token = nullptr;

	strcpy_s(line, instruction);

	char *token = strtok_s(line, ",", &next_token);
	if (*token)
	{
		char *ptr = strstr(token, " ");
		if (*ptr)
		{
			ptr++; // skip space
			strcpy_s(destination, MAX_MNEMONIC_SIZE * 4, ptr);
		}
	}

	if (*next_token)
		strcpy_s(source, MAX_MNEMONIC_SIZE * 4, next_token);
}

// ------------------------------------------------------------------------------------
// Gets the destination register in an arguments the instruction 
// ------------------------------------------------------------------------------------
void GetDestinationRegister(char *instruction, char *destRegister)
{
	char *next_token = nullptr;

	char *pch = strtok_s(instruction, ",", &next_token); // get the string of the left operand of the instruction
	if (strncmp(instruction, "push ", 5) != 0 && pch != NULL)
	{
		char *reg = strstr(pch, " ");
		if (reg != NULL)
		{
			reg++; // avoid blank space
			strcpy_s(destRegister, MAX_MNEMONIC_SIZE * 4, reg);
			return;
		}
	}

	strcpy_s(destRegister, MAX_MNEMONIC_SIZE * 4, " ");
}

// ------------------------------------------------------------------------------------
// Gets the correct argument index from the stack 
// ------------------------------------------------------------------------------------
void GetArgument(duint CurrentParam, vector<INSTRUCTIONSTACK*> &arguments, INSTRUCTIONSTACK &arg)
{
#ifdef _WIN64
	int del_index = 0;
	bool found = false;

	switch (CurrentParam)
	{
	case 1:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i]->DestinationRegister, "rcx", 3) == 0 ||
				strncmp(arguments[i]->DestinationRegister, "ecx", 3) == 0 ||
				strncmp(arguments[i]->DestinationRegister, "cx", 2) == 0 ||
				strncmp(arguments[i]->DestinationRegister, "ch", 2) == 0 ||
				strncmp(arguments[i]->DestinationRegister, "cl", 2) == 0)
			{
				arg = *arguments[i];
				del_index = i;
				found = true;
				break;
			}
		}
		if (found) break;
	case 2:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i]->DestinationRegister, "rdx", 3) == 0 ||
				strncmp(arguments[i]->DestinationRegister, "edx", 3) == 0 ||
				strncmp(arguments[i]->DestinationRegister, "dx", 2) == 0 ||
				strncmp(arguments[i]->DestinationRegister, "dh", 2) == 0 ||
				strncmp(arguments[i]->DestinationRegister, "dl", 2) == 0)
			{
				arg = *arguments[i];
				del_index = i;
				found = true;
				break;
			}
		}
		if (found) break;
	case 3:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i]->DestinationRegister, "r8", 2) == 0)
			{
				arg = *arguments[i];
				del_index = i;
				found = true;
				break;
			}
		}
		if (found) break;
	case 4:
		for (int i = 0; i < arguments.size(); i++)
		{
			if (strncmp(arguments[i]->DestinationRegister, "r9", 2) == 0)
			{
				arg = *arguments[i];
				del_index = i;
				found = true;
				break;
			}
		}
		if (found) break;
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
	if (addressFunctionStart != 0 && bii->addr >= addressFunctionStart && bii->addr < CurrentAddress)
	{
		LOOPSTACK *loop = new LOOPSTACK;
		loop->dwStartAddress = bii->addr;
		loop->dwEndAddress = CurrentAddress;

		stackLoops.push(loop);
	}
}

// ------------------------------------------------------------------------------------
// Set all loops stored in the stack inside the current function
// (Loops are only allowed to be set from the outside to the inside, that's why the loops stack)
// ------------------------------------------------------------------------------------
void SetFunctionLoops()
{
	LOOPSTACK *loop;

	while (!stackLoops.empty())
	{
		loop = stackLoops.top();
		DbgLoopAdd(loop->dwStartAddress, loop->dwEndAddress);
		procSummary.loopsDetected++; // get record of loops amount
		stackLoops.pop();
	}
}

// ------------------------------------------------------------------------------------
// Give the correct module name to lookup from different dll versions and variants
// ------------------------------------------------------------------------------------
void GetModuleNameSearch(char *szAPIModuleName, char *szAPIModuleNameSearch)
{
	// check for vc dll version "msvcxxx" and runtimes "vcruntime, ucrtbase"
	if (strncmp(szAPIModuleName, vc, 5) == 0 || 
		strncmp(szAPIModuleName, vcrt, strlen(vcrt)) == 0 || 
		strncmp(szAPIModuleName, ucrt, strlen(ucrt)) == 0)
		strcpy_s(szAPIModuleNameSearch, MAX_MODULE_SIZE, vc);
	else
		strcpy_s(szAPIModuleNameSearch, MAX_MODULE_SIZE, szAPIModuleName);		
}

// ------------------------------------------------------------------------------------
// Goes through the list of instructions to find the correct function name, thus
// predicting calls like CALL {REGISTER}, CALL {STACK}, etc
// ------------------------------------------------------------------------------------
bool FindFunctionFromPointer(char *szDisasmText, char *szFunctionName)
{
	char line[GUI_MAX_DISASSEMBLY_SIZE] = "";
	bool found = false;
	strcpy_s(line, szDisasmText);
	char *addr = nullptr;
	strtok_s(line, " ", &addr);

	if (!addr)
		return false;

	duint index = 0;
	while (!found && index < vectorFunctPointer.size())
	{
		INSTRUCTIONSTACK *inst = vectorFunctPointer.at(index);
		if (strcmp(inst->DestinationRegister, addr) == 0)
		{
			if (strstr(inst->SourceRegister, "<") != nullptr) // if this is the instruction with the function pointer 
			{
				string funct = StripFunctionNamePointer(inst->SourceRegister);
				if (funct != "")
				{
					szOriginalCharsetAPIFunction = funct;
					// transform charsets search
					if (funct.back() == 'A' || funct.back() == 'W')
						funct.pop_back();

					szAPIFunction = funct;
					strcpy_s(szFunctionName, MAX_COMMENT_SIZE, funct.c_str());
					found = true;
				}
			}
			else
				addr = inst->SourceRegister;
		}

		index++;
	}

	return found;
}

// ------------------------------------------------------------------------------------
// Check if the current module backup database is present
// ------------------------------------------------------------------------------------
bool FileDbExists()
{
	char mod_name[MAX_MODULE_SIZE] = "";
	char db_path[MAX_PATH] = "";

	strcpy_s(db_path, szCurrentDirectory);
	PathRemoveFileSpec(db_path);
	PathRemoveFileSpec(db_path);

	strcat_s(db_path, "\\db\\");
	Module::GetMainModuleName(mod_name);
	strcat_s(db_path, mod_name);

#ifdef _WIN64
	strcat_s(db_path, ".dd64");
#else
	strcat_s(db_path, ".dd32");
#endif // _WIN64

	return GetFileAttributes(db_path) != INVALID_FILE_ATTRIBUTES;
}

// ------------------------------------------------------------------------------------
// Load the configuration file with the settings of the plugin
// ------------------------------------------------------------------------------------
void LoadConfig()
{
 	IniManager iniReader(config_path);
	conf.undef_funtion_analysis = iniReader.ReadBoolean("settings", "analysis_undefunctions", false);
	conf.auto_analysis = iniReader.ReadBoolean("settings", "analysis_auto", false);
	conf.extended_analysis = iniReader.ReadBoolean("settings", "analysis_extended", false);
	conf.clear_usercomments = iniReader.ReadBoolean("settings", "clear_usercomments", false);
	conf.clear_userlabels = iniReader.ReadBoolean("settings", "clear_userlabels", false);
	conf.clear_autocomments = iniReader.ReadBoolean("settings", "clear_autocomments", true);
	conf.clear_autolabels = iniReader.ReadBoolean("settings", "clear_autolabels", true);
	conf.track_undef_functions = iniReader.ReadBoolean("settings", "track_undef_functions", true);
}

// ------------------------------------------------------------------------------------
// Save the configuration file for the settings of the plugin
// ------------------------------------------------------------------------------------
void SaveConfig()
{
	IniManager iniWriter(config_path);
	iniWriter.WriteBoolean("settings", "analysis_extended", conf.extended_analysis);
	iniWriter.WriteBoolean("settings", "analysis_undefunctions", conf.undef_funtion_analysis);
	iniWriter.WriteBoolean("settings", "analysis_auto", conf.auto_analysis);
	iniWriter.WriteBoolean("settings", "clear_usercomments", conf.clear_usercomments);
	iniWriter.WriteBoolean("settings", "clear_userlabels", conf.clear_userlabels);
	iniWriter.WriteBoolean("settings", "clear_autocomments", conf.clear_autocomments);
	iniWriter.WriteBoolean("settings", "clear_autolabels", conf.clear_autolabels);
	iniWriter.WriteBoolean("settings", "track_undef_functions", conf.track_undef_functions);

	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_EXT, conf.extended_analysis);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_UNDEF, conf.undef_funtion_analysis);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_AUTO, conf.auto_analysis);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_CLEAR_CMTS, conf.clear_usercomments);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_CLEAR_LBLS, conf.clear_userlabels);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_CLEAR_ACMTS, conf.clear_autocomments);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_CLEAR_ALBLS, conf.clear_autolabels);
	_plugin_menuentrysetchecked(pluginHandle, MENU_ANALYZE_TRACK_UNDEF, conf.track_undef_functions);
}

// ------------------------------------------------------------------------------------
// Load all the definition files
// ------------------------------------------------------------------------------------
bool LoadDefinitionFiles(string &defDir, string &faultyFile, int &errorLine)
{
 	char szAllFiles[MAX_PATH] = "";
	defDir = "";

 	apiFiles.clear();
	apiHFiles.clear();
 	
	defDir = szCurrentDirectory + string("apis_def\\");

	// Load api definition files
	strcpy_s(szAllFiles, szCurrentDirectory);
	strcat_s(szAllFiles, "apis_def\\*.*");
	if (!LoadApiFiles(&apiFiles, szAllFiles, defDir, faultyFile, errorLine))
		return false;

	// Load api definition files headers
	errorLine = -1; // restart error line flag
	defDir = szCurrentDirectory + string("apis_def\\headers\\");
	ZeroMemory(szAllFiles, MAX_PATH);
	strcpy_s(szAllFiles, szCurrentDirectory);
	strcat_s(szAllFiles, "apis_def\\headers\\*.*");
	if (!LoadApiFiles(&apiHFiles, szAllFiles, defDir, faultyFile, errorLine))
		return false;

	return true;
}

// ------------------------------------------------------------------------------------
// Load the given definition files directory into a global unordered_map
// ------------------------------------------------------------------------------------
bool LoadApiFiles(unordered_map<string, Utf8Ini*> *filesMap, char *szAllFiles, string defDir, string &faultyFile, int &errorLine)
{
	bool result = false;
	WIN32_FIND_DATA fd;

	HANDLE hFind = FindFirstFile(szAllFiles, &fd);
	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {
			// read all (real) files in current folder
			// , delete '!' read other 2 default folder . and ..
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
			{
				string currentFile = defDir + fd.cFileName;
				auto hFile = CreateFile(currentFile.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
				if (hFile != INVALID_HANDLE_VALUE)
				{
					auto size = GetFileSize(hFile, nullptr);
					if (size)
					{
						vector<char> iniData(size + 1, '\0');
						DWORD read = 0;
						if (ReadFile(hFile, iniData.data(), size, &read, nullptr))
						{
							Utf8Ini *file = new Utf8Ini();
							if (file->Deserialize(iniData.data(), errorLine))
							{
								size_t fnsize = strlen(fd.cFileName) + 1;
								char *api = new char[fnsize];
								strcpy_s(api, fnsize, fd.cFileName);
								TruncateString(api, '.'); // strip .api from file name
								string apiName = api;

								// Add to map of def files
								filesMap->insert({ apiName, file });

								result = true;
								delete[] api;
							}
							else
							{	// if there is any malformed definition file dont load
								faultyFile = currentFile;
								result = false;
								CloseHandle(hFile);
								break;
							}
						}
					}
					CloseHandle(hFile);
				}
			}
		} while (FindNextFile(hFind, &fd));
		FindClose(hFind);
	}

	return result;
}

// ------------------------------------------------------------------------------------
// Clear all loops in a given range
// ------------------------------------------------------------------------------------
void ClearLoopsRange(const duint start, const duint end, duint depth)
{
	duint loop_start = 0;
	duint loop_end = 0;
	BASIC_INSTRUCTION_INFO bii;

	ZeroMemory(&bii, sizeof(BASIC_INSTRUCTION_INFO));
	duint ptrIndex = start;
	do
	{
		DbgDisasmFastAt(ptrIndex, &bii);

		DbgLoopGet(0, ptrIndex, &loop_start, &loop_end);
		if (loop_start != 0)
		{
			DbgLoopDel(0, loop_start);
			ptrIndex = loop_end; // jump to the end of the loop
			DbgDisasmFastAt(ptrIndex, &bii);
		}

		loop_start = 0;
		loop_end = 0;
		ptrIndex += bii.size;
	} while (ptrIndex < end);
}

// ------------------------------------------------------------------------------------
// Returns true if there are multiple lines selected in the disasm window
// ------------------------------------------------------------------------------------
bool IsMultipleSelection()
{
	duint start = 0;
	duint end = 0;

	GetDisasmRange(&start, &end);
	return (start != end);
}

// ------------------------------------------------------------------------------------
// Removes the analysis in the given case
// ------------------------------------------------------------------------------------
void ResetGlobals()
{
	// reset analysis menus flags
	selectionAnal = false;
	singleFunctionAnal = false;
	completeAnal = false;

	// reset global flags
	IsPrologCall = false;

	ZeroMemory(&procSummary, sizeof(stPROCSUMMARY));
}

// ------------------------------------------------------------------------------------
// Prints an analysis summary to log
// ------------------------------------------------------------------------------------
void PrintExecLogSummary()
{
	char summaryMsg[512] = "";

	sprintf_s(summaryMsg, "[xAnalyzer]: Execution Summary\r\n"
							"-------------------------------\r\n"
							" - Defined Functions Detected: %d\r\n"
							" - Undefined Functions Detected: %d\r\n"
							" - VB DllFunctionCalls Stubs Detected: %d\r\n"
							" - Total Functions Detected: %d\r\n"
							" - Total Loops Detected: %d\r\n"
							" - Total Comments Set: %d\r\n"
							" - Total Labels Set: %d\r\n"
							"-------------------------------\r\n",
							procSummary.defCallsDetected,
							procSummary.undefCallsDetected,
							procSummary.DllFunctionCallsDetected,
							procSummary.defCallsDetected + procSummary.undefCallsDetected,
							procSummary.loopsDetected,
							procSummary.totalCommentsSet,
							procSummary.totalLabelsSet);

	GuiAddLogMessage(summaryMsg);
}

//------------------------------------------------------------------------------------
// This command displays a brief commands help for the plugin usage
//------------------------------------------------------------------------------------
void DisplayHelp()
{
	const char *pluginHelp = "\n[xAnalyzer]: Available Commands:\r\n"
							 "--------------------------------\r\n"
							 "xanal selection : Performs a selection analysis\r\n"
							 "xanal function : Performs a function analysis\r\n"
							 "xanal module : Performs an entire module code section analysis\r\n"
							 "xanalremove selection : Removes a previous selection analysis\r\n"
							 "xanalremove function : Removes a previous function analysis\r\n"
							 "xanalremove module : Removes a previous module code section analysis\r\n"
							 "xanal help : Brings up this help text\r\n\n";

	GuiAddLogMessage(pluginHelp);
}
