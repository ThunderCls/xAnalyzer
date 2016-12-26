#pragma once

#ifndef xanalyzer
#define xanalyzer

#include "plugin.h"
#include <stack>


#define INSTRUCTIONSTACK_MAXSIZE 50
#define REGISTER_MAXSIZE 10

using namespace std;
using namespace Script;

typedef struct stINSTRUCTIONSTACK{
	duint Address;
	char Instruction[MAX_MNEMONIC_SIZE * 4];
	char destRegister[REGISTER_MAXSIZE];
}INSTRUCTIONSTACK;

typedef struct stLOOPSTACK{
	duint dwStartAddress;
	duint dwEndAddress;
}LOOPSTACK;

typedef struct stCONFIG{
	bool undef_funtion_analysis;
	bool auto_analysis;
	bool extended_analysis;
}CONFIG;

extern CONFIG conf;
extern bool selectionAnal;
extern bool singleFunctionAnal;
extern bool completeAnal;
extern char szCurrentDirectory[MAX_PATH];
extern char szAPIFunction[MAX_COMMENT_SIZE];
extern char szAPIFunctionParameter[MAX_COMMENT_SIZE];
extern char config_path[MAX_PATH];
extern duint addressFunctionStart;
extern stack <INSTRUCTIONSTACK*> IS;

void AnalyzeBytesRange(duint dwEntry, duint dwExit);
void OnBreakpoint(PLUG_CB_BREAKPOINT* bpInfo);
void OnWinEvent(PLUG_CB_WINEVENT *info);
void DbgGetEntryExitPoints(duint *lpdwEntry, duint *lpdwExit);
void GetExtendedAnalysisRange(duint *lpdwEntry, duint *lpdwExit, duint entry, char *modname, Module::ModuleSectionInfo *modInfo);
void GetRegularAnalysisRange(duint *lpdwEntry, duint *lpdwExit, char *modname);
void GetFunctionAnalysisRange(duint *lpdwEntry, duint *lpdwExit, duint selectedAddr);
void GetAnalysisBoundaries();
bool Strip_x64dbg_calls(LPSTR lpszCallText, LPSTR lpszAPIFunction);
bool GetDynamicUndefinedCall(LPSTR lpszCallText, LPSTR dest);
bool HasRegister(LPSTR reg);
void SetAutoCommentIfCommentIsEmpty(INSTRUCTIONSTACK *inst, LPSTR CommentString, size_t CommentStringCount, bool apiCALL = false);
bool SearchApiFileForDefinition(LPSTR lpszApiModule, LPSTR lpszApiFunction, LPSTR lpszApiDefinition, bool recursive);
int GetFunctionParamCount(LPSTR lpszApiModule, LPSTR lpszApiFunction);
bool GetFunctionParam(LPSTR lpszApiModule, LPSTR lpszApiFunction, duint dwParamNo, LPSTR lpszApiFunctionParameter);
bool ishex(LPCTSTR str);
void DoInitialAnalysis();
void TruncateString(LPSTR str, char value);
void ToUpperHex(char *str);
void GetDisasmRange(duint *selstart, duint *selend, duint raw_start = 0, duint raw_end = 0);
bool IsMultipleSelection();
void ExtraAnalysis();
bool cbExtendedAnalysis(int argc, char* argv[]);
bool cbExtendedAnalysisRemove(int argc, char* argv[]);
void DoExtendedAnalysis();
void ClearStack(stack<INSTRUCTIONSTACK*> &q);
void ClearLoopStack(stack<LOOPSTACK*> &q);
string CallDirection(BASIC_INSTRUCTION_INFO *bii);
bool SetFunctionParams(Script::Argument::ArgumentInfo *ai, char *szAPIModuleName);
bool SetSubParams(Argument::ArgumentInfo *ai);
bool IsArgumentInstruction(const BASIC_INSTRUCTION_INFO *bii);
bool IsProlog(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress);
bool IsEpilog(const BASIC_INSTRUCTION_INFO *bii);
char *GetInstructionSource(char *instruction);
void GetDestRegister(char *instruction, char *destRegister);
void GetArgument(duint CurrentParam, vector<INSTRUCTIONSTACK*> &arguments, INSTRUCTIONSTACK &arg);
void IsLoopJump(BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress);
void SetFunctionLoops();
bool FileDbExists();
void LoadConfig();
void SaveConfig();
bool LoadDefinitionFiles(string &faultyFile, int &errorLine);
void RemoveAnalysis();
void ResetGlobals();
void ClearLoopsRange(const duint start, const duint end, duint depth = 0);
void ClearPrevAnalysis(const duint start, const duint end, bool clear_user_comments = false);
void GetModuleNameSearch(char *szAPIModuleName, char *szAPIModuleNameSearch);
#ifdef _WIN64
bool IsArgumentRegister(const char *destination);
#endif


#endif