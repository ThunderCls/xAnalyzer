#pragma once

#ifndef xanalyzer
#define xanalyzer

#include "plugin.h"
#include <stack>


#define INSTRUCTIONSTACK_MAXSIZE 24

using namespace std;

typedef struct stINSTRUCTIONSTACK{
	DWORD Address;
	char Instruction[MAX_MNEMONIC_SIZE * 4];
}INSTRUCTIONSTACK;

extern char szCurrentDirectory[MAX_PATH];
extern char szFindApiFiles[MAX_PATH];
extern char szAPIFunction[MAX_PATH];
extern char szApiFile[MAX_PATH];
extern char szAPIDefinition[MAX_PATH];
extern char szAPIFunctionParameter[MAX_COMMENT_SIZE];
extern char szDisasmText[GUI_MAX_DISASSEMBLY_SIZE];
extern std::stack <INSTRUCTIONSTACK*> IS;


void OnBreakpoint(PLUG_CB_BREAKPOINT* bpInfo);
void DbgGetEntryExitPoints(DWORD *lpdwEntry, DWORD *lpdwExit);
bool Strip_x64dbg_calls(LPSTR lpszCallText, LPSTR lpszAPIFunction);
void SetAutoCommentIfCommentIsEmpty(const INSTRUCTIONSTACK *inst, LPSTR CommentString, bool apiCALL = false);
bool SearchApiFileForDefinition(LPSTR lpszApiModule, LPSTR lpszApiFunction, LPSTR lpszApiDefinition);
int GetFunctionParamCount(LPSTR lpszApiModule, LPSTR lpszApiFunction);
bool GetFunctionParam(LPSTR lpszApiModule, LPSTR lpszApiFunction, DWORD dwParamNo, LPSTR lpszApiFunctionParameter);
bool ishex(LPCTSTR str);
void TruncateString(LPSTR str, char value);
void GenAPIInfo();
bool cbExtendedAnalysis(int argc, char* argv[]);
void DoExtendedAnalysis();
void ClearStack(stack<INSTRUCTIONSTACK*> &q);
LPSTR IndirectCallDirection(LPSTR szInstruction);
void SetFunctionParams(Script::Argument::ArgumentInfo *ai, char *szAPIModuleName);


#endif