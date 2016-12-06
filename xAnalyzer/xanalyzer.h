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

extern bool extendedAnal;
extern char szCurrentDirectory[MAX_PATH];
extern char szAPIFunction[MAX_COMMENT_SIZE];
extern char szApiFile[MAX_PATH];
extern char szAPIFunctionParameter[MAX_COMMENT_SIZE];
extern duint addressFunctionStart;
extern stack <INSTRUCTIONSTACK*> IS;

void OnBreakpoint(PLUG_CB_BREAKPOINT* bpInfo);
void DbgGetEntryExitPoints(duint *lpdwEntry, duint *lpdwExit);
bool Strip_x64dbg_calls(LPSTR lpszCallText, LPSTR lpszAPIFunction);
bool GetDynamicUndefinedCall(LPSTR lpszCallText, LPSTR dest);
bool HasRegister(LPSTR reg);
void SetAutoCommentIfCommentIsEmpty(INSTRUCTIONSTACK *inst, LPSTR CommentString, size_t CommentStringCount, bool apiCALL = false);
bool SearchApiFileForDefinition(LPSTR lpszApiModule, LPSTR lpszApiFunction, LPSTR lpszApiDefinition, bool recursive);
bool GetApiFileDefinition(LPSTR lpszApiFunction, LPSTR lpszApiDefinition, LPSTR szFile);
int GetFunctionParamCount(LPSTR lpszApiModule, LPSTR lpszApiFunction);
bool GetFunctionParam(LPSTR lpszApiModule, LPSTR lpszApiFunction, duint dwParamNo, LPSTR lpszApiFunctionParameter);
bool ishex(LPCTSTR str);
void TruncateString(LPSTR str, char value);
void ExtraAnalysis();
bool cbExtendedAnalysis(int argc, char* argv[]);
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
#ifdef _WIN64
bool IsArgumentRegister(const char *destination);
#endif


#endif