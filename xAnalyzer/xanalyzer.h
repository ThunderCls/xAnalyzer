#pragma once

#ifndef xanalyzer
#define xanalyzer

#include "plugin.h"
#include <stack>
#include "Utf8Ini/Utf8Ini.h"


#define INSTRUCTIONSTACK_MAXSIZE 50
#define INSTRUCTION_FUNCT_POINTER_MAXSIZE 100
//#define REGISTER_MAXSIZE 10
#define VB_STUB_SIZE 32
#define VB_STUB_APISTR_POINTER 20

using namespace std;
using namespace Script;

typedef struct stINSTRUCTIONSTACK{
	duint Address;
	char Instruction[MAX_MNEMONIC_SIZE * 4];
	char GuiInstruction[MAX_MNEMONIC_SIZE * 4];
	char DestinationRegister[MAX_MNEMONIC_SIZE * 4];
	char SourceRegister[MAX_MNEMONIC_SIZE * 4];
}INSTRUCTIONSTACK;

typedef struct stLOOPSTACK{
	duint dwStartAddress;
	duint dwEndAddress;
}LOOPSTACK;

typedef struct stCONFIG{
	bool undef_funtion_analysis;
	bool auto_analysis;
	bool extended_analysis;
	bool clear_usercomments;
	bool clear_autocomments;
	bool clear_userlabels;
	bool clear_autolabels;
	bool track_undef_functions;
}CONFIG;

typedef struct stPROCSUMMARY{
	duint defCallsDetected;
	duint undefCallsDetected;
	duint DllFunctionCallsDetected;
	duint loopsDetected;
	duint totalCommentsSet;
	duint totalLabelsSet;
}PROCSUMMARY;

extern CONFIG conf;
extern bool selectionAnal;
extern bool singleFunctionAnal;
extern bool completeAnal;
extern string config_path;
extern string szAPIFunction;
extern char szCurrentDirectory[MAX_PATH];
extern char szAPIFunctionParameter[MAX_COMMENT_SIZE];
extern duint addressFunctionStart;
extern stack <INSTRUCTIONSTACK*> stackInstructions;

void AnalyzeBytesRange(duint dwEntry, duint dwExit);
void OnBreakpoint(PLUG_CB_BREAKPOINT* bpInfo);
//void OnWinEvent(PLUG_CB_WINEVENT *info);
void DbgGetEntryExitPoints(duint *lpdwEntry, duint *lpdwExit);
void GetExtendedAnalysisRange(duint *lpdwEntry, duint *lpdwExit, duint entry, char *modname, Module::ModuleSectionInfo *modInfo);
void GetRegularAnalysisRange(duint *lpdwEntry, duint *lpdwExit, char *modname);
void GetFunctionAnalysisRange(duint *lpdwEntry, duint *lpdwExit, duint selectedAddr);
void GetAnalysisBoundaries();
duint GetModuleEntryPoint(char *modname);
bool Strip_x64dbg_calls(LPSTR lpszCallText);
void StripDbgCommentAddress(char *szComment);
string StripFunctNameFromInst(char *instruction);
bool GetDynamicUndefinedCall(LPSTR lpszCallText, LPSTR dest);
bool HasRegister(const char *reg);
void SetAutoCommentIfCommentIsEmpty(INSTRUCTIONSTACK *inst, char *CommentString, size_t CommentStringCount, bool apiCALL = false);
bool SearchApiFileForDefinition(LPSTR lpszApiModule, LPSTR lpszApiDefinition, bool recursive);
int GetFunctionParamCount(LPSTR lpszApiModule, string lpszApiFunction);
bool GetFunctionParam(LPSTR lpszApiModule, string lpszApiFunction, duint dwParamNo, LPSTR lpszApiFunctionParameter);
bool IsHex(const char *str);
duint hextoduint(LPCTSTR str);
void DoInitialAnalysis();
void ProcessDllFunctionCalls(duint startAddr = -1, duint size = -1);
void LabelDllFunctionCalls(duint rvaCodeSection, duint sectionSize, string DllFunctionCallPattern);
bool IsVBExecutable();
void PrintExecLogSummary();
void TruncateString(LPSTR str, char value);
void ToUpperHex(char *str);
string ToUpper(const char *str);
void GetDisasmRange(duint *selstart, duint *selend, duint raw_start = 0, duint raw_end = 0);
bool IsMultipleSelection();
void ExtraAnalysis();
bool cbExtendedAnalysis(int argc, char* argv[]);
bool cbExtendedAnalysisRemove(int argc, char* argv[]);
void DoExtendedAnalysis();
void ClearStack(stack<INSTRUCTIONSTACK*> &q);
void ClearLoopStack(stack<LOOPSTACK*> &q);
void ClearVector(vector<INSTRUCTIONSTACK*> &q);
string CallDirection(BASIC_INSTRUCTION_INFO *bii);
bool SetFunctionParams(Script::Argument::ArgumentInfo *ai, char *szAPIModuleName);
bool IsHeaderConstant(const char *CommentString, char *szComment, char *inst_source = NULL, char *gui_inst_source = NULL);
bool IsNumericParam(string paramType);
bool IsMovStack(BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress);
bool IsMovFunctPointer(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress);
void TraverseHFilesTree(string &base, string header, string &htype, char *lpszApiConstant, Utf8Ini *defApiHFile, bool getTypeDisplay = false);
void GetConstantValue(char *lpszApiConstant, const char *CommentString);
bool SetSubParams(Argument::ArgumentInfo *ai);
bool IsArgumentInstruction(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress);
bool IsValidArgumentInstruction(INSTRUCTIONSTACK *inst, duint args_count);
bool IsProlog(const BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress);
bool IsEpilog(const BASIC_INSTRUCTION_INFO *bii);
char *GetInstructionSource(char *instruction);
void DecomposeMovInstruction(char *instruction, char *destination, char *source);
void GetDestinationRegister(char *instruction, char *destRegister);
void GetArgument(duint CurrentParam, vector<INSTRUCTIONSTACK*> &arguments, INSTRUCTIONSTACK &arg);
void IsLoopJump(BASIC_INSTRUCTION_INFO *bii, duint CurrentAddress);
void SetFunctionLoops();
bool FileDbExists();
void DisplayHelp();
void LoadConfig();
void SaveConfig();
bool LoadDefinitionFiles(string &folder, string &faultyFile, int &errorLine);
bool LoadApiFiles(unordered_map<string, Utf8Ini*> *filesMap, char *szAllFiles, string defDir, string &faultyFile, int &errorLine);
void RemoveAnalysis();
void ResetGlobals();
void ClearLoopsRange(const duint start, const duint end, duint depth = 0);
void ClearPrevAnalysis(const duint start, const duint end);
void GetModuleNameSearch(char *szAPIModuleName, char *szAPIModuleNameSearch);
bool FindFunctionFromPointer(char *szDisasmText, char *szFunctionName);
string StripFunctionNamePointer(char *line, int *index = 0);
#ifdef _WIN64
bool IsArgumentRegister(const char *destination);
#endif


#endif