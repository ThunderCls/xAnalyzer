#ifndef _PLUGINS_H
#define _PLUGINS_H

#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifndef PLUG_IMPEXP
#ifdef BUILD_DBG
#define PLUG_IMPEXP __declspec(dllexport)
#else
#define PLUG_IMPEXP __declspec(dllimport)
#endif //BUILD_DBG
#endif //PLUG_IMPEXP

#include "_plugin_types.h"

//default structure alignments forced
#ifdef _WIN64
#pragma pack(push, 16)
#else //x86
#pragma pack(push, 8)
#endif //_WIN64

//defines
#define PLUG_SDKVERSION 1

#define PLUG_DB_LOADSAVE_DATA 1
#define PLUG_DB_LOADSAVE_ALL 2

//structures
typedef struct
{
    //provided by the debugger
    int pluginHandle;
    //provided by the pluginit function
    int sdkVersion;
    int pluginVersion;
    char pluginName[256];
} PLUG_INITSTRUCT;

typedef struct
{
    //provided by the debugger
    HWND hwndDlg; //gui window handle
    int hMenu; //plugin menu handle
    int hMenuDisasm; //plugin disasm menu handle
    int hMenuDump; //plugin dump menu handle
    int hMenuStack; //plugin stack menu handle
} PLUG_SETUPSTRUCT;

typedef struct
{
    void* data; //user data
} PLUG_SCRIPTSTRUCT;

//callback structures
typedef struct
{
    const char* szFileName;
} PLUG_CB_INITDEBUG;

typedef struct
{
    void* reserved;
} PLUG_CB_STOPDEBUG;

typedef struct
{
    CREATE_PROCESS_DEBUG_INFO* CreateProcessInfo;
    IMAGEHLP_MODULE64* modInfo;
    const char* DebugFileName;
    PROCESS_INFORMATION* fdProcessInfo;
} PLUG_CB_CREATEPROCESS;

typedef struct
{
    EXIT_PROCESS_DEBUG_INFO* ExitProcess;
} PLUG_CB_EXITPROCESS;

typedef struct
{
    CREATE_THREAD_DEBUG_INFO* CreateThread;
    DWORD dwThreadId;
} PLUG_CB_CREATETHREAD;

typedef struct
{
    EXIT_THREAD_DEBUG_INFO* ExitThread;
    DWORD dwThreadId;
} PLUG_CB_EXITTHREAD;

typedef struct
{
    void* reserved;
} PLUG_CB_SYSTEMBREAKPOINT;

typedef struct
{
    LOAD_DLL_DEBUG_INFO* LoadDll;
    IMAGEHLP_MODULE64* modInfo;
    const char* modname;
} PLUG_CB_LOADDLL;

typedef struct
{
    UNLOAD_DLL_DEBUG_INFO* UnloadDll;
} PLUG_CB_UNLOADDLL;

typedef struct
{
    OUTPUT_DEBUG_STRING_INFO* DebugString;
} PLUG_CB_OUTPUTDEBUGSTRING;

typedef struct
{
    EXCEPTION_DEBUG_INFO* Exception;
} PLUG_CB_EXCEPTION;

typedef struct
{
    BRIDGEBP* breakpoint;
} PLUG_CB_BREAKPOINT;

typedef struct
{
    void* reserved;
} PLUG_CB_PAUSEDEBUG;

typedef struct
{
    void* reserved;
} PLUG_CB_RESUMEDEBUG;

typedef struct
{
    void* reserved;
} PLUG_CB_STEPPED;

typedef struct
{
    DWORD dwProcessId;
} PLUG_CB_ATTACH;

typedef struct
{
    PROCESS_INFORMATION* fdProcessInfo;
} PLUG_CB_DETACH;

typedef struct
{
    DEBUG_EVENT* DebugEvent;
} PLUG_CB_DEBUGEVENT;

typedef struct
{
    int hEntry;
} PLUG_CB_MENUENTRY;

typedef struct
{
    MSG* message;
    long* result;
    bool retval;
} PLUG_CB_WINEVENT;

typedef struct
{
    MSG* message;
    bool retval;
} PLUG_CB_WINEVENTGLOBAL;

typedef struct
{
    json_t* root;
    int loadSaveType;
} PLUG_CB_LOADSAVEDB;

typedef struct
{
    const char* symbol;
    bool retval;
} PLUG_CB_FILTERSYMBOL;

typedef struct
{
    duint cip;
    bool stop;
} PLUG_CB_TRACEEXECUTE;

typedef struct
{
    int hWindow;
    duint VA;
} PLUG_CB_SELCHANGED;

typedef struct
{
    BridgeCFGraphList graph;
} PLUG_CB_ANALYZE;

typedef struct
{
    duint addr;
    ADDRINFO* addrinfo;
    bool retval;
} PLUG_CB_ADDRINFO;

//enums
typedef enum
{
    CB_INITDEBUG, //PLUG_CB_INITDEBUG
    CB_STOPDEBUG, //PLUG_CB_STOPDEBUG
    CB_CREATEPROCESS, //PLUG_CB_CREATEPROCESS
    CB_EXITPROCESS, //PLUG_CB_EXITPROCESS
    CB_CREATETHREAD, //PLUG_CB_CREATETHREAD
    CB_EXITTHREAD, //PLUG_CB_EXITTHREAD
    CB_SYSTEMBREAKPOINT, //PLUG_CB_SYSTEMBREAKPOINT
    CB_LOADDLL, //PLUG_CB_LOADDLL
    CB_UNLOADDLL, //PLUG_CB_UNLOADDLL
    CB_OUTPUTDEBUGSTRING, //PLUG_CB_OUTPUTDEBUGSTRING
    CB_EXCEPTION, //PLUG_CB_EXCEPTION
    CB_BREAKPOINT, //PLUG_CB_BREAKPOINT
    CB_PAUSEDEBUG, //PLUG_CB_PAUSEDEBUG
    CB_RESUMEDEBUG, //PLUG_CB_RESUMEDEBUG
    CB_STEPPED, //PLUG_CB_STEPPED
    CB_ATTACH, //PLUG_CB_ATTACHED (before attaching, after CB_INITDEBUG)
    CB_DETACH, //PLUG_CB_DETACH (before detaching, before CB_STOPDEBUG)
    CB_DEBUGEVENT, //PLUG_CB_DEBUGEVENT (called on any debug event)
    CB_MENUENTRY, //PLUG_CB_MENUENTRY
    CB_WINEVENT, //PLUG_CB_WINEVENT
    CB_WINEVENTGLOBAL, //PLUG_CB_WINEVENTGLOBAL
    CB_LOADDB, //PLUG_CB_LOADSAVEDB
    CB_SAVEDB, //PLUG_CB_LOADSAVEDB
    CB_FILTERSYMBOL, //PLUG_CB_FILTERSYMBOL
    CB_TRACEEXECUTE, //PLUG_CB_TRACEEXECUTE
    CB_SELCHANGED, //PLUG_CB_SELCHANGED
    CB_ANALYZE, //PLUG_CB_ANALYZE
    CB_ADDRINFO, //PLUG_CB_ADDRINFO
    CB_LAST
} CBTYPE;

//typedefs
typedef void (*CBPLUGIN)(CBTYPE cbType, void* callbackInfo);
typedef bool (*CBPLUGINCOMMAND)(int argc, char** argv);
typedef void (*CBPLUGINSCRIPT)();
typedef duint(*CBPLUGINEXPRFUNCTION)(int argc, duint* argv, void* userdata);

//exports
#ifdef __cplusplus
extern "C"
{
#endif

PLUG_IMPEXP void _plugin_registercallback(int pluginHandle, CBTYPE cbType, CBPLUGIN cbPlugin);
PLUG_IMPEXP bool _plugin_unregistercallback(int pluginHandle, CBTYPE cbType);
PLUG_IMPEXP bool _plugin_registercommand(int pluginHandle, const char* command, CBPLUGINCOMMAND cbCommand, bool debugonly);
PLUG_IMPEXP bool _plugin_unregistercommand(int pluginHandle, const char* command);
PLUG_IMPEXP void _plugin_logprintf(const char* format, ...);
PLUG_IMPEXP void _plugin_logputs(const char* text);
PLUG_IMPEXP void _plugin_debugpause();
PLUG_IMPEXP void _plugin_debugskipexceptions(bool skip);
PLUG_IMPEXP int _plugin_menuadd(int hMenu, const char* title);
PLUG_IMPEXP bool _plugin_menuaddentry(int hMenu, int hEntry, const char* title);
PLUG_IMPEXP bool _plugin_menuaddseparator(int hMenu);
PLUG_IMPEXP bool _plugin_menuclear(int hMenu);
PLUG_IMPEXP void _plugin_menuseticon(int hMenu, const ICONDATA* icon);
PLUG_IMPEXP void _plugin_menuentryseticon(int pluginHandle, int hEntry, const ICONDATA* icon);
PLUG_IMPEXP void _plugin_menuentrysetchecked(int pluginHandle, int hEntry, bool checked);
PLUG_IMPEXP void _plugin_startscript(CBPLUGINSCRIPT cbScript);
PLUG_IMPEXP bool _plugin_waituntilpaused();
PLUG_IMPEXP bool _plugin_registerexprfunction(int pluginHandle, const char* name, int argc, CBPLUGINEXPRFUNCTION cbFunction, void* userdata);
PLUG_IMPEXP bool _plugin_unregisterexprfunction(int pluginHandle, const char* name);
PLUG_IMPEXP bool _plugin_unload(const char* pluginName);
PLUG_IMPEXP bool _plugin_load(const char* pluginName);
PLUG_IMPEXP duint _plugin_hash(const void* data, duint size);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif // _PLUGINS_H
