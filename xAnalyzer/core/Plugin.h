#pragma once

// workaround for compiler dependent relative path
// https://forum.qt.io/topic/109248/is-there-a-define-for-checking-if-the-compiler-is-qt/6
#if defined(QT_CORE_LIB)
	#define PATH "../"
#elif defined(UNIT_TEST)
	#define PATH "../xAnalyzer/"
#else
	#define PATH "./"
#endif

#include "../pluginsdk/bridgemain.h"
#include "../pluginsdk/_plugins.h"

#include "../pluginsdk/_scriptapi_argument.h"
#include "../pluginsdk/_scriptapi_assembler.h"
#include "../pluginsdk/_scriptapi_bookmark.h"
#include "../pluginsdk/_scriptapi_comment.h"
#include "../pluginsdk/_scriptapi_debug.h"
#include "../pluginsdk/_scriptapi_flag.h"
#include "../pluginsdk/_scriptapi_function.h"
#include "../pluginsdk/_scriptapi_gui.h"
#include "../pluginsdk/_scriptapi_label.h"
#include "../pluginsdk/_scriptapi_memory.h"
#include "../pluginsdk/_scriptapi_misc.h"
#include "../pluginsdk/_scriptapi_module.h"
#include "../pluginsdk/_scriptapi_pattern.h"
#include "../pluginsdk/_scriptapi_register.h"
#include "../pluginsdk/_scriptapi_stack.h"
#include "../pluginsdk/_scriptapi_symbol.h"

#include "../pluginsdk/DeviceNameResolver/DeviceNameResolver.h"
#include "../pluginsdk/jansson/jansson.h"
#include "../pluginsdk/lz4/lz4file.h"
#include "../pluginsdk/TitanEngine/TitanEngine.h"
#include "../pluginsdk/XEDParse/XEDParse.h"

#ifdef _WIN64
#pragma comment(lib, PATH"pluginsdk/x64dbg.lib")
#pragma comment(lib, PATH"pluginsdk/x64bridge.lib")
#pragma comment(lib, PATH"pluginsdk/DeviceNameResolver/DeviceNameResolver_x64.lib")
#pragma comment(lib, PATH"pluginsdk/jansson/jansson_x64.lib")
#pragma comment(lib, PATH"pluginsdk/lz4/lz4_x64.lib")
#pragma comment(lib, PATH"pluginsdk/TitanEngine/TitanEngine_x64.lib")
#pragma comment(lib, PATH"pluginsdk/XEDParse/XEDParse_x64.lib")
#else
#pragma comment(lib, PATH"pluginsdk/x32dbg.lib")
#pragma comment(lib, PATH"pluginsdk/x32bridge.lib")
#pragma comment(lib, PATH"pluginsdk/DeviceNameResolver/DeviceNameResolver_x86.lib")
#pragma comment(lib, PATH"pluginsdk/jansson/jansson_x86.lib")
#pragma comment(lib, PATH"pluginsdk/lz4/lz4_x86.lib")
#pragma comment(lib, PATH"pluginsdk/TitanEngine/TitanEngine_x86.lib")
#pragma comment(lib, PATH"pluginsdk/XEDParse/XEDParse_x86.lib")
#endif //_WIN64