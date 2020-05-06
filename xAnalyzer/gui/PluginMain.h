#pragma once

#ifndef _PLUGINMAIN_H
#define _PLUGINMAIN_H

#include <windows.h>

namespace Plugin
{
    extern int handle;
    extern HWND hwndDlg;
    extern int hMenu;
    extern int hMenuDisasm;
    extern int hMenuDump;
    extern int hMenuStack;
    extern int hMenuGraph;
    extern int hMenuMemmap;
    extern int hMenuSymmod;
} //Plugin

#endif //_PLUGINMAIN_H
