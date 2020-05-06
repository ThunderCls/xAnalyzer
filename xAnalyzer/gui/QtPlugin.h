#pragma once

#ifndef QTPLUGIN_H
#define QTPLUGIN_H

#include "../core/AnalyzerHub.h"
#include <QString>

namespace QtPlugin
{
    enum
    {
        Options = 1,
        About,
        AnalyzeSelection,
        AnalyzeFunction,
        AnalyzeModule,
        RemoveSelection,
        RemoveFunction,
        RemoveModule
    };

    bool Init();
    void Setup();
    void WaitForSetup();
    void Stop();
    void WaitForStop();
    void ShowTab();
    void CreatePluginMenu();
    void LoadSettings();
    void SaveSettings();

    HUB_EXPIMP void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info);
    HUB_EXPIMP void CBBREAKPOINT(CBTYPE cbType, PLUG_CB_BREAKPOINT* bpInfo);

    bool cbRunAnalysis(int argc, char* argv[]);
    bool cbRemoveAnalysis(int argc, char* argv[]);
    bool LaunchAnalyzerTask(QString analysisType, AnalyzerHub::AnalyzerMode analyzerMode);
    bool DebugeeDatabaseExists();
} //QtPlugin

#endif // QTPLUGIN_H
