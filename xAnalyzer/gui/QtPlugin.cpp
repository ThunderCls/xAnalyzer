#include "QtPlugin.h"
#include "OptionsDialog.h"
#include "PluginTabWidget.h"
#include "PluginMain.h"
#include "AboutDialog.h"
#include <QFile>
#include <QDir>
#include <QSettings>
#include <ctime>
#include "../core/AnalyzerHub.h"
#include <QDebug> // TODO: remove (debug only)

static OptionsDialog* optionsDialog;
static AboutDialog* aboutDialog;
static HANDLE hSetupEvent;
static HANDLE hStopEvent;
static bool analysisLaunched;
static QSettings *qSettings;

AnalyzerHub::PluginSettings AnalyzerHub::pSettings;
AnalyzerHub::AnalysisType AnalyzerHub::analysisType;
AnalyzerHub::AnalyzerMode AnalyzerHub::analyzerMode;

//static PluginTabWidget* pluginTabWidget;

// --------------------------------------------------------
// plugin setup/stop code start
// --------------------------------------------------------

/**
 * @brief getResourceBytes
 * @param path
 * @return
 */
static QByteArray getResourceBytes(const char* path)
{
    QByteArray b;
    QFile s(path);
    if(s.open(QFile::ReadOnly))
        b = s.readAll();
    return b;
}

/**
 * @brief getParent
 * @return
 */
static QWidget* getParent()
{
    return QWidget::find((WId)Plugin::hwndDlg);
}

/**
 * @brief QtPlugin::Init
 */
bool QtPlugin::Init()
{
    LoadSettings();
    // TODO: implement
    /*if (!LoadDefinitionFiles())
    {
        if (errorLine != -1)
            sprintf_s(message, "[" PLUGIN_NAME "] Failed to load API definitions in file: \n%s - Line: %d\r\n"
                        "            Check the malformed file/line and try again...exiting plugin initialization!\r\n", faultyFile.c_str(), errorLine);
        else
            sprintf_s(message, "[" PLUGIN_NAME "] Failed to locate API definitions files.\r\n"
            "            Check that the folder: %s\r\n"
            "            and definition files are present and try again...exiting plugin initialization!\r\n", folder.c_str());

        _plugin_logprintf(message);
        return false;
    }*/

    hSetupEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    return true;
}

/**
 * @brief QtPlugin::Setup
 */
void QtPlugin::Setup()
{
    QWidget* parent = getParent();
    optionsDialog = new OptionsDialog(parent);
    aboutDialog = new AboutDialog(parent);
    analysisLaunched = false;    

    //pluginTabWidget = new PluginTabWidget(parent);
    //GuiAddQWidgetTab(pluginTabWidget);

    CreatePluginMenu();
    SetEvent(hSetupEvent);
}

/**
 * @brief QtPlugin::WaitForSetup
 */
void QtPlugin::WaitForSetup()
{
    WaitForSingleObject(hSetupEvent, INFINITE);
}

/**
 * @brief QtPlugin::Stop
 */
void QtPlugin::Stop()
{
    //GuiCloseQWidgetTab(pluginTabWidget);
    //pluginTabWidget->close();
    //delete pluginTabWidget;
    optionsDialog->close();
    aboutDialog->close();
    delete optionsDialog;
    delete aboutDialog;

    SetEvent(hStopEvent);
}

/**
 * @brief QtPlugin::WaitForStop
 */
void QtPlugin::WaitForStop()
{
    WaitForSingleObject(hStopEvent, INFINITE);
}

// --------------------------------------------------------
// plugin setup/stop code end
// --------------------------------------------------------

// --------------------------------------------------------
// plugin commands callbacks code start
// --------------------------------------------------------

bool QtPlugin::cbRunAnalysis(int argc, char* argv[])
{
    if (argc < 2)
    {
        return false;
    }

    return LaunchAnalyzerTask(QString(argv[1]), AnalyzerHub::AnalyzerMode::ModeAnalyze);
}

bool QtPlugin::cbRemoveAnalysis(int argc, char* argv[])
{
    if (argc < 2)
    {
        return false;
    }

    return LaunchAnalyzerTask(QString(argv[1]), AnalyzerHub::AnalyzerMode::ModeRemove);
}

bool QtPlugin::LaunchAnalyzerTask(QString action, AnalyzerHub::AnalyzerMode analyzerMode)
{
    AnalyzerHub::analyzerMode = analyzerMode;
    AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeNone;
    if(action == "selection")
    {
        SELECTIONDATA selection;
        GuiSelectionGet(GUI_DISASSEMBLY, &selection);
        if(selection.start != selection.end)
        {
            AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeSelection;
        }
    }
    else if(action == "function")
    {
        AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeFunction;
    }
    else if(action == "module")
    {
        AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeModule;
    }

    RunAnalyzer();
    return true;
}

// --------------------------------------------------------
// plugin commands callbacks code end
// --------------------------------------------------------

// --------------------------------------------------------
// plugin exported callback functions code start
// --------------------------------------------------------

HUB_EXPIMP void QtPlugin::CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
    AnalyzerHub::AnalysisType type = AnalyzerHub::TypeNone;
    switch(info->hEntry)
    {
        case QtPlugin::Options:
            optionsDialog->show();
            break;

        case QtPlugin::About:
            aboutDialog->show();
            break;

        case QtPlugin::AnalyzeSelection:
            //DbgCmdExec("xanal selection");
            AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeSelection;
            AnalyzerHub::analyzerMode = AnalyzerHub::AnalyzerMode::ModeAnalyze;
            RunAnalyzer();
            break;

        case QtPlugin::AnalyzeFunction:        
            //DbgCmdExec("xanal function");
            AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeFunction;
            AnalyzerHub::analyzerMode = AnalyzerHub::AnalyzerMode::ModeAnalyze;
            RunAnalyzer();
            break;

        case QtPlugin::AnalyzeModule:
            //DbgCmdExec("xanal module");
            AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeModule;
            AnalyzerHub::analyzerMode = AnalyzerHub::AnalyzerMode::ModeAnalyze;
            RunAnalyzer();
            break;

        case QtPlugin::RemoveSelection:
            //DbgCmdExec("xanalremove selection");
            AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeSelection;
            AnalyzerHub::analyzerMode = AnalyzerHub::AnalyzerMode::ModeRemove;
            RunAnalyzer();
            break;

        case QtPlugin::RemoveFunction:
            //DbgCmdExec("xanalremove function");
            AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeFunction;
            AnalyzerHub::analyzerMode = AnalyzerHub::AnalyzerMode::ModeRemove;
            RunAnalyzer();
            break;

        case QtPlugin::RemoveModule:
            //DbgCmdExec("xanalremove module");
            AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeModule;
            AnalyzerHub::analyzerMode = AnalyzerHub::AnalyzerMode::ModeRemove;
            RunAnalyzer();
            break;
    }
}

HUB_EXPIMP void QtPlugin::CBBREAKPOINT(CBTYPE cbType, PLUG_CB_BREAKPOINT* bpInfo)
{    
    if(analysisLaunched)
    {
        return;
    }

    if(Script::Module::EntryFromAddr(bpInfo->breakpoint->addr) == bpInfo->breakpoint->addr)
    {
        analysisLaunched = true;
        if(AnalyzerHub::pSettings.autoAnalysis)
        {
            /*clock_t start_t;
            clock_t end_t;
            GuiAddLogMessage("[xAnalyzer Qt] Starting entropy calculation\r\n");
            start_t = clock();*/

            // TODO: show entropy value in the gui?
            if(AnalyzerHub::pSettings.analyzeEntropy)
            {
                char exePath[MAX_PATH] = {0};
                Script::Module::PathFromAddr(bpInfo->breakpoint->addr, exePath);
                if(AnalyzerHub::IsExecutablePacked(exePath))
                {
                    MessageBoxA((HWND)getParent()->winId(),
                               "A high entropy has been found which could indicate a possible encrypted or packed executable",
                               "High Entropy",
                                MB_ICONINFORMATION + MB_OK);
                }
            }
            // TODO: remove only for debug
            /*end_t = clock();
            std::string msg = "[xAnalyzer Qt] Done in " + std::to_string(static_cast<double>((end_t - start_t) / CLOCKS_PER_SEC)) + "\r\n";
            GuiAddLogMessage(msg.c_str());*/

            if(!DebugeeDatabaseExists())
            {
                //DbgCmdExec("xanal module");
                AnalyzerHub::analysisType = AnalyzerHub::AnalysisType::TypeModule;
                AnalyzerHub::analyzerMode = AnalyzerHub::AnalyzerMode::ModeAnalyze;
                RunAnalyzer();
            }
            else
            {
                GuiAddLogMessage("[xAnalyzer]: Analysis retrieved from the data base\r\n");
                GuiAddStatusBarMessage("[xAnalyzer]: Analysis retrieved from the data base\r\n");
            }
        }
        else
        {
            GuiAddLogMessage("[xAnalyzer]: Automatic analysis is disabled\r\n");
            GuiAddStatusBarMessage("[xAnalyzer]: Automatic analysis is disabled\r\n");
        }
    }
}

HUB_EXPIMP void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
{
    // reset analysis flag
    analysisLaunched = false;
}

//HUB_EXPIMP void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
//{
//}
//
//HUB_EXPIMP void CBEXCEPTION(CBTYPE cbType, PLUG_CB_EXCEPTION* info)
//{
//}
//
//HUB_EXPIMP void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info)
//{
//}
//
//HUB_EXPIMP void CBCREATEPROCESS(CBTYPE cbType, PLUG_CB_CREATEPROCESS* info)
//{
//}
//
//HUB_EXPIMP void CBLOADDLL(CBTYPE cbType, PLUG_CB_LOADDLL* info)
//{
//}
//
//HUB_EXPIMP void CBSYSTEMBREAKPOINT(CBTYPE cbType, PLUG_CB_SYSTEMBREAKPOINT* info)
//{
//}
//
//HUB_EXPIMP void CBWINEVENT(CBTYPE cbType, PLUG_CB_WINEVENT* info)
//{
//}
//

// --------------------------------------------------------
// plugin exported callback functions code end
// --------------------------------------------------------

// --------------------------------------------------------
// plugin user functions code start
// --------------------------------------------------------

/**
 * @brief Passes data to the hub and launches the analyzer
 */
void QtPlugin::RunAnalyzer()
{
    AnalyzerHub::SetAnalyzerMode(AnalyzerHub::analyzerMode);
    AnalyzerHub::SetAnalysisType(AnalyzerHub::analysisType);
    AnalyzerHub::SetHubSettings(&AnalyzerHub::pSettings);
    AnalyzerHub::StartAnalyzer();
}

/**
 * @brief Loads the settings or creates a default file
 */
void QtPlugin::LoadSettings()
{
    QString settingsFile = QDir::currentPath();
    if(QDir(settingsFile).dirName().toLower() != "plugins")
    {
        settingsFile += "/plugins";
    }
    settingsFile += "/xanalyzer.ini";

    qSettings = new QSettings(settingsFile, QSettings::IniFormat);
    if(!QFile(settingsFile).exists())
    {
        // default settings

        // TODO: Add here other settings under this group
        //settings->beginGroup("settings");
        //settings->endGroup();

        qSettings->beginGroup("analysis");
        qSettings->setValue("extended", "true");
        qSettings->setValue("undefunctions", "true");
        qSettings->setValue("smarttrack", "true");
        qSettings->setValue("auto", "false");
        qSettings->setValue("entropy", "false");
        qSettings->endGroup();

        qSettings->beginGroup("data");
        qSettings->setValue("comment_type", 1);
        qSettings->setValue("clear_usercomments", "true");
        qSettings->setValue("clear_userlabels", "true");
        qSettings->setValue("clear_autocomments", "true");
        qSettings->setValue("clear_autolabels", "true");
        qSettings->endGroup();

        qSettings->sync();
    }

    // read values
    qSettings->beginGroup("analysis");
    AnalyzerHub::pSettings.extendedAnalysis = qSettings->value("extended").toBool();
    AnalyzerHub::pSettings.undeFunctions = qSettings->value("undefunctions").toBool();
    AnalyzerHub::pSettings.smartTrack = qSettings->value("smarttrack").toBool();
    AnalyzerHub::pSettings.autoAnalysis = qSettings->value("auto").toBool();
    AnalyzerHub::pSettings.analyzeEntropy = qSettings->value("entropy").toBool();
    qSettings->endGroup();

    qSettings->beginGroup("data");
    AnalyzerHub::pSettings.commentType = static_cast<AnalyzerHub::CommentType>(qSettings->value("comment_type").toInt());
    AnalyzerHub::pSettings.clearUsercomments = qSettings->value("clear_usercomments").toBool();
    AnalyzerHub::pSettings.clearUserlabels = qSettings->value("clear_userlabels").toBool();
    AnalyzerHub::pSettings.clearAutocomments = qSettings->value("clear_autocomments").toBool();
    AnalyzerHub::pSettings.clearAutolabels = qSettings->value("clear_autolabels").toBool();
    qSettings->endGroup();
}

/**
 * @brief Save settings back to disk
 */
void QtPlugin::SaveSettings()
{
    qSettings->beginGroup("analysis");
    qSettings->setValue("extended", AnalyzerHub::pSettings.extendedAnalysis);
    qSettings->setValue("undefunctions", AnalyzerHub::pSettings.undeFunctions);
    qSettings->setValue("smarttrack", AnalyzerHub::pSettings.smartTrack);
    //TODO: REMOVE
    //qDebug().nospace().noquote() << "pSettings Auto: " << AnalyzerHub::pSettings.autoAnalysis;
    qSettings->setValue("auto", AnalyzerHub::pSettings.autoAnalysis);
    qSettings->setValue("entropy", AnalyzerHub::pSettings.analyzeEntropy);
    qSettings->endGroup();

    qSettings->beginGroup("data");
    qSettings->setValue("comment_type", static_cast<int>(AnalyzerHub::pSettings.commentType));
    qSettings->setValue("clear_usercomments", AnalyzerHub::pSettings.clearUsercomments);
    qSettings->setValue("clear_userlabels", AnalyzerHub::pSettings.clearUserlabels);
    qSettings->setValue("clear_autocomments", AnalyzerHub::pSettings.clearAutocomments);
    qSettings->setValue("clear_autolabels", AnalyzerHub::pSettings.clearAutolabels);
    qSettings->endGroup();

    qSettings->sync();
}

/**
 * @brief Checks if a previous debugee database exists
 * @return
 */
bool QtPlugin::DebugeeDatabaseExists()
{
    //TODO: Check the db content and see if it is empty
    char moduleName[MAX_MODULE_SIZE] = {};

    Script::Module::GetMainModuleName(moduleName);
    QString dbPath = QDir::currentPath() + "\\db\\" + moduleName;

#ifdef _WIN64
    dbPath.append(".dd64");
#else
    dbPath.append(".dd32");
#endif // _WIN64

    return GetFileAttributes(dbPath.toStdWString().c_str()) != INVALID_FILE_ATTRIBUTES;
}

/**
 * @brief Create the plugin menus
 */
void QtPlugin::CreatePluginMenu()
{
    // main menus
    QFile iconFile(":/icons/images/mainicon.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        GuiMenuSetIcon(Plugin::hMenu, &icon);
        GuiMenuSetIcon(Plugin::hMenuDisasm, &icon);
        iconFile.close();
    }

    _plugin_menuaddentry(Plugin::hMenu, QtPlugin::Options, "Options...");
    iconFile.setFileName(":/icons/images/settings.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        _plugin_menuentryseticon(Plugin::handle, QtPlugin::Options, &icon);
        iconFile.close();
    }

    _plugin_menuaddentry(Plugin::hMenu, QtPlugin::About, "About");
    iconFile.setFileName(":/icons/images/information.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        _plugin_menuentryseticon(Plugin::handle, QtPlugin::About, &icon);
        iconFile.close();
    }


    // disasm window menus
    _plugin_menuaddentry(Plugin::hMenuDisasm, QtPlugin::AnalyzeSelection, "&Analyze Selection");
    iconFile.setFileName(":/icons/images/analselection.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        _plugin_menuentryseticon(Plugin::handle, QtPlugin::AnalyzeSelection, &icon);
        iconFile.close();
    }

    _plugin_menuaddentry(Plugin::hMenuDisasm, QtPlugin::AnalyzeFunction, "&Analyze Function");
    iconFile.setFileName(":/icons/images/analfunction.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        _plugin_menuentryseticon(Plugin::handle, QtPlugin::AnalyzeFunction, &icon);
        iconFile.close();
    }

    _plugin_menuaddentry(Plugin::hMenuDisasm, QtPlugin::AnalyzeModule, "&Analyze Module");
    iconFile.setFileName(":/icons/images/analexe.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        _plugin_menuentryseticon(Plugin::handle, QtPlugin::AnalyzeModule, &icon);
        iconFile.close();
    }

    _plugin_menuaddseparator(Plugin::hMenuDisasm);

    _plugin_menuaddentry(Plugin::hMenuDisasm, QtPlugin::RemoveSelection, "&Rollback Selection");
    iconFile.setFileName(":/icons/images/remselection.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        _plugin_menuentryseticon(Plugin::handle, QtPlugin::RemoveSelection, &icon);
        iconFile.close();
    }

    _plugin_menuaddentry(Plugin::hMenuDisasm, QtPlugin::RemoveFunction, "&Rollback Function");
    iconFile.setFileName(":/icons/images/remfunction.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        _plugin_menuentryseticon(Plugin::handle, QtPlugin::RemoveFunction, &icon);
        iconFile.close();
    }

    _plugin_menuaddentry(Plugin::hMenuDisasm, QtPlugin::RemoveModule, "&Rollback Module");
    iconFile.setFileName(":/icons/images/remexe.png");
    if (iconFile.open(QIODevice::ReadOnly))
    {
        QByteArray arr = iconFile.readAll();
        ICONDATA icon;
        icon.data = arr.data();
        icon.size = arr.size();
        _plugin_menuentryseticon(Plugin::handle, QtPlugin::RemoveModule, &icon);
        iconFile.close();
    }
}


void QtPlugin::ShowTab()
{
    //GuiShowQWidgetTab(pluginTabWidget);
}
