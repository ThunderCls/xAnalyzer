#include "QtPlugin.h"
#include "OptionsDialog.h"
#include "PluginTabWidget.h"
#include "PluginMain.h"
#include "AboutDialog.h"
#include <QFile>
#include <QDir>
#include <QSettings>
#include <QMessageBox> // TODO: remove (debug only)

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
    // TODO: Check if apis definitions are in place or return false to prevent plugin loading

    hSetupEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    // register plugin commands
    _plugin_registercommand(Plugin::handle, "xanal", cbRunAnalysis, true);
    _plugin_registercommand(Plugin::handle, "xanalremove", cbRemoveAnalysis, true);

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

    AnalyzerHub::StartAnalyzer();
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
    switch(info->hEntry)
    {
        case QtPlugin::Options:
            optionsDialog->show();
            break;

        case QtPlugin::About:
            aboutDialog->show();
            break;

        case QtPlugin::AnalyzeSelection:
            DbgCmdExec("xanal selection");
            break;

        case QtPlugin::AnalyzeFunction:
            DbgCmdExec("xanal function");
            break;

        case QtPlugin::AnalyzeModule:
            DbgCmdExec("xanal module");
            break;

        case QtPlugin::RemoveSelection:
            DbgCmdExec("xanalremove selection");
            break;

        case QtPlugin::RemoveFunction:
            DbgCmdExec("xanalremove function");
            break;

        case QtPlugin::RemoveModule:
            DbgCmdExec("xanalremove module");
    }
}

HUB_EXPIMP void QtPlugin::CBBREAKPOINT(CBTYPE cbType, PLUG_CB_BREAKPOINT* bpInfo)
{
    if(analysisLaunched)
    {
        return;
    }

    Script::Module::ModuleInfo mi;
    Script::Module::InfoFromAddr(bpInfo->breakpoint->addr, &mi);

    if(AnalyzerHub::GetModuleEntryPoint(mi.name) == bpInfo->breakpoint->addr)
    {
        analysisLaunched = true;
        if(AnalyzerHub::pSettings.autoAnalysis)
        {
            if(!DebugeeDatabaseExists())
            {
                DbgCmdExec("xanal module");
            }
            else
            {
                GuiAddLogMessage("[xAnalyzer]: Analysis retrieved from the data base\r\n");
                GuiAddStatusBarMessage("[xAnalyzer]: Analysis retrieved from the data base\r\n");
            }
        }
        else
        {
            GuiAddLogMessage("[xAnalyzer]: Automatic analysis is disabled...skipping automatic analysis\r\n");
            GuiAddStatusBarMessage("[xAnalyzer]: Automatic analysis is disabled...skipping automatic analysis\r\n");
        }
    }
}

//HUB_EXPIMP void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info)
//{
//}
//
//HUB_EXPIMP void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info)
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
 * @brief Loads the settings or creates a default file
 */
void QtPlugin::LoadSettings()
{
    QString settingsFile = QDir::currentPath() + "/xanalyzer.ini";
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
    qSettings->setValue("auto", AnalyzerHub::pSettings.autoAnalysis);
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
    char moduleName[MAX_MODULE_SIZE] = "";
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
