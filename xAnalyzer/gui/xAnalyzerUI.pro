#-------------------------------------------------
#
# Project created by QtCreator 2015-07-07T21:06:57
#
#-------------------------------------------------

##
## Pre-defined global variables
##

TARGET = xAnalyzer
TEMPLATE = lib
LIBS += -luser32 -lshlwapi

QT       += core gui widgets

#generate debug symbols in release mode
QMAKE_CFLAGS_RELEASE += -Zi
QMAKE_LFLAGS_RELEASE += /DEBUG
# http://www.hexblog.com/?p=991
QMAKE_CXXFLAGS += -DQT_NO_UNICODE_LITERAL

# ----------------------------------
# ONLY FOR DEBUGGING IN IDE PURPOSES
# COMMENT BEFORE DEPLOYING FINAL VERSION
# ----------------------------------
# keep debug symbols in release mode
QMAKE_CXXFLAGS_RELEASE += -Zi
# remove optimizations from release mode
QMAKE_CXXFLAGS_RELEASE -= -O
QMAKE_CXXFLAGS_RELEASE -= -O1
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE -= -O3
# ----------------------------------

win32 {

    ## Windows common build here

    !contains(QMAKE_TARGET.arch, x86_64) {
        message("x86 build")
        QMAKE_EXTENSION_SHLIB = dp32
        X64_BIN_DIR = $$PWD/bin/x32
        DLLDESTDIR += C:/x64dbg/release/x32/plugins
        DLLDESTDIR += $$PWD/../bin/x32

        LIBS += -lx32dbg -lx32bridge -L"$$PWD/../pluginsdk"
        LIBS += -lxanalcore32 -L$$PWD/../core/bin/x32
        INCLUDEPATH += $$PWD/../core/bin/x32
        DEPENDPATH += $$PWD/../core/bin/x32
    } else {
        message("x64 build")
        QMAKE_EXTENSION_SHLIB = dp64
        X64_BIN_DIR = $$PWD/bin/x64
        DLLDESTDIR += C:/x64dbg/release/x64/plugins
        DLLDESTDIR += $$PWD/../bin/x64

        LIBS += -lx64dbg -lx64bridge -L"$$PWD/../pluginsdk"
        LIBS += -lxanalcore64 -L$$PWD/../core/bin/x64
        INCLUDEPATH += $$PWD/../core/bin/x64
        DEPENDPATH += $$PWD/../core/bin/x64
    }
}

##
## QMake output directories
##
DESTDIR = $${X64_BIN_DIR}

SOURCES +=\
    PluginMain.cpp \
    QtPlugin.cpp \
    OptionsDialog.cpp \
    AboutDialog.cpp \
    PluginMainWindow.cpp \
    PluginTabWidget.cpp

HEADERS  += \
    PluginMain.h \
    ../pluginsdk/dbghelp/dbghelp.h \
    ../pluginsdk/DeviceNameResolver/DeviceNameResolver.h \
    ../pluginsdk/jansson/jansson.h \
    ../pluginsdk/jansson/jansson_config.h \
    ../pluginsdk/jansson/jansson_x64dbg.h \
    ../pluginsdk/lz4/lz4.h \
    ../pluginsdk/lz4/lz4file.h \
    ../pluginsdk/lz4/lz4hc.h \
    ../pluginsdk/TitanEngine/TitanEngine.h \
    ../pluginsdk/XEDParse/XEDParse.h \
    ../pluginsdk/_dbgfunctions.h \
    ../pluginsdk/_plugin_types.h \
    ../pluginsdk/_plugins.h \
    ../pluginsdk/_scriptapi.h \
    ../pluginsdk/_scriptapi_assembler.h \
    ../pluginsdk/_scriptapi_debug.h \
    ../pluginsdk/_scriptapi_gui.h \
    ../pluginsdk/_scriptapi_memory.h \
    ../pluginsdk/_scriptapi_misc.h \
    ../pluginsdk/_scriptapi_module.h \
    ../pluginsdk/_scriptapi_pattern.h \
    ../pluginsdk/_scriptapi_register.h \
    ../pluginsdk/_scriptapi_stack.h \
    ../pluginsdk/bridgemain.h \
    QtPlugin.h \
    OptionsDialog.h \
    AboutDialog.h \
    PluginMainWindow.h \
    PluginTabWidget.h \
    ../pluginsdk/_scriptapi_argument.h \
    ../pluginsdk/_scriptapi_bookmark.h \
    ../pluginsdk/_scriptapi_comment.h \
    ../pluginsdk/_scriptapi_flag.h \
    ../pluginsdk/_scriptapi_function.h \
    ../pluginsdk/_scriptapi_label.h \
    ../pluginsdk/_scriptapi_symbol.h \
    ../pluginsdk/bridgegraph.h \
    ../pluginsdk/bridgelist.h

FORMS    += \
    OptionsDialog.ui \
    AboutDialog.ui \
    PluginMainWindow.ui

RESOURCES += \
    resource.qrc


