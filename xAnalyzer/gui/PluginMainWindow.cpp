#include "PluginMainWindow.h"
#include "ui_PluginMainWindow.h"

/**
 * @brief PluginMainWindow::PluginMainWindow
 * @param parent
 */
PluginMainWindow::PluginMainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::PluginMainWindow)
{
    ui->setupUi(this);
}

/**
 * @brief PluginMainWindow::~PluginMainWindow
 */
PluginMainWindow::~PluginMainWindow()
{
    delete ui;
}
