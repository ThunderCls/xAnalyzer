#include "PluginTabWidget.h"
#include "PluginMain.h"
#include <QVBoxLayout>
#include <QMessageBox>

/**
 * @brief PluginTabWidget::PluginTabWidget
 * @param parent
 */
PluginTabWidget::PluginTabWidget(QWidget* parent) :
    QWidget(parent)
{
    mPluginMainWindow = new PluginMainWindow(parent);
    mPluginMainWindow->setAutoFillBackground(true);
    QVBoxLayout* layout = new QVBoxLayout(parent);
    layout->addWidget(mPluginMainWindow);
    layout->setMargin(0);
    setLayout(layout);
    setWindowTitle(mPluginMainWindow->windowTitle());
    setWindowIcon(mPluginMainWindow->windowIcon());
}

/**
 * @brief PluginTabWidget::closeEvent
 * @param event
 */
void PluginTabWidget::closeEvent(QCloseEvent* event)
{
    Q_UNUSED(event);
    mPluginMainWindow->close();
}
