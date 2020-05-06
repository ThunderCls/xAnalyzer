#ifndef PLUGINMAINWINDOW_H
#define PLUGINMAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class PluginMainWindow;
}

class PluginMainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit PluginMainWindow(QWidget* parent = nullptr);
    ~PluginMainWindow();

private:
    Ui::PluginMainWindow* ui;
};

#endif // PLUGINMAINWINDOW_H
