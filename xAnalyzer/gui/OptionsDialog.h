#ifndef OPTIONSDIALOG_H
#define OPTIONSDIALOG_H

#include <QDialog>
#include <windows.h>

namespace Ui
{
class OptionsDialog;
}

class OptionsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit OptionsDialog(QWidget* parent);
    ~OptionsDialog();

private slots:
    void on_btnSaveSettings_clicked();

    void on_btnCancel_clicked();

protected:
      void showEvent(QShowEvent *ev);

private:
    Ui::OptionsDialog *ui;
    void LoadSettings();
};

#endif // OPTIONSDIALOG_H
