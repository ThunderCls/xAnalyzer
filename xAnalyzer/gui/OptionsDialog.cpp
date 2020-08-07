#include "OptionsDialog.h"
#include "ui_OptionsDialog.h"
#include <QMessageBox>
#include "QtPlugin.h"
#include <QDebug>

/**
 * @brief OptionsDialog::OptionsDialog
 * @param parent
 */
OptionsDialog::OptionsDialog(QWidget* parent) : QDialog(parent), ui(new Ui::OptionsDialog)
{
    ui->setupUi(this);
    setModal(true);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint | Qt::MSWindowsFixedSizeDialogHint);
}

/**
 * @brief Overrided show event
 * @param ev
 */
void OptionsDialog::showEvent(QShowEvent *ev)
{
    QDialog::showEvent(ev);
    LoadSettings();
}

/**
 * @brief OptionsDialog::~OptionsDialog
 */
OptionsDialog::~OptionsDialog()
{
    delete ui;
}

void OptionsDialog::on_btnSaveSettings_clicked()
{
    AnalyzerHub::pSettings.AutoAnalysis = ui->checkAutoAnalysis->isChecked();
    AnalyzerHub::pSettings.PreliminaryAnalysis = ui->checkPreliminary->isChecked();
    AnalyzerHub::pSettings.UndefFunctions = ui->checkUndefFunctions->isChecked();

    AnalyzerHub::pSettings.ClearAutocomments = ui->checkClrAutoComments->isChecked();
    AnalyzerHub::pSettings.ClearAutolabels = ui->checkClrAutoLabels->isChecked();
    AnalyzerHub::pSettings.ClearUsercomments = ui->checkClrUserComments->isChecked();
    AnalyzerHub::pSettings.ClearUserlabels = ui->checkClrUserLabels->isChecked();
    if(ui->radUserCom->isChecked())
    {
        AnalyzerHub::pSettings.AnnotationType = AnalyzerHub::CommentType::TypeUserComment;
    }
    else if(ui->radAutoCom->isChecked())
    {
        AnalyzerHub::pSettings.AnnotationType = AnalyzerHub::CommentType::TypeAutoComment;
    }

    // TODO: remove
    //qDebug().nospace().noquote() << "Auto: " << AnalyzerHub::pSettings.autoAnalysis;
    QtPlugin::SaveSettings();    
    this->close();
}

void OptionsDialog::on_btnCancel_clicked()
{
    this->close();
}

void OptionsDialog::LoadSettings()
{
    QtPlugin::LoadSettings();

    ui->checkAutoAnalysis->setChecked(AnalyzerHub::pSettings.AutoAnalysis);
    ui->checkPreliminary->setEnabled(AnalyzerHub::pSettings.AutoAnalysis);
    ui->checkPreliminary->setChecked(AnalyzerHub::pSettings.PreliminaryAnalysis);
    ui->checkUndefFunctions->setChecked(AnalyzerHub::pSettings.UndefFunctions);

    ui->checkClrAutoComments->setChecked(AnalyzerHub::pSettings.ClearAutocomments);
    ui->checkClrAutoLabels->setChecked(AnalyzerHub::pSettings.ClearAutolabels);
    ui->checkClrUserComments->setChecked(AnalyzerHub::pSettings.ClearUsercomments);
    ui->checkClrUserLabels->setChecked(AnalyzerHub::pSettings.ClearUserlabels);
    if(AnalyzerHub::pSettings.AnnotationType == AnalyzerHub::CommentType::TypeUserComment)
    {
         ui->radUserCom->setChecked(true);
    }
    else if(AnalyzerHub::pSettings.AnnotationType == AnalyzerHub::CommentType::TypeAutoComment)
    {
        ui->radAutoCom->setChecked(true);
    }
}

void OptionsDialog::on_checkAutoAnalysis_clicked()
{
    ui->checkPreliminary->setEnabled(ui->checkAutoAnalysis->isChecked());
}
