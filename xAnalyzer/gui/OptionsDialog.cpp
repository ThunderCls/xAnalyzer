#include "OptionsDialog.h"
#include "ui_OptionsDialog.h"
#include <QMessageBox>
#include "QtPlugin.h"

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
    AnalyzerHub::pSettings.autoAnalysis = ui->checkAutoAnalysis->isChecked();
    AnalyzerHub::pSettings.extendedAnalysis = ui->checkExtendedAnalysis->isChecked();
    AnalyzerHub::pSettings.undeFunctions = ui->checkUndefFunctions->isChecked();
    AnalyzerHub::pSettings.smartTrack = ui->checkSmartTracking->isChecked();

    AnalyzerHub::pSettings.clearAutocomments = ui->checkClrAutoComments->isChecked();
    AnalyzerHub::pSettings.clearAutolabels = ui->checkClrAutoLabels->isChecked();
    AnalyzerHub::pSettings.clearUsercomments = ui->checkClrUserComments->isChecked();
    AnalyzerHub::pSettings.clearUserlabels = ui->checkClrUserLabels->isChecked();
    if(ui->radUserCom->isChecked())
    {
        AnalyzerHub::pSettings.commentType = AnalyzerHub::CommentType::TypeUserComment;
    }
    else if(ui->radAutoCom->isChecked())
    {
        AnalyzerHub::pSettings.commentType = AnalyzerHub::CommentType::TypeAutoComment;
    }

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

    ui->checkAutoAnalysis->setChecked(AnalyzerHub::pSettings.autoAnalysis);
    ui->checkExtendedAnalysis->setChecked(AnalyzerHub::pSettings.extendedAnalysis);
    ui->checkUndefFunctions->setChecked(AnalyzerHub::pSettings.undeFunctions);
    ui->checkSmartTracking->setChecked(AnalyzerHub::pSettings.smartTrack);

    ui->checkClrAutoComments->setChecked(AnalyzerHub::pSettings.clearAutocomments);
    ui->checkClrAutoLabels->setChecked(AnalyzerHub::pSettings.clearAutolabels);
    ui->checkClrUserComments->setChecked(AnalyzerHub::pSettings.clearUsercomments);
    ui->checkClrUserLabels->setChecked(AnalyzerHub::pSettings.clearUserlabels);
    if(AnalyzerHub::pSettings.commentType == AnalyzerHub::CommentType::TypeUserComment)
    {
         ui->radUserCom->setChecked(true);
    }
    else if(AnalyzerHub::pSettings.commentType == AnalyzerHub::CommentType::TypeAutoComment)
    {
        ui->radAutoCom->setChecked(true);
    }
}
