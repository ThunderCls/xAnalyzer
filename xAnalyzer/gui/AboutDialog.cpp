#include "AboutDialog.h"
#include "ui_AboutDialog.h"
#include "../core/AnalyzerHub.h"
#include <QDesktopServices>
#include <QUrl>

/**
 * @brief AboutDialog::AboutDialog
 * @param parent
 */
AboutDialog::AboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    setModal(true);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint | Qt::MSWindowsFixedSizeDialogHint);
    ui->lblVersion->setText("Version: " + QString(AnalyzerHub::PluginVersionStr.c_str()));

    ui->lblQrCode->installEventFilter(this);
    ui->lblGithubUrl->installEventFilter(this);
    ui->lblx64Url->installEventFilter(this);
}

/**
 * @brief AboutDialog::~AboutDialog
 */
AboutDialog::~AboutDialog()
{
    delete ui;
}

/**
 * @brief AboutDialog::on_btnOk_clicked
 */
void AboutDialog::on_btnOk_clicked()
{
    this->close();
}

bool AboutDialog::eventFilter(QObject* obj, QEvent* event)
{
    if(event->type() == QEvent::MouseButtonPress)
    {
        if(obj == ui->lblQrCode)
        {
            QDesktopServices::openUrl(QUrl("https://www.blockchain.com/btc/address/14auaiH9gLqvXE6ygQg39ri7tGALaf6bXd"));
        }
        else if(obj == ui->lblGithubUrl)
        {
            QDesktopServices::openUrl(QUrl("https://github.com/ThunderCls/xAnalyzer"));
        }
        else if(obj == ui->lblx64Url)
        {
            QDesktopServices::openUrl(QUrl("https://github.com/x64dbg/x64dbg"));
        }
    }

    return false;
}

void AboutDialog::on_btnDonate_clicked()
{
    QDesktopServices::openUrl(QUrl("https://www.blockchain.com/btc/address/14auaiH9gLqvXE6ygQg39ri7tGALaf6bXd"));
}
