#include "distributedivdialog.h"
#include "ui_distributedivdialog.h"
#include "scanbalance.h"

#include <boost/foreach.hpp>
#include <QFileDialog>
#include <QStandardItemModel>
#include <QMessageBox>
#include <ctime>
#include "json/json_spirit_writer_template.h"

using namespace std;
using namespace json_spirit;

class QAddressItem : public QStandardItem
{
public:
    QAddressItem(const CBitcoinAddress &address)
    {
        QVariant addressString(address.ToString().c_str());
        setData(addressString, Qt::DisplayRole);
        setData(addressString, Qt::UserRole);
    }
};

class QBalanceItem : public QStandardItem
{
public:
    QBalanceItem(int64 nBalance)
    {
        double dBalance = (double)nBalance / COIN;
        QString sBalance;
        sBalance.sprintf("%.4f", dBalance);
        setData(QVariant(sBalance), Qt::DisplayRole);
        setData(QVariant(dBalance), Qt::UserRole);
        setData(QVariant(Qt::AlignRight | Qt::AlignVCenter), Qt::TextAlignmentRole);
    }
};

class QDividendItem : public QStandardItem
{
public:
    QDividendItem(double dDividend)
    {
        QString sDividend;
        sDividend.sprintf("%.2f", dDividend);
        setData(QVariant(sDividend), Qt::DisplayRole);
        setData(QVariant(dDividend), Qt::UserRole);
        setData(QVariant(Qt::AlignRight | Qt::AlignVCenter), Qt::TextAlignmentRole);
    }
};

void BalanceScannerThread::run()
{
    fSuccess = false;
    sError = "Scanning thread did not terminate properly";
    try
    {
        GetAddressBalances(cutoffTime, mapBalance);
        emit updateScanningProgress(100, false);
        fSuccess = true;
        sError = "";
    }
    catch (const exception &error)
    {
        fSuccess = false;
        sError = error.what();
        emit updateScanningProgress(100, true);
    }
}

void BalanceScannerThread::Scan(unsigned int cutoffTime)
{
    this->cutoffTime = cutoffTime;
    fUserCanceled = false;

    connect(this, SIGNAL(updateScanningProgress(int,bool)),
            this, SLOT(receiveScanningProgress(int,bool)), Qt::QueuedConnection);
    connect(&progressDialog,SIGNAL(canceled()), this,SLOT(onProgressDialogCanceled()));

    mapBalance.clear();
    progressDialog.setWindowFlags(progressDialog.windowFlags() & (~Qt::WindowContextHelpButtonHint));
    progressDialog.reset();
    progressDialog.setWindowTitle("Please Wait");
    progressDialog.setLabelText("Scanning local blockchain");
    progressDialog.setMinimumDuration(0);
    progressDialog.setModal(true);
    progressDialog.setValue(0);
    start(QThread::IdlePriority);
    progressDialog.exec();
}


const char* DistributeDivDialog::columnHeadings[] = {
    "Peershares Address", "Shares", "Peercoin Address", "Dividend"
};

DistributeDivDialog::DistributeDivDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DistributeDivDialog)
{
    ui->setupUi(this);

    QStandardItemModel *pm = new QStandardItemModel(0, 4, this);

    QStringList sl;
    sl << columnHeadings[0] << columnHeadings[1] << columnHeadings[2] << columnHeadings[3];
    pm->setHorizontalHeaderLabels(sl);
    ui->tableView->setModel(pm);
    ui->tableView->resizeColumnsToContents();
    ui->tableView->verticalHeader()->setVisible(false);

    QDate date = QDate::currentDate();
    ui->recordDate->setDate(date);
}

DistributeDivDialog::~DistributeDivDialog()
{
    delete ui;
}

unsigned int DistributeDivDialog::GetCutoffTime() const
{
    tm t;
    memset(&t, 0, sizeof(t));

    QDate date = ui->recordDate->date();
    t.tm_year = date.year() - 1900;
    t.tm_mon = date.month() - 1;
    t.tm_mday = date.day();

    QTime time = ui->recordDate->time();
    t.tm_hour = time.hour();
    t.tm_min = time.minute();
    t.tm_sec = time.second();

    t.tm_isdst = -1;
    time_t cutoffTime = mktime(&t);

    return cutoffTime;
}

void DistributeDivDialog::ResizeColumns()
{
    ui->tableView->setVisible(false);
    ui->tableView->resizeColumnsToContents();
    ui->tableView->setVisible(true);
}

void DistributeDivDialog::on_getShareholdsListButton_clicked()
{
    BalanceScannerThread scanner(this);
    scanner.Scan(GetCutoffTime());
    scanner.wait();

    if (!scanner.fSuccess)
    {
        QMessageBox::critical(this,"Scanning Error",scanner.sError.c_str());
        return;
    }

    if (scanner.fUserCanceled)
        return;

    BalanceMap& mapBalance = scanner.mapBalance;
    distributor.SetBalanceMap(mapBalance);

    QStandardItemModel *model = (QStandardItemModel*)ui->tableView->model();

    ui->tableView->setColumnHidden(2, true);
    ui->tableView->setColumnHidden(3, true);

    model->removeRows(0, model->rowCount());
    model->setRowCount(mapBalance.size());

    int i = 0;
    for (BalanceMap::iterator it = mapBalance.begin(); it != mapBalance.end(); it++, i++)
    {
        const CBitcoinAddress& address(it->first);
        int64 nBalance = it->second;

        model->setItem(i, 0, new QAddressItem(address));
        model->setItem(i, 1, new QBalanceItem(nBalance));
    }

    model->setSortRole(Qt::UserRole);
    ui->tableView->sortByColumn(1, Qt::DescendingOrder);

    ResizeColumns();
}

void DistributeDivDialog::on_calcDividendsButton_clicked()
{
    bool fConversionSuccess;
    double dAmount = ui->totalDividend->text().toDouble(&fConversionSuccess);
    if (!fConversionSuccess || dAmount <= 0)
    {
        QMessageBox::critical(this, "Invalid Total Dividend", "Please enter a valid total dividend value.");
        ui->totalDividend->setFocus();
        return;
    }

    double dMinPayout = GetMinimumDividendPayout();

    try
    {
        distributor.Distribute(dAmount, dMinPayout);
    }
    catch (const exception &error)
    {
        QMessageBox::critical(this, "Distribution error", error.what());
        return;
    }

    const DistributionVector& vDistribution = distributor.GetDistributions();

    QStandardItemModel *model = (QStandardItemModel*)ui->tableView->model();

    ui->tableView->setColumnHidden(2, false);
    ui->tableView->setColumnHidden(3, false);

    model->removeRows(0, model->rowCount());
    model->setRowCount(vDistribution.size());

    int i = 0;
    for (DistributionVector::const_iterator it = vDistribution.begin(); it != vDistribution.end(); it++, i++)
    {
        model->setItem(i, 0, new QAddressItem(it->GetPeershareAddress()));
        model->setItem(i, 1, new QBalanceItem(it->GetBalance()));
        model->setItem(i, 2, new QAddressItem(it->GetPeercoinAddress()));
        model->setItem(i, 3, new QDividendItem(it->GetDividendAmount()));
    }

    model->setSortRole(Qt::UserRole);
    ui->tableView->sortByColumn(3, Qt::DescendingOrder);

    ResizeColumns();
}

void DistributeDivDialog::on_exportButton_clicked()
{
    DistributionVector vDistribution = distributor.GetDistributions();

    if (vDistribution.size() == 0)
    {
        QMessageBox::about(this, "Nothing to export", "No shareholders list to export.");
        return;
    }

    QString fn = QFileDialog::getSaveFileName(this, tr("Save As ..."), "",
                        "CSV files (*.csv);;All files (*.*)");

    FILE*fp = fopen(fn.toStdString().c_str(), "wt");
    if (!fp)
    {
        QMessageBox::critical(this, "File save error", "Failed to open file for writing:\n  "+fn);
        return;
    }
    fprintf(fp,"%s,%s,%s,%s\n", columnHeadings[0], columnHeadings[1], columnHeadings[2], columnHeadings[3]);

    for (unsigned int i=0; i < vDistribution.size(); i++)
    {
        fprintf(fp, "%s,%lld,%s,%f\n",
                vDistribution[i].GetPeershareAddress().ToString().c_str(),
                vDistribution[i].GetBalance(),
                vDistribution[i].GetPeercoinAddress().ToString().c_str(),
                vDistribution[i].GetDividendAmount());
    }

    fclose(fp);
    QMessageBox::about(this, "OK", "Successfully saved to file: " + fn);
}

bool DistributeDivDialog::ConfirmDistribution()
{
    QMessageBox::StandardButton reply;
    double dBalance;
    try
    {
        dBalance = GetDistributionBalance();
    }
    catch (const exception &error)
    {
        QMessageBox::critical(this, "Error", QString("Unable to get Peercoin balance: %1").arg(error.what()));
        return false;
    }
    QString sQuestion = QString("%1 peercoins will be sent to %2 addresses in %3 transaction(s).\nYour current peercoin balance is %4.\n\nAre you sure?").arg(
            QString::number(distributor.TotalDistributed()),
            QString::number(distributor.GetDistributions().size()),
            QString::number(GetTransactionCount()),
            QString::number(dBalance));
    reply = QMessageBox::warning(this, "Distribution confirmation", sQuestion, QMessageBox::Yes | QMessageBox::No);
    return reply == QMessageBox::Yes;
}

int DistributeDivDialog::GetTransactionCount() const
{
    int nMaxDistributionPerTransaction = GetMaximumDistributionPerTransaction();
    return distributor.GetTransactionCount(nMaxDistributionPerTransaction);
}

void DistributeDivDialog::accept()
{
    if (!ConfirmDistribution())
        return;

    try
    {
        Array transactionIds = SendDistribution(distributor);
        QString message("Distribution succeeded. Transaction IDs:\n");
        BOOST_FOREACH(const Value transactionId, transactionIds)
            message += QString("%1\n").arg(transactionId.get_str().c_str());

        QMessageBox::about(this, "Distribution result", message);
        QDialog::accept();
    }
    catch (runtime_error &error)
    {
        QMessageBox::critical(this, "Error", error.what());
    }
}
