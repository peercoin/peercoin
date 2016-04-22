#ifndef DISTRIBUTEDIVDIALOG_H
#define DISTRIBUTEDIVDIALOG_H

#include <string>
#include <map>
#include <vector>

#include <QDialog>
#include <QProgressDialog>
#include <QThread>

#include "util.h"
#include "distribution.h"

namespace Ui
{
    class DistributeDivDialog;
}


class BalanceScannerThread : public QThread
{
    Q_OBJECT

public:

    BalanceScannerThread(QDialog* parent) : parent(parent), progressDialog(parent)
    {
        setStackSize(1024 * 1024);
    }

    void Scan(unsigned int cutoffTime);

    BalanceMap mapBalance;
    bool fSuccess;
    std::string sError;

    volatile bool fUserCanceled;

private:
    QDialog* parent;
    unsigned int cutoffTime;
    QProgressDialog progressDialog;


protected:
    void run();

private slots:

    void receiveScanningProgress(int i, bool fAbort)
    {
        if (fAbort)
        {
            progressDialog.cancel();
            return;
        }
        if (progressDialog.wasCanceled()) return;
        if (!progressDialog.isVisible()) return;
        progressDialog.setValue(i);
    }

    void onProgressDialogCanceled()
    {
        fUserCanceled = true;
    }

signals:
    void updateScanningProgress(int i, bool fAbort);
};


class DistributeDivDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DistributeDivDialog(QWidget *parent = 0);
    ~DistributeDivDialog();

    unsigned int GetCutoffTime() const;
    void ResizeColumns();
    bool ConfirmDistribution();
    int GetTransactionCount() const;

private:

    static const char* columnHeadings[];

    DividendDistributor distributor;

private:
    Ui::DistributeDivDialog *ui;

private slots:
    void on_getShareholdsListButton_clicked();
    void on_calcDividendsButton_clicked();

    void on_exportButton_clicked();
    void accept();
};

#endif // DISTRIBUTEDIVDIALOG_H
