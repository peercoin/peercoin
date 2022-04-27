#include <qt/mintingtablemodel.h>
#include <qt/mintingfilterproxy.h>

#include <kernelrecord.h>
#include <qt/transactiondesc.h>
#include <qt/transactionrecord.h>
//#include <qt/guiutil.h>
#include <qt/walletmodel.h>
#include <qt/guiconstants.h>
#include <qt/bitcoinunits.h>
#include <qt/optionsmodel.h>
#include <qt/addresstablemodel.h>

#include <wallet/wallet.h>
#include <validation.h>
#include <chainparams.h>
#include <ui_interface.h>

#include <QColor>
#include <QTimer>

// Amount column is right-aligned it contains numbers
static int column_alignments[] = {
        Qt::AlignLeft|Qt::AlignVCenter,
        Qt::AlignLeft|Qt::AlignVCenter,
        Qt::AlignRight|Qt::AlignVCenter,
        Qt::AlignRight|Qt::AlignVCenter,
        Qt::AlignRight|Qt::AlignVCenter,
        Qt::AlignRight|Qt::AlignVCenter
    };

// Comparison operator for sort/binary search of model tx list
struct TxLessThan
{
    bool operator()(const KernelRecord &a, const KernelRecord &b) const
    {
        return a.hash < b.hash;
    }
    bool operator()(const KernelRecord &a, const uint256 &b) const
    {
        return a.hash < b;
    }
    bool operator()(const uint256 &a, const KernelRecord &b) const
    {
        return a < b.hash;
    }
};

// Private implementation
class MintingTablePriv
{
public:
    MintingTablePriv(WalletModel *walletModel, MintingTableModel *parent):
            walletModel(walletModel),
            parent(parent)
    {
    }
    WalletModel *walletModel;
    MintingTableModel *parent;

    /* Local cache of wallet.
     * As it is in the same order as the CWallet, by definition
     * this is sorted by sha256.
     */
    QList<KernelRecord> cachedWallet;

    /* Query entire wallet anew from core.
     */
    void refreshWallet()
    {
        cachedWallet.clear();
        const auto& vwtx = walletModel->wallet().getWalletTxs();
        for(const auto& wtx : vwtx) {
            std::vector<KernelRecord> txList = KernelRecord::decomposeOutput(walletModel->wallet(), wtx);

            int numBlocks;
            interfaces::WalletTxStatus status;
            interfaces::WalletOrderForm orderForm;
            bool inMempool;
            walletModel->wallet().getWalletTxDetails(wtx.tx->GetHash(), status, orderForm, inMempool, numBlocks);

            if(KernelRecord::showTransaction(wtx.is_coinbase, status.depth_in_main_chain))
                for(const KernelRecord& kr : txList) {
                    if(!kr.spent) {
                        cachedWallet.append(kr);
                    }
                }
        }
    }

    /* Update our model of the wallet incrementally, to synchronize our model of the wallet
       with that of the core.

       Call with transaction that was added, removed or changed.
     */
    void updateWallet(const uint256 &hash, int status)
    {
        LogPrintf("minting updateWallet %s %i\n", hash.ToString(), status);
        {
            // Find transaction in wallet
            auto wtx = walletModel->wallet().getWalletTx(hash);
            bool inWallet = wtx.tx ? true : false;

            // Find bounds of this transaction in model
            QList<KernelRecord>::iterator lower = qLowerBound(
                cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
            QList<KernelRecord>::iterator upper = qUpperBound(
                cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
            int lowerIndex = (lower - cachedWallet.begin());
            int upperIndex = (upper - cachedWallet.begin());
            bool inModel = (lower != upper);

            // Determine whether to show transaction or not
            bool showTransaction = false;
            if (inWallet) {
                int numBlocks;
                interfaces::WalletTxStatus status;
                interfaces::WalletOrderForm orderForm;
                bool inMempool;
                walletModel->wallet().getWalletTxDetails(wtx.tx->GetHash(), status, orderForm, inMempool, numBlocks);

                showTransaction = KernelRecord::showTransaction(wtx.is_coinbase, status.depth_in_main_chain);
            }

            if(status == CT_UPDATED)
            {
                if(showTransaction && !inModel)
                    status = CT_NEW; /* Not in model, but want to show, treat as new */
                if(!showTransaction && inModel)
                    status = CT_DELETED; /* In model, but want to hide, treat as deleted */
            }

            LogPrintf("   inWallet=%i inModel=%i Index=%i-%i showTransaction=%i derivedStatus=%i\n",
                     inWallet, inModel, lowerIndex, upperIndex, showTransaction, status);

            switch(status)
            {
            case CT_NEW:
                if(inModel)
                {
                    LogPrintf("Warning: updateWallet: Got CT_NEW, but transaction is already in model\n");
                    break;
                }
                if(!inWallet)
                {
                    LogPrintf("Warning: updateWallet: Got CT_NEW, but transaction is not in wallet\n");
                    break;
                }
                if(showTransaction)
                {
                    // Added -- insert at the right position
                    std::vector<KernelRecord> toInsert =
                            KernelRecord::decomposeOutput(walletModel->wallet(), wtx);
                    if(toInsert.size() != 0) /* only if something to insert */
                    {
                        parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex+toInsert.size()-1);
                        int insert_idx = lowerIndex;
                        for (const KernelRecord &rec : toInsert)
                        {
                            if(!rec.spent)
                            {
                                cachedWallet.insert(insert_idx, rec);
                                insert_idx += 1;
                            }
                        }
                        parent->endInsertRows();
                    }
                }
                break;
            case CT_DELETED:
                if(!inModel)
                {
                    LogPrintf("Warning: updateWallet: Got CT_DELETED, but transaction is not in model\n");
                    break;
                }
                // Removed -- remove entire transaction from table
                parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
                cachedWallet.erase(lower, upper);
                parent->endRemoveRows();
                break;
            case CT_UPDATED:
                // Updated -- remove spent coins from table
                std::vector<KernelRecord> toCheck = KernelRecord::decomposeOutput(walletModel->wallet(), wtx);
                if(!toCheck.empty())
                {
                    for(const KernelRecord &rec : toCheck)
                    {
                        if(rec.spent)
                        {
                            for(int i = lowerIndex; i < upperIndex; i++)
                            {
                                if(i>=cachedWallet.size())
                                {
                                    LogPrintf("updateWallet: cachedWallet is smaller than expected, access item %d not in size %d\n", i, cachedWallet.size());
                                    break;
                                }
                                KernelRecord cachedRec = cachedWallet.at(i);
                                if((rec.address == cachedRec.address)
                                   && (rec.nValue == cachedRec.nValue)
                                   && (rec.idx == cachedRec.idx))
                                {
                                    if(i>=cachedWallet.size())
                                    {
                                        LogPrintf("updateWallet: cachedWallet is smaller than expected, remove item %d not in size %d\n", i, cachedWallet.size());
                                        break;
                                    }
                                    parent->beginRemoveRows(QModelIndex(), i, i);
                                    cachedWallet.removeAt(i);
                                    parent->endRemoveRows();
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            }
        }
    }

    int size()
    {
        return cachedWallet.size();
    }

    KernelRecord *index(int idx)
    {
        if(idx >= 0 && idx < cachedWallet.size())
        {
            KernelRecord *rec = &cachedWallet[idx];
            return rec;
        }
        else
        {
            return 0;
        }
    }

    QString describe(TransactionRecord *rec)
    {
        {
            return TransactionDesc::toHTML(walletModel->node(), walletModel->wallet(), rec, BitcoinUnits::BTC);  
        }
        return QString("");
    }

};

struct TransactionNotification2
{
public:
    TransactionNotification2() {}
    TransactionNotification2(uint256 _hash, ChangeType _status):
        hash(_hash), status(_status) {}

    void invoke(QObject *ttm)
    {
        QString strHash = QString::fromStdString(hash.GetHex());
        QMetaObject::invokeMethod(ttm, "updateTransaction", Qt::QueuedConnection,
                                  Q_ARG(QString, strHash),
                                  Q_ARG(int, status));
    }
private:
    uint256 hash;
    ChangeType status;
};

static bool fQueueNotifications = false;
static std::vector< TransactionNotification2 > vQueueNotifications;

static void NotifyTransactionChanged(MintingTableModel *ttm, const uint256 &hash, ChangeType status)
{
    // Find transaction in wallet
    // Determine whether to show transaction or not (determine this here so that no relocking is needed in GUI thread)
   // bool showTransaction = TransactionRecord::showTransaction();

    TransactionNotification2 notification(hash, status);

    if (fQueueNotifications)
    {
        vQueueNotifications.push_back(notification);
        return;
    }
    notification.invoke(ttm);
}

MintingTableModel::MintingTableModel(WalletModel *parent) :
        QAbstractTableModel(parent),
        walletModel(parent),
        mintingInterval(1440),
        priv(new MintingTablePriv(walletModel, this)),
        cachedNumBlocks(0)
{
    columns << tr("Transaction") <<  tr("Address") << tr("Age") << tr("Balance") << tr("CoinDay") << tr("MintProbability");

    priv->refreshWallet();

    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateAge()));
    timer->start(MODEL_UPDATE_DELAY);

    connect(walletModel->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    m_handler_transaction_changed = walletModel->wallet().handleTransactionChanged(std::bind(NotifyTransactionChanged, this, std::placeholders::_1, std::placeholders::_2));
}

MintingTableModel::~MintingTableModel()
{
    m_handler_transaction_changed->disconnect();
    delete priv;
}

void MintingTableModel::updateTransaction(const QString &hash, int status)
{
    uint256 updated;
    updated.SetHex(hash.toStdString());

    priv->updateWallet(updated, status);
    mintingProxyModel->invalidate(); // Force deletion of empty rows
}

void MintingTableModel::updateAge()
{
    Q_EMIT dataChanged(index(0, Age), index(priv->size()-1, Age));
    Q_EMIT dataChanged(index(0, CoinDay), index(priv->size()-1, CoinDay));
    Q_EMIT dataChanged(index(0, MintProbability), index(priv->size()-1, MintProbability));
}

void MintingTableModel::setMintingProxyModel(MintingFilterProxy *mintingProxy)
{
    mintingProxyModel = mintingProxy;
}

int MintingTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int MintingTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant MintingTableModel::data(const QModelIndex &index, int role) const
{
    const Consensus::Params& params = Params().GetConsensus();
    if(!index.isValid())
        return QVariant();
    KernelRecord *rec = static_cast<KernelRecord*>(index.internalPointer());

    switch(role)
    {
      case Qt::DisplayRole:
        switch(index.column())
        {
        case Address:
            return formatTxAddress(rec, false);
        case TxHash:
            return formatTxHash(rec);
        case Age:
            return formatTxAge(rec);
        case Balance:
            return formatTxBalance(rec);
        case CoinDay:
            return formatTxCoinDay(rec);
        case MintProbability:
            return formatDayToMint(rec);
        }
        break;
      case Qt::TextAlignmentRole:
        return column_alignments[index.column()];
        break;
      case Qt::ToolTipRole:
        switch(index.column())
        {
        case MintProbability:
            int interval = this->mintingInterval;
            QString unit = tr("minutes");

            int hours = interval / 60;
            int days = hours  / 24;

            if(hours > 1) {
                interval = hours;
                unit = tr("hours");
            }
            if(days > 1) {
                interval = days;
                unit = tr("days");
            }

            QString str = QString(tr("You have %1 chance to find a POS block if you mint %2 %3 at current difficulty."));
            return str.arg(index.data().toString().toUtf8().constData()).arg(interval).arg(unit);
        }
        break;
      case Qt::EditRole:
        switch(index.column())
        {
        case Address:
            return formatTxAddress(rec, false);
        case TxHash:
            return formatTxHash(rec);
        case Age:
            return qint64(rec->getAge());
        case CoinDay:
            return qint64(rec->getCoinAge());
        case Balance:
            return qint64(rec->nValue);
        case MintProbability:
            return getDayToMint(rec);
        }
        break;
      case Qt::BackgroundColorRole:
        int minAge = params.nStakeMinAge / 60 / 60 / 24;
        int maxAge = params.nStakeMaxAge / 60 / 60 / 24;
        if(rec->getAge() < minAge)
        {
            return COLOR_MINT_YOUNG;
        }
        else if (rec->getAge() >= minAge && rec->getAge() < maxAge)
        {
            return COLOR_MINT_MATURE;
        }
        else
        {
            return COLOR_MINT_OLD;
        }
        break;

    }
    return QVariant();
}

void MintingTableModel::setMintingInterval(int interval)
{
    mintingInterval = interval;
}

QString MintingTableModel::lookupAddress(const std::string &address, bool tooltip) const
{
    QString label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(address));
    QString description;
    if(!label.isEmpty())
    {
        description += label + QString(" ");
    }
    if(label.isEmpty() || tooltip)
    {
        description += QString(" (") + QString::fromStdString(address) + QString(")");
    }
    return description;
}

double MintingTableModel::getDayToMint(KernelRecord *wtx) const
{
    const CBlockIndex *p = GetLastBlockIndex(::ChainActive().Tip(), true);
    double difficulty = p->GetBlockDifficulty();

    double prob = wtx->getProbToMintWithinNMinutes(difficulty, mintingInterval);
    prob = prob * 100;
    return prob;
}

QString MintingTableModel::formatDayToMint(KernelRecord *wtx) const
{
    double prob = getDayToMint(wtx);
    return QString::number(prob, 'f', 6) + "%";
}

QString MintingTableModel::formatTxAddress(const KernelRecord *wtx, bool tooltip) const
{
    return QString::fromStdString(wtx->address);
}

QString MintingTableModel::formatTxHash(const KernelRecord *wtx) const
{
    return QString::fromStdString(wtx->hash.ToString());
}

QString MintingTableModel::formatTxCoinDay(const KernelRecord *wtx) const
{
    return QString::number(wtx->getCoinAge());
}

QString MintingTableModel::formatTxAge(const KernelRecord *wtx) const
{
    int64_t nAge = wtx->getAge();
    return QString::number(nAge);
}

QString MintingTableModel::formatTxBalance(const KernelRecord *wtx) const
{
    return BitcoinUnits::format(walletModel->getOptionsModel()->getDisplayUnit(), wtx->nValue);
}

QVariant MintingTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
        else if (role == Qt::TextAlignmentRole)
        {
            return column_alignments[section];
        } else if (role == Qt::ToolTipRole)
        {
            switch(section)
            {
            case Address:
                return tr("Destination address of the output.");
            case TxHash:
                return tr("Original transaction id.");
            case Age:
                return tr("Age of the transaction in days.");
            case Balance:
                return tr("Balance of the output.");
            case CoinDay:
                return tr("Coin age in the output.");
            case MintProbability:
                return tr("Chance to mint a block within given time interval.");
            }
        }
    }
    return QVariant();
}

QModelIndex MintingTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    KernelRecord *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void MintingTableModel::updateDisplayUnit()
{
    // emit dataChanged to update Balance column with the current unit
    Q_EMIT dataChanged(index(0, Balance), index(priv->size()-1, Balance));
}
