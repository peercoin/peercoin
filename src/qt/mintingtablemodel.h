// Copyright (c) 2012-2025 The Peercoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef PEERCOIN_QT_MINTINGTABLEMODEL_H
#define PEERCOIN_QT_MINTINGTABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>
#include <interfaces/handler.h>
#include <uint256.h>

#include <chrono>
#include <set>

class CBlockIndex;
class MintingTablePriv;
class MintingFilterProxy;
class KernelRecord;
class QTimer;
class WalletModel;

/** UI model for the minting table of a wallet.
 */
class MintingTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit MintingTableModel(WalletModel *parent = 0);
    ~MintingTableModel();

    enum ColumnIndex {
        TxHash = 0,
        Address = 1,
        Age = 2,
        Balance = 3,
        CoinDay = 4,
        MintProbability = 5
    };


    void setMintingProxyModel(MintingFilterProxy* mintingProxy);
    int rowCount(const QModelIndex& parent) const override;
    int columnCount(const QModelIndex& parent) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;

    void setMintingInterval(int interval);

private:
    WalletModel *walletModel;
    std::unique_ptr<interfaces::Handler> m_handler_transaction_changed;
    std::unique_ptr<interfaces::Handler> m_handler_show_progress;
    QStringList columns;
    int mintingInterval;
    MintingTablePriv *priv;
    MintingFilterProxy* mintingProxyModel{nullptr};
    int cachedNumBlocks;

    QTimer* m_update_timer{nullptr};
    std::set<uint256> m_pending_txids;
    bool m_synced{false};
    bool m_full_refresh_pending{true};

    mutable const CBlockIndex* m_cached_pos_block{nullptr};
    mutable double m_cached_pos_difficulty{0.0};
    mutable bool m_cached_pos_valid{false};

    QString lookupAddress(const std::string &address, bool tooltip) const;

    void refreshPosDifficulty() const;
    void refreshModel();
    void processPendingUpdates();

    double getDayToMint(KernelRecord *wtx) const;
    QString formatDayToMint(KernelRecord *wtx) const;
    QString formatTxAddress(const KernelRecord *wtx, bool tooltip) const;
    QString formatTxHash(const KernelRecord *wtx) const;
    QString formatTxAge(const KernelRecord *wtx) const;
    QString formatTxBalance(const KernelRecord *wtx) const;
    QString formatTxCoinDay(const KernelRecord *wtx) const;

public Q_SLOTS:
    void updateTransaction(const QString &hash, int status);
    void updateAge();
    void updateDisplayUnit();

    friend class MintingTablePriv;
};

#endif // PEERCOIN_QT_MINTINGTABLEMODEL_H
