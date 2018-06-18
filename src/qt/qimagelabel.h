// Copyright (c) 2018 NEETCOIN Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef QIMAGELABEL_H
#define QIMAGELABEL_H

#include <QLabel>

class QImageLabel : public QLabel
{
public:
    explicit QImageLabel(QWidget *parent);

    void paintEvent(QPaintEvent *event) override;
};

#endif
