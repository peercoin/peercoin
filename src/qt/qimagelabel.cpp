// Copyright (c) 2018 NEETCOIN Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <QtGui/QPainter>
#include <QtWidgets/QStyleOption>

#include "qimagelabel.h"

QImageLabel::QImageLabel(QWidget *parent) : QLabel(parent) {
    QSizePolicy policy = sizePolicy();
    policy.setRetainSizeWhenHidden(true);
    setSizePolicy(policy);
}

void QImageLabel::paintEvent(QPaintEvent *event) {
    // If pixmap is not set, call parent's method
    if (!pixmap() || pixmap()->isNull()) {
        QLabel::paintEvent(event);
        return;
    }

    QPainter painter(this);
    drawFrame(&painter);

    QSize scaledSize = size() * devicePixelRatio();
    QImage *originalImage = new QImage(pixmap()->toImage());
    QImage scaledImage = originalImage->scaled(scaledSize, Qt::KeepAspectRatio, Qt::SmoothTransformation);

    QPixmap *scaledPixmap = new QPixmap(QPixmap::fromImage(scaledImage));
    scaledPixmap->setDevicePixelRatio(devicePixelRatio());

    int marginX = (width() - scaledPixmap->width()) / 2;
    int marginY = (height() - scaledPixmap->height()) / 2;

    painter.drawPixmap(marginX, marginY, *scaledPixmap);

    delete originalImage;
    delete scaledPixmap;
}
