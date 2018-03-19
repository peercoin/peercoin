// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/uritests.h>

#include <qt/guiutil.h>
#include <qt/walletmodel.h>

#include <QUrl>

void URITests::uriTests()
{
    SendCoinsRecipient rv;
    QUrl uri;
    uri.setUrl(QString("peercoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?req-dontexist="));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?dontexist="));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?label=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD"));
    QVERIFY(rv.label == QString("Wikipedia Example Address"));
    QVERIFY(rv.amount == 0);

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?amount=0.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 1000);

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?amount=1.001"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD"));
    QVERIFY(rv.label == QString());
    QVERIFY(rv.amount == 1001000);

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?amount=100&label=Wikipedia Example"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD"));
    QVERIFY(rv.amount == 100000000LL);
    QVERIFY(rv.label == QString("Wikipedia Example"));

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));
    QVERIFY(rv.address == QString("PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD"));
    QVERIFY(rv.label == QString());

    QVERIFY(GUIUtil::parseBitcoinURI("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?message=Wikipedia Example Address", &rv));
    QVERIFY(rv.address == QString("PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD"));
    QVERIFY(rv.label == QString());

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?req-message=Wikipedia Example Address"));
    QVERIFY(GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?amount=1,000&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));

    uri.setUrl(QString("peercoin:PHbS6MgBPu11wn3zsjkEewYUH7Fqmt8EMD?amount=1,000.0&label=Wikipedia Example"));
    QVERIFY(!GUIUtil::parseBitcoinURI(uri, &rv));
}
