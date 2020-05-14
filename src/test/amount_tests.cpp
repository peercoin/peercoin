// Copyright (c) 2016-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <test/test_bitcoin.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(amount_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(MoneyRangeTest)
{
    BOOST_CHECK_EQUAL(MoneyRange(CAmount(-1)), false);
    BOOST_CHECK_EQUAL(MoneyRange(MAX_MONEY + CAmount(1)), false);
    BOOST_CHECK_EQUAL(MoneyRange(CAmount(1)), true);
}

BOOST_AUTO_TEST_SUITE_END()
