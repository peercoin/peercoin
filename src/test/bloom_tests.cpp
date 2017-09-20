// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bloom.h>

#include <clientversion.h>
#include <key.h>
#include <key_io.h>
#include <merkleblock.h>
#include <primitives/block.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>
#include <test/test_bitcoin.h>

#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bloom_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize)
{
    CBloomFilter filter(3, 0.01, 0, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "Bloom filter doesn't contain just-inserted object (3)!");

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    std::vector<unsigned char> vch = ParseHex("03614e9b050000000000000001");
    std::vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());

    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    filter.clear();
    BOOST_CHECK_MESSAGE( !filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter should be empty!");
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_serialize_with_tweak)
{
    // Same test as bloom_create_insert_serialize, but we add a nTweak of 100
    CBloomFilter filter(3, 0.01, 2147483649UL, BLOOM_UPDATE_ALL);

    filter.insert(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8"));
    BOOST_CHECK_MESSAGE( filter.contains(ParseHex("99108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter doesn't contain just-inserted object!");
    // One bit different in first byte
    BOOST_CHECK_MESSAGE(!filter.contains(ParseHex("19108ad8ed9bb6274d3980bab5a85c048f0950c8")), "Bloom filter contains something it shouldn't!");

    filter.insert(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee")), "Bloom filter doesn't contain just-inserted object (2)!");

    filter.insert(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5"));
    BOOST_CHECK_MESSAGE(filter.contains(ParseHex("b9300670b4c5366e95b2699e8b18bc75e5f729c5")), "Bloom filter doesn't contain just-inserted object (3)!");

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    std::vector<unsigned char> vch = ParseHex("03ce4299050000000100008001");
    std::vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_create_insert_key)
{
    std::string strSecret = std::string("U5RC3sP4wcBYeKR1f1t55DYNEE9AxMaWvrED3CJDAyWGDqubPWmU");
    CKey key = DecodeSecret(strSecret);
    CPubKey pubkey = key.GetPubKey();
    std::vector<unsigned char> vchPubKey(pubkey.begin(), pubkey.end());

    CBloomFilter filter(2, 0.001, 0, BLOOM_UPDATE_ALL);
    filter.insert(vchPubKey);
    uint160 hash = pubkey.GetID();
    filter.insert(std::vector<unsigned char>(hash.begin(), hash.end()));

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << filter;

    std::vector<unsigned char> vch = ParseHex("034d116d080000000000000001");
    std::vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(stream.begin(), stream.end(), expected.begin(), expected.end());
}

BOOST_AUTO_TEST_CASE(bloom_match)
{
    // Random real transaction (32f9df57f5ce6cc39652189e2934e9197efa6acec0f8d815696d405d71fef6bd)

    CDataStream stream(ParseHex("01000000c7c3d25d0194ece2c855ca314fcdede15bbb21cd92e01faaa79ca8fcdb20360548c432c21801000000484730440220084e61eb39f13cc7cf371cbedc8a3198384516a734a812d0458a34c1f599e60e02202424031420b12ed826cb1452919be77625ee4bef77e19dbd508bd57dd9e6474301ffffffff0300000000000000000008fcc93b00000000232103311d03833ab18c00b3e8a5a41e9d34011b5d517b877ca903c18d19988307c69facde02ca3b00000000232103311d03833ab18c00b3e8a5a41e9d34011b5d517b877ca903c18d19988307c69fac00000000"), SER_DISK, CLIENT_VERSION);
    CTransaction tx(deserialize, stream);

    // and one which spends it (78dd4f1f61f92b27035f2bf893d08078ae7d4ab583d5235e79b97b0ecdc7cc8f)
    unsigned char ch[] = {0x01, 0x00, 0x00, 0x00, 0x15, 0x8d, 0x31, 0x5e, 0x01, 0xbd, 0xf6, 0xfe, 0x71, 0x5d, 0x40, 0x6d, 0x69, 0x15, 0xd8, 0xf8, 0xc0, 0xce, 0x6a, 0xfa, 0x7e, 0x19, 0xe9, 0x34, 0x29, 0x9e, 0x18, 0x52, 0x96, 0xc3, 0x6c, 0xce, 0xf5, 0x57, 0xdf, 0xf9, 0x32, 0x02, 0x00, 0x00, 0x00, 0x49, 0x48, 0x30, 0x45, 0x02, 0x21, 0x00, 0xd7, 0xe2, 0xc4, 0x97, 0x72, 0xb9, 0xf8, 0xa2, 0xf5, 0xff, 0x87, 0xc6, 0x2e, 0x89, 0x13, 0xe5, 0x21, 0xf0, 0xff, 0x7a, 0x10, 0x33, 0x31, 0xec, 0x3f, 0x32, 0x2a, 0xb1, 0x84, 0x81, 0xe3, 0xdc, 0x02, 0x20, 0x08, 0xb3, 0xbf, 0xeb, 0xe2, 0xd2, 0x8e, 0x1f, 0x18, 0x57, 0x64, 0x55, 0xe4, 0x07, 0x91, 0x34, 0xfa, 0x24, 0x98, 0x22, 0x22, 0x59, 0xd2, 0x6a, 0x65, 0x96, 0x8c, 0x80, 0x5b, 0xff, 0x36, 0xab, 0x01, 0xff, 0xff, 0xff, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x03, 0xf4, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x23, 0x21, 0x03, 0x31, 0x1d, 0x03, 0x83, 0x3a, 0xb1, 0x8c, 0x00, 0xb3, 0xe8, 0xa5, 0xa4, 0x1e, 0x9d, 0x34, 0x01, 0x1b, 0x5d, 0x51, 0x7b, 0x87, 0x7c, 0xa9, 0x03, 0xc1, 0x8d, 0x19, 0x98, 0x83, 0x07, 0xc6, 0x9f, 0xac, 0x94, 0x09, 0xf4, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x23, 0x21, 0x03, 0x31, 0x1d, 0x03, 0x83, 0x3a, 0xb1, 0x8c, 0x00, 0xb3, 0xe8, 0xa5, 0xa4, 0x1e, 0x9d, 0x34, 0x01, 0x1b, 0x5d, 0x51, 0x7b, 0x87, 0x7c, 0xa9, 0x03, 0xc1, 0x8d, 0x19, 0x98, 0x83, 0x07, 0xc6, 0x9f, 0xac, 0x00, 0x00, 0x00, 0x00};

    std::vector<unsigned char> vch(ch, ch + sizeof(ch));
    CDataStream spendStream(vch, SER_DISK, CLIENT_VERSION);
    CTransaction spendingTx(deserialize, spendStream);

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256S("0x32f9df57f5ce6cc39652189e2934e9197efa6acec0f8d815696d405d71fef6bd"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // byte-reversed tx hash
    filter.insert(ParseHex("bdf6fe715d406d6915d8f8c0ce6afa7e19e934299e185296c36ccef557dff932"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("30440220084e61eb39f13cc7cf371cbedc8a3198384516a734a812d0458a34c1f599e60e02202424031420b12ed826cb1452919be77625ee4bef77e19dbd508bd57dd9e6474301"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input signature");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("03311d03833ab18c00b3e8a5a41e9d34011b5d517b877ca903c18d19988307c69f"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match input pub key");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("03311d03833ab18c00b3e8a5a41e9d34011b5d517b877ca903c18d19988307c69f"));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match output address");
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(spendingTx), "Simple Bloom filter didn't add output");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x18c232c448053620dbfca89ca7aa1fe092cd21bb5be1edcd4f31ca55c8e2ec94"), 1));
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    COutPoint prevOutPoint(uint256S("0x18c232c448053620dbfca89ca7aa1fe092cd21bb5be1edcd4f31ca55c8e2ec94"), 1);
    {
        std::vector<unsigned char> data(32 + sizeof(unsigned int));
        memcpy(data.data(), prevOutPoint.hash.begin(), 32);
        memcpy(data.data()+32, &prevOutPoint.n, sizeof(unsigned int));
        filter.insert(data);
    }
    BOOST_CHECK_MESSAGE(filter.IsRelevantAndUpdate(tx), "Simple Bloom filter didn't match manually serialized COutPoint");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(uint256S("00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random tx hash");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(ParseHex("0000006d2965547608b9e15d9032a7b9d64fa431"));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched random address");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 1));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");

    filter = CBloomFilter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    filter.insert(COutPoint(uint256S("0x000000d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0));
    BOOST_CHECK_MESSAGE(!filter.IsRelevantAndUpdate(tx), "Simple Bloom filter matched COutPoint for an output we didn't care about");
}

BOOST_AUTO_TEST_CASE(merkle_block_1)
{
    CBlock block = getBlockf098f();
    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(uint256S("0x82bff09813f1d208a6238088919281df6382f8db904a843296c5552d4c1e8476"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK_EQUAL(merkleBlock.header.GetHash().GetHex(), block.GetHash().GetHex());

    BOOST_CHECK_EQUAL(merkleBlock.vMatchedTxn.size(), 1);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x82bff09813f1d208a6238088919281df6382f8db904a843296c5552d4c1e8476"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 11);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 11th transaction
    filter.insert(uint256S("0x0eac12af87276113554c73be10d6298458b7b0c17164aac4fe9568f20a924484"));
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x0eac12af87276113554c73be10d6298458b7b0c17164aac4fe9568f20a924484"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 10);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_2)
{
    // Random real block (000000000006e3369eec8df8317a4329a2b7e1fd0de83349606f5b4bb128041b)
    // With 11 txes
    CBlock block;
    CDataStream stream(ParseHex("01000000414654761c63c77dd5d6c021c189150c8141dddac787fadd7e940200000000000a0d7fe57e90b3d31d72622df0fcf1999d0b21fa5ce14d00a587f89204724ab9b1df7f5075fe061b7ad80ad50b0100000068df7f50010000000000000000000000000000000000000000000000000000000000000000ffffffff0f04b1df7f5002db04062f503253482fffffffff01d05a933c0000000023210319ca2438763be59099f3c493b8d4bf65e58a04c1d5b02fb31ca930dd414312a4ac0000000001000000a2de7f5001a3e0be821f002db0352c8a590ec53a8f7a9f8acb106a227ebf3761f23cfb106d000000004948304502202f045f74b73a6949624cf41a547d9a07db665b634faf21696a6580388aed6dc702210086989be0d8595be72be196a2e1c062792613ac0f449e0bb6b855da495749f95201ffffffff0225f4a038000000001976a914893f2f1393a363182754afc5b3f8183ebf82fa4d88ac5b35c200000000001976a91419aac4dca9c5173ac882c6751def2f783566627d88ac0000000001000000addc7f5001df1361091949355824045b9c506394306ba132b95a0f1135f57c6b48b8674407000000006a47304402203ae3b9ecaa2111c8494400e8e640446b75b68589d36561549268612e06b8185402205a017c57319d0a7ccab65fee471af1cefc897385481de17e0a17e83eb5fdaece01210319bce8c75a215cce6f1b0d126c0280b3c1d53b90a73dea44bb38464d746c3990ffffffff0276de2037000000001976a914985d1feeabd90aa41d0bf047cfd62fe18ca8122288ac8ecdcd00000000001976a914c623a1b9b38df2924c3781f1c4dd1bb3886afd6688ac0000000001000000b8da7f5001195d933d58626b1c358cc9c79ac5a44dcb8f71454af47688ad34031dc4483704000000006b483045022100dd5f8c053abf9fad68725f204c31e02507b9ad545de56b7396eb4d5f41936ba1022028f6ba63eae7c1082adf6143ced5476f9a38f05a0ed25e5f57034f2d171d893d012102f0d44273f54d7910d7c554f59b0bac9adc64fbea18e0afbbab4185d31378ccc9ffffffff0270582937000000001976a914cdd760417c14e86c8f027d273b35650cc338220488acf404ab00000000001976a91419aac4dca9c5173ac882c6751def2f783566627d88ac000000000100000031da7f5007e50b5165abd60b84b82a88e480184e0b38fe5c3e78408f5fa14482777df7c27e000000006a4730440220079d1e15d96fd4395082eb6d2b95b1d99009aac6e1376d05850a7e07a5da411a02207f8a39a3dfd8549658a0da1e8372375d39ab1a7dde99a193a8d4fade528f6574012103071a8555e34c0c4ecfe690ca8131a3f59ca78a724d99f44c07cd2c1452cb830affffffff0d57eda3a3b2431de5f27193c5a875cb8077f7b091acc9d8a57a609cfbe57d75010000006b4830450220403a1f83a8ce9cc858e54d335378f2931b480b7de14dc6f47630741094296d76022100f631c2800ffb5812a7f5ab0fd5362cce5c9c4cccf31b41e8a4e7b5a5e1b307100121020118bc0aee9555545886699720487c90c7df00b2efa4b907678a84ebe70cf396ffffffff143f03dd643dbce3c644af76012c79eeec750ba5a1ea847b99404218f05a5565010000006a473044022002859fcf13b8ab688f631e30fdb2fb6e15471edfb7098f915e742e1aeb8c6bf00220238974fac8636bf10fb0951c43b1687b6db44d7ea41193245006b8eadd811a670121020118bc0aee9555545886699720487c90c7df00b2efa4b907678a84ebe70cf396ffffffff176fbf3c711c354d2dfbc45c80cb733f6ef666b5aef9d38a746a2d2e81c66747010000006a473044022008a06988a9b523bbb62450cfc2ec29e15812428799e7369fde52af2bae92f580022067f230ff6faac4d1305ec72ec2df9fa4f650c57ba2ad89ca8710ff09a933f63d0121020118bc0aee9555545886699720487c90c7df00b2efa4b907678a84ebe70cf396ffffffffef1540b5041e637f8d0132ff6a52e0f71af8fe3d7bfce814d8e1c5007bc7d8bd010000006a47304402200c44803513f1a18dd8bda3f1876b38a4ac009408228fdd85f6945e6acac156e202206fe3b591f444b826c2c70f64c78db7dff989b5a18a05de53f7bd6858b64b1a120121020118bc0aee9555545886699720487c90c7df00b2efa4b907678a84ebe70cf396ffffffff995d35145c81c9c956b3f17754377116c57770cbccd13cf1b6e872c86495ff4d010000006c4930460221009c795908c033af79ed6714fddbdfbaa50a2d1cc96471f3bf153db5ca39665da9022100edd8dff14346a209eaa6610c3740774a090b0782f8365a39802eea45d09d82860121020118bc0aee9555545886699720487c90c7df00b2efa4b907678a84ebe70cf396ffffffff6d42dcde469fa745740a82dd83024b8e7a0c034c41dbb7c07e1020a64c5486a2010000006b4830450220538522916be3cf36b370a6a86805b37374a3fe91a26ae10ee7e1e3727a31febf022100cde0c5acbec7c6809e34b1375e8986227ca5ca5812cc6456a7c29c3c25ee9f400121020118bc0aee9555545886699720487c90c7df00b2efa4b907678a84ebe70cf396ffffffff0213270000000000001976a914e4d8d918757781aa7c624f1cb5f0e99877b887c288ac808f891b000000001976a914e3a5e0e00e5c59ddeef47733f2d8658c871ca21388ac0000000001000000fdd77f5001794797936fda80a3c0cffc4db19243411d904a5e40d1573465ab5a8a692cea76000000006b483045022100da06d1e0b0053a5a4e154e5c12b28b7a8d9f44133303a9ae3882ceb11edb102702207e3daba574f9120b0edc5ae2202585ec9a4710f99f35b1f962109cf16d29b792012102ce4a2428aa97f5d97b9b0c11d12f1e00fa05bf2a957445922276b58142875f14ffffffff0256d0ef09000000001976a91455cde9bca271bc56b15fb59aa390d00dac5bd57d88acc4a9b908000000001976a914195ec5af75e514643fa01f690deac40ed7113ae288ac000000000100000061df7f5001719851db115d64333378088bf0c50ae672c395be8758cc2b528232704c752230000000006c493046022100c0f5e163bd9942971b83847821260f8a18421acabe4c3eb99b9835d3d84615260221009771d3cec881a7bb3a74727090de2d7ae4462efb751afeb13bca379b6c224e8e0121039c64797701af16eaca24c5a97264fecd33359fc43fd19afc5670c3e33b0719c3ffffffff024878170b000000001976a9147b3e4110b85866f730c95ccd37b995bdd51fa93188ac4b44fe0a000000001976a914953c4f2be9e917c8bf6d8570f7de681d52fc37fe88ac0000000001000000c5d87f500180fbdaef15a9869e518b23b3fbf69ef6c208e66e78dc2336436f07d0574e3b33000000006a47304402203917a8d63a1a9dd34a5b1e82cbe4bcfe37e29f66d30cc526faa9e941c53ab88302204d4f5393ff96ae02e53766240fb649a9c63e68d2553bf918a5bb2b1aa407fae5012102ed7177ea4053870dfafed18ddd8cc09f29198e8d5372581f07e8b78c4bcfd237ffffffff022da9d629000000001976a914a26f0593376a559a5ebbaba097000205715fd80688ac32add600000000001976a914c623a1b9b38df2924c3781f1c4dd1bb3886afd6688ac0000000001000000c4d87f5001a40f9c8ae7b52ec4cc023363ce8b446e44fd0fbf169dfaa4de96104ed3487064000000006b483045022100a7b20139694c5c109f79512c49ed81076a7ce58b591c6ba16381bc396cd6f30602205d2252f8f51bb694b092e36a88e3fbbd3ca1f6d555cc4dfa2ea605d82a5622d40121038c0c2c04d36e1e266f26c267c12b1a6d0fa5ef308c20e2459e8265c2b8bdfa2effffffff0238646729000000001976a914cd5e9cb659ffab238f38fe9c19a02b4ad30aeace88ac0ce49800000000001976a914ec1befddea771e8d597667e2ddd76ed957ad7ab388ac0000000001000000d0d67f5001f4f11840ff63dc667b40d59f123b033f716d6178de61e0cfdd777c7258a2cb94000000006b483045022100c0c574d2587f1d9eee0503a6372bc748e109717c84267889d08d0b55fac2035d0220343fb09af4dc514139d9db6f99eec6663876870ce5453f7844970c9b3e462b9f012103b1aae1e9a9b584e20562b000e3c3d78415502f7bc25bb8e291ab1b7c6191fb3cffffffff020fd4f303000000001976a914baf501b30d8097010654a31612b2c371336542c388ac2ca38203000000001976a914eba61671226ec9aa17dd6cc48db5b2a8d3055b3a88ac0000000001000000cfd67f500332f4d5cae99bc324493c1f0c67d056b82b0e3f1007020de1b0602441ad1a9289000000006b48304502206a3071fa89d881fc2966e417ef65cac58bb651ea6c828102b0cda8290465b6a60221009cb939e8c37c4d836e9f4abf4e076fd720c1d9f21f7e6dd5fa538c8f258cd67a012103d15875203f18187c0f054b6f4583e015a1a026d0f96868606e005b450ece7fd3ffffffffa894d903ee419ef143a69d75a2fa671aed5e85c9d4c9a669576f4bb6c377ab26000000006b4830450221009dad22c707506c0c9a826211a1e617967a15a30866a01c80baf175fb902cf25202204a6b86cd8e0a36fa126ce8a8bdda3358b91d5afcba3e387f2f66b38789ec453f012102df2717f3a7df36fbe00e1b6d6afae9790912bdcd96294dfa05f09bed3251bbc1ffffffffe69f189b68249642d7ed4daa1036fee171182de361f930f9f07a8750c4d7e721000000006b483045022100ea1ed06702f156a55b977132ef80985b2e449fa56487aae151c7a79cc6095bee0220673beec715ef26de37704bc37f9572d26dbd90450cf2b07d1351502706443ee90121029f02c614481cd9588745546a7e91e465e47b9841f03ff4e92020ec1802c9cb7dffffffff02815a0000000000001976a914653e8eac1c4d467a6bc2b6e5429e87efbc96312288ac2ed49a00000000001976a91419aac4dca9c5173ac882c6751def2f783566627d88ac000000004730450220033c69bf3133496af631f4f4b794877f6cfacac81d2683d19df0b67549a16062022100ce585e59b460b51bc158d14f5faef3d77d908499ae6e27e1d13a6636f4e1be5e"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the first transaction
    filter.insert(uint256S("6be9a85a1890f04b6d9ecdbbc58eb4c46b363a5bd180bec8dc25ab9e8e724b62"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x6be9a85a1890f04b6d9ecdbbc58eb4c46b363a5bd180bec8dc25ab9e8e724b62"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match an output from the third transaction (the pubkeyhash for address PSeqdh6vqJoFNBLfaz3YkkLhwoADVtYkRZ)
    // This should match the fifth transaction because it spends the output matched
    // And also the eighth transaction

    filter.insert(ParseHex("c623a1b9b38df2924c3781f1c4dd1bb3886afd66"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 3);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x6be9a85a1890f04b6d9ecdbbc58eb4c46b363a5bd180bec8dc25ab9e8e724b62"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second == uint256S("0x04ff3afd7d6b1ac43b6b4b2192f25629e89d8476f9353108b099c4f12532f421"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[2].second == uint256S("0xedc8922889d1262e89de8aa20b842f22c5d8c2cbd8db5de929f00d6ef761def1"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[2].first == 7);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_2_with_update_none)
{
    // Random real block (49cbf8fe73f45600378f3560e760f6734b1b9eff77a294871ebab3fe95a4ab4c)
    // With 4 txes
    CBlock block;
    CDataStream stream(ParseHex("03000000613e2be45d88514e35737656df16355d796136d16b01079f98cb267585ed88e4a117015dee06c75910908e41a797c5163675894aee2cf50ebbf93e0cdde67715ad44875e6418221c000000000401000000ad44875e0001010000000000000000000000000000000000000000000000000000000000000000ffffffff0603e37b070101ffffffff020000000000000000000000000000000000266a24aa21a9eda0d1da67ad12228074d673465df1f41ee33c731246eadd35db8787dc6f88bcf0012000000000000000000000000000000000000000000000000000000000000000000000000001000000ad44875e01cd95b1f908f60ea47daf030117ca5881a1b1292a5bc2f048de7d657aa22b9bb001000000484730440220152d5b82e9c249d2567ba712e6d5b04683ba4b0b42ed39702cf4317d8741b0f902202e3dc742c62caaf043fb828704fe5ae2ac060c010204b49bdfee8b462f37713901ffffffff0200000000000000000054446b06000000002321031d79360a9e5f3ec6ce2822605eb9448565443dc1ed4db8f4b5dd653bf170e5bdac0000000001000000acfb865e010909f8788c9d88c677c0e91d214a56a88efad037934fc40c176a3b144c62e3f7000000006b483045022100e86aa171ff96ebc46228c764f8ef4d1ace743ccb39b5e8219d249781e272f10d02200559f307ed541885e22191099cb13fd5c3332ee16c0d180bb61b56b34510e58201210300758bacfc40de896ad13464d2e83273e24374e4f66e3da0147d40b88758114fffffffff02f0550000000000001976a9146d3d29306faac2531bcad295e23faa88244c131488ac30f20000000000001976a914ff9a05654150fdc92b1655f49d7f2a8aaf6a3a2a88ac00000000010000003a40875e024f5569be5337094ec0dba5f47fc8c6f7f52499d43f53af1072dd2bb19918d027000000006a47304402206dac672c5e75f5da961b63f86c004ec13341cf22bcf7a004d66ac52d7d773516022050f52ad39a20baf3225889a562b401a046779a270fd464db2a9bfc0d09da8e840121028fd5d18ac220d00a9213a04a2037b0fe3497db392060aa69070730d7630ba788ffffffff4f5569be5337094ec0dba5f47fc8c6f7f52499d43f53af1072dd2bb19918d027010000006a47304402203f3c81747ca6c279d81e467326b5f8c2f4d0c1df79d92f0e67ab82ca43b8f4ee02200b36a5bbac4fc8eee8ea9d14c866122b6829dd9ee6d15306dda3454d11a011af01210300758bacfc40de896ad13464d2e83273e24374e4f66e3da0147d40b88758114fffffffff02204e0000000000001976a9146d3d29306faac2531bcad295e23faa88244c131488ac60ea0000000000001976a9146d3d29306faac2531bcad295e23faa88244c131488ac0000000046304402204c538ec22eb5dcfcb418350ccf2a5c1531a815f0386a23eb6fdf1825153314ad02201e9dfa44e8527077126131fe6bf059a7242951abbbef6e5f30458ccb560e7caa"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the first transaction
    filter.insert(uint256S("0x2ca51406400816e324cb1f77c13bb2c636135bd947175c9c8201318f2fbba320"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x2ca51406400816e324cb1f77c13bb2c636135bd947175c9c8201318f2fbba320"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Match an output from the third transaction (the pubkeyhash for address PXtfyTjzgXSgTwK5AbszdHQSSxyQN3BLM5)
    // This should not match the fourth transaction though it spends the output matched
    filter.insert(ParseHex("ff9a05654150fdc92b1655f49d7f2a8aaf6a3a2a"));

    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(pair == merkleBlock.vMatchedTxn[0]);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1].second == uint256S("0x27d01899b12bdd7210af533fd49924f5f7c6c87ff4a5dbc04e093753be69554f"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[1].first == 2);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_3_and_serialize)
{
    // Random real block (000000000010ac231dfb422a1bf512b9bfc9915c08d9a9c253c8337f9869f58b)
    // With one tx
    CBlock block;
    CDataStream stream(ParseHex("01000000c6ea48b2ceb01563ff317b7eb6b7d9c35120b16ed65119c41c1fb20000000000c89d8542ad87d6d5eac869b9c19abd4b826552ef09e45cfb5d010dbe4e192ff03a8e315008c0001c01d9ba490101000000f18d3150010000000000000000000000000000000000000000000000000000000000000000ffffffff0f043a8e3150020601062f503253482fffffffff01e0bda98a00000000232102013d6810139d4e980f1d2d7e0f279cd3bb536193aac7171c61cb4cac77b55c27ac00000000473045022053f90b7b253c7502191aa762dd2bca00d988021a58a02eadd4af68d230ae406f022100c4ec59db901e038e86437fbce0470c7c749ddf3868ac0438ddccee8b1ebc92ac"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the only transaction
    filter.insert(uint256S("0xf02f194ebe0d015dfb5ce409ef5265824bbd9ac1b969c8ead5d687ad42859dc8"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0xf02f194ebe0d015dfb5ce409ef5265824bbd9ac1b969c8ead5d687ad42859dc8"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 0);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    CDataStream merkleStream(SER_NETWORK, PROTOCOL_VERSION);
    merkleStream << merkleBlock;

    std::vector<unsigned char> vch = ParseHex("01000000c6ea48b2ceb01563ff317b7eb6b7d9c35120b16ed65119c41c1fb20000000000c89d8542ad87d6d5eac869b9c19abd4b826552ef09e45cfb5d010dbe4e192ff03a8e315008c0001c01d9ba490100000001c89d8542ad87d6d5eac869b9c19abd4b826552ef09e45cfb5d010dbe4e192ff00101");
    std::vector<char> expected(vch.size());

    for (unsigned int i = 0; i < vch.size(); i++)
        expected[i] = (char)vch[i];

    BOOST_CHECK_EQUAL_COLLECTIONS(expected.begin(), expected.end(), merkleStream.begin(), merkleStream.end());
}

BOOST_AUTO_TEST_CASE(merkle_block_4)
{
    // Random real block (fd9746b9d919f077c918b4f2e001422b6e052a3100b78e552db85a3c0d7e7543)
    // With 7 txes
    CBlock block;
    CDataStream stream(ParseHex("030000007c67e8e4c0f14c5e17fa5504d174adf89fa9f4d6b5894a7f534022b7c2b62e59b2ad7999ec42f953446338580e19a7587b62187c7cf7628dc9b449b68fe9806c0043875e261f221c0000000007010000000043875e0001010000000000000000000000000000000000000000000000000000000000000000ffffffff0603e07b070101ffffffff020000000000000000000000000000000000266a24aa21a9ed30d60beaa36e70b85b0f825cae1279e76fd43368f20f2aedf0e4201a36c0fb3a0120000000000000000000000000000000000000000000000000000000000000000000000000010000000043875e01a6bc3d06d7473e0c00a45f202843f99ff53053ff22c743822538bee7faf20b240100000049483045022100de635e829c2ddd1c6e0e054448889766be6d584e51e059128e3d606fc47d7a5702206c2c7c41d42f3ef696a48cceb896cbb18aade80b07564af7b3f5aef866ab183801ffffffff02000000000000000000fc8e4f0200000000232102c52c310fe34bf66c78e1b055d92e3b35710cf455da9e2880a5b2814c4fdaf933ac00000000010000009940875e05512f99ba3a5399d5045d70e9e2575fc4fbdac1c7074a6644cfc8bd35e224aa340100000049483045022100c40aab59b6cb34a61878fab08020310e4071a4ba83f598777c22bbf1fa9b4dbd022045ecd4708b31bc07cb6bddfc992a66b0584811f00b141d8d037f05d901f98fe601ffffffff6dc189eaa66e6b738097ef22c57af802b862fb8056cdfceeb9bbef29a7e06e2f0100000049483045022100b354066ae1c565a7870596315f5d0446f09068b91ff3c1b7e811934d1dbd180102206327c12b77f327a83083684626dfade63d6f664a43cb57b911c9dd72bdb5521601ffffffffa8b94774cec2156a56d9875a4d82a07f851df6d7ad2a2fae759d59cced92e83c010000004847304402200330577283f1d20ffcd9a27983534dc4fa46d4d25a3d1ee06a1d72d5469bbcc4022040187e24ae01fa5b91d18e874d787099a0c7ba28e51b94c97d63b858caab5ee501ffffffffccd4d1112de710485ed696cb82e3ceed825eb8486a2252612238ef40ce9ec048010000004847304402205970f1b00ffa668837be3153236e94c443356a6c002dc5e197d501ed98ef65dc022018cf92280c61184af0dbf335601dd6974b2b7316f9f9f2919bd4fe8cf13b894f01ffffffffdcafe60c675f5d4740050ae45315319237f44bf28e9f2a33eebed871f31f2db30100000048473044022003e91c1f4b8c3e1b46cab08f3b5718d3d101af9d092044eedb043c058feabbfd02204bf62a1e2514a88467b8641f886fe72796d27dfc514dcce71c6a67c0aee998cc01ffffffff01bce5c20e000000001976a914e2f86d01a603b8fd4d4fc2d5987a2809ccb17ddb88ac0000000001000000af40875e01b314a530e95aa598bfba86dc363ab0651f8bd91f8319dab827db5285132bcf38000000006a47304402201b54d202acb9505e691f2ec8d19709f3fd7626d83addfe59a21d2347bd40d45f022037deaad99f7a72e6731cdca8c34edb0a773eda28a139cda649f58f6da144d195012103c2414bbf06b76b36c8b86eb314c277fbd5374f96643aa71c2755173c96c82728ffffffff029fac1000000000001976a91490431d9cf0da1efc67e5cb7b53bf89431a41fdd688acd3975203000000001976a914f94edd8ea993015f91fd729dc410a39901d9516488ac00000000010000009f41875e01b1df1734f4757ebe89adc8255d21d1b494c6618e7ff8998dd0ceb7f4ea0e804a000000006a47304402206286a6a924b03f8574d9246de30c9134fda38497067daeed83fc54cfdab8a69502204a7e698ecf0c6debef4da60035af53c3d0bba739bcbd3512a10c7b6e054ec7e7012102e3332119f97bd5728ff86f3240906686e476bb9c3c0e558edf35480d0591bcafffffffff02137a1600000000001976a9149135e126fd3c2e2aad34570dea863a17ccca461088acb3495203000000001976a9147f705f7e554e9080e4579f54e4e55604ffa8494b88ac00000000010000005e40875e054241943606f1874cafffeb5664c98baa3a8f6678e7d83394a06e20ab7612a1600100000049483045022100db1fd21d20a36de63341fcaba90cf8b51262345f3b96b29149e60102f4242a90022026441f99834d6a83b93acbc6258f2ff466544f2f37bf6775dbb763c7eae3f0cb01ffffffff4484f4035aae32a4ade3366a062a2663e0f0c6ba05b098f88914c417975963c4000000006b4830450221008121448796d1e52074729f01efc1702559a5b739f98f7cd910eb584b68262afa022071a4d4755e0bc28226a21ae53e27aeb48f7b0d543bdcd477fbd0a524ce049272012103c47b74e7ffdbde6c3429a974b363910dfcd71257a3dc50b2c2dff8dc991dc5caffffffff51aa4a973a21e5186f8dcbf39d23deddfe3dc7ae7163ad8df676c03e0632debb2a0000006a47304402205fc3c84ee6690b6616405c2f36b6a3149f03651f697a6103f15c5afd0ba0a9e702205fdabcefed1f4e84901d3751e4dcb163a4af6b13bc136b9c6c6c572620066658012103bcd26c4064ebf95a702bec1d96ba26b86ccd6fde6325c91d68e743d0eaaa5d15ffffffffdc8e7e144b41d6dbbe2b387ceb549c4ccc553ad4f6292c12c91e71a5edbee7712d0000006a4730440220032e3344d62db576716c60478cff615acdce9021ab83f914537ae662f49d851f02206124e921ed59e56ee15921d20131c79cf009902e3e69e58cb7b24543c2958ff601210206011c7b532045702db88c9d3306c3c2d33d910bb2b3ce55b968b68ebcd4d6ffffffffffed44c72b182519d4e647e42838de6471f3f0d9fe0b24e4140fb026a2b7837ba5010000006b483045022100b7dd069e1d6699ad62635eb4dbc915ccd3d3ca1e5f9b50ef05f5bbddf0da36a402205b2fd112ccb87002963e9ca26c8860c293d9ee131d9be6495686546aba5b4177012102e8715d1cf08b6e3443ed0b60bb18bbc7e1bfa3579625ed2bff07e5eb2ba808f2ffffffff0260b8e74a000000001976a914ec6cb8e7d45f3ead7ef5694c1fa8846dcb26987788ac7c290000000000001976a914b0649b70b542f6d609c5928ed2ae8d33d6a8a37788ac00000000010000007b41875e01740ac9b1c07ad9cd7e6267db5b09a7806ae842ea5561a1238d88c3701a1358bc00000000494830450221009dfd28c3b6cf05f22789a1be50d931d24963a433acc22f8167c96f1cc99263f6022054801ec348281d15ddedf99988c93399b97c1a60be8c5b4715bf8d95a9dbba2c01ffffffff0258e59400000000001976a914cfc2051b57759c4ef3789e3452570944e7dd712888ace0b85a02000000001976a914a8a8cb16e38a84167bf9f41233dc2fb3bdcecf4f88ac000000004630440220549a4eb250cc499daae7ab023ee6e4fa959b847d12e8231c0cb9238918f45ff302201f04ce6c5cb85164d7d2e498dd9eeba46a3a3fdd879662d93d43593b77347868"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_ALL);
    // Match the last transaction
    filter.insert(uint256S("0x37b54662a34b6704d3efe004c91f516ca910f7e9d322b0138b5b36642cc63003"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 1);
    std::pair<unsigned int, uint256> pair = merkleBlock.vMatchedTxn[0];

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x37b54662a34b6704d3efe004c91f516ca910f7e9d322b0138b5b36642cc63003"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 6);

    std::vector<uint256> vMatched;
    std::vector<unsigned int> vIndex;
    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);

    // Also match the 4th transaction
    filter.insert(uint256S("0x0553dcfa3347311fc3e6482a79705de888272702c4c10242a1fb86c8f7a1d91e"));
    merkleBlock = CMerkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    BOOST_CHECK(merkleBlock.vMatchedTxn.size() == 2);

    BOOST_CHECK(merkleBlock.vMatchedTxn[0].second == uint256S("0x0553dcfa3347311fc3e6482a79705de888272702c4c10242a1fb86c8f7a1d91e"));
    BOOST_CHECK(merkleBlock.vMatchedTxn[0].first == 3);

    BOOST_CHECK(merkleBlock.vMatchedTxn[1] == pair);

    BOOST_CHECK(merkleBlock.txn.ExtractMatches(vMatched, vIndex) == block.hashMerkleRoot);
    BOOST_CHECK(vMatched.size() == merkleBlock.vMatchedTxn.size());
    for (unsigned int i = 0; i < vMatched.size(); i++)
        BOOST_CHECK(vMatched[i] == merkleBlock.vMatchedTxn[i].second);
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_p2pubkey_only)
{
    // Random real block (0000000000000023fa07ab32d8d621480df0faada99b5aaef8b4d91d2d88a771)
    // With 3 txes
    CBlock block;
    CDataStream stream(ParseHex("010000005569536f89a2d0114a9a5a8db1bf02aa8e9b682750ffb80933ebb6a65980b78eb45138b0c54db43ba3ce0e351b36a25acac55bf1b9a0439f0ff50e24664bd1b4b69b1853dc852d19eee12bc703010000009e9b1853010000000000000000000000000000000000000000000000000000000000000000ffffffff2703b18601062f503253482f049f9b185308f80006281e0c00000d2f7374726174756d506f6f6c2f000000000120280c0600000000232102acf82ecda9ecab975f75917ab6b9448f63bc286a2d89faa5aef21182b034bd48ac0000000001000000c49a1853018b73dc1de5107a8616475d563f3c6a51ed03a0467964dbdbffa4b79e11572e1b000000006b483045022100b569451331c5f822d18d791ac403f54864a5e3535b2d9cbe859a602e5810d4e5022064cba28c24a22180cdc0cb2921be87d3e0fa80e897aafe3d2ae1dc5e3a57c79f0121031608d5966610f4a478b04e49e9db8d9b6c397e1ec6ffa3133b1d54551cdf1e7bffffffff0210ae90bf000000001976a91486dea551bdb8e8a628f9a1e239ca8514271939dd88aca02b76ae000000001976a914de37f6605e41b07de6514dfa9bcf4269e719f00b88ac0000000001000000e69a18530197c5cf861118701448fc2c271fc81efef2963bb9f8b98c23237ce8d9bc3e3ac6010000006b48304502200d2c5bc630fb0be320fb99c0ddf8c7e152c7f39be7ade6f5a412ea4d311ea5ab022100e3790b9a1dda3c91d6ad40054661529b68b32926dff43ada8fa1fc1156535ba2012103679f4073e2a99752cdb68ddcfb9bbd4fdff1be3af21dfd0d7248f176b0ea1ac6ffffffff0199040f00000000001976a9142aacd640b76516efb8908a30dd76d2381879bfa088ac00000000473045022100eb72f06d373987e02f20324e611e9fdd541d02be98cd53998194fafe2b0a517d02200e4cf35fed6e05f0cc70ea19f8368bd3784a17203d8adf18a0dbc9a6bdd2526f"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_P2PUBKEY_ONLY);
    // Match the generation pubkey
    filter.insert(ParseHex("02acf82ecda9ecab975f75917ab6b9448f63bc286a2d89faa5aef21182b034bd48"));
    // ...and the output address of the 3rd transaction
    filter.insert(ParseHex("2aacd640b76516efb8908a30dd76d2381879bfa0"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // We should match the generation outpoint
    BOOST_CHECK(filter.contains(COutPoint(uint256S("0xe7a805c6a3de96145d37364a66131f2d3ed25e53aa5d117add348365000e8610"), 0)));
    // ... but not the 3rd transaction's output (its not pay-2-pubkey)
    BOOST_CHECK(!filter.contains(COutPoint(uint256S("0x983e170e05d7a5aeb5744049405a49a47353bc5e2df375ab07623942db23caa6"), 0)));
}

BOOST_AUTO_TEST_CASE(merkle_block_4_test_update_none)
{
    // Random real block (00000000000000272556cc9aada55d3954ca9e85e2f84060c9cdcf1769e9fa4f)
    // With 3 txes
    CBlock block;
    CDataStream stream(ParseHex("0100000071a7882d1dd9b4f8ae5a9ba9adfaf00d4821d6d832ab07fa230000000000000072046dc418bf04cc710982dbe3823f8bd1eaf23e164705de1767deb6096e1dda5c9d18534ee52f19181c17aa0301000000239d1853010000000000000000000000000000000000000000000000000000000000000000ffffffff2203b28601062f503253482f04249d185308f800958200000408082f4437506f6f6c2f000000000130d71f0600000000232102acf82ecda9ecab975f75917ab6b9448f63bc286a2d89faa5aef21182b034bd48ac0000000001000000439c1853042138615671a86a17881b541bc703d96915f845be640a485043b08e44a80a9c9f000000006b483045022100d175ee826a4520288a8d30f15cdb9a472e8aec7438c59523949e3dc33feeadd4022039fe83c08c70de823790db57b3f3bc35417b75be359bb65c9fb16d9df35a5a190121020da94624ada51e21aa76a4458b2ef41b4669d9b8f9434418e93cb5e901f03eafffffffff2e0a37498838217065e9623daefd89c45e38e3886d237d4f963584052f913065000000006c493046022100f57aec26a743d3d43a9a6787b41c0601ecb05488ce32ce940a64618dc614a7620221009c04b9ac3293e6c58bf84fd86dc1a93b1c16d97c7555318b5d9d238c123290560121030dba5d30b2ab8222bdd840175eb10a78e7da3f83392d9b1a681521a8bcea699effffffff9ed64a1b4517ca7f8e5ea00fa3398de71555ac25f6edc3a5d85804cb442f65fb000000006c493046022100a0be3d022d09e874abeaecdf46c33bfa295871ec30e10300b1590286d653379b022100b3e5b33cf1639392b73a065c57487a7418db7bd12474dba6ec7b2ad9de14f1210121024a596fd5740470a230d2ecd4b32c5dca114b62c772215b33e4c0a52e9f4b520bffffffffa07fdcd60d4b9246a915ec26b1ec3343e821e0b0d3700908dd21e1fb5a1413bb000000006c49304602210084235fb75f673332b1d50a62e47d73c0c75dc28994ddf6fff1550e2961fa2091022100e55feff112921810f66eb2709602eaef4c42d6bee85cd066b7d777c1e98d0a4f012103148da2839c7767ba9d426104bbc8e54ff8b5ee2941614b90af2764ba1e34cfb6ffffffff029e440100000000001976a914346e954352183ab1df13e8a3d678c7fa0c8efa9088ac8085b50d000000001976a9149284a2bbc8885cef9911af906688d8287027045d88ac0000000001000000e89c1853029d7104086eddff432c73c70dcc22aca0a90988a42a5fffc91327f19c686fd197010000006b483045022100bfdc707b987ae034692d120b5d69716fd624b61c26aad8a0e8178cb77d2ce29102202e1c01d59216331877fa92b2680af32a267ca41ba6cc390ff8bebfd521d9dfad012103dc631d66d29bd7598b8b28364743b130de0ceca8aed55fd109cc63e78b63b327ffffffff0bca1b29fbc5d0c4e168e97866d1940e972382b0c136c1de5f8279ad0f8616c6010000006b48304502203daaddf7ba1a9f5d97b6f0a20e00356e07ef0d22597074261f32a3f1eb32e978022100fbc64b75657fde5894202bb702e5a3c70a5b345e0d02adbf1370da46720449ef012102f92fb3c682e23178f7a73ebc93655a747bfd5d210a5d60e2e3aa87a042ba5837ffffffff02eb4d0300000000001976a914649b4733011b5da9f76a59dd75e3dba001aa4cff88ac7508bc07000000001976a9149ea4c1dc8ba4092255bbd9da23a22e091d7e416f88ac00000000463044022009fb0696701a19fb611eeb5f57b9f5e4ac0b9382021e1cdc77844b8f495177b902204b5d65d17c89c30d4a40839db53357e4432391a62b613b0861e470cb2d38616c"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;

    CBloomFilter filter(10, 0.000001, 0, BLOOM_UPDATE_NONE);
    // Match the generation pubkey
    filter.insert(ParseHex("0x02acf82ecda9ecab975f75917ab6b9448f63bc286a2d89faa5aef21182b034bd48"));
    // ...and the output address of the 4th transaction
    filter.insert(ParseHex("9ea4c1dc8ba4092255bbd9da23a22e091d7e416f"));

    CMerkleBlock merkleBlock(block, filter);
    BOOST_CHECK(merkleBlock.header.GetHash() == block.GetHash());

    // We shouldn't match any outpoints (UPDATE_NONE)
    BOOST_CHECK(!filter.contains(COutPoint(uint256S("0x69c53b615c1b86cdbb08ace8f8c4217fca2d60d6dbb5bd131c069c9231889391"), 0)));
    BOOST_CHECK(!filter.contains(COutPoint(uint256S("0x60d5892df2e71bb5d0ed4c2f7e25c3c854eb43257bf078e0381688f967a0cc98"), 0)));
}

static std::vector<unsigned char> RandomData()
{
    uint256 r = InsecureRand256();
    return std::vector<unsigned char>(r.begin(), r.end());
}

BOOST_AUTO_TEST_CASE(rolling_bloom)
{
    // last-100-entry, 1% false positive:
    CRollingBloomFilter rb1(100, 0.01);

    // Overfill:
    static const int DATASIZE=399;
    std::vector<unsigned char> data[DATASIZE];
    for (int i = 0; i < DATASIZE; i++) {
        data[i] = RandomData();
        rb1.insert(data[i]);
    }
    // Last 100 guaranteed to be remembered:
    for (int i = 299; i < DATASIZE; i++) {
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // false positive rate is 1%, so we should get about 100 hits if
    // testing 10,000 random keys. We get worst-case false positive
    // behavior when the filter is as full as possible, which is
    // when we've inserted one minus an integer multiple of nElement*2.
    unsigned int nHits = 0;
    for (int i = 0; i < 10000; i++) {
        if (rb1.contains(RandomData()))
            ++nHits;
    }
    // Run test_bitcoin with --log_level=message to see BOOST_TEST_MESSAGEs:
    BOOST_TEST_MESSAGE("RollingBloomFilter got " << nHits << " false positives (~100 expected)");

    // Insanely unlikely to get a fp count outside this range:
    BOOST_CHECK(nHits > 25);
    BOOST_CHECK(nHits < 175);

    BOOST_CHECK(rb1.contains(data[DATASIZE-1]));
    rb1.reset();
    BOOST_CHECK(!rb1.contains(data[DATASIZE-1]));

    // Now roll through data, make sure last 100 entries
    // are always remembered:
    for (int i = 0; i < DATASIZE; i++) {
        if (i >= 100)
            BOOST_CHECK(rb1.contains(data[i-100]));
        rb1.insert(data[i]);
        BOOST_CHECK(rb1.contains(data[i]));
    }

    // Insert 999 more random entries:
    for (int i = 0; i < 999; i++) {
        std::vector<unsigned char> d = RandomData();
        rb1.insert(d);
        BOOST_CHECK(rb1.contains(d));
    }
    // Sanity check to make sure the filter isn't just filling up:
    nHits = 0;
    for (int i = 0; i < DATASIZE; i++) {
        if (rb1.contains(data[i]))
            ++nHits;
    }
    // Expect about 5 false positives, more than 100 means
    // something is definitely broken.
    BOOST_TEST_MESSAGE("RollingBloomFilter got " << nHits << " false positives (~5 expected)");
    BOOST_CHECK(nHits < 100);

    // last-1000-entry, 0.01% false positive:
    CRollingBloomFilter rb2(1000, 0.001);
    for (int i = 0; i < DATASIZE; i++) {
        rb2.insert(data[i]);
    }
    // ... room for all of them:
    for (int i = 0; i < DATASIZE; i++) {
        BOOST_CHECK(rb2.contains(data[i]));
    }
}

BOOST_AUTO_TEST_SUITE_END()
