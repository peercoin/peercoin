// Copyright (c) 2011-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/test_bitcoin.h>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <crypto/sha256.h>
#include <validation.h>
#include <miner.h>
#include <net_processing.h>
#include <ui_interface.h>
#include <streams.h>
#include <rpc/server.h>
#include <rpc/register.h>
#include <script/sigcache.h>

#include <memory>

void CConnmanTest::AddNode(CNode& node)
{
    LOCK(g_connman->cs_vNodes);
    g_connman->vNodes.push_back(&node);
}

void CConnmanTest::ClearNodes()
{
    LOCK(g_connman->cs_vNodes);
    for (CNode* node : g_connman->vNodes) {
        delete node;
    }
    g_connman->vNodes.clear();
}

uint256 insecure_rand_seed = GetRandHash();
FastRandomContext insecure_rand_ctx(insecure_rand_seed);

extern bool fPrintToConsole;
extern void noui_connect();

std::ostream& operator<<(std::ostream& os, const uint256& num)
{
    os << num.ToString();
    return os;
}

BasicTestingSetup::BasicTestingSetup(const std::string& chainName)
{
        SHA256AutoDetect();
        RandomInit();
        ECC_Start();
        SetupEnvironment();
        SetupNetworking();
        InitSignatureCache();
        InitScriptExecutionCache();
        fPrintToDebugLog = false; // don't want to write to debug.log file
        fCheckBlockIndex = true;
        SelectParams(chainName);
        noui_connect();
}

BasicTestingSetup::~BasicTestingSetup()
{
        ECC_Stop();
}

TestingSetup::TestingSetup(const std::string& chainName) : BasicTestingSetup(chainName)
{
    const CChainParams& chainparams = Params();
        // Ideally we'd move all the RPC tests to the functional testing framework
        // instead of unit tests, but for now we need these here.

        RegisterAllCoreRPCCommands(tableRPC);
        ClearDatadirCache();
        pathTemp = fs::temp_directory_path() / strprintf("test_bitcoin_%lu_%i", (unsigned long)GetTime(), (int)(InsecureRandRange(100000)));
        fs::create_directories(pathTemp);
        gArgs.ForceSetArg("-datadir", pathTemp.string());

        // We have to run a scheduler thread to prevent ActivateBestChain
        // from blocking due to queue overrun.
        threadGroup.create_thread(boost::bind(&CScheduler::serviceQueue, &scheduler));
        GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);

        mempool.setSanityCheck(1.0);
        pblocktree.reset(new CBlockTreeDB(1 << 20, true));
        pcoinsdbview.reset(new CCoinsViewDB(1 << 23, true));
        pcoinsTip.reset(new CCoinsViewCache(pcoinsdbview.get()));
        if (!LoadGenesisBlock(chainparams)) {
            throw std::runtime_error("LoadGenesisBlock failed.");
        }
        {
            CValidationState state;
            if (!ActivateBestChain(state, chainparams)) {
                throw std::runtime_error("ActivateBestChain failed.");
            }
        }
        nScriptCheckThreads = 3;
        for (int i=0; i < nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
        g_connman = std::unique_ptr<CConnman>(new CConnman(0x1337, 0x1337)); // Deterministic randomness for tests.
        connman = g_connman.get();
        peerLogic.reset(new PeerLogicValidation(connman, scheduler));
}

TestingSetup::~TestingSetup()
{
        threadGroup.interrupt_all();
        threadGroup.join_all();
        GetMainSignals().FlushBackgroundCallbacks();
        GetMainSignals().UnregisterBackgroundSignalScheduler();
        g_connman.reset();
        peerLogic.reset();
        UnloadBlockIndex();
        pcoinsTip.reset();
        pcoinsdbview.reset();
        pblocktree.reset();
        fs::remove_all(pathTemp);
}

TestChain100Setup::TestChain100Setup() : TestingSetup(CBaseChainParams::REGTEST)
{
    // CreateAndProcessBlock() does not support building SegWit blocks, so don't activate in these tests.
    // TODO: fix the code to support SegWit blocks.
//    UpdateVersionBitsParameters(Consensus::DEPLOYMENT_SEGWIT, 0, Consensus::BIP9Deployment::NO_TIMEOUT);
    // Generate a 100-block chain:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() <<  ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    const Consensus::Params& params = Params().GetConsensus();
    for (int i = 0; i < params.nCoinbaseMaturity; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        coinbaseTxns.push_back(*b.vtx[0]);
    }
}

//
// Create a new block with just given transactions, coinbase paying to
// scriptPubKey, and try to add it to the current chain.
//
CBlock
TestChain100Setup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
{
    const CChainParams& chainparams = Params();
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
    CBlock& block = pblocktemplate->block;

    // Replace mempool-selected txns with just coinbase plus passed-in txns:
    block.vtx.resize(1);
    for (const CMutableTransaction& tx : txns)
        block.vtx.push_back(MakeTransactionRef(tx));
    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    unsigned int extraNonce = 0;
    {
        LOCK(cs_main);
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
    }

    while (!CheckProofOfWork(block.GetHash(), block.nBits, chainparams.GetConsensus())) ++block.nNonce;

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
    ProcessNewBlock(chainparams, shared_pblock, true, nullptr);

    CBlock result = block;
    return result;
}

TestChain100Setup::~TestChain100Setup()
{
}


CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CMutableTransaction &tx) {
    CTransaction txn(tx);
    return FromTx(txn);
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CTransaction &txn) {
    return CTxMemPoolEntry(MakeTransactionRef(txn), nFee, nTime, nHeight,
                           spendsCoinbase, sigOpCost, lp);
}

/**
 * @returns a real block (f098fcfaccc9c0c4037dec7875315502caa6135d2450e0b740111d08a54d6299)
 *      with 9 txs.
 */
CBlock getBlockf098f()
{
    CBlock block;
    CDataStream stream(ParseHex("03000000c5c615c44d1ed7f2304f290bc254dc4d453eb968ea4d984e6f83c369eb826a59624df54b822f1710ac0bdbddc289c4271f495de1fb1591eb95311bffb95923f80bae855eb3ba221c000000000c010000000bae855e0001010000000000000000000000000000000000000000000000000000000000000000ffffffff0603f67a070101ffffffff020000000000000000000000000000000000266a24aa21a9ed1994b6c8a3efd0f2f1bfa6151d97463ef7f164f69a39e82ef9d5f0cb01f6c9920120000000000000000000000000000000000000000000000000000000000000000000000000010000000bae855e01ae85ab33c32eabadd0319fe4b140e1d3890b61513b1f9690b1851410df43b9e0020000004847304402206a70431ec92af79b0b48abba5c6260cb59bc8f010e80bd43efb42ded7eef125f022026e0c855c2669746ab2b384ae73ec3d0f0f176d913a8215d4828366fe3b5940701ffffffff02000000000000000000a4f58e04000000004341040d785650b58e942e9b2c09d5c8b683f1ba129c98a56aeb8c22b87e02942e59b56a4e67cc612f82142e05155f488e43c1fca60770e35992ff51a0df284627c6a0ac0000000001000000b5a9855e0587695f0d75e0f739b6d6ac62c0fe2c9a0c94e6e15be46fef323c92ebe8bec5ce010000006a47304402204d7883fe8e3631d82dd04f8522953597ed0ae6c86e41611ad663683b4ee2022e022018ae194fa03a4c6e8c1b83d87cb8674f703435ee3ddb91b0b9effba734b37be7012103c091da65cdc44d41d00f3d109c2ee9207f9069dbd5c3cd4a5f85596ba7426adaffffffffb1df1734f4757ebe89adc8255d21d1b494c6618e7ff8998dd0ceb7f4ea0e804a010000006a473044022028de48fbda77e4362d0a19294fa1dc8f708571869f18e1957d905cec66fe36b802207eb902495ef2d678ee2fb2f944fe69e49bd5cf773de5081e1e201720691d74b001210200aa18958ccaed19780df803d61c3653d30202caec08cf1e836eed1c51da0e90ffffffffdd32bcee3225cd8d70d7470d740db3a273ebeeda57258fcb630594f0e38ecd54010000006a4730440220496100f31256eae8ac2c71e5d162cd938997d9ba010709452d231a52e2434ba30220664d77d6861ab6322c07381e17dffa1f93060966526e6a54804e51141b0c7ee701210230df54674407a9867701b682f67bae6acfa31a0c512c52df2eaef0e80033f456ffffffffe172f8db87ea4b34af87e825d0d40d008e5c137a4a69298a7bd4ad8aa7bcab37000000006b483045022100a637d0570c894a941e1be1abf9b789a3f78d7fa95c2b0852de0238bcd67f058202205986a6edd1b24388b10effbca0953bcd244ca58cbf19a0bff8da188025581bab0121036dd7012f7d7350caa912d0520a45e33be72018f010f01b72f1b639eb75c240bdfffffffff2fc937fe93f4b1e55b6c6f1971035ebee12f98e25e5ef53bda40862541de705010000006b4830450221009e44a1c232ece9bdc06c3962822b070376988b7f65d9dc0baa93e6e78df1322d022051c804661bf58704387a4b5243d6bddc750eae03b248e37f88f09eb9ce8c755f0121025e99f8c9dbd70d164ec0b6bf8a4920528d9163cbae6791d2a161f8697e0bfbeeffffffff0252ab9300000000001976a91468d13f96f5cfaeda979fc1ca3794f77ba8885a8488acc83e0000000000001976a914dc0cb5e7f16f80da2098791020a5b98f75c8d4c088ac0000000001000000c3ab855e06eef5d71f0f02cd13d8c06aa7d15d52950bae211397a3c5b2ebe43b8a89a784a3010000006b483045022100a12eba2a67e2fe118e4b391649b961396547f0e309260591fce956c0871a717802206d6827f8b7b388d3260ccf0da205fcb2e099ebe7d9b65ab7be3ec5c4db1bf4e3012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df043efd09804da878f5af71997a2853a073f28603d533f0c829c2612d8dab749dc000000006a473044022016657ae999a31cf9a2c3176684ccab3e1b7555d8a8716e039bde364307a6eb51022005fe2c899aeec785416e7726f6544b73e0a52d6e38587703711a0615914a0e0d012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df0a31d558ceb894db1e421e6ee044d0c39995d15cde9789d6d0c1724bc3084291c000000006a47304402204afee7182b55f98823f8ae4c75f3487231df0b3b8d717d8c66805bb4470f29c3022006f22aa966545c055dab50c30803cf0e32bd1e089ba528ccc51d4df5df506c0f012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df0b03586870f45a92dff8ac8a43778b5ee6bbaef910ac29ba80517375bd24d8b07000000006b483045022100a327d97b5e1f52e86b474f1b66abab1ef85ef13f962a1cd1b93c842aaca1204302204adca2d8faf860ad6665254931f49c06ac7416214ee22342062a571b830a6e54012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df04221718b101cd972ac46650f14731c08bc7af26abc449e4317372860d979f503020000006b483045022100a4f6e45a623327d7e634dbbb5b856c981da66d141b7e11d136f4d3f92a4e552102205c775094e9a463ef8d7c52e62c8f351520a5e918416a74d4acb4a6dfac863994012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df090f96f2356654d19f6dcf4438b9747f8342ac6d98391e03c14c9646d26ff8340010000006b483045022100f8abc2ef972c590d0066741aa5322ae6dcabaf72e1a529f27b566e3cd574888d0220384ef37ace11abbc867e2cea1e2068fb609f320d31a69eb3210b87419e14a97d012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df00280c3c901000000001976a914c694f4bedfc3f0b48e89c39ad2028355d936c18188ac52400400000000001976a91468d13f96f5cfaeda979fc1ca3794f77ba8885a8488ac0000000001000000cfab855e04dee76c9790408ee069a65c22b740e5eb5ac0ba8558d8f902db2e0d207e332e99010000006b483045022100e637487c710b791b0074b8a798eab60f66826311b6b284ac0f933b879068f54102206929536682dbb020e53cc751bf20baea2055edec810d663602b51f21c7669de1012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df0a431d91ba867392a357f1e9e97b593e182c9a019e7ce242f3c13dc5bc64639e4000000006a47304402204cb9c4782e7c56a32c1d36942f6a53349788e803f4dcfb90cfe3b80a25060a7002206ab217aaf5ee55b738227ab85b81371458bb91124565551383e2764cb637d578012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df0a236b69b1e524ffeca8a5a90161f099597ad2fa7dfa3e8539dc420eac98e985e010000006b483045022100cc094e4ac5d31b3583305b01f430ea9cd5103ef85af9692c55c04916c6d3cb6f022045194235c6ff446d3b32a45f27c7903549403a49031c20691c85075be24428cc012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df021b3add1b6b1295340fe4046bbdb7fc6203472b7fc57cd4121dd38791b1ed821010000006a4730440220671ffbc3881cb432fcb5c36b00bdf3fcd095dd58f00eaec6368ae62712506eb802207a5df645fb2c59b1a122485e64cb99300028c9958d139f3ec5852c026c671df9012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df00280c3c901000000001976a914c694f4bedfc3f0b48e89c39ad2028355d936c18188ac18c80d00000000001976a91468d13f96f5cfaeda979fc1ca3794f77ba8885a8488ac00000000010000000dac855e02fc30c5a4979e84f7faf0976eb9db04fb8e36e6b210a484c695faa756f1aff533010000006a473044022063e8049ec857f35c540e1a8db4b649b2a59b0542bddc40a58287f903bd24c022022011c0aff0f2f178c18cae93b9317a451890e41bda78e03cbe67aacd24f204c0e8012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df0652c80707defcca44a5cef29cf5f18f095571e88beaa2af1bbb31ea4e1e589a7000000006b483045022100b63b8144efbe4e9751d0f957b2ffb1136e259f773286c9b805456d1e923c7636022012119736d7da36a115b1dcb0d6652c64c55ae558ba4908ffe6c1de393fb7d2b8012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df00280969800000000001976a914c694f4bedfc3f0b48e89c39ad2028355d936c18188ac599c1200000000001976a91468d13f96f5cfaeda979fc1ca3794f77ba8885a8488ac000000000100000045ac855e0167d4cb07bd0c332060eee8e9398b134f175bb68ca82076d858092b8d44993e43010000006b483045022100ba513af59bf45877bd58da5a098e8ccb5d3537e2f135e6d3700deb57ab8be03402204f44fe5b9ee71b181041362b79d2a672f813a27c1b29100d0a57aad50bc2d750012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df00240420f00000000001976a914c694f4bedfc3f0b48e89c39ad2028355d936c18188ac09330300000000001976a91468d13f96f5cfaeda979fc1ca3794f77ba8885a8488ac000000000100000067ac855e01014e6b7ae9a3f9875eadf9a5e10b2eccf314a8fcf1ee7407340e867e3b73ef65010000006a473044022062962b18d21500639d83545a9fa59e357e42399d053bdbaea6af0b9cb115b23102203c96459bc2f405b72a9a9951d468c6f1838846e3fbdfbdde59259f5c0d8ef3b5012103f85e8d3b4cf691303f9c88fd3f743cf525994eb54d2cebb31aeecb54fb537109beba0df002f0490200000000001976a914c694f4bedfc3f0b48e89c39ad2028355d936c18188ac09c20000000000001976a91468d13f96f5cfaeda979fc1ca3794f77ba8885a8488ac000000000100000046ab855e040749341147a4691402e6ecd93038cd564ea227f79752048663e9e3aead8f87a4000000004847304402206ff71fa9dc9c9235784152150b3e7eddc60ba3d39f7373064229a83b4a503aa2022078bc8b4960eeb55a9f2109e57389ab558930a640b045cd6184f9f01f9515725701ffffffff0b8c0759dac92f3367c6547e5792d92afdbae84b165f66ef3288171c8ac61871000000006a47304402206f3f0d6b2a21502be5b9a2fadb9bdcc540f4a63560f130d96e4485750ea81f160220218ca1c9e4245ac364e91a2cfd82cb3d238d9bb1f684b78764b449a7fe5866d001210382ec39c764a92e012fc6e32683eb47f7993cbcf60cd580ade0045ab082cb154cffffffff3175ff66eba0a5c55c8a02504a1fa821638e440db2f0880365329cfcf7bdd31d000000006a473044022005cd27c49412f178563fec3b7e27e49add94eae4587061c0a12b38ddb337225002204078857b2b51124dd404179021e31b16850c23f506b30de8494e08fc8b4b71cf01210324f405a45ae17a9fd48fe0ae68ff4fa68e670815793330672c6b6be679716a6cffffffffa78080c10c15b258c62264c71f38b4e78b84133022ab220db56ec53208666eb1000000004847304402204a930995de812bbc4fee0b8d864ff832abf0536120c23da90d04de9bdb00aac302200b635d632712d2250656e95859a9198f276b70e3089d76bbbc0f360613108c8401ffffffff02d0170306000000001976a91480c7989cc8e7b121e32fedef337f6e1e6d6d3e9788ac5a370000000000001976a914ce6a388d02b67cc846430ffa7cf415b23cc5643d88ac000000000100000046ab855e012d89237a61a98b09c384ccede5c8c52edc49d588f05ad44a9f8042aefd59d169000000004847304402200d252834c061924a32611ea3d44ceea6f4cfc79f03af90664bc68ee8654a2bd002202f8d42d89380da14353775dcb9ce81ce355b11fdf58294918000db5c94cd443d01ffffffff02e8c68200000000001976a914b0452f74c3901fa1a6a77c73d9228d0f050ab8e888ac30dc7302000000001976a9149da18bedcbacc9bbd03b1e481dc4e0cea622dfb988ac00000000010000003aa3855e054fb768722762123a5ccd3cb82dda42d94f7ff9cd554c4b0ede2d3d0e15f44fa8010000006a47304402207f48023514155ec9ca044c10642fca9947d6f337c954027bb00d71cf3ae5b79d0220599a9b904d46958f8639d85b28ec5467ac69653d12dcc3a22919904a776626af0121020001bc1e75e2b0df5132cef84cb4566585dbc0fbee908a4609332270cdeee644ffffffff6747c1b07407051e3d5b9bac450bc6b3ceed5651b32561e9906155eaf06aec8200000000484730440220770d9796afe368e9ee5e7b4c01f499310ecb5bf135040eca2e3cad9ac6b212bd022019d0b1aac03221812da9b2adfe4eca101085a779c27a5fa3f0a80bb9e60f649101ffffffff90f96f2356654d19f6dcf4438b9747f8342ac6d98391e03c14c9646d26ff8340000000006a47304402203040747e88463ae56b1bd570b7da678d643764a377c394adbcc8bb3638f12a1a02206945508b08e7b0921d4ffd0c8cba710f7efc8974dc8f1731a6de121247dd32d10121029b634f36a59883eebf35adec1489e5237fbeff552354d59f9f6bf066154c0552ffffffff9696980de0c262de1cbc3f11fb915a997a04f37792418f756abf8bb5b711a9ba010000006b483045022100c7f3bce9c6bc792df80af63fbccf408284bcd4378c9bec37929fcb907d1fb796022066018b3d222418c2664a858365d6889a48bc244963c5f983ba866fd91bddc86901210344f6907f2c48f89ce9ef56b5cdad9775f708795a6eb99a04cedce7d3c0356734ffffffffa150b0c87b5f0c807f7140536d165c65da80fd4871c2ee2f73db0b79f9c8f3e1000000004847304402201d4043a5a646d5edd0aba24bb714a889deed3d605cea07c1392938fc7fd194cf0220077c16261005e1ebb833df6f77623cb3a685b40c36657b4b40afa5424d6b99c601ffffffff03ef6bf505000000001976a914408623acc4f5cc54c237da7d7d80b3ccc817128588acf6290000000000001976a914047c97da5e468ed66757790ba991bf65532de8e588ac41052e00000000001976a9142635217cedb6952240381d06fb1589de20ac162d88ac00000000010000002ba5855e029313c6441f61a6148bd663047dbe1811cc431fd1f0dad8cb1cafd427b7a8d93f0000000049483045022100ab922eaddb8a182a2b0919b9c57c39b93c4af362cae98ce880128573940ea3b902206e4e82b923fb59b2d9ae1a8acb4055c3fd2535c50e4370b02a42c6293014f81301fffffffffd6c85e44dc93a3c2a4eec84debc22aa2365b03053d8ea69828518bcdd5c8726010000006a47304402207e1502b533f669278009325c1bb8a5d51a0b5fefc5db384a5d18c990a222e42a02206a745e68c0d122edcb3189f622ad1406c1fbe89769f3873aca3eb4421fc256a601210370a150cecbb37e5bf28eb3abaf3d9b3989ad5de7ae6ca4807d5dce6e1267c861ffffffff02be500000000000001976a9140e2a0600aa977913cbb05fd5a6f3f82ef03dcc2b88ac86762403000000001976a91492097caf7dd84001a436c9fed025d27e8ae4e50888ac00000000463044022024944a566fd186bcd956119d583a867db5ee546d02fc062bdf5ed772ad372d0802204032f51c339cd74664b54a3cb833563f5bda12ffc0f9aa6a68a7c7c5bd425a4e"), SER_NETWORK, PROTOCOL_VERSION);
    stream >> block;
    return block;
}
