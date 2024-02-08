// Copyright (c) 2018-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <script/descriptor.h>
#include <script/sign.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <vector>

namespace {

void CheckUnparsable(const std::string& prv, const std::string& pub, const std::string& expected_error)
{
    FlatSigningProvider keys_priv, keys_pub;
    std::string error;
    auto parse_priv = Parse(prv, keys_priv, error);
    auto parse_pub = Parse(pub, keys_pub, error);
    BOOST_CHECK_MESSAGE(!parse_priv, prv);
    BOOST_CHECK_MESSAGE(!parse_pub, pub);
    BOOST_CHECK_EQUAL(error, expected_error);
}

/** Check that the script is inferred as non-standard */
void CheckInferRaw(const CScript& script)
{
    FlatSigningProvider dummy_provider;
    std::unique_ptr<Descriptor> desc = InferDescriptor(script, dummy_provider);
    BOOST_CHECK(desc->ToString().rfind("raw(", 0) == 0);
}

constexpr int DEFAULT = 0;
constexpr int RANGE = 1; // Expected to be ranged descriptor
constexpr int HARDENED = 2; // Derivation needs access to private keys
constexpr int UNSOLVABLE = 4; // This descriptor is not expected to be solvable
constexpr int SIGNABLE = 8; // We can sign with this descriptor (this is not true when actual BIP32 derivation is used, as that's not integrated in our signing code)
constexpr int DERIVE_HARDENED = 16; // The final derivation is hardened, i.e. ends with *' or *h
constexpr int MIXED_PUBKEYS = 32;
constexpr int XONLY_KEYS = 64; // X-only pubkeys are in use (and thus inferring/caching may swap parity of pubkeys/keyids)
constexpr int MISSING_PRIVKEYS = 128; // Not all private keys are available, so ToPrivateString will fail.
constexpr int SIGNABLE_FAILS = 256; // We can sign with this descriptor, but actually trying to sign will fail

/** Compare two descriptors. If only one of them has a checksum, the checksum is ignored. */
bool EqualDescriptor(std::string a, std::string b)
{
    bool a_check = (a.size() > 9 && a[a.size() - 9] == '#');
    bool b_check = (b.size() > 9 && b[b.size() - 9] == '#');
    if (a_check != b_check) {
        if (a_check) a = a.substr(0, a.size() - 9);
        if (b_check) b = b.substr(0, b.size() - 9);
    }
    return a == b;
}

std::string UseHInsteadOfApostrophe(const std::string& desc)
{
    std::string ret = desc;
    while (true) {
        auto it = ret.find('\'');
        if (it == std::string::npos) break;
        ret[it] = 'h';
    }

    // GetDescriptorChecksum returns "" if the checksum exists but is bad.
    // Switching apostrophes with 'h' breaks the checksum if it exists - recalculate it and replace the broken one.
    if (GetDescriptorChecksum(ret) == "") {
        ret = ret.substr(0, desc.size() - 9);
        ret += std::string("#") + GetDescriptorChecksum(ret);
    }
    return ret;
}

// Count the number of times the string "xpub" appears in a descriptor string
static size_t CountXpubs(const std::string& desc)
{
    size_t count = 0;
    size_t p = desc.find("xpub", 0);
    while (p != std::string::npos) {
        count++;
        p = desc.find("xpub", p + 1);
    }
    return count;
}

const std::set<std::vector<uint32_t>> ONLY_EMPTY{{}};

std::set<CPubKey> GetKeyData(const FlatSigningProvider& provider, int flags) {
    std::set<CPubKey> ret;
    for (const auto& [_, pubkey] : provider.pubkeys) {
        if (flags & XONLY_KEYS) {
            unsigned char bytes[33];
            BOOST_CHECK_EQUAL(pubkey.size(), 33);
            std::copy(pubkey.begin(), pubkey.end(), bytes);
            bytes[0] = 0x02;
            CPubKey norm_pubkey{bytes};
            ret.insert(norm_pubkey);
        } else {
            ret.insert(pubkey);
        }
    }
    return ret;
}

std::set<std::pair<CPubKey, KeyOriginInfo>> GetKeyOriginData(const FlatSigningProvider& provider, int flags) {
    std::set<std::pair<CPubKey, KeyOriginInfo>> ret;
    for (const auto& [_, data] : provider.origins) {
        if (flags & XONLY_KEYS) {
            unsigned char bytes[33];
            BOOST_CHECK_EQUAL(data.first.size(), 33);
            std::copy(data.first.begin(), data.first.end(), bytes);
            bytes[0] = 0x02;
            CPubKey norm_pubkey{bytes};
            KeyOriginInfo norm_origin = data.second;
            std::fill(std::begin(norm_origin.fingerprint), std::end(norm_origin.fingerprint), 0); // fingerprints don't necessarily match.
            ret.emplace(norm_pubkey, norm_origin);
        } else {
            ret.insert(data);
        }
    }
    return ret;
}

void DoCheck(const std::string& prv, const std::string& pub, const std::string& norm_pub, int flags,
             const std::vector<std::vector<std::string>>& scripts, const std::optional<OutputType>& type,
             const std::set<std::vector<uint32_t>>& paths = ONLY_EMPTY, bool replace_apostrophe_with_h_in_prv=false,
             bool replace_apostrophe_with_h_in_pub=false, uint32_t spender_nlocktime=0, uint32_t spender_nsequence=CTxIn::SEQUENCE_FINAL,
             std::map<std::vector<uint8_t>, std::vector<uint8_t>> preimages={})
{
    FlatSigningProvider keys_priv, keys_pub;
    std::set<std::vector<uint32_t>> left_paths = paths;
    std::string error;

    std::unique_ptr<Descriptor> parse_priv;
    std::unique_ptr<Descriptor> parse_pub;
    // Check that parsing succeeds.
    if (replace_apostrophe_with_h_in_prv) {
        parse_priv = Parse(UseHInsteadOfApostrophe(prv), keys_priv, error);
    } else {
        parse_priv = Parse(prv, keys_priv, error);
    }
    BOOST_CHECK_MESSAGE(parse_priv, error);
    if (replace_apostrophe_with_h_in_pub) {
        parse_pub = Parse(UseHInsteadOfApostrophe(pub), keys_pub, error);
    } else {
        parse_pub = Parse(pub, keys_pub, error);
    }
    BOOST_CHECK_MESSAGE(parse_pub, error);

    // Check that the correct OutputType is inferred
    BOOST_CHECK(parse_priv->GetOutputType() == type);
    BOOST_CHECK(parse_pub->GetOutputType() == type);

    // Check private keys are extracted from the private version but not the public one.
    BOOST_CHECK(keys_priv.keys.size());
    BOOST_CHECK(!keys_pub.keys.size());

    // Check that both versions serialize back to the public version.
    std::string pub1 = parse_priv->ToString();
    std::string pub2 = parse_pub->ToString();
    BOOST_CHECK_MESSAGE(EqualDescriptor(pub, pub1), "Private ser: " + pub1 + " Public desc: " + pub);
    BOOST_CHECK_MESSAGE(EqualDescriptor(pub, pub2), "Public ser: " + pub2 + " Public desc: " + pub);

    // Check that both can be serialized with private key back to the private version, but not without private key.
    if (!(flags & MISSING_PRIVKEYS)) {
        std::string prv1;
        BOOST_CHECK(parse_priv->ToPrivateString(keys_priv, prv1));
        BOOST_CHECK(EqualDescriptor(prv, prv1));
        BOOST_CHECK(!parse_priv->ToPrivateString(keys_pub, prv1));
        BOOST_CHECK(parse_pub->ToPrivateString(keys_priv, prv1));
        BOOST_CHECK(EqualDescriptor(prv, prv1));
        BOOST_CHECK(!parse_pub->ToPrivateString(keys_pub, prv1));
    }

    // Check that private can produce the normalized descriptors
    std::string norm1;
    BOOST_CHECK(parse_priv->ToNormalizedString(keys_priv, norm1));
    BOOST_CHECK(EqualDescriptor(norm1, norm_pub));
    BOOST_CHECK(parse_pub->ToNormalizedString(keys_priv, norm1));
    BOOST_CHECK(EqualDescriptor(norm1, norm_pub));

    // Check whether IsRange on both returns the expected result
    BOOST_CHECK_EQUAL(parse_pub->IsRange(), (flags & RANGE) != 0);
    BOOST_CHECK_EQUAL(parse_priv->IsRange(), (flags & RANGE) != 0);

    // * For ranged descriptors,  the `scripts` parameter is a list of expected result outputs, for subsequent
    //   positions to evaluate the descriptors on (so the first element of `scripts` is for evaluating the
    //   descriptor at 0; the second at 1; and so on). To verify this, we evaluate the descriptors once for
    //   each element in `scripts`.
    // * For non-ranged descriptors, we evaluate the descriptors at positions 0, 1, and 2, but expect the
    //   same result in each case, namely the first element of `scripts`. Because of that, the size of
    //   `scripts` must be one in that case.
    if (!(flags & RANGE)) assert(scripts.size() == 1);
    size_t max = (flags & RANGE) ? scripts.size() : 3;

    // Iterate over the position we'll evaluate the descriptors in.
    for (size_t i = 0; i < max; ++i) {
        // Call the expected result scripts `ref`.
        const auto& ref = scripts[(flags & RANGE) ? i : 0];
        // When t=0, evaluate the `prv` descriptor; when t=1, evaluate the `pub` descriptor.
        for (int t = 0; t < 2; ++t) {
            // When the descriptor is hardened, evaluate with access to the private keys inside.
            const FlatSigningProvider& key_provider = (flags & HARDENED) ? keys_priv : keys_pub;

            // Evaluate the descriptor selected by `t` in position `i`.
            FlatSigningProvider script_provider, script_provider_cached;
            std::vector<CScript> spks, spks_cached;
            DescriptorCache desc_cache;
            BOOST_CHECK((t ? parse_priv : parse_pub)->Expand(i, key_provider, spks, script_provider, &desc_cache));

            // Compare the output with the expected result.
            BOOST_CHECK_EQUAL(spks.size(), ref.size());

            // Try to expand again using cached data, and compare.
            BOOST_CHECK(parse_pub->ExpandFromCache(i, desc_cache, spks_cached, script_provider_cached));
            BOOST_CHECK(spks == spks_cached);
            BOOST_CHECK(GetKeyData(script_provider, flags) == GetKeyData(script_provider_cached, flags));
            BOOST_CHECK(script_provider.scripts == script_provider_cached.scripts);
            BOOST_CHECK(GetKeyOriginData(script_provider, flags) == GetKeyOriginData(script_provider_cached, flags));

            // Check whether keys are in the cache
            const auto& der_xpub_cache = desc_cache.GetCachedDerivedExtPubKeys();
            const auto& parent_xpub_cache = desc_cache.GetCachedParentExtPubKeys();
            const size_t num_xpubs = CountXpubs(pub1);
            if ((flags & RANGE) && !(flags & (DERIVE_HARDENED))) {
                // For ranged, unhardened derivation, None of the keys in origins should appear in the cache but the cache should have parent keys
                // But we can derive one level from each of those parent keys and find them all
                BOOST_CHECK(der_xpub_cache.empty());
                BOOST_CHECK(parent_xpub_cache.size() > 0);
                std::set<CPubKey> pubkeys;
                for (const auto& xpub_pair : parent_xpub_cache) {
                    const CExtPubKey& xpub = xpub_pair.second;
                    CExtPubKey der;
                    BOOST_CHECK(xpub.Derive(der, i));
                    pubkeys.insert(der.pubkey);
                }
                int count_pks = 0;
                for (const auto& origin_pair : script_provider_cached.origins) {
                    const CPubKey& pk = origin_pair.second.first;
                    count_pks += pubkeys.count(pk);
                }
                if (flags & MIXED_PUBKEYS) {
                    BOOST_CHECK_EQUAL(num_xpubs, count_pks);
                } else {
                    BOOST_CHECK_EQUAL(script_provider_cached.origins.size(), count_pks);
                }
            } else if (num_xpubs > 0) {
                // For ranged, hardened derivation, or not ranged, but has an xpub, all of the keys should appear in the cache
                BOOST_CHECK(der_xpub_cache.size() + parent_xpub_cache.size() == num_xpubs);
                if (!(flags & MIXED_PUBKEYS)) {
                    BOOST_CHECK(num_xpubs == script_provider_cached.origins.size());
                }
                // Get all of the derived pubkeys
                std::set<CPubKey> pubkeys;
                for (const auto& xpub_map_pair : der_xpub_cache) {
                    for (const auto& xpub_pair : xpub_map_pair.second) {
                        const CExtPubKey& xpub = xpub_pair.second;
                        pubkeys.insert(xpub.pubkey);
                    }
                }
                // Derive one level from all of the parents
                for (const auto& xpub_pair : parent_xpub_cache) {
                    const CExtPubKey& xpub = xpub_pair.second;
                    pubkeys.insert(xpub.pubkey);
                    CExtPubKey der;
                    BOOST_CHECK(xpub.Derive(der, i));
                    pubkeys.insert(der.pubkey);
                }
                int count_pks = 0;
                for (const auto& origin_pair : script_provider_cached.origins) {
                    const CPubKey& pk = origin_pair.second.first;
                    count_pks += pubkeys.count(pk);
                }
                if (flags & MIXED_PUBKEYS) {
                    BOOST_CHECK_EQUAL(num_xpubs, count_pks);
                } else {
                    BOOST_CHECK_EQUAL(script_provider_cached.origins.size(), count_pks);
                }
            } else if (!(flags & MIXED_PUBKEYS)) {
                // Only const pubkeys, nothing should be cached
                BOOST_CHECK(der_xpub_cache.empty());
                BOOST_CHECK(parent_xpub_cache.empty());
            }

            // Make sure we can expand using cached xpubs for unhardened derivation
            if (!(flags & DERIVE_HARDENED)) {
                // Evaluate the descriptor at i + 1
                FlatSigningProvider script_provider1, script_provider_cached1;
                std::vector<CScript> spks1, spk1_from_cache;
                BOOST_CHECK((t ? parse_priv : parse_pub)->Expand(i + 1, key_provider, spks1, script_provider1, nullptr));

                // Try again but use the cache from expanding i. That cache won't have the pubkeys for i + 1, but will have the parent xpub for derivation.
                BOOST_CHECK(parse_pub->ExpandFromCache(i + 1, desc_cache, spk1_from_cache, script_provider_cached1));
                BOOST_CHECK(spks1 == spk1_from_cache);
                BOOST_CHECK(GetKeyData(script_provider1, flags) == GetKeyData(script_provider_cached1, flags));
                BOOST_CHECK(script_provider1.scripts == script_provider_cached1.scripts);
                BOOST_CHECK(GetKeyOriginData(script_provider1, flags) == GetKeyOriginData(script_provider_cached1, flags));
            }

            // For each of the produced scripts, verify solvability, and when possible, try to sign a transaction spending it.
            for (size_t n = 0; n < spks.size(); ++n) {
                BOOST_CHECK_EQUAL(ref[n], HexStr(spks[n]));

                if (flags & (SIGNABLE | SIGNABLE_FAILS)) {
                    CMutableTransaction spend;
                    spend.nLockTime = spender_nlocktime;
                    spend.vin.resize(1);
                    spend.vin[0].nSequence = spender_nsequence;
                    spend.vout.resize(1);
                    std::vector<CTxOut> utxos(1);
                    PrecomputedTransactionData txdata;
                    txdata.Init(spend, std::move(utxos), /*force=*/true);
                    MutableTransactionSignatureCreator creator{spend, 0, CAmount{0}, &txdata, SIGHASH_DEFAULT};
                    SignatureData sigdata;
                    // We assume there is no collision between the hashes (eg h1=SHA256(SHA256(x)) and h2=SHA256(x))
                    sigdata.sha256_preimages = preimages;
                    sigdata.hash256_preimages = preimages;
                    sigdata.ripemd160_preimages = preimages;
                    sigdata.hash160_preimages = preimages;
                    const auto prod_sig_res = ProduceSignature(FlatSigningProvider{keys_priv}.Merge(FlatSigningProvider{script_provider}), creator, spks[n], sigdata);
                    BOOST_CHECK_MESSAGE(prod_sig_res == !(flags & SIGNABLE_FAILS), prv);
                }

                /* Infer a descriptor from the generated script, and verify its solvability and that it roundtrips. */
                auto inferred = InferDescriptor(spks[n], script_provider);
                BOOST_CHECK_EQUAL(inferred->IsSolvable(), !(flags & UNSOLVABLE));
                std::vector<CScript> spks_inferred;
                FlatSigningProvider provider_inferred;
                BOOST_CHECK(inferred->Expand(0, provider_inferred, spks_inferred, provider_inferred));
                BOOST_CHECK_EQUAL(spks_inferred.size(), 1U);
                BOOST_CHECK(spks_inferred[0] == spks[n]);
                BOOST_CHECK_EQUAL(InferDescriptor(spks_inferred[0], provider_inferred)->IsSolvable(), !(flags & UNSOLVABLE));
                BOOST_CHECK(GetKeyOriginData(provider_inferred, flags) == GetKeyOriginData(script_provider, flags));
            }

            // Test whether the observed key path is present in the 'paths' variable (which contains expected, unobserved paths),
            // and then remove it from that set.
            for (const auto& origin : script_provider.origins) {
                BOOST_CHECK_MESSAGE(paths.count(origin.second.second.path), "Unexpected key path: " + prv);
                left_paths.erase(origin.second.second.path);
            }
        }
    }

    // Verify no expected paths remain that were not observed.
    BOOST_CHECK_MESSAGE(left_paths.empty(), "Not all expected key paths found: " + prv);
}

void Check(const std::string& prv, const std::string& pub, const std::string& norm_pub, int flags,
           const std::vector<std::vector<std::string>>& scripts, const std::optional<OutputType>& type,
           const std::set<std::vector<uint32_t>>& paths = ONLY_EMPTY, uint32_t spender_nlocktime=0,
           uint32_t spender_nsequence=CTxIn::SEQUENCE_FINAL, std::map<std::vector<uint8_t>, std::vector<uint8_t>> preimages={})
{
    bool found_apostrophes_in_prv = false;
    bool found_apostrophes_in_pub = false;

    // Do not replace apostrophes with 'h' in prv and pub
    DoCheck(prv, pub, norm_pub, flags, scripts, type, paths, /*replace_apostrophe_with_h_in_prv=*/false,
            /*replace_apostrophe_with_h_in_pub=*/false, /*spender_nlocktime=*/spender_nlocktime,
            /*spender_nsequence=*/spender_nsequence, /*preimages=*/preimages);

    // Replace apostrophes with 'h' in prv but not in pub, if apostrophes are found in prv
    if (prv.find('\'') != std::string::npos) {
        found_apostrophes_in_prv = true;
        DoCheck(prv, pub, norm_pub, flags, scripts, type, paths, /*replace_apostrophe_with_h_in_prv=*/true,
                /*replace_apostrophe_with_h_in_pub=*/false, /*spender_nlocktime=*/spender_nlocktime,
                /*spender_nsequence=*/spender_nsequence, /*preimages=*/preimages);
    }

    // Replace apostrophes with 'h' in pub but not in prv, if apostrophes are found in pub
    if (pub.find('\'') != std::string::npos) {
        found_apostrophes_in_pub = true;
        DoCheck(prv, pub, norm_pub, flags, scripts, type, paths, /*replace_apostrophe_with_h_in_prv=*/false,
                /*replace_apostrophe_with_h_in_pub=*/true,  /*spender_nlocktime=*/spender_nlocktime,
                /*spender_nsequence=*/spender_nsequence, /*preimages=*/preimages);
    }

    // Replace apostrophes with 'h' both in prv and in pub, if apostrophes are found in both
    if (found_apostrophes_in_prv && found_apostrophes_in_pub) {
        DoCheck(prv, pub, norm_pub, flags, scripts, type, paths, /*replace_apostrophe_with_h_in_prv=*/true,
                /*replace_apostrophe_with_h_in_pub=*/true, /*spender_nlocktime=*/spender_nlocktime,
                /*spender_nsequence=*/spender_nsequence, /*preimages=*/preimages);
    }
}

}

BOOST_FIXTURE_TEST_SUITE(descriptor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(descriptor_test)
{
    // Basic single-key compressed
    Check("combo(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "combo(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "combo(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", SIGNABLE, {{"21024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308ac","76a914193f5f1fc3a4cf5404cc0e4c341abff5f333e34488ac","0014193f5f1fc3a4cf5404cc0e4c341abff5f333e344","a9142b404939a3614542e0f6e4bdef0a57fa1067da0587"}}, std::nullopt);
    Check("pk(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", SIGNABLE, {{"21024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308ac"}}, std::nullopt);
    Check("pkh([deadbeef/1/2'/3/4']U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "pkh([deadbeef/1/2'/3/4']024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "pkh([deadbeef/1/2'/3/4']024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", SIGNABLE, {{"76a914193f5f1fc3a4cf5404cc0e4c341abff5f333e34488ac"}}, OutputType::LEGACY, {{1,0x80000002UL,3,0x80000004UL}});
    Check("wpkh(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "wpkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "wpkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", SIGNABLE, {{"0014193f5f1fc3a4cf5404cc0e4c341abff5f333e344"}}, OutputType::BECH32);
    Check("sh(wpkh(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))", "sh(wpkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", "sh(wpkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", SIGNABLE, {{"a9142b404939a3614542e0f6e4bdef0a57fa1067da0587"}}, OutputType::P2SH_SEGWIT);
    Check("tr(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "tr(4f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "tr(4f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", SIGNABLE | XONLY_KEYS, {{"512041524c2edf15e8f0738109fd7709578d708c655cf657c013284773a43e845094"}}, OutputType::BECH32M);
    CheckUnparsable("sh(wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY2))", "sh(wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5))", "wpkh(): Pubkey '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5' is invalid"); // Invalid pubkey
    CheckUnparsable("pkh(deadbeef/1/2'/3/4']U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "pkh(deadbeef/1/2'/3/4']024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "pkh(): Key origin start '[ character expected but not found, got 'd' instead"); // Missing start bracket in key origin
    CheckUnparsable("pkh([deadbeef]/1/2'/3/4']U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "pkh([deadbeef]/1/2'/3/4']024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "pkh(): Multiple ']' characters found for a single pubkey"); // Multiple end brackets in key origin

    // Basic single-key uncompressed
    Check("combo(7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "combo(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "combo(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)",SIGNABLE, {{"4104dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44bac","76a91442bee04edafe3a09ecf43bb52575bb713f3ca44588ac"}}, std::nullopt);
    Check("pk(7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "pk(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "pk(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", SIGNABLE, {{"4104dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44bac"}}, std::nullopt);
    Check("pkh(7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "pkh(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "pkh(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", SIGNABLE, {{"76a91442bee04edafe3a09ecf43bb52575bb713f3ca44588ac"}}, OutputType::LEGACY);
    CheckUnparsable("wpkh(7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "wpkh(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "wpkh(): Uncompressed keys are not allowed"); // No uncompressed keys in witness
    CheckUnparsable("wsh(pk(7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf))", "wsh(pk(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b))", "pk(): Uncompressed keys are not allowed"); // No uncompressed keys in witness
    CheckUnparsable("sh(wpkh(7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf))", "sh(wpkh(04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b))", "wpkh(): Uncompressed keys are not allowed"); // No uncompressed keys in witness

    // Some unconventional single-key constructions
    Check("sh(pk(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))", "sh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", "sh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", SIGNABLE, {{"a9140823042319af799524a0b34ef780c7eef45ff57a87"}}, OutputType::LEGACY);
    Check("sh(pkh(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))", "sh(pkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", "sh(pkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", SIGNABLE, {{"a914d97fe4605b350a65aed44734758d42f911b8f81787"}}, OutputType::LEGACY);
    Check("wsh(pk(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))", "wsh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", "wsh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", SIGNABLE, {{"002078d6059d368a703c17b5ed5604edae402c8a78b1cbcb6a42a44abfb48a694440"}}, OutputType::BECH32);
    Check("wsh(pkh(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))", "wsh(pkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", "wsh(pkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", SIGNABLE, {{"0020ef7ab37991998c47ca4e5d3a4be1d77ebf852bdf006484c816d6393403bdd652"}}, OutputType::BECH32);
    Check("sh(wsh(pk(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)))", "sh(wsh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)))", "sh(wsh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)))", SIGNABLE, {{"a9141e44a3167ae361b28b3222b6064382eab11bf44487"}}, OutputType::P2SH_SEGWIT);
    Check("sh(wsh(pkh(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)))", "sh(wsh(pkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)))", "sh(wsh(pkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)))", SIGNABLE, {{"a914dfc38dcf807e8a00d34887ab703696906311c9cb87"}}, OutputType::P2SH_SEGWIT);
    Check("tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})", "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(4f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})", "tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5,{pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5),{pk(4f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308),pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5)}})", XONLY_KEYS | SIGNABLE | MISSING_PRIVKEYS, {{"5120a1a056c78da5327e230d735409a22c6664c2ef31531b965bc3f77a7ca8de5224"}}, OutputType::BECH32M);

    // Versions with BIP32 derivations
    Check("combo([01234567]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)", "combo([01234567]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)", "combo([01234567]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)", SIGNABLE, {{"2102d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0ac","76a91431a507b815593dfc51ffc7245ae7e5aee304246e88ac","001431a507b815593dfc51ffc7245ae7e5aee304246e","a9142aafb926eb247cb18240a7f4c07983ad1f37922687"}}, std::nullopt);
    Check("pk(xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0)", "pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)", "pk(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)", DEFAULT, {{"210379e45b3cf75f9c5f9befd8e9506fb962f6a9d185ac87001ec44a8d3df8d4a9e3ac"}}, std::nullopt, {{0}});
    Check("pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0)", "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)", "pkh([bd16bee5/2147483647']xpub69H7F5dQzmVd3vPuLKtcXJziMEQByuDidnX3YdwgtNsecY5HRGtAAQC5mXTt4dsv9RzyjgDjAQs9VGVV6ydYCHnprc9vvaA5YtqWyL6hyds/0)", HARDENED, {{"76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"}}, OutputType::LEGACY, {{0xFFFFFFFFUL,0}});

    Check("wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*)", "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)", "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)", RANGE, {{"0014326b2249e3a25d5dc60935f044ee835d090ba859"},{"0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"},{"00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27"}}, OutputType::BECH32, {{0x8000000DUL, 1, 2, 0}, {0x8000000DUL, 1, 2, 1}, {0x8000000DUL, 1, 2, 2}});
    Check("sh(wpkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))", "sh(wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", "sh(wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", RANGE | HARDENED | DERIVE_HARDENED, {{"a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87"},{"a914bed59fc0024fae941d6e20a3b44a109ae740129287"},{"a9148483aa1116eb9c05c482a72bada4b1db24af654387"}}, OutputType::P2SH_SEGWIT, {{10, 20, 30, 40, 0x80000000UL}, {10, 20, 30, 40, 0x80000001UL}, {10, 20, 30, 40, 0x80000002UL}});
    Check("combo(xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/*)", "combo(xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*)", "combo(xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*)", RANGE, {{"2102df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076ac","76a914f90e3178ca25f2c808dc76624032d352fdbdfaf288ac","0014f90e3178ca25f2c808dc76624032d352fdbdfaf2","a91408f3ea8c68d4a7585bf9e8bda226723f70e445f087"},{"21032869a233c9adff9a994e4966e5b821fd5bac066da6c3112488dc52383b4a98ecac","76a914a8409d1b6dfb1ed2a3e8aa5e0ef2ff26b15b75b788ac","0014a8409d1b6dfb1ed2a3e8aa5e0ef2ff26b15b75b7","a91473e39884cb71ae4e5ac9739e9225026c99763e6687"}}, std::nullopt, {{0}, {1}});
    Check("tr(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/0/*,pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/1/*))", "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*))", "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*))", XONLY_KEYS | RANGE, {{"512078bc707124daa551b65af74de2ec128b7525e10f374dc67b64e00ce0ab8b3e12"}, {"512001f0a02a17808c20134b78faab80ef93ffba82261ccef0a2314f5d62b6438f11"}, {"512021024954fcec88237a9386fce80ef2ced5f1e91b422b26c59ccfc174c8d1ad25"}}, OutputType::BECH32M, {{0, 0}, {0, 1}, {0, 2}, {1, 0}, {1, 1}, {1, 2}});
    // Mixed xpubs and const pubkeys
    Check("wsh(multi(1,xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))","wsh(multi(1,xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/0,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))","wsh(multi(1,xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/0,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", MIXED_PUBKEYS, {{"00202f4a7d57a46bd78e97e38189ccc28ddad8e2a5bb9af23d7ecd7b257ad89e5b0c"}},OutputType::BECH32,{{0},{}});
    // Mixed range xpubs and const pubkeys
    Check("multi(1,xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/*,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)","multi(1,xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)","multi(1,xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV/*,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", RANGE | MIXED_PUBKEYS, {{"512102df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e07621024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc730852ae"},{"5121032869a233c9adff9a994e4966e5b821fd5bac066da6c3112488dc52383b4a98ec21024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc730852ae"},{"5121035d30b6c66dc1e036c45369da8287518cf7e0d6ed1e2b905171c605708f14ca0321024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc730852ae"}}, std::nullopt,{{2},{1},{0},{}});

    CheckUnparsable("combo([012345678]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)", "combo([012345678]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)", "combo(): Fingerprint is not 4 bytes (9 characters instead of 8 characters)"); // Too long key fingerprint
    CheckUnparsable("pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483648)", "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483648)", "pkh(): Key path value 2147483648 is out of range"); // BIP 32 path element overflow
    CheckUnparsable("pkh(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/1aa)", "pkh(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1aa)", "pkh(): Key path value '1aa' is not a valid uint32"); // Path is not valid uint
    Check("pkh([01234567/10/20]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0)", "pkh([01234567/10/20]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0)", "pkh([01234567/10/20/2147483647']xpub69H7F5dQzmVd3vPuLKtcXJziMEQByuDidnX3YdwgtNsecY5HRGtAAQC5mXTt4dsv9RzyjgDjAQs9VGVV6ydYCHnprc9vvaA5YtqWyL6hyds/0)", HARDENED, {{"76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"}}, OutputType::LEGACY, {{10, 20, 0xFFFFFFFFUL, 0}});

    // Multisig constructions
    Check("multi(1,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt,7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "multi(1,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "multi(1,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", SIGNABLE, {{"5121024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc73084104dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b52ae"}}, std::nullopt);
    Check("sortedmulti(1,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt,7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "sortedmulti(1,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "sortedmulti(1,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", SIGNABLE, {{"5121024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc73084104dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b52ae"}}, std::nullopt);
    Check("sortedmulti(1,7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "sortedmulti(1,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "sortedmulti(1,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", SIGNABLE, {{"5121024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc73084104dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b52ae"}}, std::nullopt);
    Check("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))", DEFAULT, {{"a91445a9a622a8b0a1269944be477640eedc447bbd8487"}}, OutputType::LEGACY, {{0x8000006FUL,222},{0}});
    Check("sortedmulti(2,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/*,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0/0/*)", "sortedmulti(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*)", "sortedmulti(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*)", RANGE, {{"5221025d5fc65ebb8d44a5274b53bac21ff8307fec2334a32df05553459f8b1f7fe1b62102fbd47cc8034098f0e6a94c6aeee8528abf0a2153a5d8e46d325b7284c046784652ae"}, {"52210264fd4d1f5dea8ded94c61e9641309349b62f27fbffe807291f664e286bfbe6472103f4ece6dfccfa37b211eb3d0af4d0c61dba9ef698622dc17eecdf764beeb005a652ae"}, {"5221022ccabda84c30bad578b13c89eb3b9544ce149787e5b538175b1d1ba259cbb83321024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c52ae"}}, std::nullopt, {{0}, {1}, {2}, {0, 0, 0}, {0, 0, 1}, {0, 0, 2}});
    Check("wsh(multi(2,xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))", "wsh(multi(2,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", "wsh(multi(2,[bd16bee5/2147483647']xpub69H7F5dQzmVd3vPuLKtcXJziMEQByuDidnX3YdwgtNsecY5HRGtAAQC5mXTt4dsv9RzyjgDjAQs9VGVV6ydYCHnprc9vvaA5YtqWyL6hyds/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", HARDENED | RANGE | DERIVE_HARDENED, {{"0020b92623201f3bb7c3771d45b2ad1d0351ea8fbf8cfe0a0e570264e1075fa1948f"},{"002036a08bbe4923af41cf4316817c93b8d37e2f635dd25cfff06bd50df6ae7ea203"},{"0020a96e7ab4607ca6b261bfe3245ffda9c746b28d3f59e83d34820ec0e2b36c139c"}}, OutputType::BECH32, {{0xFFFFFFFFUL,0}, {1,2,0}, {1,2,1}, {1,2,2}, {10, 20, 30, 40, 0x80000000UL}, {10, 20, 30, 40, 0x80000001UL}, {10, 20, 30, 40, 0x80000002UL}});
    Check("sh(wsh(multi(16,U9YzFw3aHmb5NTbbd9iA5ekb68YLKLhiEC4mxXne17Z5KhFJFhgg,U9SmYY8oJWSjEYVkXEHHCFQ52YFrdFWBjcHMGReD7WhWm2EVQcBJ,UAXu6GBPnTzjBhVwy7LfaaCxxeCb4jhYkjYxHiDJ6FGXFWzYt5gq,U6XtjW6u5DTYXdSvXBAXncHc1rkGSVpjRSUM5AFVNQWXbND1i9pB,UAiS9tnptx194BNUBUz2iD93ZX48DGx9GJNekKDEazosgT7VRpGy,U9ynbLeFvzo6vwpoJMpcnCYiTA4yHgP2erCsfB3apbKgF8ngvQqk,U9xj7zavCQUVEePLwyiLWbYD37TyujvodLHoDMiBtzZSHpp26hdP,UA6Cm9xoUX5a81VsT2ixvvH4Qy1ZF7F7DqyPrz1AQoK5SwMVsw53,UCpbmwhiHgoLTv1D7Q9xunPenpqhSyr84B6uEUAWF3qPGasgMbB2,U717ZeD8tCrgdSwgULawYw82tLvwVAdv5sXmV5YoVqvZuDTfCehw,UAcWB7Kn7P5LpMaCxHnYSqwhEtZw3JoRqV9FLsvW6LjxF8xyENuw,UAxxKXwDaCyj57he5rRS1FcCwGqkKKNACXqSxCDrZ8oy1sW89sVA,U5tgY8DVvKBsfJT2fiFKC2rye9hxATirv6qtyawdw2tyo94RyY54,UBeH9oCyLUDafNbENwbMZnq5w3Teks5DxEgFgmhN2k4HC61cs8UF,U8e8JHiDVPz6XuoaqhDR5hxmC8Es7UeMc3kvRUXTXvHJRzMkZz8Z,UCSFsLeknWKjyrTXiFnGCHnUNemwgieuZQ4W2HxToqKfTvwFmTDX)))","sh(wsh(multi(16,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754,039bc932eb018ef301976c609b05bf62eb2486eb6826ddec7f8bbb394d6ff755a7,028af84779f096f95342f6f3605e440cb868f17fc95e4a45946d801279b48a3d1f,037626ada861e2889269fb3bf028b47066ecf89b92ddbac52d9bfc6ec0786cbbf0,0385af33d66981cabb6fc2167c57367791f6dae6e99c86daf101e0c9b3cb0e05d8,0201295b1c7a45e58c86bef979434660845b36e6111f16200690edab0315cc5cad,03e1eb17f416e858a178201dd1140bebb53b01bc9550f584b748c2850781e5a0f6,02ac3c4ba7acb5d4edbb514f0ddc8fc4c515855f00cccf06f07258d66bd79886ea,0255869a5609616f2718b5accdb136cc13968b2735b7ce4790db4a781fd62c82a3,0305f20642f237f2d466a2d10392962c14408141840d801ba0397613f51ca51f19,0383710a72e7f417ff730735ba336596b90ce775fb8aae794e70954c57c356b0df,026169fa51018edb044bede4f6a9eff9869db22e1a82bbaab31ac106f142f60ba0,02d82a04c69cba026357ca98f63c359152bbc63600905882ba0e25c77c358b27ee)))", "sh(wsh(multi(16,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754,039bc932eb018ef301976c609b05bf62eb2486eb6826ddec7f8bbb394d6ff755a7,028af84779f096f95342f6f3605e440cb868f17fc95e4a45946d801279b48a3d1f,037626ada861e2889269fb3bf028b47066ecf89b92ddbac52d9bfc6ec0786cbbf0,0385af33d66981cabb6fc2167c57367791f6dae6e99c86daf101e0c9b3cb0e05d8,0201295b1c7a45e58c86bef979434660845b36e6111f16200690edab0315cc5cad,03e1eb17f416e858a178201dd1140bebb53b01bc9550f584b748c2850781e5a0f6,02ac3c4ba7acb5d4edbb514f0ddc8fc4c515855f00cccf06f07258d66bd79886ea,0255869a5609616f2718b5accdb136cc13968b2735b7ce4790db4a781fd62c82a3,0305f20642f237f2d466a2d10392962c14408141840d801ba0397613f51ca51f19,0383710a72e7f417ff730735ba336596b90ce775fb8aae794e70954c57c356b0df,026169fa51018edb044bede4f6a9eff9869db22e1a82bbaab31ac106f142f60ba0,02d82a04c69cba026357ca98f63c359152bbc63600905882ba0e25c77c358b27ee)))", SIGNABLE, {{"a914a5d07cd5738cc75fa5baef59b450028aeeaba6d287"}}, OutputType::P2SH_SEGWIT);
    Check("tr(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt,pk(U9YzFw3aHmb5NTbbd9iA5ekb68YLKLhiEC4mxXne17Z5KhFJFhgg))", "tr(4f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,pk(726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f))", "tr(4f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,pk(726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f))", SIGNABLE | XONLY_KEYS, {{"5120793167c552ab8371fa787739eca4b0f69c8de8c6339b96a77ae2d39a3abcf0a6"}}, OutputType::BECH32M);
    CheckUnparsable("sh(multi(16,U9YzFw3aHmb5NTbbd9iA5ekb68YLKLhiEC4mxXne17Z5KhFJFhgg,U9SmYY8oJWSjEYVkXEHHCFQ52YFrdFWBjcHMGReD7WhWm2EVQcBJ,UAXu6GBPnTzjBhVwy7LfaaCxxeCb4jhYkjYxHiDJ6FGXFWzYt5gq,U6XtjW6u5DTYXdSvXBAXncHc1rkGSVpjRSUM5AFVNQWXbND1i9pB,UAiS9tnptx194BNUBUz2iD93ZX48DGx9GJNekKDEazosgT7VRpGy,U9ynbLeFvzo6vwpoJMpcnCYiTA4yHgP2erCsfB3apbKgF8ngvQqk,U9xj7zavCQUVEePLwyiLWbYD37TyujvodLHoDMiBtzZSHpp26hdP,UA6Cm9xoUX5a81VsT2ixvvH4Qy1ZF7F7DqyPrz1AQoK5SwMVsw53,UCpbmwhiHgoLTv1D7Q9xunPenpqhSyr84B6uEUAWF3qPGasgMbB2,U717ZeD8tCrgdSwgULawYw82tLvwVAdv5sXmV5YoVqvZuDTfCehw,UAcWB7Kn7P5LpMaCxHnYSqwhEtZw3JoRqV9FLsvW6LjxF8xyENuw,UAxxKXwDaCyj57he5rRS1FcCwGqkKKNACXqSxCDrZ8oy1sW89sVA,U5tgY8DVvKBsfJT2fiFKC2rye9hxATirv6qtyawdw2tyo94RyY54,UBeH9oCyLUDafNbENwbMZnq5w3Teks5DxEgFgmhN2k4HC61cs8UF,U8e8JHiDVPz6XuoaqhDR5hxmC8Es7UeMc3kvRUXTXvHJRzMkZz8Z,UCSFsLeknWKjyrTXiFnGCHnUNemwgieuZQ4W2HxToqKfTvwFmTDX))","sh(multi(16,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754,039bc932eb018ef301976c609b05bf62eb2486eb6826ddec7f8bbb394d6ff755a7,028af84779f096f95342f6f3605e440cb868f17fc95e4a45946d801279b48a3d1f,037626ada861e2889269fb3bf028b47066ecf89b92ddbac52d9bfc6ec0786cbbf0,0385af33d66981cabb6fc2167c57367791f6dae6e99c86daf101e0c9b3cb0e05d8,0201295b1c7a45e58c86bef979434660845b36e6111f16200690edab0315cc5cad,03e1eb17f416e858a178201dd1140bebb53b01bc9550f584b748c2850781e5a0f6,02ac3c4ba7acb5d4edbb514f0ddc8fc4c515855f00cccf06f07258d66bd79886ea,0255869a5609616f2718b5accdb136cc13968b2735b7ce4790db4a781fd62c82a3,0305f20642f237f2d466a2d10392962c14408141840d801ba0397613f51ca51f19,0383710a72e7f417ff730735ba336596b90ce775fb8aae794e70954c57c356b0df,026169fa51018edb044bede4f6a9eff9869db22e1a82bbaab31ac106f142f60ba0,02d82a04c69cba026357ca98f63c359152bbc63600905882ba0e25c77c358b27ee))", "P2SH script is too large, 547 bytes is larger than 520 bytes"); // P2SH does not fit 16 compressed pubkeys in a redeemscript
    CheckUnparsable("wsh(multi(2,[aaaaaaaa][aaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaa][aaaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", "Multi: Multiple ']' characters found for a single pubkey"); // Double key origin descriptor
    CheckUnparsable("wsh(multi(2,[aaaagaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))", "wsh(multi(2,[aaagaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", "Multi: Fingerprint 'aaagaaaa' is not hex"); // Non hex fingerprint
    CheckUnparsable("wsh(multi(2,[aaaaaaaa],xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaa],xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", "Multi: No key provided"); // No public key with origin
    CheckUnparsable("wsh(multi(2,[aaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", "Multi: Fingerprint is not 4 bytes (7 characters instead of 8 characters)"); // Too short fingerprint
    CheckUnparsable("wsh(multi(2,[aaaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))", "wsh(multi(2,[aaaaaaaaa]xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*,xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/10/20/30/40/*'))", "Multi: Fingerprint is not 4 bytes (9 characters instead of 8 characters)"); // Too long fingerprint
    CheckUnparsable("multi(a,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt,7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "multi(a,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "Multi threshold 'a' is not valid"); // Invalid threshold
    CheckUnparsable("multi(0,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt,7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "multi(0,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "Multisig threshold cannot be 0, must be at least 1"); // Threshold of 0
    CheckUnparsable("multi(3,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt,7A1cTqn3twP92WJ4oPEa3JYkXm2xUt6xHwp9bWneSCAZ2iEeixf)", "multi(3,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308,04dbc01b52a02f682055bf7e5d67ac963517ca9e2402b7892fe3382289f47661597c1dcb69ca48deb197164c48ba86ecc2bd29eb8bb8428e3d44eefdb7c6b8b44b)", "Multisig threshold cannot be larger than the number of keys; threshold is 3 but only 2 keys specified"); // Threshold larger than number of keys
    CheckUnparsable("multi(3,U9YzFw3aHmb5NTbbd9iA5ekb68YLKLhiEC4mxXne17Z5KhFJFhgg,U9SmYY8oJWSjEYVkXEHHCFQ52YFrdFWBjcHMGReD7WhWm2EVQcBJ,UAXu6GBPnTzjBhVwy7LfaaCxxeCb4jhYkjYxHiDJ6FGXFWzYt5gq,U6XtjW6u5DTYXdSvXBAXncHc1rkGSVpjRSUM5AFVNQWXbND1i9pB)", "multi(3,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754)", "Cannot have 4 pubkeys in bare multisig; only at most 3 pubkeys"); // Threshold larger than number of keys
    CheckUnparsable("sh(multi(16,U9YzFw3aHmb5NTbbd9iA5ekb68YLKLhiEC4mxXne17Z5KhFJFhgg,U9SmYY8oJWSjEYVkXEHHCFQ52YFrdFWBjcHMGReD7WhWm2EVQcBJ,UAXu6GBPnTzjBhVwy7LfaaCxxeCb4jhYkjYxHiDJ6FGXFWzYt5gq,U6XtjW6u5DTYXdSvXBAXncHc1rkGSVpjRSUM5AFVNQWXbND1i9pB,UAiS9tnptx194BNUBUz2iD93ZX48DGx9GJNekKDEazosgT7VRpGy,U9ynbLeFvzo6vwpoJMpcnCYiTA4yHgP2erCsfB3apbKgF8ngvQqk,U9xj7zavCQUVEePLwyiLWbYD37TyujvodLHoDMiBtzZSHpp26hdP,UA6Cm9xoUX5a81VsT2ixvvH4Qy1ZF7F7DqyPrz1AQoK5SwMVsw53,UCpbmwhiHgoLTv1D7Q9xunPenpqhSyr84B6uEUAWF3qPGasgMbB2,U717ZeD8tCrgdSwgULawYw82tLvwVAdv5sXmV5YoVqvZuDTfCehw,UAcWB7Kn7P5LpMaCxHnYSqwhEtZw3JoRqV9FLsvW6LjxF8xyENuw,UAxxKXwDaCyj57he5rRS1FcCwGqkKKNACXqSxCDrZ8oy1sW89sVA,U5tgY8DVvKBsfJT2fiFKC2rye9hxATirv6qtyawdw2tyo94RyY54,UBeH9oCyLUDafNbENwbMZnq5w3Teks5DxEgFgmhN2k4HC61cs8UF,U8e8JHiDVPz6XuoaqhDR5hxmC8Es7UeMc3kvRUXTXvHJRzMkZz8Z,UCSFsLeknWKjyrTXiFnGCHnUNemwgieuZQ4W2HxToqKfTvwFmTDX,U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))","sh(multi(16,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754,039bc932eb018ef301976c609b05bf62eb2486eb6826ddec7f8bbb394d6ff755a7,028af84779f096f95342f6f3605e440cb868f17fc95e4a45946d801279b48a3d1f,037626ada861e2889269fb3bf028b47066ecf89b92ddbac52d9bfc6ec0786cbbf0,0385af33d66981cabb6fc2167c57367791f6dae6e99c86daf101e0c9b3cb0e05d8,0201295b1c7a45e58c86bef979434660845b36e6111f16200690edab0315cc5cad,03e1eb17f416e858a178201dd1140bebb53b01bc9550f584b748c2850781e5a0f6,02ac3c4ba7acb5d4edbb514f0ddc8fc4c515855f00cccf06f07258d66bd79886ea,0255869a5609616f2718b5accdb136cc13968b2735b7ce4790db4a781fd62c82a3,0305f20642f237f2d466a2d10392962c14408141840d801ba0397613f51ca51f19,0383710a72e7f417ff730735ba336596b90ce775fb8aae794e70954c57c356b0df,026169fa51018edb044bede4f6a9eff9869db22e1a82bbaab31ac106f142f60ba0,02d82a04c69cba026357ca98f63c359152bbc63600905882ba0e25c77c358b27ee,024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", "P2SH script is too large, 581 bytes is larger than 520 bytes"); // Cannot have more than 15 keys in a P2SH multisig, or we exceed maximum push size
    Check("wsh(multi(20,U9YzFw3aHmb5NTbbd9iA5ekb68YLKLhiEC4mxXne17Z5KhFJFhgg,U9SmYY8oJWSjEYVkXEHHCFQ52YFrdFWBjcHMGReD7WhWm2EVQcBJ,UAXu6GBPnTzjBhVwy7LfaaCxxeCb4jhYkjYxHiDJ6FGXFWzYt5gq,U6XtjW6u5DTYXdSvXBAXncHc1rkGSVpjRSUM5AFVNQWXbND1i9pB,UAiS9tnptx194BNUBUz2iD93ZX48DGx9GJNekKDEazosgT7VRpGy,U9ynbLeFvzo6vwpoJMpcnCYiTA4yHgP2erCsfB3apbKgF8ngvQqk,U9xj7zavCQUVEePLwyiLWbYD37TyujvodLHoDMiBtzZSHpp26hdP,UA6Cm9xoUX5a81VsT2ixvvH4Qy1ZF7F7DqyPrz1AQoK5SwMVsw53,UCpbmwhiHgoLTv1D7Q9xunPenpqhSyr84B6uEUAWF3qPGasgMbB2,U717ZeD8tCrgdSwgULawYw82tLvwVAdv5sXmV5YoVqvZuDTfCehw,UAcWB7Kn7P5LpMaCxHnYSqwhEtZw3JoRqV9FLsvW6LjxF8xyENuw,UAxxKXwDaCyj57he5rRS1FcCwGqkKKNACXqSxCDrZ8oy1sW89sVA,U5tgY8DVvKBsfJT2fiFKC2rye9hxATirv6qtyawdw2tyo94RyY54,UBeH9oCyLUDafNbENwbMZnq5w3Teks5DxEgFgmhN2k4HC61cs8UF,U8e8JHiDVPz6XuoaqhDR5hxmC8Es7UeMc3kvRUXTXvHJRzMkZz8Z,UCSFsLeknWKjyrTXiFnGCHnUNemwgieuZQ4W2HxToqKfTvwFmTDX,U8tLyAiL6N6KBuJb1aJQkwKsNpkGrCTg8oNNhYZ81GzsTuLbKZqv,UARcoSRRYjJLWyhY9dc4fKTkyxBP29n2dA4RpjYzBu3KUCNA4FUV,UBWPychSSa1UfcuhbKK7QoEy7Z5fgoaDGXP7bwHL5G9iNN4ad15v,UCqAgZ6XSbANN3xzbnUMraFeqCzTKjBCL5jyN2ZH3NsLNFY7REDn))","wsh(multi(20,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754,039bc932eb018ef301976c609b05bf62eb2486eb6826ddec7f8bbb394d6ff755a7,028af84779f096f95342f6f3605e440cb868f17fc95e4a45946d801279b48a3d1f,037626ada861e2889269fb3bf028b47066ecf89b92ddbac52d9bfc6ec0786cbbf0,0385af33d66981cabb6fc2167c57367791f6dae6e99c86daf101e0c9b3cb0e05d8,0201295b1c7a45e58c86bef979434660845b36e6111f16200690edab0315cc5cad,03e1eb17f416e858a178201dd1140bebb53b01bc9550f584b748c2850781e5a0f6,02ac3c4ba7acb5d4edbb514f0ddc8fc4c515855f00cccf06f07258d66bd79886ea,0255869a5609616f2718b5accdb136cc13968b2735b7ce4790db4a781fd62c82a3,0305f20642f237f2d466a2d10392962c14408141840d801ba0397613f51ca51f19,0383710a72e7f417ff730735ba336596b90ce775fb8aae794e70954c57c356b0df,026169fa51018edb044bede4f6a9eff9869db22e1a82bbaab31ac106f142f60ba0,02d82a04c69cba026357ca98f63c359152bbc63600905882ba0e25c77c358b27ee,03ead2c7859d6f2a3e4b2789e232a65cf0d8bb2c8eb2be23a1a6e00f33a0698ca0,0231fba8fe0c3bdf1a00513aa8ae667c0d4285e555e07c462bde1dbb4787462e83,02e88d3604a0bef3ffc4545cbe9d2ef6f0944adaaa93339aa118f2b2bf67d3d03c,03901937bb7dc19844eaf7dc57a5f35bb098f8871038b16e7972531e98713e0793))", "wsh(multi(20,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754,039bc932eb018ef301976c609b05bf62eb2486eb6826ddec7f8bbb394d6ff755a7,028af84779f096f95342f6f3605e440cb868f17fc95e4a45946d801279b48a3d1f,037626ada861e2889269fb3bf028b47066ecf89b92ddbac52d9bfc6ec0786cbbf0,0385af33d66981cabb6fc2167c57367791f6dae6e99c86daf101e0c9b3cb0e05d8,0201295b1c7a45e58c86bef979434660845b36e6111f16200690edab0315cc5cad,03e1eb17f416e858a178201dd1140bebb53b01bc9550f584b748c2850781e5a0f6,02ac3c4ba7acb5d4edbb514f0ddc8fc4c515855f00cccf06f07258d66bd79886ea,0255869a5609616f2718b5accdb136cc13968b2735b7ce4790db4a781fd62c82a3,0305f20642f237f2d466a2d10392962c14408141840d801ba0397613f51ca51f19,0383710a72e7f417ff730735ba336596b90ce775fb8aae794e70954c57c356b0df,026169fa51018edb044bede4f6a9eff9869db22e1a82bbaab31ac106f142f60ba0,02d82a04c69cba026357ca98f63c359152bbc63600905882ba0e25c77c358b27ee,03ead2c7859d6f2a3e4b2789e232a65cf0d8bb2c8eb2be23a1a6e00f33a0698ca0,0231fba8fe0c3bdf1a00513aa8ae667c0d4285e555e07c462bde1dbb4787462e83,02e88d3604a0bef3ffc4545cbe9d2ef6f0944adaaa93339aa118f2b2bf67d3d03c,03901937bb7dc19844eaf7dc57a5f35bb098f8871038b16e7972531e98713e0793))", SIGNABLE, {{"00203a31e9c37e8e54b5c64b4c8bdf8870ab61dd2fdf6591af15c607e7350dd0ab70"}}, OutputType::BECH32); // In P2WSH we can have up to 20 keys
    Check("sh(wsh(multi(20,U9YzFw3aHmb5NTbbd9iA5ekb68YLKLhiEC4mxXne17Z5KhFJFhgg,U9SmYY8oJWSjEYVkXEHHCFQ52YFrdFWBjcHMGReD7WhWm2EVQcBJ,UAXu6GBPnTzjBhVwy7LfaaCxxeCb4jhYkjYxHiDJ6FGXFWzYt5gq,U6XtjW6u5DTYXdSvXBAXncHc1rkGSVpjRSUM5AFVNQWXbND1i9pB,UAiS9tnptx194BNUBUz2iD93ZX48DGx9GJNekKDEazosgT7VRpGy,U9ynbLeFvzo6vwpoJMpcnCYiTA4yHgP2erCsfB3apbKgF8ngvQqk,U9xj7zavCQUVEePLwyiLWbYD37TyujvodLHoDMiBtzZSHpp26hdP,UA6Cm9xoUX5a81VsT2ixvvH4Qy1ZF7F7DqyPrz1AQoK5SwMVsw53,UCpbmwhiHgoLTv1D7Q9xunPenpqhSyr84B6uEUAWF3qPGasgMbB2,U717ZeD8tCrgdSwgULawYw82tLvwVAdv5sXmV5YoVqvZuDTfCehw,UAcWB7Kn7P5LpMaCxHnYSqwhEtZw3JoRqV9FLsvW6LjxF8xyENuw,UAxxKXwDaCyj57he5rRS1FcCwGqkKKNACXqSxCDrZ8oy1sW89sVA,U5tgY8DVvKBsfJT2fiFKC2rye9hxATirv6qtyawdw2tyo94RyY54,UBeH9oCyLUDafNbENwbMZnq5w3Teks5DxEgFgmhN2k4HC61cs8UF,U8e8JHiDVPz6XuoaqhDR5hxmC8Es7UeMc3kvRUXTXvHJRzMkZz8Z,UCSFsLeknWKjyrTXiFnGCHnUNemwgieuZQ4W2HxToqKfTvwFmTDX,U8tLyAiL6N6KBuJb1aJQkwKsNpkGrCTg8oNNhYZ81GzsTuLbKZqv,UARcoSRRYjJLWyhY9dc4fKTkyxBP29n2dA4RpjYzBu3KUCNA4FUV,UBWPychSSa1UfcuhbKK7QoEy7Z5fgoaDGXP7bwHL5G9iNN4ad15v,UCqAgZ6XSbANN3xzbnUMraFeqCzTKjBCL5jyN2ZH3NsLNFY7REDn)))","sh(wsh(multi(20,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754,039bc932eb018ef301976c609b05bf62eb2486eb6826ddec7f8bbb394d6ff755a7,028af84779f096f95342f6f3605e440cb868f17fc95e4a45946d801279b48a3d1f,037626ada861e2889269fb3bf028b47066ecf89b92ddbac52d9bfc6ec0786cbbf0,0385af33d66981cabb6fc2167c57367791f6dae6e99c86daf101e0c9b3cb0e05d8,0201295b1c7a45e58c86bef979434660845b36e6111f16200690edab0315cc5cad,03e1eb17f416e858a178201dd1140bebb53b01bc9550f584b748c2850781e5a0f6,02ac3c4ba7acb5d4edbb514f0ddc8fc4c515855f00cccf06f07258d66bd79886ea,0255869a5609616f2718b5accdb136cc13968b2735b7ce4790db4a781fd62c82a3,0305f20642f237f2d466a2d10392962c14408141840d801ba0397613f51ca51f19,0383710a72e7f417ff730735ba336596b90ce775fb8aae794e70954c57c356b0df,026169fa51018edb044bede4f6a9eff9869db22e1a82bbaab31ac106f142f60ba0,02d82a04c69cba026357ca98f63c359152bbc63600905882ba0e25c77c358b27ee,03ead2c7859d6f2a3e4b2789e232a65cf0d8bb2c8eb2be23a1a6e00f33a0698ca0,0231fba8fe0c3bdf1a00513aa8ae667c0d4285e555e07c462bde1dbb4787462e83,02e88d3604a0bef3ffc4545cbe9d2ef6f0944adaaa93339aa118f2b2bf67d3d03c,03901937bb7dc19844eaf7dc57a5f35bb098f8871038b16e7972531e98713e0793)))", "sh(wsh(multi(20,02726f085779989a221ffbc78306227b947c511612e255b2503a5e80be3408869f,0212a769c5fe819eaa989a5ef6558920afcd5e66f46e93810c029a80a4a0f00450,0360999742ab2e86216423359a2502c0833e0893d963f2a417cdc2bb9de0c97219,0225763db8c5ce6c22b7ca11ac4abc2c71c7dea504440cf07bcc22ed6682b15754,039bc932eb018ef301976c609b05bf62eb2486eb6826ddec7f8bbb394d6ff755a7,028af84779f096f95342f6f3605e440cb868f17fc95e4a45946d801279b48a3d1f,037626ada861e2889269fb3bf028b47066ecf89b92ddbac52d9bfc6ec0786cbbf0,0385af33d66981cabb6fc2167c57367791f6dae6e99c86daf101e0c9b3cb0e05d8,0201295b1c7a45e58c86bef979434660845b36e6111f16200690edab0315cc5cad,03e1eb17f416e858a178201dd1140bebb53b01bc9550f584b748c2850781e5a0f6,02ac3c4ba7acb5d4edbb514f0ddc8fc4c515855f00cccf06f07258d66bd79886ea,0255869a5609616f2718b5accdb136cc13968b2735b7ce4790db4a781fd62c82a3,0305f20642f237f2d466a2d10392962c14408141840d801ba0397613f51ca51f19,0383710a72e7f417ff730735ba336596b90ce775fb8aae794e70954c57c356b0df,026169fa51018edb044bede4f6a9eff9869db22e1a82bbaab31ac106f142f60ba0,02d82a04c69cba026357ca98f63c359152bbc63600905882ba0e25c77c358b27ee,03ead2c7859d6f2a3e4b2789e232a65cf0d8bb2c8eb2be23a1a6e00f33a0698ca0,0231fba8fe0c3bdf1a00513aa8ae667c0d4285e555e07c462bde1dbb4787462e83,02e88d3604a0bef3ffc4545cbe9d2ef6f0944adaaa93339aa118f2b2bf67d3d03c,03901937bb7dc19844eaf7dc57a5f35bb098f8871038b16e7972531e98713e0793)))", SIGNABLE, {{"a9147fc062ffd996b90d61e208a25aab0bde0931c96187"}}, OutputType::P2SH_SEGWIT); // Even if it's wrapped into P2SH
    // Check for invalid nesting of structures
    CheckUnparsable("sh(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "sh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "A function is needed within P2SH"); // P2SH needs a script, not a key
    CheckUnparsable("sh(combo(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))", "sh(combo(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", "Can only have combo() at top level"); // Old must be top level
    CheckUnparsable("wsh(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)", "wsh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)", "A function is needed within P2WSH"); // P2WSH needs a script, not a key
    CheckUnparsable("wsh(wpkh(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt))", "wsh(wpkh(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308))", "Can only have wpkh() at top level or inside sh()"); // Cannot embed witness inside witness
    CheckUnparsable("wsh(sh(pk(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)))", "wsh(sh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)))", "Can only have sh() at top level"); // Cannot embed P2SH inside P2WSH
    CheckUnparsable("sh(sh(pk(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)))", "sh(sh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)))", "Can only have sh() at top level"); // Cannot embed P2SH inside P2SH
    CheckUnparsable("wsh(wsh(pk(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)))", "wsh(wsh(pk(024f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)))", "Can only have wsh() at top level or inside sh()"); // Cannot embed P2WSH inside P2WSH

    // Checksums
    Check("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t", DEFAULT, {{"a91445a9a622a8b0a1269944be477640eedc447bbd8487"}}, OutputType::LEGACY, {{0x8000006FUL,222},{0}});
    Check("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))", DEFAULT, {{"a91445a9a622a8b0a1269944be477640eedc447bbd8487"}}, OutputType::LEGACY, {{0x8000006FUL,222},{0}});
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#", "Expected 8 character checksum, not 0 characters"); // Empty checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfyq", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5tq", "Expected 8 character checksum, not 9 characters"); // Too long checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxf", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5", "Expected 8 character checksum, not 7 characters"); // Too short checksum
    CheckUnparsable("sh(multi(3,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy", "sh(multi(3,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjg09x5t", "Provided checksum 'tjg09x5t' does not match computed checksum 'd4x0uxyv'"); // Error in payload
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggssrxfy", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))#tjq09x4t", "Provided checksum 'tjq09x4t' does not match computed checksum 'tjg09x5t'"); // Error in checksum
    CheckUnparsable("sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))##ggssrxfy", "sh(multi(2,[00000000/111'/222]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0))##tjq09x4t", "Multiple '#' symbols"); // Error in checksum

    // Addr and raw tests
    CheckUnparsable("", "addr(asdf)", "Address is not valid"); // Invalid address
    CheckUnparsable("", "raw(asdf)", "Raw script is not hex"); // Invalid script
    CheckUnparsable("", "raw(Ü)#00000000", "Invalid characters in payload"); // Invalid chars

    Check(
        "rawtr(xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/86'/1'/0'/1/*)#a5gn3t7k",
        "rawtr(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/86'/1'/0'/1/*)#4ur3xhft",
        "rawtr([5a61ff8e/86'/1'/0']xpub6DtZpc9PRL2B6pwoNGysmHAaBofDmWv5S6KQEKKGPKhf5fV62ywDtSziSApYVK3JnYY5KUSgiCwiXW5wtd8z7LNBxT9Mu5sEro8itdGfTeA/1/*)#llheyd9x",
        RANGE | HARDENED | XONLY_KEYS,
        {{"51205172af752f057d543ce8e4a6f8dcf15548ec6be44041bfa93b72e191cfc8c1ee"}, {"51201b66f20b86f700c945ecb9ad9b0ad1662b73084e2bfea48bee02126350b8a5b1"}, {"512063e70f66d815218abcc2306aa930aaca07c5cde73b75127eb27b5e8c16b58a25"}},
        OutputType::BECH32M,
        {{0x80000056, 0x80000001, 0x80000000, 1, 0}, {0x80000056, 0x80000001, 0x80000000, 1, 1}, {0x80000056, 0x80000001, 0x80000000, 1, 2}});


    Check(
        "rawtr(U6SgXHtaZxiGR6jXnYmxQbr9N7n8C753wU338u2xAWVwQRSCRQAt)",
        "rawtr(4f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)",
        "rawtr(4f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308)",
        SIGNABLE | XONLY_KEYS,
        {{"51204f1104abfffa3490f2fec7ea6c62a65f35c5e626c79a09ae28495668a8fc7308"}},
        OutputType::BECH32M);

    CheckUnparsable(
        "",
        "rawtr(xpub68FQ9imX6mCWacw6eNRjaa8q8ynnHmUd5i7MVR51ZMPP5JycyfVHSLQVFPHMYiTybWJnSBL2tCBpy6aJTR2DYrshWYfwAxs8SosGXd66d8/*, xpub69Mvq3QMipdvnd9hAyeTnT5jrkcBuLErV212nsGf3qr7JPWysc9HnNhCsazdzj1etSx28hPSE8D7DnceFbNdw4Kg8SyRfjE2HFLv1P8TSGc/*)",
        "rawtr(): only one key expected.");

    // A 2of4 but using a direct push rather than OP_2
    CScript nonminimalmultisig;
    CKey keys[4];
    nonminimalmultisig << std::vector<unsigned char>{2};
    for (int i = 0; i < 4; i++) {
        keys[i].MakeNewKey(true);
        nonminimalmultisig << ToByteVector(keys[i].GetPubKey());
    }
    nonminimalmultisig << 4 << OP_CHECKMULTISIG;
    CheckInferRaw(nonminimalmultisig);

    // A 2of4 but using a direct push rather than OP_4
    nonminimalmultisig.clear();
    nonminimalmultisig << 2;
    for (int i = 0; i < 4; i++) {
        keys[i].MakeNewKey(true);
        nonminimalmultisig << ToByteVector(keys[i].GetPubKey());
    }
    nonminimalmultisig << std::vector<unsigned char>{4} << OP_CHECKMULTISIG;
    CheckInferRaw(nonminimalmultisig);

    // Miniscript tests

    // Invalid checksum
    CheckUnparsable("wsh(and_v(vc:andor(pk(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))#abcdef12", "wsh(and_v(vc:andor(pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))#abcdef12", "Provided checksum 'abcdef12' does not match computed checksum 'hj69xv3e'");
    // Only p2wsh context is valid
    CheckUnparsable("sh(and_v(vc:andor(pk(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))", "sh(and_v(vc:andor(pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "Miniscript expressions can only be used in wsh");
    CheckUnparsable("tr(and_v(vc:andor(pk(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))", "tr(and_v(vc:andor(pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "tr(): key 'and_v(vc:andor(pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10))' is not valid");
    CheckUnparsable("raw(and_v(vc:andor(pk(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))", "sh(and_v(vc:andor(pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "Miniscript expressions can only be used in wsh");
    CheckUnparsable("", "tr(034D2224bbbbbbbbbbcbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb40,{{{{{{{{{{{{{{{{{{{{{{multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/967808'/9,xprvA1RpRA33e1JQ7ifknakTFNpgXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/968/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/3/4/5/58/55/2/5/58/58/2/5/5/5/8/5/2/8/5/85/2/8/2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/8/5/8/5/4/5/585/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/8/2/5/8/5/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/58/58/2/0/8/5/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/5/8/5/8/24/5/58/52/5/8/5/2/8/24/5/58/588/246/8/5/2/8/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/5/4/5/58/55/58/2/5/8/55/2/5/8/58/555/58/2/5/8/4//2/5/58/5w/2/5/8/5/2/4/5/58/5558'/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/8/2/5/8/5/5/8/58/2/5/58/58/2/5/8/9/588/2/58/2/5/8/5/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/82/5/8/5/5/58/52/6/8/5/2/8/{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{}{{{{{{{{{DDD2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8588/246/8/5/2DLDDDDDDDbbD3DDDD/8/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/3/4/5/58/55/2/5/58/58/2/5/5/5/8/5/2/8/5/85/2/8/2/5/8D)/5/2/5/58/58/2/5/58/58/58/588/2/58/2/5/8/5/25/58/58/2/5/58/58/2/5/8/9/588/2/58/2/6780,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFW/8/5/2/5/58678008')", "'multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/967808'/9,xprvA1RpRA33e1JQ7ifknakTFNpgXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/968/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/3/4/5/58/55/2/5/58/58/2/5/5/5/8/5/2/8/5/85/2/8/2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/8/5/8/5/4/5/585/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/8/2/5/8/5/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/58/58/2/0/8/5/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/5/8/5/8/24/5/58/52/5/8/5/2/8/24/5/58/588/246/8/5/2/8/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/5/4/5/58/55/58/2/5/8/55/2/5/8/58/555/58/2/5/8/4//2/5/58/5w/2/5/8/5/2/4/5/58/5558'/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/8/2/5/8/5/5/8/58/2/5/58/58/2/5/8/9/588/2/58/2/5/8/5/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8/5/2/5/58/58/2/5/5/58/588/2/58/2/5/8/5/2/82/5/8/5/5/58/52/6/8/5/2/8/{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{}{{{{{{{{{DDD2/5/8/5/2/5/58/58/2/5/58/58/588/2/58/2/8/5/8/5/4/5/58/588/2/6/8/5/2/8/2/5/8588/246/8/5/2DLDDDDDDDbbD3DDDD/8/2/5/8/5/2/5/58/58/2/5/5/5/58/588/2/6/8/5/2/8/2/5/8/2/58/2/5/8/5/2/8/5/8/3/4/5/58/55/2/5/58/58/2/5/5/5/8/5/2/8/5/85/2/8/2/5/8D)/5/2/5/58/58/2/5/58/58/58/588/2/58/2/5/8/5/25/58/58/2/5/58/58/2/5/8/9/588/2/58/2/6780,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFW/8/5/2/5/58678008'' is not a valid descriptor function");
    // Insane at top level
    CheckUnparsable("wsh(and_b(vc:andor(pk(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))", "wsh(and_b(vc:andor(pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "and_b(vc:andor(pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)) is invalid");
    // Invalid sub
    CheckUnparsable("wsh(and_v(vc:andor(v:pk_k(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))", "wsh(and_v(vc:andor(v:pk_k(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "v:pk_k(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684) is invalid");
    // Insane subs
    CheckUnparsable("wsh(or_i(older(1),pk(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP)))", "wsh(or_i(older(1),pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684)))", "or_i(older(1),pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684)) is not sane: witnesses without signature exist");
    CheckUnparsable("wsh(or_b(sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684)))", "wsh(or_b(sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684)))", "or_b(sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684)) is not sane: malleable witnesses exist");
    CheckUnparsable("wsh(and_b(and_b(older(1),a:older(100000000)),s:pk(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP)))", "wsh(and_b(and_b(older(1),a:older(100000000)),s:pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684)))", "and_b(older(1),a:older(100000000)) is not sane: contains mixes of timelocks expressed in blocks and seconds");
    CheckUnparsable("wsh(and_b(or_b(pkh(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP),s:pk(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn)),s:pk(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP)))", "wsh(and_b(or_b(pkh(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),s:pk(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0)),s:pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684)))", "and_b(or_b(pkh(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),s:pk(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0)),s:pk(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684)) is not sane: contains duplicate public keys");
    // Valid with extended keys.
    Check("wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0)))", "wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)))", "wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)))", DEFAULT, {{"0020acf425291b98a1d7e0d4690139442abc289175be32ef1f75945e339924246d73"}}, OutputType::BECH32, {{},{0}});
    // Valid under sh(wsh()) and with a mix of xpubs and raw keys.
    Check("sh(wsh(thresh(1,pkh(U6u12Bc9r2xGVWxmrfzAerijhmuVbdXexVQMnyFdN3nTBPTAD5UP),a:and_n(multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0),n:older(2)))))", "sh(wsh(thresh(1,pkh(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))", "sh(wsh(thresh(1,pkh(0375bdf05ad80cb5f2e8f4a5913634577563d2ba23db256f12b737393348cc0684),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))", SIGNABLE | MIXED_PUBKEYS, {{"a914006e643dcef9cb9706cff532d17b058d8ca96f6c87"}}, OutputType::P2SH_SEGWIT, {{},{0}});
    // An exotic multisig, we can sign for both branches
    Check("wsh(thresh(1,pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc),a:pkh(xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0)))", "wsh(thresh(1,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),a:pkh(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)))", "wsh(thresh(1,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),a:pkh(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)))", SIGNABLE, {{"00204a4528fbc0947e02e921b54bd476fc8cc2ebb5c6ae2ccf10ed29fe2937fb6892"}}, OutputType::BECH32, {{},{0}});
    // We can sign for a script requiring the two kinds of timelock.
    // But if we don't set a sequence high enough, we'll fail.
    Check("sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))", SIGNABLE_FAILS, {{"a914099f400961f930d4c16c3b33c0e2a58ef53ac38f87"}}, OutputType::P2SH_SEGWIT, {{},{0}}, /*spender_nlocktime=*/1000, /*spender_nsequence=*/1);
    // And same for the nLockTime.
    Check("sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))", SIGNABLE_FAILS, {{"a914099f400961f930d4c16c3b33c0e2a58ef53ac38f87"}}, OutputType::P2SH_SEGWIT, {{},{0}}, /*spender_nlocktime=*/999, /*spender_nsequence=*/2);
    // But if both are set to (at least) the required value, we'll succeed.
    Check("sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))", "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))", SIGNABLE, {{"a914099f400961f930d4c16c3b33c0e2a58ef53ac38f87"}}, OutputType::P2SH_SEGWIT, {{},{0}}, /*spender_nlocktime=*/1000, /*spender_nsequence=*/2);
    // We can't sign for a script requiring a ripemd160 preimage without providing it.
    Check("wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))", "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", SIGNABLE_FAILS, {{"002001549deda34cbc4a5982263191380f522695a2ddc2f99fc3a65c736264bd6cab"}}, OutputType::BECH32, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {});
    // But if we provide it, we can.
    Check("wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))", "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", SIGNABLE, {{"002001549deda34cbc4a5982263191380f522695a2ddc2f99fc3a65c736264bd6cab"}}, OutputType::BECH32, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {{ParseHex("ff9aa1829c90d26e73301383f549e1497b7d6325"), ParseHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")}});
    // Same for sha256
    Check("wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))", "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", SIGNABLE_FAILS, {{"002071f7283dbbb9a55ed43a54cda16ba0efd0f16dc48fe200f299e57bb5d7be8dd4"}}, OutputType::BECH32, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {});
    Check("wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))", "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", SIGNABLE, {{"002071f7283dbbb9a55ed43a54cda16ba0efd0f16dc48fe200f299e57bb5d7be8dd4"}}, OutputType::BECH32, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {{ParseHex("7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863"), ParseHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")}});
    // Same for hash160
    Check("wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))", "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", SIGNABLE_FAILS, {{"00209b9d5b45735d0e15df5b41d6594602d3de472262f7b75edc6cf5f3e3fa4e3ae4"}}, OutputType::BECH32, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {});
    Check("wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))", "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", SIGNABLE, {{"00209b9d5b45735d0e15df5b41d6594602d3de472262f7b75edc6cf5f3e3fa4e3ae4"}}, OutputType::BECH32, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {{ParseHex("292e2df59e3a22109200beed0cdc84b12e66793e"), ParseHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")}});
    // Same for hash256
    Check("wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))", "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", SIGNABLE_FAILS, {{"0020cf62bf97baf977aec69cbc290c372899f913337a9093e8f066ab59b8657a365c"}}, OutputType::BECH32, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {});
    Check("wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))", "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))", SIGNABLE, {{"0020cf62bf97baf977aec69cbc290c372899f913337a9093e8f066ab59b8657a365c"}}, OutputType::BECH32, {{}}, /*spender_nlocktime=*/0, /*spender_nsequence=*/CTxIn::SEQUENCE_FINAL, {{ParseHex("ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588"), ParseHex("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")}});
}

BOOST_AUTO_TEST_SUITE_END()
