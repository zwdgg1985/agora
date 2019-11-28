/*******************************************************************************

    These tests are inspired by SCP's QuorumSetTests, which test various
    quorum configurations.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.QuorumSetTests;

import agora.common.crypto.Key;
import agora.common.Hash;
import agora.common.Serializer;
import agora.utils.Log;

import scpd.Cpp;
import scpd.scp.LocalNode;
import scpd.scp.NominationProtocol;
import scpd.scp.QuorumSetUtils;
import scpd.scp.SCPDriver;
import scpd.scp.SCP;
import scpd.scp.Slot;
import scpd.scp.Utils;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types;
import scpd.types.Stellar_types : StellarHash = Hash, StellarKey = NodeID;
import scpd.types.Utils;

import std.algorithm;
import std.conv;
import std.digest.sha;
import std.format;
import std.math;
import std.stdio;

import core.stdc.stdint;

alias Hash = agora.common.Hash.Hash;

mixin AddLogger!();

//TEST_CASE("sane quorum set", "[scp][quorumset]")
unittest
{
    auto makeSingleton = (ref StellarKey key) {
        SCPQuorumSet result;
        result.threshold = 1;
        result.validators.push_back(key);
        return result;
    };

    StellarKey[] keys;
    foreach (_; 0 .. 1001)
        keys ~= StellarKey(StellarHash(KeyPair.random().address[]));

    sort!((a, b) => PublicKey(a.ed25519_[]).toString() < PublicKey(b.ed25519_[]).toString())(keys);

    void printQuorumSet ( SCPQuorumSet set )
    {
        writef("threshold: %s ", set.threshold);
        write("validators: [");
        foreach (validator; set.validators)
            writef("%s ", PublicKey(validator.ed25519_[]));
        write("]");

        write(" innerSets: [");
        foreach (subset; set.innerSets)
        {
            printQuorumSet(subset);
        }

        write("] ");
    }

    void check (bool print = false) (ref SCPQuorumSet qSetCheck, bool expected,
                  ref SCPQuorumSet expectedSelfQSet,
                  size_t line = __LINE__)
    {
        try
        {
            if (print)
            {
                printQuorumSet(qSetCheck);
            }
            // first, without normalization
            assert(expected == isQuorumSetSane(qSetCheck, false));

            // secondary test: attempts to build local node with the set
            // (this normalizes the set)
            SCPQuorumSet normalizedQSet = qSetCheck;
            normalizeQSet(normalizedQSet);
            auto selfIsSane = isQuorumSetSane(qSetCheck, false);

            assert(expected == selfIsSane);
            assert(expectedSelfQSet == normalizedQSet);
        }
        catch (Error error)
        {
            error.msg ~= " from line: %s".format(line);
            throw error;
        }
    }

    //SECTION("{ t: 0 }")
    {
        SCPQuorumSet qSet = SCPQuorumSet.init;
        qSet.threshold = 0;
        check(qSet, false, qSet);
    }

    auto validOneNode = makeSingleton(keys[0]);

    //SECTION("{ t: 0, v0 }")
    {
        auto qSet = validOneNode;
        qSet.threshold = 0;
        check(qSet, false, qSet);
    }

    //SECTION("{ t: 2, v0 }")
    {
        auto qSet = validOneNode;
        qSet.threshold = 2;
        check(qSet, false, qSet);
    }

    //SECTION("{ t: 1, v0 }")
    {
        check(validOneNode, true, validOneNode);
    }

    //SECTION("{ t: 1, v0, { t: 1, v1 } -> { t:1, v0, v1 }")
    {
        SCPQuorumSet qSet = SCPQuorumSet.init;
        qSet.threshold = 1;
        qSet.validators.push_back(keys[0]);

        auto qSelfSet = qSet;
        qSelfSet.validators.push_back(keys[1]);

        auto def = SCPQuorumSet.init;
        qSet.innerSets.push_back(def);
        qSet.innerSets[$ - 1].threshold = 1;
        qSet.innerSets[$ - 1].validators.push_back(keys[1]);

        check(qSet, true, qSelfSet);
    }

    //SECTION("{ t: 1, v0, { t: 1, v1 }, { t: 2, v2 } } -> { t:1, v0, v1, { t: 2, v2 } }")
    {
        SCPQuorumSet qSet = SCPQuorumSet.init;
        qSet.threshold = 1;
        qSet.validators.push_back(keys[0]);

        auto def1 = SCPQuorumSet.init;
        qSet.innerSets.push_back(def1);
        qSet.innerSets[$ - 1].threshold = 2;
        qSet.innerSets[$ - 1].validators.push_back(keys[1]);

        auto qSelfSet = qSet;
        qSelfSet.validators.push_back(keys[2]);

        auto def2 = SCPQuorumSet.init;
        qSet.innerSets.push_back(def2);
        qSet.innerSets[$ - 1].threshold = 1;
        qSet.innerSets[$ - 1].validators.push_back(keys[2]);

        check(qSet, false, qSelfSet);
    }

    SCPQuorumSet validMultipleNodes = SCPQuorumSet.init;
    validMultipleNodes.threshold = 1;
    validMultipleNodes.validators.push_back(keys[0]);

    auto def1 = SCPQuorumSet.init;
    validMultipleNodes.innerSets.push_back(def1);
    validMultipleNodes.innerSets[$ - 1].threshold = 1;
    validMultipleNodes.innerSets[$ - 1].validators.push_back(keys[1]);

    auto def2 = SCPQuorumSet.init;
    validMultipleNodes.innerSets.push_back(def2);
    validMultipleNodes.innerSets[$ - 1].threshold = 1;
    validMultipleNodes.innerSets[$ - 1].validators.push_back(keys[2]);
    validMultipleNodes.innerSets[$ - 1].validators.push_back(keys[3]);

    SCPQuorumSet validMultipleNodesNormalized = SCPQuorumSet.init;
    validMultipleNodesNormalized.threshold = 1;
    validMultipleNodesNormalized.validators.push_back(keys[0]);
    validMultipleNodesNormalized.validators.push_back(keys[1]);

    auto def3 = SCPQuorumSet.init;
    validMultipleNodesNormalized.innerSets.push_back(def3);
    validMultipleNodesNormalized.innerSets[$ - 1].threshold = 1;
    validMultipleNodesNormalized.innerSets[$ - 1].validators.push_back(keys[2]);
    validMultipleNodesNormalized.innerSets[$ - 1].validators.push_back(keys[3]);

    //SECTION("{ t: 1, v0, { t: 1, v1 }, { t: 1, v2, v3 } } -> { t:1, v0, v1, { t: 1, v2, v3 } }")
    {
        check(validMultipleNodes, true, validMultipleNodesNormalized);
    }

    //SECTION("{ t: 1, { t: 1, v0, { t: 1, v1 }, { t: 1, v2, v3 } } } -> { t:1, v0, v1, { t: 1, v2, v3 } }")
    {
        SCPQuorumSet containingSet = SCPQuorumSet.init;
        containingSet.threshold = 1;
        containingSet.innerSets.push_back(validMultipleNodes);

        check(containingSet, true, validMultipleNodesNormalized);
    }

    //SECTION("{ t: 1, v0, { t: 1, v1, { t: 1, v2 } } } -> { t: 1, v0, { t: 1, v1, v2 } }")
    {
        auto qSet = makeSingleton(keys[0]);
        auto qSet1 = makeSingleton(keys[1]);
        auto qSet2 = makeSingleton(keys[2]);
        qSet1.innerSets.push_back(qSet2);
        qSet.innerSets.push_back(qSet1);

        auto qSelfSet = SCPQuorumSet.init;
        qSelfSet.threshold = 1;
        qSelfSet.validators.push_back(keys[0]);
        auto def4 = SCPQuorumSet.init;
        qSelfSet.innerSets.push_back(def4);
        qSelfSet.innerSets[$ - 1].threshold = 1;
        qSelfSet.innerSets[$ - 1].validators.push_back(keys[1]);
        qSelfSet.innerSets[$ - 1].validators.push_back(keys[2]);

        check(qSet, true, qSelfSet);
    }

    //SECTION("{ t: 1, v0, { t: 1, v1, { t: 1, v2, { t: 1, v3 } } } } -> too deep")
    {
        auto qSet = makeSingleton(keys[0]);
        auto qSet1 = makeSingleton(keys[1]);
        auto qSet2 = makeSingleton(keys[2]);
        auto qSet3 = makeSingleton(keys[3]);
        qSet2.innerSets.push_back(qSet3);
        qSet1.innerSets.push_back(qSet2);
        qSet.innerSets.push_back(qSet1);

        auto qSelfSet = SCPQuorumSet.init;
        qSelfSet.threshold = 1;
        qSelfSet.validators.push_back(keys[0]);
        auto def4 = SCPQuorumSet.init;
        qSelfSet.innerSets.push_back(def4);
        qSelfSet.innerSets[$ - 1].threshold = 1;
        qSelfSet.innerSets[$ - 1].validators.push_back(keys[1]);
        auto def5 = SCPQuorumSet.init;
        qSelfSet.innerSets[$ - 1].innerSets.push_back(def5);
        qSelfSet.innerSets[$ - 1].innerSets[$ - 1].threshold = 1;
        qSelfSet.innerSets[$ - 1].innerSets[$ - 1].validators.push_back(
            keys[2]);
        qSelfSet.innerSets[$ - 1].innerSets[$ - 1].validators.push_back(
            keys[3]);

        check(qSet, false, qSelfSet);
    }

    //SECTION("{ t: 1, v0..v999 } -> { t: 1, v0..v999 }")
    {
        SCPQuorumSet qSet = SCPQuorumSet.init;
        qSet.threshold = 1;
        for (auto i = 0; i < 1000; i++)
            qSet.validators.push_back(keys[i]);

        check(qSet, true, qSet);
    }

    //SECTION("{ t: 1, v0..v1000 } -> too big")
    {
        SCPQuorumSet qSet = SCPQuorumSet.init;
        qSet.threshold = 1;
        for (auto i = 0; i < 1001; i++)
            qSet.validators.push_back(keys[i]);

        check(qSet, false, qSet);
    }

    //SECTION("{ t: 1, v0, { t: 1, v1..v100 }, { t: 1, v101..v200} ... { t: 1, v901..v1000} -> too big")
    {
        SCPQuorumSet qSet = SCPQuorumSet.init;
        qSet.threshold = 1;
        qSet.validators.push_back(keys[0]);
        for (auto i = 0; i < 10; i++)
        {
            auto def = SCPQuorumSet.init;
            qSet.innerSets.push_back(def);
            qSet.innerSets[$ - 1].threshold = 1;
            for (auto j = i * 100 + 1; j <= (i + 1) * 100; j++)
                qSet.innerSets[$ - 1].validators.push_back(keys[j]);
        }

        check(qSet, false, qSet);
    }
}
