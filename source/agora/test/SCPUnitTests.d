/*******************************************************************************

    These tests are inspired by SCP's UnitTests, which test the basic
    functionality of the SCP protocol. They were adapted to D to ensure we
    have the same exact behavior in our wrapper classes.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.SCPUnitTests;

import agora.common.crypto.Key;
import agora.common.Hash;
import agora.common.Serializer;
import agora.utils.Log;

import scpd.Cpp;
import scpd.scp.LocalNode;
import scpd.scp.NominationProtocol;
import scpd.scp.SCPDriver;
import scpd.scp.SCP;
import scpd.scp.Slot;
import scpd.scp.Utils;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types;
import scpd.types.Stellar_types : StellarHash = Hash, StellarKey = NodeID;
import scpd.types.Utils;

import std.algorithm;
import std.digest.sha;
import std.format;
import std.math;
import std.stdio;

import core.stdc.stdint;

alias Hash = agora.common.Hash.Hash;

mixin AddLogger!();

bool isNear (uint64_t r, double target)
{
    double v = cast(double)r / cast(double)ulong.max;
    return abs(v - target) < .01;
}

mixin template SIMULATION_CREATE_NODE (size_t N)
{
    // note: these should be const
    mixin(format(`KeyPair v%skp = KeyPair.random();`, N));
    mixin(format(`SecretKey v%sSecretKey = v%skp.secret;`, N, N));
    mixin(format(`StellarKey v%sNodeID = StellarKey(StellarHash(v%skp.address[]));`, N, N));
}

public extern (C++) class TestNominationSCP : SCPDriver
{
    public SCPQuorumSetPtr[StellarHash] mQuorumSets;
    public SCP* mSCP;

    public this (ref const(NodeID) nodeID, ref const(SCPQuorumSet) qSetLocal)
    {
        mSCP = createSCP(this, nodeID, true, qSetLocal);
        auto localQSet = makeSharedSCPQuorumSet(mSCP.getLocalQuorumSet());
        this.storeQuorumSet(localQSet);
    }

    public override void signEnvelope (ref SCPEnvelope)
    {
    }

    public override ValidationLevel validateValue (uint64_t slot_idx,
        ref const(Value) value, bool nomination) nothrow
    {
        return ValidationLevel.kFullyValidatedValue;
    }

    public override SCPQuorumSetPtr getQSet (ref const(StellarHash) qSetHash)
    {
        if (auto val = qSetHash in this.mQuorumSets)
            return *val;

        return SCPQuorumSetPtr();
    }

    public override void emitEnvelope (ref const(SCPEnvelope) envelope)
    {
    }

    public override Value combineCandidates (uint64_t slot_idx,
        ref const(set!Value) candidates)
    {
        return Value.init;
    }

    public override void setupTimer (ulong slotIndex, int timerID,
                             milliseconds timeout,
                             CPPDelegate!(void function())*)
    {

    }

    public ref const(Value) getLatestCompositeCandidate (uint64_t slotIndex)
    {
        static const(Value) emptyValue;
        return emptyValue;
    }

    private void storeQuorumSet (SCPQuorumSetPtr qSet)
    {
        const bytes = ByteSlice.make(XDRToOpaque(*qSet));
        auto quorum_hash = sha256(bytes);
        this.mQuorumSets[quorum_hash] = qSet;
    }
}

// note: stellar used inheritance for this (but it was actually compositing),
// there are no virtual methods
struct NominationTestHandler
{
    NominationProtocol proto;
    alias proto this;

    public this (ref Slot s)
    {
        this.proto = NominationProtocol(s);
    }

    public void setPreviousValue (ref Value v)
    {
        mPreviousValue = v;
    }

    public void setRoundNumber (int n)
    {
        mRoundNumber = n;
    }

    public void updateRoundLeaders ()
    {
        this.proto.updateRoundLeaders();
    }

    public ref set!NodeID getRoundLeaders ()
    {
        return mRoundLeaders;
    }

    public uint64_t getNodePriority (ref const(NodeID) nodeID,
        ref const(SCPQuorumSet) qset)
    {
        return this.proto.getNodePriority(nodeID, qset);
    }
}

static SCPQuorumSet makeQSet (ref const(vector!NodeID) nodeIDs, int threshold,
    int total, int offset)
{
    SCPQuorumSet qSet;
    qSet.threshold = threshold;
    for (int i = 0; i < total; i++)
        qSet.validators.push_back(nodeIDs[i + offset]);

    return qSet;
}

Value toValue (T)(T value)
{
    static struct S
    {
        T value;
    }

    return Value(serializeFull(S(value)).toVec());
}

//TEST_CASE("nomination weight", "[scp]")
unittest
{
    mixin SIMULATION_CREATE_NODE!0;
    mixin SIMULATION_CREATE_NODE!1;
    mixin SIMULATION_CREATE_NODE!2;
    mixin SIMULATION_CREATE_NODE!3;
    mixin SIMULATION_CREATE_NODE!4;
    mixin SIMULATION_CREATE_NODE!5;

    SCPQuorumSet qSet;
    qSet.threshold = 3;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);

    uint64_t result = LocalNode.getNodeWeight(v2NodeID, qSet);

    assert(isNear(result, .75));

    result = LocalNode.getNodeWeight(v4NodeID, qSet);
    assert(result == 0);

    SCPQuorumSet iQSet;
    iQSet.threshold = 1;
    iQSet.validators.push_back(v4NodeID);
    iQSet.validators.push_back(v5NodeID);
    qSet.innerSets.push_back(iQSet);

    result = LocalNode.getNodeWeight(v4NodeID, qSet);

    assert(isNear(result, .6 * .5));
}

// this test case display statistical information on the priority function used
// by nomination
//TEST_CASE("nomination weight stats", "[scp][!hide]")
unittest
{
    mixin SIMULATION_CREATE_NODE!0;
    mixin SIMULATION_CREATE_NODE!1;
    mixin SIMULATION_CREATE_NODE!2;
    mixin SIMULATION_CREATE_NODE!3;
    mixin SIMULATION_CREATE_NODE!4;
    mixin SIMULATION_CREATE_NODE!5;
    mixin SIMULATION_CREATE_NODE!6;

    vector!NodeID nodeIDs;
    foreach (node; [v0NodeID, v1NodeID, v2NodeID, v3NodeID, v4NodeID, v5NodeID, v6NodeID])
        nodeIDs.push_back(node);

    const int totalSlots = 1000;
    const int maxRoundPerSlot = 5; // 5 -> 15 seconds
    const int totalRounds = totalSlots * maxRoundPerSlot;

    auto runTests = (SCPQuorumSet qSet) {
        int[NodeID] wins;

        TestNominationSCP nomSCP = new TestNominationSCP(v0NodeID, qSet);
        for (int s = 0; s < totalSlots; s++)
        {
            Slot slot = Slot(s, *nomSCP.mSCP);

            NominationTestHandler nom = NominationTestHandler(slot);

            Value v = s.toValue();

            nom.setPreviousValue(v);

            for (int i = 0; i < maxRoundPerSlot; i++)
            {
                nom.setRoundNumber(i);
                nom.updateRoundLeaders();
                set!NodeID* l = &nom.getRoundLeaders();
                assert(!l.empty());
                foreach (ref w; *l)
                    wins[w]++;
            }
        }
        return wins;
    };

    //SECTION("flat quorum")
    {
        auto flatTest = (int threshold, int total)
        {
            auto qSet = makeQSet(nodeIDs, threshold, total, 0);

            auto wins = runTests(qSet);

            foreach (key, value; wins)
            {
                double stats = double(value * 100) / double(totalRounds);
                log.info("Got {} {}", stats, (v0NodeID == key) ? " LOCAL" : "");
            }
        };

        //SECTION("3 out of 5")
        {
            flatTest(3, 5);
        }
        //SECTION("2 out of 3")
        {
            flatTest(2, 3);
        }
    }

    //SECTION("hierarchy")
    {
        auto qSet = makeQSet(nodeIDs, 3, 4, 0);

        auto qSetInner = makeQSet(nodeIDs, 2, 3, 4);
        qSet.innerSets.push_back(qSetInner);

        auto wins = runTests(qSet);

        foreach (key, value; wins)
        {
            double stats = double(value * 100) / double(totalRounds);

            bool outer;
            foreach (val; qSet.validators)
            {
                if (val == key)
                {
                    outer = true;
                    break;
                }
            }

            log.info("Got {} {}", stats,
                (v0NodeID == key)
                    ? "LOCAL"
                    : (outer ? "OUTER" : "INNER"));
        }
    }
}

//TEST_CASE("nomination two nodes win stats", "[scp][!hide]")
unittest
{
    // todo note: this was 9, but it's unnecessary as it slows down test-suite
    const int nbRoundsForStats = 1;

    mixin SIMULATION_CREATE_NODE!0;
    mixin SIMULATION_CREATE_NODE!1;
    mixin SIMULATION_CREATE_NODE!2;
    mixin SIMULATION_CREATE_NODE!3;
    mixin SIMULATION_CREATE_NODE!4;
    mixin SIMULATION_CREATE_NODE!5;
    mixin SIMULATION_CREATE_NODE!6;

    vector!NodeID nodeIDs;
    foreach (node; [v0NodeID, v1NodeID, v2NodeID, v3NodeID, v4NodeID, v5NodeID, v6NodeID])
        nodeIDs.push_back(node);

    const int totalIter = 10000;

    // maxRounds is the number of rounds to evaluate in a row
    // the iteration is considered successful if validators could
    // agree on what to nominate before maxRounds is reached
    auto nominationLeaders = (int maxRounds, SCPQuorumSet qSetNode0,
                                 SCPQuorumSet qSetNode1) {
        auto nomSCP0 = new TestNominationSCP(v0NodeID, qSetNode0);
        Slot slot0 = Slot(0, *nomSCP0.mSCP);
        auto nom0 = NominationTestHandler(slot0);

        auto nomSCP1 = new TestNominationSCP(v1NodeID, qSetNode1);
        Slot slot1 = Slot(0, *nomSCP1.mSCP);
        auto nom1 = NominationTestHandler(slot1);

        int tot = 0;
        for (int g = 0; g < totalIter; g++)
        {
            writefln("Iteration %s", g);
            Value v = g.toValue();
            nom0.setPreviousValue(v);
            nom1.setPreviousValue(v);

            bool res = true;

            bool v0Voted = false;
            bool v1Voted = false;

            int r = 0;
            do
            {
                nom0.setRoundNumber(r);
                nom1.setRoundNumber(r);
                nom0.updateRoundLeaders();
                nom1.updateRoundLeaders();

                auto l0 = &nom0.getRoundLeaders();
                assert(!l0.empty());
                auto l1 = &nom1.getRoundLeaders();
                assert(!l1.empty());

                auto updateVoted = (NodeID id, set!NodeID* leaders, ref bool voted)
                {
                    if (!voted)
                    {
                        foreach (leader; *leaders)
                        {
                            if (id == leader)
                            {
                                voted = true;
                                break;
                            }
                        }
                    }
                };

                // checks if id voted (any past round, including this one)
                // AND id is a leader this round
                auto findNode = (NodeID id, bool idVoted, set!NodeID* otherLeaders)
                {
                    if (!idVoted)
                        return false;

                    foreach (other; *otherLeaders)
                    {
                        if (other == id)
                            return true;
                    }

                    return false;
                };

                updateVoted(v0NodeID, l0, v0Voted);
                updateVoted(v1NodeID, l1, v1Voted);

                // either both vote for v0 or both vote for v1
                res = findNode(v0NodeID, v0Voted, l1);
                res = res || findNode(v1NodeID, v1Voted, l0);
            } while (!res && ++r < maxRounds);

            tot += res ? 1 : 0;
        }
        return tot;
    };

    //SECTION("flat quorum")
    {
        // test using the same quorum on all nodes
        auto flatTest = (int threshold, int total) {
            auto qSet = makeQSet(nodeIDs, threshold, total, 0);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet, qSet);
                double stats = double(tot * 100) / double(totalIter);
                log.info("Win rate for {} : {}", maxRounds, stats);
            }
        };

        //SECTION("3 out of 5")
        {
            flatTest(3, 5);
        }
        //SECTION("2 out of 3")
        {
            flatTest(2, 3);
        }
    }

    //SECTION("hierarchy")
    {
        //SECTION("same qSet")
        {
            auto qSet = makeQSet(nodeIDs, 3, 4, 0);

            auto qSetInner = makeQSet(nodeIDs, 2, 3, 4);
            qSet.innerSets.push_back(qSetInner);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet, qSet);
                double stats = double(tot * 100) / double(totalIter);
                log.info("Win rate for {} : {}", maxRounds, stats);
            }
        }
        //SECTION("v0 is inner node for v1")
        {
            auto qSet0 = makeQSet(nodeIDs, 3, 4, 0);
            auto qSetInner0 = makeQSet(nodeIDs, 2, 3, 4);
            qSet0.innerSets.push_back(qSetInner0);

            // v1's qset: we move v0 into the inner set
            auto qSet1 = qSet0;
            assert(qSet1.validators[0] == v0NodeID);
            swap(qSet1.validators[0], qSet1.innerSets[0].validators[0]);

            for (int maxRounds = 1; maxRounds <= nbRoundsForStats; maxRounds++)
            {
                int tot = nominationLeaders(maxRounds, qSet0, qSet1);
                double stats = double(tot * 100) / double(totalIter);
                log.info("Win rate for {} : {}", maxRounds, stats);
            }
        }
    }
}
