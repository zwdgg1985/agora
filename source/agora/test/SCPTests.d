/*******************************************************************************

    These tests are inspired by SCP's QuorumSetTests, which test various
    quorum configurations.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.SCPTests;

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
import scpd.Util;

import libsodium.randombytes;

import core.exception;

import std.algorithm;
import std.conv;
import std.digest.sha;
import std.format;
import std.math;
import std.meta;
import std.range;
import std.stdio;

import core.stdc.stdint;

alias Hash = agora.common.Hash.Hash;

mixin AddLogger!();

ref T* activate (T)(ref T* ptr)
{
    if (ptr is null)
        ptr = new T;
    return ptr;
}

// x < y < z < zz
// k can be anything
Value xValue, yValue, zValue, zzValue, kValue;

void setupValues ()
{
    Hash[] v = 4.iota.map!(_ => hashFull(randombytes_random())).array;
    sort(v);

    xValue = v[0][].toVec();
    yValue = v[1][].toVec();
    zValue = v[2][].toVec();
    zzValue = v[3][].toVec();

    // kValue is independent
    kValue = hashFull(randombytes_random())[].toVec();
}

extern(C++) class TestSCP : SCPDriver
{
    struct TimerData
    {
        milliseconds mAbsoluteTimeout;
        CPPDelegate!(void function())* mCallback;
    }

    SCP* mSCP;
    set!Value mExpectedCandidates;
    Value mCompositeValue;
    uint64_t delegate(ref const(NodeID)) mPriorityLookup;
    uint64_t delegate(ref const(Value)) mHashValueCalculator;
    public SCPQuorumSetPtr[StellarHash] mQuorumSets;
    vector!SCPEnvelope mEnvs;
    Value[uint64_t] mExternalizedValues;
    vector!SCPBallot[uint64_t] mHeardFromQuorums;
    TimerData[int] mTimers;
    milliseconds mCurrentTimerOffset;


    public this (NodeID nodeID, ref const(SCPQuorumSet) qSetLocal,
        bool isValidator = true)
    {
        mSCP = createSCP(this, nodeID, isValidator, qSetLocal);

        mPriorityLookup = (ref const(NodeID) n)
        {
            return (n == mSCP.getLocalNodeID()) ? 1000 : 1;
        };

        mHashValueCalculator = (ref const(Value) v) { return 0; };

        auto localQSet = makeSharedSCPQuorumSet(mSCP.getLocalQuorumSet());
        storeQuorumSet(localQSet);
    }

    public override void signEnvelope (ref SCPEnvelope)
    {
    }

    public override SCPDriver.ValidationLevel validateValue (uint64_t slotIndex,
        ref const(Value) value, bool nomination)
    {
        return ValidationLevel.kFullyValidatedValue;
    }

    public override void ballotDidHearFromQuorum (uint64_t slotIndex,
        ref const(SCPBallot) ballot)
    {
        mHeardFromQuorums[slotIndex].push_back(ballot);
    }

    public override void valueExternalized (uint64_t slotIndex,
        ref const(Value) value)
    {
        if (slotIndex in mExternalizedValues)
            throw new AssertError("Value already externalized");

        // note: cast due to inability to use `const` in AA value type
        mExternalizedValues[slotIndex] = cast()value;
    }

    public override SCPQuorumSetPtr getQSet (ref const(StellarHash) qSetHash)
    {
        if (auto val = qSetHash in this.mQuorumSets)
            return *val;

        return SCPQuorumSetPtr();
    }

    public override void emitEnvelope (ref const(SCPEnvelope) envelope)
    {
        mEnvs.push_back(envelope);
    }

    // used to test BallotProtocol and bypass nomination
    public bool bumpState(uint64_t slotIndex, ref const(Value) v)
    {
        return mSCP.getSlot(slotIndex, true).bumpState(v, true);
    }

    public bool nominate(uint64_t slotIndex, ref const(Value) value, bool timedout)
    {
        return mSCP.getSlot(slotIndex, true).nominate(value, value, timedout);
    }

    // only used by nomination protocol
    public override Value combineCandidates(uint64_t slotIndex,
        ref const(set!Value) candidates)
    {
        assert(candidates == mExpectedCandidates);
        assert(!mCompositeValue.empty());

        return mCompositeValue;
    }

    // override the internal hashing scheme in order to make tests
    // more predictable.
    public override uint64_t computeHashNode (uint64_t slotIndex, ref const(Value) prev,
        bool isPriority, int32_t roundNumber, ref const(NodeID) nodeID)
    {
        scope (failure) assert(0);  // todo: fix mPriorityLookup to be nothrow
        uint64_t res;
        if (isPriority)
        {
            res = mPriorityLookup(nodeID);
        }
        else
        {
            res = 0;
        }
        return res;
    }

    // override the value hashing, to make tests more predictable.
    public override uint64_t computeValueHash (uint64_t slotIndex, ref const(Value) prev,
        int32_t roundNumber, ref const(Value) value)
    {
        scope (failure) assert(0);  // todo: fix mPriorityLookup to be nothrow
        return mHashValueCalculator(value);
    }

    public override void setupTimer (ulong slotIndex, int timerID,
        milliseconds timeout, CPPDelegate!(void function())* cb)
    {
        mTimers[timerID] =
            TimerData(milliseconds(mCurrentTimerOffset +
                          // todo: use proper zero, wrap milliseconds::zero maybe
                          //(cb ? timeout : milliseconds.zero()),
                          (cb !is null ? timeout : milliseconds.init)),
                      cb);
    }

    public TimerData getBallotProtocolTimer()
    {
        return mTimers[Slot.timerIDs.BALLOT_PROTOCOL_TIMER];
    }

    // pretends the time moved forward
    public milliseconds bumpTimerOffset()
    {
        // increase by more than the maximum timeout
        // todo: fix this
        //mCurrentTimerOffset += std.chrono.hours(5);
        return mCurrentTimerOffset;
    }

    // returns true if a ballot protocol timer exists (in the past or future)
    public bool hasBallotTimer ()
    {
        return getBallotProtocolTimer().mCallback !is null;
    }

    // returns true if the ballot protocol timer is scheduled in the future
    // false if scheduled in the past
    // this method is mostly used to verify that the timer *would* have fired
    public bool hasBallotTimerUpcoming ()
    {
        // timer must be scheduled in the past or future
        assert(hasBallotTimer());
        return mCurrentTimerOffset < getBallotProtocolTimer().mAbsoluteTimeout;
    }

    public ref const(Value) getLatestCompositeCandidate (uint64_t slotIndex)
    {
        return mSCP.getSlot(slotIndex, true).getLatestCompositeCandidate();
    }

    public void receiveEnvelope (const(SCPEnvelope) envelope)
    {
        mSCP.receiveEnvelope(envelope);
    }

    public ref Slot getSlot (uint64_t index)
    {
        return *mSCP.getSlot(index, false);
    }

    public vector!SCPEnvelope getEntireState (uint64_t index)
    {
        auto v = mSCP.getSlot(index, false).getEntireCurrentState();
        return v;
    }

    public SCPEnvelope getCurrentEnvelope (uint64_t index, ref const(NodeID) id)
    {
        auto r = getEntireState(index);

        foreach (ref env; r)
        {
            if (env.statement.nodeID == id)
                return env;
        }

        throw new AssertError("not found");
    }

    public set!NodeID getNominationLeaders (uint64_t slotIndex)
    {
        return mSCP.getSlot(slotIndex, false).getNominationLeaders();
    }

    private void storeQuorumSet (SCPQuorumSetPtr qSet)
    {
        const bytes = ByteSlice.make(XDRToOpaque(*qSet));
        auto quorum_hash = sha256(bytes);
        this.mQuorumSets[quorum_hash] = qSet;
    }
}

SCPEnvelope makeEnvelope (SecretKey secretKey,
    PublicKey publicKey, uint64_t slotIndex,
    ref SCPStatement statement)
{
    SCPEnvelope envelope;
    envelope.statement = statement;
    envelope.statement.nodeID = publicKey;
    envelope.statement.slotIndex = slotIndex;

    envelope.signature = secretKey.sign(
        hashFull(XDRToOpaque(envelope.statement))[])[].toVec;

    return envelope;
}

SCPEnvelope makeExternalize (SecretKey secretKey,
    PublicKey publicKey,
    StellarHash qSetHash, uint64_t slotIndex,
    SCPBallot commitBallot, uint32_t nH)
{
    SCPStatement st;
    st.pledges.type_ = SCPStatementType.SCP_ST_EXTERNALIZE;
    auto ext = &st.pledges.externalize_;
    ext.commit = cast()commitBallot;
    ext.nH = nH;
    ext.commitQuorumSetHash = qSetHash;

    return makeEnvelope(secretKey, publicKey, slotIndex, st);
}

SCPEnvelope makeConfirm (SecretKey secretKey,
    PublicKey publicKey,
    StellarHash qSetHash, uint64_t slotIndex, uint32_t prepareCounter,
    SCPBallot b, uint32_t nC, uint32_t nH)
{
    SCPStatement st;
    // todo: this was a function call in C++ which destroyed an existing
    // object type in the pledge. However, we don't need to destroy anything
    // because we never change the type after it's set.
    st.pledges.type_ = SCPStatementType.SCP_ST_CONFIRM;
    auto con = &st.pledges.confirm_;
    con.ballot = cast()b;
    con.nPrepared = prepareCounter;
    con.nCommit = nC;
    con.nH = nH;
    con.quorumSetHash = qSetHash;

    return makeEnvelope(secretKey, publicKey, slotIndex, st);
}

SCPEnvelope makePrepare (SecretKey secretKey,
    PublicKey publicKey,
    StellarHash qSetHash, uint64_t slotIndex,
    SCPBallot ballot, SCPBallot* prepared = null,
    uint32_t nC = 0, uint32_t nH = 0, SCPBallot* preparedPrime = null)
{
    SCPStatement st;
    st.pledges.type_ = SCPStatementType.SCP_ST_PREPARE;
    auto p = &st.pledges.prepare_;
    p.ballot = cast()ballot;
    p.quorumSetHash = qSetHash;
    if (prepared)
    {
        *p.prepared.activate() = *prepared;
    }

    p.nC = nC;
    p.nH = nH;

    if (preparedPrime)
    {
        *p.preparedPrime.activate() = *preparedPrime;
    }

    return makeEnvelope(secretKey, publicKey, slotIndex, st);
}

SCPEnvelope makeNominate (SecretKey secretKey,
    PublicKey publicKey,
    StellarHash qSetHash, uint64_t slotIndex,
    vector!Value votes_ = vector!Value.init,
    vector!Value accepted_ = vector!Value.init)
{
    auto votes = votes_[].map!(a => a[]).array;
    auto accepted = accepted_[].map!(a => a[]).array;

    sort(votes);
    sort(accepted);

    SCPStatement st;
    st.pledges.type_ = SCPStatementType.SCP_ST_NOMINATE;
    auto nom = &st.pledges.nominate_;
    nom.quorumSetHash = qSetHash;
    foreach (const ref ubyte[] v; votes)
    {
        auto vec = v.toVec();
        nom.votes.push_back(vec);
    }

    foreach (const ref ubyte[] a; accepted)
    {
        auto vec = a.toVec();
        nom.accepted.push_back(vec);
    }

    return makeEnvelope(secretKey, publicKey, slotIndex, st);
}

void verifyPrepare (SCPEnvelope actual, SecretKey secretKey,
    PublicKey publicKey,
    StellarHash qSetHash, uint64_t slotIndex, SCPBallot ballot,
    SCPBallot* prepared = null, uint32_t nC = 0, uint32_t nH = 0,
    SCPBallot* preparedPrime = null)
{
    auto exp = makePrepare(secretKey, publicKey, qSetHash, slotIndex, ballot,
        prepared, nC, nH, preparedPrime);
    assert(exp.statement == actual.statement);
}

void verifyConfirm (SCPEnvelope actual,
    SecretKey secretKey, PublicKey publicKey,
    StellarHash qSetHash,
    uint64_t slotIndex, uint32_t nPrepared, SCPBallot b, uint32_t nC,
    uint32_t nH)
{
    auto exp = makeConfirm(secretKey, publicKey, qSetHash, slotIndex, nPrepared,
        b, nC, nH);
    assert(exp.statement == actual.statement);
}

void verifyExternalize(SCPEnvelope actual, SecretKey secretKey,
                PublicKey publicKey,
                  StellarHash qSetHash, uint64_t slotIndex,
                  SCPBallot commit, uint32_t nH)
{
    auto exp = makeExternalize(secretKey, publicKey, qSetHash, slotIndex,
        commit, nH);
    assert(exp.statement == actual.statement);
}

void verifyNominate(SCPEnvelope actual, SecretKey secretKey,
                PublicKey publicKey,
               StellarHash qSetHash, uint64_t slotIndex, vector!Value votes,
               vector!Value accepted = vector!Value.init)
{
    auto exp = makeNominate(secretKey, publicKey, qSetHash, slotIndex, votes,
        accepted);
    assert(exp.statement == actual.statement);
}

mixin template SIMULATION_CREATE_NODE (size_t N)
{
    // note: these should be const
    mixin(format(`KeyPair v%skp = KeyPair.random();`, N));
    mixin(format(`SecretKey v%sSecretKey = v%skp.secret;`, N, N));
    mixin(format(`PublicKey v%sPublicKey = v%skp.address;`, N, N));
    mixin(format(`StellarKey v%sNodeID = StellarKey(StellarHash(v%skp.address[]));`, N, N));
}

mixin template SIMULATION_CREATE_NODE (string N)
{
    // note: these should be const
    mixin(format(`KeyPair v%skp = KeyPair.random();`, N));
    mixin(format(`SecretKey v%sSecretKey = v%skp.secret;`, N, N));
    mixin(format(`PublicKey v%sPublicKey = v%skp.address;`, N, N));
    mixin(format(`StellarKey v%sNodeID = StellarKey(StellarHash(v%skp.address[]));`, N, N));
}

//TEST_CASE("vblocking and quorum", "[scp]")
unittest
{
    setupValues();
    mixin SIMULATION_CREATE_NODE!0;
    mixin SIMULATION_CREATE_NODE!1;
    mixin SIMULATION_CREATE_NODE!2;
    mixin SIMULATION_CREATE_NODE!3;

    SCPQuorumSet qSet;
    qSet.threshold = 3;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);

    vector!NodeID nodeSet;
    nodeSet.push_back(v0NodeID);

    assert(LocalNode.isQuorumSlice(qSet, nodeSet) == false);
    assert(LocalNode.isVBlocking(qSet, nodeSet) == false);

    nodeSet.push_back(v2NodeID);

    assert(LocalNode.isQuorumSlice(qSet, nodeSet) == false);
    assert(LocalNode.isVBlocking(qSet, nodeSet) == true);

    nodeSet.push_back(v3NodeID);
    assert(LocalNode.isQuorumSlice(qSet, nodeSet) == true);
    assert(LocalNode.isVBlocking(qSet, nodeSet) == true);

    nodeSet.push_back(v1NodeID);
    assert(LocalNode.isQuorumSlice(qSet, nodeSet) == true);
    assert(LocalNode.isVBlocking(qSet, nodeSet) == true);
}

//TEST_CASE("v blocking distance", "[scp]")
unittest
{
    setupValues();
    mixin SIMULATION_CREATE_NODE!0;
    mixin SIMULATION_CREATE_NODE!1;
    mixin SIMULATION_CREATE_NODE!2;
    mixin SIMULATION_CREATE_NODE!3;
    mixin SIMULATION_CREATE_NODE!4;
    mixin SIMULATION_CREATE_NODE!5;
    mixin SIMULATION_CREATE_NODE!6;
    mixin SIMULATION_CREATE_NODE!7;

    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    auto check = (ref const(SCPQuorumSet) qSetCheck, ref const(set!NodeID) s,
                  int expected)
    {
        auto r = LocalNode.findClosestVBlocking(qSetCheck, s, null);
        assert(expected == r.length());
    };

    set!NodeID good;
    good.insert(v0NodeID);

    // already v-blocking
    check(qSet, good, 0);

    good.insert(v1NodeID);
    // either v0 or v1
    check(qSet, good, 1);

    good.insert(v2NodeID);
    // any 2 of v0..v2
    check(qSet, good, 2);

    SCPQuorumSet qSubSet1;
    qSubSet1.threshold = 1;
    qSubSet1.validators.push_back(v3NodeID);
    qSubSet1.validators.push_back(v4NodeID);
    qSubSet1.validators.push_back(v5NodeID);
    qSet.innerSets.push_back(qSubSet1);

    good.insert(v3NodeID);
    // any 3 of v0..v3
    check(qSet, good, 3);

    good.insert(v4NodeID);
    // v0..v2
    check(qSet, good, 3);

    qSet.threshold = 1;
    // v0..v4
    check(qSet, good, 5);

    good.insert(v5NodeID);
    // v0..v5
    check(qSet, good, 6);

    SCPQuorumSet qSubSet2;
    qSubSet2.threshold = 2;
    qSubSet2.validators.push_back(v6NodeID);
    qSubSet2.validators.push_back(v7NodeID);

    qSet.innerSets.push_back(qSubSet2);
    // v0..v5
    check(qSet, good, 6);

    good.insert(v6NodeID);
    // v0..v5
    check(qSet, good, 6);

    good.insert(v7NodeID);
    // v0..v5 and one of 6,7
    check(qSet, good, 7);

    qSet.threshold = 4;
    // v6, v7
    check(qSet, good, 2);

    qSet.threshold = 3;
    // v0..v2
    check(qSet, good, 3);

    qSet.threshold = 2;
    // v0..v2 and one of v6,v7
    check(qSet, good, 4);
}

alias genEnvelope = SCPEnvelope delegate(SecretKey sk,
    PublicKey pk);

genEnvelope makePrepareGen(StellarHash qSetHash,
    SCPBallot ballot, SCPBallot* prepared = null, uint32_t nC = 0,
    uint32_t nH = 0, SCPBallot* preparedPrime = null)
{
    return (SecretKey sk, PublicKey pk)
    {
        return makePrepare(sk, pk, qSetHash, 0, ballot, prepared, nC, nH,
            preparedPrime);
    };
}

genEnvelope makeConfirmGen(StellarHash qSetHash,
    uint32_t prepareCounter, SCPBallot b, uint32_t nC, uint32_t nH)
{
    return (SecretKey sk, PublicKey pk)
    {
        return makeConfirm(sk, pk, qSetHash, 0, prepareCounter, b, nC, nH);
    };
}

genEnvelope makeExternalizeGen(StellarHash qSetHash,
    SCPBallot commitBallot, uint32_t nH)
{
    return (SecretKey sk, PublicKey pk)
    {
        return makeExternalize(sk, pk, qSetHash, 0, commitBallot, nH);
    };
}

//TEST_CASE("ballot protocol core5", "[scp][ballotprotocol]")
unittest
{
    setupValues();
    mixin SIMULATION_CREATE_NODE!0;
    mixin SIMULATION_CREATE_NODE!1;
    mixin SIMULATION_CREATE_NODE!2;
    mixin SIMULATION_CREATE_NODE!3;
    mixin SIMULATION_CREATE_NODE!4;

    // we need 5 nodes to avoid sharing various thresholds:
    // v-blocking set size: 2
    // threshold: 4 = 3 + self or 4 others
    SCPQuorumSet qSet;
    qSet.threshold = 4;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);
    qSet.validators.push_back(v4NodeID);

    const bytes = ByteSlice.make(XDRToOpaque(qSet));
    uint256 qSetHash = sha256(bytes);

    TestSCP scp = new TestSCP(v0NodeID, qSet);

    scp.storeQuorumSet(makeSharedSCPQuorumSet(qSet));
    uint256 qSetHash0 = scp.mSCP.getLocalNode().getQuorumSetHash();

    // todo
    //assert(xValue < yValue);
    //assert(yValue < zValue);
    //assert(zValue < zzValue);

    auto recvVBlockingChecks = (genEnvelope gen, bool withChecks) {
        SCPEnvelope e1 = gen(v1SecretKey, v1PublicKey);
        SCPEnvelope e2 = gen(v2SecretKey, v2PublicKey);

        scp.bumpTimerOffset();

        // nothing should happen with first message
        size_t i = scp.mEnvs.length();
        scp.receiveEnvelope(e1);
        if (withChecks)
        {
            assert(scp.mEnvs.length() == i);
        }
        i++;
        scp.receiveEnvelope(e2);
        if (withChecks)
        {
            assert(scp.mEnvs.length() == i);
        }
    };

    auto recvVBlocking = (genEnvelope gen)
    {
        return recvVBlockingChecks(gen, true);
    };

    auto recvQuorumChecksEx = (genEnvelope gen, bool withChecks,
        bool delayedQuorum, bool checkUpcoming)
    {
        SCPEnvelope e1 = gen(v1SecretKey, v1PublicKey);
        SCPEnvelope e2 = gen(v2SecretKey, v2PublicKey);
        SCPEnvelope e3 = gen(v3SecretKey, v3PublicKey);
        SCPEnvelope e4 = gen(v4SecretKey, v4PublicKey);

        scp.bumpTimerOffset();

        scp.receiveEnvelope(e1);
        scp.receiveEnvelope(e2);
        size_t i = scp.mEnvs.length() + 1;
        scp.receiveEnvelope(e3);
        if (withChecks && !delayedQuorum)
        {
            assert(scp.mEnvs.length() == i);
        }
        if (checkUpcoming && !delayedQuorum)
        {
            assert(scp.hasBallotTimerUpcoming());
        }
        // nothing happens with an extra vote (unless we're in delayedQuorum)
        scp.receiveEnvelope(e4);
        if (withChecks && delayedQuorum)
        {
            assert(scp.mEnvs.length() == i);
        }
        if (checkUpcoming && delayedQuorum)
        {
            assert(scp.hasBallotTimerUpcoming());
        }
    };

    // doesn't check timers
    auto recvQuorumChecks = (genEnvelope gen, bool withChecks,
        bool delayedQuorum)
    {
        return recvQuorumChecksEx(gen, withChecks, delayedQuorum, false);
    };

    // checks enabled, no delayed quorum
    auto recvQuorumEx = (genEnvelope gen, bool withChecks)
    {
        return recvQuorumChecksEx(gen, true, false, withChecks);
    };

    // checks enabled, no delayed quorum, no check timers
    auto recvQuorum = (genEnvelope gen)
    {
        return recvQuorumEx(gen, false);
    };

    auto nodesAllPledgeToCommit = ()
    {
        SCPBallot b = SCPBallot(1, xValue);
        SCPEnvelope prepare1 = makePrepare(v1SecretKey, v1PublicKey, qSetHash, 0, b);
        SCPEnvelope prepare2 = makePrepare(v2SecretKey, v2PublicKey, qSetHash, 0, b);
        SCPEnvelope prepare3 = makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, b);
        SCPEnvelope prepare4 = makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, b);

        assert(scp.bumpState(0, xValue));
        assert(scp.mEnvs.size() == 1);

        verifyPrepare(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, b);

        scp.receiveEnvelope(prepare1);
        assert(scp.mEnvs.size() == 1);
        assert(scp.mHeardFromQuorums[0].size() == 0);

        scp.receiveEnvelope(prepare2);
        assert(scp.mEnvs.size() == 1);
        assert(scp.mHeardFromQuorums[0].size() == 0);

        scp.receiveEnvelope(prepare3);
        assert(scp.mEnvs.size() == 2);
        assert(scp.mHeardFromQuorums[0].size() == 1);
        assert(scp.mHeardFromQuorums[0][0] == b);

        // We have a quorum including us

        verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, b, &b);

        scp.receiveEnvelope(prepare4);
        assert(scp.mEnvs.size() == 2);

        SCPEnvelope prepared1 = makePrepare(v1SecretKey, v1PublicKey, qSetHash, 0, b, &b);
        SCPEnvelope prepared2 = makePrepare(v2SecretKey, v2PublicKey, qSetHash, 0, b, &b);
        SCPEnvelope prepared3 = makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, b, &b);
        SCPEnvelope prepared4 = makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, b, &b);

        scp.receiveEnvelope(prepared4);
        scp.receiveEnvelope(prepared3);
        assert(scp.mEnvs.size() == 2);

        scp.receiveEnvelope(prepared2);
        assert(scp.mEnvs.size() == 3);

        // confirms prepared
        verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, b,
            &b, b.counter, b.counter);

        // extra statement doesn't do anything
        scp.receiveEnvelope(prepared1);
        assert(scp.mEnvs.size() == 3);
    };

    //SECTION("bumpState x")
    {
        assert(scp.bumpState(0, xValue));
        assert(scp.mEnvs.size() == 1);

        SCPBallot expectedBallot = SCPBallot(1, xValue);

        verifyPrepare(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0,
            expectedBallot);
    }

    //SECTION("start <1,x>")
    {
        // no timer is set
        assert(!scp.hasBallotTimer());

        Value aValue = xValue;
        Value bValue = zValue;
        Value midValue = yValue;
        Value bigValue = zzValue;

        SCPBallot A1 = SCPBallot(1, aValue);
        SCPBallot B1 = SCPBallot(1, bValue);
        SCPBallot Mid1 = SCPBallot(1, midValue);
        SCPBallot Big1 = SCPBallot(1, bigValue);

        SCPBallot A2 = A1;
        A2.counter++;

        SCPBallot A3 = A2;
        A3.counter++;

        SCPBallot A4 = A3;
        A4.counter++;

        SCPBallot A5 = A4;
        A5.counter++;

        SCPBallot AInf = SCPBallot(uint32_t.max, aValue);
        SCPBallot BInf = SCPBallot(uint32_t.max, bValue);

        SCPBallot B2 = B1;
        B2.counter++;

        SCPBallot B3 = B2;
        B3.counter++;

        SCPBallot Mid2 = Mid1;
        Mid2.counter++;

        SCPBallot Big2 = Big1;
        Big2.counter++;

        assert(scp.bumpState(0, aValue));
        assert(scp.mEnvs.size() == 1);
        assert(!scp.hasBallotTimer());

        //SECTION("prepared A1")
        {
            recvQuorumEx(makePrepareGen(qSetHash, A1), true);

            assert(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &A1);

            //SECTION("bump prepared A2")
            {
                // bump to (2,a)

                scp.bumpTimerOffset();
                assert(scp.bumpState(0, aValue));
                assert(scp.mEnvs.size() == 3);
                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, A2, &A1);
                assert(!scp.hasBallotTimer());

                recvQuorumEx(makePrepareGen(qSetHash, A2), true);
                assert(scp.mEnvs.size() == 4);
                verifyPrepare(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, A2, &A2);

                //SECTION("Confirm prepared A2")
                {
                    recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                    assert(scp.mEnvs.size() == 5);
                    verifyPrepare(scp.mEnvs[4], v0SecretKey, v0PublicKey, qSetHash0, 0, A2,
                                  &A2, 2, 2);
                    assert(!scp.hasBallotTimerUpcoming());

                    //SECTION("Accept commit")
                    {
                        //SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            assert(scp.mEnvs.size() == 6);
                            verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                            assert(!scp.hasBallotTimerUpcoming());

                            //SECTION("Quorum prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2));
                                assert(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 2, A3, 2, 2);
                                assert(!scp.hasBallotTimer());

                                recvQuorumEx(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2),
                                    true);
                                assert(scp.mEnvs.size() == 8);
                                verifyConfirm(scp.mEnvs[7], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 3, A3, 2, 2);

                                //SECTION("Accept more commit A3")
                                {
                                    recvQuorum(makePrepareGen(qSetHash, A3, &A3,
                                                              2, 3));
                                    assert(scp.mEnvs.size() == 9);
                                    verifyConfirm(scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 3, A3, 2, 3);
                                    assert(!scp.hasBallotTimerUpcoming());

                                    assert(scp.mExternalizedValues.length ==
                                            0);

                                    //SECTION("Quorum externalize A3")
                                    {
                                        recvQuorum(makeConfirmGen(qSetHash, 3,
                                                                  A3, 2, 3));
                                        assert(scp.mEnvs.size() == 10);
                                        verifyExternalize(scp.mEnvs[9],
                                                          v0SecretKey, v0PublicKey,
                                                          qSetHash0, 0, A2, 3);
                                        assert(!scp.hasBallotTimer());

                                        assert(
                                            scp.mExternalizedValues.length ==
                                            1);
                                        assert(scp.mExternalizedValues[0] ==
                                                aValue);
                                    }
                                }
                                //SECTION("v-blocking accept more A3")
                                {
                                    //SECTION("Confirm A3")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, A3, 2, 3));
                                        assert(scp.mEnvs.size() == 9);
                                        verifyConfirm(scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                      qSetHash0, 0, 3, A3, 2,
                                                      3);
                                        assert(!scp.hasBallotTimerUpcoming());
                                    }
                                    //SECTION("Externalize A3")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, A2, 3));
                                        assert(scp.mEnvs.size() == 9);
                                        verifyConfirm(scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                      qSetHash0, 0, uint32_t.max,
                                                      AInf, 2, uint32_t.max);
                                        assert(!scp.hasBallotTimer());
                                    }
                                    //SECTION("other nodes moved to c=A4 h=A5")
                                    {
                                        //SECTION("Confirm A4..5")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, A5, 4, 5));
                                            assert(scp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                qSetHash0, 0, 3, A5, 4, 5);
                                            assert(!scp.hasBallotTimer());
                                        }
                                        //SECTION("Externalize A4..5")
                                        {
                                            recvVBlocking(makeExternalizeGen(
                                                qSetHash, A4, 5));
                                            assert(scp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                qSetHash0, 0, uint32_t.max, AInf,
                                                4, uint32_t.max);
                                            assert(!scp.hasBallotTimer());
                                        }
                                    }
                                }
                            }
                            //SECTION("v-blocking prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A3, 2, 2));
                                assert(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                assert(!scp.hasBallotTimer());
                            }
                            //SECTION("v-blocking prepared A3+B3")
                            {
                                recvVBlocking(makePrepareGen(qSetHash, A3, &B3,
                                                             2, 2, &A3));
                                assert(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                assert(!scp.hasBallotTimer());
                            }
                            //SECTION("v-blocking confirm A3")
                            {
                                recvVBlocking(
                                    makeConfirmGen(qSetHash, 3, A3, 2, 2));
                                assert(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                assert(!scp.hasBallotTimer());
                            }
                            //SECTION("Hang - does not switch to B in CONFIRM")
                            {
                                //SECTION("Network EXTERNALIZE")
                                {
                                    // externalize messages have a counter at
                                    // infinite
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 3));
                                    assert(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 2, AInf, 2, 2);
                                    assert(!scp.hasBallotTimer());

                                    // stuck
                                    recvQuorumChecks(
                                        makeExternalizeGen(qSetHash, B2, 3),
                                        false, false);
                                    assert(scp.mEnvs.size() == 7);
                                    assert(scp.mExternalizedValues.length ==
                                            0);
                                    // timer scheduled as there is a quorum
                                    // with (2, *)
                                    assert(scp.hasBallotTimerUpcoming());
                                }
                                //SECTION("Network CONFIRMS other ballot")
                                {
                                    //SECTION("at same counter")
                                    {
                                        // nothing should happen here, in
                                        // particular, node should not attempt
                                        // to switch 'p'
                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B2, 2,
                                                           3),
                                            false, false);
                                        assert(scp.mEnvs.size() == 6);
                                        assert(
                                            scp.mExternalizedValues.length ==
                                            0);
                                        assert(!scp.hasBallotTimerUpcoming());
                                    }
                                    //SECTION("at a different counter")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, B3, 3, 3));
                                        assert(scp.mEnvs.size() == 7);
                                        verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                                      qSetHash0, 0, 2, A3, 2,
                                                      2);
                                        assert(!scp.hasBallotTimer());

                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B3, 3,
                                                           3),
                                            false, false);
                                        assert(scp.mEnvs.size() == 7);
                                        assert(
                                            scp.mExternalizedValues.length ==
                                            0);
                                        // timer scheduled as there is a quorum
                                        // with (3, *)
                                        assert(scp.hasBallotTimerUpcoming());
                                    }
                                }
                            }
                        }
                        //SECTION("v-blocking")
                        {
                            //SECTION("CONFIRM")
                            {
                                //SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                    assert(!scp.hasBallotTimerUpcoming());
                                }
                                //SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                    assert(!scp.hasBallotTimer());
                                }
                                //SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                    assert(!scp.hasBallotTimerUpcoming());
                                }
                            }
                            //SECTION("EXTERNALIZE")
                            {
                                //SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, uint32_t.max,
                                                  AInf, 2, uint32_t.max);
                                    assert(!scp.hasBallotTimer());
                                }
                                //SECTION("EXTERNALIZE B2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, uint32_t.max,
                                                  BInf, 2, uint32_t.max);
                                    assert(!scp.hasBallotTimer());
                                }
                            }
                        }
                    }
                    //SECTION("get conflicting prepared B")
                    {
                        //SECTION("same counter")
                        {
                            recvVBlocking(makePrepareGen(qSetHash, B2, &B2));
                            assert(scp.mEnvs.size() == 6);
                            verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                qSetHash0, 0, A2, &B2, 0, 2, &A2);
                            assert(!scp.hasBallotTimerUpcoming());

                            recvQuorum(makePrepareGen(qSetHash, B2, &B2, 2, 2));
                            assert(scp.mEnvs.size() == 7);
                            verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                qSetHash0, 0, 2, B2, 2, 2);
                            assert(!scp.hasBallotTimerUpcoming());
                        }
                        //SECTION("higher counter")
                        {
                            recvVBlocking(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2));
                            assert(scp.mEnvs.size() == 6);
                            verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                qSetHash0, 0, A3, &B2, 0, 2, &A2);
                            assert(!scp.hasBallotTimer());

                            recvQuorumChecksEx(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2), true,
                                true, true);
                            assert(scp.mEnvs.size() == 7);
                            verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                qSetHash0, 0, 3, B3, 2, 2);
                        }
                    }
                }
                //SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared B2
                    recvVBlocking(makePrepareGen(qSetHash, B2, &B2, 0, 0, &A2));
                    assert(scp.mEnvs.size() == 5);
                    verifyPrepare(scp.mEnvs[4], v0SecretKey, v0PublicKey,
                        qSetHash0, 0, A2, &B2, 0, 0, &A2);
                    assert(!scp.hasBallotTimerUpcoming());

                    //SECTION("mixed A2")
                    {
                        // causes h=A2
                        // but c = 0, as p >!~ h
                        scp.bumpTimerOffset();
                        scp.receiveEnvelope(
                            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, A2, &A2));

                        assert(scp.mEnvs.size() == 6);
                        verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                            qSetHash0, 0, A2, &B2, 0, 2, &A2);
                        assert(!scp.hasBallotTimerUpcoming());

                        scp.bumpTimerOffset();
                        scp.receiveEnvelope(
                            makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, A2, &A2));

                        assert(scp.mEnvs.size() == 6);
                        assert(!scp.hasBallotTimerUpcoming());
                    }
                    //SECTION("mixed B2")
                    {
                        // causes h=B2, c=B2
                        scp.bumpTimerOffset();
                        scp.receiveEnvelope(
                            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, B2, &B2));

                        assert(scp.mEnvs.size() == 6);
                        verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);
                        assert(!scp.hasBallotTimerUpcoming());

                        scp.bumpTimerOffset();
                        scp.receiveEnvelope(
                            makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, B2, &B2));

                        assert(scp.mEnvs.size() == 6);
                        assert(!scp.hasBallotTimerUpcoming());
                    }
                }
            }
            //SECTION("switch prepared B1 from A1")
            {
                // (p,p') = (B1, A1) [ from (A1, null) ]
                recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
                assert(scp.mEnvs.size() == 3);
                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &B1,
                              0, 0, &A1);
                assert(!scp.hasBallotTimerUpcoming());

                // v-blocking with n=2 . bump n
                recvVBlocking(makePrepareGen(qSetHash, B2));
                assert(scp.mEnvs.size() == 4);
                verifyPrepare(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, A2, &B1,
                              0, 0, &A1);

                // move to (p,p') = (B2, A1) [update p from B1 . B2]
                recvVBlocking(makePrepareGen(qSetHash, B2, &B2));
                assert(scp.mEnvs.size() == 5);
                verifyPrepare(scp.mEnvs[4], v0SecretKey, v0PublicKey, qSetHash0, 0, A2, &B2,
                              0, 0, &A1);
                assert(
                    !scp.hasBallotTimer()); // no quorum (other nodes on (A,1))

                //SECTION("v-blocking switches to previous value of p")
                {
                    // v-blocking with n=3 . bump n
                    recvVBlocking(makePrepareGen(qSetHash, B3));
                    assert(scp.mEnvs.size() == 6);
                    verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0, 0, A3,
                                  &B2, 0, 0, &A1);
                    assert(!scp.hasBallotTimer()); // no quorum (other nodes on
                                                    // (A,1))

                    // vBlocking set says "B1" is prepared - but we already have
                    // p=B2
                    recvVBlockingChecks(makePrepareGen(qSetHash, B3, &B1),
                                        false);
                    assert(scp.mEnvs.size() == 6);
                    assert(!scp.hasBallotTimer());
                }
                //SECTION("switch p' to Mid2")
                {
                    // (p,p') = (B2, Mid2)
                    recvVBlocking(
                        makePrepareGen(qSetHash, B2, &B2, 0, 0, &Mid2));
                    assert(scp.mEnvs.size() == 6);
                    verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0, 0, A2,
                                  &B2, 0, 0, &Mid2);
                    assert(!scp.hasBallotTimer());
                }
                //SECTION("switch again Big2")
                {
                    // both p and p' get updated
                    // (p,p') = (Big2, B2)
                    recvVBlocking(
                        makePrepareGen(qSetHash, B2, &Big2, 0, 0, &B2));
                    assert(scp.mEnvs.size() == 6);
                    verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0, 0, A2,
                                  &Big2, 0, 0, &B2);
                    assert(!scp.hasBallotTimer());
                }
            }
            //SECTION("switch prepare B1")
            {
                recvQuorumChecks(makePrepareGen(qSetHash, B1), true, true);
                assert(scp.mEnvs.size() == 3);
                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &B1,
                              0, 0, &A1);
                assert(!scp.hasBallotTimerUpcoming());
            }
            //SECTION("prepare higher counter (v-blocking)")
            {
                recvVBlocking(makePrepareGen(qSetHash, B2));
                assert(scp.mEnvs.size() == 3);
                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, A2, &A1);
                assert(!scp.hasBallotTimer());

                // more timeout from vBlocking set
                recvVBlocking(makePrepareGen(qSetHash, B3));
                assert(scp.mEnvs.size() == 4);
                verifyPrepare(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, A3, &A1);
                assert(!scp.hasBallotTimer());
            }
        }
        //SECTION("prepared B (v-blocking)")
        {
            recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
            assert(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &B1);
            assert(!scp.hasBallotTimer());
        }
        //SECTION("prepare B (quorum)")
        {
            recvQuorumChecksEx(makePrepareGen(qSetHash, B1), true, true, true);
            assert(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &B1);
        }
        //SECTION("confirm (v-blocking)")
        {
            //SECTION("via CONFIRM")
            {
                scp.bumpTimerOffset();
                scp.receiveEnvelope(
                    makeConfirm(v1SecretKey, v1PublicKey, qSetHash, 0, 3, A3, 3, 3));
                scp.receiveEnvelope(
                    makeConfirm(v2SecretKey, v2PublicKey, qSetHash, 0, 4, A4, 2, 4));
                assert(scp.mEnvs.size() == 2);
                verifyConfirm(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, 3, A3, 3,
                              3);
                assert(!scp.hasBallotTimer());
            }
            //SECTION("via EXTERNALIZE")
            {
                scp.receiveEnvelope(
                    makeExternalize(v1SecretKey, v1PublicKey, qSetHash, 0, A2, 4));
                scp.receiveEnvelope(
                    makeExternalize(v2SecretKey, v2PublicKey, qSetHash, 0, A3, 5));
                assert(scp.mEnvs.size() == 2);
                verifyConfirm(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0,
                              uint32_t.max, AInf, 3, uint32_t.max);
                assert(!scp.hasBallotTimer());
            }
        }
    }

    // this is the same test suite than "start <1,x>" with the exception that
    // some transitions are not possible as x < z - so instead we verify that
    // nothing happens
    //SECTION("start <1,z>")
    {
        // no timer is set
        assert(!scp.hasBallotTimer());

        Value aValue = zValue;
        Value bValue = xValue;

        SCPBallot A1 = SCPBallot(1, aValue);
        SCPBallot B1 = SCPBallot(1, bValue);

        SCPBallot A2 = A1;
        A2.counter++;

        SCPBallot A3 = A2;
        A3.counter++;

        SCPBallot A4 = A3;
        A4.counter++;

        SCPBallot A5 = A4;
        A5.counter++;

        SCPBallot AInf = SCPBallot(uint32_t.max, aValue);
        SCPBallot BInf = SCPBallot(uint32_t.max, bValue);

        SCPBallot B2 = B1;
        B2.counter++;

        SCPBallot B3 = B2;
        B3.counter++;

        assert(scp.bumpState(0, aValue));
        assert(scp.mEnvs.size() == 1);
        assert(!scp.hasBallotTimer());

        //SECTION("prepared A1")
        {
            recvQuorumEx(makePrepareGen(qSetHash, A1), true);

            assert(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &A1);

            //SECTION("bump prepared A2")
            {
                // bump to (2,a)

                scp.bumpTimerOffset();
                assert(scp.bumpState(0, aValue));
                assert(scp.mEnvs.size() == 3);
                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, A2, &A1);
                assert(!scp.hasBallotTimer());

                recvQuorumEx(makePrepareGen(qSetHash, A2), true);
                assert(scp.mEnvs.size() == 4);
                verifyPrepare(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, A2, &A2);

                //SECTION("Confirm prepared A2")
                {
                    recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                    assert(scp.mEnvs.size() == 5);
                    verifyPrepare(scp.mEnvs[4], v0SecretKey, v0PublicKey, qSetHash0, 0, A2,
                                  &A2, 2, 2);
                    assert(!scp.hasBallotTimerUpcoming());

                    //SECTION("Accept commit")
                    {
                        //SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            assert(scp.mEnvs.size() == 6);
                            verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                            assert(!scp.hasBallotTimerUpcoming());

                            //SECTION("Quorum prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2));
                                assert(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 2, A3, 2, 2);
                                assert(!scp.hasBallotTimer());

                                recvQuorumEx(
                                    makePrepareGen(qSetHash, A3, &A2, 2, 2),
                                    true);
                                assert(scp.mEnvs.size() == 8);
                                verifyConfirm(scp.mEnvs[7], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 3, A3, 2, 2);

                                //SECTION("Accept more commit A3")
                                {
                                    recvQuorum(makePrepareGen(qSetHash, A3, &A3,
                                                              2, 3));
                                    assert(scp.mEnvs.size() == 9);
                                    verifyConfirm(scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 3, A3, 2, 3);
                                    assert(!scp.hasBallotTimerUpcoming());

                                    assert(scp.mExternalizedValues.length ==
                                            0);

                                    //SECTION("Quorum externalize A3")
                                    {
                                        recvQuorum(makeConfirmGen(qSetHash, 3,
                                                                  A3, 2, 3));
                                        assert(scp.mEnvs.size() == 10);
                                        verifyExternalize(scp.mEnvs[9],
                                                          v0SecretKey, v0PublicKey,
                                                          qSetHash0, 0, A2, 3);
                                        assert(!scp.hasBallotTimer());

                                        assert(
                                            scp.mExternalizedValues.length ==
                                            1);
                                        assert(scp.mExternalizedValues[0] ==
                                                aValue);
                                    }
                                }
                                //SECTION("v-blocking accept more A3")
                                {
                                    //SECTION("Confirm A3")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, A3, 2, 3));
                                        assert(scp.mEnvs.size() == 9);
                                        verifyConfirm(scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                      qSetHash0, 0, 3, A3, 2,
                                                      3);
                                        assert(!scp.hasBallotTimerUpcoming());
                                    }
                                    //SECTION("Externalize A3")
                                    {
                                        recvVBlocking(makeExternalizeGen(
                                            qSetHash, A2, 3));
                                        assert(scp.mEnvs.size() == 9);
                                        verifyConfirm(scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                      qSetHash0, 0, uint32_t.max,
                                                      AInf, 2, uint32_t.max);
                                        assert(!scp.hasBallotTimer());
                                    }
                                    //SECTION("other nodes moved to c=A4 h=A5")
                                    {
                                        //SECTION("Confirm A4..5")
                                        {
                                            recvVBlocking(makeConfirmGen(
                                                qSetHash, 3, A5, 4, 5));
                                            assert(scp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                qSetHash0, 0, 3, A5, 4, 5);
                                            assert(!scp.hasBallotTimer());
                                        }
                                        //SECTION("Externalize A4..5")
                                        {
                                            recvVBlocking(makeExternalizeGen(
                                                qSetHash, A4, 5));
                                            assert(scp.mEnvs.size() == 9);
                                            verifyConfirm(
                                                scp.mEnvs[8], v0SecretKey, v0PublicKey,
                                                qSetHash0, 0, uint32_t.max, AInf,
                                                4, uint32_t.max);
                                            assert(!scp.hasBallotTimer());
                                        }
                                    }
                                }
                            }
                            //SECTION("v-blocking prepared A3")
                            {
                                recvVBlocking(
                                    makePrepareGen(qSetHash, A3, &A3, 2, 2));
                                assert(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                assert(!scp.hasBallotTimer());
                            }
                            //SECTION("v-blocking prepared A3+B3")
                            {
                                recvVBlocking(makePrepareGen(qSetHash, A3, &A3,
                                                             2, 2, &B3));
                                assert(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                assert(!scp.hasBallotTimer());
                            }
                            //SECTION("v-blocking confirm A3")
                            {
                                recvVBlocking(
                                    makeConfirmGen(qSetHash, 3, A3, 2, 2));
                                assert(scp.mEnvs.size() == 7);
                                verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                              qSetHash0, 0, 3, A3, 2, 2);
                                assert(!scp.hasBallotTimer());
                            }
                            //SECTION("Hang - does not switch to B in CONFIRM")
                            {
                                //SECTION("Network EXTERNALIZE")
                                {
                                    // externalize messages have a counter at
                                    // infinite
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 3));
                                    assert(scp.mEnvs.size() == 7);
                                    verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 2, AInf, 2, 2);
                                    assert(!scp.hasBallotTimer());

                                    // stuck
                                    recvQuorumChecks(
                                        makeExternalizeGen(qSetHash, B2, 3),
                                        false, false);
                                    assert(scp.mEnvs.size() == 7);
                                    assert(scp.mExternalizedValues.length ==
                                            0);
                                    // timer scheduled as there is a quorum
                                    // with (inf, *)
                                    assert(scp.hasBallotTimerUpcoming());
                                }
                                //SECTION("Network CONFIRMS other ballot")
                                {
                                    //SECTION("at same counter")
                                    {
                                        // nothing should happen here, in
                                        // particular, node should not attempt
                                        // to switch 'p'
                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B2, 2,
                                                           3),
                                            false, false);
                                        assert(scp.mEnvs.size() == 6);
                                        assert(
                                            scp.mExternalizedValues.length ==
                                            0);
                                        assert(!scp.hasBallotTimerUpcoming());
                                    }
                                    //SECTION("at a different counter")
                                    {
                                        recvVBlocking(makeConfirmGen(
                                            qSetHash, 3, B3, 3, 3));
                                        assert(scp.mEnvs.size() == 7);
                                        verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey,
                                                      qSetHash0, 0, 2, A3, 2,
                                                      2);
                                        assert(!scp.hasBallotTimer());

                                        recvQuorumChecks(
                                            makeConfirmGen(qSetHash, 3, B3, 3,
                                                           3),
                                            false, false);
                                        assert(scp.mEnvs.size() == 7);
                                        assert(
                                            scp.mExternalizedValues.length ==
                                            0);
                                        // timer scheduled as there is a quorum
                                        // with (3, *)
                                        assert(scp.hasBallotTimerUpcoming());
                                    }
                                }
                            }
                        }
                        //SECTION("v-blocking")
                        {
                            //SECTION("CONFIRM")
                            {
                                //SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                    assert(!scp.hasBallotTimerUpcoming());
                                }
                                //SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                    assert(!scp.hasBallotTimer());
                                }
                                //SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                    assert(!scp.hasBallotTimerUpcoming());
                                }
                            }
                            //SECTION("EXTERNALIZE")
                            {
                                //SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, uint32_t.max,
                                                  AInf, 2, uint32_t.max);
                                    assert(!scp.hasBallotTimer());
                                }
                                //SECTION("EXTERNALIZE B2")
                                {
                                    // can switch to B2 with externalize (higher
                                    // counter)
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    assert(scp.mEnvs.size() == 6);
                                    verifyConfirm(scp.mEnvs[5], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, uint32_t.max,
                                                  BInf, 2, uint32_t.max);
                                    assert(!scp.hasBallotTimer());
                                }
                            }
                        }
                    }
                    //SECTION("get conflicting prepared B")
                    {
                        //SECTION("same counter")
                        {
                            // messages are ignored as B2 < A2
                            recvQuorumChecks(makePrepareGen(qSetHash, B2, &B2),
                                             false, false);
                            assert(scp.mEnvs.size() == 5);
                            assert(!scp.hasBallotTimerUpcoming());
                        }
                        //SECTION("higher counter")
                        {
                            recvVBlocking(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2));
                            assert(scp.mEnvs.size() == 6);
                            // A2 > B2 . p = A2, p'=B2
                            verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0,
                                          0, A3, &A2, 2, 2, &B2);
                            assert(!scp.hasBallotTimer());

                            // node is trying to commit A2=<2,y> but rest
                            // of its quorum is trying to commit B2
                            // we end up with a delayed quorum
                            recvQuorumChecksEx(
                                makePrepareGen(qSetHash, B3, &B2, 2, 2), true,
                                true, true);
                            assert(scp.mEnvs.size() == 7);
                            verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey, qSetHash0,
                                          0, 3, B3, 2, 2);
                        }
                    }
                }
                //SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared B2
                    recvVBlocking(makePrepareGen(qSetHash, A2, &A2, 0, 0, &B2));
                    assert(scp.mEnvs.size() == 5);
                    verifyPrepare(scp.mEnvs[4], v0SecretKey, v0PublicKey, qSetHash0, 0, A2,
                                  &A2, 0, 0, &B2);
                    assert(!scp.hasBallotTimerUpcoming());

                    //SECTION("mixed A2")
                    {
                        // causes h=A2, c=A2
                        scp.bumpTimerOffset();
                        scp.receiveEnvelope(
                            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, A2, &A2));

                        assert(scp.mEnvs.size() == 6);
                        verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                      A2, &A2, 2, 2, &B2);
                        assert(!scp.hasBallotTimerUpcoming());

                        scp.bumpTimerOffset();
                        scp.receiveEnvelope(
                            makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, A2, &A2));

                        assert(scp.mEnvs.size() == 6);
                        assert(!scp.hasBallotTimerUpcoming());
                    }
                    //SECTION("mixed B2")
                    {
                        // causes computed_h=B2 ~ not set as h ~!= b
                        // . noop
                        scp.bumpTimerOffset();
                        scp.receiveEnvelope(
                            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, A2, &B2));

                        assert(scp.mEnvs.size() == 5);
                        assert(!scp.hasBallotTimerUpcoming());

                        scp.bumpTimerOffset();
                        scp.receiveEnvelope(
                            makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, B2, &B2));

                        assert(scp.mEnvs.size() == 5);
                        assert(!scp.hasBallotTimerUpcoming());
                    }
                }
            }
            //SECTION("switch prepared B1 from A1")
            {
                // can't switch to B1
                recvQuorumChecks(makePrepareGen(qSetHash, B1, &B1), false,
                                 false);
                assert(scp.mEnvs.size() == 2);
                assert(!scp.hasBallotTimerUpcoming());
            }
            //SECTION("switch prepare B1")
            {
                // doesn't switch as B1 < A1
                recvQuorumChecks(makePrepareGen(qSetHash, B1), false, false);
                assert(scp.mEnvs.size() == 2);
                assert(!scp.hasBallotTimerUpcoming());
            }
            //SECTION("prepare higher counter (v-blocking)")
            {
                recvVBlocking(makePrepareGen(qSetHash, B2));
                assert(scp.mEnvs.size() == 3);
                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, A2, &A1);
                assert(!scp.hasBallotTimer());

                // more timeout from vBlocking set
                recvVBlocking(makePrepareGen(qSetHash, B3));
                assert(scp.mEnvs.size() == 4);
                verifyPrepare(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, A3, &A1);
                assert(!scp.hasBallotTimer());
            }
        }
        //SECTION("prepared B (v-blocking)")
        {
            recvVBlocking(makePrepareGen(qSetHash, B1, &B1));
            assert(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &B1);
            assert(!scp.hasBallotTimer());
        }
        //SECTION("prepare B (quorum)")
        {
            recvQuorumChecksEx(makePrepareGen(qSetHash, B1), true, true, true);
            assert(scp.mEnvs.size() == 2);
            verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &B1);
        }
        //SECTION("confirm (v-blocking)")
        {
            //SECTION("via CONFIRM")
            {
                scp.bumpTimerOffset();
                scp.receiveEnvelope(
                    makeConfirm(v1SecretKey, v1PublicKey, qSetHash, 0, 3, A3, 3, 3));
                scp.receiveEnvelope(
                    makeConfirm(v2SecretKey, v2PublicKey, qSetHash, 0, 4, A4, 2, 4));
                assert(scp.mEnvs.size() == 2);
                verifyConfirm(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, 3, A3, 3,
                              3);
                assert(!scp.hasBallotTimer());
            }
            //SECTION("via EXTERNALIZE")
            {
                scp.receiveEnvelope(
                    makeExternalize(v1SecretKey, v1PublicKey, qSetHash, 0, A2, 4));
                scp.receiveEnvelope(
                    makeExternalize(v2SecretKey, v2PublicKey, qSetHash, 0, A3, 5));
                assert(scp.mEnvs.size() == 2);
                verifyConfirm(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0,
                              uint32_t.max, AInf, 3, uint32_t.max);
                assert(!scp.hasBallotTimer());
            }
        }
    }

    // this is the same test suite than "start <1,x>" but only keeping
    // the transitions that are observable when starting from empty
    //SECTION("start from pristine")
    {
        Value aValue = xValue;
        Value bValue = zValue;

        SCPBallot A1 = SCPBallot(1, aValue);
        SCPBallot B1 = SCPBallot(1, bValue);

        SCPBallot A2 = A1;
        A2.counter++;

        SCPBallot A3 = A2;
        A3.counter++;

        SCPBallot A4 = A3;
        A4.counter++;

        SCPBallot A5 = A4;
        A5.counter++;

        SCPBallot AInf = SCPBallot(uint32_t.max, aValue);
        SCPBallot BInf = SCPBallot(uint32_t.max, bValue);

        SCPBallot B2 = B1;
        B2.counter++;

        SCPBallot B3 = B2;
        B3.counter++;

        assert(scp.mEnvs.size() == 0);

        //SECTION("prepared A1")
        {
            recvQuorumChecks(makePrepareGen(qSetHash, A1), false, false);
            assert(scp.mEnvs.size() == 0);

            //SECTION("bump prepared A2")
            {
                //SECTION("Confirm prepared A2")
                {
                    recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                        false);
                    assert(scp.mEnvs.size() == 0);

                    //SECTION("Quorum A2")
                    {
                        recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                            false);
                        assert(scp.mEnvs.size() == 0);
                        recvQuorum(makePrepareGen(qSetHash, A2, &A2));
                        assert(scp.mEnvs.size() == 1);
                        verifyPrepare(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                      A2, &A2, 1, 2);
                    }
                    //SECTION("Quorum B2")
                    {
                        recvVBlockingChecks(makePrepareGen(qSetHash, B2, &B2),
                                            false);
                        assert(scp.mEnvs.size() == 0);
                        recvQuorum(makePrepareGen(qSetHash, B2, &B2));
                        assert(scp.mEnvs.size() == 1);
                        verifyPrepare(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);
                    }
                    //SECTION("Accept commit")
                    {
                        //SECTION("Quorum A2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, A2, &A2, 2, 2));
                            assert(scp.mEnvs.size() == 1);
                            verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0,
                                          0, 2, A2, 2, 2);
                        }
                        //SECTION("Quorum B2")
                        {
                            recvQuorum(makePrepareGen(qSetHash, B2, &B2, 2, 2));
                            assert(scp.mEnvs.size() == 1);
                            verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0,
                                          0, 2, B2, 2, 2);
                        }
                        //SECTION("v-blocking")
                        {
                            //SECTION("CONFIRM")
                            {
                                //SECTION("CONFIRM A2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, A2, 2, 2));
                                    assert(scp.mEnvs.size() == 1);
                                    verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 2, A2, 2, 2);
                                }
                                //SECTION("CONFIRM A3..4")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 4, A4, 3, 4));
                                    assert(scp.mEnvs.size() == 1);
                                    verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 4, A4, 3, 4);
                                }
                                //SECTION("CONFIRM B2")
                                {
                                    recvVBlocking(
                                        makeConfirmGen(qSetHash, 2, B2, 2, 2));
                                    assert(scp.mEnvs.size() == 1);
                                    verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, 2, B2, 2, 2);
                                }
                            }
                            //SECTION("EXTERNALIZE")
                            {
                                //SECTION("EXTERNALIZE A2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, A2, 2));
                                    assert(scp.mEnvs.size() == 1);
                                    verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, uint32_t.max,
                                                  AInf, 2, uint32_t.max);
                                }
                                //SECTION("EXTERNALIZE B2")
                                {
                                    recvVBlocking(
                                        makeExternalizeGen(qSetHash, B2, 2));
                                    assert(scp.mEnvs.size() == 1);
                                    verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey,
                                                  qSetHash0, 0, uint32_t.max,
                                                  BInf, 2, uint32_t.max);
                                }
                            }
                        }
                    }
                }
                //SECTION("Confirm prepared mixed")
                {
                    // a few nodes prepared A2
                    // causes p=A2
                    recvVBlockingChecks(makePrepareGen(qSetHash, A2, &A2),
                                        false);
                    assert(scp.mEnvs.size() == 0);

                    // a few nodes prepared B2
                    // causes p=B2, p'=A2
                    recvVBlockingChecks(
                        makePrepareGen(qSetHash, A2, &B2, 0, 0, &A2), false);
                    assert(scp.mEnvs.size() == 0);

                    //SECTION("mixed A2")
                    {
                        // causes h=A2
                        // but c = 0, as p >!~ h
                        scp.receiveEnvelope(
                            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, A2, &A2));

                        assert(scp.mEnvs.size() == 1);
                        verifyPrepare(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                      A2, &B2, 0, 2, &A2);

                        scp.receiveEnvelope(
                            makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, A2, &A2));

                        assert(scp.mEnvs.size() == 1);
                    }
                    //SECTION("mixed B2")
                    {
                        // causes h=B2, c=B2
                        scp.receiveEnvelope(
                            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, B2, &B2));

                        assert(scp.mEnvs.size() == 1);
                        verifyPrepare(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                      B2, &B2, 2, 2, &A2);

                        scp.receiveEnvelope(
                            makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, B2, &B2));

                        assert(scp.mEnvs.size() == 1);
                    }
                }
            }
            //SECTION("switch prepared B1")
            {
                recvVBlockingChecks(makePrepareGen(qSetHash, B1, &B1), false);
                assert(scp.mEnvs.size() == 0);
            }
        }
        //SECTION("prepared B (v-blocking)")
        {
            recvVBlockingChecks(makePrepareGen(qSetHash, B1, &B1), false);
            assert(scp.mEnvs.size() == 0);
        }
        //SECTION("confirm (v-blocking)")
        {
            //SECTION("via CONFIRM")
            {
                scp.receiveEnvelope(
                    makeConfirm(v1SecretKey, v1PublicKey, qSetHash, 0, 3, A3, 3, 3));
                scp.receiveEnvelope(
                    makeConfirm(v2SecretKey, v2PublicKey, qSetHash, 0, 4, A4, 2, 4));
                assert(scp.mEnvs.size() == 1);
                verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, 3, A3, 3,
                              3);
            }
            //SECTION("via EXTERNALIZE")
            {
                scp.receiveEnvelope(
                    makeExternalize(v1SecretKey, v1PublicKey, qSetHash, 0, A2, 4));
                scp.receiveEnvelope(
                    makeExternalize(v2SecretKey, v2PublicKey, qSetHash, 0, A3, 5));
                assert(scp.mEnvs.size() == 1);
                verifyConfirm(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0,
                              uint32_t.max, AInf, 3, uint32_t.max);
            }
        }
    }

    //SECTION("normal round (1,x)")
    {
        nodesAllPledgeToCommit();
        assert(scp.mEnvs.size() == 3);

        SCPBallot b = SCPBallot(1, xValue);

        // bunch of prepare messages with "commit b"
        SCPEnvelope preparedC1 =
            makePrepare(v1SecretKey, v1PublicKey, qSetHash, 0, b, &b, b.counter, b.counter);
        SCPEnvelope preparedC2 =
            makePrepare(v2SecretKey, v2PublicKey, qSetHash, 0, b, &b, b.counter, b.counter);
        SCPEnvelope preparedC3 =
            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, b, &b, b.counter, b.counter);
        SCPEnvelope preparedC4 =
            makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, b, &b, b.counter, b.counter);

        // those should not trigger anything just yet
        scp.receiveEnvelope(preparedC1);
        scp.receiveEnvelope(preparedC2);
        assert(scp.mEnvs.size() == 3);

        // this should cause the node to accept 'commit b' (quorum)
        // and therefore send a "CONFIRM" message
        scp.receiveEnvelope(preparedC3);
        assert(scp.mEnvs.size() == 4);

        verifyConfirm(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, 1, b, b.counter,
                      b.counter);

        // bunch of confirm messages
        SCPEnvelope confirm1 = makeConfirm(v1SecretKey, v1PublicKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        SCPEnvelope confirm2 = makeConfirm(v2SecretKey, v2PublicKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        SCPEnvelope confirm3 = makeConfirm(v3SecretKey, v3PublicKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);
        SCPEnvelope confirm4 = makeConfirm(v4SecretKey, v4PublicKey, qSetHash, 0, b.counter,
                                           b, b.counter, b.counter);

        // those should not trigger anything just yet
        scp.receiveEnvelope(confirm1);
        scp.receiveEnvelope(confirm2);
        assert(scp.mEnvs.size() == 4);

        scp.receiveEnvelope(confirm3);
        // this causes our node to
        // externalize (confirm commit c)
        assert(scp.mEnvs.size() == 5);

        // The slot should have externalized the value
        assert(scp.mExternalizedValues.length == 1);
        assert(scp.mExternalizedValues[0] == xValue);

        verifyExternalize(scp.mEnvs[4], v0SecretKey, v0PublicKey, qSetHash0, 0, b,
                          b.counter);

        // extra vote should not do anything
        scp.receiveEnvelope(confirm4);
        assert(scp.mEnvs.size() == 5);
        assert(scp.mExternalizedValues.length == 1);

        // duplicate should just no-op
        scp.receiveEnvelope(confirm2);
        assert(scp.mEnvs.size() == 5);
        assert(scp.mExternalizedValues.length == 1);

        //SECTION("bumpToBallot prevented once committed")
        {
            SCPBallot b2;
            //SECTION("bumpToBallot prevented once committed (by value)")
            {
                b2 = SCPBallot(1, zValue);
            }
            //SECTION("bumpToBallot prevented once committed (by counter)")
            {
                b2 = SCPBallot(2, xValue);
            }
            //SECTION(
                //"bumpToBallot prevented once committed (by value and counter)")
            {
                b2 = SCPBallot(2, zValue);
            }

            SCPEnvelope confirm1b2, confirm2b2, confirm3b2, confirm4b2;
            confirm1b2 = makeConfirm(v1SecretKey, v1PublicKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm2b2 = makeConfirm(v2SecretKey, v2PublicKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm3b2 = makeConfirm(v3SecretKey, v3PublicKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);
            confirm4b2 = makeConfirm(v4SecretKey, v4PublicKey, qSetHash, 0, b2.counter, b2,
                                     b2.counter, b2.counter);

            scp.receiveEnvelope(confirm1b2);
            scp.receiveEnvelope(confirm2b2);
            scp.receiveEnvelope(confirm3b2);
            scp.receiveEnvelope(confirm4b2);
            assert(scp.mEnvs.size() == 5);
            assert(scp.mExternalizedValues.length == 1);
        }
    }

    //SECTION("range check")
    {
        nodesAllPledgeToCommit();
        assert(scp.mEnvs.size() == 3);

        SCPBallot b = SCPBallot(1, xValue);

        // bunch of prepare messages with "commit b"
        SCPEnvelope preparedC1 =
            makePrepare(v1SecretKey, v1PublicKey, qSetHash, 0, b, &b, b.counter, b.counter);
        SCPEnvelope preparedC2 =
            makePrepare(v2SecretKey, v2PublicKey, qSetHash, 0, b, &b, b.counter, b.counter);
        SCPEnvelope preparedC3 =
            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, b, &b, b.counter, b.counter);
        SCPEnvelope preparedC4 =
            makePrepare(v4SecretKey, v4PublicKey, qSetHash, 0, b, &b, b.counter, b.counter);

        // those should not trigger anything just yet
        scp.receiveEnvelope(preparedC1);
        scp.receiveEnvelope(preparedC2);
        assert(scp.mEnvs.size() == 3);

        // this should cause the node to accept 'commit b' (quorum)
        // and therefore send a "CONFIRM" message
        scp.receiveEnvelope(preparedC3);
        assert(scp.mEnvs.size() == 4);

        verifyConfirm(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, 1, b, b.counter,
                      b.counter);

        // bunch of confirm messages with different ranges
        SCPBallot b5 = SCPBallot(5, xValue);
        SCPEnvelope confirm1 = makeConfirm(v1SecretKey, v1PublicKey, qSetHash, 0, 4,
                                           SCPBallot(4, xValue), 2, 4);
        SCPEnvelope confirm2 = makeConfirm(v2SecretKey, v2PublicKey, qSetHash, 0, 6,
                                           SCPBallot(6, xValue), 2, 6);
        SCPEnvelope confirm3 = makeConfirm(v3SecretKey, v3PublicKey, qSetHash, 0, 5,
                                           SCPBallot(5, xValue), 3, 5);
        SCPEnvelope confirm4 = makeConfirm(v4SecretKey, v4PublicKey, qSetHash, 0, 6,
                                           SCPBallot(6, xValue), 3, 6);

        // this should not trigger anything just yet
        scp.receiveEnvelope(confirm1);

        // v-blocking
        //   * b gets bumped to (4,x)
        //   * p gets bumped to (4,x)
        //   * (c,h) gets bumped to (2,4)
        scp.receiveEnvelope(confirm2);
        assert(scp.mEnvs.size() == 5);
        verifyConfirm(scp.mEnvs[4], v0SecretKey, v0PublicKey, qSetHash0, 0, 4,
                      SCPBallot(4, xValue), 2, 4);

        // this causes to externalize
        // range is [3,4]
        scp.receiveEnvelope(confirm4);
        assert(scp.mEnvs.size() == 6);

        // The slot should have externalized the value
        assert(scp.mExternalizedValues.length == 1);
        assert(scp.mExternalizedValues[0] == xValue);

        verifyExternalize(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0, 0,
                          SCPBallot(3, xValue), 4);
    }

    //SECTION("timeout when h is set . stay locked on h")
    {
        SCPBallot bx = SCPBallot(1, xValue);
        assert(scp.bumpState(0, xValue));
        assert(scp.mEnvs.size() == 1);

        // v-blocking . prepared
        // quorum . confirm prepared
        recvQuorum(makePrepareGen(qSetHash, bx, &bx));
        assert(scp.mEnvs.size() == 3);
        verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, bx, &bx,
                      bx.counter, bx.counter);

        // now, see if we can timeout and move to a different value
        assert(scp.bumpState(0, yValue));
        assert(scp.mEnvs.size() == 4);
        SCPBallot newbx = SCPBallot(2, xValue);
        verifyPrepare(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, newbx, &bx,
                      bx.counter, bx.counter);
    }
    //SECTION("timeout when h exists but can't be set . vote for h")
    {
        // start with (1,y)
        SCPBallot by = SCPBallot(1, yValue);
        assert(scp.bumpState(0, yValue));
        assert(scp.mEnvs.size() == 1);

        SCPBallot bx = SCPBallot(1, xValue);
        // but quorum goes with (1,x)
        // v-blocking . prepared
        recvVBlocking(makePrepareGen(qSetHash, bx, &bx));
        assert(scp.mEnvs.size() == 2);
        verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, by, &bx);
        // quorum . confirm prepared (no-op as b > h)
        recvQuorumChecks(makePrepareGen(qSetHash, bx, &bx), false, false);
        assert(scp.mEnvs.size() == 2);

        assert(scp.bumpState(0, yValue));
        assert(scp.mEnvs.size() == 3);
        SCPBallot newbx = SCPBallot(2, xValue);
        // on timeout:
        // * we should move to the quorum's h value
        // * c can't be set yet as b > h
        verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, newbx, &bx, 0,
                      bx.counter);
    }

    //SECTION("timeout from multiple nodes")
    {
        assert(scp.bumpState(0, xValue));

        SCPBallot x1 = SCPBallot(1, xValue);

        assert(scp.mEnvs.size() == 1);
        verifyPrepare(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, x1);

        recvQuorum(makePrepareGen(qSetHash, x1));
        // quorum . prepared (1,x)
        assert(scp.mEnvs.size() == 2);
        verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, x1, &x1);

        SCPBallot x2 = SCPBallot(2, xValue);
        // timeout from local node
        assert(scp.bumpState(0, xValue));
        // prepares (2,x)
        assert(scp.mEnvs.size() == 3);
        verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, x2, &x1);

        recvQuorum(makePrepareGen(qSetHash, x1, &x1));
        // quorum . set nH=1
        assert(scp.mEnvs.size() == 4);
        verifyPrepare(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, x2, &x1, 0, 1);
        assert(scp.mEnvs.size() == 4);

        recvVBlocking(makePrepareGen(qSetHash, x2, &x2, 1, 1));
        // v-blocking prepared (2,x) . prepared (2,x)
        assert(scp.mEnvs.size() == 5);
        verifyPrepare(scp.mEnvs[4], v0SecretKey, v0PublicKey, qSetHash0, 0, x2, &x2, 0, 1);

        recvQuorum(makePrepareGen(qSetHash, x2, &x2, 1, 1));
        // quorum (including us) confirms (2,x) prepared . set h=c=x2
        // we also get extra message: a quorum not including us confirms (1,x)
        // prepared
        //  . we confirm c=h=x1
        assert(scp.mEnvs.size() == 7);
        verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0, 0, x2, &x2, 2, 2);
        verifyConfirm(scp.mEnvs[6], v0SecretKey, v0PublicKey, qSetHash0, 0, 2, x2, 1, 1);
    }

    //SECTION("timeout after prepare, receive old messages to prepare")
    {
        assert(scp.bumpState(0, xValue));

        SCPBallot x1 = SCPBallot(1, xValue);

        assert(scp.mEnvs.size() == 1);
        verifyPrepare(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, x1);

        scp.receiveEnvelope(makePrepare(v1SecretKey, v1PublicKey, qSetHash, 0, x1));
        scp.receiveEnvelope(makePrepare(v2SecretKey, v2PublicKey, qSetHash, 0, x1));
        scp.receiveEnvelope(makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, x1));

        // quorum . prepared (1,x)
        assert(scp.mEnvs.size() == 2);
        verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, x1, &x1);

        SCPBallot x2 = SCPBallot(2, xValue);
        // timeout from local node
        assert(scp.bumpState(0, xValue));
        // prepares (2,x)
        assert(scp.mEnvs.size() == 3);
        verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, x2, &x1);

        SCPBallot x3 = SCPBallot(3, xValue);
        // timeout again
        assert(scp.bumpState(0, xValue));
        // prepares (3,x)
        assert(scp.mEnvs.size() == 4);
        verifyPrepare(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, x3, &x1);

        // other nodes moved on with x2
        scp.receiveEnvelope(
            makePrepare(v1SecretKey, v1PublicKey, qSetHash, 0, x2, &x2, 1, 2));
        scp.receiveEnvelope(
            makePrepare(v2SecretKey, v2PublicKey, qSetHash, 0, x2, &x2, 1, 2));
        // v-blocking . prepared x2
        assert(scp.mEnvs.size() == 5);
        verifyPrepare(scp.mEnvs[4], v0SecretKey, v0PublicKey, qSetHash0, 0, x3, &x2);

        scp.receiveEnvelope(
            makePrepare(v3SecretKey, v3PublicKey, qSetHash, 0, x2, &x2, 1, 2));
        // quorum . set nH=2
        assert(scp.mEnvs.size() == 6);
        verifyPrepare(scp.mEnvs[5], v0SecretKey, v0PublicKey, qSetHash0, 0, x3, &x2, 0, 2);
    }

    //SECTION("non validator watching the network")
    {
        mixin SIMULATION_CREATE_NODE!"NV";
        TestSCP scpNV = new TestSCP(vNVNodeID, qSet, false);
        scpNV.storeQuorumSet(makeSharedSCPQuorumSet(qSet));
        uint256 qSetHashNV = scpNV.mSCP.getLocalNode().getQuorumSetHash();

        SCPBallot b = SCPBallot(1, xValue);
        assert(scpNV.bumpState(0, xValue));
        assert(scpNV.mEnvs.size() == 0);
        verifyPrepare(scpNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey, vNVPublicKey,
                      qSetHashNV, 0, b);
        auto ext1 = makeExternalize(v1SecretKey, v1PublicKey, qSetHash, 0, b, 1);
        auto ext2 = makeExternalize(v2SecretKey, v2PublicKey, qSetHash, 0, b, 1);
        auto ext3 = makeExternalize(v3SecretKey, v3PublicKey, qSetHash, 0, b, 1);
        auto ext4 = makeExternalize(v4SecretKey, v4PublicKey, qSetHash, 0, b, 1);
        scpNV.receiveEnvelope(ext1);
        scpNV.receiveEnvelope(ext2);
        scpNV.receiveEnvelope(ext3);
        assert(scpNV.mEnvs.size() == 0);
        verifyConfirm(scpNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey, vNVPublicKey,
                      qSetHashNV, 0, uint32_t.max, SCPBallot(uint32_t.max, xValue),
                      1, uint32_t.max);
        scpNV.receiveEnvelope(ext4);
        assert(scpNV.mEnvs.size() == 0);
        verifyExternalize(scpNV.getCurrentEnvelope(0, vNVNodeID), vNVSecretKey, vNVPublicKey,
                          qSetHashNV, 0, b, uint32_t.max);
        assert(scpNV.mExternalizedValues[0] == xValue);
    }

    //SECTION("restore ballot protocol")
    {
        TestSCP scp2 = new TestSCP(v0NodeID, qSet);
        scp2.storeQuorumSet(makeSharedSCPQuorumSet(qSet));
        SCPBallot b = SCPBallot(2, xValue);
        //SECTION("prepare")
        {
            auto val = makePrepare(v0SecretKey, v0PublicKey, qSetHash0, 0, b);
            scp2.mSCP.setStateFromEnvelope(
                0, val);
        }
        //SECTION("confirm")
        {
            auto val = makeConfirm(v0SecretKey, v0PublicKey, qSetHash0, 0, 2, b, 1, 2);
            scp2.mSCP.setStateFromEnvelope(
                0, val);
        }
        //SECTION("externalize")
        {
            auto val = makeExternalize(v0SecretKey, v0PublicKey, qSetHash0, 0, b, 2);
            scp2.mSCP.setStateFromEnvelope(
                0, val);
        }
    }
}

//TEST_CASE("ballot protocol core3", "[scp][ballotprotocol]")
unittest
{
    setupValues();
    mixin SIMULATION_CREATE_NODE!0;
    mixin SIMULATION_CREATE_NODE!1;
    mixin SIMULATION_CREATE_NODE!2;

    // core3 has an edge case where v-blocking and quorum can be the same
    // v-blocking set size: 2
    // threshold: 2 = 1 + self or 2 others
    SCPQuorumSet qSet;
    qSet.threshold = 2;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);

    const bytes = ByteSlice.make(XDRToOpaque(qSet));
    uint256 qSetHash = sha256(bytes);

    TestSCP scp = new TestSCP(v0NodeID, qSet);

    scp.storeQuorumSet(makeSharedSCPQuorumSet(qSet));
    uint256 qSetHash0 = scp.mSCP.getLocalNode().getQuorumSetHash();

    // todo
    //assert(xValue < yValue);
    //assert(yValue < zValue);

    auto recvQuorumChecksEx2 = (genEnvelope gen, bool withChecks,
                                   bool delayedQuorum, bool checkUpcoming,
                                   bool minQuorum) {
        SCPEnvelope e1 = gen(v1SecretKey, v1PublicKey);
        SCPEnvelope e2 = gen(v2SecretKey, v2PublicKey);

        scp.bumpTimerOffset();

        size_t i = scp.mEnvs.size() + 1;
        scp.receiveEnvelope(e1);
        if (withChecks && !delayedQuorum)
        {
            assert(scp.mEnvs.size() == i);
        }
        if (checkUpcoming)
        {
            assert(scp.hasBallotTimerUpcoming());
        }
        if (!minQuorum)
        {
            // nothing happens with an extra vote (unless we're in
            // delayedQuorum)
            scp.receiveEnvelope(e2);
            if (withChecks)
            {
                assert(scp.mEnvs.size() == i);
            }
        }
    };

    auto recvQuorumChecksEx = (genEnvelope gen, bool withChecks,
                               bool delayedQuorum, bool checkUpcoming)
    {
        return recvQuorumChecksEx2(gen, withChecks, delayedQuorum, checkUpcoming,
            false);
    };

    auto recvQuorumChecks = (genEnvelope gen, bool withChecks, bool delayedQuorum)
    {
        return recvQuorumChecksEx(gen, withChecks, delayedQuorum, false);
    };

    auto recvQuorumEx = (genEnvelope gen, bool checkUpcoming)
    {
        return recvQuorumChecksEx(gen, true, false, checkUpcoming);
    };

    auto recvQuorum = (genEnvelope gen)
    {
        return recvQuorumEx(gen, false);
    };

    // no timer is set
    assert(!scp.hasBallotTimer());

    Value aValue = zValue;
    Value bValue = xValue;

    SCPBallot A1 = SCPBallot(1, aValue);
    SCPBallot B1 = SCPBallot(1, bValue);

    SCPBallot A2 = A1;
    A2.counter++;

    SCPBallot A3 = A2;
    A3.counter++;

    SCPBallot A4 = A3;
    A4.counter++;

    SCPBallot A5 = A4;
    A5.counter++;

    SCPBallot AInf = SCPBallot(uint32_t.max, aValue);
    SCPBallot BInf = SCPBallot(uint32_t.max, bValue);

    SCPBallot B2 = B1;
    B2.counter++;

    SCPBallot B3 = B2;
    B3.counter++;

    assert(scp.bumpState(0, aValue));
    assert(scp.mEnvs.size() == 1);
    assert(!scp.hasBallotTimer());

    //SECTION("prepared B1 (quorum votes B1)")
    {
        scp.bumpTimerOffset();
        recvQuorumChecks(makePrepareGen(qSetHash, B1), true, true);
        assert(scp.mEnvs.size() == 2);
        verifyPrepare(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &B1);
        assert(scp.hasBallotTimerUpcoming());
        //SECTION("quorum prepared B1")
        {
            scp.bumpTimerOffset();
            recvQuorumChecks(makePrepareGen(qSetHash, B1, &B1), false, false);
            assert(scp.mEnvs.size() == 2);
            // nothing happens:
            // computed_h = B1 (2)
            //    does not actually update h as b > computed_h
            //    also skips (3)
            assert(!scp.hasBallotTimerUpcoming());
            //SECTION("quorum bumps to A1")
            {
                scp.bumpTimerOffset();
                recvQuorumChecksEx2(makePrepareGen(qSetHash, A1, &B1), false,
                                    false, false, true);

                assert(scp.mEnvs.size() == 3);
                // still does not set h as b > computed_h
                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0, A1, &A1,
                              0, 0, &B1);
                assert(!scp.hasBallotTimerUpcoming());

                scp.bumpTimerOffset();
                // quorum commits A1
                recvQuorumChecksEx2(
                    makePrepareGen(qSetHash, A2, &A1, 1, 1, &B1), false, false,
                    false, true);
                assert(scp.mEnvs.size() == 4);
                verifyConfirm(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0, 2, A1, 1,
                              1);
                assert(!scp.hasBallotTimerUpcoming());
            }
        }
    }
}

//TEST_CASE("nomination tests core5", "[scp][nominationprotocol]")
unittest
{
    setupValues();
    mixin SIMULATION_CREATE_NODE!0;
    mixin SIMULATION_CREATE_NODE!1;
    mixin SIMULATION_CREATE_NODE!2;
    mixin SIMULATION_CREATE_NODE!3;
    mixin SIMULATION_CREATE_NODE!4;

    // we need 5 nodes to avoid sharing various thresholds:
    // v-blocking set size: 2
    // threshold: 4 = 3 + self or 4 others
    SCPQuorumSet qSet;
    qSet.threshold = 4;
    qSet.validators.push_back(v0NodeID);
    qSet.validators.push_back(v1NodeID);
    qSet.validators.push_back(v2NodeID);
    qSet.validators.push_back(v3NodeID);
    qSet.validators.push_back(v4NodeID);

    const bytes = ByteSlice.make(XDRToOpaque(qSet));
    uint256 qSetHash = sha256(bytes);

    // todo
    //assert(xValue < yValue);
    //assert(yValue < zValue);

    auto checkLeaders = (TestSCP scp, set!NodeID expectedLeaders)
    {
        auto l = scp.getNominationLeaders(0);
        assert(l.size() == expectedLeaders.size());

        // todo: figure out compiler error, enable equality checks later
        //assert(equal(l, expectedLeaders));
    };

    //SECTION("nomination - v0 is top")
    {
        TestSCP scp = new TestSCP(v0NodeID, qSet);
        uint256 qSetHash0 = scp.mSCP.getLocalNode().getQuorumSetHash();
        scp.storeQuorumSet(makeSharedSCPQuorumSet(qSet));

        //SECTION("v0 starts to nominates xValue")
        {
            assert(scp.nominate(0, xValue, false));

            checkLeaders(scp, set!NodeID(v0NodeID));

            //SECTION("others nominate what v0 says (x) . prepare x")
            {
                vector!Value votes, accepted;
                votes.push_back(xValue);

                assert(scp.mEnvs.size() == 1);
                verifyNominate(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, votes,
                               accepted);

                SCPEnvelope nom1 =
                    makeNominate(v1SecretKey, v1PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope nom2 =
                    makeNominate(v2SecretKey, v2PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope nom3 =
                    makeNominate(v3SecretKey, v3PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope nom4 =
                    makeNominate(v4SecretKey, v4PublicKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                scp.receiveEnvelope(nom1);
                scp.receiveEnvelope(nom2);
                assert(scp.mEnvs.size() == 1);

                // this causes 'x' to be accepted (quorum)
                scp.receiveEnvelope(nom3);
                assert(scp.mEnvs.size() == 2);

                scp.mExpectedCandidates.insert(xValue);
                scp.mCompositeValue = xValue;

                accepted.push_back(xValue);
                verifyNominate(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, votes,
                               accepted);

                // extra message doesn't do anything
                scp.receiveEnvelope(nom4);
                assert(scp.mEnvs.size() == 2);

                SCPEnvelope acc1 =
                    makeNominate(v1SecretKey, v1PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope acc2 =
                    makeNominate(v2SecretKey, v2PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope acc3 =
                    makeNominate(v3SecretKey, v3PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope acc4 =
                    makeNominate(v4SecretKey, v4PublicKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                scp.receiveEnvelope(acc1);
                scp.receiveEnvelope(acc2);
                assert(scp.mEnvs.size() == 2);

                scp.mCompositeValue = xValue;
                // this causes the node to send a prepare message (quorum)
                scp.receiveEnvelope(acc3);
                assert(scp.mEnvs.size() == 3);

                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0,
                              SCPBallot(1, xValue));

                scp.receiveEnvelope(acc4);
                assert(scp.mEnvs.size() == 3);

                vector!Value votes2 = votes;
                votes2.push_back(yValue);

                //SECTION(
                //    "nominate x . accept x . prepare (x) ; others accepted y "
                //    ". update latest to (z=x+y)")
                {
                    SCPEnvelope acc1_2 =
                        makeNominate(v1SecretKey, v1PublicKey, qSetHash, 0, votes2, votes2);
                    SCPEnvelope acc2_2 =
                        makeNominate(v2SecretKey, v2PublicKey, qSetHash, 0, votes2, votes2);
                    SCPEnvelope acc3_2 =
                        makeNominate(v3SecretKey, v3PublicKey, qSetHash, 0, votes2, votes2);
                    SCPEnvelope acc4_2 =
                        makeNominate(v4SecretKey, v4PublicKey, qSetHash, 0, votes2, votes2);

                    scp.receiveEnvelope(acc1_2);
                    assert(scp.mEnvs.size() == 3);

                    // v-blocking
                    scp.receiveEnvelope(acc2_2);
                    assert(scp.mEnvs.size() == 4);
                    verifyNominate(scp.mEnvs[3], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                   votes2, votes2);

                    scp.mExpectedCandidates.insert(yValue);
                    scp.mCompositeValue = kValue;
                    // this updates the composite value to use next time
                    // but does not prepare it
                    scp.receiveEnvelope(acc3_2);
                    assert(scp.mEnvs.size() == 4);

                    assert(scp.getLatestCompositeCandidate(0) == kValue);

                    scp.receiveEnvelope(acc4_2);
                    assert(scp.mEnvs.size() == 4);
                }
                //SECTION("nomination - restored state")
                {
                    TestSCP scp2 = new TestSCP(v0NodeID, qSet);
                    scp2.storeQuorumSet(makeSharedSCPQuorumSet(qSet));

                    // at this point
                    // votes = { x }
                    // accepted = { x }

                    // tests if nomination proceeds like normal
                    // nominates x
                    auto nominationRestore = () {
                        // restores from the previous state
                        auto val1 = makeNominate(v0SecretKey, v0PublicKey, qSetHash0, 0, votes, accepted);
                        scp2.mSCP.setStateFromEnvelope(
                            0, val1);
                        // tries to start nomination with yValue
                        assert(scp2.nominate(0, yValue, false));

                        checkLeaders(scp2, set!NodeID(v0NodeID));

                        assert(scp2.mEnvs.size() == 1);
                        verifyNominate(scp2.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                       votes2, accepted);

                        // other nodes vote for 'x'
                        scp2.receiveEnvelope(nom1);
                        scp2.receiveEnvelope(nom2);
                        assert(scp2.mEnvs.size() == 1);
                        // 'x' is accepted (quorum)
                        // but because the restored state already included
                        // 'x' in the accepted set, no new message is emitted
                        scp2.receiveEnvelope(nom3);

                        scp2.mExpectedCandidates.insert(xValue);
                        scp2.mCompositeValue = xValue;

                        // other nodes not emit 'x' as accepted
                        scp2.receiveEnvelope(acc1);
                        scp2.receiveEnvelope(acc2);
                        assert(scp2.mEnvs.size() == 1);

                        scp2.mCompositeValue = xValue;
                        // this causes the node to update its composite value to
                        // x
                        scp2.receiveEnvelope(acc3);
                    };

                    //SECTION("ballot protocol not started")
                    {
                        nominationRestore();
                        // nomination ended up starting the ballot protocol
                        assert(scp2.mEnvs.size() == 2);

                        verifyPrepare(scp2.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0,
                                      SCPBallot(1, xValue));
                    }
                    //SECTION("ballot protocol started (on value k)")
                    {
                        auto val2 = makePrepare(v0SecretKey, v0PublicKey, qSetHash0, 0, SCPBallot(1, kValue));
                        scp2.mSCP.setStateFromEnvelope(
                            0, val2);
                        nominationRestore();
                        // nomination didn't do anything (already working on k)
                        assert(scp2.mEnvs.size() == 1);
                    }
                }
            }
            //SECTION(
                //"receive more messages, then v0 switches to a different leader")
            {
                vector!Value val1;
                val1.push_back(kValue);

                vector!Value val2;
                val2.push_back(yValue);

                SCPEnvelope nom1 =
                    makeNominate(v1SecretKey, v1PublicKey, qSetHash, 0, val1);
                SCPEnvelope nom2 =
                    makeNominate(v2SecretKey, v2PublicKey, qSetHash, 0, val2);

                // nothing more happens
                scp.receiveEnvelope(nom1);
                scp.receiveEnvelope(nom2);
                assert(scp.mEnvs.size() == 1);

                // switch leader to v1
                scp.mPriorityLookup = (ref const(NodeID) n) {
                    return (n == v1NodeID) ? 1000 : 1;
                };
                assert(scp.nominate(0, xValue, true));
                assert(scp.mEnvs.size() == 2);

                vector!Value votesXK;

                if (xValue[] < kValue[])
                {
                    votesXK.push_back(xValue);
                    votesXK.push_back(kValue);
                }
                else
                {
                    votesXK.push_back(kValue);
                    votesXK.push_back(xValue);
                }

                verifyNominate(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, votesXK);
            }
        }
        //SECTION("self nominates 'x', others nominate y . prepare y")
        {
            vector!Value myVotes, accepted;
            myVotes.push_back(xValue);

            scp.mExpectedCandidates.insert(xValue);
            scp.mCompositeValue = xValue;
            assert(scp.nominate(0, xValue, false));

            assert(scp.mEnvs.size() == 1);
            verifyNominate(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, myVotes,
                           accepted);

            vector!Value votes;
            votes.push_back(yValue);

            vector!Value acceptedY = accepted;

            acceptedY.push_back(yValue);

            //SECTION("others only vote for y")
            {
                SCPEnvelope nom1 =
                    makeNominate(v1SecretKey, v1PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope nom2 =
                    makeNominate(v2SecretKey, v2PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope nom3 =
                    makeNominate(v3SecretKey, v3PublicKey, qSetHash, 0, votes, accepted);
                SCPEnvelope nom4 =
                    makeNominate(v4SecretKey, v4PublicKey, qSetHash, 0, votes, accepted);

                // nothing happens yet
                scp.receiveEnvelope(nom1);
                scp.receiveEnvelope(nom2);
                scp.receiveEnvelope(nom3);
                assert(scp.mEnvs.size() == 1);

                // 'y' is accepted (quorum)
                scp.receiveEnvelope(nom4);
                assert(scp.mEnvs.size() == 2);
                myVotes.push_back(yValue);
                verifyNominate(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, myVotes,
                               acceptedY);
            }
            //SECTION("others accepted y")
            {
                SCPEnvelope acc1 =
                    makeNominate(v1SecretKey, v1PublicKey, qSetHash, 0, votes, acceptedY);
                SCPEnvelope acc2 =
                    makeNominate(v2SecretKey, v2PublicKey, qSetHash, 0, votes, acceptedY);
                SCPEnvelope acc3 =
                    makeNominate(v3SecretKey, v3PublicKey, qSetHash, 0, votes, acceptedY);
                SCPEnvelope acc4 =
                    makeNominate(v4SecretKey, v4PublicKey, qSetHash, 0, votes, acceptedY);

                scp.receiveEnvelope(acc1);
                assert(scp.mEnvs.size() == 1);

                // this causes 'y' to be accepted (v-blocking)
                scp.receiveEnvelope(acc2);
                assert(scp.mEnvs.size() == 2);

                myVotes.push_back(yValue);
                verifyNominate(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, myVotes,
                               acceptedY);

                scp.mExpectedCandidates.clear();
                scp.mExpectedCandidates.insert(yValue);
                scp.mCompositeValue = yValue;
                // this causes the node to send a prepare message (quorum)
                scp.receiveEnvelope(acc3);
                assert(scp.mEnvs.size() == 3);

                verifyPrepare(scp.mEnvs[2], v0SecretKey, v0PublicKey, qSetHash0, 0,
                              SCPBallot(1, yValue));

                scp.receiveEnvelope(acc4);
                assert(scp.mEnvs.size() == 3);
            }
        }
    }
    //SECTION("v1 is top node")
    {
        TestSCP scp = new TestSCP(v0NodeID, qSet);
        uint256 qSetHash0 = scp.mSCP.getLocalNode().getQuorumSetHash();
        scp.storeQuorumSet(makeSharedSCPQuorumSet(qSet));

        scp.mPriorityLookup = (ref const(NodeID) n) {
            return (n == v1NodeID) ? 1000 : 1;
        };

        vector!Value votesX, votesY, votesK, votesXY, votesYK, votesXK,
            emptyV;
        votesX.push_back(xValue);
        votesY.push_back(yValue);
        votesK.push_back(kValue);

        votesXY.push_back(xValue);
        votesXY.push_back(yValue);

        votesYK.push_back(yValue);
        votesYK.push_back(kValue);
        // todo
        //std.sort(votesYK.begin(), votesYK.end());

        votesXK.push_back(xValue);
        votesXK.push_back(kValue);
        //std.sort(votesXK.begin(), votesXK.end());

        vector!Value valuesHash;
        valuesHash.push_back(xValue);
        valuesHash.push_back(yValue);
        valuesHash.push_back(kValue);
        //std.sort(valuesHash.begin(), valuesHash.end());

        scp.mHashValueCalculator = (ref const(Value) v)
        {
            foreach (idx, val; valuesHash[])
            {
                if (val == v)
                    return 1 + idx;
            }

            // value should have been there
            assert(0);
        };

        SCPEnvelope nom1 =
            makeNominate(v1SecretKey, v1PublicKey, qSetHash, 0, votesXY, emptyV);
        SCPEnvelope nom2 =
            makeNominate(v2SecretKey, v2PublicKey, qSetHash, 0, votesXK, emptyV);

        //SECTION("nomination waits for v1")
        {
            assert(!scp.nominate(0, xValue, false));

            checkLeaders(scp, set!NodeID(v1NodeID));

            assert(scp.mEnvs.size() == 0);

            SCPEnvelope nom3 =
                makeNominate(v3SecretKey, v3PublicKey, qSetHash, 0, votesYK, emptyV);
            SCPEnvelope nom4 =
                makeNominate(v4SecretKey, v4PublicKey, qSetHash, 0, votesXK, emptyV);

            // nothing happens with non top nodes
            scp.receiveEnvelope(nom2);
            scp.receiveEnvelope(nom3);
            assert(scp.mEnvs.size() == 0);

            scp.receiveEnvelope(nom1);
            assert(scp.mEnvs.size() == 1);
            verifyNominate(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, votesY,
                           emptyV);

            scp.receiveEnvelope(nom4);
            assert(scp.mEnvs.size() == 1);

            //SECTION("timeout . pick another value from v1")
            {
                scp.mExpectedCandidates.insert(xValue);
                scp.mCompositeValue = xValue;

                // note: value passed in here should be ignored
                assert(scp.nominate(0, kValue, true));
                // picks up 'x' from v1 (as we already have 'y')
                // which also happens to causes 'x' to be accepted
                assert(scp.mEnvs.size() == 2);
                verifyNominate(scp.mEnvs[1], v0SecretKey, v0PublicKey, qSetHash0, 0, votesXY,
                               votesX);
            }
        }
        //SECTION("v1 dead, timeout")
        {
            assert(!scp.nominate(0, xValue, false));

            assert(scp.mEnvs.size() == 0);

            scp.receiveEnvelope(nom2);
            assert(scp.mEnvs.size() == 0);

            checkLeaders(scp, set!NodeID(v1NodeID));

            //SECTION("v0 is new top node")
            {
                scp.mPriorityLookup = (ref const(NodeID) n) {
                    return (n == v0NodeID) ? 1000 : 1;
                };

                assert(scp.nominate(0, xValue, true));
                checkLeaders(scp,
                    set!NodeID(v0NodeID, v1NodeID));

                assert(scp.mEnvs.size() == 1);
                verifyNominate(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, votesX,
                               emptyV);
            }
            //SECTION("v2 is new top node")
            {
                scp.mPriorityLookup = (ref const(NodeID) n) {
                    return (n == v2NodeID) ? 1000 : 1;
                };

                assert(scp.nominate(0, xValue, true));
                checkLeaders(scp, set!NodeID(v1NodeID, v2NodeID));

                assert(scp.mEnvs.size() == 1);
                // v2 votes for XK, but nomination only picks the highest value
                vector!Value v2Top;
                auto max_val = (max(xValue[], kValue[])).toVec();
                v2Top.push_back(max_val);  // todo
                verifyNominate(scp.mEnvs[0], v0SecretKey, v0PublicKey, qSetHash0, 0, v2Top,
                               emptyV);
            }
            //SECTION("v3 is new top node")
            {
                scp.mPriorityLookup = (ref const(NodeID) n) {
                    return (n == v3NodeID) ? 1000 : 1;
                };
                // nothing happens, we don't have any message for v3
                assert(!scp.nominate(0, xValue, true));
                checkLeaders(scp,
                    set!NodeID(v1NodeID,
                               v3NodeID));

                assert(scp.mEnvs.size() == 0);
            }
        }
    }
}
