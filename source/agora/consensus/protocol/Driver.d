/*******************************************************************************

    Contains the SCP consensus driver implementation.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.protocol.Driver;

import agora.common.crypto.Key;
import agora.common.Deserializer;
import agora.common.Hash : hashFull;
import agora.common.Serializer;
import agora.common.Set;
import agora.common.Task;
import agora.consensus.data.Block;
import agora.network.NetworkClient;
import agora.node.Ledger;
import agora.utils.Log;

import scpd.Cpp;
import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.scp.Utils;
import scpd.types.Stellar_types;
import scpd.types.Stellar_types : StellarHash = Hash;
import scpd.types.Stellar_SCP;
import scpd.types.Utils;

import core.stdc.stdint;
//import std.algorithm;
//import std.exception;

mixin AddLogger!();

/// Used for validating proposed blocks
public alias ValidateBlockDg = string delegate(const ref Block block) nothrow @safe;

/// Used for adding a block to the ledger after it was externalized
public alias ExternalizeBlockDg = bool delegate(const ref Block block) @safe;

void print (T...)(T args) nothrow
{
    try
    {
        import std.stdio;
        writefln(args);
    }
    catch (Exception ex)
    {

    }
}

/// Ditto
public extern (C++) class Driver : SCPDriver
{
    /// SCP
    private SCP* scp;

    /// Key pair of this node
    private KeyPair key_pair;

    /// Task manager
    private TaskManager taskman;

    /// Callback to validate blocks with
    private ValidateBlockDg validateBlockDg;

    /// Callback to add externalized blocks to the ledger
    private ExternalizeBlockDg externalizeBlockDg;

    /// This node's quorum node clients
    private NetworkClient[PublicKey] peers;

extern(D):

    /// overridable by tests
    public uint64_t delegate(ref const(Value)) nothrow mHashValueCalculator;

    private SCPQuorumSetPtr[Hash] mQuorumSets;
    private SCPEnvelope[] mEnvs;
    private Set!uint64_t mExternalizedValues;

    // note: only used in tests in SCPTests.cpp, might want to check what
    // the herder does
    private const(SCPBallot)[][uint64_t] mHeardFromQuorums;

    // todo: use one-shot timers
    //struct TimerData
    //{
    //    std::chrono::milliseconds mAbsoluteTimeout;
    //    std::function<void()> mCallback;
    //};

    //std::map<int, TimerData> mTimers;
    //std::chrono::milliseconds mCurrentTimerOffset;

    /***************************************************************************

        Constructor

        Params:
            key_pair = the key pair of this node
            ledger = needed for SCP state restoration & block validation
            taskman = used to run timers
            peers = the set of clients to the peers in the quorum
            quorum_set = the quorum set of this node

    ***************************************************************************/

    public this (KeyPair key_pair, Ledger ledger,
        TaskManager taskman, NetworkClient[PublicKey] peers,
        SCPQuorumSet quorum_set)
    {
        print("%s Driver.ctor", this.key_pair.address);
        this.key_pair = key_pair;
        import scpd.types.Stellar_types : StellarHash = Hash;
        auto node_id = NodeID(StellarHash(key_pair.address[]));
        const IsValidator = true;
        this.scp = createSCP(this, node_id, IsValidator, quorum_set);

        this.taskman = taskman;

        this.validateBlockDg = &ledger.validateBlock;
        this.externalizeBlockDg = &ledger.acceptBlock;
        this.peers = peers;
        this.prepareSCP(ledger);

        this.mHashValueCalculator = (ref const(Value)) => 0;

        auto local_quorum_set = this.scp.getLocalQuorumSet();
        auto localQSet =
            makeSharedSCPQuorumSet(local_quorum_set);
        this.storeQuorumSet(localQSet);
    }

    /***************************************************************************

        Try to propose a new block to the network.

        Returns:
            true if there were enough transactions in the pool to
            create a block, and the block was nominated and accepted
            by the quorum.

    ***************************************************************************/

    public void nominateBlock (Block last_block, Block block) @trusted
    {
        print("%s nominateBlock", this.key_pair.address);

        auto slot_idx = last_block.header.height + 1;
        log.info("proposeNewBlock(): Proposing block for slot {}", slot_idx);

        auto new_block_vec = block.serializeFull().toVec();
        auto last_block_vec = last_block.serializeFull().toVec();
        if (this.scp.nominate(slot_idx, new_block_vec, last_block_vec))
        {
            log.info("proposeNewBlock(): Block nominated");
        }
        else
        {
            log.info("proposeNewBlock(): Block rejected nomination");
        }
    }

    /***************************************************************************

        Restore SCP's internal state based on the provided ledger state

        Params:
            ledger = the ledger instance

    ***************************************************************************/

    private void prepareSCP (Ledger ledger)
    {
        print("%s prepareSCP", this.key_pair.address);

        import agora.common.Serializer;
        import scpd.types.Stellar_SCP;
        import scpd.types.Utils;
        import scpd.types.Stellar_types : StellarHash = Hash, NodeID;
        import std.range;

        // Restore the SCP state
        // We should never have an empty SCP state, even in tests,
        // because there is *always* a genesis block used to segment
        // the networks.
        scope (exit)
            if (this.scp.empty()) assert(0);

        log.info("prepareSCP()");
        auto key = StellarHash(this.key_pair.address[]);
        auto pub_key = NodeID(key);

        foreach (block_idx, block; ledger.getBlocksFrom(0).enumerate)
        {
            Value block_value = block.serializeFull().toVec();

            SCPStatement statement =
            {
                nodeID: pub_key,
                slotIndex: block_idx,
                pledges: {
                    type_: SCPStatementType.SCP_ST_EXTERNALIZE,
                    externalize_: {
                        commit: {
                            counter: 0,
                            value: block_value,
                        },
                        nH: 0,
                    },
                },
            };

            SCPEnvelope env = SCPEnvelope(statement);
            this.scp.setStateFromEnvelope(block_idx, env);
            if (!this.scp.isSlotFullyValidated(block_idx))
                assert(0);
        }
    }

    // todo: for tests we should dependency-inject a version of the node
    // which implements this mPriorityLookup and uses it in the public
    // override of computeHashNode()
    private uint64_t mPriorityLookup (ref const(NodeID) node_id) nothrow
    {
        print("%s mPriorityLookup", this.key_pair.address);

        return (node_id == scp.getLocalNodeID()) ? 1000 : 1;
    }

    /***************************************************************************

        Called when a new SCP Envelope is received from the network.

        Params:
            envelope = the SCP envelope

        Returns:
            true if the SCP protocol accepted this envelope

    ***************************************************************************/

    public bool receiveEnvelope (SCPEnvelope envelope) @safe
    {
        print("%s receiveEnvelope", this.key_pair.address);

        if (!this.verifyEnvelope(envelope))
        {
            log.info("Invalid envelope: %s", envelope);
            return false;
        }

        log.info("receiveEnvelope()");

        return () @trusted {
            return this.scp.receiveEnvelope(envelope) == SCP.EnvelopeState.VALID;
        }();
    }

    private bool verifyEnvelope (SCPEnvelope envelope) @trusted
    {
        print("%s verifyEnvelope", this.key_pair.address);

        return true;

        // todo: implement proper support for this
        version (none)
        {
            // todo: this should verify more than the statement, but also the
            // xdr::xdr_to_opaque(mApp.getNetworkID(), ENVELOPE_TYPE_SCP, envelope.statement)
            // todo: check how the herder signs it:
            //     envelope.signature = s.sign(xdr::xdr_to_opaque(
            // mApp.getNetworkID(), ENVELOPE_TYPE_SCP, envelope.statement));

            const bytes = ByteSlice.make(XDRToOpaque(envelope.statement));
            auto statement_hash = sha256(bytes);
            auto pub_key = PublicKey(envelope.statement.nodeID[]);

            //public alias Signature = BitBlob!512;

            import agora.common.Types;
            auto sig = Signature(envelope.signature[]);
            return pub_key.verify(sig, statement_hash[]);
        }
    }

    /// todo: same part as TestNominationSCP, therefore it should work
    extern (C++):

    ///
    public override void signEnvelope (ref SCPEnvelope envelope)
    {
        print("%s signEnvelope", this.key_pair.address);

        // todo: implement proper support for this
        version (none)
        {
            const bytes = ByteSlice.make(XDRToOpaque(envelope.statement));
            auto statement_hash = sha256(bytes);
            import scpd.types.Stellar_types;

            envelope.signature = Signature(
                this.key_pair.secret.sign(statement_hash[])[]);
        }
    }

    // todo: this is called in tests too for some reason
    private void storeQuorumSet(SCPQuorumSetPtr qSet)
    {
        print("%s storeQuorumSet", this.key_pair.address);

        // todo
        const bytes = ByteSlice.make(XDRToOpaque(*qSet));
        auto quorum_hash = sha256(bytes);
        mQuorumSets[quorum_hash] = qSet;
    }

    public override ValidationLevel validateValue (uint64_t slot_idx,
        ref const(Value) value, bool nomination) nothrow
    {
        print("%s validateValue", this.key_pair.address);

        scope (failure) assert(0);

        try
        {
            log.info("validateValue(): Before block is deserialized");
            Block block;

            // todo: stellar does upgrade path checks in this code,
            // we don't have version upgrade support yet, but we can
            // add it here in the future

            try
            {
                auto block_bytes = cast(ubyte[])value._start[0 .. value._end - value._start];
                block = deserializeFull!Block(block_bytes);
            }
            catch (Exception ex)
            {
                log.error("{}: Received invalid block. Error: {}",
                    __FUNCTION__, ex.message);

                // todo: keep track of failed blocks, in order to ban the IP?
                return ValidationLevel.kInvalidValue;
            }

            if (auto fail_reason = this.validateBlockDg(block))
            {
                log.error("validateValue(): Invalid block: {}", fail_reason);
                return ValidationLevel.kInvalidValue;
            }
        }
        catch (Throwable ex)
        {
            import std.stdio;
            writefln(" --- ERROR: %s", ex);
            throw ex;
        }

        return ValidationLevel.kFullyValidatedValue;
    }

    public override void ballotDidHearFromQuorum (uint64_t slotIndex,
        ref const(SCPBallot) ballot) nothrow
    {
        print("%s ballotDidHearFromQuorum", this.key_pair.address);

        import std.stdio;
        try { stderr.writefln("index %s found ballot", slotIndex); } catch (Exception ex) { }
        mHeardFromQuorums[slotIndex] ~= ballot;
    }

    public override void valueExternalized (uint64_t slot_idx,
        ref const(Value) value)
    {
        print("%s valueExternalized", this.key_pair.address);

        try
        {
            // todo: ignore this just like HerderSCPDriver
            //if (slotIndex <= mApp.getHerder().getCurrentLedgerSeq())

            if (slot_idx in this.mExternalizedValues)
                assert(0, "This slot was already externalized!");
            this.mExternalizedValues.put(slot_idx);

            import std.stdio;
            auto block_bytes = cast(ubyte[])value._start[0 .. value._end - value._start];
            auto block = deserializeFull!Block(block_bytes);
            log.info("Externalized block at {}: {}", slot_idx,
                block.header.height);
            if (!this.externalizeBlockDg(block))
                assert(0);
        }
        catch (Exception ex)
        {
            try { log.info("Exception: {}", ex.msg); } catch (Exception) { }
            assert(0);
        }
    }

    ///
    public override SCPQuorumSetPtr getQSet (ref const(StellarHash) qSetHash)
    {
        print("%s getQSet", this.key_pair.address);

        if (auto scp_quroum = qSetHash in this.mQuorumSets)
            return *scp_quroum;

        return SCPQuorumSetPtr.init;
    }

    /// todo: in tests this just appends
    public override void emitEnvelope (ref const(SCPEnvelope) envelope)
    {
        print("%s emitEnvelope", this.key_pair.address);
        scope (failure) assert(0);

        foreach (key, node; this.peers)
        {
            log.info("{} emitEnvelope(): Sending envelope to {}",
                this.key_pair.address, key);

            // cannot deal with const parameter types in the API
            auto env = cast()envelope;
            if (!node.sendEnvelope(env))
            {
                // drey todo: why does sending an envelope fail?
                // because something is already considered externalized?
                //assert(0);  // todo: handle failure
            }
        }
    }


    /***************************************************************************

        Combine a set of candidate Blocks into a single Block.

        todo: replace this with transaction sets

        Params:
            slot_idx = the index of the candidate slot
            candidates = a set of candidate blocks

    ***************************************************************************/

    public override Value combineCandidates (uint64_t slot_idx,
        ref const(set!Value) candidates)
    {
        print("%s combineCandidates", this.key_pair.address);
        scope (failure) assert(0);

        // todo:
        //if (candidates.empty())
        //    assert(0, "Unexpected empty candidates");

        Value combined;
        foreach (ref const(Value) candidate; candidates)
        {
            auto block_bytes = cast(ubyte[])candidate._start[0 .. candidate._end - candidate._start];
            auto block = deserializeFull!Block(block_bytes);
            log.error("candidate block: {}", block.header.height);

            if (auto msg = this.validateBlockDg(block))
            {
                log.error("combineCandidates(): Invalid block: {} - {}",
                    msg, block.header.height);

                continue;
            }
            else
            {
                log.info("combineCandidates: {}", slot_idx);
            }

            // todo: currently we just pick the first of the candidate values
            if (combined == Value.init)
            {
                combined = block.serializeFull().toVec();
                break;
            }
        }

        assert(combined != Value.init);
        return combined;
    }

    // override the internal hashing scheme in order to make tests
    // more predictable.
    public override uint64_t computeHashNode (uint64_t slotIndex,
        ref const(Value) prev, bool isPriority, int32_t roundNumber,
        ref const(NodeID) nodeID)
    {
        print("%s computeHashNode", this.key_pair.address);
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
    public override uint64_t computeValueHash (uint64_t slotIndex,
        ref const(Value) prev, int32_t roundNumber, ref const(Value) value)
    {
        print("%s computeValueHash", this.key_pair.address);
        return mHashValueCalculator(value);
    }

    ///
    public override void setupTimer (ulong slotIndex, int timerID,
        chrono.duration timeout, cppdelegate!StellarCallback* cb)
    {
        print("%s setupTimer", this.key_pair.address);

        import core.time;
        scope (failure) assert(0);

        if (timeout == 0)  // todo: this should disable the timer @ timerID
            return;

        log.info("-- setupTimer(): slotIndex {}, timerID {}, timeout {}, cb {}",
            slotIndex, timerID, timeout, &cb);

        this.taskman.runTask(
        {
            this.taskman.wait(timeout.msecs);
            callCallback(cb);
        });
    }
}
