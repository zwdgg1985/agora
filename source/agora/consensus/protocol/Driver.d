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
import agora.common.Serializer;
import agora.consensus.data.Block;
import agora.network.NetworkClient;
import agora.utils.Log;

import scpd.Cpp;
import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.types.Stellar_types;
import scpd.types.Stellar_types : StellarHash = Hash;
import scpd.types.Stellar_SCP;
import scpd.types.Utils;

import core.stdc.stdint;
import std.algorithm;
import std.exception;

mixin AddLogger!();

/// Used for validating proposed blocks
public alias ValidateBlockDg = string delegate(const ref Block block) nothrow @safe;

/// Used for adding a block to the ledger after it was externalized
public alias ExternalizeBlockDg = bool delegate(const ref Block block) @safe;

/// Ditto
public extern (C++) class Driver : SCPDriver
{
    /// Callback to validate blocks with
    private ValidateBlockDg validateBlockDg;

    /// Callback to add externalized blocks to the ledger
    private ExternalizeBlockDg externalizeBlockDg;

    /// This node's quorum node clients
    private NetworkClient[PublicKey] nodes;

    /// Cache of quorum set
    private SCPQuorumSet[StellarHash] quorum_cache;


    /***************************************************************************

        Constructor

        Params:
            validateBlockDg = used for validating proposed blocks
            externalizeBlockDg = used for adding a block to the ledger after
                                 it was externalized
            nodes = the set of clients to the nodes in the quorum
            quorum_set = the quorum set of this node

    ***************************************************************************/

    extern (D) public this (ValidateBlockDg validateBlockDg,
        ExternalizeBlockDg externalizeBlockDg, NetworkClient[PublicKey] nodes,
        SCPQuorumSet quorum_set)
    {
        this.validateBlockDg = validateBlockDg;
        this.externalizeBlockDg = externalizeBlockDg;
        this.nodes = nodes;

        const bs = ByteSlice.make(XDRToOpaque(quorum_set));
        auto quorum_hash = sha256(bs);
        this.quorum_cache[quorum_hash] = quorum_set;
    }

    extern (C++):

    // called when a value was externalized, it triggers another nomination
    // sequence in a given time
    public override void valueExternalized (uint64_t slot_idx,
        ref const(Value) value)
    {
        try
        {
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

    public override ValidationLevel validateValue (uint64_t slot_idx,
        ref const(Value) value, bool nomination) nothrow
    {
        scope (failure) assert(0);
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

        return ValidationLevel.kFullyValidatedValue;
    }

    ///
    public override void signEnvelope (ref SCPEnvelope envelope)
    {
        // todo: add our signature (via schnorr hopefully)
        //log.info("signEnvelope(): envelope");
    }

    ///
    public override SCPQuorumSetPtr getQSet (ref const(StellarHash) qSetHash)
    {
        //log.info("getQSet {}", qSetHash);

        // todo note: if this is enabled, we have to support combineCandidates(),
        // but we need std::set support first.
        if (auto scp_quroum = qSetHash in this.quorum_cache)
        {
            //log.info("Found a quorum with hash {}: {}", qSetHash, *scp_quroum);
            return SCPQuorumSetPtr(scp_quroum);
        }

        return SCPQuorumSetPtr.init;
    }

    ///
    public override void emitEnvelope (ref const(SCPEnvelope) envelope)
    {
        scope (failure) assert(0);

        foreach (key, node; this.nodes)
        {
            log.info("emitEnvelope(): Sending envelope to {}", key);

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
        scope (failure) assert(0);
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

    ///
    public override void setupTimer()
    {
        //log.info("setupTimer()");
    }
}
