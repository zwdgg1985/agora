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

import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.types.Stellar_types;
import scpd.types.Stellar_SCP;
import scpd.types.Utils;

import vibe.core.log;

import core.stdc.stdint;
import std.algorithm;

import scpd.types.Stellar_types : StellarHash = Hash;

/// Validator delegate type
public alias ValidateBlockDg = string delegate(const ref Block block) nothrow @safe;

/// SCP validation driver
public extern(C++) class Driver : SCPDriver
{
    /// Callback to validate blocks with
    private ValidateBlockDg validateBlockDg;

    /// This node's quorum node clients
    private NetworkClient[PublicKey] nodes;

    /// Cache of quorum set
    private SCPQuorumSet[StellarHash] quorum_cache;


    /// Constructor
    extern(D) public this (ValidateBlockDg validateBlockDg,
        NetworkClient[PublicKey] nodes, SCPQuorumSet quorum_set)
    {
        this.validateBlockDg = validateBlockDg;
        this.nodes = nodes;

        const bs = ByteSlice.make(XDRToOpaque(quorum_set));
        auto quorum_hash = sha256(bs);
        this.quorum_cache[quorum_hash] = quorum_set;
    }

    extern (C++):

    public override ValidationLevel validateValue (uint64_t slotIndex,
        ref const(Value) value, bool nomination) nothrow
    {
        logInfo("%s: %s", __PRETTY_FUNCTION__, "Before block is deserialized");
        Block block;

        // todo: stellar does upgrade path checks in this code,
        // we don't have version upgrade support yet, but we can
        // add it here in the future

        try
        {
            auto block_bytes = cast(ubyte[])value._start[0 .. value._end - value._start];
            block = deserialize!Block(block_bytes);
        }
        catch (Exception ex)
        {
            logError("%s: Received invalid block. Error: %s",
                __PRETTY_FUNCTION__, ex.message);

            // todo: keep track of failed blocks, in order to ban the IP?
            return ValidationLevel.kInvalidValue;
        }

        logInfo("%s: %s", __PRETTY_FUNCTION__, "Block was deserialized");

        if (auto fail_reason = this.validateBlockDg(block))
        {
            logError("validateValue(): Invalid block: %s", fail_reason);
            return ValidationLevel.kInvalidValue;
        }

        logInfo("%s: %s", __PRETTY_FUNCTION__, "Block is valid!");
        return ValidationLevel.kFullyValidatedValue;
    }

    ///
    public override void signEnvelope (ref SCPEnvelope envelope)
    {
        // todo: add our signature (via schnorr hopefully)
        logInfo("%s: %s", __PRETTY_FUNCTION__, "envelope");
    }

    ///
    public override SCPQuorumSetPtr getQSet (ref const(StellarHash) qSetHash)
    {
        logInfo("%s: %s", __PRETTY_FUNCTION__, qSetHash);

        // todo: this segfaults
        //if (auto scp_quroum = qSetHash in this.quorum_cache)
        //{
        //    return SCPQuorumSetPtr(scp_quroum);
        //}

        return SCPQuorumSetPtr.init;
    }

    ///
    public override void emitEnvelope (ref const(SCPEnvelope) envelope)
    {
        foreach (key, node; this.nodes)
        {
            logInfo("Sending envelope to %s", key);

            // cannot deal with const parameter types in the API
            auto env = cast()envelope;
            if (!node.sendEnvelope(env))
                assert(0);  // todo: handle failure
        }
    }

    ///
    public override Value combineCandidates (uint64_t slotIndex,
        ref const(Value)* candidates)
    {
        // todo: in Stellar this is used for
        // - upgrading the protocol
        // - selecting the block with the biggest set of transactions,
        // and highest xored hash
        logInfo("%s: %s %p", __PRETTY_FUNCTION__, slotIndex, candidates);
        //abort();
        assert(0);
    }

    ///
    public override void setupTimer()
    {
        logInfo("%s", __PRETTY_FUNCTION__);
    }
}
