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
import agora.node.Ledger;

import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.types.Stellar_types;
import scpd.types.Stellar_SCP;
import scpd.types.Utils;

import vibe.core.log;

import core.stdc.stdint;
import std.algorithm;

import scpd.types.Stellar_types : StellarHash = Hash;

/// SCP validation driver
class Driver : SCPDriver
{
    /// Ledger instance
    private Ledger ledger;

    /// This node's quorum node clients
    private NetworkClient[PublicKey] nodes;

    /// Cache of quorum set
    private SCPQuorumSet[StellarHash] quorum_cache;


    /// Constructor
    public this (Ledger ledger, NetworkClient[PublicKey] nodes,
        SCPQuorumSet[StellarHash] quorum_cache)
    {
        this.ledger = ledger;
        this.nodes = nodes;
        this.quorum_cache = quorum_cache;
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

        if (!this.ledger.isValidBlock(block))
            return ValidationLevel.kInvalidValue;

        return ValidationLevel.kFullyValidatedValue;
    }

    ///
    public override void signEnvelope (ref SCPEnvelope envelope)
    {
        // todo: add our signature (via schnorr hopefully)
        logInfo("%s: %s", __PRETTY_FUNCTION__, "envelope");
    }

    ///
    public override bool verifyEnvelope (ref const(SCPEnvelope) envelope)
    {
        // todo: this is only about verifying the signatures
        // and not verifying that the block is valid,
        // although it might be a good idea to validate the block too.
        logInfo("%s", __PRETTY_FUNCTION__);
        return true;

        //auto block_height = envelope.statement.slotIndex;
        //auto pledge = envelope.statement.pledges;

        //switch (pledge.type_)
        //{
        //    // todo: should we only verify blocks in prepare messages?
        //    case SCPStatementType.SCP_ST_PREPARE:
        //    {
        //        import agora.common.Deserializer;
        //        auto value = pledge.prepare_.ballot.value;

        //        auto block_bytes = cast(ubyte[])value._start[0 .. value._end - value._start];
        //        auto block = deserialize!Block(block_bytes);

        //        // todo: check with the Ledger if this is a valid block
        //        return true;
        //    }

        //    case SCPStatementType.SCP_ST_CONFIRM:
        //    case SCPStatementType.SCP_ST_EXTERNALIZE:
        //    case SCPStatementType.SCP_ST_NOMINATE:
        //    default: assert(0);
        //}
    }

    ///
    public override SCPQuorumSetPtr getQSet (ref const(StellarHash) qSetHash)
    {
        logInfo("%s: %s", __PRETTY_FUNCTION__, qSetHash);

        if (auto scp_quroum = qSetHash in this.quorum_cache)
        {
            return SCPQuorumSetPtr(scp_quroum);
        }

        return SCPQuorumSetPtr.init;
    }

    ///
    public override void emitEnvelope (ref const(SCPEnvelope) envelope)
    {
        foreach (key, node; this.nodes)
        {
            auto env = cast()envelope;

            // cannot deal with const parameter types in the API
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
