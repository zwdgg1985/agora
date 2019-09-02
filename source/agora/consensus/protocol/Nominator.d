/*******************************************************************************

    Contains the SCP consensus driver implementation.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.protocol.Nominator;

import agora.common.Config;
import agora.common.crypto.Key;
import agora.common.Serializer;
import agora.consensus.data.Block;
import agora.consensus.protocol.Driver;
import agora.network.NetworkClient;
import agora.node.Ledger;

import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types;
import scpd.types.Utils;

import vibe.core.log;

import std.algorithm;
import std.concurrency;

class Nominator
{
    /// Ledger
    private Ledger ledger;

    private Driver driver;

    /// SCP
    public SCP* scp;

    import scpd.types.Stellar_types : StellarHash = Hash;


    /// Ctor
    public this (Ledger ledger, PublicKey pub_key,
        NetworkClient[PublicKey] nodes, SCPQuorumSet quorum_set,
        SCPQuorumSet[StellarHash] quorum_cache)
    {
        assert(nodes.length > 0);
        assert(ledger !is null);
        assert(quorum_cache.length > 0);

        this.ledger = ledger;
        this.driver = new Driver(ledger, nodes, quorum_cache);

        const IsValidator = true;
        import scpd.types.Stellar_types : StellarHash = Hash;
        auto key = StellarHash(pub_key[]);

        auto node_id = NodeID(key);
        this.scp = createSCP(driver, node_id, IsValidator,
            quorum_set);
    }

    /// Forward received envelope to the SCP instance
    public bool receiveEnvelope (SCPEnvelope envelope) @safe
    {
        logInfo("%s: %s - %s", __PRETTY_FUNCTION__, "Received an envelope:",
            envelope);

        return () @trusted {
            return this.scp.receiveEnvelope(envelope) == SCP.EnvelopeState.VALID;
        }();
    }

    public void proposeNewBlock () @trusted
    {
        //updateRoundLeaders

        //import std.conv;
        //import std.stdio;

        //logInfo("%s: %s", __PRETTY_FUNCTION__, "About to create a block");
        //Block block;
        //if (!this.ledger.createBlock(block))
        //    return;

        //auto last_block = this.ledger.getLastBlock();

        //auto last_block_vec = last_block.serializeFull().toVec();
        //auto block_vec = block.serializeFull().toVec();

        //auto slot_idx = this.scp.getHighSlotIndex();

        //logInfo("%s: %s %s", __PRETTY_FUNCTION__, "About to nominate a block at slot index ", slot_idx);
        //if (this.scp.nominate(slot_idx, block_vec, last_block_vec))
        //{
        //    logInfo("%s: %s", __PRETTY_FUNCTION__, "Block nominated");
        //    this.ledger.addValidatedBlock(block);
        //}
        //else
        //{
        //    logInfo("%s: %s", __PRETTY_FUNCTION__, "Block rejected nomination");
        //}
    }
}
