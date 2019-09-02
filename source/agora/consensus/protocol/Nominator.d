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
import agora.common.Task;
import agora.consensus.data.Block;
import agora.consensus.Genesis;
import agora.consensus.protocol.Driver;
import agora.network.NetworkClient;
import agora.node.Ledger;

import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types;
import scpd.types.Utils;

import vibe.core.log;

import core.time;

import std.algorithm;
import std.concurrency;

import scpd.types.Stellar_types : StellarHash = Hash;

/// Ditto
class Nominator
{
    /// The public key of this node
    private PublicKey pub_key;

    /// Ledger
    private Ledger ledger;

    /// SCP driver
    private Driver driver;

    /// SCP
    private SCP* scp;

    /// Task manager
    private TaskManager taskman;

    /// Ctor
    public this (Ledger ledger, PublicKey pub_key,
        NetworkClient[PublicKey] nodes, SCPQuorumSet quorum_set,
        TaskManager taskman)
    {
        assert(nodes.length > 0);

        this.pub_key = pub_key;
        this.ledger = ledger;
        this.taskman = taskman;
        this.driver = new Driver(&ledger.validateBlock, nodes, quorum_set);

        // todo: this should be based on the node config
        const IsValidator = true;

        import scpd.types.Stellar_types : StellarHash = Hash;
        auto key = StellarHash(pub_key[]);

        // todo: check if the binary compatibility of the NodeID and Hash are
        // actually compatible => check boa-core and print out some NodeIDs based
        // on existing hashes to make sure this part is correct
        auto node_id = NodeID(key);
        this.scp = createSCP(driver, node_id, IsValidator, quorum_set);

        this.prepareSCP();
        this.startNominationTimer();
    }

    /***************************************************************************

        Start a task which periodically proposes new blocks.

    ***************************************************************************/

    public void startNominationTimer ()
    {
        logInfo("startNominationTimer()");
        this.taskman.runTask(()
        {
            while (1)
            {
                if (this.proposeNewBlock())
                    this.taskman.wait(5.seconds);
                else
                    this.taskman.wait(1.seconds);
            }
        });
    }

    /***************************************************************************

        Called when a new SCP Envelope is received from the network.

        Params:
            envelope = the SCP envelope

        Returns:
            true if the SCP protocol accepted this envelope (todo: describe why)

    ***************************************************************************/

    public bool receiveEnvelope (SCPEnvelope envelope) @safe
    {
        logInfo("%s: %s - %s", __PRETTY_FUNCTION__, "Received an envelope:",
            envelope);

        return () @trusted {
            return this.scp.receiveEnvelope(envelope) == SCP.EnvelopeState.VALID;
        }();
    }

    /***************************************************************************

        Restore SCP's internal state based on the serialized Blockchain

        todo: this currently only restores the genesis block

    ***************************************************************************/

    private void prepareSCP ()
    {
        import agora.common.Serializer;
        import scpd.types.Stellar_SCP;
        import scpd.types.Utils;
        import scpd.types.Stellar_types : StellarHash = Hash, NodeID;

        // Restore the SCP state
        // We should never have an empty SCP state, even in tests,
        // because there is *always* a genesis block used to segment
        // the networks.
        scope (exit)
            if (this.scp.empty()) assert(0);

        logInfo("prepareSCP()");

        // todo: should this be this specific node,
        // or a single agreed-upon hardcoded node?
        auto key = StellarHash(this.pub_key[]);
        auto pub_key = NodeID(key);
        Value gen_value = GenesisBlock.serializeFull().toVec();

        SCPStatement genesis =
        {
            nodeID: pub_key,
            slotIndex: 0,
            pledges: {
                type_: SCPStatementType.SCP_ST_EXTERNALIZE,
                externalize_: {
                    commit: {
                        counter: 0,
                        value: gen_value,
                    },
                    nH: 0,
                },
            },
        };

        // note: cannot verify data in the slot after this point,
        // it's actually in the blockchain, getLatestCompositeCandidate()
        // is only for the candidates.
        // note: when nominating, we use the nomination protocol (via SCP),
        // but when externalizing, we seem to use the ballot protocol instead.
        SCPEnvelope env = SCPEnvelope(genesis);
        this.scp.setStateFromEnvelope(0, env);
        assert(this.scp.isSlotFullyValidated(0));
    }

    /***************************************************************************

        Try to propose a new block to the network.

        Returns:
            true if there were enough transactions in the pool to
            create a block, and the block was nominated and accepted
            by the quorum.

    ***************************************************************************/

    private bool proposeNewBlock () @trusted
    {
        import std.conv;
        import std.stdio;

        Block block;
        if (!this.ledger.tryCreateBlock(block))
        {
            logInfo("proposeNewBlock(): No new block from Ledger yet");
            return false;  // nothing to propose yet
        }

        logInfo("proposeNewBlock(): Ledger created a block for us: %s",
            block.header.height);

        auto last_block = this.ledger.getLastBlock();
        //this.ledger.addValidatedBlock(block);
        //return true;

        //version (none)
        //{
            auto slot_idx = this.scp.getHighSlotIndex();
            logInfo("%s: %s %s", __PRETTY_FUNCTION__, "About to nominate a block at slot index ", slot_idx);
            auto block_vec = block.serializeFull().toVec();
            auto last_block_vec = last_block.serializeFull().toVec();
            if (this.scp.nominate(slot_idx, block_vec, last_block_vec))
            {
                logInfo("%s: %s", __PRETTY_FUNCTION__, "Block nominated");
                this.ledger.addValidatedBlock(block);
                return true;
            }
            else
            {
                logInfo("%s: %s", __PRETTY_FUNCTION__, "Block rejected nomination");
                return false;
            }
        //}
    }
}
