/*******************************************************************************

    Contains the SCP consensus nominator.

    This class should only be used if the node is a validating node,
    otherwise keeping SCP state is unnecessary.

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
import agora.utils.Log;

import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.scp.Utils;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types;
import scpd.types.Stellar_types : StellarHash = Hash;
import scpd.types.Utils;

import core.time;
import std.algorithm;
import std.concurrency;

mixin AddLogger!();

/// Ditto
class Nominator
{
    /// The public key of this node
    private PublicKey pub_key;

    /// SCP driver
    private Driver driver;

    /// SCP
    private SCP* scp;


    /***************************************************************************

        Constructor

        Params:
            pub_key = public key of this node
            nodes = the map of clients for network I/O that form the quorum
            quorum_set = the configured quorum configuration
            ledger = ledger instance

    ***************************************************************************/

    public this (TaskManager taskman, PublicKey pub_key,
        NetworkClient[PublicKey] nodes, SCPQuorumSet quorum_set, Ledger ledger)
    {
        assert(nodes.length > 0);

        this.pub_key = pub_key;
        this.driver = new Driver(taskman, &ledger.validateBlock,
            &ledger.acceptBlock, nodes, quorum_set);

        import scpd.types.Stellar_types : StellarHash = Hash;
        auto node_id = NodeID(StellarHash(pub_key[]));
        const IsValidator = true;
        this.scp = createSCP(driver, node_id, IsValidator, quorum_set);

        this.prepareSCP(ledger);
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
        log.info("receiveEnvelope()");

        return () @trusted {
            return this.scp.receiveEnvelope(envelope) == SCP.EnvelopeState.VALID;
        }();
    }

    /***************************************************************************

        Restore SCP's internal state based on the provided ledger state

        Params:
            ledger = the ledger instance

    ***************************************************************************/

    private void prepareSCP (Ledger ledger)
    {
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
        auto key = StellarHash(this.pub_key[]);
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

    /***************************************************************************

        Try to propose a new block to the network.

        Returns:
            true if there were enough transactions in the pool to
            create a block, and the block was nominated and accepted
            by the quorum.

    ***************************************************************************/

    public void nominateBlock (Block last_block, Block block) @trusted
    {
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
}
