/*******************************************************************************

    Contains consensus tests for various types of quorum configurations.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.Consensus;

version (unittest):

import agora.common.Amount;
import agora.common.crypto.Key;
import agora.common.Hash;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Transaction;
import agora.consensus.data.UTXOSet;
import agora.consensus.Genesis;
import agora.test.Base;

version (none):
/// test cyclic quorum config
unittest
{
    import std.algorithm;
    import std.range;
    import core.time;

    const NodeCount = 6;
    auto network = makeTestNetwork(NetworkTopology.Cyclic, NodeCount, true,
        100, 20, 100);  // reduce timeout to 100 msecs
    network.start();
    scope(exit) network.shutdown();
    assert(network.getDiscoveredNodes().length == NodeCount);

    auto nodes = network.apis.values;
    auto node_1 = nodes[0];

    // ignore transaction propagation and periodically retrieve blocks via getBlocksFrom
    nodes[1 .. $].each!(node => node.filter!(node.putTransaction));

    auto txs = makeChainedTransactions(getGenesisKeyPair(), null, 2);
    txs.each!(tx => node_1.putTransaction(tx));
    containSameBlocks(nodes, 2).retryFor(8.seconds);
}
