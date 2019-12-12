/*******************************************************************************

    Contains tests for banning of unreachable nodes or in situations
    where timeouts fail or time-out.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.test.BanManager;

version (unittest):

import agora.common.crypto.Key;
import agora.common.Types;
import agora.common.Hash;
import agora.consensus.data.Block;
import agora.consensus.data.Transaction;
import agora.consensus.Genesis;
import agora.test.Base;

/// test node banning after putTransaction fails a number of times
unittest
{
    import core.thread;
    import std.algorithm;
    import std.conv;
    import std.range;
    const NodeCount = 2;

    const long retry_delay = 10;
    const size_t max_retries = 10;
    const long timeout = 10;
    const size_t max_failed_requests = 4 * Block.TxsInBlock;

    auto network = makeTestNetwork(NetworkTopology.Simple, NodeCount, true,
        retry_delay, max_retries, timeout, max_failed_requests);
    network.start();
    scope(exit) network.shutdown();
    scope(failure) network.printLogs();
    assert(network.getDiscoveredNodes().length == NodeCount);

    auto keys = network.apis.keys;
    auto node_1 = network.apis[keys[0]];
    auto node_2 = network.apis[keys[1]];
    auto nodes = [node_1, node_2];
    auto gen_key = getGenesisKeyPair();

    Transaction[] all_txs;
    Transaction[] last_txs;

    // generate enough transactions to form 'count' blocks
    Transaction[] genBlockTransactions (size_t count)
    {
        auto txes = makeChainedTransactions(gen_key, last_txs, count);
        // keep track of last tx's to chain them to
        last_txs = txes[$ - Block.TxsInBlock .. $];
        all_txs ~= txes;
        return txes;
    }


    genBlockTransactions(1).each!(tx => node_1.putTransaction(tx));
    // need to wait for propagation to finish before offsetting time
    Thread.sleep(200.msecs);
    nodes.each!(node => node.ctrl.offsetTime(10.minutes));

    // wait until the transactions were gossiped
    retryFor(node_1.getBlockHeight() == 1, 4.seconds);

    node_1.filter!(node_1.getBlocksFrom);  // node 1 won't send block
    node_2.filter!(node_2.putTransaction); // node 2 won't receive txs

    // leftover txs which node 2 rejected due to filter
    Transaction[] left_txs;

    foreach (idx; 0 .. 4)
    {
        auto new_tx = genBlockTransactions(1);
        left_txs ~= new_tx;
        new_tx.each!(tx => node_1.putTransaction(tx));

        Thread.sleep(200.msecs);
        nodes.each!(node => node.ctrl.offsetTime(10.minutes));

        // need to wait for the block to be generated
        retryFor(node_1.getBlockHeight() == 1 + idx + 1, 4.seconds);
    }

    // wait for node 2 to be banned and all putTransaction requests to time-out
    Thread.sleep(2.seconds);

    retryFor(node_1.getBlockHeight() == 5, 1.seconds);
    retryFor(node_2.getBlockHeight() == 1, 1.seconds);

    // clear putTransaction filter
    node_2.clearFilter();

    foreach (idx; 0 .. 4)
    {
        auto txs = left_txs[0 .. 8];
        left_txs = left_txs[8 .. $];
        txs.each!(tx => node_2.putTransaction(tx));  // add leftover txs
        Thread.sleep(200.msecs);  // wait for propagation
        node_2.ctrl.offsetTime(10.minutes);

        retryFor(node_2.getBlockHeight() == 1 + idx + 1, 1.seconds);
    }

    // node 2 should be banned by this point
    auto new_tx = genBlockTransactions(1);
    left_txs ~= new_tx;
    new_tx.each!(tx => node_1.putTransaction(tx));
    Thread.sleep(200.msecs);  // wait for propagation
    nodes.each!(node => node.ctrl.offsetTime(10.minutes));
    retryFor(node_1.getBlockHeight() == 6, 1.seconds);
    retryFor(node_2.getBlockHeight() == 5, 1.seconds);  // node was banned

    left_txs.each!(tx => node_2.putTransaction(tx));  // add leftover txs
    Thread.sleep(200.msecs);  // wait for propagation
    nodes.each!(node => node.ctrl.offsetTime(10.minutes));
    retryFor(node_1.getBlockHeight() == 6, 1.seconds);
    retryFor(node_2.getBlockHeight() == 6, 1.seconds);

    FakeClockBanManager.time += 500;  // nodes should be unbanned now

    new_tx = genBlockTransactions(1);
    left_txs ~= new_tx;
    new_tx.each!(tx => node_1.putTransaction(tx));
    Thread.sleep(200.msecs);  // wait for propagation
    nodes.each!(node => node.ctrl.offsetTime(10.minutes));
    retryFor(node_1.getBlockHeight() == 7, 1.seconds);
    retryFor(node_2.getBlockHeight() == 7, 1.seconds);  // node was un-banned
}
