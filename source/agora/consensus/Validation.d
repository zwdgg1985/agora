/*******************************************************************************

    Contains validation routines for all data types required for consensus.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.Validation;

import agora.common.Amount;
import agora.common.crypto.Key;
import agora.common.Hash;
import agora.consensus.data.Block;
import agora.consensus.data.Transaction;
import agora.consensus.Genesis;

/// Delegate to find an unspent UTXO
public alias UtxoFinder = scope bool delegate (Hash hash, size_t index,
    out Output) @safe nothrow;

/*******************************************************************************

    Get result of transaction data and signature verification

    Params:
        tx = `Transaction`
        findOutput = delegate for finding `Output`

    Return:
        Return true if this transaction is verified.

*******************************************************************************/

public bool isValid (const Transaction tx, UtxoFinder findOutput)
    @safe nothrow
{
    if (tx.inputs.length == 0)
        return false;

    if (tx.outputs.length == 0)
        return false;

    // disallow negative amounts
    foreach (output; tx.outputs)
        if (!output.value.isValid())
            return false;

    Amount sum_unspent;

    const tx_hash = hashFull(tx);
    foreach (input; tx.inputs)
    {
        // all referenced outputs must be present
        Output output;
        if (!findOutput(input.previous, input.index, output))
            return false;

        if (!output.address.verify(input.signature, tx_hash[]))
            return false;

        if (!sum_unspent.add(output.value))
            return false;
    }

    Amount new_unspent;
    return tx.getSumOutput(new_unspent) && sum_unspent.sub(new_unspent);
}

/// verify transaction data
unittest
{
    import std.format;

    Transaction[Hash] storage;
    KeyPair[] key_pairs = [KeyPair.random, KeyPair.random, KeyPair.random, KeyPair.random];

    // Creates the first transaction.
    Transaction previousTx = newCoinbaseTX(key_pairs[0].address, Amount(100));

    // Save
    Hash previousHash = hashFull(previousTx);
    storage[previousHash] = previousTx;

    // Creates the second transaction.
    Transaction secondTx = Transaction(
        [
            Input(previousHash, 0)
        ],
        [
            Output(Amount(50), key_pairs[1].address)
        ]
    );

    // delegate for finding `Output`
    scope findOutput = (Hash hash, size_t index, out Output output)
    {
        if (auto tx = hash in storage)
        {
            if (index < tx.outputs.length)
            {
                output = tx.outputs[index];
                return true;
            }
        }

        return false;
    };

    secondTx.inputs[0].signature = key_pairs[0].secret.sign(hashFull(secondTx)[]);

    // It is validated. (the sum of `Output` < the sum of `Input`)
    assert(secondTx.isValid(findOutput), format("Transaction data is not validated %s", secondTx));

    secondTx.outputs ~= Output(Amount(50), key_pairs[2].address);
    secondTx.inputs[0].signature = key_pairs[0].secret.sign(hashFull(secondTx)[]);

    // It is validated. (the sum of `Output` == the sum of `Input`)
    assert(secondTx.isValid(findOutput), format("Transaction data is not validated %s", secondTx));

    secondTx.outputs ~= Output(Amount(50), key_pairs[3].address);
    secondTx.inputs[0].signature = key_pairs[0].secret.sign(hashFull(secondTx)[]);

    // It isn't validated. (the sum of `Output` > the sum of `Input`)
    assert(!secondTx.isValid(findOutput), format("Transaction data is not validated %s", secondTx));
}

/// negative output amounts disallowed
unittest
{
    KeyPair[] key_pairs = [KeyPair.random(), KeyPair.random()];
    Transaction tx_1 = newCoinbaseTX(key_pairs[0].address, Amount(1000));
    Hash tx_1_hash = hashFull(tx_1);

    Transaction[Hash] storage;
    storage[tx_1_hash] = tx_1;

    // delegate for finding `Output`
    scope findOutput = (Hash hash, size_t index, out Output output)
    {
        if (auto tx = hash in storage)
        {
            if (index < tx.outputs.length)
            {
                output = tx.outputs[index];
                return true;
            }
        }

        return false;
    };

    // Creates the second transaction.
    Transaction tx_2 =
    {
        inputs  : [Input(tx_1_hash, 0)],
        // oops
        outputs : [Output(Amount.invalid(-400_000), key_pairs[1].address)]
    };

    tx_2.inputs[0].signature = key_pairs[0].secret.sign(hashFull(tx_2)[]);

    assert(!tx_2.isValid(findOutput));
}

/// This creates a new transaction and signs it as a publickey
/// of the previous transaction to create and validate the input.
unittest
{
    import std.format;

    Transaction[Hash] storage;

    immutable(KeyPair)[] key_pairs;
    key_pairs ~= KeyPair.random();
    key_pairs ~= KeyPair.random();
    key_pairs ~= KeyPair.random();

    // delegate for finding `Output`
    scope findOutput = (Hash hash, size_t index, out Output output)
    {
        if (auto tx = hash in storage)
        {
            if (index < tx.outputs.length)
            {
                output = tx.outputs[index];
                return true;
            }
        }

        return false;
    };

    // Create the first transaction.
    Transaction genesisTx = newCoinbaseTX(key_pairs[0].address, Amount(100_000));
    Hash genesisHash = hashFull(genesisTx);
    storage[genesisHash] = genesisTx;
    genesisTx.inputs[0].signature = key_pairs[0].secret.sign(hashFull(genesisTx)[]);

    // Create the second transaction.
    Transaction tx1 = Transaction(
        [
            Input(genesisHash, 0)
        ],
        [
            Output(Amount(1_000), key_pairs[1].address)
        ]
    );

    // Signs the previous hash value.
    Hash tx1Hash = hashFull(tx1);
    tx1.inputs[0].signature = key_pairs[0].secret.sign(tx1Hash[]);
    storage[tx1Hash] = tx1;

    assert(tx1.isValid(findOutput), format("Transaction signature is not validated %s", tx1));

    Transaction tx2 = Transaction(
        [
            Input(tx1Hash, 0)
        ],
        [
            Output(Amount(1_000), key_pairs[1].address)
        ]
    );

    Hash tx2Hash = hashFull(tx2);
    // Sign with incorrect key
    tx2.inputs[0].signature = key_pairs[2].secret.sign(tx2Hash[]);
    storage[tx2Hash] = tx2;
    // Signature verification must be error
    assert(!tx2.isValid(findOutput), format("Transaction signature is not validated %s", tx2));
}

/*******************************************************************************

    Check the validity of a block.

    A block is considered valid if:
        - its height is the previous block height + 1
        - its prev_hash is the previous block header's hash
        - the number of transactions in the block are equal to Block.TxsInBlock
        - the merkle root in the header matches the re-built merkle tree root
          based on the included transactions in the block
        - all the the transactions pass validation, which implies:
            - signatures are authentic
            - the inputs spend an output which must be found with the
              findOutput() delegate

    Note that checking for transactions which double-spend is the responsibility
    of the findOutput() delegate. During validation, whenever this delegate is
    called it should also keep track of the used UTXOs, thereby marking
    it as a spent output. See the `findNotDoubleSpent` function in the
    unittest for an example.

    Params:
        block = the block to check
        prev_height = the height of the previous block which this
                      block should point to
        findOutput = delegate to find the referenced unspent UTXOs with

    Returns:
        true if the block is considered valid

*******************************************************************************/

public bool isValid (const ref Block block, in ulong prev_height,
    in Hash prev_hash, UtxoFinder findOutput) nothrow @safe
{
    import std.algorithm;

    // special case for the genesis block
    if (block.header.height == 0)
    {
        return () @trusted
        {
            try { return block == getGenesisBlock(); }
            catch (Exception) { assert(0); }
        }();
    }

    if (block.header.height != prev_height + 1)
        return false;

    if (block.header.prev_block != prev_hash)
        return false;

    if (block.txs.length != Block.TxsInBlock)
        return false;

    if (block.txs.any!(tx => !tx.isValid(findOutput)))
        return false;

    static Hash[] merkle_tree;
    if (block.header.merkle_root != Block.buildMerkleTree(block.txs, merkle_tree))
        return false;

    return true;
}

///
unittest
{
    import agora.consensus.Genesis;
    import std.algorithm;
    import std.range;

    // note: using array as a workaround to be able to store const Transactions
    const(Transaction)[][Hash] tx_map;
    scope findOutput = (Hash hash, size_t index, out Output output)
    {
        if (auto tx = hash in tx_map)
        {
            if (index < (*tx).front.outputs.length)
            {
                output = (*tx).front.outputs[index];
                return true;
            }
        }

        return false;
    };

    auto gen_key = getGenesisKeyPair();
    auto gen_block = getGenesisBlock();
    assert(gen_block.isValid(gen_block.header.height, Hash.init, null));
    auto gen_hash = gen_block.header.hashFull();

    auto gen_tx = gen_block.txs[0];
    tx_map[gen_tx.hashFull()] = [gen_tx];
    auto txs = makeChainedTransactions(gen_key, null, 1);
    auto block = makeNewBlock(gen_block, txs);

    // height checks
    assert(block.isValid(gen_block.header.height, gen_hash, findOutput));

    block.header.height = 100;
    assert(!block.isValid(gen_block.header.height, gen_hash, findOutput));

    block.header.height = gen_block.header.height + 1;
    assert(block.isValid(gen_block.header.height, gen_hash, findOutput));

    /// .pref_block check
    block.header.prev_block = block.header.hashFull();
    assert(!block.isValid(gen_block.header.height, gen_hash, findOutput));

    block.header.prev_block = gen_hash;
    assert(block.isValid(gen_block.header.height, gen_hash, findOutput));

    /// .txs length check
    block.txs = txs[0 .. $ - 1];
    assert(!block.isValid(gen_block.header.height, gen_hash, findOutput));

    block.txs = txs ~ txs;
    assert(!block.isValid(gen_block.header.height, gen_hash, findOutput));

    block.txs = txs;
    assert(block.isValid(gen_block.header.height, gen_hash, findOutput));

    /// no matching utxo => fail
    tx_map.clear();
    assert(!block.isValid(gen_block.header.height, gen_hash, findOutput));

    tx_map[gen_tx.hashFull()] = [gen_tx];
    assert(block.isValid(gen_block.header.height, gen_hash, findOutput));

    tx_map.clear();  // genesis is spent
    auto prev_txs = txs;
    prev_txs.each!(tx => tx_map[tx.hashFull()] = [tx]);  // these will be spent

    auto prev_block = block;
    txs = makeChainedTransactions(gen_key, prev_txs, 1);
    block = makeNewBlock(prev_block, txs);
    assert(block.isValid(prev_block.header.height, prev_block.header.hashFull(),
        findOutput));

    assert(prev_txs.length > 0);  // sanity check
    foreach (tx; prev_txs)
    {
        // one utxo missing from the set => fail
        tx_map.remove(tx.hashFull);
        assert(!block.isValid(prev_block.header.height, prev_block.header.hashFull(),
            findOutput));

        tx_map[tx.hashFull] = [tx];
        assert(block.isValid(prev_block.header.height, prev_block.header.hashFull(),
            findOutput));
    }

    // the key is hashMulti(hash(prev_tx), index)
    Output[Hash] utxo_set;

    foreach (idx, output; gen_tx.outputs)
        utxo_set[hashMulti(gen_tx.hashFull, idx)] = output;

    assert(utxo_set.length != 0);
    const utxo_set_len = utxo_set.length;

    // contains the used set of UTXOs during validation (to prevent double-spend)
    Output[Hash] used_set;
    UtxoFinder findNotDoubleSpent = (Hash hash, size_t index, out Output output)
    {
        auto utxo_hash = hashMulti(hash, index);

        if (utxo_hash in used_set)
            return false;  // double-spend

        if (auto utxo = utxo_hash in utxo_set)
        {
            used_set[utxo_hash] = *utxo;
            output = *utxo;
            return true;
        }

        return false;
    };

    // consumed all utxo => fail
    txs = makeChainedTransactions(gen_key, null, 1);
    block = makeNewBlock(gen_block, txs);
    assert(block.isValid(gen_block.header.height, gen_block.header.hashFull(),
            findNotDoubleSpent));

    assert(used_set.length == utxo_set_len);  // consumed all utxos

    // reset state
    used_set.clear();

    // consumed same utxo twice => fail
    txs[$ - 1] = txs[$ - 2];
    block = makeNewBlock(gen_block, txs);
    assert(!block.isValid(gen_block.header.height, gen_block.header.hashFull(),
            findNotDoubleSpent));

    // we stopped validation due to a double-spend
    assert(used_set.length == txs.length - 1);

    txs = makeChainedTransactions(gen_key, prev_txs, 1);
    block = makeNewBlock(gen_block, txs);
    assert(block.isValid(gen_block.header.height, gen_block.header.hashFull(),
        findOutput));

    // modify the last hex byte of the merkle root
    block.header.merkle_root = Hash("0x18cb29d05b784548fe385401df4e0a920d254" ~
        "dd3c59ab8942888e40211acf05581ad8547a2c7d37d532a1465cdba0acaa2492f49" ~
        "f30331cabebe2464c89e1554");

    assert(!block.isValid(gen_block.header.height, gen_block.header.hashFull(),
        findOutput));

    // now modify it back to what it was
    block.header.merkle_root = Hash("0x18cb29d05b784548fe385401df4e0a920d254" ~
        "dd3c59ab8942888e40211acf05581ad8547a2c7d37d532a1465cdba0acaa2492f49" ~
        "f30331cabebe2464c89e1553");
    assert(block.isValid(gen_block.header.height, gen_block.header.hashFull(),
        findOutput));

    // txs with a different amount
    txs = makeChainedTransactions(gen_key, prev_txs, 1, 20_000_000);
    block = makeNewBlock(gen_block, txs);
    assert(block.isValid(gen_block.header.height, gen_block.header.hashFull(),
        findOutput));

    // the previous merkle root should not match these txs
    block.header.merkle_root = Hash("0x18cb29d05b784548fe385401df4e0a920d254" ~
        "dd3c59ab8942888e40211acf05581ad8547a2c7d37d532a1465cdba0acaa2492f49" ~
        "f30331cabebe2464c89e1553");
    assert(!block.isValid(gen_block.header.height, gen_block.header.hashFull(),
        findOutput));
}
