/*******************************************************************************

    Defines the data structure of a transaction

    The current design is heavily influenced by Bitcoin: as we have a UTXO,
    starting with a simple input/output approach seems to make the most sense.
    Script is not implemented: instead, we currently only have a simple signature
    verification step.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.Transaction;

import agora.common.Data;
import agora.common.crypto.Key;


/*******************************************************************************

    Currency amount type to use

    This is simply an alias to `long` at the moment, and should be made smarter.
    Currently this has two major drawbacks:
    - It does not do any overflow / underflow checks (over the total amount)
    - It can go negative
    We should probably wrap this in a smarter type to do currency operations,
    and move it to a shared location, as currency operations might be performed
    independently of `Transaction`.

*******************************************************************************/

public alias Amount = long;

/*******************************************************************************

    Represents a transaction (shortened as 'tx')

    Agora uses a UTXO model for transactions, so the transaction format is
    originally derived from that of Bitcoin.

*******************************************************************************/

public struct Transaction
{
    /// The list of unspent `outputs` from previous transaction(s) that will be spent
    public Input[] inputs;

    /// The list of newly created outputs to put in the UTXO
    public Output[] outputs;
}

/*******************************************************************************

    Represents an entry in the UTXO

    This is created by a valid `Transaction` and is added to the UTXO after
    a transaction is confirmed.

*******************************************************************************/

public struct Output
{
    /// The monetary value of this output, in 1/10^7
    public Amount value;

    /// The public key that can redeem this output (A = pubkey)
    /// Note that in Bitcoin, this is an address (the double hash of a pubkey)
    public PublicKey address;
}

/// The input of the transaction, which spends a previously received `Output`
public struct Input
{
    /// The hash of a previous transaction containing the `Output` to spend
    public Hash previous;

    /// Index of the `Output` in the `previous` `Transaction`
    public uint index;

    /// A signature that should be verified using the `previous[index].address` public key
    public Signature signature;
}