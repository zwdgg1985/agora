/*******************************************************************************

    Contains the unspent transaction output set implementation

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.UtxoSet;

import agora.common.Hash;
import agora.common.Serializer;
import agora.common.Set;
import agora.consensus.data.Transaction;
import agora.consensus.Validation;

import d2sqlite3.database;
import d2sqlite3.library;
import d2sqlite3.results;
import d2sqlite3.sqlite3;

import std.algorithm;
import std.conv;
import std.exception;
import std.file;
import std.range;
import std.path;

/*******************************************************************************

    Utxo map backed by SQLite

*******************************************************************************/

public class UtxoDb
{
    /// SQLite db instance
    private Database db;


    /***************************************************************************

        Constructor

    ***************************************************************************/

    public this ()
    {
        const db_path = ":memory:";  // todo: replace

        //const db_exists = db_path.exists;
        //if (db_exists)
        //    logInfo("Loading database from: %s", db_path);

        // note: can fail. we may want to just recover txes from the network instead.
        this.db = Database(db_path);

        //if (db_exists)
        //    logInfo("Loaded database from: %s", db_path);

        // create the table if it doesn't exist yet
        this.db.execute("CREATE TABLE IF NOT EXISTS utxo_map " ~
            "(key BLOB PRIMARY KEY, val BLOB NOT NULL)");
    }


    /***************************************************************************

        Shut down the database

        Note: this method must be called explicitly, and not inside of
        a destructor.

    ***************************************************************************/

    public void shutdown ()
    {
        this.db.close();
    }

    /***************************************************************************

        Look up the output in the map, and store it to 'output' if found

        Returns:
            true if the output was found

    ***************************************************************************/

    public bool find (string op : "in")(Hash key, out Output output)
        @nogc const nothrow @safe
    {
        auto results = db.execute("SELECT val FROM utxo_map WHERE key = ?",
            key[]);

        foreach (row; results)
        {
            output = deserialize!Output(row.peek!(ubyte[])(1));
            return true;
        }

        return false;
    }

    /***************************************************************************

        Add an Output to the map

    ***************************************************************************/

    public void opIndexAssign (Hash key, Output output) nothrow @safe
    {
        static ubyte[] buffer;
        buffer.length = 0;
        () @trusted { assumeSafeAppend(buffer); }();

        scope SerializeDg dg = (scope const(ubyte[]) data) nothrow @safe
        {
            buffer ~= data;
        };

        serializePart(output, dg);

        () @trusted {
            try
            {
                db.execute("INSERT INTO utxo_map (key, val) VALUES (?, ?)",
                    key[], buffer);
            }
            catch (Exception ex)
            {
                assert(0);
            }
        }();
    }

    /***************************************************************************

        Remove an Output from the map

    ***************************************************************************/

    public void remove (Hash key) nothrow
    {
        try
        {
            db.execute("DELETE FROM utxo_map WHERE key = ?", key[]);
        }
        catch (Exception ex)
        {
            assert(0);
        }
    }
}

public class GenerationalUtxoMap
{
    /// Change later
    private const MaxRecentUtxos = 1024;

    /// Most recent unspent outputs
    private Output[Hash] utxo_map;

    /// Unspent outputs in the database
    private UtxoDb utxo_db;

    /// used to track which Outputs should be moved from utxo_map => utxo_db
    private Hash[MaxRecentUtxos] most_recent_utxos;

    public Output* opBinaryRight (string op : "in")(Hash key) const nothrow @safe
    {
        if (auto output = key in this.utxo_map)
            return output;

        Output output;
        if (this.utxo_db.find(key, output))
        {
            this.utxo_db.remove(key);

        }

        if (auto output = key in this.utxo_db)
        {
        }

        // must deserialize
    }
}

/// ditto
public class UtxoSet
{
    /// Unspent outputs
    private Output[Hash] utxo_map;

    /// Set of consumed outputs during validation
    private Set!Hash used_utxos;


    /***************************************************************************

        Constructor

        Params:
            utxo_set_path = path to the utxo set

    ***************************************************************************/

    public this (in string utxo_set_path)
    {

    }

    /***************************************************************************

        Add all of a transaction's outputs to the Utxo set,
        and remove the spent outputs in the transaction from the set.

        Params:
            tx = the transaction

    ***************************************************************************/

    public void updateUtxoSet (const ref Transaction tx) nothrow @safe
    {
        foreach (input; tx.inputs)
        {
            auto utxo_hash = hashMulti(input.previous, cast(size_t)input.index);
            this.utxo_map.remove(utxo_hash);
        }

        Hash tx_hash = tx.hashFull();
        foreach (idx, output; tx.outputs)
        {
            auto utxo_hash = hashMulti(tx_hash, cast(size_t)idx);
            this.utxo_map[utxo_hash] = output;
        }
    }

    /***************************************************************************

        Prepare tracking double-spend and return the UtxoFinder delegate

        Returns:
            the UtxoFinder delegate

    ***************************************************************************/

    public UtxoFinder getUtxoFinder () nothrow @safe
    {
        // clear used UTXOs
        this.used_utxos.clear();
        return &this.findOutput;
    }

    /***************************************************************************

        Find an unspent Output in the UTXO set.

        Params:
            tx_hash = the hash of transation
            index = the index of the output
            output = will contain the UTXO if found

        Return:
            Return true if the UTXO was found

    ***************************************************************************/

    public bool findOutput (Hash hash, size_t index, out Output output)
        nothrow @safe
    {
        auto utxo_hash = hashMulti(hash, cast(size_t)index);

        if (utxo_hash in this.used_utxos)
            return false;  // double-spend

        if (auto utxo = utxo_hash in this.utxo_map)
        {
            this.used_utxos.put(utxo_hash);
            output = *utxo;
            return true;
        }

        return false;
    }
}
