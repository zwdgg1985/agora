/*******************************************************************************

    Contains an SQLite-backed UTXO transaction set class

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.UTXOSet;

import agora.common.Deserializer;
import agora.common.Hash;
import agora.common.Serializer;
import agora.common.Set;
import agora.consensus.data.Transaction;
import agora.consensus.Validation;

import d2sqlite3.database;
import d2sqlite3.library;
import d2sqlite3.results;
import d2sqlite3.sqlite3;

import vibe.core.log;

import std.algorithm;
import std.conv;
import std.exception;
import std.file;
import std.range;
import std.path;

/// ditto
public class UTXOSet
{
    /// Utxo cache backed by a database
    private UTXOCache utxo_cache;

    /// Set of consumed outputs during validation
    private Set!Hash used_utxos;


    /***************************************************************************

        Constructor

        Params:
            max_hot_items = max number of UTXOs to keep in the hot cache
            utxo_db_path = path to the UTXO database

    ***************************************************************************/

    public this (size_t max_hot_items, in string utxo_db_path)
    {
        this.utxo_cache = new UTXOCache(max_hot_items, utxo_db_path);
    }

    /***************************************************************************

        Shut down the utxo store

    ***************************************************************************/

    public void shutdown ()
    {
        this.utxo_cache.shutdown();
    }

    /***************************************************************************

        Add all of a transaction's outputs to the Utxo set,
        and remove the spent outputs in the transaction from the set.

        Params:
            tx = the transaction

    ***************************************************************************/

    public void updateUtxoCache (const ref Transaction tx) nothrow @safe
    {
        foreach (input; tx.inputs)
        {
            auto utxo_hash = hashMulti(input.previous, cast(size_t)input.index);
            this.utxo_cache.remove(utxo_hash);
        }

        Hash tx_hash = tx.hashFull();
        foreach (idx, output; tx.outputs)
        {
            auto utxo_hash = hashMulti(tx_hash, cast(size_t)idx);
            this.utxo_cache[utxo_hash] = output;
        }
    }

    /***************************************************************************

        Reset the tracking of spent UTXOs

    ***************************************************************************/

    public void reset () @trusted nothrow
    {
        this.used_utxos.clear();
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

    public bool findUTXO (Hash hash, size_t index, out Output output)
        nothrow @safe
    {
        auto utxo_hash = hashMulti(hash, cast(size_t)index);

        if (utxo_hash in this.used_utxos)
            return false;  // double-spend

        if (this.utxo_cache.find(utxo_hash, output))
        {
            this.used_utxos.put(utxo_hash);
            return true;
        }

        return false;
    }
}

/*******************************************************************************

    Contains a hot cache and SQLite backed cold storage of UTXOs

*******************************************************************************/

private class UTXOCache
{
    /// UTXO Key/Value pair
    private struct UtxoPair
    {
        /// Key of the UTXO
        private Hash key;

        /// The Output
        private Output value;
    }

    /// UTXOs which become old are stored in the database
    private UTXODB cold_store;

    /// Most recent unspent outputs
    private Output[Hash] hot_cache;

    /// max items in 'hot_queue'
    private const size_t max_hot_items;

    /// used to track which Outputs should be moved from hot_cache => cold_store
    private UtxoPair[] hot_queue;


    /***************************************************************************

        Constructor

        Params:
            max_hot_items = max number of UTXOs to keep in the hot cache
            utxo_db_path = path to the UTXO database

    ***************************************************************************/

    public this (size_t max_hot_items, string utxo_db_path)
    {
        this.max_hot_items = max_hot_items;
        this.cold_store = new UTXODB(utxo_db_path);
    }

    /***************************************************************************

        When shutting down, we must push all items from the
        hot cache to the cold store and dump the cold store to disk

    ***************************************************************************/

    public void shutdown ()
    {
        foreach (key, output; this.hot_cache)
            this.cold_store[key] = output;

        this.cold_store.shutdown();
    }

    /***************************************************************************

        Find a UTXO with the given key

        Params:
            key = the key to look up
            output = will contain the output if it's found

        Returns:
            true if the Output with the given key was found

    ***************************************************************************/

    public bool find (Hash key, out Output output) nothrow @safe
    {
        // in the hot cache
        if (auto out_ptr = key in this.hot_cache)
        {
            output = *out_ptr;
            return true;
        }

        // in the cold cache
        if (this.cold_store.find(key, output))
            return true;

        return false;
    }

    /***************************************************************************

        Remove a spent UTXO from the store

        Params:
            key = the key to remove

    ***************************************************************************/

    public void remove (Hash key) nothrow @safe
    {
        // in the hot cache
        if (auto out_ptr = key in this.hot_cache)
            this.hot_cache.remove(key);
        else
            this.cold_store.remove(key);  // it must be in the cold store
    }

    /***************************************************************************

        Add an Output to the map

        Params:
            output = the output to add
            key = the key to use

    ***************************************************************************/

    public void opIndexAssign (const ref Output output, Hash key) nothrow @safe
    {
        // just added => move to hot cache
        this.hot_cache[key] = output;

        // hot cache is full, move coldest item to the cold store
        if (this.hot_queue.length + 1 >= this.max_hot_items)
        {
            auto least_used = this.hot_queue[0];

            () @trusted {
                this.hot_queue.dropIndex(0);
                assumeSafeAppend(this.hot_queue);
            }();

            // move the utxo to the cold storage
            this.cold_store[least_used.key] = least_used.value;
        }

        // add it
        this.hot_queue ~= UtxoPair(key, output);
    }
}

/*******************************************************************************

    Database of UTXOs using SQLite as the backing store

*******************************************************************************/

private class UTXODB
{
    /// SQLite db instance
    private Database db;


    /***************************************************************************

        Constructor

        Params:
            utxo_db_path = path to the UTXO database file

    ***************************************************************************/

    public this (string utxo_db_path)
    {
        const db_exists = utxo_db_path.exists;
        if (db_exists)
            logInfo("Loading UTXO database from: %s", utxo_db_path);

        // todo: can fail. we would have to recover by either:
        // A) reconstructing it from our blockchain storage
        // B) requesting the UTXO set from our peers
        this.db = Database(utxo_db_path);

        if (db_exists)
            logInfo("Loaded database from: %s", utxo_db_path);

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

        Params:
            key = the key to find
            output = will contain the Output if found

        Returns:
            true if the output was found

    ***************************************************************************/

    public bool find (Hash key, out Output output) nothrow @trusted
    {
        try
        {
            auto results = db.execute("SELECT val FROM utxo_map WHERE key = ?",
                key[]);

            foreach (row; results)
            {
                output = deserialize!Output(row.peek!(ubyte[])(1));
                return true;
            }
        }
        catch (Exception)
        {
            assert(0);
        }

        return false;
    }

    /***************************************************************************

        Add an Output to the map

        Params:
            output = the output to add
            key = the key to use

    ***************************************************************************/

    public void opIndexAssign (const ref Output output, Hash key) nothrow @safe
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

        Params:
            key = the key to remove

    ***************************************************************************/

    public void remove (Hash key) nothrow @safe
    {
        try
        {
            () @trusted {
                db.execute("DELETE FROM utxo_map WHERE key = ?", key[]); }();
        }
        catch (Exception ex)
        {
            assert(0);
        }
    }
}
