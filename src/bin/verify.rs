extern crate bn;
extern crate powersoftau;
extern crate rand;
extern crate blake2;
extern crate byteorder;

use powersoftau::*;
use std::fs::OpenOptions;
use std::io::{self, BufReader, Write};

fn into_hex(h: &[u8]) -> String {
    let mut f = String::new();

    for byte in &h[..] {
        f += &format!("{:02x}", byte);
    }

    f
}

// Computes the hash of the challenge file for the player,
// given the current state of the accumulator and the last
// response file hash.
fn get_challenge_file_hash(
    acc: &Accumulator,
    last_response_file_hash: &[u8; 64]
) -> [u8; 64]
{
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);

    sink.write_all(last_response_file_hash)
        .unwrap();

    acc.serialize(
        &mut sink,
        UseCompression::No
    ).unwrap();

    let mut tmp = [0; 64];
    tmp.copy_from_slice(sink.into_hash().as_slice());

    tmp
}

// Computes the hash of the response file, given the new
// accumulator, the player's public key, and the challenge
// file's hash.
fn get_response_file_hash(
    acc: &Accumulator,
    pubkey: &PublicKey,
    last_challenge_file_hash: &[u8; 64]
) -> [u8; 64]
{
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);

    sink.write_all(last_challenge_file_hash)
        .unwrap();

    acc.serialize(
        &mut sink,
        UseCompression::Yes
    ).unwrap();

    pubkey.serialize(&mut sink).unwrap();

    let mut tmp = [0; 64];
    tmp.copy_from_slice(sink.into_hash().as_slice());

    tmp
}

fn main() {
    // Try to load `./transcript` from disk.
    let reader = OpenOptions::new()
                            .read(true)
                            .open("transcript")
                            .expect("unable open `./transcript` in this directory");

    let mut reader = BufReader::with_capacity(1024 * 1024, reader);

    // Initialize the accumulator
    let mut current_accumulator = Accumulator::new();

    // The "last response file hash" is just a blank BLAKE2b hash
    // at the beginning of the hash chain.
    let mut last_response_file_hash = [0; 64];
    last_response_file_hash.copy_from_slice(blank_hash().as_slice());

    // There were 89 rounds.
    for _ in 0..89 {
        // Compute the hash of the challenge file that the player
        // should have received.
        let last_challenge_file_hash = get_challenge_file_hash(
            &current_accumulator,
            &last_response_file_hash
        );

        // Deserialize the accumulator provided by the player in
        // their response file. It's stored in the transcript in
        // uncompressed form so that we can more efficiently
        // deserialize it.
        let response_file_accumulator = Accumulator::deserialize(
            &mut reader,
            UseCompression::No,
            CheckForCorrectness::Yes
        ).expect("unable to read uncompressed accumulator");

        // Deserialize the public key provided by the player.
        let response_file_pubkey = PublicKey::deserialize(&mut reader)
            .expect("wasn't able to deserialize the response file's public key");

        // Compute the hash of the response file. (we had it in uncompressed
        // form in the transcript, but the response file is compressed to save
        // participants bandwidth.)
        last_response_file_hash = get_response_file_hash(
            &response_file_accumulator,
            &response_file_pubkey,
            &last_challenge_file_hash
        );

        print!("{}", into_hex(&last_response_file_hash));

        // Verify the transformation from the previous accumulator to the new
        // one. This also verifies the correctness of the accumulators and the
        // public keys, with respect to the transcript so far.
        if !verify_transform(
            &current_accumulator,
            &response_file_accumulator,
            &response_file_pubkey,
            &last_challenge_file_hash
        )
        {
            println!(" ... FAILED");
            panic!("INVALID RESPONSE FILE!");
        } else {
            println!("");
        }

        current_accumulator = response_file_accumulator;
    }

    println!("Transcript OK!");
}
