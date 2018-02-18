extern crate powersoftau;
extern crate rand;
extern crate blake2;
extern crate byteorder;

use powersoftau::*;

use std::fs::OpenOptions;
use std::io::{self, Read, BufReader};
use blake2::{Blake2b, Digest};

fn main() {
    println!("Loading accumulator...");
    let current_accumulator_hash;
    {
        // Try to load `./challenge` from disk.
        let reader = OpenOptions::new()
                                .read(true)
                                .open("challenge").expect("unable open `./challenge` in this directory");

        {
            let metadata = reader.metadata().expect("unable to get filesystem metadata for `./challenge`");
            if metadata.len() != (ACCUMULATOR_BYTE_SIZE as u64) {
                panic!("The size of `./challenge` should be {}, but it's {}, so something isn't right.", ACCUMULATOR_BYTE_SIZE, metadata.len());
            }
        }

        let reader = BufReader::new(reader);
        let mut reader = HashReader::new(reader);

        // Read the BLAKE2b hash of the previous contribution
        {
            // We don't need to do anything with it, but it's important for
            // the hash chain.
            let mut tmp = [0; 64];
            reader.read_exact(&mut tmp).expect("unable to read BLAKE2b hash of previous contribution");
        }

        // Load the current accumulator into memory
        Accumulator::deserialize(&mut reader, UseCompression::No, CheckForCorrectness::No)
        .expect("unable to read uncompressed accumulator");
        
        // Get the hash of the current accumulator
        current_accumulator_hash = reader.into_hash();
    }

    println!("Enter your secrets, one by one.");

    // Collect secrets from the user
    let mut secrets = vec![];

    let mut i = 1;
    loop {
        println!("Secret {} (or \"DONE\" if done.): ", i);

        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input).expect("expected to read some random text from the user");

        if user_input == "DONE\n" {
            break;
        }

        secrets.push(user_input);
        i += 1;
    }

    let mut check = Blake2b::default();
    check.input(format!("{} pubkeys, coming up!", secrets.len()).as_bytes());

    for secret in secrets {
        use byteorder::{ReadBytesExt, BigEndian};
        use rand::{SeedableRng};
        use rand::chacha::ChaChaRng;

        let h = {
            let mut h = Blake2b::default();
            h.input(&secret.as_bytes());
            h.result()
        };

        let mut digest = &h[..];

        // Interpret the first 32 bytes of the digest as 8 32-bit words
        let mut seed = [0u32; 8];
        for i in 0..8 {
            seed[i] = digest.read_u32::<BigEndian>().expect("digest is large enough for this to work");
        }

        let mut rng = ChaChaRng::from_seed(&seed);

        let (pubkey, _) = keypair(&mut rng, current_accumulator_hash.as_ref());

        let mut tmp: Vec<u8> = vec![];
        pubkey.serialize(&mut tmp).expect("unable to write public key");
        check.input(&tmp);
    }

    let check = check.result();

    print!("Done!\n\n\
              The BLAKE2b hash is:\n");

    for line in check.as_slice().chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!("");
    }

    println!("\n");
}
