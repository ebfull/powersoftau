extern crate powersoftau;
extern crate rand;
extern crate blake2;
extern crate byteorder;

use powersoftau::*;

use std::fs::OpenOptions;
use std::io::{Read, BufReader};
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

    // Collect secrets from the user
    let secrets = vec![
        "test"
    ];

    let mut check = Blake2b::default();
    check.input(format!("{} pubkeys, coming up!", secrets.len()).as_bytes());

    for secret in secrets {
        use byteorder::{ReadBytesExt, BigEndian};
        use rand::{SeedableRng};
        use rand::chacha::ChaChaRng;

        let pubkey = if secret == "?" {
            // Load the pubkey from the response file
            // Try to load `./response` from disk.
            let response_reader = OpenOptions::new()
                                    .read(true)
                                    .open("response").expect("unable open `./response` in this directory");

            {
                let metadata = response_reader.metadata().expect("unable to get filesystem metadata for `./response`");
                if metadata.len() != (CONTRIBUTION_BYTE_SIZE as u64) {
                    panic!("The size of `./response` should be {}, but it's {}, so something isn't right.", CONTRIBUTION_BYTE_SIZE, metadata.len());
                }
            }

            let mut response_reader = BufReader::new(response_reader);

            // Check the hash chain
            {
                let mut response_challenge_hash = [0; 64];
                response_reader.read_exact(&mut response_challenge_hash).expect("couldn't read hash of challenge file from response file");

                if &response_challenge_hash[..] != current_accumulator_hash.as_slice() {
                    panic!("Hash chain failure. This is not the right response.");
                }
            }

            // Skip enough bytes...
            {
                let mut t = (&mut response_reader).take((CONTRIBUTION_BYTE_SIZE - PUBLIC_KEY_SIZE - 64) as u64);
                let mut tmpbuf = [0; 1024];
                while let Ok(n) = t.read(&mut tmpbuf) {
                    if n == 0 {
                        break;
                    }
                }
            }

            PublicKey::deserialize(&mut response_reader)
            .expect("wasn't able to deserialize the response file's public key")
        } else {
            let h = {
                let mut h = Blake2b::default();
                h.input(&secret.as_bytes());
                h.input("\n".as_bytes());
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

            pubkey
        };
        
        let mut tmp: Vec<u8> = vec![];
        pubkey.serialize(&mut tmp).expect("unable to write public key");
        check.input(&tmp);
    }

    let check = check.result();

    print!("Done!\n\n\
              The BLAKE2b hash should be:\n");

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
