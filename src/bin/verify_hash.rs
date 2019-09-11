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
        "13355 52232 62363 55653 66356 62246 55655 45445 24345 25515",
        "46254 56523 21346 44331 51245 42446 61244 26212 12665 44343",
        "12662 11533 36631 26523 43354 53615 42124 63165 11635 35235",
        "61536 51343 52264 31615 53144 22352 34433 35152 14222 31143",
        "35633 33141 41533 31455 51614 32464 16626 52652 24456 16625",
        "24352 24312 16236 36442 62154 65643 55435 14636 64544 15611",
        "64541 31465 23422 41543 15124 63241 36352 35636 63113 56542",
        "32224 63341 26155 14232 43646 65534 12243 66623 52115 55665",
        "25216 13465 22666 13265 66613 62351 43331 14323 32646 32623",
        "32562 45532 51645 56362 21215 31444 36126 53522 15356 64164",
        "36621 14124 24324 54134 36445 25636 24265 25642 25544 52154",
        "15461 23234 33242 13231 11666 43243 25431 54451 24546 51355",
        "34444 65126 35114 55113 44216 56123 54162 34532 36614 26641",
        "?",
        "35361 22454 46651 25233 36264 15665 11411 64514 32446 53453",
        "61166 62423 45163 66125 41434 15543 55146 44656 53361 12212",
        "21312 34255 54463 46436 43152 41514 51454 32234 63444 43622",
        "45153 54344 61253 65266 31164 34514 52631 42321 41655 33151",
        "64234 56115 24635 65256 66636 13433 23665 44653 34654 32553",
        "54253 36554 43352 22633 15423 13243 56523 35234 43565 62245"
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
