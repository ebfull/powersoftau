//! This ceremony constructs the "powers of tau" for Jens Groth's 2016 zk-SNARK proving
//! system using the BN256 pairing-friendly elliptic curve construction.
//!
//! # Overview
//!
//! Participants of the ceremony receive a "challenge" file containing:
//!
//! * the BLAKE2b hash of the last file entered into the transcript
//! * an `Accumulator` (with curve points encoded in uncompressed form for fast deserialization)
//!
//! The participant runs a tool which generates a random keypair (`PublicKey`, `PrivateKey`)
//! used for modifying the `Accumulator` from the "challenge" file. The keypair is then used to
//! transform the `Accumulator`, and a "response" file is generated containing:
//!
//! * the BLAKE2b hash of the "challenge" file (thus forming a hash chain over the entire transcript)
//! * an `Accumulator` (with curve points encoded in compressed form for fast uploading)
//! * the `PublicKey`
//!
//! This "challenge" file is entered into the protocol transcript. A given transcript is valid
//! if the transformations between consecutive `Accumulator`s verify with their respective
//! `PublicKey`s. Participants (and the public) can ensure that their contribution to the
//! `Accumulator` was accepted by ensuring the transcript contains their "response" file, ideally
//! by comparison of the BLAKE2b hash of the "response" file.
//!
//! After some time has elapsed for participants to contribute to the ceremony, a participant is
//! simulated with a randomness beacon. The resulting `Accumulator` contains partial zk-SNARK
//! public parameters for all circuits within a bounded size.

extern crate bn;
extern crate rand;
extern crate crossbeam;
extern crate num_cpus;
extern crate blake2;
extern crate generic_array;
extern crate typenum;
extern crate byteorder;
extern crate bincode;

use byteorder::{ReadBytesExt, BigEndian};
use rand::{SeedableRng, Rng};
use rand::chacha::ChaChaRng;
use bn::*;
use std::ops::*;
use bincode::{DecodingError, EncodingError};

const INF : bincode::SizeLimit = bincode::SizeLimit::Infinite;

use std::io::{self, Read, Write};
use generic_array::GenericArray;
use typenum::consts::U64;
use blake2::{Blake2b, Digest};
use std::fmt;

// This ceremony is based on the BN256 elliptic curve construction.
const G1_UNCOMPRESSED_BYTE_SIZE: usize = 1 + 32 + 32;
const G2_UNCOMPRESSED_BYTE_SIZE: usize = 1 + 64 + 64;
const G1_COMPRESSED_BYTE_SIZE: usize = 1 + 32 + 32;
const G2_COMPRESSED_BYTE_SIZE: usize = 1 + 64 + 64;

/// The accumulator supports circuits with 2^21 multiplication gates.
const TAU_POWERS_LENGTH: usize = (1 << 21);

/// More tau powers are needed in G1 because the Groth16 H query
/// includes terms of the form tau^i * (tau^m - 1) = tau^(i+m) - tau^i
/// where the largest i = m - 2, requiring the computation of tau^(2m - 2)
/// and thus giving us a vector length of 2^22 - 1.
const TAU_POWERS_G1_LENGTH: usize = (TAU_POWERS_LENGTH << 1) - 1;

/// The size of the accumulator on disk.
pub const ACCUMULATOR_BYTE_SIZE: usize = (TAU_POWERS_G1_LENGTH * G1_UNCOMPRESSED_BYTE_SIZE) + // g1 tau powers
                                         (TAU_POWERS_LENGTH * G2_UNCOMPRESSED_BYTE_SIZE) + // g2 tau powers
                                         (TAU_POWERS_LENGTH * G1_UNCOMPRESSED_BYTE_SIZE) + // alpha tau powers
                                         (TAU_POWERS_LENGTH * G1_UNCOMPRESSED_BYTE_SIZE) // beta tau powers
                                         + G2_UNCOMPRESSED_BYTE_SIZE // beta in g2
                                         + 64; // blake2b hash of previous contribution

/// The "public key" is used to verify a contribution was correctly
/// computed.
pub const PUBLIC_KEY_SIZE: usize = 3 * G2_UNCOMPRESSED_BYTE_SIZE + // tau, alpha, and beta in g2
                                   6 * G1_UNCOMPRESSED_BYTE_SIZE; // (s1, s1*tau), (s2, s2*alpha), (s3, s3*beta) in g1

/// The size of the contribution on disk.
pub const CONTRIBUTION_BYTE_SIZE: usize = (TAU_POWERS_G1_LENGTH * G1_COMPRESSED_BYTE_SIZE) + // g1 tau powers
                                          (TAU_POWERS_LENGTH * G2_COMPRESSED_BYTE_SIZE) + // g2 tau powers
                                          (TAU_POWERS_LENGTH * G1_COMPRESSED_BYTE_SIZE) + // alpha tau powers
                                          (TAU_POWERS_LENGTH * G1_COMPRESSED_BYTE_SIZE) // beta tau powers
                                          + G2_COMPRESSED_BYTE_SIZE // beta in g2
                                          + 64 // blake2b hash of input accumulator
                                          + PUBLIC_KEY_SIZE; // public key

/// Hashes to G2 using the first 32 bytes of `digest`. Panics if `digest` is less
/// than 32 bytes.
fn hash_to_g2(mut digest: &[u8]) -> G2
{
    assert!(digest.len() >= 32);

    let mut seed = Vec::with_capacity(8);

    for _ in 0..8 {
        seed.push(digest.read_u32::<BigEndian>().expect("assertion above guarantees this to work"));
    }

    G2::random(&mut ChaChaRng::from_seed(&seed))
}

#[test]
fn test_hash_to_g2() {
    assert!(
        hash_to_g2(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33])
        ==
        hash_to_g2(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,34])
    );

    assert!(
        hash_to_g2(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32])
        !=
        hash_to_g2(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,33])
    );
}

/// Contains terms of the form (s<sub>1</sub>, s<sub>1</sub><sup>x</sup>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)
/// for all x in τ, α and β, and some s chosen randomly by its creator. The function H "hashes into" the group G2. No points in the public key may be the identity.
///
/// The elements in G2 are used to verify transformations of the accumulator. By its nature, the public key proves
/// knowledge of τ, α and β.
///
/// It is necessary to verify `same_ratio`((s<sub>1</sub>, s<sub>1</sub><sup>x</sup>), (H(s<sub>1</sub><sup>x</sup>)<sub>2</sub>, H(s<sub>1</sub><sup>x</sup>)<sub>2</sub><sup>x</sup>)).
#[derive(PartialEq, Eq)]
pub struct PublicKey {
    tau_g1: (G1, G1),
    alpha_g1: (G1, G1),
    beta_g1: (G1, G1),
    tau_g2: G2,
    alpha_g2: G2,
    beta_g2: G2
}

/// Contains the secrets τ, α and β that the participant of the ceremony must destroy.
pub struct PrivateKey {
    tau: Fr,
    alpha: Fr,
    beta: Fr
}

fn compute_g2_s(
    g1_s: &G1,
    g1_s_x: &G1,
    personalization: u8,
    transcript_digest: &[u8]) -> G2
{
    let g1_s_enc = bincode::encode(&g1_s, INF)
        .expect("g1_s encoding");
    let g1_s_x_enc = bincode::encode(&g1_s_x, INF)
        .expect("g1_s_x encoding");

    // Compute BLAKE2b(personalization | transcript | g^s | g^{s*x})
    let mut h = Blake2b::default();
    h.input(&[personalization]);
    h.input(transcript_digest);
    h.input(g1_s_enc.as_ref());
    h.input(g1_s_x_enc.as_ref());

    // Hash into G2 as g^{s'}
    hash_to_g2(&h.result())
}

/// Constructs a keypair given an RNG and a 64-byte transcript `digest`.
pub fn keypair<R: Rng>(rng: &mut R, digest: &[u8]) -> (PublicKey, PrivateKey)
{
    assert_eq!(digest.len(), 64);

    let tau = Fr::random(rng);
    let alpha = Fr::random(rng);
    let beta = Fr::random(rng);

    let mut op = |x, personalization: u8| {
        // Sample random g^s
        let g1_s = G1::random(rng);
        // Compute g^{s*x}
        let g1_s_x = g1_s.mul(x);
        // Compute hash in G2
        let g2_s = compute_g2_s(&g1_s, &g1_s_x, personalization, digest);
        // Compute g^{s'*x}
        let g2_s_x = g2_s.mul(x);

        ((g1_s, g1_s_x), g2_s_x)
    };

    let pk_tau = op(tau, 0);
    let pk_alpha = op(alpha, 1);
    let pk_beta = op(beta, 2);

    (
        PublicKey {
            tau_g1: pk_tau.0,
            alpha_g1: pk_alpha.0,
            beta_g1: pk_beta.0,
            tau_g2: pk_tau.1,
            alpha_g2: pk_alpha.1,
            beta_g2: pk_beta.1,
        },
        PrivateKey {
            tau: tau,
            alpha: alpha,
            beta: beta
        }
    )
}

/// Determines if point compression should be used.
#[derive(Copy, Clone)]
pub enum UseCompression {
    Yes,
    No
}

/// Determines if points should be checked for correctness during deserialization.
/// This is not necessary for participants, because a transcript verifier can
/// check this theirself.
#[derive(Copy, Clone)]
pub enum CheckForCorrectness {
    Yes,
    No
}

fn write_point<W, G>(
    writer: &mut W,
    p: &G,
    _compression: UseCompression
) -> io::Result<()>
    where W: Write,
          G: Group
{
    // TODO: Support exporting to compressed format

    match bincode::encode_into(p, writer, INF) {
        Err(EncodingError::IoError(io_err)) => Err(io_err),
        Err(EncodingError::SizeLimit) => Err(io::ErrorKind::Other)?,
        Ok(()) => Ok(()),
    }
}

/// Errors that might occur during deserialization.
#[derive(Debug)]
pub enum DeserializationError {
    IoError(io::Error),
    DecodingError(DecodingError),
    PointAtInfinity
}

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DeserializationError::IoError(ref e) => write!(f, "Disk IO error: {}", e),
            DeserializationError::DecodingError(ref e) => write!(f, "Decoding error: {}", e),
            DeserializationError::PointAtInfinity => write!(f, "Point at infinity found")
        }
    }
}

impl From<io::Error> for DeserializationError {
    fn from(err: io::Error) -> DeserializationError {
        DeserializationError::IoError(err)
    }
}

impl From<DecodingError> for DeserializationError {
    fn from(err: DecodingError) -> DeserializationError {
        DeserializationError::DecodingError(err)
    }
}

impl PublicKey {
    /// Serialize the public key. Points are always in uncompressed form.
    pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()>
    {
        write_point(writer, &self.tau_g1.0, UseCompression::No)?;
        write_point(writer, &self.tau_g1.1, UseCompression::No)?;

        write_point(writer, &self.alpha_g1.0, UseCompression::No)?;
        write_point(writer, &self.alpha_g1.1, UseCompression::No)?;

        write_point(writer, &self.beta_g1.0, UseCompression::No)?;
        write_point(writer, &self.beta_g1.1, UseCompression::No)?;

        write_point(writer, &self.tau_g2, UseCompression::No)?;
        write_point(writer, &self.alpha_g2, UseCompression::No)?;
        write_point(writer, &self.beta_g2, UseCompression::No)?;

        Ok(())
    }

    /// Deserialize the public key. Points are always in uncompressed form, and
    /// always checked, since there aren't very many of them. Does not allow any
    /// points at infinity.
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<PublicKey, DeserializationError>
    {
        fn read_uncompressed<C: Group, R: Read>(reader: &mut R) -> Result<C, DeserializationError> {
            let v : C = bincode::decode_from(reader, INF)?;

            if v.is_zero() {
                Err(DeserializationError::PointAtInfinity)
            } else {
                Ok(v)
            }
        }

        let tau_g1_s = read_uncompressed(reader)?;
        let tau_g1_s_tau = read_uncompressed(reader)?;

        let alpha_g1_s = read_uncompressed(reader)?;
        let alpha_g1_s_alpha = read_uncompressed(reader)?;

        let beta_g1_s = read_uncompressed(reader)?;
        let beta_g1_s_beta = read_uncompressed(reader)?;

        let tau_g2 = read_uncompressed(reader)?;
        let alpha_g2 = read_uncompressed(reader)?;
        let beta_g2 = read_uncompressed(reader)?;

        Ok(PublicKey {
            tau_g1: (tau_g1_s, tau_g1_s_tau),
            alpha_g1: (alpha_g1_s, alpha_g1_s_alpha),
            beta_g1: (beta_g1_s, beta_g1_s_beta),
            tau_g2: tau_g2,
            alpha_g2: alpha_g2,
            beta_g2: beta_g2
        })
    }
}

#[test]
fn test_pubkey_serialization() {
    use rand::thread_rng;

    let rng = &mut thread_rng();
    let digest = (0..64).map(|_| rng.gen()).collect::<Vec<_>>();
    let (pk, _) = keypair(rng, &digest);
    let mut v = vec![];
    pk.serialize(&mut v).unwrap();
    assert_eq!(v.len(), PUBLIC_KEY_SIZE);
    let deserialized = PublicKey::deserialize(&mut &v[..]).unwrap();
    assert!(pk == deserialized);
}

/// The `Accumulator` is an object that participants of the ceremony contribute
/// randomness to. This object contains powers of trapdoor `tau` in G1 and in G2 over
/// fixed generators, and additionally in G1 over two other generators of exponents
/// `alpha` and `beta` over those fixed generators. In other words:
///
/// * (τ, τ<sup>2</sup>, ..., τ<sup>2<sup>22</sup> - 2</sup>, α, ατ, ατ<sup>2</sup>, ..., ατ<sup>2<sup>21</sup> - 1</sup>, β, βτ, βτ<sup>2</sup>, ..., βτ<sup>2<sup>21</sup> - 1</sup>)<sub>1</sub>
/// * (β, τ, τ<sup>2</sup>, ..., τ<sup>2<sup>21</sup> - 1</sup>)<sub>2</sub>
#[derive(PartialEq, Eq, Clone)]
pub struct Accumulator {
    /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_G1_LENGTH - 1}
    pub tau_powers_g1: Vec<G1>,
    /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_LENGTH - 1}
    pub tau_powers_g2: Vec<G2>,
    /// alpha * tau^0, alpha * tau^1, alpha * tau^2, ..., alpha * tau^{TAU_POWERS_LENGTH - 1}
    pub alpha_tau_powers_g1: Vec<G1>,
    /// beta * tau^0, beta * tau^1, beta * tau^2, ..., beta * tau^{TAU_POWERS_LENGTH - 1}
    pub beta_tau_powers_g1: Vec<G1>,
    /// beta
    pub beta_g2: G2
}

impl Accumulator {
    /// Constructs an "initial" accumulator with τ = 1, α = 1, β = 1.
    pub fn new() -> Self {
        Accumulator {
            tau_powers_g1: vec![G1::one(); TAU_POWERS_G1_LENGTH],
            tau_powers_g2: vec![G2::one(); TAU_POWERS_LENGTH],
            alpha_tau_powers_g1: vec![G1::one(); TAU_POWERS_LENGTH],
            beta_tau_powers_g1: vec![G1::one(); TAU_POWERS_LENGTH],
            beta_g2: G2::one()
        }
    }

    /// Write the accumulator with some compression behavior.
    pub fn serialize<W: Write>(
        &self,
        writer: &mut W,
        compression: UseCompression
    ) -> io::Result<()>
    {
        fn write_all<W: Write, C: Group>(
            writer: &mut W,
            c: &[C],
            compression: UseCompression
        ) -> io::Result<()>
        {
            for c in c {
                write_point(writer, c, compression)?;
            }

            Ok(())
        }

        write_all(writer, &self.tau_powers_g1, compression)?;
        write_all(writer, &self.tau_powers_g2, compression)?;
        write_all(writer, &self.alpha_tau_powers_g1, compression)?;
        write_all(writer, &self.beta_tau_powers_g1, compression)?;
        write_all(writer, &[self.beta_g2], compression)?;

        Ok(())
    }

    /// Read the accumulator from disk with some compression behavior. `checked`
    /// indicates whether we should check it's a valid element of the group and
    /// not the point at infinity.
    pub fn deserialize<R: Read>(
        reader: &mut R,
        compression: UseCompression,
        checked: CheckForCorrectness
    ) -> Result<Self, DeserializationError>
    {
        fn read_all<R: Read, C: Group>(
            reader: &mut R,
            size: usize,
            _compression: UseCompression,
            checked: CheckForCorrectness
        ) -> Result<Vec<C>, DecodingError>
        {
            fn decompress_all<R: Read, C: Group>(
                reader: &mut R,
                size: usize,
                _checked: CheckForCorrectness
            ) -> Result<Vec<C>, DecodingError>
            {
                // TODO: Support skipping correctness checking

                // TODO: Support reading compressed points

                // Read the encoded elements
                let mut elements = vec![C::zero(); size];

                for element in &mut elements {
                    *element = bincode::decode_from(reader, INF)?;
                }

                Ok(elements)
            }

            decompress_all::<_, C>(reader, size, checked)
        }

        let tau_powers_g1 = read_all(reader, TAU_POWERS_G1_LENGTH, compression, checked)?;
        let tau_powers_g2 = read_all(reader, TAU_POWERS_LENGTH, compression, checked)?;
        let alpha_tau_powers_g1 = read_all(reader, TAU_POWERS_LENGTH, compression, checked)?;
        let beta_tau_powers_g1 = read_all(reader, TAU_POWERS_LENGTH, compression, checked)?;
        let beta_g2 = read_all(reader, 1, compression, checked)?[0];

        Ok(Accumulator {
            tau_powers_g1: tau_powers_g1,
            tau_powers_g2: tau_powers_g2,
            alpha_tau_powers_g1: alpha_tau_powers_g1,
            beta_tau_powers_g1: beta_tau_powers_g1,
            beta_g2: beta_g2
        })
    }

    /// Transforms the accumulator with a private key.
    pub fn transform(&mut self, key: &PrivateKey)
    {
        // Construct the powers of tau

        /// Exponentiate a large number of points, with an optional
        /// coefficient to be applied to the exponent.
        fn batch_exp<C: Group>(bases: &mut [C], tau: &Fr, coeff: Option<&Fr>)
        {
            // TODO: Restore the wMAF approach for (coeff) \tau^i

            // TODO: The naive approach may be too slow even for a PoC.  May
            // need to refactor before wMAF.

            let mut tau_power = Fr::one();
            if let Some(coeff) = coeff {
                tau_power = tau_power.mul(*coeff);
            }

            bases[0] = bases[0].mul(tau_power);

            for i in 1..bases.len() {
                tau_power = tau_power.mul(*tau);
                bases[i] = bases[i].mul(tau_power);
            }
        }

        batch_exp(&mut self.tau_powers_g1, &key.tau, None);
        batch_exp(&mut self.tau_powers_g2, &key.tau, None);
        batch_exp(&mut self.alpha_tau_powers_g1, &key.tau, Some(&key.alpha));
        batch_exp(&mut self.beta_tau_powers_g1, &key.tau, Some(&key.beta));
        self.beta_g2 = self.beta_g2.mul(key.beta);
    }
}

/// Verifies a transformation of the `Accumulator` with the `PublicKey`, given a 64-byte transcript `digest`.
pub fn verify_transform(before: &Accumulator, after: &Accumulator, key: &PublicKey, digest: &[u8]) -> bool
{
    assert_eq!(digest.len(), 64);

    let tau_g2_s = compute_g2_s(&key.tau_g1.0, &key.tau_g1.1, 0, digest);
    let alpha_g2_s = compute_g2_s(&key.alpha_g1.0, &key.alpha_g1.1, 1, digest);
    let beta_g2_s = compute_g2_s(&key.beta_g1.0, &key.beta_g1.1, 2, digest);

    // Check the proofs-of-knowledge for tau/alpha/beta
    if !same_ratio(key.tau_g1, (tau_g2_s, key.tau_g2)) {
        return false;
    }
    if !same_ratio(key.alpha_g1, (alpha_g2_s, key.alpha_g2)) {
        return false;
    }
    if !same_ratio(key.beta_g1, (beta_g2_s, key.beta_g2)) {
        return false;
    }

    // Check the correctness of the generators for tau powers
    if after.tau_powers_g1[0] != G1::one() {
        return false;
    }
    if after.tau_powers_g2[0] != G2::one() {
        return false;
    }

    // Did the participant multiply the previous tau by the new one?
    if !same_ratio((before.tau_powers_g1[1], after.tau_powers_g1[1]), (tau_g2_s, key.tau_g2)) {
        return false;
    }

    // Did the participant multiply the previous alpha by the new one?
    if !same_ratio((before.alpha_tau_powers_g1[0], after.alpha_tau_powers_g1[0]), (alpha_g2_s, key.alpha_g2)) {
        return false;
    }

    // Did the participant multiply the previous beta by the new one?
    if !same_ratio((before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]), (beta_g2_s, key.beta_g2)) {
        return false;
    }
    if !same_ratio((before.beta_tau_powers_g1[0], after.beta_tau_powers_g1[0]), (before.beta_g2, after.beta_g2)) {
        return false;
    }

    // Are the powers of tau correct?
    if !same_ratio(power_pairs(&after.tau_powers_g1), (after.tau_powers_g2[0], after.tau_powers_g2[1])) {
        return false;
    }
    if !same_ratio(
        (after.tau_powers_g1[0], after.tau_powers_g1[1]),
        power_pairs(&after.tau_powers_g2)) {
        return false;
    }
    if !same_ratio(power_pairs(&after.alpha_tau_powers_g1), (after.tau_powers_g2[0], after.tau_powers_g2[1])) {
        return false;
    }
    if !same_ratio(power_pairs(&after.beta_tau_powers_g1), (after.tau_powers_g2[0], after.tau_powers_g2[1])) {
        return false;
    }

    true
}

/// Computes a random linear combination over v1/v2.
///
/// Checking that many pairs of elements are exponentiated by
/// the same `x` can be achieved (with high probability) with
/// the following technique:
///
/// Given v1 = [a, b, c] and v2 = [as, bs, cs], compute
/// (a*r1 + b*r2 + c*r3, (as)*r1 + (bs)*r2 + (cs)*r3) for some
/// random r1, r2, r3. Given (g, g^s)...
///
/// e(g, (as)*r1 + (bs)*r2 + (cs)*r3) = e(g^s, a*r1 + b*r2 + c*r3)
///
/// ... with high probability.
fn merge_pairs<G: Group>(v1: &[G], v2: &[G]) -> (G, G)
{
    use rand::{thread_rng};
    use std::sync::{Arc, Mutex};

    assert_eq!(v1.len(), v2.len());

    // TODO: Multi-thread this

    // TODO: Use wMAF and multi-threading

    let chunk = (v1.len() / num_cpus::get()) + 1;
    let s = Arc::new(Mutex::new(G::zero()));
    let sx = Arc::new(Mutex::new(G::zero()));

    crossbeam::scope(|scope| {
        for (v1, v2) in v1.chunks(chunk).zip(v2.chunks(chunk)) {
            let s = s.clone();
            let sx = sx.clone();

            scope.spawn(move || {
                // We do not need to be overly cautious of the RNG
                // used for this check.
                let rng = &mut thread_rng();

                let mut local_s = G::zero();
                let mut local_sx = G::zero();

                for (v1, v2) in v1.iter().zip(v2.iter()) {
                    let rho = Fr::random(rng);
                    local_s = local_s.add(v1.mul(rho));
                    local_sx = local_sx.add(v2.mul(rho));

                }

                let mut s_ref = s.lock().unwrap();
                let mut sx_ref = sx.lock().unwrap();
                *s_ref = (*s_ref).add(local_s);
                *sx_ref = (*sx_ref).add(local_sx);
            });
        }
    });

    let s = s.lock().unwrap();
    let sx = sx.lock().unwrap();

    (*s, *sx)
}

/// Construct a single pair (s, s^x) for a vector of
/// the form [1, x, x^2, x^3, ...].
fn power_pairs<G: Group>(v: &[G]) -> (G, G)
{
    merge_pairs(&v[0..(v.len()-1)], &v[1..])
}

#[test]
fn test_power_pairs() {
    use rand::thread_rng;

    let rng = &mut thread_rng();

    let mut v = vec![];
    let x = Fr::random(rng);
    let mut acc = Fr::one();
    for _ in 0..100 {
        v.push(G1::one().mul(acc));
        acc = acc.mul(x);
    }

    let gx = G2::one().mul(x);

    assert!(same_ratio(power_pairs(&v), (G2::one(), gx)));

    v[1] = v[1].mul(Fr::random(rng));

    assert!(!same_ratio(power_pairs(&v), (G2::one(), gx)));
}

/// Checks if pairs have the same ratio.
fn same_ratio(
    g1: (G1, G1),
    g2: (G2, G2)
) -> bool
{
    bn::pairing(g1.0, g2.1) == bn::pairing(g1.1, g2.0)
}

#[test]
fn test_same_ratio() {
    use rand::thread_rng;

    let rng = &mut thread_rng();

    let s = Fr::random(rng);
    let g1 = G1::one();
    let g2 = G2::one();
    let g1_s = g1.mul(s);
    let g2_s = g2.mul(s);

    assert!(same_ratio((g1, g1_s), (g2, g2_s)));
    assert!(!same_ratio((g1_s, g1), (g2, g2_s)));
}

#[test]
fn test_accumulator_serialization() {
    use rand::thread_rng;

    let rng = &mut thread_rng();
    let mut digest = (0..64).map(|_| rng.gen()).collect::<Vec<_>>();

    let mut acc = Accumulator::new();
    let before = acc.clone();
    let (pk, sk) = keypair(rng, &digest);
    acc.transform(&sk);
    assert!(verify_transform(&before, &acc, &pk, &digest));
    digest[0] = !digest[0];
    assert!(!verify_transform(&before, &acc, &pk, &digest));
    let mut v = Vec::with_capacity(ACCUMULATOR_BYTE_SIZE - 64);
    acc.serialize(&mut v, UseCompression::No).unwrap();
    assert_eq!(v.len(), ACCUMULATOR_BYTE_SIZE - 64);
    let deserialized = Accumulator::deserialize(&mut &v[..], UseCompression::No, CheckForCorrectness::No).unwrap();
    assert!(acc == deserialized);
}

/// Compute BLAKE2b("")
pub fn blank_hash() -> GenericArray<u8, U64> {
    Blake2b::new().result()
}

/// Abstraction over a reader which hashes the data being read.
pub struct HashReader<R: Read> {
    reader: R,
    hasher: Blake2b
}

impl<R: Read> HashReader<R> {
    /// Construct a new `HashReader` given an existing `reader` by value.
    pub fn new(reader: R) -> Self {
        HashReader {
            reader: reader,
            hasher: Blake2b::default()
        }
    }

    /// Destroy this reader and return the hash of what was read.
    pub fn into_hash(self) -> GenericArray<u8, U64> {
        self.hasher.result()
    }
}

impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;

        if bytes > 0 {
            self.hasher.input(&buf[0..bytes]);
        }

        Ok(bytes)
    }
}

/// Abstraction over a writer which hashes the data being written.
pub struct HashWriter<W: Write> {
    writer: W,
    hasher: Blake2b
}

impl<W: Write> HashWriter<W> {
    /// Construct a new `HashWriter` given an existing `writer` by value.
    pub fn new(writer: W) -> Self {
        HashWriter {
            writer: writer,
            hasher: Blake2b::default()
        }
    }

    /// Destroy this writer and return the hash of what was written.
    pub fn into_hash(self) -> GenericArray<u8, U64> {
        self.hasher.result()
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self.writer.write(buf)?;

        if bytes > 0 {
            self.hasher.input(&buf[0..bytes]);
        }

        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
