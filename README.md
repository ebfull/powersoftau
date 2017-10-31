# Powers of Tau

This is a [multi-party computation](https://en.wikipedia.org/wiki/Secure_multi-party_computation) (MPC) ceremony which constructs partial zk-SNARK parameters for _all_ circuits up to a depth of 2<sup>21</sup>. It works by taking a step that is performed by all zk-SNARK MPCs and performing it in just one single ceremony. This makes individual zk-SNARK MPCs much cheaper and allows them to scale to practically unbounded numbers of participants.

This protocol is described in a [forthcoming paper](https://eprint.iacr.org/2017/1050). It produces parameters for an adaptation of [Jens Groth's 2016 pairing-based proving system](https://eprint.iacr.org/2016/260) using the [BLS12-381](https://github.com/ebfull/pairing/tree/master/src/bls12_381) elliptic curve construction. The security proof relies on a randomness beacon being applied at the end of the ceremony.

**This is a work in progress.**

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
