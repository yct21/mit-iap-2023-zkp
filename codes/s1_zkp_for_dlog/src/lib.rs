//! Specifically, you should implement:
//!
//! - a function dlogProof(x, g, p) that returns
//!   - (1) a residue y, evaluated as g^x (mod p)
//!   - (2) a proof of knowledge pf that you know x that is the discrete log of y.
//! - a function verify(y, g, p, pf) that evaluates to true if pf is a valid proof of knowledge, and false otherwise.
//!   The prover should only be able to compute a valid proof with non-negligible probability
//!   if they do indeed know valid x.

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::OsRng,
    NonZero, RandomMod, Uint,
};

const ROUND_OF_VERIFY: usize = 100;

pub struct Proof<const LIMBS: usize> {
    pub h: Uint<LIMBS>, // h = g^r (mod p)
    pub s: Uint<LIMBS>, // s = (r + b * x) (mod q - 1)
}

pub type Proofs<const LIMBS: usize> = Vec<Proof<LIMBS>>;

/// dlogProof(x, g, p) to prove that we know secret x such that y = g^x (mod p)
///
/// Returns (residue y, proofs)
pub fn prove<const LIMBS: usize>(
    secret: Uint<LIMBS>,
    generator: Uint<LIMBS>,
    modulus: Uint<LIMBS>,
) -> (Uint<LIMBS>, Proofs<LIMBS>) {
    assert!(modulus > <Uint<LIMBS>>::ONE); // assert p > 1

    // y = g^x (mod p)
    let rem_cac_cache = RemCaculateCache::new(&modulus); // store p in cache
    let residue = rem_cac_cache.pow_mod(&generator, &secret);

    // caculate p - 1 to generate `r` after
    let p_minus_1 = modulus.wrapping_sub(&<Uint<LIMBS>>::ONE);
    // we asserted p > 1 before, so it is safe to unwrap here
    let non_zero_modulus = NonZero::new(p_minus_1).unwrap();

    // caculate proofs
    let mut proofs = Vec::with_capacity(ROUND_OF_VERIFY);
    for _ in 0..ROUND_OF_VERIFY {
        // generate random `r` below (p-1) and compute each `h = g^r (mod p)`
        let r = Uint::<LIMBS>::random_mod(&mut OsRng, &non_zero_modulus);
        let h = rem_cac_cache.pow_mod(&generator, &r);
        let bit = get_bit_by_hashing(&h, &generator, &modulus);

        let s = if bit > 0 {
            r.add_mod(&secret, &non_zero_modulus)
        } else {
            r
        };

        proofs.push(Proof { h, s });
    }

    (residue, proofs)
}

/// a function verify(y, g, p, pf) that evaluates to true if pf is a valid proof of knowledge, and false otherwise.
/// The prover should only be able to compute a valid proof with non-negligible probability
/// if they do indeed know valid x.
pub fn verify<const LIMBS: usize>(
    residue: Uint<LIMBS>,
    generator: Uint<LIMBS>,
    modulus: Uint<LIMBS>,
    proofs: Proofs<LIMBS>,
) -> bool {
    if proofs.len() != ROUND_OF_VERIFY {
        return false;
    }

    let rem_cac_cache = RemCaculateCache::new(&modulus);

    proofs.iter().all(|proof| {
        let Proof { h, s } = proof;
        let bit = get_bit_by_hashing(&h, &generator, &modulus);

        let lhs = rem_cac_cache.pow_mod(&generator, &s); // g ^ s (mod p)
        let rhs = if bit > 0 {
            rem_cac_cache.mul_mod(&h, &residue) // h * y (mod p)
        } else {
            *h
        };

        // println!("h: {:?}, s: {:?}, bit: {}", h, s, bit);
        // println!("lhs: {:?}, rhs: {:?}", lhs, rhs);

        lhs == rhs
    })
}

fn get_bit_by_hashing<const LIMBS: usize>(
    h: &Uint<LIMBS>,
    generator: &Uint<LIMBS>,
    modulus: &Uint<LIMBS>,
) -> u8 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(transmute_uint_to_u8_slice(h));
    hasher.update(transmute_uint_to_u8_slice(generator));
    hasher.update(transmute_uint_to_u8_slice(modulus));
    let hash = hasher.finalize();
    hash.as_bytes()[0] % 2
}

fn transmute_uint_to_u8_slice<const LIMBS: usize>(v: &Uint<LIMBS>) -> &[u8] {
    let slice = unsafe { v.as_words().align_to::<u8>().1 };
    assert_eq!(slice.len(), LIMBS * 8);

    slice
}

/// Wraps around a weird API from crypto-bigint to compute exponentiation with remainder
///
/// Precompute some stuff (?) for montgomery reduction and reuse it in each computation with same modulus
struct RemCaculateCache<const LIMBS: usize> {
    dyn_residue_params: DynResidueParams<LIMBS>,
}

impl<const LIMBS: usize> RemCaculateCache<LIMBS> {
    fn new(modulus: &Uint<LIMBS>) -> Self {
        let dyn_residue_params = DynResidueParams::new(&modulus);

        Self { dyn_residue_params }
    }

    fn pow_mod(&self, base: &Uint<LIMBS>, exp: &Uint<LIMBS>) -> Uint<LIMBS> {
        let dyn_residue = DynResidue::new(base, self.dyn_residue_params);

        dyn_residue.pow(exp).retrieve()
    }

    fn mul_mod(&self, lhs: &Uint<LIMBS>, rhs: &Uint<LIMBS>) -> Uint<LIMBS> {
        let dyn_residue_lhs = DynResidue::new(lhs, self.dyn_residue_params);
        let dyn_residue_rhs = DynResidue::new(rhs, self.dyn_residue_params);

        dyn_residue_lhs.mul(&dyn_residue_rhs).retrieve()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn test_positive() {
        let secret = U256::from_u64(17);
        let generator = U256::from_u64(3);
        let modulus = U256::from_u64(31);
        let (residue, proofs) = prove(secret, generator, modulus);

        assert!(verify(residue, generator, modulus, proofs));
    }

    #[test]
    fn test_negative() {
        let secret = U256::from_u64(10);
        let generator = U256::from_u64(2);
        let modulus = U256::from_u64(67);
        let (residue, proofs) = prove(secret, generator, modulus);

        assert!(!verify(residue, generator, modulus, proofs));
    }
}
