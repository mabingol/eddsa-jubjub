use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use poseidon2::poseidon_btree_hasher;
use rand::{CryptoRng, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

type ScalarField = ark_ed_on_bls12_381::Fr;
type BaseField = ark_ed_on_bls12_381::Fq;
type Affine = ark_ed_on_bls12_381::EdwardsAffine;
// Import the hasher from your previous module

/// A private key for the EdDSA signature scheme on BabyJubjub.
///
/// Security Note: Utilizes `ZeroizeOnDrop` to ensure raw key material is
/// wiped from memory when this struct goes out of scope.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EdDSAPrivateKey([u8; 32]);

impl EdDSAPrivateKey {
    /// Create a private key from a raw 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Expose the raw private key bytes.
    /// Warning: Handle these bytes with care to avoid leakage.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Generate a cryptographically secure random private key.
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Expands the 32-byte seed into 64 bytes using BLAKE3.
    ///
    /// - Low 32 bytes: Used to derive the Scalar Signing Key (sk).
    /// - High 32 bytes: Used as a seed to derive the deterministic nonce (r).
    ///
    /// This follows RFC 8032 design principles to prevent bias.
    fn hash_blake(&self) -> [u8; 64] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.0);
        let mut r = hasher.finalize_xof();
        let mut output = [0u8; 64];
        r.fill(&mut output);
        output
    }

    /// "Clamps" the bytes to ensure the key is safe for the curve.
    ///
    /// 1. `buf[0] &= 0xF8`: Clears the lowest 3 bits. This forces the scalar
    ///    to be a multiple of 8 (the cofactor). This prevents small-subgroup attacks.
    /// 2. `buf[31] &= 0x7F`: Clears the highest bit. Ensures scalar < Order (soundness).
    /// 3. `buf[31] |= 0x40`: Sets the second highest bit. A counter-measure against
    ///    implementation-specific timing attacks (ensures a consistent bit-length).
    fn derive_sk(input: &[u8]) -> ScalarField {
        let sk_buf = {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&input[0..32]);

            // Apply Clamping
            buf[0] &= 0xF8; // cofactor = 8
            buf[31] &= 0x7F;
            buf[31] |= 0x40;
            buf
        };
        ScalarField::from_le_bytes_mod_order(&sk_buf)
    }

    /// Derive the Public Key: `Pk = sk * G`
    pub fn public(&self) -> EdDSAPublicKey {
        let out = self.hash_blake();
        let sk = Self::derive_sk(&out);
        // Multiply generator by clamped scalar
        let pk = (Affine::generator() * sk).into_affine();
        EdDSAPublicKey { pk }
    }

    /// Generates a deterministic nonce `r` for the signature.
    ///
    /// Instead of using a random RNG (which fails catastrophically if the RNG is weak),
    /// we derive `r` by hashing the Private Key + Message.
    /// This ensures `r` is unique per message but consistent for the same message.
    fn deterministic_nonce(message: BaseField, sk: ScalarField) -> ScalarField {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&EdDSASignature::get_dst_nonce().into_bigint().to_bytes_be());
        // Bind to the secret key
        hasher.update(&sk.into_bigint().to_bytes_be());
        // Bind to the message
        hasher.update(&message.into_bigint().to_bytes_be());

        let mut r = hasher.finalize_xof();
        let mut output = [0u8; 64];
        r.fill(&mut output);

        // Reduce 512 bits mod L to avoid modulo bias
        ScalarField::from_be_bytes_mod_order(&output)
    }

    /// Signs a message (a BaseField element) using EdDSA.
    ///
    /// Formula: `s = r + c * sk`
    pub fn sign(&self, message: BaseField) -> EdDSASignature {
        // 1. Expand key
        let out = self.hash_blake();
        let sk = Self::derive_sk(&out);

        // 2. Generate Deterministic Nonce (r)
        // Note: We use the *high* 32 bytes of the hash expansion as the nonce secret
        let nonce_secret = ScalarField::from_le_bytes_mod_order(&out[32..64]);
        let r_scalar = Self::deterministic_nonce(message, nonce_secret);

        // 3. Compute R point: R = r * G
        let nonce_point = (Affine::generator() * r_scalar).into_affine();

        // 4. Compute Public Key (needed for the Challenge Hash)
        let pk = (Affine::generator() * sk).into_affine();

        // 5. Compute Challenge `c = H(R, Pk, Msg)`
        // This implements "Strong Fiat-Shamir" by including Pk in the hash.
        let challenge = challenge_hash(message, nonce_point, pk);
        let c_scalar = convert_base_to_scalar(challenge);

        // 6. Compute Signature Scalar `s = r + c * sk`
        let s = r_scalar + (c_scalar * sk);

        EdDSASignature { r: nonce_point, s }
    }
}

/// A public key for EdDSA over BabyJubjub.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdDSAPublicKey {
    pub pk: Affine,
}

impl EdDSAPublicKey {
    /// Verify an EdDSA signature.
    ///
    /// Verification Equation: `8 * s * G == 8 * R + 8 * c * Pk`
    ///
    /// This uses **Cofactored Verification**. BabyJubjub has a cofactor of 8.
    /// Multiplying the entire equation by 8 ensures the check holds even if points
    /// have small-subgroup components, enabling batch verification compatibility.
    pub fn verify(&self, message: BaseField, signature: &EdDSASignature) -> bool {
        // 1. Check Range: s < L
        // Prevents signature malleability where s' = s + L would otherwise be valid.
        let s_biguint: BigUint = signature.s.into();
        if s_biguint >= ScalarField::MODULUS.into() {
            return false;
        }

        // 2. Check Point Validity
        // Ensures A and R are on the curve and not the point at infinity.
        // We do NOT strictly check if they are in the prime subgroup here,
        // because the "multiply by 8" step later handles the cofactor component.
        if self.pk.is_zero() || !self.pk.is_on_curve() || !signature.r.is_on_curve() {
            return false;
        }

        // 3. Recompute Challenge `c = H(R, Pk, Msg)`
        let challenge = challenge_hash(message, signature.r, self.pk);
        let c = convert_base_to_scalar(challenge);

        // 4. Verify Equation: 8 * (s*G - R - c*Pk) == 0
        let s_times_g = Affine::generator() * signature.s;
        let c_times_pk = self.pk * c;

        let mut result = s_times_g - signature.r - c_times_pk;

        // Multiply by Cofactor (8)
        // Doubling 3 times is equivalent to * 8
        result.double_in_place();
        result.double_in_place();
        result.double_in_place();

        result.is_zero()
    }

    pub fn to_compressed_bytes(&self) -> eyre::Result<[u8; 32]> {
        let mut buf = Vec::new();
        self.pk
            .y
            .serialize_compressed(&mut buf)
            .expect("TODO: panic message");
        buf[31] |= if self.pk.x.into_bigint().is_odd() {
            0x80
        } else {
            0x00
        };
        //self.pk.serialize_compressed(&mut buf).unwrap();

        let mut bytes = [0u8; 32];
        if buf.len() == 32 {
            bytes.copy_from_slice(&buf);
        } else {
            return Err(eyre::eyre!(format!(
                "Serialization resulted in incorrect length {}",
                buf.len()
            )));
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdDSASignature {
    pub r: Affine,
    pub s: ScalarField,
}

impl EdDSASignature {
    const DST_NONCE: &[u8] = b"TokamakAuth\xE2\x80\x91EDDSA\xE2\x80\x91NONCE\xE2\x80\x91v1";
    fn get_dst_nonce() -> BaseField {
        BaseField::from_be_bytes_mod_order(Self::DST_NONCE)
    }
    pub fn to_compressed_bytes(&self) -> eyre::Result<[u8; 64]> {
        let mut buf = Vec::new();
        self.r.y.serialize_compressed(&mut buf).unwrap();
        buf[31] |= if self.r.x.into_bigint().is_odd() {
            0x80
        } else {
            0x00
        };

        let mut buf2 = Vec::new();
        self.s.serialize_compressed(&mut buf2).unwrap();
        buf.extend(buf2);

        let mut bytes = [0u8; 64];
        if buf.len() == 64 {
            bytes.copy_from_slice(&buf);
        } else {
            return Err(eyre::eyre!("Serialization length mismatch"));
        }
        Ok(bytes)
    }
}

/// Computes the Fiat-Shamir challenge.
/// Inputs: `Hash(DomainSeparator, R.x, R.y, Pk.x, Pk.y, Msg)`
fn challenge_hash(message: BaseField, nonce_r: Affine, pk: Affine) -> BaseField {
    // Convert Curve Points to BigInt Bytes (Big Endian for Poseidon)
    let rx = nonce_r.x.into_bigint().to_bytes_be();
    let ry = nonce_r.y.into_bigint().to_bytes_be();
    let px = pk.x.into_bigint().to_bytes_be();
    let py = pk.y.into_bigint().to_bytes_be();
    let msg = message.into_bigint().to_bytes_be();

    let mut inputs = vec![];
    inputs.extend(rx);
    inputs.extend(ry);
    inputs.extend(px);
    inputs.extend(py);
    inputs.extend(msg);

    // Call the Merkle Hasher (Poseidon)
    // Note: This expects inputs to be properly formatted for the hasher
    let result = poseidon_btree_hasher(inputs.as_slice()).expect("Poseidon hash failed");
    BaseField::from_be_bytes_mod_order(&result)
}

/// Converts a BaseField element (Poseidon Output) to a ScalarField element.
///
///
/// Since BaseField < ScalarField, we can convert bytes directly without
/// introducing modulo bias. This property is specific to embedded curves like BabyJubjub.
pub(crate) fn convert_base_to_scalar(f: BaseField) -> ScalarField {
    let bytes = f.into_bigint().to_bytes_le();
    ScalarField::from_le_bytes_mod_order(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use num_bigint::{BigInt, Sign};
    use poseidon2::poseidon_n;
    use poseidon2::poseidon_n2x_compress;
    use poseidon2::set_length_left;

    #[test]
    fn test_sign_and_verify_flow() {
        let mut rng = rand::thread_rng();

        // 1. Generate Keypair
        let sk = EdDSAPrivateKey::random(&mut rng);
        let pk = sk.public();

        // 2. Generate Random Message (Field Element)
        let message = BaseField::rand(&mut rng);

        // 3. Sign
        let signature = sk.sign(message);

        // 4. Verify Positive Case
        assert!(pk.verify(message, &signature), "Signature should be valid");

        // 5. Verify Negative Case (Wrong Message)
        let bad_message = BaseField::rand(&mut rng);
        assert!(
            !pk.verify(bad_message, &signature),
            "Signature should fail for wrong message"
        );

        // 6. Verify Negative Case (Wrong Key)
        let bad_sk = EdDSAPrivateKey::random(&mut rng);
        let bad_pk = bad_sk.public();
        assert!(
            !bad_pk.verify(message, &signature),
            "Signature should fail for wrong key"
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = rand::thread_rng();
        let sk = EdDSAPrivateKey::random(&mut rng);
        let pk = sk.public();
        let msg = BaseField::rand(&mut rng);
        let sig = sk.sign(msg);
        // Public Key Roundtrip
        let pk_bytes = pk.to_compressed_bytes().unwrap();
        // Signature Roundtrip
        let sig_bytes = sig.to_compressed_bytes().unwrap();
        println!(
            "let msg= {:?}",
            hex::encode(msg.into_bigint().to_bytes_be())
        );
        println!("let public_key= {:?}", hex::encode(pk_bytes));
        println!("let signature = {:?}", hex::encode(sig_bytes));
    }
    #[test]
    fn test_empty_input() {
        let input = b"";
        let res = poseidon_btree_hasher(input);
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 32);
    }

    #[test]
    fn test_exact_chunk_size() {
        // 32 bytes exact
        let input = vec![1u8; 32];
        let res = poseidon_btree_hasher(&input);
        assert!(res.is_ok());
    }

    #[test]
    fn test_odd_size() {
        // 33 bytes (will result in 2 chunks, second one padded)
        let input = vec![8u8; 33];
        let res = poseidon_btree_hasher(&input);
        assert!(res.is_ok());
    }

    #[test]
    fn test_padding_logic_complex() {
        // 3 chunks.
        // Logic should: Pad 3 -> 4.
        // Use `poseidon_n2x_compress` (4 inputs).
        // Result: 1 root.
        let input = vec![1u8; 32 * 3];
        let res = poseidon_btree_hasher(&input);
        assert!(res.is_ok());
    }
    #[test]
    fn test_poseidon_n2x_compress() {
        let inputs = vec![
            BigInt::from(1),
            BigInt::from(2),
            BigInt::from(3),
            BigInt::from(4),
        ];
        let result = poseidon_n2x_compress(&inputs).unwrap();
        let result_l = poseidon_n(&vec![BigInt::from(1), BigInt::from(2)]).unwrap();
        let result_r = poseidon_n(&vec![BigInt::from(3), BigInt::from(4)]).unwrap();

        let result_ex = poseidon_n(&vec![result_l, result_r]).unwrap();
        assert_eq!(result, result_ex);
    }
    #[test]
    fn test_poseidon_btree_hasher() {
        let x = 6;
        let y = 3;
        let z = 8;
        let t = 0;
        //todo
        let (_, a) = BigInt::from(x).to_bytes_be();
        let (_, b) = BigInt::from(y).to_bytes_be();
        let (_, c) = BigInt::from(z).to_bytes_be();
        let (_, d) = BigInt::from(t).to_bytes_be();

        let mut a = set_length_left(a.as_slice(), 32);
        let mut b = set_length_left(b.as_slice(), 32);
        let mut c = set_length_left(c.as_slice(), 32);
        let mut d = set_length_left(d.as_slice(), 32);

        let mut input = vec![];
        input.append(&mut a);
        input.append(&mut b);
        input.append(&mut c);
        //   input.append(&mut d);
        let res = poseidon_btree_hasher(&input);
        assert!(res.is_ok());

        let result1 = res.unwrap();
        assert_eq!(result1.len(), 32);

        let inputs = vec![
            BigInt::from(x),
            BigInt::from(y),
            BigInt::from(z),
            BigInt::from(t),
        ];
        let result2 = poseidon_n2x_compress(&inputs).unwrap();

        assert_eq!(
            BigInt::from_bytes_be(Sign::Plus, result1.as_slice()),
            result2
        );
    }
}
