//! # Shamir's Secret Sharing Implementation in Rust
//!
//! This crate provides an implementation of Shamir's Secret Sharing algorithm over a finite field.
//! It splits a secret into multiple shares using a random polynomial and can reconstruct the secret
//! from a subset of those shares using Lagrange interpolation.
//!
//! The implementation uses the prime modulus defined by the secp256k1 curve:
//! \( p = 2^{256} - 2^{32} - 977 \).
//!
//! ## How It Works
//!
//! 1. **Field Selection:**  
//!    A prime \( p \) is chosen to define the finite field over which all computations occur.
//!
//! 2. **Polynomial Construction:**  
//!    A random polynomial \( f(x) = a_0 + a_1 x + a_2 x^2 + \dots + a_{k-1} x^{k-1} \) is generated,
//!    where \( a_0 \) is the secret and the other coefficients \( a_i \) are generated randomly.
//!
//! 3. **Share Generation:**  
//!    The polynomial is evaluated at \( n \) distinct nonzero x-values to yield shares \( (x_i, f(x_i)) \).
//!
//! 4. **Secret Reconstruction:**  
//!    Given at least \( k \) shares, Lagrange interpolation is used to reconstruct \( f(0) \), which is the secret.
//!
//! ## Security
//!
//! Shamir's Secret Sharing is information-theoretically secure. Any set of fewer than \( k \) shares
//! yields no information about the secret due to the randomness of the polynomial coefficients.
//!
//! **Important considerations:**
//! - **Randomness:** The security relies on using a cryptographically secure random number generator for
//!   coefficient generation.
//! - **Parameter Selection:** The secret must be less than \( p \), and the threshold \( k \) should be chosen
//!   according to the desired security policy.
//!
//! ## Potential Vulnerabilities
//!
//! - **Weak Randomness:** If the random number generator is compromised or not cryptographically secure,
//!   an attacker may recover the random coefficients and, therefore, the secret.
//!
//! - **Side Channel Attacks:** As with many cryptographic algorithms, careful attention must be paid to avoid
//!   side channel leaks (timing, power, etc.), especially in a constrained or adversarial environment.
//!
//! - **Misconfiguration:** Incorrect parameters (e.g., secret larger than \( p \) or an invalid threshold)
//!   can cause the scheme to fail or reduce security.

use num_bigint::{BigUint, ToBigUint, RandBigInt};
use num_traits::{One, Zero, Num};
use rand::thread_rng;

/// Represents a single share in Shamir's Secret Sharing.
///
/// Each share is a point \((x, y)\) on the polynomial.
#[derive(Debug, Clone)]
pub struct Share {
    /// The x-coordinate of the share.
    pub x: BigUint,
    /// The y-coordinate of the share.
    pub y: BigUint,
}

/// Returns the prime modulus \( p = 2^{256} - 2^{32} - 977 \).
///
/// This prime is used in secp256k1 and is large enough for 256-bit secrets, ensuring that
/// all arithmetic operations remain valid in the finite field.
///
/// # Returns
/// A `BigUint` representing the prime modulus.
pub fn get_prime() -> BigUint {
    BigUint::from_str_radix(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        16,
    )
    .unwrap()
}

/// Computes the modular inverse of `a` modulo `p` using Fermat's Little Theorem.
///
/// Given that `p` is prime, the modular inverse is computed as:
/// \[ a^{-1} \equiv a^{p-2} \mod p \]
///
/// # Arguments
///
/// * `a` - The number for which the inverse is computed.
/// * `p` - The prime modulus.
///
/// # Returns
/// The modular inverse of `a` modulo `p`.
pub fn modinv(a: &BigUint, p: &BigUint) -> BigUint {
    a.modpow(&(p - 2u32.to_biguint().unwrap()), p)
}

/// Evaluates a polynomial at a given point \( x \) modulo \( p \).
///
/// The polynomial is given by its coefficients in ascending order:
/// \[ f(x) = \sum_{i=0}^{n-1} \text{coeffs}[i] \cdot x^i \mod p \]
///
/// # Arguments
///
/// * `coeffs` - A slice of `BigUint` containing the polynomial coefficients.
/// * `x` - The evaluation point.
/// * `p` - The prime modulus.
///
/// # Returns
/// The result of the polynomial evaluation \( f(x) \mod p \).
pub fn evaluate_polynomial(coeffs: &[BigUint], x: &BigUint, p: &BigUint) -> BigUint {
    let mut result = BigUint::zero();
    let mut power_of_x = BigUint::one();
    for coeff in coeffs {
        result = (result + (coeff * &power_of_x) % p) % p;
        power_of_x = (power_of_x * x) % p;
    }
    result
}

/// Splits a secret into a specified number of shares with a reconstruction threshold.
///
/// A random polynomial of degree `threshold - 1` is constructed with the secret as the constant term.
/// The polynomial is then evaluated at different nonzero x-values to produce the shares.
///
/// # Arguments
///
/// * `secret` - The secret to be shared. Must be less than `p`.
/// * `threshold` - The minimum number of shares required to reconstruct the secret.
/// * `share_count` - The total number of shares to generate.
/// * `p` - The prime modulus.
///
/// # Returns
/// * `Ok(Vec<Share>)` containing the generated shares, or an error string if parameters are invalid.
pub fn split_secret(
    secret: &BigUint,
    threshold: usize,
    share_count: usize,
    p: &BigUint,
) -> Result<Vec<Share>, String> {
    if threshold > share_count {
        return Err("Threshold cannot be greater than the number of shares".to_string());
    }
    if secret >= p {
        return Err("Secret must be less than the prime modulus".to_string());
    }
    let mut rng = thread_rng();
    let mut coeffs: Vec<BigUint> = vec![secret.clone()];
    for _ in 1..threshold {
        coeffs.push(rng.gen_biguint_below(p));
    }
    let mut shares: Vec<Share> = Vec::new();
    for i in 1..=share_count {
        let x = BigUint::from(i);
        let y = evaluate_polynomial(&coeffs, &x, p);
        shares.push(Share { x, y });
    }
    Ok(shares)
}

/// Reconstructs the secret from a given set of shares using Lagrange interpolation.
///
/// Lagrange interpolation is used to compute \( f(0) \), which recovers the secret.
/// Each share contributes a Lagrange basis polynomial, and the sum of the contributions
/// gives the original secret.
///
/// # Arguments
///
/// * `shares` - A slice containing at least `threshold` shares.
/// * `p` - The prime modulus.
///
/// # Returns
/// The reconstructed secret \( f(0) \).
pub fn reconstruct_secret(shares: &[Share], p: &BigUint) -> BigUint {
    let mut secret = BigUint::zero();
    let k = shares.len();
    for j in 0..k {
        let mut numerator = BigUint::one();
        let mut denominator = BigUint::one();
        for m in 0..k {
            if m != j {
                let xm = &shares[m].x;
                numerator = (&numerator * (p - xm)) % p;
                let xj = &shares[j].x;
                let diff = if xj >= xm { xj - xm } else { p - (xm - xj) };
                denominator = (denominator * diff) % p;
            }
        }
        let lambda = (&numerator * modinv(&denominator, p)) % p;
        secret = (secret + (&shares[j].y * lambda)) % p;
    }
    secret
}

// The following module adds WebAssembly bindings for TypeScript using wasm-bindgen.
// It exports functions to split a secret key into 4 shares and to reconstruct the key from those shares.

#[cfg(target_arch = "wasm32")]
mod wasm_bindings {
    use super::*;
    use wasm_bindgen::prelude::*;
    use serde::{Serialize, Deserialize};

    /// A share structure for TypeScript binding.
    /// The x and y coordinates are represented as hexadecimal strings.
    #[derive(Serialize, Deserialize)]
    pub struct TSShare {
        pub x: String,
        pub y: String,
    }

    /// Splits a secret key into 4 parts.
    ///
    /// This function expects the secret as a hexadecimal string, and returns a JsValue
    /// representing an array of TSShare objects. It uses a fixed threshold and share count of 4,
    /// meaning that all 4 shares are required to reconstruct the key.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key as a hexadecimal string.
    ///
    /// # Returns
    ///
    /// A JsValue containing an array of TSShare objects.
    #[wasm_bindgen]
    pub fn split_key(secret: &str) -> Result<JsValue, JsValue> {
        // Parse the secret from a hex string into a BigUint.
        let secret_biguint = BigUint::from_str_radix(secret, 16)
            .map_err(|e| JsValue::from_str(&format!("Invalid secret hex string: {}", e)))?;
        
        let p = get_prime();
        
        // Use a fixed threshold and share_count of 4 (all shares required to reconstruct).
        let shares = split_secret(&secret_biguint, 4, 4, &p)
            .map_err(|e| JsValue::from_str(&e))?;
        
        // Convert each share into a TSShare with hexadecimal string representations.
        let ts_shares: Vec<TSShare> = shares.into_iter().map(|s| {
            TSShare {
                x: s.x.to_str_radix(16),
                y: s.y.to_str_radix(16),
            }
        }).collect();
        
        // Serialize the array of TSShare objects into a JsValue.
        serde_wasm_bindgen::to_value(&ts_shares)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }

    /// Reconstructs a secret key from an array of TSShare objects.
    ///
    /// The shares must be provided as a JsValue representing an array where each element has
    /// `x` and `y` fields (both hexadecimal strings). This function returns the reconstructed
    /// secret as a hexadecimal string.
    ///
    /// # Arguments
    ///
    /// * `shares` - A JsValue representing an array of share objects.
    ///
    /// # Returns
    ///
    /// The reconstructed secret key as a hexadecimal string.
    #[wasm_bindgen]
    pub fn reconstruct_key(shares: &JsValue) -> Result<String, JsValue> {
        // Deserialize the JsValue into a vector of TSShare objects.
        let ts_shares: Vec<TSShare> = serde_wasm_bindgen::from_value(shares.clone())
            .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))?;
        
        // Convert each TSShare back into a Share (with BigUint fields).
        let mut shares_converted = Vec::new();
        for s in ts_shares {
            let x = BigUint::from_str_radix(&s.x, 16)
                .map_err(|e| JsValue::from_str(&format!("Invalid x coordinate: {}", e)))?;
            let y = BigUint::from_str_radix(&s.y, 16)
                .map_err(|e| JsValue::from_str(&format!("Invalid y coordinate: {}", e)))?;
            shares_converted.push(Share { x, y });
        }
        
        let p = get_prime();
        let secret = reconstruct_secret(&shares_converted, &p);
        Ok(secret.to_str_radix(16))
    }
}

// Re-export the wasm_bindings module for use when compiling to wasm32.
#[cfg(target_arch = "wasm32")]
pub use wasm_bindings::*;