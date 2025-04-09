use adi_shamir_sharing::{get_prime, split_secret, reconstruct_secret};
use num_bigint::BigUint;
use num_traits::Num;

/// The main function demonstrating the splitting and reconstruction of a secret.
///
/// It splits a small example secret into multiple shares and then reconstructs the secret
/// from a subset of those shares.
fn main() {
    println!("Shamir's Secret Sharing Demo");

    // For demonstration purposes, we'll split a small secret.
    let secret_str = "123456789";
    let secret = BigUint::from_str_radix(secret_str, 10)
        .expect("Failed to parse the secret");

    let threshold = 3;
    let total_shares = 5;
    let p = get_prime();
    let shares = split_secret(&secret, threshold, total_shares, &p)
        .expect("Failed to split secret");

    println!("Generated shares:");
    for share in &shares {
        println!("x: {}, y: {}", share.x, share.y);
    }

    // Reconstruct the secret from the first `threshold` shares.
    let subset = &shares[0..threshold];
    let recovered = reconstruct_secret(subset, &p);
    println!("Recovered secret: {}", recovered);
}
