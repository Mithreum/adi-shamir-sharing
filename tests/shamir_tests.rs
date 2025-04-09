use adi_shamir_sharing::{get_prime, split_secret, reconstruct_secret};
use num_bigint::BigUint;

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Num;

    /// Test the algorithm with an Ethereum (EVM) private key.
    #[test]
    fn test_evm_private_key() {
        let p = get_prime();
        let evm_key_str = "4c0883a69102937d6231471b5dbb6204fe512961708279e6ae5d47ee21b7e1cd";
        let secret = BigUint::from_str_radix(evm_key_str, 16).unwrap();
        let threshold = 3;
        let total_shares = 5;
        let shares = split_secret(&secret, threshold, total_shares, &p)
            .expect("Failed to split secret into shares.");
        let subset = shares[0..threshold].to_vec();
        let recovered = reconstruct_secret(&subset, &p);
        assert_eq!(secret, recovered, "Recovered EVM key does not match the original.");
    }

    /// Test the algorithm with a Solana private key.
    #[test]
    fn test_solana_private_key() {
        let p = get_prime();
        let solana_key_str = "3f9d86dc77a19a6f7a1ee2dc19f7528409929a1c8ee0f0b9807c3af87bf98e3d";
        let secret = BigUint::from_str_radix(solana_key_str, 16).unwrap();
        let threshold = 4;
        let total_shares = 7;
        let shares = split_secret(&secret, threshold, total_shares, &p)
            .expect("Failed to split secret into shares.");
        let subset = shares[0..threshold].to_vec();
        let recovered = reconstruct_secret(&subset, &p);
        assert_eq!(secret, recovered, "Recovered Solana key does not match the original.");
    }
}