//! Core math for MPC: Shamir Secret Sharing (SSS) and Lagrange interpolation.
//!
//! ## Features
//!
//! 1. **`calculate_lagrange_coefficient`**:
//!    - Used in t-of-n threshold signing to turn Shamir shares into additive shares.
//!    - Key step for collaborative signing without exposing the full secret.
//!
//! 2. **`generate_polynomial_shares`**:
//!    - Used for distributed resharing or refresh.
//!    - Builds a random polynomial and splits a secret (e.g. an additive share) into sub-shares for other parties.
//!
//! ## Security
//!
//! - All arithmetic is in the prime field using `k256::Scalar`.
//! - Randomness uses `OsRng`.
//! - This module is math-only; no networking or key storage.
//!
//! There are generic secret-sharing crates (e.g. `vsss-rs`); we keep a small local implementation
//! to avoid index conventions (0-based vs 1-based) biting us. We can revisit `vsss-rs` later.

use elliptic_curve::Field;
use k256::Scalar;
use rand_core::OsRng;

/// Lagrange interpolation coefficient λ_i at x = 0.
///
/// ### Theory
/// In SSS/MPC, to recover the secret (or build additive shares) from `t` shares we use Lagrange
/// interpolation. For party indices `S` with `|S| ≥ t`, the secret `s = f(0)` satisfies
/// $$ f(0) = \sum_{i \in S} y_i \cdot \lambda_{i, S}(0) $$
/// where λ_{i,S}(0) is the Lagrange basis evaluated at 0:
/// $$ \lambda_{i, S} = \prod_{j \in S, j \neq i} \frac{x_j}{x_j - x_i} $$
///
/// ### Parameters
/// - `party_index`: This party's x-coordinate (usually 1-based).
/// - `all_indices`: Full set `S = {x_1, …, x_t}` used in the reconstruction.
///
/// ### References
/// - Shamir's Secret Sharing
/// - Lagrange polynomial
pub fn calculate_lagrange_coefficient(party_index: u64, all_indices: &[u64]) -> Scalar {
    let my_x = Scalar::from(party_index);
    let mut lambda = Scalar::ONE;
    
    for &other_idx in all_indices {
        let other_x = Scalar::from(other_idx);
        if other_x == my_x {
            continue;
        }
        // Formula: lambda *= x_j / (x_j - x_i)
        // Note: In finite fields, division is multiplication by modular inverse.
        // num = x_j
        // den = x_j - x_i
        // We use a slightly different form in code often:
        // lambda_i = Product_{j!=i} (0 - x_j) / (x_i - x_j)
        // Which simplifies to Product_{j!=i} x_j / (x_j - x_i)
        
        let num = other_x;
        let den = (other_x - my_x).invert().unwrap();
        lambda *= num * den;
    }
    lambda
}

/// Generate Shamir shares for a secret (polynomial evaluation at 1..n).
///
/// ### Theory
/// To share secret `s` among `n` parties such that any `t` can recover, use a degree `(t-1)` polynomial
/// $$ f(x) = s + a_1 x + a_2 x^2 + \dots + a_{t-1} x^{t-1} \pmod q $$
/// - `s` is the constant term.
/// - `a_1, …, a_{t-1}` are random field elements.
///
/// Party `P_j` (index `j ∈ {1,…,n}`) gets `y_j = f(j)`.
///
/// ### Usage
/// Used in MPC **resharing**: each node uses its additive share as the constant term, distributes
/// polynomial evaluations, and refreshes or reallocates without exposing the full key.
///
/// ### Parameters
/// - `secret`: Constant term of the polynomial.
/// - `threshold`: Minimum parties `t` to recover (polynomial degree is `t-1`).
/// - `n`: Total parties; produces `n` evaluations.
///
/// ### Returns
/// Vector of `n` scalars: values at `x = 1, …, n`.
pub fn generate_polynomial_shares(
    secret: Scalar,
    threshold: u16,
    n: u16,
) -> Vec<Scalar> {
    // 1. Polynomial degree = t - 1
    let degree = (threshold as usize).saturating_sub(1);
    
    // 2. Random coefficients
    // f(x) = secret + a_1*x + ... + a_{t-1}*x^{t-1}
    let mut coeffs = Vec::with_capacity(degree + 1);
    coeffs.push(secret); // a_0 = secret

    for _ in 0..degree {
        coeffs.push(Scalar::random(&mut OsRng));
    }

    // 3. Evaluate f(1)..f(n)
    let mut shares = Vec::with_capacity(n as usize);
    for j in 1..=n {
        let x = Scalar::from(j as u64);
        let mut y = Scalar::ZERO;
        
        // Horner's method or direct sum for polynomial evaluation
        let mut x_pow = Scalar::ONE;
        for coeff in &coeffs {
            y += *coeff * x_pow;
            x_pow *= x;
        }
        shares.push(y);
    }

    shares
}
