//! # Core bridge logic: additive ↔ Shamir conversion
//!
//! ## Goal
//! Bidirectional conversion between **additive secret sharing** and **Shamir secret sharing**,
//! bridging MPC stacks such as `cggmp24` and `synedrion`.
//!
//! ## Background
//!
//! 1. **Shamir Secret Sharing (SSS)**:
//!    - Secret `s` is the constant term of a degree-(t-1) polynomial `f(x)`.
//!    - **t-of-n** threshold; any `t` parties can reconstruct.
//!    - **Used by**: `cggmp24` primarily.
//!
//! 2. **Additive Secret Sharing**:
//!    - Secret `s` splits into shares `x_i` with `s = sum x_i mod q`.
//!    - **n-of-n**; linear and simple to combine.
//!    - **Used by**: some Synedrion phases and for simplified cross-protocol use.
//!
//! ## Conversion
//!
//! ### 1. Shamir → Additive (local)
//! - **Method**: Lagrange interpolation.
//! - **Formula**: `w_i = x_i * lambda_{i,S}(0)` for a chosen set `S` of `t` parties.
//! - **Note**: Local only; additive shares `w_i` are defined for that specific `S`.
//!
//! ### 2. Additive → Shamir (interactive)
//! - **Method**: VSS or resharing.
//! - **Flow**: Each party treats its additive share as a secret, shares it with a new polynomial;
//!   new Shamir shares are sums of received sub-shares.
//! - **Note**: Interactive; roughly O(n²) messages.
//!
//! ## Pitfalls
//! 1. **Indexing**: Libraries differ on 0-based vs 1-based party indices; small mistakes break reconstruction.
//! 2. **Security**: The full secret must never be reconstructed on one machine.
//!    - Shamir → additive is a safe local map.
//!    - Additive → Shamir needs a real MPC resharing; collecting all shares and redistributing is trusted-dealer behavior.
//! 3. **Synchronization**: All parties must agree on `t`, participant set `S`, etc., or shares diverge.

use super::common::{pad_hex, strip_0x, PortableKeyShare};
use anyhow::{anyhow, Context, Result};
use elliptic_curve::PrimeField;
use k256::Scalar;

/// Generate a resharing polynomial (Shamir sub-shares for one additive share).
///
/// **Behavior**: Produces Shamir sub-shares for a single additive share.
///
/// **Idea**: Core SSS step: to share secret `s` (here, an additive share) among `n` parties,
/// build degree `(t-1)` polynomial `f` with `f(0) = s`.
///
/// **Steps**:
/// 1. Parse hex to scalar.
/// 2. Call `math::generate_polynomial_shares` for `f(1)..f(n)`.
/// 3. Encode back to hex.
///
/// **Deployment**: Pure compute, but in a real protocol these sub-shares must be sent to the other
/// `n-1` parties over secure channels.
pub fn generate_resharing_polynomial(
    additive_share_hex: &str,
    threshold: u16, // min_signers (degree = threshold - 1)
    n: u16,         // total parties
) -> Result<Vec<String>> {
    // 1. Parse secret (additive share)
    let padded = pad_hex(strip_0x(additive_share_hex).to_string());
    let bytes = hex::decode(&padded)?;

    let mut s_bytes = k256::FieldBytes::default();
    // Handle potential size mismatch
    if bytes.len() > 32 {
        return Err(anyhow!("Scalar bytes too long"));
    }
    let offset = 32 - bytes.len();
    s_bytes[offset..].copy_from_slice(&bytes);

    let secret = Option::<k256::Scalar>::from(k256::Scalar::from_repr(s_bytes))
        .context("Invalid scalar")?;

    // 2. Delegate math to math.rs
    let scalar_shares = crate::math::generate_polynomial_shares(secret, threshold, n);

    // 3. Convert back to Hex
    let hex_shares = scalar_shares
        .iter()
        .map(|s| hex::encode(s.to_bytes()))
        .collect();

    Ok(hex_shares)
}

/// Reshare additive portable shares into Shamir portable shares (simulated MPC resharing).
///
/// **Behavior**: Maps a set of additive shares to Shamir shares as in a resharing round.
///
/// **Idea**: If global secret `x = sum w_i`, each party `i` Shamir-shares `w_i` into sub-shares
/// `w_{i→j}` to party `j`. Party `j` sums: `x_j = sum_i w_{i→j}`. By additivity of polynomials,
/// each `x_j` is a valid Shamir share of `x`.
///
/// **Steps**:
/// 1. **Generate**: each `i` builds sub-share matrix for all receivers.
/// 2. **Distribute**: (simulated) send to recipients.
/// 3. **Aggregate**: each `j` sums incoming sub-shares into a new secret share.
///
/// **Deployment**: Interactive; step 2 needs O(n²) secure channels (e.g. TLS) to avoid sub-share leakage.
pub fn additive_portable_to_shamir_portable(
    mut additive_shares: Vec<PortableKeyShare>,
    threshold: u16,
) -> Result<Vec<PortableKeyShare>> {
    let n = additive_shares.len() as u16;

    // Sort by index so matrix layout matches party order (0, 1, …)
    additive_shares.sort_by_key(|s| s.i);

    // 1. Each party generates sub-shares for everyone
    // shares_sent[i][j] = sub-share from party i to party j
    let mut shares_sent: Vec<Vec<String>> = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let my_additive_share = &additive_shares[i].x_hex;
        // Polynomial f_i and evaluations f_i(1)..f_i(n)
        let sub_shares = generate_resharing_polynomial(my_additive_share, threshold, n)?;
        shares_sent.push(sub_shares);
    }

    // 2. Each party aggregates received sub-shares
    // New share for party j = sum_i shares_sent[i][j]
    for j in 0..n as usize {
        let mut sum_scalar = k256::Scalar::ZERO;
        for i in 0..n as usize {
            // Party j receives from party i
            let share_hex = &shares_sent[i][j];

            let padded = pad_hex(strip_0x(share_hex).to_string());
            let bytes = hex::decode(&padded)?;

            let mut s_bytes = k256::FieldBytes::default();
            let offset = 32 - bytes.len();
            s_bytes[offset..].copy_from_slice(&bytes);

            let s = Option::<k256::Scalar>::from(k256::Scalar::from_repr(s_bytes))
                .context("Invalid scalar")?;
            sum_scalar += s;
        }
        // New Shamir share
        additive_shares[j].x_hex = hex::encode(sum_scalar.to_bytes());
        additive_shares[j].t = threshold;
    }

    Ok(additive_shares)
}

/// Convert Shamir portable share to additive (n-of-n) portable share.
///
/// **Behavior**: Maps standard Shamir (t-of-n) shares to additive shares for the signing subset.
///
/// **Idea**: Lagrange at 0: `x = f(0) = sum_{i in S} x_i * lambda_{i,S}(0)`.
/// Define `w_i = x_i * lambda_{i,S}(0)` so `sum w_i = x`, enabling additive-style signing.
///
/// **Steps**:
/// 1. Fix participant index set `S` (`all_indices`).
/// 2. Compute Lagrange coefficient `lambda_i` for this party.
/// 3. Set `w_i = x_i * lambda_i`.
///
/// **Deployment**: No network; each party agrees on `S` and computes locally.
pub fn shamir_portable_to_additive_portable(
    mut share: PortableKeyShare,
    all_indices: &[u64],
) -> Result<PortableKeyShare> {
    // 1. Parse secret (Shamir share)
    let padded = pad_hex(strip_0x(&share.x_hex).to_string());
    let bytes = hex::decode(&padded)?;
    let mut s_bytes = k256::FieldBytes::default();
    if bytes.len() > 32 {
        return Err(anyhow!("Scalar bytes too long"));
    }
    let offset = 32 - bytes.len();
    s_bytes[offset..].copy_from_slice(&bytes);
    
    let secret = Option::<Scalar>::from(Scalar::from_repr(s_bytes)).context("Invalid scalar")?;

    // 2. Calculate Lagrange Coefficient
    // Note: cggmp uses 0-based index i, so x = i + 1 for polynomial evaluation
    let my_idx = share.i as u64 + 1;
    let lambda = crate::math::calculate_lagrange_coefficient(my_idx, all_indices);

    // 3. Convert to Additive Share: w_i = x_i * lambda_i
    let additive_secret = secret * lambda;

    // 4. Update share
    share.x_hex = hex::encode(additive_secret.to_bytes());
    
    // Additive sharing is effectively n-of-n here: threshold = total parties
    share.t = share.n;

    Ok(share)
}
