use super::common::{pad_hex, strip_0x, PortableKeyShare};
use anyhow::{anyhow, Context, Result};
use cggmp24::generic_ec::{Point, Scalar};
#[allow(unused_imports)]
use cggmp24::key_share::AnyKeyShare; // Trait glue; may be required by downstream code
use cggmp24::key_share::KeyShare as CggmpKeyShare;
use cggmp24::security_level::SecurityLevel;
use serde_json::Value;

// ============================================================================
// CGGMP24 adapters
// ============================================================================

/// Export a cggmp24 key share to the portable format.
///
/// **Behavior**: Converts `cggmp24::KeyShare` into a `PortableKeyShare`.
pub fn from_cggmp_to_portable<E: cggmp24::generic_ec::Curve, L: SecurityLevel>(
    share: &CggmpKeyShare<E, L>,
) -> Result<PortableKeyShare> {
    // Use serde to bypass private field access
    let v: Value = serde_json::to_value(share)?;

    // 1. Extract core.x
    // cggmp24 serializes scalars as hex strings usually
    let raw_x_hex = v
        .pointer("/core/x")
        .and_then(|s| s.as_str())
        .context("Missing core.x")?
        .to_string();
    let x_hex = pad_hex(strip_0x(&raw_x_hex).to_string());

    // 2. Extract Public Key Y
    let y_hex = hex::encode(share.shared_public_key().to_bytes(true));

    // 3. Extract metadata
    let i = v.pointer("/core/i").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
    let min_signers = v
        .pointer("/core/vss_setup/min_signers")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;
    let n = v
        .pointer("/core/vss_setup/I")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0) as u16;

    Ok(PortableKeyShare {
        i,
        t: min_signers,
        n,
        x_hex,
        y_hex,
    })
}

/// Patch a cggmp24 key share with refreshed portable data.
///
/// **Behavior**: Updates an existing `cggmp24::KeyShare` template using refreshed `PortableKeyShare` fields.
pub fn from_portable_to_cggmp<E, L>(
    template_share: &CggmpKeyShare<E, L>,
    refreshed: &PortableKeyShare,
    new_public_shares: Option<&[String]>,
    new_vss_commitments: Option<&[String]>,
) -> Result<CggmpKeyShare<E, L>>
where
    E: cggmp24::generic_ec::Curve,
    L: SecurityLevel,
{
    let mut share_json = serde_json::to_value(template_share)?;

    // Update Core (x)
    if let Some(core) = share_json.get_mut("core") {
        if let Some(x_field) = core.get_mut("x") {
            *x_field = serde_json::Value::String(refreshed.x_hex.clone());
        }

        // Update Public Shares
        if let Some(ps) = new_public_shares {
            if let Some(ps_field) = core.get_mut("public_shares") {
                *ps_field = serde_json::json!(ps);
            }
        }

        // Update VSS Commitments
        if let Some(comm) = new_vss_commitments {
            if !comm.is_empty() {
                if let Some(vss) = core.get_mut("vss_setup") {
                    if let Some(comm_field) = vss.get_mut("commitments") {
                        *comm_field = serde_json::json!(comm);
                    }
                }
                // The shared public key must match the first commitment (constant term of the polynomial).
                if let Some(first_comm) = comm.first() {
                    if let Some(pk_field) = core.get_mut("shared_public_key") {
                        *pk_field = serde_json::Value::String(first_comm.clone());
                    }
                }
            }
        }
    }

    let updated_share: CggmpKeyShare<E, L> =
        serde_json::from_value(share_json).context("Failed to deserialize patched KeyShare")?;

    Ok(updated_share)
}

/// Reconstruct global parameters (VSS commitments and public shares).
///
/// **Behavior**: From a set of `PortableKeyShare` (Shamir shares), reconstruct the polynomial and
/// compute VSS commitments and public shares. These parameters are identical for every party.
///
/// **Why reconstruct**:
/// 1. **Consistency**: cggmp24's `KeyShare` holds not only the local secret share but also global
///    data defining the secret polynomial (VSS commitments) and every party's public share.
/// 2. **Origin**: When private shares `x` are updated via the bridge (e.g. from Synedrion or an
///    external refresh), the old global data (old polynomial) is invalid. New polynomial parameters
///    must be derived from the new shares or `KeyShare` is internally inconsistent.
/// 3. **If skipped**: Later MPC signing ZK proofs fail (proofs bind to commitments), aborting the
///    protocol or flagging parties as malicious.
///
/// **Communication & security**:
/// - **Note**: This implementation takes a slice of **secret shares** (`x_hex`).
/// - **Typical use**: Trusted-dealer mode or local simulation/testing.
/// - **Production**: No single party should hold all secret shares. Real DKG/resharing exchanges
///   public shares or commitments, not collected secrets. This function approximates the global
///   state agreed at DKG end.
///
/// TODO:
// - CGGMP here recomputes public keys from secrets; Synedrion outputs public keys from the protocol.
// - Future: drive CGGMP updates from Synedrion's public key list to avoid redundant work and secret aggregation.
pub fn reconstruct_global_params<E: cggmp24::generic_ec::Curve>(
    refreshed_data: &[PortableKeyShare],
) -> Result<(Vec<String>, Vec<String>)> {
    // 1. Reconstruct polynomial coefficients
    let mut shares_points = Vec::new();
    for data in refreshed_data {
        let x_bytes = hex::decode(&data.x_hex)?;
        let x_scalar = Scalar::<E>::from_be_bytes_mod_order(&x_bytes);
        // x coordinate for party i is i+1 (cggmp convention)
        let x_coord = Scalar::<E>::from(data.i as u64 + 1);
        let y_point = Point::<E>::generator() * x_scalar;
        shares_points.push((x_coord, y_point));
    }

    let n_shares = shares_points.len();
    if n_shares == 0 {
        return Err(anyhow!("No refreshed data provided"));
    }
    let required_min_signers = refreshed_data[0].t as usize;
    if n_shares < required_min_signers {
        return Err(anyhow!(
            "Not enough parties to reconstruct polynomial: need {}, got {}",
            required_min_signers,
            n_shares
        ));
    }

    // Lagrange Interpolation to find coefficients
    let zero_point = Point::<E>::generator() * Scalar::<E>::from(0u64);
    let mut coeffs = vec![zero_point; n_shares];

    for i in 0..n_shares {
        let (xi, yi) = shares_points[i];
        let mut denom = Scalar::<E>::from(1u64);
        for j in 0..n_shares {
            if i == j {
                continue;
            }
            let (xj, _) = shares_points[j];
            denom = denom * (xi - xj);
        }
        let inv_denom = denom.invert().ok_or(anyhow!("Inversion failed"))?;

        let mut poly = vec![Scalar::<E>::from(0u64); n_shares];
        poly[0] = Scalar::<E>::from(1u64);

        for j in 0..n_shares {
            if i == j {
                continue;
            }
            let (xj, _) = shares_points[j];
            for k in (1..n_shares).rev() {
                poly[k] = poly[k - 1] - xj * poly[k];
            }
            poly[0] = -xj * poly[0];
        }

        for k in 0..n_shares {
            coeffs[k] = coeffs[k] + yi * (poly[k] * inv_denom);
        }
    }

    let new_commitments_hex: Vec<String> = coeffs
        .iter()
        .map(|c| hex::encode(c.to_bytes(true)))
        .collect();

    // 2. Compute everyone's public shares
    let n_total = refreshed_data.first().map(|d| d.n).unwrap_or(0) as usize;
    let mut new_public_shares_hex = Vec::with_capacity(n_total);

    for i in 0..n_total {
        let x_coord = Scalar::<E>::from((i + 1) as u64);
        let mut y_point = Point::<E>::generator() * Scalar::<E>::from(0u64);
        let mut x_pow = Scalar::<E>::one();
        for coeff in &coeffs {
            y_point = y_point + *coeff * x_pow;
            x_pow = x_pow * x_coord;
        }
        new_public_shares_hex.push(hex::encode(y_point.to_bytes(true)));
    }

    Ok((new_commitments_hex, new_public_shares_hex))
}

/// Batch-update cggmp24 key shares from portable Shamir shares.
///
/// **Behavior**: Reconstructs the polynomial from new `PortableKeyShare` values, computes global
/// parameters (VSS commitments, public shares), and updates every `cggmp24` `KeyShare`.
pub fn update_cggmp_shares_from_portable<E, L>(
    old_shares_templates: &[CggmpKeyShare<E, L>],
    refreshed_data: &[PortableKeyShare],
) -> Result<Vec<CggmpKeyShare<E, L>>>
where
    E: cggmp24::generic_ec::Curve,
    L: SecurityLevel,
{
    let (new_commitments_hex, new_public_shares_hex) =
        reconstruct_global_params::<E>(refreshed_data)?;

    let mut updated_cggmp_shares = Vec::new();
    // Create a map for refreshed data to match by ID
    let refreshed_map: std::collections::HashMap<u16, &PortableKeyShare> =
        refreshed_data.iter().map(|s| (s.i, s)).collect();

    for template_share in old_shares_templates {
        let party_id = template_share.core.i;
        if let Some(refreshed) = refreshed_map.get(&party_id) {
            let updated_share = from_portable_to_cggmp(
                template_share,
                refreshed,
                Some(&new_public_shares_hex),
                Some(&new_commitments_hex),
            )?;
            updated_cggmp_shares.push(updated_share);
        } else {
            return Err(anyhow!("Missing refreshed data for party {}", party_id));
        }
    }

    Ok(updated_cggmp_shares)
}
