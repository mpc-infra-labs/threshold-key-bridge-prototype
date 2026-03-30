use super::common::{
    truncate_hex, FastSecp256k1, SimpleSessionParams, SimpleSigner, SimpleVerifier,
};
use crate::bridge;
use crate::eth_utils::{calc_recovery_id, compute_eth_address_from_pubkey};
use anyhow::{anyhow, Context};
use elliptic_curve::CurveArithmetic;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use rand_core::OsRng;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Run Synedrion's native AuxGen to produce auxiliary data (e.g. Paillier keys).
pub async fn run_synedrion_aux_gen<P>(
    party_ids: BTreeSet<u16>,
) -> anyhow::Result<BTreeMap<u16, synedrion::AuxInfo<P, u16>>>
where
    P: synedrion::SchemeParams + Send + Sync + 'static,
    P::Paillier: Send + Sync,
    <P::Curve as CurveArithmetic>::ProjectivePoint: Send + Sync,
    <P::Curve as CurveArithmetic>::Scalar: Send + Sync,
{
    use manul::dev::tokio::run_async;
    use synedrion::AuxGen;

    let cache_path = "data/synedrion_aux_gen.json";
    if Path::new(cache_path).exists() {
        println!("      [INFO] Found Synedrion AuxGen cache, loading...");
        match fs::read_to_string(cache_path) {
            Ok(content) => {
                match serde_json::from_str::<BTreeMap<u16, synedrion::AuxInfo<P, u16>>>(&content) {
                    Ok(cached_data) => {
                        let cached_keys: BTreeSet<u16> = cached_data.keys().cloned().collect();
                        if cached_keys == party_ids {
                            println!("      [INFO] Loaded cached AuxInfo");
                            return Ok(cached_data);
                        }
                        println!(
                            "      [WARN] Cached parties ({:?}) != requested ({:?}); regenerating.",
                            cached_keys, party_ids
                        );
                    }
                    Err(e) => println!("      [WARN] Cache parse failed: {}; regenerating.", e),
                }
            }
            Err(e) => println!("      [WARN] Cache read failed: {}; regenerating.", e),
        }
    }

    println!("      (sim) Synedrion AuxGen Protocol Start...");

    let mut entry_points = Vec::new();
    let verifiers: BTreeSet<SimpleVerifier> =
        party_ids.iter().map(|&id| SimpleVerifier(id)).collect();

    for &id in &party_ids {
        let signer = SimpleSigner {
            id,
            verifier: SimpleVerifier(id),
        };
        let entry_point = AuxGen::<P, SimpleVerifier>::new(verifiers.clone())
            .map_err(|e| anyhow!("Failed to create AuxGen: {}", e))?;
        entry_points.push((signer, entry_point));
    }

    let execution_result = run_async::<_, SimpleSessionParams>(&mut OsRng, entry_points, true)
        .await
        .map_err(|e| anyhow!("AuxGen simulation failed: {}", e))?;

    let results = execution_result
        .results()
        .map_err(|e| anyhow!("AuxGen protocol execution failed: {}", e))?;

    // Map SimpleVerifier results to u16 party ids for the rest of the demo
    let mut converted_results = BTreeMap::new();
    for (verifier, aux) in results {
        let aux_json = serde_json::to_string(&aux)?;
        let aux_u16: synedrion::AuxInfo<P, u16> = serde_json::from_str(&aux_json)?;
        converted_results.insert(verifier.0, aux_u16);
    }

    if let Ok(json) = serde_json::to_string_pretty(&converted_results) {
        let _ = fs::write(cache_path, json);
        println!("      [INFO] Synedrion AuxInfo saved to {}", cache_path);
    }

    Ok(converted_results)
}

pub async fn run_synedrion_refresh_simulation<P>(
    shares: Vec<synedrion::KeyShare<P, u16>>,
    _t: u16,
) -> anyhow::Result<
    BTreeMap<
        SimpleVerifier,
        (
            synedrion::KeyShareChange<P, SimpleVerifier>,
            synedrion::AuxInfo<P, SimpleVerifier>,
        ),
    >,
>
where
    <P::Curve as CurveArithmetic>::ProjectivePoint:
        FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
    P: synedrion::SchemeParams + Send + Sync + 'static,
    P::Paillier: Send + Sync,
    <P::Curve as CurveArithmetic>::ProjectivePoint: Send + Sync,
    <P::Curve as CurveArithmetic>::Scalar: Send + Sync,
{
    use manul::dev::tokio::run_async;
    use synedrion::KeyRefresh;

    println!("      (sim) Synedrion Refresh Protocol Start...");
    let n = shares.len() as u16;
    if n == 0 {
        return Ok(BTreeMap::new());
    }
    let party_ids: BTreeSet<u16> = (0..n).collect();

    let mut original_public_shares = BTreeMap::new();
    for share in &shares {
        if let Ok(pt) = bridge::get_public_share_point(share, *share.owner()) {
            original_public_shares.insert(share.owner(), pt);
        }
    }

    let mut entry_points = Vec::new();
    for (i, share) in shares.iter().enumerate() {
        let signer = SimpleSigner {
            id: i as u16,
            verifier: SimpleVerifier(i as u16),
        };
        let _share_conv = bridge::convert_synedrion_key_share::<P, u16, SimpleVerifier>(share)?;
        let ids_conv: BTreeSet<SimpleVerifier> =
            party_ids.iter().map(|&id| SimpleVerifier(id)).collect();
        let entry_point = KeyRefresh::<P, SimpleVerifier>::new(ids_conv)
            .map_err(|e| anyhow!("Failed to create KeyRefresh: {}", e))?;
        entry_points.push((signer, entry_point));
    }

    let execution_result = run_async::<_, SimpleSessionParams>(&mut OsRng, entry_points, true)
        .await
        .map_err(|e| anyhow!("Simulation failed: {}", e))?;
    let results = execution_result
        .results()
        .map_err(|e| anyhow!("Protocol execution failed: {}", e))?;
    println!("\n      === Refresh summary ===");
    for (verifier, (new_share, new_aux)) in &results {
        let new_n =
            bridge::get_aux_n_hex(new_aux, *verifier).unwrap_or_else(|_| "unknown".to_string());

        // Calculate new global public key using bridge helper
        let mut new_global_pk = None;
        for (pid, original_pt) in &original_public_shares {
            let v_id = SimpleVerifier(**pid);
            if let Ok(Some(delta)) = bridge::extract_refresh_delta(new_share, v_id) {
                let updated_pt = *original_pt + delta;
                new_global_pk = match new_global_pk {
                    Some(acc) => Some(acc + updated_pt),
                    None => Some(updated_pt),
                };
            }
        }
        let refreshed_pk_hex = new_global_pk
            .map(|p| hex::encode(p.to_encoded_point(true).as_bytes()))
            .unwrap_or_else(|| "N/A".to_string());

        println!("       Party {}:", verifier.0);
        println!(
            "        - [ECDSA] Global pubkey (after refresh): 0x{}",
            refreshed_pk_hex
        );
        println!("        - [Paillier] New N = {}", truncate_hex(&new_n));
    }
    Ok(results)
}
pub async fn run_synedrion_signing_simulation<P>(
    parties_data: &BTreeMap<
        SimpleVerifier,
        (
            synedrion::KeyShare<P, SimpleVerifier>,
            synedrion::AuxInfo<P, SimpleVerifier>,
        ),
    >,
    message_hash: [u8; 32],
) -> anyhow::Result<([u8; 32], [u8; 32], u8)>
where
    P: synedrion::SchemeParams + Send + Sync + 'static,
    <P::Curve as CurveArithmetic>::ProjectivePoint:
        FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
    elliptic_curve::FieldBytes<P::Curve>: From<[u8; 32]>,
{
    use manul::dev::tokio::run_async;
    use synedrion::InteractiveSigning;

    println!("      Synedrion Signing Protocol Start...");

    // Active signers only
    let active_verifiers: BTreeSet<SimpleVerifier> = parties_data.keys().cloned().collect();

    let mut entry_points = Vec::new();
    for (verifier, (share, aux)) in parties_data {
        let signer = SimpleSigner {
            id: verifier.0,
            verifier: *verifier,
        };

        // Filter `public` in KeyShare to active parties only; otherwise Synedrion may message
        // absent parties and hit "channel closed unexpectedly" in local simulation.
        let mut share_val = serde_json::to_value(share)?;
        if let Some(public_list) = share_val.get_mut("public").and_then(|v| v.as_array_mut()) {
            public_list.retain(|item| {
                if let Some(id_val) = item.get(0) {
                    if let Ok(id) = serde_json::from_value::<SimpleVerifier>(id_val.clone()) {
                        return active_verifiers.contains(&id);
                    }
                }
                false
            });
        }
        let filtered_share: synedrion::KeyShare<P, SimpleVerifier> =
            serde_json::from_value(share_val)?;

        // Same for AuxInfo: KeyShare and AuxInfo must list the same party set
        let mut aux_val = serde_json::to_value(aux)?;
        if let Some(public_list) = aux_val.get_mut("public").and_then(|v| v.as_array_mut()) {
            public_list.retain(|item| {
                if let Some(id_val) = item.get(0) {
                    if let Ok(id) = serde_json::from_value::<SimpleVerifier>(id_val.clone()) {
                        return active_verifiers.contains(&id);
                    }
                }
                false
            });
        }
        let filtered_aux: synedrion::AuxInfo<P, SimpleVerifier> = serde_json::from_value(aux_val)?;

        let protocol = InteractiveSigning::new(message_hash.into(), filtered_share, filtered_aux)
            .map_err(|e| anyhow!("Synedrion error: {:?}", e))?;
        entry_points.push((signer, protocol));
    }

    let execution_result = run_async::<_, SimpleSessionParams>(&mut OsRng, entry_points, true)
        .await
        .map_err(|e| anyhow!("Signing failed: {}", e))?;
    let results: BTreeMap<SimpleVerifier, synedrion::RecoverableSignature<P>> = execution_result
        .results()
        .map_err(|e| anyhow!("Protocol failed: {:?}", e))?;

    let (_, signature) = results.first_key_value().context("No signature produced")?;
    let (backend_sig, _) = signature.clone().to_backend();
    let (r_field, s_field) = backend_sig.split_bytes();
    let r_bytes: [u8; 32] = r_field
        .to_vec()
        .try_into()
        .map_err(|_| anyhow!("r error"))?;
    let s_bytes: [u8; 32] = s_field
        .to_vec()
        .try_into()
        .map_err(|_| anyhow!("s error"))?;

    let first_share = &parties_data.values().next().unwrap().0;
    let global_pk_point =
        bridge::get_global_public_key_point(first_share).expect("Failed to get global pk");
    let pk_bytes = global_pk_point.to_encoded_point(false).as_bytes().to_vec();
    let expected_addr = compute_eth_address_from_pubkey(&pk_bytes);
    let v = calc_recovery_id(&r_bytes, &s_bytes, &message_hash, expected_addr)
        .map_err(|e| anyhow!(e))?;

    Ok((r_bytes, s_bytes, v))
}

pub async fn run_refresh_workflow(
    synedrion_data: Vec<(
        synedrion::KeyShare<FastSecp256k1, u16>,
        synedrion::AuxInfo<FastSecp256k1, u16>,
    )>,
    threshold: u16,
    cache_path: &str,
    force_refresh: bool,
) -> anyhow::Result<
    BTreeMap<
        SimpleVerifier,
        (
            synedrion::KeyShare<FastSecp256k1, SimpleVerifier>,
            synedrion::AuxInfo<FastSecp256k1, SimpleVerifier>,
        ),
    >,
> {
    let mut updated_shares = BTreeMap::new();
    let mut cache_loaded = false;

    if Path::new(cache_path).exists() && !force_refresh {
        let result: anyhow::Result<()> = (|| {
            let content = fs::read_to_string(cache_path)?;
            updated_shares = serde_json::from_str(&content)?;
            Ok(())
        })();

        if let Ok(_) = result {
            println!("       Loaded Synedrion post-refresh cache.");
            cache_loaded = true;
        } else {
            println!(
                "       Cache invalid or corrupt ({:?}); re-running Key Refresh...",
                result.err().unwrap()
            );
            updated_shares.clear();
        }
    }

    if !cache_loaded {
        let synedrion_data_backup = synedrion_data.clone();
        let shares_only: Vec<_> = synedrion_data.into_iter().map(|(s, _)| s).collect();
        let refreshed_changes = run_synedrion_refresh_simulation(shares_only, threshold).await?;

        for (share, aux) in synedrion_data_backup {
            let (share_conv, aux_conv) =
                bridge::convert_synedrion_types::<FastSecp256k1, u16, SimpleVerifier>(
                    &share, &aux,
                )?;
            let verifier = *share_conv.owner();

            if let Some((change, _new_aux)) = refreshed_changes.get(&verifier) {
                let updated_share = share_conv.update(change.clone()).expect("Update failed");
                updated_shares.insert(verifier, (updated_share, aux_conv));
            }
        }

        let json = serde_json::to_string_pretty(&updated_shares)?;
        fs::write(cache_path, json)?;
        println!("       Saved refreshed Synedrion data to {}", cache_path);
    }

    Ok(updated_shares)
}
