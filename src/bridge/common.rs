// ============================================================================
// 1. Data structures
// ============================================================================

/// Portable key share (`PortableKeyShare`)
///
/// Intermediate format made entirely of hex strings for moving data between MPC
/// libraries or persisting to disk, without concrete Rust type coupling.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct PortableKeyShare {
    pub i: u16,        // Party index
    pub t: u16,        // Threshold
    pub n: u16,        // Total party count
    pub x_hex: String, // Secret share (scalar)
    pub y_hex: String, // Aggregate public key (point, compressed hex)
}

// ============================================================================
// 2. Hex string helpers
// ============================================================================

pub fn ensure_0x(s: &str) -> String {
    if s.starts_with("0x") {
        s.to_string()
    } else {
        format!("0x{}", s)
    }
}

pub fn strip_0x(s: &str) -> &str {
    s.trim_start_matches("0x")
}

pub fn pad_hex(s: String) -> String {
    if s.len() % 2 != 0 {
        format!("0{}", s)
    } else {
        s
    }
}
