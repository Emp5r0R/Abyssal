// Replaced only through the documented offline release-key ceremony. This
// sentinel is intentionally unusable: every production verification fails
// closed until a real public key is reviewed and committed.
#[cfg(not(feature = "integration-release-root"))]
pub const RELEASE_PUBKEY: [u8; 32] = [0; 32];

#[cfg(all(feature = "integration-release-root", not(debug_assertions)))]
compile_error!("the integration release root is forbidden in release builds");

// Public half of the fixed test-only seed used by the loopback integration
// harness. Production and release builds never enable this feature.
#[cfg(feature = "integration-release-root")]
pub const RELEASE_PUBKEY: [u8; 32] = [
    0xea, 0x4a, 0x6c, 0x63, 0xe2, 0x9c, 0x52, 0x0a, 0xbe, 0xf5, 0x50, 0x7b, 0x13, 0x2e, 0xc5, 0xf9,
    0x95, 0x47, 0x76, 0xae, 0xbe, 0xbe, 0x7b, 0x92, 0x42, 0x1e, 0xea, 0x69, 0x14, 0x46, 0xd2, 0x2c,
];
