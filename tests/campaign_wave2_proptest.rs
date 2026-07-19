//! WAVE2 (openpack limits invariants).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

macro_rules! wave2_openpack {
    ($($name:ident => |$bind:ident| $body:block),+ $(,)?) => {
        $(proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]
            #[test]
            fn $name($bind in prop::collection::vec(any::<u8>(), 0..256)) {
                $body
            }
        })+
    };
}

wave2_openpack! {
    p00_strict_limits_validate => |p| { let l = openpack::Limits::strict(); prop_assert!(l.max_archive_size > 0); prop_assert!(l.max_entries > 0); },
    p01_permissive_gt_strict_archive => |p| { let s = openpack::Limits::strict(); let pm = openpack::Limits::permissive(); prop_assert!(pm.max_archive_size > s.max_archive_size); },
    p02_from_toml_no_panic => |p| { let raw = String::from_utf8_lossy(&p); let _ = openpack::Limits::from_toml(&raw); },
    p03_zero_max_entries_toml_rejects => |p| { let raw = "max_archive_size=1\nmax_entry_uncompressed_size=1\nmax_total_uncompressed_size=1\nmax_entries=0\nmax_compression_ratio=1.0"; prop_assert!(openpack::Limits::from_toml(raw).is_err()); },
    p04_nan_ratio_rejects => |p| { let raw = "max_archive_size=1\nmax_entry_uncompressed_size=1\nmax_total_uncompressed_size=1\nmax_entries=1\nmax_compression_ratio=nan"; prop_assert!(openpack::Limits::from_toml(raw).is_err()); },
    p05_total_gte_entry_in_strict => |p| { let l = openpack::Limits::strict(); prop_assert!(l.max_total_uncompressed_size >= l.max_entry_uncompressed_size); },
    p06_builtin_matches_strict_order => |p| { let b = openpack::Limits::builtin(); let s = openpack::Limits::strict(); prop_assert!(b.max_entries >= s.max_entries); },
    p07_valid_minimal_toml_parses => |p| { let raw = "max_archive_size = 1024\nmax_entry_uncompressed_size = 512\nmax_total_uncompressed_size = 1024\nmax_entries = 10\nmax_compression_ratio = 2.0"; prop_assert!(openpack::Limits::from_toml(raw).is_ok()); },
    p08_invalid_total_lt_entry_rejects => |p| { let raw = "max_archive_size=100\nmax_entry_uncompressed_size=50\nmax_total_uncompressed_size=10\nmax_entries=5\nmax_compression_ratio=2.0"; prop_assert!(openpack::Limits::from_toml(raw).is_err()); },
}
