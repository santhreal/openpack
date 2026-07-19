#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Mass archive byte roundtrip properties (S-proptest-02).

use proptest::prelude::*;
use zip::CompressionMethod;

use openpack::{OpenPack, OpenPackError};

use super::archive_helpers::{permissive_limits, write_zip, Scratch};

macro_rules! archive_read_roundtrip {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(32))]

            $(
                #[test]
                fn $name(data in prop::collection::vec(any::<u8>(), 0..4096)) {
                    let archive = Scratch::new("zip");
                    write_zip(
                        &archive.path,
                        &[("payload.bin", &data, CompressionMethod::Stored)],
                    );
                    if let Ok(pack) = OpenPack::open(&archive.path, permissive_limits()) {
                        match pack.read_entry("payload.bin") {
                            Ok(read) => assert_eq!(read, data),
                            Err(e) => assert!(
                                matches!(e, OpenPackError::LimitExceeded(_) | OpenPackError::Zip(_)),
                                "{e:?}"
                            ),
                        }
                    }
                }
            )+
        }
    };
}

archive_read_roundtrip! {
    archive_bytes_roundtrip_01,
    archive_bytes_roundtrip_02,
    archive_bytes_roundtrip_03,
    archive_bytes_roundtrip_04,
    archive_bytes_roundtrip_05,
    archive_bytes_roundtrip_06,
    archive_bytes_roundtrip_07,
    archive_bytes_roundtrip_08,
    archive_bytes_roundtrip_09,
    archive_bytes_roundtrip_10,
    archive_bytes_roundtrip_11,
    archive_bytes_roundtrip_12,
    archive_bytes_roundtrip_13,
    archive_bytes_roundtrip_14,
    archive_bytes_roundtrip_15,
    archive_bytes_roundtrip_16,
    archive_bytes_roundtrip_17,
    archive_bytes_roundtrip_18,
    archive_bytes_roundtrip_19,
    archive_bytes_roundtrip_20,
}

macro_rules! archive_content_props {
    ($($name:ident),+ $(,)?) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(24))]

            $(
                #[test]
                fn $name(
                    data in prop::collection::vec(any::<u8>(), 0..256),
                ) {
                    let archive = Scratch::new("zip");
                    write_zip(&archive.path, &[("h.bin", &data, CompressionMethod::Stored)]);
                    if let Ok(pack) = OpenPack::open(&archive.path, permissive_limits()) {
                        if let Ok(a) = pack.read_entry("h.bin") {
                            if let Ok(b) = pack.read_entry("h.bin") {
                                assert_eq!(a, b);
                                assert_eq!(a, data);
                            }
                        }
                    }
                }
            )+
        }
    };
}

archive_content_props! {
    archive_content_hash_stable_21,
    archive_content_hash_stable_22,
    archive_content_hash_stable_23,
    archive_content_hash_stable_24,
    archive_content_hash_stable_25,
    archive_content_hash_stable_26,
    archive_content_hash_stable_27,
    archive_content_hash_stable_28,
    archive_content_hash_stable_29,
    archive_content_hash_stable_30,
    archive_content_hash_stable_31,
    archive_content_hash_stable_32,
    archive_content_hash_stable_33,
    archive_content_hash_stable_34,
    archive_content_hash_stable_35,
    archive_content_hash_stable_36,
    archive_content_hash_stable_37,
    archive_content_hash_stable_38,
    archive_content_hash_stable_39,
    archive_content_hash_stable_40,
    archive_content_hash_stable_41,
    archive_content_hash_stable_42,
    archive_content_hash_stable_43,
    archive_content_hash_stable_44,
    archive_content_hash_stable_45,
}
