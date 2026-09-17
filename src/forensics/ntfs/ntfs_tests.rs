    use super::{NtfsOptions, inspect_ntfs_bytes};
    use super::ntfs_fixtures::*;

    #[test]
    fn enumerates_deleted_resident_and_non_resident_entries() {
        let image = build_test_image();
        let report = inspect_ntfs_bytes(
            &image,
            "test.img".to_string(),
            &NtfsOptions {
                max_records: 4,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.boot.record_size, 1024);
        assert_eq!(report.deleted_entries, 2);
        assert_eq!(report.returned_entries, 3);

        let resident = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.txt"))
            .unwrap();
        assert!(resident.deleted);
        assert_eq!(resident.resident_data_size, Some(5));
        assert_eq!(resident.real_size, Some(5));

        let non_resident = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("archive.bin"))
            .unwrap();
        assert!(non_resident.deleted);
        assert_eq!(non_resident.non_resident_data_size, Some(13));
        assert_eq!(non_resident.data_runs, Some(1));
    }

    #[test]
    fn filters_to_deleted_and_extracts_deleted_data() {
        let image = build_test_image();
        let output_dir =
            std::env::temp_dir().join(format!("hashendra-ntfs-recovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);

        let report = inspect_ntfs_bytes(
            &image,
            "test.img".to_string(),
            &NtfsOptions {
                max_records: 4,
                deleted_only: true,
                extract_data_to: Some(output_dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.returned_entries, 2);
        assert_eq!(report.resident_recovered, 2);
        assert_eq!(report.non_resident_recovered, 1);
        assert_eq!(report.recovered_bytes, 32);

        let resident_path = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.txt"))
            .and_then(|entry| entry.extracted_path.as_ref())
            .unwrap();
        let resident = std::fs::read(resident_path).unwrap();
        assert_eq!(resident, b"hello");

        let non_resident_path = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("archive.bin"))
            .and_then(|entry| entry.extracted_path.as_ref())
            .unwrap();
        let non_resident = std::fs::read(non_resident_path).unwrap();
        assert_eq!(non_resident, b"forensic-data");

        let _ = std::fs::remove_dir_all(output_dir);
    }

    #[test]
    fn supports_nonzero_volume_offsets() {
        let mut prefixed = vec![0u8; 512];
        prefixed.extend(build_test_image());

        let report = inspect_ntfs_bytes(
            &prefixed,
            "offset.img".to_string(),
            &NtfsOptions {
                volume_offset: 512,
                max_records: 4,
                deleted_only: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.boot.volume_offset, 512);
        assert_eq!(report.returned_entries, 2);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.name.as_deref() == Some("secret.txt"))
        );
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.name.as_deref() == Some("archive.bin"))
        );
    }

    #[test]
    fn reports_named_ads_and_system_artifacts() {
        let image = build_test_image();
        let report = inspect_ntfs_bytes(
            &image,
            "test.img".to_string(),
            &NtfsOptions {
                max_records: 10,
                include_directories: true,
                ..Default::default()
            },
        )
        .unwrap();

        let secret = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.txt"))
            .unwrap();
        assert_eq!(secret.alternate_data_streams.len(), 1);
        assert_eq!(secret.alternate_data_streams[0].name, "Zone.Identifier");

        let bitmap = report.system_artifacts.bitmap.as_ref().unwrap();
        assert!(bitmap.tracked_clusters >= 64);
        assert!(bitmap.allocated_clusters >= 5);

        let logfile = report.system_artifacts.logfile.as_ref().unwrap();
        assert_eq!(logfile.restart_pages, 1);
        assert_eq!(logfile.first_magic.as_deref(), Some("RSTR"));

        let usn = report.system_artifacts.usn_journal.as_ref().unwrap();
        assert_eq!(usn.stream_name, "$J");
        assert_eq!(usn.records, 1);
        assert!(usn.sample_names.iter().any(|name| name == "deleted.tmp"));
    }

    #[test]
    fn recovers_ads_bitmap_extended_compressed_and_encrypted_streams() {
        let image = build_test_image();
        let output_dir =
            std::env::temp_dir().join(format!("hashendra-ntfs-streams-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);

        let report = inspect_ntfs_bytes(
            &image,
            "test.img".to_string(),
            &NtfsOptions {
                max_records: 10,
                deleted_only: true,
                extract_data_to: Some(output_dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        let secret = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.txt"))
            .unwrap();
        let ads_path = secret.alternate_data_streams[0]
            .extracted_path
            .as_ref()
            .unwrap();
        assert_eq!(std::fs::read(ads_path).unwrap(), b"[ZoneTransfer]");

        let fragment = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("fragment.bin"))
            .unwrap();
        assert!(
            fragment
                .recovery_note
                .as_deref()
                .unwrap_or_default()
                .contains("bitmap heuristic")
        );
        let fragment_path = fragment.extracted_path.as_ref().unwrap();
        let fragment_bytes = std::fs::read(fragment_path).unwrap();
        assert_eq!(fragment_bytes.len(), 700);
        assert_eq!(&fragment_bytes[..4], b"frag");

        let compressed = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("compressed.bin"))
            .unwrap();
        assert!(
            compressed
                .recovery_note
                .as_deref()
                .unwrap_or_default()
                .contains("compressed stream rebuilt")
        );
        let compressed_path = compressed.extracted_path.as_ref().unwrap();
        assert_eq!(std::fs::read(compressed_path).unwrap(), vec![b'C'; 600]);

        let encrypted = report
            .entries
            .iter()
            .find(|entry| entry.name.as_deref() == Some("secret.enc"))
            .unwrap();
        assert!(
            encrypted
                .recovery_note
                .as_deref()
                .unwrap_or_default()
                .contains("raw encrypted")
        );
        let encrypted_path = encrypted.extracted_path.as_ref().unwrap();
        assert_eq!(std::fs::read(encrypted_path).unwrap(), b"cipher");

        let _ = std::fs::remove_dir_all(output_dir);
    }
