    use super::{
        BytePattern, CarveOptions, CarveProfile, builtin_profiles, carve_from_bytes, carve_path,
        load_profiles_from_config, supported_carve_types_with_profiles,
    };
    use std::collections::BTreeSet;

    #[test]
    fn exposes_unique_supported_extensions() {
        let supported = supported_carve_types_with_profiles(&[]);
        assert!(supported.iter().any(|entry| entry.extension == "png"));
        assert!(supported.iter().any(|entry| entry.extension == "wav"));
        assert_eq!(
            supported
                .iter()
                .filter(|entry| entry.extension == "zip")
                .count(),
            1
        );
    }

    #[test]
    fn carves_filtered_embedded_png_without_writing() {
        let data = b"prefix\
\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x02\
\x00\x00\x00\x03\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82\
suffix";

        let mut filters = BTreeSet::new();
        filters.insert("png".to_string());
        let options = CarveOptions {
            type_filters: filters,
            write_files: false,
            write_audit: false,
            ..Default::default()
        };

        let artifacts = carve_from_bytes(data, None, &options);
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].extension, "png");
        assert_eq!(artifacts[0].length, Some(45));
        assert!(artifacts[0].extracted_path.is_none());
    }

    #[test]
    fn quick_mode_stops_after_first_profile_hit() {
        let data = b"pad\
\x89PNG\r\n\x1a\nabcd\x00\x00\x00\x00IEND\xAE\x42\x60\x82\
\x89PNG\r\n\x1a\nabcd\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        let options = CarveOptions {
            quick: true,
            write_files: false,
            write_audit: false,
            ..Default::default()
        };

        let artifacts = carve_from_bytes(data, None, &options);
        assert_eq!(artifacts.len(), 1);
    }

    #[test]
    fn parses_custom_config_profiles() {
        let path =
            std::env::temp_dir().join(format!("hashendra-carve-conf-{}", std::process::id()));
        std::fs::write(
            &path,
            "foo y 4096 ABCD WXYZ Custom Foo\nbar y 0 RIFF????WAVE -\n",
        )
        .unwrap();

        let profiles = load_profiles_from_config(&path).unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(profiles[0].extension, "foo");
        assert_eq!(profiles[0].description, "Custom Foo");
        assert_eq!(profiles[1].extension, "bar");
        assert_eq!(profiles[1].max_size, None);

        let supported = supported_carve_types_with_profiles(&profiles);
        assert!(supported.iter().any(|entry| entry.extension == "foo"));
        assert!(supported.iter().any(|entry| entry.extension == "bar"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn builtin_profiles_include_foremost_style_media_types() {
        let builtins = builtin_profiles();
        assert!(builtins.iter().any(|profile| profile.extension == "mov"));
        assert!(builtins.iter().any(|profile| profile.extension == "wmv"));
        assert!(builtins.iter().any(|profile| profile.extension == "ole"));
    }

    #[test]
    fn matryoshka_rescans_extracted_artifacts() {
        let root =
            std::env::temp_dir().join(format!("hashendra-carve-recursive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("sample.bin");
        let output = root.join("out");

        let png = b"\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x02\
\x00\x00\x00\x03\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        let data = [b"prefixOUTER".as_slice(), png.as_slice(), b"END!suffix"].concat();
        std::fs::write(&input, data).unwrap();

        let options = CarveOptions {
            output_dir: Some(output.clone()),
            write_files: true,
            write_audit: false,
            recursive_extract_depth: 1,
            profiles: vec![CarveProfile {
                extension: "outer".to_string(),
                description: "Outer Container".to_string(),
                headers: vec![BytePattern::exact(b"OUTER")],
                footer: Some(BytePattern::exact(b"END!")),
                max_size: Some(4096),
            }],
            ..Default::default()
        };

        let report = carve_path(&input, None, &options).unwrap();
        assert_eq!(report.recursive_extract_depth, 1);
        assert!(report.files_scanned >= 3);
        assert!(report.matched >= 3);
        assert!(report.by_type.get("outer").copied().unwrap_or(0) >= 1);
        assert!(report.by_type.get("png").copied().unwrap_or(0) >= 2);
        assert!(
            report
                .sources
                .iter()
                .any(|source| source.source.ends_with(".outer"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn matryoshka_expands_zip_members() {
        let root = std::env::temp_dir().join(format!("hashendra-carve-zip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("archive.zip");
        let output = root.join("out");

        let png = b"\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x02\
\x00\x00\x00\x03\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        std::fs::write(&input, build_stored_zip("nested/payload.png", png)).unwrap();

        let options = CarveOptions {
            output_dir: Some(output.clone()),
            write_files: true,
            write_audit: false,
            recursive_extract_depth: 2,
            ..Default::default()
        };

        let report = carve_path(&input, None, &options).unwrap();
        assert!(report.containers_expanded >= 1);
        assert!(report.container_members_written >= 1);
        assert!(report.by_type.get("png").copied().unwrap_or(0) >= 1);
        assert!(
            report
                .sources
                .iter()
                .any(|source| source.source.ends_with("payload.png"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn matryoshka_expands_tar_members() {
        let root = std::env::temp_dir().join(format!("hashendra-carve-tar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let input = root.join("archive.tar");
        let output = root.join("out");

        let png = b"\x89PNG\r\n\x1a\n\
\x00\x00\x00\x0dIHDR\
\x00\x00\x00\x02\
\x00\x00\x00\x03\
\x08\x06\x00\x00\x00\
\x00\x00\x00\x00\
\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        std::fs::write(&input, build_tar("nested/payload.png", png)).unwrap();

        let options = CarveOptions {
            output_dir: Some(output.clone()),
            write_files: true,
            write_audit: false,
            recursive_extract_depth: 2,
            ..Default::default()
        };

        let report = carve_path(&input, None, &options).unwrap();
        assert!(report.containers_expanded >= 1);
        assert!(report.container_members_written >= 1);
        assert!(report.by_type.get("png").copied().unwrap_or(0) >= 1);
        assert!(
            report
                .sources
                .iter()
                .any(|source| source.source.ends_with("payload.png"))
        );

        let _ = std::fs::remove_dir_all(root);
    }

    fn build_stored_zip(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut zip = Vec::new();
        let name_bytes = name.as_bytes();

        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name_bytes);
        zip.extend_from_slice(payload);

        let central_offset = zip.len() as u32;
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(name_bytes);

        let central_size = zip.len() as u32 - central_offset;
        zip.extend_from_slice(b"PK\x05\x06");
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&central_size.to_le_bytes());
        zip.extend_from_slice(&central_offset.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip
    }

    fn build_tar(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut tar = vec![0u8; 512];
        let name_bytes = name.as_bytes();
        tar[..name_bytes.len()].copy_from_slice(name_bytes);
        tar[100..108].copy_from_slice(b"0000644\0");
        tar[108..116].copy_from_slice(b"0000000\0");
        tar[116..124].copy_from_slice(b"0000000\0");
        let size = format!("{:011o}\0", payload.len());
        tar[124..136].copy_from_slice(size.as_bytes());
        tar[136..148].copy_from_slice(b"00000000000\0");
        tar[148..156].fill(b' ');
        tar[156] = b'0';
        tar[257..263].copy_from_slice(b"ustar\0");
        tar[263..265].copy_from_slice(b"00");
        let checksum: u32 = tar.iter().map(|byte| *byte as u32).sum();
        let checksum_field = format!("{:06o}\0 ", checksum);
        tar[148..156].copy_from_slice(checksum_field.as_bytes());
        tar.extend_from_slice(payload);
        let padding = (512 - (payload.len() % 512)) % 512;
        tar.extend(std::iter::repeat_n(0u8, padding + 1024));
        tar
    }
