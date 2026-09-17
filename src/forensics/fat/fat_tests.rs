    use super::{FatOptions, inspect_fat_bytes};

    #[test]
    fn enumerates_and_recovers_deleted_fat32_entries() {
        let image = build_test_image();
        let output_dir = std::env::temp_dir().join(format!("hashendra-fat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);

        let report = inspect_fat_bytes(
            &image,
            "fat.img".to_string(),
            &FatOptions {
                max_entries: 32,
                include_directories: true,
                extract_data_to: Some(output_dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.boot.kind, "FAT32");
        assert_eq!(report.deleted_entries, 1);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.path.as_deref() == Some("DOCS"))
        );
        let deleted = report
            .entries
            .iter()
            .find(|entry| entry.deleted && entry.short_name == "_ELTXT.TXT")
            .unwrap();
        assert!(
            deleted
                .recovery_note
                .as_deref()
                .unwrap_or_default()
                .contains("contiguous")
        );
        let deleted_path = deleted.extracted_path.as_ref().unwrap();
        assert_eq!(
            std::fs::read(deleted_path).unwrap(),
            build_deleted_payload()
        );

        let live_nested = report
            .entries
            .iter()
            .find(|entry| entry.path.as_deref() == Some("DOCS/INNER.BIN"))
            .unwrap();
        assert_eq!(
            std::fs::read(live_nested.extracted_path.as_ref().unwrap()).unwrap(),
            b"ABCD"
        );

        let _ = std::fs::remove_dir_all(output_dir);
    }

    fn build_test_image() -> Vec<u8> {
        let sector_size = 512usize;
        let total_sectors = 70_000usize;
        let mut image = vec![0u8; sector_size * total_sectors];

        image[11..13].copy_from_slice(&(sector_size as u16).to_le_bytes());
        image[13] = 1;
        image[14..16].copy_from_slice(&1u16.to_le_bytes());
        image[16] = 1;
        image[17..19].copy_from_slice(&0u16.to_le_bytes());
        image[19..21].copy_from_slice(&0u16.to_le_bytes());
        image[21] = 0xF8;
        image[32..36].copy_from_slice(&(total_sectors as u32).to_le_bytes());
        image[36..40].copy_from_slice(&1u32.to_le_bytes());
        image[44..48].copy_from_slice(&2u32.to_le_bytes());
        image[71..82].copy_from_slice(b"EVIDENCE   ");
        image[82..90].copy_from_slice(b"FAT32   ");
        image[510] = 0x55;
        image[511] = 0xAA;

        let fat_offset = sector_size;
        write_fat32_entry(&mut image, fat_offset, 0, 0x0FFF_FFF8);
        write_fat32_entry(&mut image, fat_offset, 1, 0xFFFF_FFFF);
        write_fat32_entry(&mut image, fat_offset, 2, 0x0FFF_FFFF);
        write_fat32_entry(&mut image, fat_offset, 3, 0x0FFF_FFFF);
        write_fat32_entry(&mut image, fat_offset, 4, 0x0FFF_FFFF);
        write_fat32_entry(&mut image, fat_offset, 5, 0);
        write_fat32_entry(&mut image, fat_offset, 6, 0);
        write_fat32_entry(&mut image, fat_offset, 7, 0x0FFF_FFFF);

        let root = 2 * sector_size;
        write_dir_entry(
            &mut image[root..root + 32],
            b"DOCS    ",
            b"   ",
            0x10,
            3,
            0,
            false,
        );
        write_dir_entry(
            &mut image[root + 32..root + 64],
            b"DELTXT  ",
            b"TXT",
            0x20,
            5,
            build_deleted_payload().len() as u32,
            true,
        );
        write_dir_entry(
            &mut image[root + 64..root + 96],
            b"LIVE    ",
            b"TXT",
            0x20,
            4,
            10,
            false,
        );
        image[root + 96] = 0;

        let docs = 3 * sector_size;
        write_dir_entry(
            &mut image[docs..docs + 32],
            b".       ",
            b"   ",
            0x10,
            3,
            0,
            false,
        );
        write_dir_entry(
            &mut image[docs + 32..docs + 64],
            b"..      ",
            b"   ",
            0x10,
            2,
            0,
            false,
        );
        write_dir_entry(
            &mut image[docs + 64..docs + 96],
            b"INNER   ",
            b"BIN",
            0x20,
            7,
            4,
            false,
        );
        image[docs + 96] = 0;

        let live = 4 * sector_size;
        image[live..live + 10].copy_from_slice(b"live-data\n");

        let deleted_payload = build_deleted_payload();
        let deleted_a = 5 * sector_size;
        let deleted_b = 6 * sector_size;
        image[deleted_a..deleted_a + sector_size].copy_from_slice(&deleted_payload[..sector_size]);
        image[deleted_b..deleted_b + deleted_payload.len() - sector_size]
            .copy_from_slice(&deleted_payload[sector_size..]);

        let inner = 7 * sector_size;
        image[inner..inner + 4].copy_from_slice(b"ABCD");

        image
    }

    fn build_deleted_payload() -> Vec<u8> {
        let mut payload = vec![b'R'; 700];
        payload[0..15].copy_from_slice(b"recovered-data!");
        payload
    }

    fn write_fat32_entry(image: &mut [u8], fat_offset: usize, cluster: usize, value: u32) {
        let offset = fat_offset + cluster * 4;
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_dir_entry(
        entry: &mut [u8],
        base: &[u8; 8],
        ext: &[u8; 3],
        attr: u8,
        cluster: u32,
        size: u32,
        deleted: bool,
    ) {
        entry[..8].copy_from_slice(base);
        entry[8..11].copy_from_slice(ext);
        entry[11] = attr;
        if deleted {
            entry[0] = 0xE5;
        }
        entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        entry[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
        entry[28..32].copy_from_slice(&size.to_le_bytes());
    }
