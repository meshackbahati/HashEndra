    use super::{inspect_disk_bytes, inspect_filesystem_bytes};

    #[test]
    fn parses_mbr_with_fat32_partition() {
        let mut data = vec![0u8; 4096];
        data[510] = 0x55;
        data[511] = 0xAA;
        data[446] = 0x80;
        data[450] = 0x0C;
        data[454..458].copy_from_slice(&1u32.to_le_bytes());
        data[458..462].copy_from_slice(&100u32.to_le_bytes());

        let boot = 512usize;
        data[boot + 11..boot + 13].copy_from_slice(&512u16.to_le_bytes());
        data[boot + 13] = 8;
        data[boot + 14..boot + 16].copy_from_slice(&32u16.to_le_bytes());
        data[boot + 16] = 2;
        data[boot + 32..boot + 36].copy_from_slice(&100u32.to_le_bytes());
        data[boot + 36..boot + 40].copy_from_slice(&16u32.to_le_bytes());
        data[boot + 44..boot + 48].copy_from_slice(&2u32.to_le_bytes());
        data[boot + 82..boot + 90].copy_from_slice(b"FAT32   ");

        let report = inspect_disk_bytes(&data, "mbr.img".to_string(), 512);
        assert_eq!(report.scheme.as_deref(), Some("MBR"));
        assert_eq!(report.partitions.len(), 1);
        assert_eq!(
            report.partitions[0].filesystem.as_ref().unwrap().kind,
            "FAT32"
        );
    }

    #[test]
    fn parses_gpt_with_ntfs_partition() {
        let mut data = vec![0u8; 40 * 512 + 512];
        data[510] = 0x55;
        data[511] = 0xAA;
        data[450] = 0xEE;
        data[454..458].copy_from_slice(&1u32.to_le_bytes());
        data[458..462].copy_from_slice(&400u32.to_le_bytes());

        let header = 512usize;
        data[header..header + 8].copy_from_slice(b"EFI PART");
        data[header + 72..header + 80].copy_from_slice(&2u64.to_le_bytes());
        data[header + 80..header + 84].copy_from_slice(&1u32.to_le_bytes());
        data[header + 84..header + 88].copy_from_slice(&128u32.to_le_bytes());

        let entry = 1024usize;
        data[entry..entry + 16].copy_from_slice(&[
            0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
            0x99, 0xC7,
        ]);
        data[entry + 32..entry + 40].copy_from_slice(&40u64.to_le_bytes());
        data[entry + 40..entry + 48].copy_from_slice(&80u64.to_le_bytes());
        let name: Vec<u8> = "DATA"
            .encode_utf16()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        data[entry + 56..entry + 56 + name.len()].copy_from_slice(&name);

        let boot = 40 * 512;
        data[boot + 3..boot + 11].copy_from_slice(b"NTFS    ");
        data[boot + 11..boot + 13].copy_from_slice(&512u16.to_le_bytes());
        data[boot + 13] = 8;
        data[boot + 40..boot + 48].copy_from_slice(&2048u64.to_le_bytes());
        data[boot + 48..boot + 56].copy_from_slice(&4u64.to_le_bytes());
        data[boot + 72..boot + 80].copy_from_slice(&0x12345678ABCDEF00u64.to_le_bytes());

        let report = inspect_disk_bytes(&data, "gpt.img".to_string(), 512);
        assert_eq!(report.scheme.as_deref(), Some("GPT"));
        assert_eq!(report.partitions.len(), 1);
        assert_eq!(report.partitions[0].name.as_deref(), Some("DATA"));
        assert_eq!(
            report.partitions[0].filesystem.as_ref().unwrap().kind,
            "NTFS"
        );
    }

    #[test]
    fn detects_standalone_ext_volume() {
        let mut data = vec![0u8; 4096];
        let super_offset = 1024usize;
        data[super_offset + 4..super_offset + 8].copy_from_slice(&8192u32.to_le_bytes());
        data[super_offset + 24..super_offset + 28].copy_from_slice(&2u32.to_le_bytes());
        data[super_offset + 32..super_offset + 36].copy_from_slice(&32768u32.to_le_bytes());
        data[super_offset + 40..super_offset + 44].copy_from_slice(&8192u32.to_le_bytes());
        data[super_offset + 56..super_offset + 58].copy_from_slice(&0xEF53u16.to_le_bytes());
        data[super_offset + 96..super_offset + 100].copy_from_slice(&0x40u32.to_le_bytes());
        data[super_offset + 120..super_offset + 128].copy_from_slice(b"evidence");

        let report = inspect_disk_bytes(&data, "ext.img".to_string(), 512);
        assert!(report.partitions.is_empty());
        assert_eq!(report.standalone_filesystem.as_ref().unwrap().kind, "ext4");
    }

    #[test]
    fn detects_standalone_btrfs_volume() {
        let mut data = vec![0u8; 0x12000];
        let super_offset = 0x10000usize;
        data[super_offset + 0x20..super_offset + 0x30].copy_from_slice(&[0x11; 16]);
        data[super_offset + 0x30..super_offset + 0x38].copy_from_slice(&(0x10000u64).to_le_bytes());
        data[super_offset + 0x40..super_offset + 0x48].copy_from_slice(b"_BHRfS_M");
        data[super_offset + 0x70..super_offset + 0x78]
            .copy_from_slice(&(8 * 1024 * 1024u64).to_le_bytes());

        let report = inspect_disk_bytes(&data, "btrfs.img".to_string(), 512);
        assert!(report.partitions.is_empty());
        assert_eq!(report.standalone_filesystem.as_ref().unwrap().kind, "Btrfs");
    }

    #[test]
    fn detects_standalone_swap_area() {
        let mut data = vec![0u8; 8192];
        data[4086..4096].copy_from_slice(b"SWAPSPACE2");

        let report = inspect_disk_bytes(&data, "swap.img".to_string(), 512);
        assert!(report.partitions.is_empty());
        assert_eq!(report.standalone_filesystem.as_ref().unwrap().kind, "swap");
    }

    #[test]
    fn detects_refs_signature() {
        let mut data = vec![0u8; 4096];
        data[3..7].copy_from_slice(b"ReFS");
        data[56..64].copy_from_slice(&0x1234_5678_90AB_CDEFu64.to_le_bytes());

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "ReFS");
    }

    #[test]
    fn detects_xfs_signature() {
        let mut data = vec![0u8; 4096];
        data[..4].copy_from_slice(b"XFSB");
        data[4..8].copy_from_slice(&4096u32.to_be_bytes());
        data[8..16].copy_from_slice(&1024u64.to_be_bytes());
        data[108..113].copy_from_slice(b"DATA ");

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "XFS");
    }

    #[test]
    fn detects_f2fs_signature() {
        let mut data = vec![0u8; 4096];
        let super_offset = 1024usize;
        data[super_offset..super_offset + 4].copy_from_slice(&0xF2F52010u32.to_le_bytes());
        data[super_offset + 24..super_offset + 28].copy_from_slice(&12u32.to_le_bytes());
        data[super_offset + 104..super_offset + 108].copy_from_slice(&64u32.to_le_bytes());

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "F2FS");
    }

    #[test]
    fn detects_hfs_plus_signature() {
        let mut data = vec![0u8; 4096];
        let header_offset = 1024usize;
        data[header_offset..header_offset + 2].copy_from_slice(&0x482Bu16.to_be_bytes());
        data[header_offset + 40..header_offset + 44].copy_from_slice(&4096u32.to_be_bytes());
        data[header_offset + 44..header_offset + 48].copy_from_slice(&2048u32.to_be_bytes());

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "HFS+");
    }

    #[test]
    fn detects_apfs_signature() {
        let mut data = vec![0u8; 4096];
        data[32..36].copy_from_slice(b"NXSB");
        data[36..40].copy_from_slice(&4096u32.to_le_bytes());
        data[40..48].copy_from_slice(&8192u64.to_le_bytes());

        let filesystem = inspect_filesystem_bytes(&data, 0, 512).unwrap();
        assert_eq!(filesystem.kind, "APFS");
    }

    #[test]
    fn detects_optical_filesystem_signatures() {
        let mut iso = vec![0u8; 18 * 2048];
        let vd = 16 * 2048;
        iso[vd + 1..vd + 6].copy_from_slice(b"CD001");
        iso[vd + 40..vd + 46].copy_from_slice(b"DISC01");
        assert_eq!(
            inspect_filesystem_bytes(&iso, 0, 512).unwrap().kind,
            "ISO9660"
        );

        let mut udf = vec![0u8; 24 * 2048];
        let descriptor = 20 * 2048;
        udf[descriptor + 1..descriptor + 6].copy_from_slice(b"NSR02");
        assert_eq!(inspect_filesystem_bytes(&udf, 0, 512).unwrap().kind, "UDF");
    }
