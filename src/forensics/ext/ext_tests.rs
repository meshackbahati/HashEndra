    use super::{ExtOptions, inspect_ext_bytes};

    #[test]
    fn enumerates_deleted_ext_entries_and_journal() {
        let image = build_test_image();
        let report = inspect_ext_bytes(
            &image,
            "ext.img".to_string(),
            &ExtOptions {
                max_inodes: 16,
                include_directories: true,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.superblock.kind, "ext4");
        assert_eq!(report.deleted_entries, 2);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.path.as_deref() == Some("live.txt"))
        );
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.inode == 12 && entry.deleted)
        );
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.inode == 13 && entry.storage == "extents")
        );
        assert_eq!(report.journal.as_ref().unwrap().inode, 8);
        assert_eq!(report.journal.as_ref().unwrap().block_size, Some(1024));
    }

    #[test]
    fn recovers_deleted_ext_direct_and_extent_files() {
        let image = build_test_image();
        let output_dir =
            std::env::temp_dir().join(format!("hashendra-ext-recovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);

        let report = inspect_ext_bytes(
            &image,
            "ext.img".to_string(),
            &ExtOptions {
                max_inodes: 16,
                deleted_only: true,
                extract_data_to: Some(output_dir.clone()),
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(report.returned_entries, 2);
        assert_eq!(report.recovered_files, 2);

        let direct = report
            .entries
            .iter()
            .find(|entry| entry.inode == 12)
            .unwrap();
        let direct_path = direct.extracted_path.as_ref().unwrap();
        assert_eq!(std::fs::read(direct_path).unwrap(), b"hello");

        let extent = report
            .entries
            .iter()
            .find(|entry| entry.inode == 13)
            .unwrap();
        let extent_path = extent.extracted_path.as_ref().unwrap();
        assert_eq!(std::fs::read(extent_path).unwrap(), b"extent-data");

        let _ = std::fs::remove_dir_all(output_dir);
    }

    fn build_test_image() -> Vec<u8> {
        let mut image = vec![0u8; 64 * 1024];
        let sb = 1024usize;
        image[sb..sb + 0x04].copy_from_slice(&32u32.to_le_bytes());
        image[sb + 0x04..sb + 0x08].copy_from_slice(&64u32.to_le_bytes());
        image[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
        image[sb + 0x18..sb + 0x1C].copy_from_slice(&0u32.to_le_bytes());
        image[sb + 0x20..sb + 0x24].copy_from_slice(&64u32.to_le_bytes());
        image[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
        image[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        image[sb + 0x58..sb + 0x5A].copy_from_slice(&128u16.to_le_bytes());
        image[sb + 0x5C..sb + 0x60].copy_from_slice(&0x4u32.to_le_bytes());
        image[sb + 0x60..sb + 0x64].copy_from_slice(&0x40u32.to_le_bytes());
        image[sb + 0x78..sb + 0x80].copy_from_slice(b"evidence");
        image[sb + 0xE0..sb + 0xE4].copy_from_slice(&8u32.to_le_bytes());

        let gd = 2048usize;
        image[gd + 0x08..gd + 0x0C].copy_from_slice(&5u32.to_le_bytes());

        let inode_table = 5 * 1024usize;
        let root = build_inode(0x41ED, 1024, 2, 0, 0, &[10], None);
        write_inode(&mut image, inode_table, 2, &root);
        let journal = build_inode(0x81A4, 1024, 1, 0, 0, &[14], None);
        write_inode(&mut image, inode_table, 8, &journal);
        let live = build_inode(0x81A4, 4, 1, 0, 0, &[11], None);
        write_inode(&mut image, inode_table, 11, &live);
        let deleted = build_inode(0x81A4, 5, 0, 1, 0, &[12], None);
        write_inode(&mut image, inode_table, 12, &deleted);
        let extent = build_extent_inode(11, 13);
        write_inode(&mut image, inode_table, 13, &extent);

        let dir_block = 10 * 1024usize;
        write_dir_entry(&mut image[dir_block..dir_block + 1024], 0, 2, ".", 2, 12);
        write_dir_entry(&mut image[dir_block..dir_block + 1024], 12, 2, "..", 2, 12);
        write_dir_entry(
            &mut image[dir_block..dir_block + 1024],
            24,
            11,
            "live.txt",
            1,
            1024 - 24,
        );

        image[11 * 1024..11 * 1024 + 4].copy_from_slice(b"live");
        image[12 * 1024..12 * 1024 + 5].copy_from_slice(b"hello");
        image[13 * 1024..13 * 1024 + 11].copy_from_slice(b"extent-data");

        let journal_block = 14 * 1024usize;
        image[journal_block..journal_block + 4].copy_from_slice(&0xC03B3998u32.to_be_bytes());
        image[journal_block + 4..journal_block + 8].copy_from_slice(&4u32.to_be_bytes());
        image[journal_block + 12..journal_block + 16].copy_from_slice(&1024u32.to_be_bytes());
        image[journal_block + 16..journal_block + 20].copy_from_slice(&64u32.to_be_bytes());
        image[journal_block + 20..journal_block + 24].copy_from_slice(&1u32.to_be_bytes());

        image
    }

    fn build_inode(
        mode: u16,
        size: u32,
        links_count: u16,
        dtime: u32,
        flags: u32,
        blocks: &[u32],
        note: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut inode = vec![0u8; 128];
        inode[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        inode[0x04..0x08].copy_from_slice(&size.to_le_bytes());
        inode[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
        inode[0x1A..0x1C].copy_from_slice(&links_count.to_le_bytes());
        inode[0x1C..0x20].copy_from_slice(&((blocks.len() as u32) * 2).to_le_bytes());
        inode[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        for (index, block) in blocks.iter().enumerate() {
            inode[0x28 + index * 4..0x2C + index * 4].copy_from_slice(&block.to_le_bytes());
        }
        if let Some(extra) = note {
            let len = extra.len().min(16);
            inode[0x64..0x64 + len].copy_from_slice(&extra[..len]);
        }
        inode
    }

    fn build_extent_inode(size: u32, block: u32) -> Vec<u8> {
        let mut inode = build_inode(0x81A4, size, 0, 2, 0x80000, &[], None);
        inode[0x1C..0x20].copy_from_slice(&2u32.to_le_bytes());
        inode[0x28..0x2A].copy_from_slice(&0xF30Au16.to_le_bytes());
        inode[0x2A..0x2C].copy_from_slice(&1u16.to_le_bytes());
        inode[0x2C..0x2E].copy_from_slice(&4u16.to_le_bytes());
        inode[0x2E..0x30].copy_from_slice(&0u16.to_le_bytes());
        inode[0x34..0x38].copy_from_slice(&0u32.to_le_bytes());
        inode[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        inode[0x3A..0x3C].copy_from_slice(&0u16.to_le_bytes());
        inode[0x3C..0x40].copy_from_slice(&block.to_le_bytes());
        inode
    }

    fn write_inode(image: &mut [u8], inode_table: usize, inode: usize, bytes: &[u8]) {
        let offset = inode_table + (inode - 1) * 128;
        image[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn write_dir_entry(
        block: &mut [u8],
        offset: usize,
        inode: u32,
        name: &str,
        file_type: u8,
        rec_len: usize,
    ) {
        let name_bytes = name.as_bytes();
        block[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
        block[offset + 4..offset + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
        block[offset + 6] = name_bytes.len() as u8;
        block[offset + 7] = file_type;
        block[offset + 8..offset + 8 + name_bytes.len()].copy_from_slice(name_bytes);
    }
