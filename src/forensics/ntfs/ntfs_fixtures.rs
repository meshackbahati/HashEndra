    pub(crate) fn build_test_image() -> Vec<u8> {
        let mut image = vec![0u8; 65536];
        image[3..11].copy_from_slice(b"NTFS    ");
        image[11..13].copy_from_slice(&512u16.to_le_bytes());
        image[13] = 1;
        image[40..48].copy_from_slice(&32768u64.to_le_bytes());
        image[48..56].copy_from_slice(&4u64.to_le_bytes());
        image[56..64].copy_from_slice(&8u64.to_le_bytes());
        image[64] = 0xF6;
        image[68] = 0xF4;
        image[72..80].copy_from_slice(&0x1122334455667788u64.to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xAA;

        let mft_offset = 4 * 512;
        let first = build_resident_record(0, true, false, Some("MFT"), None);
        let second = build_resident_record_with_streams(
            1,
            false,
            false,
            Some("secret.txt"),
            Some(b"hello"),
            &[("Zone.Identifier", b"[ZoneTransfer]")],
        );
        let third = build_non_resident_record(
            2,
            false,
            false,
            "archive.bin",
            b"forensic-data".len() as u64,
            512,
            &[(32, 1)],
        );
        let bitmap =
            build_resident_record(4, true, false, Some("$Bitmap"), Some(&build_bitmap_bytes()));
        let logfile = build_resident_record(
            5,
            true,
            false,
            Some("$LogFile"),
            Some(&build_logfile_bytes()),
        );
        let usn = build_resident_record_with_streams(
            6,
            true,
            false,
            Some("$UsnJrnl"),
            None,
            &[("$J", &build_usn_record("deleted.tmp"))],
        );
        let fragment =
            build_non_resident_record(7, false, false, "fragment.bin", 700, 1024, &[(40, 1)]);
        let compressed = build_non_resident_record_with_flags(
            8,
            false,
            false,
            "compressed.bin",
            600,
            1024,
            &[(42, 2)],
            0x0001,
            1,
        );
        let encrypted = build_non_resident_record_with_flags(
            9,
            false,
            false,
            "secret.enc",
            6,
            512,
            &[(44, 1)],
            0x4000,
            0,
        );
        image[mft_offset..mft_offset + 1024].copy_from_slice(&first);
        image[mft_offset + 1024..mft_offset + 2048].copy_from_slice(&second);
        image[mft_offset + 2048..mft_offset + 3072].copy_from_slice(&third);
        image[mft_offset + 4096..mft_offset + 5120].copy_from_slice(&bitmap);
        image[mft_offset + 5120..mft_offset + 6144].copy_from_slice(&logfile);
        image[mft_offset + 6144..mft_offset + 7168].copy_from_slice(&usn);
        image[mft_offset + 7168..mft_offset + 8192].copy_from_slice(&fragment);
        image[mft_offset + 8192..mft_offset + 9216].copy_from_slice(&compressed);
        image[mft_offset + 9216..mft_offset + 10240].copy_from_slice(&encrypted);
        image[32 * 512..32 * 512 + b"forensic-data".len()].copy_from_slice(b"forensic-data");
        image[40 * 512..40 * 512 + 512].fill(b'F');
        image[40 * 512..40 * 512 + 4].copy_from_slice(b"frag");
        image[41 * 512..41 * 512 + 188].fill(b'G');
        image[42 * 512..42 * 512 + 600].fill(b'C');
        image[44 * 512..44 * 512 + 6].copy_from_slice(b"cipher");

        image
    }

    pub(crate) fn build_resident_record(
        record_number: u32,
        in_use: bool,
        directory: bool,
        name: Option<&str>,
        resident_data: Option<&[u8]>,
    ) -> Vec<u8> {
        build_resident_record_with_streams(
            record_number,
            in_use,
            directory,
            name,
            resident_data,
            &[],
        )
    }

    pub(crate) fn build_resident_record_with_streams(
        record_number: u32,
        in_use: bool,
        directory: bool,
        name: Option<&str>,
        resident_data: Option<&[u8]>,
        named_streams: &[(&str, &[u8])],
    ) -> Vec<u8> {
        let mut record = vec![0u8; 1024];
        record[..4].copy_from_slice(b"FILE");
        record[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        record[6..8].copy_from_slice(&3u16.to_le_bytes());
        record[16..18].copy_from_slice(&1u16.to_le_bytes());
        record[18..20].copy_from_slice(&1u16.to_le_bytes());
        record[20..22].copy_from_slice(&0x38u16.to_le_bytes());

        let mut flags = 0u16;
        if in_use {
            flags |= 0x01;
        }
        if directory {
            flags |= 0x02;
        }
        record[22..24].copy_from_slice(&flags.to_le_bytes());
        record[28..32].copy_from_slice(&(1024u32).to_le_bytes());
        record[44..48].copy_from_slice(&record_number.to_le_bytes());

        let mut cursor = 0x38usize;
        if let Some(name) = name {
            cursor = write_resident_attr(
                &mut record,
                cursor,
                0x30,
                &build_file_name_attr(
                    name,
                    resident_data.map_or(0, |data| data.len() as u64),
                    resident_data.map_or(0, |data| data.len() as u64),
                ),
            );
        }

        if let Some(data) = resident_data {
            cursor = write_resident_attr(&mut record, cursor, 0x80, data);
        }

        for (stream_name, bytes) in named_streams {
            cursor = write_named_resident_attr(&mut record, cursor, 0x80, stream_name, bytes);
        }

        record[cursor..cursor + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        cursor += 4;
        record[24..28].copy_from_slice(&(cursor as u32).to_le_bytes());

        record[0x30..0x32].copy_from_slice(&0xAAAAu16.to_le_bytes());
        record[0x32..0x34].copy_from_slice(&0u16.to_le_bytes());
        record[0x34..0x36].copy_from_slice(&0u16.to_le_bytes());
        record[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());
        record[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());

        record
    }

    pub(crate) fn build_non_resident_record(
        record_number: u32,
        in_use: bool,
        directory: bool,
        name: &str,
        real_size: u64,
        allocated_size: u64,
        runs: &[(u64, u64)],
    ) -> Vec<u8> {
        build_non_resident_record_with_flags(
            record_number,
            in_use,
            directory,
            name,
            real_size,
            allocated_size,
            runs,
            0,
            0,
        )
    }

    // Test fixture mirrors the on-disk record layout field-for-field;
    // grouping the args would hide that correspondence.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_non_resident_record_with_flags(
        record_number: u32,
        in_use: bool,
        directory: bool,
        name: &str,
        real_size: u64,
        allocated_size: u64,
        runs: &[(u64, u64)],
        flags: u16,
        compression_unit_shift: u16,
    ) -> Vec<u8> {
        let mut record = build_resident_record(record_number, in_use, directory, Some(name), None);
        let mut cursor = 0x38usize;
        cursor = write_resident_attr(
            &mut record,
            cursor,
            0x30,
            &build_file_name_attr(name, allocated_size, real_size),
        );
        cursor = write_non_resident_attr_with_flags(
            &mut record,
            cursor,
            0x80,
            real_size,
            allocated_size,
            runs,
            flags,
            compression_unit_shift,
        );
        record[cursor..cursor + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        cursor += 4;
        record[24..28].copy_from_slice(&(cursor as u32).to_le_bytes());
        record
    }

    pub(crate) fn build_file_name_attr(name: &str, allocated_size: u64, real_size: u64) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let mut value = vec![0u8; 66 + name_utf16.len() * 2];
        value[0..8].copy_from_slice(&5u64.to_le_bytes());
        value[40..48].copy_from_slice(&allocated_size.to_le_bytes());
        value[48..56].copy_from_slice(&real_size.to_le_bytes());
        value[64] = name_utf16.len() as u8;
        value[65] = 1;
        for (index, unit) in name_utf16.iter().enumerate() {
            let offset = 66 + index * 2;
            value[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        value
    }

    pub(crate) fn write_resident_attr(
        record: &mut [u8],
        offset: usize,
        attr_type: u32,
        value: &[u8],
    ) -> usize {
        let header_size = 24usize;
        let attr_len = align8(header_size + value.len());
        record[offset..offset + 4].copy_from_slice(&attr_type.to_le_bytes());
        record[offset + 4..offset + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        record[offset + 8] = 0;
        record[offset + 9] = 0;
        record[offset + 10..offset + 12].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 12..offset + 14].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 14..offset + 16].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 16..offset + 20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        record[offset + 20..offset + 22].copy_from_slice(&(header_size as u16).to_le_bytes());
        record[offset + 22] = 0;
        record[offset + 23] = 0;
        record[offset + header_size..offset + header_size + value.len()].copy_from_slice(value);
        offset + attr_len
    }

    pub(crate) fn write_named_resident_attr(
        record: &mut [u8],
        offset: usize,
        attr_type: u32,
        name: &str,
        value: &[u8],
    ) -> usize {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = name_utf16
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let name_offset = 24usize;
        let value_offset = align8(name_offset + name_bytes.len());
        let attr_len = align8(value_offset + value.len());
        record[offset..offset + 4].copy_from_slice(&attr_type.to_le_bytes());
        record[offset + 4..offset + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        record[offset + 8] = 0;
        record[offset + 9] = name_utf16.len() as u8;
        record[offset + 10..offset + 12].copy_from_slice(&(name_offset as u16).to_le_bytes());
        record[offset + 12..offset + 14].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 14..offset + 16].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 16..offset + 20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        record[offset + 20..offset + 22].copy_from_slice(&(value_offset as u16).to_le_bytes());
        record[offset + 22] = 0;
        record[offset + 23] = 0;
        record[offset + name_offset..offset + name_offset + name_bytes.len()]
            .copy_from_slice(&name_bytes);
        record[offset + value_offset..offset + value_offset + value.len()].copy_from_slice(value);
        offset + attr_len
    }

    // Test fixture mirrors the on-disk attribute layout field-for-field.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn write_non_resident_attr_with_flags(
        record: &mut [u8],
        offset: usize,
        attr_type: u32,
        real_size: u64,
        allocated_size: u64,
        runs: &[(u64, u64)],
        flags: u16,
        compression_unit_shift: u16,
    ) -> usize {
        let header_size = 64usize;
        let runlist = build_runlist(runs);
        let total_clusters: u64 = runs.iter().map(|(_, cluster_count)| *cluster_count).sum();
        let attr_len = align8(header_size + runlist.len());
        record[offset..offset + 4].copy_from_slice(&attr_type.to_le_bytes());
        record[offset + 4..offset + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        record[offset + 8] = 1;
        record[offset + 9] = 0;
        record[offset + 10..offset + 12].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 12..offset + 14].copy_from_slice(&flags.to_le_bytes());
        record[offset + 14..offset + 16].copy_from_slice(&0u16.to_le_bytes());
        record[offset + 16..offset + 24].copy_from_slice(&0u64.to_le_bytes());
        record[offset + 24..offset + 32]
            .copy_from_slice(&total_clusters.saturating_sub(1).to_le_bytes());
        record[offset + 32..offset + 34].copy_from_slice(&(header_size as u16).to_le_bytes());
        record[offset + 34..offset + 36].copy_from_slice(&compression_unit_shift.to_le_bytes());
        record[offset + 36..offset + 40].copy_from_slice(&0u32.to_le_bytes());
        record[offset + 40..offset + 48].copy_from_slice(&allocated_size.to_le_bytes());
        record[offset + 48..offset + 56].copy_from_slice(&real_size.to_le_bytes());
        record[offset + 56..offset + 64].copy_from_slice(&real_size.to_le_bytes());
        record[offset + header_size..offset + header_size + runlist.len()]
            .copy_from_slice(&runlist);
        offset + attr_len
    }

    pub(crate) fn build_bitmap_bytes() -> Vec<u8> {
        let mut bitmap = vec![0u8; 8];
        for cluster in [32u64, 40, 42, 43, 44] {
            let index = (cluster / 8) as usize;
            let bit = (cluster % 8) as u8;
            bitmap[index] |= 1 << bit;
        }
        bitmap
    }

    pub(crate) fn build_logfile_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 512];
        bytes[..4].copy_from_slice(b"RSTR");
        bytes
    }

    pub(crate) fn build_usn_record(name: &str) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = name_utf16
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let record_length = align8(60 + name_bytes.len());
        let mut record = vec![0u8; record_length];
        record[0..4].copy_from_slice(&(record_length as u32).to_le_bytes());
        record[4..6].copy_from_slice(&2u16.to_le_bytes());
        record[6..8].copy_from_slice(&0u16.to_le_bytes());
        record[56..58].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        record[58..60].copy_from_slice(&60u16.to_le_bytes());
        record[60..60 + name_bytes.len()].copy_from_slice(&name_bytes);
        record
    }

    pub(crate) fn build_runlist(runs: &[(u64, u64)]) -> Vec<u8> {
        let mut runlist = Vec::new();
        let mut previous_lcn = 0i64;

        for &(lcn, cluster_count) in runs {
            let length_bytes = minimal_unsigned_bytes(cluster_count);
            let delta = lcn as i64 - previous_lcn;
            let offset_bytes = minimal_signed_bytes(delta);
            runlist.push(((offset_bytes.len() as u8) << 4) | (length_bytes.len() as u8));
            runlist.extend_from_slice(&length_bytes);
            runlist.extend_from_slice(&offset_bytes);
            previous_lcn = lcn as i64;
        }

        runlist.push(0);
        runlist
    }

    pub(crate) fn minimal_unsigned_bytes(value: u64) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        let mut width = bytes.len();
        while width > 1 && bytes[width - 1] == 0 {
            width -= 1;
        }
        bytes[..width].to_vec()
    }

    pub(crate) fn minimal_signed_bytes(value: i64) -> Vec<u8> {
        let bytes = value.to_le_bytes();
        let mut width = bytes.len();
        while width > 1 {
            let keep_sign = (bytes[width - 1] == 0x00 && bytes[width - 2] & 0x80 == 0)
                || (bytes[width - 1] == 0xFF && bytes[width - 2] & 0x80 != 0);
            if keep_sign {
                width -= 1;
            } else {
                break;
            }
        }
        bytes[..width].to_vec()
    }

    pub(crate) fn align8(value: usize) -> usize {
        (value + 7) & !7
    }
