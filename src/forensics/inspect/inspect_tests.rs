    use super::*;
    use crate::detectors::stego::identify_file_signature;

    #[test]
    fn inspects_png_dimensions() {
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x01\x90\x00\x00\x00\xc8\x08\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00IEND\xAE\x42\x60\x82";
        let inspection = inspect_data(png).unwrap();
        assert_eq!(inspection.format, "PNG");
        assert_eq!(inspection.details.get("width").unwrap(), "400");
        assert_eq!(inspection.details.get("height").unwrap(), "200");
    }

    #[test]
    fn inspects_elf_headers() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7FELF"); elf[4] = 2; elf[5] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes());
        elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        elf[56..58].copy_from_slice(&9u16.to_le_bytes());
        elf[60..62].copy_from_slice(&31u16.to_le_bytes());
        // Set e_shstrndx = SHN_UNDO (0) to skip section name resolution
        let signature = identify_file_signature(&elf).unwrap();
        let inspection = inspect_artifact(&elf, signature).unwrap();
        assert_eq!(inspection.format, "ELF");
        assert_eq!(inspection.details.get("machine").unwrap(), "x86-64");
        assert_eq!(inspection.details.get("entry_point").unwrap(), "0x401000");
    }

    #[test]
    fn inspects_zip_central_directory() {
        let name = b"hello.txt";
        let mut zip = Vec::new();
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name);
        let central_offset = zip.len() as u32;
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&20u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(&0u32.to_le_bytes());
        zip.extend_from_slice(name);
        let central_size = zip.len() as u32 - central_offset;
        zip.extend_from_slice(b"PK\x05\x06");
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&1u16.to_le_bytes());
        zip.extend_from_slice(&central_size.to_le_bytes());
        zip.extend_from_slice(&central_offset.to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        let inspection = inspect_data(&zip).unwrap();
        assert_eq!(inspection.format, "ZIP");
        assert_eq!(inspection.details.get("entries").unwrap(), "1");
        assert!(inspection.details.get("sample_entries").unwrap().contains("hello.txt"));
    }

    #[test]
    fn inspects_gif_metadata() {
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[0x10, 0x00, 0x08, 0x00]); // 16x8
        gif.extend_from_slice(&[0x00, 0x00, 0x00]); // packed, bg, aspect
        gif.push(0x3B); // trailer
        let inspection = inspect_data(&gif).unwrap();
        assert_eq!(inspection.format, "GIF");
        assert_eq!(inspection.details.get("width").unwrap(), "16");
        assert_eq!(inspection.details.get("height").unwrap(), "8");
    }

    #[test]
    fn inspects_bmp_headers() {
        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0x46, 0x00, 0x00, 0x00]); // file size 70 @2
        bmp.extend_from_slice(&[0x00, 0x00]); // reserved1 @6
        bmp.extend_from_slice(&[0x00, 0x00]); // reserved2 @8
        bmp.extend_from_slice(&[0x36, 0x00, 0x00, 0x00]); // data offset 54 @10
        bmp.extend_from_slice(&[0x28, 0x00, 0x00, 0x00]); // header size 40 @14
        bmp.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // width 4 @18
        bmp.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // height 3 @22
        bmp.extend_from_slice(&[0x01, 0x00]); // planes @26
        bmp.extend_from_slice(&[0x18, 0x00]); // bpp 24 @28
        bmp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // compression @30
        let inspection = inspect_data(&bmp).unwrap();
        assert_eq!(inspection.format, "BMP");
        assert_eq!(inspection.details.get("width").unwrap(), "4");
        assert_eq!(inspection.details.get("height").unwrap(), "3");
    }

    #[test]
    fn inspects_wav_header() {
        let mut wav = b"RIFF".to_vec();
        wav.extend_from_slice(&[0x24, 0x00, 0x00, 0x00]); // file size 36
        wav.extend_from_slice(b"WAVE");
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // chunk size 16
        wav.extend_from_slice(&[0x01, 0x00]); // PCM
        wav.extend_from_slice(&[0x01, 0x00]); // mono
        wav.extend_from_slice(&[0x44, 0xAC, 0x00, 0x00]); // 44100 Hz
        wav.extend_from_slice(&[0x88, 0x58, 0x01, 0x00]); // byte rate
        wav.extend_from_slice(&[0x02, 0x00]); // block align
        wav.extend_from_slice(&[0x10, 0x00]); // 16-bit
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // data size
        let inspection = inspect_data(&wav).unwrap();
        assert_eq!(inspection.format, "WAV");
        assert_eq!(inspection.details.get("sample_rate").unwrap(), "44100 Hz");
        assert_eq!(inspection.details.get("channels").unwrap(), "1");
    }

    #[test]
    fn inspects_ico_headers() {
        let mut ico = b"\0\0\x01\0".to_vec();
        ico.extend_from_slice(&[0x01, 0x00]); // 1 icon
        ico.extend_from_slice(&[0x10, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // 16x16 entry
        let inspection = inspect_data(&ico).unwrap();
        assert_eq!(inspection.format, "ICO");
        assert_eq!(inspection.details.get("icon_count").unwrap(), "1");
    }

    #[test]
    fn inspects_rar_archive() {
        let rar = b"Rar!\x1A\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let inspection = inspect_data(rar).unwrap();
        assert_eq!(inspection.format, "RAR");
        assert_eq!(inspection.details.get("format_version").unwrap(), "4.x");
    }

    #[test]
    fn inspects_7z_archive() {
        let mut sz7 = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
        sz7.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0x00, 0x00]);
        sz7.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        sz7.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let inspection = inspect_data(&sz7).unwrap();
        assert_eq!(inspection.format, "7z");
    }

    #[test]
    fn inspects_ole_compound_document() {
        let mut ole: Vec<u8> = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        // Need enough room for version and other metadata
        ole.extend_from_slice(&[0x00u8; 32]);
        ole[24..26].copy_from_slice(&[0x3E, 0x00]); // minor version
        ole[26..28].copy_from_slice(&[0x03, 0x00]); // major version
        ole[28..30].copy_from_slice(&[0xFE, 0xFF]); // byte order (LE)
        ole[30] = 9; // sector shift (512 bytes)
        let inspection = inspect_data(&ole).unwrap();
        assert_eq!(inspection.format, "OLE");
        assert_eq!(inspection.details.get("version").unwrap(), "3.62");
        assert_eq!(inspection.details.get("byte_order").unwrap(), "little_endian");
    }
