use super::{format_hex, le_u16, le_u32, le_u64, read_u16, read_u32, read_u64, ArtifactInspection};
use std::collections::BTreeMap;

pub(crate) fn inspect_elf(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 0x34 || !data.starts_with(b"\x7FELF") { return None; }
    let class = *data.get(4)?;
    let little_endian = match data.get(5).copied()? { 1 => true, 2 => false, _ => return None };
    let elf_class = match class { 1 => "32-bit", 2 => "64-bit", _ => return None };
    let endian = if little_endian { "LSB" } else { "MSB" };
    let elf_type = read_u16(data, 16, little_endian)?;
    let machine = read_u16(data, 18, little_endian)?;
    let entry_point = if class == 1 { read_u32(data, 24, little_endian)? as u64 } else { read_u64(data, 24, little_endian)? };
    let program_headers = if class == 1 { read_u16(data, 44, little_endian)? } else { read_u16(data, 56, little_endian)? };
    let section_headers = if class == 1 { read_u16(data, 48, little_endian)? } else { read_u16(data, 60, little_endian)? };

    // Read section header string table for section names
    let shstrndx = if class == 1 { read_u16(data, 50, little_endian)? as usize } else { read_u16(data, 62, little_endian)? as usize };
    let shdr_size = if class == 1 { 40 } else { 64 };
    let shdr_offset = if class == 1 { read_u32(data, 32, little_endian)? as usize } else { read_u64(data, 40, little_endian)? as usize };
    let shstrtab_off = shdr_offset.checked_add(shstrndx.checked_mul(shdr_size)?)?;
    let sh_name_offset = if class == 1 { read_u32(data, shstrtab_off + 16, little_endian)? as usize }
                                  else { read_u64(data, shstrtab_off + 24, little_endian)? as usize };
    let _sh_name_size = if class == 1 { read_u32(data, shstrtab_off + 20, little_endian)? as usize }
                                  else { read_u64(data, shstrtab_off + 32, little_endian)? as usize };

    let max_sh_off = shdr_offset.saturating_add((section_headers as usize).saturating_mul(shdr_size));
    let mut section_names = Vec::new();
    if max_sh_off <= data.len() && section_headers < 256 {
        for i in 0..section_headers as usize {
            let sh_off = shdr_offset.saturating_add(i.saturating_mul(shdr_size));
            if sh_off + 8 > data.len() { break; }
            if let Some(name_idx) = read_u32(data, sh_off, little_endian) {
                let name_idx = name_idx as usize;
                if sh_name_offset.saturating_add(name_idx) < data.len() {
                    let end = data[sh_name_offset + name_idx..].iter().position(|&b| b == 0).unwrap_or(0);
                    let name = String::from_utf8_lossy(&data[sh_name_offset + name_idx..sh_name_offset + name_idx + end]).to_string();
                    if !name.is_empty() { section_names.push(name); }
                }
            }
        }
    }

    let mut details = BTreeMap::new();
    details.insert("class".to_string(), elf_class.to_string());
    details.insert("endianness".to_string(), endian.to_string());
    details.insert("type".to_string(), elf_type_name(elf_type).to_string());
    details.insert("machine".to_string(), elf_machine_name(machine).to_string());
    details.insert("entry_point".to_string(), format_hex(entry_point));
    details.insert("program_headers".to_string(), program_headers.to_string());
    details.insert("section_headers".to_string(), section_headers.to_string());
    if !section_names.is_empty() {
        details.insert("sections".to_string(), section_names.join(", "));
    }

    Some(ArtifactInspection {
        format: "ELF".to_string(),
        summary: format!("ELF {} {} {} for {}", elf_class, endian, elf_type_name(elf_type), elf_machine_name(machine)),
        details,
    })
}

pub(crate) fn elf_type_name(value: u16) -> &'static str {
    match value { 1 => "relocatable", 2 => "executable", 3 => "shared object", 4 => "core", _ => "unknown" }
}

pub(crate) fn elf_machine_name(value: u16) -> &'static str {
    match value {
        0x03 => "x86", 0x08 => "MIPS", 0x14 => "PowerPC", 0x28 => "ARM",
        0x3E => "x86-64", 0xB7 => "AArch64", 0xF3 => "RISC-V", _ => "unknown",
    }
}

pub(crate) fn inspect_pe(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 0x40 || !data.starts_with(b"MZ") { return None; }
    let pe_offset = le_u32(data, 0x3c)? as usize;
    if pe_offset + 24 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" { return None; }
    let machine = le_u16(data, pe_offset + 4)?;
    let sections = le_u16(data, pe_offset + 6)?;
    let timestamp = le_u32(data, pe_offset + 8)?;
    let size_optional_header = le_u16(data, pe_offset + 20)? as usize;
    let characteristics = le_u16(data, pe_offset + 22)?;
    let optional_offset = pe_offset + 24;
    if optional_offset + size_optional_header > data.len() { return None; }
    let magic = le_u16(data, optional_offset)?;
    let (pe_class, subsystem) = match magic {
        0x10B => ("PE32", le_u16(data, optional_offset + 68)?),
        0x20B => ("PE32+", le_u16(data, optional_offset + 88)?),
        _ => return None,
    };
    let entry_point = le_u32(data, optional_offset + 16)?;
    let image_base = match magic { 0x10B => le_u32(data, optional_offset + 28)? as u64, _ => le_u64(data, optional_offset + 24)? };
    let kind = if characteristics & 0x2000 != 0 { "DLL" } else { "Executable" };

    // Read section table for names
    let section_offset = optional_offset + size_optional_header;
    let mut section_names = Vec::new();
    for i in 0..sections as usize {
        let s_off = section_offset + i * 40;
        if s_off + 40 > data.len() { break; }
        let name_raw = &data[s_off..s_off + 8];
        let name = String::from_utf8_lossy(name_raw).trim_end_matches('\0').to_string();
        if !name.is_empty() { section_names.push(name); }
    }

    let mut details = BTreeMap::new();
    details.insert("class".to_string(), pe_class.to_string());
    details.insert("kind".to_string(), kind.to_string());
    details.insert("machine".to_string(), pe_machine_name(machine).to_string());
    details.insert("sections".to_string(), sections.to_string());
    details.insert("timestamp_unix".to_string(), timestamp.to_string());
    details.insert("entry_point".to_string(), format_hex(entry_point as u64));
    details.insert("image_base".to_string(), format_hex(image_base));
    details.insert("subsystem".to_string(), pe_subsystem_name(subsystem).to_string());
    if !section_names.is_empty() {
        details.insert("section_names".to_string(), section_names.join(", "));
    }
    Some(ArtifactInspection {
        format: "PE".to_string(),
        summary: format!("{} {} for {} with {} section{}", pe_class, kind.to_lowercase(), pe_machine_name(machine), sections, if sections == 1 { "" } else { "s" }),
        details,
    })
}

pub(crate) fn pe_machine_name(value: u16) -> &'static str {
    match value { 0x014C => "x86", 0x8664 => "x86-64", 0x01C0 => "ARM", 0xAA64 => "ARM64", _ => "unknown" }
}

pub(crate) fn pe_subsystem_name(value: u16) -> &'static str {
    match value {
        1 => "native", 2 => "windows-gui", 3 => "windows-cui", 5 => "os2-cui",
        7 => "posix-cui", 9 => "windows-ce-gui", 10 => "efi-application",
        11 => "efi-boot-service", 12 => "efi-runtime", 14 => "xbox",
        16 => "windows-boot-application", _ => "unknown",
    }
}

pub(crate) fn inspect_macho(data: &[u8]) -> Option<ArtifactInspection> {
    if data.len() < 28 { return None; }
    let (class, little_endian) = match &data[..4] {
        [0xFE, 0xED, 0xFA, 0xCE] => ("32-bit", false),
        [0xCE, 0xFA, 0xED, 0xFE] => ("32-bit", true),
        [0xFE, 0xED, 0xFA, 0xCF] => ("64-bit", false),
        [0xCF, 0xFA, 0xED, 0xFE] => ("64-bit", true),
        _ => return None,
    };
    let cpu_type = read_u32(data, 4, little_endian)?;
    let file_type = read_u32(data, 12, little_endian)?;
    let load_commands = read_u32(data, 16, little_endian)?;
    let command_bytes = read_u32(data, 20, little_endian)?;

    let mut details = BTreeMap::new();
    details.insert("class".to_string(), class.to_string());
    details.insert("endianness".to_string(), (if little_endian { "little" } else { "big" }).to_string());
    details.insert("cpu".to_string(), macho_cpu_name(cpu_type).to_string());
    details.insert("file_type".to_string(), macho_file_type_name(file_type).to_string());
    details.insert("load_commands".to_string(), load_commands.to_string());
    details.insert("load_command_bytes".to_string(), command_bytes.to_string());
    Some(ArtifactInspection {
        format: "Mach-O".to_string(),
        summary: format!("Mach-O {} {} with {} load command{}", class, macho_cpu_name(cpu_type), load_commands, if load_commands == 1 { "" } else { "s" }),
        details,
    })
}

pub(crate) fn macho_cpu_name(value: u32) -> &'static str {
    match value { 7 => "x86", 0x0100_0007 => "x86-64", 12 => "arm", 0x0100_000C => "arm64", _ => "unknown" }
}

pub(crate) fn macho_file_type_name(value: u32) -> &'static str {
    match value {
        0x1 => "object", 0x2 => "executable", 0x3 => "fixed-vm-library", 0x4 => "core",
        0x5 => "preloaded-executable", 0x6 => "dylib", 0x7 => "dylinker", 0x8 => "bundle",
        0xA => "dSYM", _ => "unknown",
    }
}
