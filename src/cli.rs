use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "hashendra")]
#[command(version = "2.0.0")]
#[command(about = "HashEndra - identify hashes, decode strings, carve files", long_about = "\
EXAMPLES:
  hashendra \"5d41402abc4b2a76b9719d911017c592\"     Identify a hash
  hashendra --decode \"aGVsbG8=\"                     Decode a single layer
  hashendra --deep-decrypt \"NzI3Ng==\"               Recursively unwrap encodings
  hashendra --rot \"Uryyb Jbeyq\"                     Brute-force ROT cipher
  hashendra --xor \"1b37373331363f78\"                 Crack single-byte XOR
  hashendra --hash sha256 \"hello world\"              Compute a hash
  hashendra --to base64 \"hello\"                      Encode to Base64
  hashendra --to morse \"SOS\"                         Encode to Morse code
  hashendra --encrypt caesar --key 13 \"hello\"         Encrypt with Caesar cipher
  hashendra -f hashes.txt                              Batch process a file
  hashendra -j \"d2Vi\"                                JSON output
  hashendra --context network \"GET /index.html\"       Context-aware detection
  hashendra forensic scan image.jpg                    Extract file metadata
  hashendra forensic carve disk.dd -o carved/          Carve embedded files
  hashendra forensic disk --deleted-only image.dd      Recover deleted files
  hashendra workshop                                   Interactive workshop

MORE INFO:
  See https://github.com/meshackbahati/HashEndra or docs/ directory")]
pub(crate) struct Cli {
    #[arg(help = "The hash or encoded string to analyze")]
    pub(crate) input: Option<String>,

    #[arg(short, long, help = "File to read hashes from")]
    pub(crate) file: Option<String>,

    #[arg(short, long, help = "Output in JSON format")]
    pub(crate) json: bool,

    #[arg(short, long, help = "Verbose mode")]
    pub(crate) verbose: bool,

    #[arg(long, help = "Attempt to decode the input")]
    pub(crate) decode: bool,

    #[arg(long, help = "Run deep recursive decryption (multi-layer)")]
    pub(crate) deep_decrypt: bool,

    #[arg(long, help = "Brute-force ROT cipher")]
    pub(crate) rot: bool,

    #[arg(long, help = "Crack single-byte XOR")]
    pub(crate) xor: bool,

    #[arg(
        long,
        default_value = "generic",
        help = "Context for detection (network, database, filesystem, etc.)"
    )]
    pub(crate) context: String,

    #[arg(
        long,
        help = "Compute a cryptographic hash of the input. Optionally specify algorithm: md5, sha1, sha256, sha512, blake3, etc. Use --list-hashes to see all."
    )]
    pub(crate) hash: Option<Option<String>>,

    #[arg(long, help = "List supported hash algorithms and exit")]
    pub(crate) list_hashes: bool,

    #[arg(
        long,
        help = "Encode input to a format: base64, base64url, base32, base58, hex, url, html, qp, binary, octal, morse, ascii85"
    )]
    pub(crate) to: Option<String>,

    #[arg(long, help = "List supported encoding formats and exit")]
    pub(crate) list_encodings: bool,

    #[arg(
        long,
        help = "Encrypt input using a cipher. Usage: --encrypt <cipher> --key <key>. Ciphers: caesar, vigenere, affine, rail-fence, xor, columnar, atbash"
    )]
    pub(crate) encrypt: Option<String>,

    #[arg(
        long,
        help = "Key for encryption ciphers (shift number for caesar, 'a,b' for affine, string key for others)"
    )]
    pub(crate) key: Option<String>,

    #[arg(
        long,
        help = "Additional cipher parameter (number of rails for rail-fence)"
    )]
    pub(crate) cipher_param: Option<String>,

    #[arg(long, help = "List supported encryption ciphers and exit")]
    pub(crate) list_ciphers: bool,

    #[arg(
        long,
        help = "Load custom detection signatures from a JSON file"
    )]
    pub(crate) custom_signatures: Option<String>,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Update the signature database
    Update,
    /// Forensic workflows: scan files, inspect disks, and carve artifacts
    Forensic {
        #[command(subcommand)]
        command: ForensicCommands,
    },
    /// Backward-compatible alias for `forensic disk`
    #[command(hide = true)]
    Disk {
        path: String,
        #[arg(long, default_value_t = 512, help = "Sector size for partition math")]
        sector_size: usize,
    },
    /// Backward-compatible alias for `forensic disk --ntfs`
    #[command(hide = true)]
    Ntfs {
        path: String,
        #[arg(
            long,
            default_value_t = 0,
            help = "Byte offset to the NTFS volume start"
        )]
        offset: usize,
        #[arg(long, default_value_t = 256, help = "Maximum MFT records to inspect")]
        max_records: usize,
        #[arg(long, help = "Only show deleted entries")]
        deleted_only: bool,
        #[arg(long, help = "Include directory records in the results")]
        include_directories: bool,
        #[arg(
            long = "extract-data",
            alias = "extract-resident",
            help = "Recover deleted file content into this directory (resident and non-resident when rebuildable)"
        )]
        extract_data: Option<String>,
        #[arg(long, help = "Allow overwriting existing recovered files")]
        overwrite: bool,
    },
    /// Backward-compatible alias for `forensic carve`
    #[command(hide = true)]
    Carve {
        #[arg(required_unless_present_any = ["list_types", "input"])]
        path: Option<String>,
        #[arg(short = 'i', long, help = "Input file or directory to carve")]
        input: Option<String>,
        #[arg(short, long, help = "Output directory for carved files")]
        output: Option<String>,
        #[arg(short = 'c', long, help = "Foremost-style carve profile config file")]
        config: Option<String>,
        #[arg(
            short = 't',
            long,
            value_delimiter = ',',
            help = "Only carve matching extensions or type names (comma-separated)"
        )]
        types: Vec<String>,
        #[arg(short = 'a', long, help = "Include signatures at offset 0")]
        include_root: bool,
        #[arg(long, default_value_t = 1, help = "Minimum carved size in bytes")]
        min_size: usize,
        #[arg(long, default_value_t = 0, help = "Start carving at this byte offset")]
        offset: usize,
        #[arg(long, help = "Limit carving to this many bytes from --offset")]
        length: Option<usize>,
        #[arg(
            long,
            help = "Maximum carved size in bytes for formats without a known footer"
        )]
        max_size: Option<usize>,
        #[arg(long, help = "Report sector numbers using this sector size")]
        sector_size: Option<usize>,
        #[arg(
            short = 'Q',
            long,
            help = "Quick mode: first hit per profile per source"
        )]
        quick: bool,
        #[arg(short = 'w', long, help = "Write audit log only; do not extract files")]
        audit_only: bool,
        #[arg(long, help = "Do not recurse when the input is a directory")]
        no_recursive: bool,
        #[arg(long, help = "Allow overwriting existing carved files")]
        overwrite: bool,
        #[arg(long, help = "Report what would be carved without writing files")]
        dry_run: bool,
        #[arg(long, help = "List supported carve types and exit")]
        list_types: bool,
        #[arg(
            short = 'M',
            long,
            help = "Recursively rescan extracted artifacts like binwalk matryoshka mode"
        )]
        matryoshka: bool,
        #[arg(
            long,
            help = "Maximum recursive extraction depth when --matryoshka is enabled"
        )]
        depth: Option<usize>,
    },
    /// Start an interactive decoding workshop
    Workshop { input: Option<String> },
}

#[derive(Subcommand)]
pub(crate) enum ForensicCommands {
    /// Run forensic analysis on a file or directory
    Scan {
        path: String,
        #[arg(long, help = "Do not carve embedded artifacts to disk")]
        no_extract: bool,
    },
    /// Inspect a disk image or volume and optionally focus on a specific filesystem
    Disk {
        path: String,
        #[arg(long, default_value_t = 512, help = "Sector size for partition math")]
        sector_size: usize,
        #[arg(
            long,
            default_value_t = 0,
            help = "Byte offset to the target filesystem volume"
        )]
        offset: usize,
        #[arg(
            long,
            default_value_t = 256,
            help = "Maximum filesystem records to inspect"
        )]
        max_records: usize,
        #[arg(long, help = "Only show deleted filesystem entries")]
        deleted_only: bool,
        #[arg(long, help = "Include directory records in the results")]
        include_directories: bool,
        #[arg(
            long = "extract-data",
            alias = "extract-resident",
            help = "Recover filesystem data streams into this directory"
        )]
        extract_data: Option<String>,
        #[arg(long, help = "Allow overwriting existing recovered files")]
        overwrite: bool,
        #[arg(long, help = "Force NTFS handling instead of auto-detect only")]
        ntfs: bool,
        #[arg(
            long,
            help = "Filesystem to inspect or recover: ntfs, fat, fat12, fat16, fat32, exfat, refs, ext2, ext3, ext4, btrfs, xfs, f2fs, hfs+, apfs, ufs, zfs, jfs, reiserfs, iso9660, udf, nfs, smb, cifs, afs, cephfs"
        )]
        fs: Option<String>,
        #[arg(long, help = "Prefer ext4 handling when available")]
        ext4: bool,
        #[arg(long, help = "Prefer swap handling when available")]
        swap: bool,
        #[arg(long, help = "Prefer Btrfs handling when available")]
        btrfs: bool,
    },
    /// Carve embedded files like a dedicated extractor
    Carve {
        #[arg(required_unless_present_any = ["list_types", "input"])]
        path: Option<String>,
        #[arg(short = 'i', long, help = "Input file or directory to carve")]
        input: Option<String>,
        #[arg(short, long, help = "Output directory for carved files")]
        output: Option<String>,
        #[arg(short = 'c', long, help = "Foremost-style carve profile config file")]
        config: Option<String>,
        #[arg(
            short = 't',
            long,
            value_delimiter = ',',
            help = "Only carve matching extensions or type names (comma-separated)"
        )]
        types: Vec<String>,
        #[arg(short = 'a', long, help = "Include signatures at offset 0")]
        include_root: bool,
        #[arg(long, default_value_t = 1, help = "Minimum carved size in bytes")]
        min_size: usize,
        #[arg(long, default_value_t = 0, help = "Start carving at this byte offset")]
        offset: usize,
        #[arg(long, help = "Limit carving to this many bytes from --offset")]
        length: Option<usize>,
        #[arg(
            long,
            help = "Maximum carved size in bytes for formats without a known footer"
        )]
        max_size: Option<usize>,
        #[arg(long, help = "Report sector numbers using this sector size")]
        sector_size: Option<usize>,
        #[arg(
            short = 'Q',
            long,
            help = "Quick mode: first hit per profile per source"
        )]
        quick: bool,
        #[arg(short = 'w', long, help = "Write audit log only; do not extract files")]
        audit_only: bool,
        #[arg(long, help = "Do not recurse when the input is a directory")]
        no_recursive: bool,
        #[arg(long, help = "Allow overwriting existing carved files")]
        overwrite: bool,
        #[arg(long, help = "Report what would be carved without writing files")]
        dry_run: bool,
        #[arg(long, help = "List supported carve types and exit")]
        list_types: bool,
        #[arg(
            short = 'M',
            long,
            help = "Recursively rescan extracted artifacts like binwalk matryoshka mode"
        )]
        matryoshka: bool,
        #[arg(
            long,
            help = "Maximum recursive extraction depth when --matryoshka is enabled"
        )]
        depth: Option<usize>,
    },
}

/// Options shared by the NTFS/ext/FAT inspect commands (identical shapes).
pub(crate) struct InspectOptions<'a> {
    pub(crate) path: &'a std::path::Path,
    pub(crate) json: bool,
    pub(crate) offset: usize,
    pub(crate) max_entries: usize,
    pub(crate) deleted_only: bool,
    pub(crate) include_directories: bool,
    pub(crate) extract_data: Option<&'a str>,
    pub(crate) overwrite: bool,
}

/// Options for the forensic disk dispatcher (14 clap flags in one place).
pub(crate) struct DiskOptions<'a> {
    pub(crate) path: &'a std::path::Path,
    pub(crate) json: bool,
    pub(crate) sector_size: usize,
    pub(crate) offset: usize,
    pub(crate) max_records: usize,
    pub(crate) deleted_only: bool,
    pub(crate) include_directories: bool,
    pub(crate) extract_data: Option<&'a str>,
    pub(crate) overwrite: bool,
    pub(crate) ntfs: bool,
    pub(crate) fs: Option<&'a str>,
    pub(crate) ext4: bool,
    pub(crate) swap: bool,
    pub(crate) btrfs: bool,
}

/// Options for the carve dispatcher (20 clap flags in one place).
pub(crate) struct CarveOptions<'a> {
    pub(crate) path: Option<&'a str>,
    pub(crate) input: Option<&'a str>,
    pub(crate) json: bool,
    pub(crate) output: Option<&'a str>,
    pub(crate) config: Option<&'a str>,
    pub(crate) types: &'a [String],
    pub(crate) include_root: bool,
    pub(crate) min_size: usize,
    pub(crate) offset: usize,
    pub(crate) length: Option<usize>,
    pub(crate) max_size: Option<usize>,
    pub(crate) sector_size: Option<usize>,
    pub(crate) quick: bool,
    pub(crate) audit_only: bool,
    pub(crate) recursive: bool,
    pub(crate) overwrite: bool,
    pub(crate) dry_run: bool,
    pub(crate) list_types: bool,
    pub(crate) matryoshka: bool,
    pub(crate) depth: Option<usize>,
}
