mod apps;
mod digests;
mod kdf;
mod keys;

use crate::core::patterns::Signature;

pub fn get_hash_signatures() -> Vec<Signature> {
    let mut out = digests::digest_signatures();
    out.extend(kdf::kdf_signatures());
    out.extend(apps::app_signatures());
    out.extend(keys::key_signatures());
    out
}
