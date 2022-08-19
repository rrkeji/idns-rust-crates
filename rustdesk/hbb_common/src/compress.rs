use std::cell::RefCell;
use zstd::bulk::{
    compress as zstd_compress, decompress as zstd_decompress, Compressor, Decompressor,
};

// thread_local! {
//     static COMPRESSOR: RefCell<Compressor> = RefCell::new(Compressor::new());
//     static DECOMPRESSOR: RefCell<Decompressor> = RefCell::new(Decompressor::new());
// }

/// The library supports regular compression levels from 1 up to ZSTD_maxCLevel(),
/// which is currently 22. Levels >= 20
/// Default level is ZSTD_CLEVEL_DEFAULT==3.
/// value 0 means default, which is controlled by ZSTD_CLEVEL_DEFAULT
pub fn compress(data: &[u8], level: i32) -> Vec<u8> {
    let mut out = Vec::new();
    match zstd_compress(data, level) {
        Ok(res) => out = res,
        Err(err) => {
            crate::log::debug!("Failed to compress: {}", err);
        }
    }
    out
}

pub fn decompress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match zstd_decompress(data, data.len()) {
        Ok(res) => out = res,
        Err(err) => {
            crate::log::debug!("Failed to decompress: {}", err);
        }
    }
    out
}
