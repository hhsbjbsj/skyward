//! Android boot images (headers v0–v4) and the newc archives their ramdisks
//! carry: read, changed and written again, by the image packer on a computer
//! and by the recovery on the phone.

mod image;
mod ramdisk;

pub use image::BootImage;
pub use ramdisk::{lz4_legacy, Compression, Entry, Ramdisk};
