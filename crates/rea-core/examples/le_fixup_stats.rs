//! Print LE fixup statistics for a binary (diagnostic).
use rea_core::le::LeImage;

fn main() {
    let path = std::env::args().nth(1).expect("usage: le_fixup_stats <file>");
    let bytes = std::fs::read(&path).expect("read failed");
    let img = LeImage::parse(&bytes).expect("parse failed");
    let mut patched = bytes;
    match img.apply_fixups(&mut patched) {
        Ok(n) => println!("{path}: {n} fixups applied"),
        Err(e) => println!("{path}: error: {e}"),
    }
}
