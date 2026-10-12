//! Print LE fixup statistics for a binary (diagnostic).
use rea_core::le::LeImage;

fn main() {
    let path = std::env::args().nth(1).expect("usage: le_fixup_stats <file>");
    let bytes = std::fs::read(&path).expect("read failed");
    let img = LeImage::parse(&bytes).expect("parse failed");
    let mut patched = bytes.clone();
    match img.apply_fixups(&mut patched) {
        Ok(n) => println!("{path}: {n} fixups applied"),
        Err(e) => println!("{path}: error: {e}"),
    }
    // Show a sample patched pointer: first fixup target 0x51b58 was derived
    // by hand; check the bytes at the corresponding source actually changed.
    if let Some(off) = img.pages.translate(0x109eb) {
        let off = off as usize;
        println!(
            "bytes at vaddr 0x109eb (file {off:#x}): {:02x?}",
            &patched[off..off + 4]
        );
    }
}
