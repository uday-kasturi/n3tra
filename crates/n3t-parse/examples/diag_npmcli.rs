//! Temporary diagnostic: localize the npm-cli corpus count anomaly (993 on
//! macOS vs ~2200 on Linux for a byte-identical file).
fn main() {
    let path = std::path::Path::new("tests/corpus/npm-cli/package-lock.json");
    let text = std::fs::read_to_string(path).expect("read");
    match n3t_parse::npm::parse_package_lock_str(&text, "diag") {
        Ok(i) => println!("DIAG raw parse_package_lock_str packages.len = {}", i.packages.len()),
        Err(e) => println!("DIAG parse error: {e}"),
    }
    let scanned = n3t_parse::scan(path.parent().unwrap(), false);
    println!("DIAG scan(false) packages.len = {}", scanned.packages.len());
    println!("DIAG sources = {:?}", scanned.sources);
}
