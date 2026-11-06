// A bare macOS binary has no bundle identity; some launch contexts crash inside
// AppKit's window-server setup (CFBundleCopyExecutableURL on a null bundle).
// Embedding an Info.plist gives the process one, same as an .app would.
fn main() {
    println!("cargo:rerun-if-changed=macos/Info.plist");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-arg-bins=-Wl,-sectcreate,__TEXT,__info_plist,{dir}/macos/Info.plist");
    }
}
