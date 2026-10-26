//! Вбудовує в `flashrec-gui.exe` маніфест із запитом прав.
//!
//! Без прав адміністратора Windows не дає читати фізичний диск, і людина бачить
//! порожній список дисків. `highestAvailable` просить UAC саме тоді, коли
//! користувач — адміністратор, а звичайному користувачеві дає запуститися
//! без них: образи відкриваються й так.
//!
//! Робиться прапорцями лінкера MSVC, без жодного crate. Для інших цілей
//! (GNU, не Windows) нічого не додається.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bins=/MANIFESTUAC:level='highestAvailable' uiAccess='false'"
        );
    }
    println!("cargo:rerun-if-changed=build.rs");
}
