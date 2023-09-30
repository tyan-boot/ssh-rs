fn main() {
    let is_static = std::env::var("LIBSSH_STATIC").is_ok();

    #[cfg(windows)]
    if try_vcpkg(is_static) {
        return;
    }

    #[cfg(not(windows))]
    if try_pkg_config(is_static) {
        return;
    }

    panic!("couldn't find libssh with specified options");
}

#[cfg(windows)]
fn try_vcpkg(is_static: bool) -> bool {
    if !is_static {
        std::env::set_var("VCPKGRS_DYNAMIC", "true");
    }

    let lib = vcpkg::find_package("libssh");

    match lib {
        Ok(lib) => {
            for metadata in lib.cargo_metadata {
                println!("{}", metadata);
            }

            true
        }
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn try_pkg_config(is_static: bool) -> bool {
    // Dynamic libssh doesn't need initialization since 0.8,
    // so we require that to keep things easy.
    pkg_config::Config::new()
        .atleast_version("0.8")
        .statik(is_static)
        .probe("libssh")
        .is_ok()
}
