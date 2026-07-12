//! The UniFFI bindings generator, run against the built `kult_ffi` library
//! to emit Kotlin/Swift sources (see the crate docs for the invocation).
//! Build-time tooling only — gated behind the `bindgen` feature.

fn main() {
    uniffi::uniffi_bindgen_main()
}
