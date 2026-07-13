// From Swift's point of view the kult_ffiFFI module is headers-only — every
// symbol lives in the Rust-built libkult_ffi. SwiftPM still requires a C
// target to contain a compilable source file; this is it. The header it
// includes is generated into include/ by ../../scripts/generate-bindings.sh.
#include "kult_ffiFFI.h"
