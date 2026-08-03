//! JSON-lines adapter for the stand-alone Komms conformance kit.

use std::io::{self, BufRead, Write};

const MAX_REQUEST_LINE_BYTES: usize = 4 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("conformance adapter failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().split(b'\n') {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let response = if line.len() > MAX_REQUEST_LINE_BYTES {
            kult_conformance::error_response(
                None,
                "request_too_large",
                "request exceeds the fixed adapter line limit",
            )
        } else {
            kult_conformance::process_request_bytes(&line)
        };
        serde_json::to_writer(&mut stdout, &response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    }
    Ok(())
}
