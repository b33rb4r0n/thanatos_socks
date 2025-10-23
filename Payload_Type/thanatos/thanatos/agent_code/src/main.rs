use thanatos::real_main;

/// Entrypoint when running the binary standalone.
fn main() {
    if let Err(e) = real_main() {
        eprintln!("Agent error: {}", e);
        std::process::exit(1);
    }
}