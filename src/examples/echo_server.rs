fn main() {
    // Delegate to main binary (same behavior) so `cargo run --example echo_server` also works.
    tcp_stack::main()
}
