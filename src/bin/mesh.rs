fn main() {
    let args: Vec<String> = std::env::args().collect();
    let tailnet = args.get(1).map(|s| s.as_str()).unwrap_or("etherhive");

    println!("etherhive-mesh :: Tailscale/Headscale peer-to-peer");
    println!("  tailnet    : {}", tailnet);
    println!("  protocol   : WireGuard");
    println!("  relay      : DERP (fallback when direct fails)");
    println!("  discovery  : coordination server");

    // Design only -- nothing below this line is real yet. In production:
    // tailscale up --login-server <headscale_url> --authkey <key>
    // Or with Tailscale SaaS: tailscale up --authkey <key>

    eprintln!("  [NOT IMPLEMENTED] this binary does not join a real mesh");
    eprintln!("  no Tailscale/Headscale connection is made -- see issue #1 (github.com/peterlodri-sec/etherhive/issues/1)");
    std::process::exit(1);
}
