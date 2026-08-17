fn main() {
    let args: Vec<String> = std::env::args().collect();
    let entry = args.get(1).map(|s| s.as_str()).unwrap_or("switzerland");
    let exit = args.get(2).map(|s| s.as_str()).unwrap_or("iceland");

    println!("etherhive-vpn :: Mullvad double-hop WireGuard");
    println!("  entry node : {}", entry);
    println!("  exit node  : {}", exit);
    println!("  protocol   : WireGuard");
    println!("  rotation   : 4 hours");

    // Design only -- nothing below this line is real yet. In production:
    // mullvad relay set location {entry} {exit}
    // mullvad connect
    // WireGuard keys rotated every 4h via cron/systemd timer

    eprintln!("  [NOT IMPLEMENTED] this binary does not open a real tunnel");
    eprintln!("  traffic is NOT routed through Mullvad or any VPN -- see issue #1 (github.com/peterlodri-sec/etherhive/issues/1)");
    std::process::exit(1);
}
