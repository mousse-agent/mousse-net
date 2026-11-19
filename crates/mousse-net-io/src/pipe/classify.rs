//! Address classes (Phase 1b §1.2): the one classifier every dial and every
//! advertised address goes through. It is an allowlist: an address in no
//! class is `forbidden`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What kind of network an address is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddrClass {
    /// RFC 1918, IPv4 link-local, IPv6 unique local outside the tailnet
    /// range.
    Lan,
    /// `100.64.0.0/10` and `fd7a:115c:a1e0::/48`.
    Tailnet,
    /// Global unicast outside every special-purpose range.
    Public,
    /// Everything else: loopback, unspecified, multicast, reserved,
    /// documentation, benchmarking, NAT64, 6to4, IPv6 link-local and
    /// IPv4-compatible addresses.
    Forbidden,
}

impl AddrClass {
    /// The name used in the app protocol and in `approvals.json`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Lan => "lan",
            Self::Tailnet => "tailnet",
            Self::Public => "public",
            Self::Forbidden => "forbidden",
        }
    }
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn in_v6(ip: Ipv6Addr, net: Ipv6Addr, bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    u128::from(ip) & mask == u128::from(net) & mask
}

/// IPv4 ranges that are never dialled or advertised.
const V4_FORBIDDEN: [([u8; 4], u32); 11] = [
    ([0, 0, 0, 0], 8),
    ([127, 0, 0, 0], 8),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 88, 99, 0], 24),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];

fn classify_v4(ip: Ipv4Addr) -> AddrClass {
    if in_v4(ip, [100, 64, 0, 0], 10) {
        AddrClass::Tailnet
    } else if in_v4(ip, [10, 0, 0, 0], 8)
        || in_v4(ip, [172, 16, 0, 0], 12)
        || in_v4(ip, [192, 168, 0, 0], 16)
        || in_v4(ip, [169, 254, 0, 0], 16)
    {
        AddrClass::Lan
    } else if V4_FORBIDDEN
        .iter()
        .any(|(net, bits)| in_v4(ip, *net, *bits))
    {
        AddrClass::Forbidden
    } else {
        AddrClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddrClass {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let v6 = |text: &str| -> Ipv6Addr { text.parse().unwrap_or(Ipv6Addr::UNSPECIFIED) };
    if in_v6(ip, v6("fd7a:115c:a1e0::"), 48) {
        AddrClass::Tailnet
    } else if in_v6(ip, v6("fc00::"), 7) {
        AddrClass::Lan
    } else if in_v6(ip, v6("2000::"), 3)
        && !in_v6(ip, v6("2001:db8::"), 32)
        && !in_v6(ip, v6("2002::"), 16)
    {
        AddrClass::Public
    } else {
        // `::`, `::1`, `fe80::/10`, `ff00::/8`, NAT64 (`64:ff9b::/96`,
        // `64:ff9b:1::/48`), IPv4-compatible `::a.b.c.d` and every other
        // range outside `2000::/3` and `fc00::/7`.
        AddrClass::Forbidden
    }
}

/// The class of `ip`. An IPv4-mapped IPv6 address takes the class of its
/// IPv4 address.
pub fn classify(ip: IpAddr) -> AddrClass {
    let class = match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    };
    // The control build counts every range outside the allowlist as public.
    if cfg!(mousse_control = "unlisted-allowed") && class == AddrClass::Forbidden {
        return AddrClass::Public;
    }
    class
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_address_falls_in_one_listed_class_or_is_forbidden() {
        let cases = [
            ("10.1.2.3", AddrClass::Lan),
            ("172.16.0.1", AddrClass::Lan),
            ("172.31.255.254", AddrClass::Lan),
            ("192.168.1.20", AddrClass::Lan),
            ("169.254.3.4", AddrClass::Lan),
            ("fd12:3456::9", AddrClass::Lan),
            ("fc00::1", AddrClass::Lan),
            ("::ffff:192.168.0.2", AddrClass::Lan),
            ("100.64.0.1", AddrClass::Tailnet),
            ("100.127.255.254", AddrClass::Tailnet),
            ("fd7a:115c:a1e0::1", AddrClass::Tailnet),
            ("8.8.8.8", AddrClass::Public),
            ("172.32.0.1", AddrClass::Public),
            ("100.128.0.1", AddrClass::Public),
            ("2606:4700::1111", AddrClass::Public),
            ("::ffff:8.8.8.8", AddrClass::Public),
            ("0.0.0.0", AddrClass::Forbidden),
            ("127.0.0.1", AddrClass::Forbidden),
            ("224.0.0.251", AddrClass::Forbidden),
            ("240.0.0.1", AddrClass::Forbidden),
            ("255.255.255.255", AddrClass::Forbidden),
            ("192.0.2.1", AddrClass::Forbidden),
            ("198.51.100.1", AddrClass::Forbidden),
            ("203.0.113.7", AddrClass::Forbidden),
            ("198.18.0.1", AddrClass::Forbidden),
            ("192.0.0.1", AddrClass::Forbidden),
            ("::", AddrClass::Forbidden),
            ("::1", AddrClass::Forbidden),
            ("fe80::1", AddrClass::Forbidden),
            ("ff02::fb", AddrClass::Forbidden),
            ("64:ff9b::808:808", AddrClass::Forbidden),
            ("64:ff9b:1::1", AddrClass::Forbidden),
            ("2001:db8::1", AddrClass::Forbidden),
            ("2002:808:808::1", AddrClass::Forbidden),
            ("::8.8.8.8", AddrClass::Forbidden),
            ("4000::1", AddrClass::Forbidden),
        ];
        for (text, class) in cases {
            assert_eq!(classify(text.parse().unwrap()), class, "{text}");
        }
    }
}
