//! Tightly scoped Linux `AF_PACKET` + classic kernel BPF (`SO_ATTACH_FILTER`) capture module.
//!
//! All `unsafe` FFI calls are isolated strictly to this module; packet parsing, correlation,
//! configuration loading, and HTTP/Prometheus serving remain 100% safe Rust.

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Builds a 25-instruction Linux classic BPF filter accepting ONLY:
/// - Unfragmented IPv4 UDP packets where sport or dport is in `{matter_port, mdns_port}`
/// - IPv6 UDP packets (Next Header == 17) where sport or dport is in `{matter_port, mdns_port}`
/// - 802.1Q VLAN tagged frames (`0x8100`), subsequently filtered by safe Rust in `parse_af_packet_udp_frame`
///
/// Drops 99.9%+ of unrelated LAN traffic directly inside the Linux kernel.
pub fn build_matter_mdns_bpf(matter_port: u16, mdns_port: u16) -> [SockFilter; 25] {
    let mp = u32::from(matter_port);
    let dp = u32::from(mdns_port);
    [
        // 00: Load EtherType at Ethernet offset 12
        SockFilter { code: 0x28, jt: 0, jf: 0, k: 12 },
        // 01: If IPv4 (0x0800) -> 02, else -> 13
        SockFilter { code: 0x15, jt: 0, jf: 11, k: 0x0800 },
        // 02: Load IPv4 protocol at offset 23
        SockFilter { code: 0x30, jt: 0, jf: 0, k: 23 },
        // 03: If UDP (17) -> 04, else -> 24 (DROP)
        SockFilter { code: 0x15, jt: 0, jf: 20, k: 17 },
        // 04: Load IPv4 flags/fragment offset at offset 20
        SockFilter { code: 0x28, jt: 0, jf: 0, k: 20 },
        // 05: If fragmented (offset != 0) -> 24 (DROP), else -> 06
        SockFilter { code: 0x45, jt: 18, jf: 0, k: 0x1FFF },
        // 06: X = IPv4 header length (4 * (raw[14] & 0x0F))
        SockFilter { code: 0xB1, jt: 0, jf: 0, k: 14 },
        // 07: Load UDP sport at [X + 14]
        SockFilter { code: 0x48, jt: 0, jf: 0, k: 14 },
        // 08: If sport == matter_port -> 23 (ACCEPT)
        SockFilter { code: 0x15, jt: 14, jf: 0, k: mp },
        // 09: If sport == mdns_port -> 23 (ACCEPT)
        SockFilter { code: 0x15, jt: 13, jf: 0, k: dp },
        // 10: Load UDP dport at [X + 16]
        SockFilter { code: 0x48, jt: 0, jf: 0, k: 16 },
        // 11: If dport == matter_port -> 23 (ACCEPT)
        SockFilter { code: 0x15, jt: 11, jf: 0, k: mp },
        // 12: If dport == mdns_port -> 23 (ACCEPT), else -> 24 (DROP)
        SockFilter { code: 0x15, jt: 10, jf: 11, k: dp },
        // 13: If 802.1Q VLAN (0x8100) -> 23 (ACCEPT for safe Rust VLAN decoder)
        SockFilter { code: 0x15, jt: 9, jf: 0, k: 0x8100 },
        // 14: If IPv6 (0x86DD) -> 15, else -> 24 (DROP)
        SockFilter { code: 0x15, jt: 0, jf: 9, k: 0x86DD },
        // 15: Load IPv6 Next Header at offset 20 (14 + 6)
        SockFilter { code: 0x30, jt: 0, jf: 0, k: 20 },
        // 16: If UDP (17) -> 17, else -> 24 (DROP)
        SockFilter { code: 0x15, jt: 0, jf: 7, k: 17 },
        // 17: Load IPv6 UDP sport at offset 54 (14 + 40)
        SockFilter { code: 0x28, jt: 0, jf: 0, k: 54 },
        // 18: If sport == matter_port -> 23 (ACCEPT)
        SockFilter { code: 0x15, jt: 4, jf: 0, k: mp },
        // 19: If sport == mdns_port -> 23 (ACCEPT)
        SockFilter { code: 0x15, jt: 3, jf: 0, k: dp },
        // 20: Load IPv6 UDP dport at offset 56 (14 + 42)
        SockFilter { code: 0x28, jt: 0, jf: 0, k: 56 },
        // 21: If dport == matter_port -> 23 (ACCEPT)
        SockFilter { code: 0x15, jt: 1, jf: 0, k: mp },
        // 22: If dport == mdns_port -> 23 (ACCEPT), else -> 24 (DROP)
        SockFilter { code: 0x15, jt: 0, jf: 1, k: dp },
        // 23: ACCEPT up to 512 bytes
        SockFilter { code: 0x06, jt: 0, jf: 0, k: 512 },
        // 24: DROP
        SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 },
    ]
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{build_matter_mdns_bpf, SockFilter};
    use std::ffi::CString;
    use std::io;
    use std::mem;
    use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};

    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const ETH_P_ALL_BE: c_int = 0x0300; // htons(0x0003) on little-endian; computed via to_be below
    const SOL_SOCKET: c_int = 1;
    const SO_ATTACH_FILTER: c_int = 26;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

    #[cfg(target_arch = "x86_64")]
    const SYS_CAPSET: c_long = 126;
    #[cfg(target_arch = "aarch64")]
    const SYS_CAPSET: c_long = 91;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const SYS_CAPSET: c_long = -1;

    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const SockFilter,
    }

    #[repr(C)]
    struct SockAddrLl {
        sll_family: u16,
        sll_protocol: u16,
        sll_ifindex: c_int,
        sll_hatype: u16,
        sll_pkttype: u8,
        sll_halen: u8,
        sll_addr: [u8; 8],
    }

    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: c_int,
    }

    #[repr(C)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn bind(sockfd: c_int, addr: *const c_void, addrlen: u32) -> c_int;
        fn setsockopt(
            sockfd: c_int,
            level: c_int,
            optname: c_int,
            optval: *const c_void,
            optlen: u32,
        ) -> c_int;
        fn recv(sockfd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        fn close(fd: c_int) -> c_int;
        fn if_nametoindex(ifname: *const c_char) -> c_uint;
        fn syscall(num: c_long, ...) -> c_long;
    }

    pub struct LinuxBpfSniffer {
        fd: c_int,
        pub bpf_attached: bool,
        pub caps_dropped: bool,
    }

    impl LinuxBpfSniffer {
        pub fn open(
            iface: &str,
            matter_port: u16,
            mdns_port: u16,
            drop_caps: bool,
        ) -> io::Result<Self> {
            let _ = ETH_P_ALL_BE;
            let proto_be = c_int::from(0x0003u16.to_be());
            let fd = unsafe { socket(AF_PACKET, SOCK_RAW, proto_be) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let c_iface = CString::new(iface).map_err(|_| {
                unsafe { close(fd) };
                io::Error::new(io::ErrorKind::InvalidInput, "interface name contains NUL")
            })?;
            let ifindex = unsafe { if_nametoindex(c_iface.as_ptr()) };
            if ifindex == 0 {
                unsafe { close(fd) };
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("network interface '{iface}' not found"),
                ));
            }

            let sll = SockAddrLl {
                sll_family: AF_PACKET as u16,
                sll_protocol: 0x0003u16.to_be(),
                sll_ifindex: ifindex as c_int,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0u8; 8],
            };
            let rc = unsafe {
                bind(
                    fd,
                    (&sll as *const SockAddrLl).cast::<c_void>(),
                    mem::size_of::<SockAddrLl>() as u32,
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                unsafe { close(fd) };
                return Err(err);
            }

            let insns = build_matter_mdns_bpf(matter_port, mdns_port);
            let prog = SockFprog {
                len: insns.len() as u16,
                filter: insns.as_ptr(),
            };
            let bpf_rc = unsafe {
                setsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ATTACH_FILTER,
                    (&prog as *const SockFprog).cast::<c_void>(),
                    mem::size_of::<SockFprog>() as u32,
                )
            };
            let bpf_attached = bpf_rc == 0;
            if !bpf_attached {
                eprintln!(
                    "[matter-echo-delta] WARN: SO_ATTACH_FILTER failed ({}); falling back to user-space filter",
                    io::Error::last_os_error()
                );
            }

            let caps_dropped = if drop_caps {
                drop_all_linux_capabilities()
            } else {
                false
            };

            Ok(Self {
                fd,
                bpf_attached,
                caps_dropped,
            })
        }

        pub fn recv_frame(&self, buf: &mut [u8]) -> io::Result<usize> {
            let n = unsafe { recv(self.fd, buf.as_mut_ptr().cast::<c_void>(), buf.len(), 0) };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    impl Drop for LinuxBpfSniffer {
        fn drop(&mut self) {
            unsafe {
                close(self.fd);
            }
        }
    }

    /// Drops all effective, permitted, and inheritable Linux capabilities (CapEff -> 0)
    /// once the read-only AF_PACKET + BPF descriptor is open.
    fn drop_all_linux_capabilities() -> bool {
        if SYS_CAPSET < 0 {
            return false;
        }
        let mut hdr = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        let rc = unsafe { syscall(SYS_CAPSET, &mut hdr as *mut CapUserHeader, data.as_ptr()) };
        rc == 0
    }
}

#[cfg(target_os = "linux")]
pub use platform::LinuxBpfSniffer;

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny deterministic classic BPF VM to prove every jump offset & filter branch mathematically.
    fn run_cbpf(prog: &[SockFilter], pkt: &[u8]) -> u32 {
        let mut pc: usize = 0;
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut steps = 0usize;
        while pc < prog.len() {
            steps += 1;
            assert!(steps <= 64, "BPF loop/overflow at pc={pc}");
            let ins = prog[pc];
            let k = ins.k as usize;
            match ins.code {
                0x28 => {
                    if k + 2 > pkt.len() {
                        return 0;
                    }
                    a = u32::from(u16::from_be_bytes([pkt[k], pkt[k + 1]]));
                    pc += 1;
                }
                0x30 => {
                    if k >= pkt.len() {
                        return 0;
                    }
                    a = u32::from(pkt[k]);
                    pc += 1;
                }
                0xB1 => {
                    if k >= pkt.len() {
                        return 0;
                    }
                    x = u32::from(pkt[k] & 0x0F) * 4;
                    pc += 1;
                }
                0x48 => {
                    let off = (x as usize) + k;
                    if off + 2 > pkt.len() {
                        return 0;
                    }
                    a = u32::from(u16::from_be_bytes([pkt[off], pkt[off + 1]]));
                    pc += 1;
                }
                0x15 => {
                    let jmp = if a == ins.k { ins.jt } else { ins.jf };
                    pc += 1 + usize::from(jmp);
                }
                0x45 => {
                    let jmp = if (a & ins.k) != 0 { ins.jt } else { ins.jf };
                    pc += 1 + usize::from(jmp);
                }
                0x06 => return ins.k,
                other => panic!("unexpected opcode 0x{other:02x}"),
            }
        }
        panic!("BPF program fell off the end");
    }

    fn ipv4_udp(sport: u16, dport: u16, frag: u16, proto: u8) -> Vec<u8> {
        let mut f = vec![0u8; 42];
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        f[14] = 0x45;
        f[20..22].copy_from_slice(&frag.to_be_bytes());
        f[23] = proto;
        f[34..36].copy_from_slice(&sport.to_be_bytes());
        f[36..38].copy_from_slice(&dport.to_be_bytes());
        f
    }

    fn ipv6_udp(sport: u16, dport: u16, next_hdr: u8) -> Vec<u8> {
        let mut f = vec![0u8; 62];
        f[12..14].copy_from_slice(&0x86DDu16.to_be_bytes());
        f[14] = 0x60;
        f[20] = next_hdr;
        f[54..56].copy_from_slice(&sport.to_be_bytes());
        f[56..58].copy_from_slice(&dport.to_be_bytes());
        f
    }

    #[test]
    fn bpf_accepts_only_matter_mdns_and_vlan_frames() {
        let prog = build_matter_mdns_bpf(5540, 5353);
        // Verify all jump targets stay inside prog
        for (i, ins) in prog.iter().enumerate() {
            if ins.code == 0x15 || ins.code == 0x45 {
                assert!(i + 1 + usize::from(ins.jt) < prog.len());
                assert!(i + 1 + usize::from(ins.jf) < prog.len());
            }
        }

        // IPv4 accepts
        assert_eq!(run_cbpf(&prog, &ipv4_udp(5540, 51234, 0, 17)), 512);
        assert_eq!(run_cbpf(&prog, &ipv4_udp(51234, 5540, 0, 17)), 512);
        assert_eq!(run_cbpf(&prog, &ipv4_udp(5353, 5353, 0, 17)), 512);
        // IPv4 drops: TCP, unrelated UDP, fragmented IPv4
        assert_eq!(run_cbpf(&prog, &ipv4_udp(5540, 5540, 0, 6)), 0);
        assert_eq!(run_cbpf(&prog, &ipv4_udp(443, 51234, 0, 17)), 0);
        assert_eq!(run_cbpf(&prog, &ipv4_udp(5540, 5540, 0x0040, 17)), 0);

        // IPv6 accepts & drops
        assert_eq!(run_cbpf(&prog, &ipv6_udp(5540, 49152, 17)), 512);
        assert_eq!(run_cbpf(&prog, &ipv6_udp(49152, 5540, 17)), 512);
        assert_eq!(run_cbpf(&prog, &ipv6_udp(5353, 5353, 17)), 512);
        assert_eq!(run_cbpf(&prog, &ipv6_udp(443, 49152, 17)), 0);
        assert_eq!(run_cbpf(&prog, &ipv6_udp(5540, 5540, 6)), 0);

        // 802.1Q VLAN frame passes to safe Rust parser
        let mut vlan = vec![0u8; 46];
        vlan[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        assert_eq!(run_cbpf(&prog, &vlan), 512);

        // ARP frame dropped
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert_eq!(run_cbpf(&prog, &arp), 0);
    }
}
