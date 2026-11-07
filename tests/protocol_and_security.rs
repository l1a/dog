// SPDX-License-Identifier: GPL-3.0-or-later

//! Offline end-to-end integration tests for protocol flags, UDP-to-TCP
//! truncation fallback, custom nameserver ports, and terminal escape
//! sanitization against a loopback DNS server.

use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use hickory_resolver::proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::rdata::{HINFO, MX, NS, TXT};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};

fn dog_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_dog"))
}

/// Spawns a one-shot UDP DNS server on `127.0.0.1:0` and returns its bound
/// address plus a join handle that yields the decoded incoming query `Message`.
fn spawn_one_shot_udp<F>(responder: F) -> (SocketAddr, thread::JoinHandle<Message>)
where
    F: FnOnce(&Message) -> Message + Send + 'static,
{
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");
    let addr = socket.local_addr().expect("local_addr");

    let handle = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (len, peer) = socket.recv_from(&mut buf).expect("recv_from");
        let request = Message::from_vec(&buf[..len]).expect("decode DNS request");
        let response = responder(&request);
        let bytes = response.to_vec().expect("encode DNS response");
        socket.send_to(&bytes, peer).expect("send_to");
        request
    });

    (addr, handle)
}

fn base_response(request: &Message) -> Message {
    let mut resp = Message::new(request.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = request.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = ResponseCode::NoError;
    for q in &request.queries {
        resp.add_query(q.clone());
    }
    resp
}

#[test]
fn wire_flags_txid_z_tweaks_and_edns_show() {
    let (addr, server) = spawn_one_shot_udp(|req| {
        let mut resp = base_response(req);
        let q = &req.queries[0];
        let record = Record::from_rdata(
            q.name().clone(),
            120,
            RData::A(Ipv4Addr::new(93, 184, 215, 14).into()),
        );
        resp.add_answer(record);

        let mut edns = Edns::new();
        edns.set_max_payload(1400);
        edns.set_dnssec_ok(true);
        resp.set_edns(edns);
        resp
    });

    let ns_arg = format!("@{addr}");
    let out = dog_bin()
        .args([
            "example.com",
            "A",
            &ns_arg,
            "-U",
            "--color=never",
            "--txid=0x1337",
            "--edns=show",
            "-Z",
            "aa",
            "-Z",
            "ad",
            "-Z",
            "cd",
            "-Z",
            "do",
            "-Z",
            "bufsize=1400",
        ])
        .output()
        .expect("run dog");

    let req = server.join().expect("server thread");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(req.id, 0x1337);
    assert!(req.metadata.authoritative, "expected AA flag");
    assert!(req.metadata.authentic_data, "expected AD flag");
    assert!(req.metadata.checking_disabled, "expected CD flag");

    let edns = req.edns.as_ref().expect("expected EDNS OPT in request");
    assert_eq!(edns.max_payload(), 1400);
    assert!(edns.flags().dnssec_ok, "expected DO bit in EDNS OPT");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("93.184.215.14"), "stdout: {}", stdout);
    assert!(
        stdout.contains("OPT") && stdout.contains("UDP payload: 1400"),
        "expected OPT row in --edns=show output, got: {}",
        stdout
    );
}

#[test]
fn edns_disable_omits_opt_record() {
    let (addr, server) = spawn_one_shot_udp(|req| {
        let mut resp = base_response(req);
        let q = &req.queries[0];
        resp.add_answer(Record::from_rdata(
            q.name().clone(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
        resp
    });

    let ns_arg = format!("@{addr}");
    let out = dog_bin()
        .args([
            "example.com",
            "A",
            &ns_arg,
            "-U",
            "--edns=disable",
            "--short",
        ])
        .output()
        .expect("run dog");

    let req = server.join().expect("server thread");
    assert_eq!(out.status.code(), Some(0));
    assert!(
        req.edns.is_none(),
        "expected no EDNS OPT record when --edns=disable"
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "192.0.2.1");
}

#[test]
fn chaos_class_query_and_response() {
    let (addr, server) = spawn_one_shot_udp(|req| {
        let mut resp = base_response(req);
        let q = &req.queries[0];
        let mut record = Record::from_rdata(
            q.name().clone(),
            0,
            RData::TXT(TXT::new(vec!["dog-test-chaos-server".to_string()])),
        );
        record.dns_class = DNSClass::CH;
        resp.add_answer(record);
        resp
    });

    let ns_arg = format!("@{addr}");
    let out = dog_bin()
        .args([
            "version.bind",
            "TXT",
            "--class=CH",
            &ns_arg,
            "-U",
            "--short",
        ])
        .output()
        .expect("run dog");

    let req = server.join().expect("server thread");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(req.queries[0].query_class(), DNSClass::CH);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("dog-test-chaos-server"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn truncated_udp_falls_back_to_tcp_by_default() {
    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
    let port = udp_socket.local_addr().expect("udp local_addr").port();
    // Bind TCP on the same port if available; retry on a fresh pair if needed.
    let (udp_socket, tcp_listener, addr) = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
        Ok(tcp) => (
            udp_socket,
            tcp,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ),
        Err(_) => {
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind TCP");
            let p = tcp.local_addr().expect("tcp local_addr").port();
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, p)).expect("bind matching UDP");
            (udp, tcp, SocketAddr::from((Ipv4Addr::LOCALHOST, p)))
        }
    };

    udp_socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("udp timeout");
    tcp_listener.set_nonblocking(false).expect("tcp blocking");

    let udp_handle = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let (len, peer) = udp_socket.recv_from(&mut buf).expect("udp recv");
        let req = Message::from_vec(&buf[..len]).expect("decode udp req");
        let mut resp = base_response(&req);
        resp.metadata.truncation = true;
        let bytes = resp.to_vec().expect("encode truncated udp resp");
        udp_socket.send_to(&bytes, peer).expect("udp send");
    });

    let tcp_handle = thread::spawn(move || {
        let (mut stream, _) = tcp_listener.accept().expect("tcp accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("tcp read timeout");
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).expect("read tcp len");
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).expect("read tcp msg");

        let req = Message::from_vec(&msg_buf).expect("decode tcp req");
        let mut resp = base_response(&req);
        let name = Name::from_str("example.com.").unwrap();
        resp.add_answer(Record::from_rdata(
            name,
            300,
            RData::A(Ipv4Addr::new(198, 51, 100, 42).into()),
        ));
        let bytes = resp.to_vec().expect("encode tcp resp");
        let out_len = u16::try_from(bytes.len()).expect("u16 len").to_be_bytes();
        stream.write_all(&out_len).expect("write tcp len");
        stream.write_all(&bytes).expect("write tcp body");
    });

    let ns_arg = format!("@{addr}");
    let out = dog_bin()
        .args(["example.com", "A", &ns_arg, "--short"])
        .output()
        .expect("run dog");

    udp_handle.join().expect("udp thread");
    tcp_handle.join().expect("tcp thread");

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "198.51.100.42");
}

#[test]
fn terminal_escape_sequences_in_dns_response_are_sanitized() {
    let (addr, server) = spawn_one_shot_udp(|req| {
        let mut resp = base_response(req);
        let q = &req.queries[0];
        let record = Record::from_rdata(
            q.name().clone(),
            60,
            RData::HINFO(HINFO::new(
                "X86\x1b[31mEVIL\x07".to_string(),
                "LINUX\u{9b}2J".to_string(),
            )),
        );
        resp.add_answer(record);
        resp
    });

    let ns_arg = format!("@{addr}");
    let out = dog_bin()
        .args(["example.com", "HINFO", &ns_arg, "-U", "--color=never"])
        .output()
        .expect("run dog");

    let _ = server.join().expect("server thread");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains('\x1b') && !stdout.contains('\x07') && !stdout.contains('\u{9b}'),
        "raw control character leaked to terminal stdout: {:?}",
        stdout
    );
    assert!(
        stdout.contains(r"\u{1b}[31mEVIL\u{7}") && stdout.contains(r"\u{9b}2J"),
        "expected escaped control sequences in stdout, got: {}",
        stdout
    );
}

#[test]
fn multiple_responses_render_in_single_aligned_table() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind UDP");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");
    let addr = socket.local_addr().expect("local_addr");

    let server = thread::spawn(move || {
        for _ in 0..5 {
            let mut buf = [0u8; 4096];
            let (len, peer) = socket.recv_from(&mut buf).expect("recv_from");
            let req = Message::from_vec(&buf[..len]).expect("decode DNS request");
            let mut resp = base_response(&req);
            let q = &req.queries[0];
            let name = q.name().clone();
            match q.query_type() {
                RecordType::A => {
                    resp.add_answer(Record::from_rdata(
                        name,
                        300,
                        RData::A(Ipv4Addr::new(104, 20, 21, 8).into()),
                    ));
                }
                RecordType::AAAA => {
                    resp.add_answer(Record::from_rdata(
                        name,
                        300,
                        RData::AAAA(
                            Ipv6Addr::from_str("2606:4700:10::6814:1508")
                                .unwrap()
                                .into(),
                        ),
                    ));
                }
                RecordType::NS => {
                    resp.add_answer(Record::from_rdata(
                        name,
                        86400,
                        RData::NS(NS(Name::from_str("hugh.ns.cloudflare.com.").unwrap())),
                    ));
                }
                RecordType::MX => {
                    resp.add_answer(Record::from_rdata(
                        name,
                        300,
                        RData::MX(MX::new(0, Name::from_str(".").unwrap())),
                    ));
                }
                RecordType::TXT => {
                    resp.add_answer(Record::from_rdata(
                        name,
                        300,
                        RData::TXT(TXT::new(vec!["v=spf1 -all".to_string()])),
                    ));
                }
                other => panic!("unexpected query type: {}", other),
            }
            let bytes = resp.to_vec().expect("encode DNS response");
            socket.send_to(&bytes, peer).expect("send_to");
        }
    });

    let ns_arg = format!("@{addr}");
    let out = dog_bin()
        .args([
            "example.net",
            "A",
            "AAAA",
            "NS",
            "MX",
            "TXT",
            &ns_arg,
            "-U",
            "--color=never",
        ])
        .output()
        .expect("run dog");

    server.join().expect("server thread");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let expected = concat!(
        "   A example.net.      5m00s   104.20.21.8\n",
        "AAAA example.net.      5m00s   2606:4700:10::6814:1508\n",
        "  NS example.net. 1d0h00m00s   hugh.ns.cloudflare.com.\n",
        "  MX example.net.      5m00s   0 .\n",
        " TXT example.net.      5m00s   v=spf1 -all\n",
    );
    assert_eq!(stdout, expected);
}
