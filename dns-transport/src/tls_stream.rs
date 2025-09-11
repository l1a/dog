use std::net::TcpStream;
use super::Error;

pub fn stream_tls(domain: &str, port: u16) -> Result<rustls::StreamOwned<rustls::ClientSession, TcpStream>, Error> {
    use std::sync::Arc;

    let mut config = rustls::ClientConfig::new();

    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(domain)?;

    let conn = rustls::ClientSession::new(&Arc::new(config), dns_name);

    let sock = TcpStream::connect((domain, port))?;
    let tls = rustls::StreamOwned::new(conn, sock);

    Ok(tls)
}
