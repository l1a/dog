use std::net::TcpStream;
use std::sync::Arc;
use rustls::pki_types::ServerName;
use super::Error;
use std::convert::TryFrom;

pub fn stream_tls(domain: &str, port: u16) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Error> {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from(domain)?.to_owned();

    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    let sock = TcpStream::connect((domain, port))?;
    let tls = rustls::StreamOwned::new(conn, sock);

    Ok(tls)
}
