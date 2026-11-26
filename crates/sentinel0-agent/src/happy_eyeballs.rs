use std::{collections::VecDeque, io, net::SocketAddr, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    task::JoinSet,
    time::sleep,
};
use tokio_tungstenite::{
    WebSocketStream, client_async_with_config,
    tungstenite::{
        self,
        handshake::client::{Request, Response},
        protocol::WebSocketConfig,
    },
};

pub(crate) trait WebSocketIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> WebSocketIo for T {}

pub(crate) type AgentWebSocket = WebSocketStream<Box<dyn WebSocketIo>>;

fn tls_connector() -> Result<btls::ssl::SslConnector, btls::error::ErrorStack> {
    use btls::{
        ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
        x509::X509,
    };
    let mut builder = SslConnector::bare_builder(SslMethod::tls_client())?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    for certificate in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        builder
            .cert_store_mut()
            .add_cert(X509::from_der(certificate.as_ref())?)?;
    }
    Ok(builder.build())
}

pub const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

fn interleave_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addrs.first() else {
        return addrs;
    };
    let first_is_v6 = first.is_ipv6();
    let (mut first_family, mut other): (VecDeque<_>, VecDeque<_>) = addrs
        .into_iter()
        .partition(|addr| addr.is_ipv6() == first_is_v6);
    let mut out = Vec::with_capacity(first_family.len() + other.len());
    while !first_family.is_empty() || !other.is_empty() {
        if let Some(addr) = first_family.pop_front() {
            out.push(addr);
        }
        if let Some(addr) = other.pop_front() {
            out.push(addr);
        }
    }
    out
}

async fn race_tcp(addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
    let addrs = interleave_addrs(addrs);
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "hub name resolved to no addresses",
        ));
    }
    let mut tasks = JoinSet::new();
    for (index, addr) in addrs.into_iter().enumerate() {
        tasks.spawn(async move {
            if index != 0 {
                sleep(
                    HAPPY_EYEBALLS_DELAY.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX)),
                )
                .await;
            }
            TcpStream::connect(addr).await
        });
    }
    let mut last_error = None;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(stream)) => {
                tasks.abort_all();
                return Ok(stream);
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                last_error = Some(io::Error::other(format!("connect task failed: {error}")));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("all hub addresses failed")))
}

pub(crate) async fn connect(
    request: Request,
    config: Option<WebSocketConfig>,
) -> Result<(AgentWebSocket, Response), tungstenite::Error> {
    let secure = match request.uri().scheme_str() {
        Some("wss") => true,
        Some("ws") => false,
        _ => {
            return Err(tungstenite::Error::Url(
                tungstenite::error::UrlError::UnsupportedUrlScheme,
            ));
        }
    };
    let host = request
        .uri()
        .host()
        .ok_or(tungstenite::Error::Url(
            tungstenite::error::UrlError::NoHostName,
        ))?
        .to_owned();
    let port = request
        .uri()
        .port_u16()
        .or_else(|| match request.uri().scheme_str() {
            Some("wss") => Some(443),
            Some("ws") => Some(80),
            _ => None,
        })
        .ok_or(tungstenite::Error::Url(
            tungstenite::error::UrlError::UnsupportedUrlScheme,
        ))?;
    let addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(tungstenite::Error::Io)?
        .collect::<Vec<_>>();
    let stream = race_tcp(addrs).await.map_err(tungstenite::Error::Io)?;
    let stream: Box<dyn WebSocketIo> = if secure {
        let tls_error =
            |error: btls::error::ErrorStack| tungstenite::Error::Io(io::Error::other(error));
        let connector = tls_connector().map_err(tls_error)?;
        let ssl = connector
            .configure()
            .and_then(|configuration| configuration.into_ssl(&host))
            .map_err(tls_error)?;
        let mut stream = tokio_btls::SslStream::new(ssl, stream).map_err(tls_error)?;
        Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|error| tungstenite::Error::Io(io::Error::other(error)))?;
        Box::new(stream)
    } else {
        Box::new(stream)
    };
    client_async_with_config(request, stream, config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_interleaved_without_reordering_each_family() {
        let v6_1 = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443));
        let v6_2 = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443));
        let v4_1 = SocketAddr::from(([192, 0, 2, 1], 443));
        let v4_2 = SocketAddr::from(([192, 0, 2, 2], 443));
        let got = interleave_addrs(vec![v6_1, v6_2, v4_1, v4_2]);
        assert!(got[0].is_ipv6());
        assert!(got[1].is_ipv4());
        assert_eq!(got[0], v6_1);
        assert_eq!(got[2], v6_2);
    }
}
