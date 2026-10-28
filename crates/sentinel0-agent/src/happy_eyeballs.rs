use std::{collections::VecDeque, io, net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, task::JoinSet, time::sleep};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{
        self,
        handshake::client::{Request, Response},
        protocol::WebSocketConfig,
    },
};

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
        if !first_family.is_empty() {
            out.push(first_family.pop_front().expect("checked non-empty"));
        }
        if !other.is_empty() {
            out.push(other.pop_front().expect("checked non-empty"));
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

pub async fn connect(
    request: Request,
    config: Option<WebSocketConfig>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), tungstenite::Error> {
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
    client_async_tls_with_config(request, stream, config, None).await
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
