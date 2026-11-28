//! Agent-specific hub WebSocket handshake.
use http::{HeaderValue, StatusCode, Uri, header::AUTHORIZATION};
use wreq::{Client, ws::WebSocket};

#[derive(Debug, thiserror::Error)]
pub enum HubConnectError {
    #[error("invalid hub WebSocket URL: {0}")]
    InvalidUrl(String),
    #[error("hub rejected WebSocket handshake: HTTP {0}")]
    Status(StatusCode),
    #[error(transparent)]
    Transport(#[from] wreq::Error),
}

pub async fn connect_hub(
    client: &Client,
    base: &str,
    authorization: HeaderValue,
) -> Result<WebSocket, HubConnectError> {
    let url = format!("{}/agent/connect", base.trim_end_matches('/'));
    let uri = url
        .parse::<Uri>()
        .map_err(|e| HubConnectError::InvalidUrl(e.to_string()))?;
    if !matches!(uri.scheme_str(), Some("ws" | "wss")) || uri.host().is_none() {
        return Err(HubConnectError::InvalidUrl(
            "expected ws:// or wss:// with a host".into(),
        ));
    }
    let response = client
        .websocket(uri)
        .header(AUTHORIZATION, authorization)
        .max_message_size(sentinel0_proto::MAX_BINARY_FRAME_BYTES)
        .send()
        .await?;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(HubConnectError::Status(response.status()));
    }
    Ok(response.into_websocket().await?)
}

#[cfg(test)]
mod tests {
    use super::{HeaderValue, connect_hub};
    use crate::test_support::{TestResult, TestValue as _};
    use btls::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        ssl::{Ssl, SslAcceptor, SslMethod},
        x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
    };
    use futures_util::{SinkExt as _, StreamExt as _};
    use std::{net::SocketAddr, pin::Pin, time::Duration};
    use tokio::{net::TcpListener, task::JoinHandle, time::timeout};
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use wreq::tls::CertStore;

    const TLS_TIMEOUT: Duration = Duration::from_secs(5);

    fn loopback_tls() -> TestResult<(SslAcceptor, CertStore)> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_nid(Nid::COMMONNAME, "localhost")?;
        let name = name.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
        cert.set_serial_number(&serial)?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&key)?;
        let not_before = Asn1Time::days_from_now(0)?;
        let not_after = Asn1Time::days_from_now(1)?;
        cert.set_not_before(&not_before)?;
        cert.set_not_after(&not_after)?;
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&cert.x509v3_context(None, None))?;
        cert.append_extension(&san)?;
        cert.sign(&key, MessageDigest::sha256())?;
        let cert = cert.build();

        let store = CertStore::builder().add_der_cert(cert.to_der()?).build()?;
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
        acceptor.set_certificate(&cert)?;
        acceptor.set_private_key(&key)?;
        acceptor.check_private_key()?;
        Ok((acceptor.build(), store))
    }

    async fn serve_websocket(
        acceptor: &SslAcceptor,
    ) -> TestResult<(SocketAddr, JoinHandle<TestResult>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let ssl = Ssl::new(acceptor.context())?;
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = tokio_btls::SslStream::new(ssl, tcp)?;
            Pin::new(&mut stream).accept().await.test_value()?;
            let mut ws = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &Request, response: Response| {
                    assert_eq!(request.uri().path(), "/agent/connect");
                    assert_eq!(
                        request.headers().get("authorization"),
                        Some(&HeaderValue::from_static("Bearer test-token"))
                    );
                    Ok(response)
                },
            )
            .await?;
            let message = ws.next().await.test_value()??;
            ws.send(message).await?;
            Ok(())
        });
        Ok((addr, task))
    }

    #[tokio::test]
    async fn encrypted_hub_handshake_checks_trust_and_hostname() -> TestResult {
        let (acceptor, trust) = loopback_tls()?;
        let token = HeaderValue::from_static("Bearer test-token");
        // Correct hostname, but the self-signed certificate is not trusted.
        let (addr, server) = serve_websocket(&acceptor).await?;
        let client = sentinel0_transport::client_builder()
            .timeout(TLS_TIMEOUT)
            .resolve_to_addrs("localhost", [addr])
            .build()?;
        let url = format!("wss://localhost:{}", addr.port());
        assert!(connect_hub(&client, &url, token.clone()).await.is_err());
        assert!(timeout(TLS_TIMEOUT, server).await??.is_err());

        // Trusted certificate, but the IP is absent from its subjectAltName.
        let (addr, server) = serve_websocket(&acceptor).await?;
        let client = sentinel0_transport::client_builder()
            .timeout(TLS_TIMEOUT)
            .tls_cert_store(trust.clone())
            .build()?;
        assert!(
            connect_hub(&client, &format!("wss://{addr}"), token.clone())
                .await
                .is_err()
        );
        assert!(timeout(TLS_TIMEOUT, server).await??.is_err());

        // Trust and hostname are correct; exercise the real authenticated upgrade.
        let (addr, server) = serve_websocket(&acceptor).await?;
        let client = sentinel0_transport::client_builder()
            .timeout(TLS_TIMEOUT)
            .resolve_to_addrs("localhost", [addr])
            .tls_cert_store(trust)
            .build()?;
        let url = format!("wss://localhost:{}", addr.port());
        let mut ws = connect_hub(&client, &url, token).await?;
        ws.send(wreq::ws::Message::Text("encrypted round trip".into()))
            .await?;
        let echoed = timeout(TLS_TIMEOUT, ws.recv()).await?.test_value()??;
        assert!(
            matches!(echoed, wreq::ws::Message::Text(text) if text.as_str() == "encrypted round trip")
        );
        timeout(TLS_TIMEOUT, server).await???;
        Ok(())
    }
}
