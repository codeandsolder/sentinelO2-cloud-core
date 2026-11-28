//! Shared HTTP client policy and bounded response handling.
use bytes::Bytes;
use futures_util::{Stream, StreamExt as _};
use std::{pin::pin, time::Duration};
use wreq::{Client, ClientBuilder, Response};

/// Build a client with explicit destination selection and no ambient proxies.
pub fn client_builder() -> ClientBuilder {
    // All outbound destinations are selected explicitly by the operation. Ambient
    // proxies and redirects would bypass that selection (and upload DNS pinning).
    Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .retry(wreq::retry::Policy::never())
        .tcp_happy_eyeballs_timeout(Duration::from_millis(250))
}

#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    #[error("response exceeded the byte limit")]
    TooLarge,
    #[error(transparent)]
    Transport(#[from] wreq::Error),
}

/// Check advertised length before reading, then enforce the limit on actual bytes,
/// including chunked responses. The stream terminates after the first error.
///
/// # Errors
/// Returns an error if the declared length exceeds the limit. The stream
/// reports transport failures and actual byte-limit violations.
pub fn bounded_body(
    response: Response,
    limit: u64,
) -> Result<impl Stream<Item = Result<Bytes, BodyError>>, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(BodyError::TooLarge);
    }
    Ok(limit_stream(response.bytes_stream(), limit))
}

fn limit_stream<S>(stream: S, limit: u64) -> impl Stream<Item = Result<Bytes, BodyError>>
where
    S: Stream<Item = Result<Bytes, wreq::Error>> + Unpin,
{
    futures_util::stream::try_unfold((stream, limit), |(mut stream, remaining)| async move {
        let Some(chunk) = stream.next().await else {
            return Ok(None);
        };
        let chunk = chunk?;
        let len = u64::try_from(chunk.len()).map_err(|_| BodyError::TooLarge)?;
        let remaining = remaining.checked_sub(len).ok_or(BodyError::TooLarge)?;
        Ok(Some((chunk, (stream, remaining))))
    })
    .fuse()
}

/// Collect a response while enforcing the byte limit.
///
/// # Errors
/// Returns an error on transport failure or if the response exceeds the limit.
pub async fn read_bounded(response: Response, limit: u64) -> Result<Vec<u8>, BodyError> {
    let mut stream = pin!(bounded_body(response, limit)?);
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk?);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wreq::StatusCode;
    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };

    async fn serve_response(
        response: &'static [u8],
    ) -> TestResult<(String, tokio::task::JoinHandle<std::io::Result<()>>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let byte = stream.read_u8().await?;
                request.push(byte);
                if request.len() > 8192 {
                    return Err(std::io::Error::other("unexpectedly large test request"));
                }
            }
            stream.write_all(response).await?;
            Ok(())
        });
        Ok((url, task))
    }

    #[tokio::test]
    async fn bounded_body_accepts_exact_limit_and_rejects_chunked_overflow() -> TestResult {
        let client = client_builder().timeout(Duration::from_secs(3)).build()?;
        for (limit, expected) in [(5, true), (4, false)] {
            let (url, server) = serve_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n",
            ).await?;
            let response = client.get(url).send().await?;
            let result = read_bounded(response, limit).await;
            if expected {
                assert_eq!(result?, b"abcde");
            } else {
                assert!(matches!(result, Err(BodyError::TooLarge)));
            }
            server.await??;
        }
        Ok(())
    }

    #[tokio::test]
    async fn bounded_stream_cannot_resume_after_overflow() -> TestResult {
        let chunks = futures_util::stream::iter([
            Ok(Bytes::from_static(b"ab")),
            Ok(Bytes::from_static(b"cdef")),
            Ok(Bytes::from_static(b"g")),
        ]);
        let mut stream = pin!(limit_stream(chunks, 3));
        assert_eq!(
            stream.next().await.transpose()?,
            Some(Bytes::from_static(b"ab"))
        );
        assert!(matches!(
            stream.next().await,
            Some(Err(BodyError::TooLarge))
        ));
        assert!(stream.next().await.is_none());
        assert!(stream.next().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn client_never_follows_redirects() -> TestResult {
        let (url, server) = serve_response(
            b"HTTP/1.1 302 Found\r\nLocation: /unexpected\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ).await?;
        let client = client_builder().timeout(Duration::from_secs(3)).build()?;
        let response = client.get(url).send().await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        server.await??;
        Ok(())
    }
}
