/// Assert request headers without changing the server handshake response.
pub struct AssertHeaders<F>(pub F);

impl<F> tokio_tungstenite::tungstenite::handshake::server::Callback for AssertHeaders<F>
where
    F: FnOnce(&tokio_tungstenite::tungstenite::handshake::server::Request),
{
    fn on_request(
        self,
        request: &tokio_tungstenite::tungstenite::handshake::server::Request,
        response: tokio_tungstenite::tungstenite::handshake::server::Response,
    ) -> Result<
        tokio_tungstenite::tungstenite::handshake::server::Response,
        tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
    > {
        (self.0)(request);
        Ok(response)
    }
}
