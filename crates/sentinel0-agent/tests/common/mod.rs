use std::{fmt::Debug, io};

pub type TestFailure = Box<dyn std::error::Error + Send + Sync>;
pub type TestResult<T = ()> = Result<T, TestFailure>;

pub trait TestValue<T> {
    fn test_value(self) -> TestResult<T>;
}

impl<T, E: Debug> TestValue<T> for Result<T, E> {
    fn test_value(self) -> TestResult<T> {
        match self {
            Ok(value) => Ok(value),
            Err(error) => {
                Err(io::Error::other(format!("expected Ok(..), got Err({error:?})")).into())
            }
        }
    }
}

impl<T> TestValue<T> for Option<T> {
    fn test_value(self) -> TestResult<T> {
        self.ok_or_else(|| io::Error::other("expected Some(..), got None").into())
    }
}

/// Share handshake verification mechanics between compatibility and reconnect
/// integration suites without changing what each suite asserts.
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
