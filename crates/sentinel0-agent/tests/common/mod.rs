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

pub trait TestError<E> {
    fn test_error(self) -> TestResult<E>;
}

impl<T, E> TestError<E> for Result<T, E> {
    fn test_error(self) -> TestResult<E> {
        match self {
            Err(error) => Ok(error),
            Ok(_) => Err(io::Error::other("expected Err(..), got Ok(..)").into()),
        }
    }
}
