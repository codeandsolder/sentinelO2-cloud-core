use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct Identity {
    pub host_id: String,
    pub token: crate::AuthToken,
    pub hub: String,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity file not found at {0} — run sentinelx-enroll to enroll this host")]
    Missing(PathBuf),
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("identity file missing field: {0}")]
    MissingField(&'static str),
    #[error("enrollment token in {path} is empty — re-run enrollment for this host")]
    EmptyToken { path: PathBuf },
    #[error(
        "enrollment token in {path} contains non-ASCII characters — re-run enrollment and paste the token exactly"
    )]
    NonAsciiToken { path: PathBuf },
    #[error(
        "enrollment token in {path} contains whitespace — copy the token as one unbroken string"
    )]
    WhitespaceToken { path: PathBuf },
    #[error(
        "enrollment token in {path} is not a well-formed token (expected three dot-separated parts)"
    )]
    MalformedToken { path: PathBuf },
}

#[derive(Deserialize)]
struct RawIdentity {
    host_id: Option<serde_json::Value>,
    token: Option<serde_json::Value>,
    hub: Option<serde_json::Value>,
}

fn scalar_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text,
        other => other.to_string(),
    }
}

fn validate_token(token: String, path: &Path) -> Result<String, IdentityError> {
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(IdentityError::EmptyToken { path: path.into() });
    }
    if !token.is_ascii() {
        return Err(IdentityError::NonAsciiToken { path: path.into() });
    }
    if token.chars().any(char::is_whitespace) {
        return Err(IdentityError::WhitespaceToken { path: path.into() });
    }
    let mut parts = token.split('.');
    let shape_ok = matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(a), Some(b), Some(c), None) if !a.is_empty() && !b.is_empty() && !c.is_empty()
    );
    if !shape_ok {
        return Err(IdentityError::MalformedToken { path: path.into() });
    }
    Ok(token)
}

pub fn load_identity(path: &Path) -> Result<Identity, IdentityError> {
    if !path.exists() {
        return Err(IdentityError::Missing(path.into()));
    }
    let text = fs::read_to_string(path).map_err(|source| IdentityError::Read {
        path: path.into(),
        source,
    })?;
    let raw: RawIdentity = serde_json::from_str(&text).map_err(|source| IdentityError::Parse {
        path: path.into(),
        source,
    })?;

    let host_id = raw
        .host_id
        .ok_or(IdentityError::MissingField("host_id"))
        .map(scalar_string)?
        .trim()
        .to_owned();
    let token = raw
        .token
        .ok_or(IdentityError::MissingField("token"))
        .map(scalar_string)?;
    let hub = raw
        .hub
        .ok_or(IdentityError::MissingField("hub"))
        .map(scalar_string)?
        .trim()
        .to_owned();
    let token = validate_token(token, path)?;

    Ok(Identity {
        host_id,
        token: crate::AuthToken::new(token),
        hub,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("identity.json");
        fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn valid_identity_trims_scalar_fields() {
        let (_dir, path) = write(
            r#"{"host_id":" host_1 ","token":" aaa.bbb.ccc \n","hub":" https://hub.example "}"#,
        );
        let identity = load_identity(&path).unwrap();
        assert_eq!(identity.host_id, "host_1");
        assert_eq!(identity.hub, "https://hub.example");
        assert_eq!(format!("{:?}", identity.token), "[redacted]");
    }

    #[test]
    fn malformed_tokens_fail_before_network_use() {
        for token in ["", "one.two", "one..three", "one two.three.four", "ą.b.c"] {
            let (_dir, path) = write(&format!(
                r#"{{"host_id":"h","token":"{token}","hub":"https://hub"}}"#
            ));
            assert!(load_identity(&path).is_err(), "{token:?}");
        }
    }

    #[test]
    fn missing_required_field_is_explicit() {
        let (_dir, path) = write(r#"{"host_id":"h","token":"a.b.c"}"#);
        assert!(matches!(
            load_identity(&path),
            Err(IdentityError::MissingField("hub"))
        ));
    }
}
