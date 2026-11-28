use crate::{
    AuthToken,
    identity::{Identity, load_identity},
};
use atomic_write_file::OpenOptions as AtomicOpenOptions;
#[cfg(unix)]
use atomic_write_file::unix::OpenOptionsExt as _;
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
#[cfg(unix)]
use nix::unistd::{AccessFlags, access};
use serde::Serialize;
use serde_json::Value;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use time::UtcDateTime;

const ROTATED_NAME: &str = "identity.rotated.json";
#[cfg(unix)]
const SYSTEM_STATE_DIR: &str = "/var/lib/sentinelx";
#[cfg(windows)]
const SYSTEM_STATE_DIR: &str = r"C:\ProgramData\SentinelO2";
const LEGACY_HALF_LIFE_SECONDS: f64 = 182.0 * 86_400.0;

#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub identity_path: PathBuf,
    pub host_id: String,
    pub hub_http_base: String,
    pub persisted_hub: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RotationError {
    #[error("rotate request failed: {0}")]
    Request(#[from] wreq::Error),
    #[error("rotate response body failed: {0}")]
    Body(#[from] sentinel0_transport::BodyError),
    #[error("rotate endpoint returned HTTP {0}")]
    Status(http::StatusCode),
    #[error("rotate response JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rotate response did not contain a well-formed credential")]
    InvalidCredential,
    #[error("could not persist rotated credential: {0}")]
    Persist(#[from] std::io::Error),
}

#[cfg(unix)]
fn directory_is_writable(path: &Path) -> bool {
    path.is_dir() && access(path, AccessFlags::W_OK).is_ok()
}

#[cfg(windows)]
fn directory_is_writable(path: &Path) -> bool {
    path.is_dir() && tempfile::tempfile_in(path).is_ok()
}

pub(crate) fn state_dir(identity_path: &Path) -> Option<PathBuf> {
    let system = Path::new(SYSTEM_STATE_DIR);
    if directory_is_writable(system) {
        return Some(system.to_owned());
    }

    let parent = identity_path.parent()?;
    directory_is_writable(parent).then(|| parent.to_owned())
}

fn rotated_path(identity_path: &Path) -> Option<PathBuf> {
    state_dir(identity_path).map(|directory| directory.join(ROTATED_NAME))
}

fn claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn numeric_claim(claims: &Value, name: &str) -> Option<f64> {
    claims.get(name)?.as_f64()
}

fn now_seconds() -> f64 {
    sentinel0_proto::clock::unix_seconds(UtcDateTime::now())
}

#[must_use = "the result determines whether credential rotation is currently due"]
pub fn should_rotate(token: &AuthToken) -> bool {
    let Some(claims) = claims(token.expose()) else {
        return false;
    };
    let Some(exp) = numeric_claim(&claims, "exp") else {
        return false;
    };
    let now = now_seconds();

    if let Some(iat) = numeric_claim(&claims, "iat") {
        return now >= iat + (exp - iat) / 2.0;
    }

    exp - now < LEGACY_HALF_LIFE_SECONDS
}

fn load_effective_identity_from(rotated: &Path, base: Identity) -> Identity {
    let candidate = match load_identity(rotated) {
        Ok(candidate) => candidate,
        Err(error) => {
            tracing::warn!(%error, path = %rotated.display(), "rotated identity unusable; using original");
            return base;
        }
    };

    let Some(claims) = claims(candidate.token.expose()) else {
        tracing::warn!(path = %rotated.display(), "rotated identity has unreadable claims; using original");
        return base;
    };
    let Some(exp) = numeric_claim(&claims, "exp") else {
        tracing::warn!(path = %rotated.display(), "rotated identity has no expiry; using original");
        return base;
    };
    if exp <= now_seconds() {
        tracing::warn!(path = %rotated.display(), "rotated identity expired; using original");
        return base;
    }
    if candidate.host_id != base.host_id {
        tracing::warn!(
            path = %rotated.display(),
            expected_host = %base.host_id,
            rotated_host = %candidate.host_id,
            "rotated identity host mismatch; using original"
        );
        return base;
    }

    Identity {
        host_id: base.host_id,
        token: candidate.token,
        hub: base.hub,
    }
}

#[must_use = "the returned identity includes any applicable persisted rotation state"]
pub fn load_effective_identity(identity_path: &Path, base: Identity) -> Identity {
    let Some(rotated) = rotated_path(identity_path) else {
        return base;
    };
    if !rotated.exists() {
        return base;
    }
    load_effective_identity_from(&rotated, base)
}

#[derive(Serialize)]
struct RotatedIdentity<'a> {
    host_id: &'a str,
    token: &'a str,
    hub: &'a str,
}

fn persist_rotated_to(
    path: &Path,
    host_id: &str,
    token: &str,
    hub: &str,
) -> Result<(), RotationError> {
    path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "rotated identity has no parent",
        )
    })?;
    let bytes = serde_json::to_vec(&RotatedIdentity {
        host_id,
        token,
        hub,
    })?;

    #[cfg(unix)]
    let mut options = AtomicOpenOptions::new();
    #[cfg(windows)]
    let options = AtomicOpenOptions::new();
    #[cfg(unix)]
    {
        options.preserve_mode(false).try_preserve_owner(false);
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.commit()?;

    Ok(())
}

/// # Errors
/// Returns an error when credential rotation is required but cannot be completed safely.
pub(crate) async fn maybe_rotate(
    client: &wreq::Client,
    config: &RotationConfig,
    token: &AuthToken,
) -> Result<bool, RotationError> {
    if !should_rotate(token) {
        return Ok(false);
    }

    let Some(path) = rotated_path(&config.identity_path) else {
        tracing::warn!("credential rotation disabled: no writable identity state directory");
        return Ok(false);
    };

    let url = format!(
        "{}/agent/rotate",
        config.hub_http_base.trim_end_matches('/')
    );
    let response = client
        .post(url)
        .bearer_auth(token.expose())
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(RotationError::Status(response.status()));
    }
    let body = sentinel0_transport::read_bounded(response, 64 * 1024).await?;
    let body: Value = serde_json::from_slice(&body)?;
    let credential = body
        .get("credential")
        .and_then(Value::as_str)
        .filter(|value| {
            let mut parts = value.split('.');
            matches!(
                (parts.next(), parts.next(), parts.next(), parts.next()),
                (Some(a), Some(b), Some(c), None)
                    if !a.is_empty() && !b.is_empty() && !c.is_empty()
            )
        })
        .ok_or(RotationError::InvalidCredential)?;

    persist_rotated_to(&path, &config.host_id, credential, &config.persisted_hub)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TestResult, TestValue as _};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn token(exp_offset: i64, iat_offset: Option<i64>) -> TestResult<String> {
        let now = UtcDateTime::now().unix_timestamp();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let mut claims = serde_json::json!({"exp": now + exp_offset});
        if let Some(iat_offset) = iat_offset {
            claims["iat"] = Value::from(now + iat_offset);
        }
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).test_value()?);
        Ok(format!("{header}.{payload}.sig"))
    }

    fn identity(host_id: &str, token: String) -> Identity {
        Identity {
            host_id: host_id.into(),
            token: AuthToken::new(token),
            hub: "https://hub.example".into(),
        }
    }

    #[test]
    fn rotates_past_half_life() -> TestResult {
        assert!(should_rotate(&AuthToken::new(token(
            100 * 86_400,
            Some(-300 * 86_400)
        )?)));
        assert!(!should_rotate(&AuthToken::new(token(
            300 * 86_400,
            Some(-60 * 86_400)
        )?)));

        Ok(())
    }

    #[test]
    fn legacy_token_rotates_near_expiry() -> TestResult {
        assert!(should_rotate(&AuthToken::new(token(100 * 86_400, None)?)));
        assert!(!should_rotate(&AuthToken::new(token(300 * 86_400, None)?)));
        assert!(!should_rotate(&AuthToken::new("not-a-jwt")));

        Ok(())
    }

    #[test]
    fn persisted_rotated_identity_is_preferred() -> TestResult {
        let dir = tempdir().test_value()?;
        let path = dir.path().join(ROTATED_NAME);
        let new = token(360 * 86_400, Some(0))?;
        persist_rotated_to(&path, "h1", &new, "https://hub.example").test_value()?;

        let effective =
            load_effective_identity_from(&path, identity("h1", token(300 * 86_400, None)?));
        assert_eq!(effective.token.expose(), new);
        assert_eq!(effective.hub, "https://hub.example");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).test_value()?.permissions().mode() & 0o777,
            0o600
        );
        let entries = fs::read_dir(dir.path())
            .test_value()?
            .collect::<Result<Vec<_>, _>>()
            .test_value()?;
        assert!(
            entries
                .iter()
                .all(|entry| !entry.file_name().to_string_lossy().starts_with(".idrot-"))
        );

        Ok(())
    }

    #[test]
    fn corrupt_expired_or_wrong_host_rotated_identity_falls_back() -> TestResult {
        let dir = tempdir().test_value()?;
        let path = dir.path().join(ROTATED_NAME);
        let original = token(300 * 86_400, None)?;

        fs::write(&path, "{broken").test_value()?;
        assert_eq!(
            load_effective_identity_from(&path, identity("h1", original.clone()))
                .token
                .expose(),
            original
        );

        persist_rotated_to(
            &path,
            "h1",
            &token(-10, Some(-360 * 86_400))?,
            "https://hub.example",
        )
        .test_value()?;
        assert_eq!(
            load_effective_identity_from(&path, identity("h1", original.clone()))
                .token
                .expose(),
            original
        );

        persist_rotated_to(
            &path,
            "OTHER",
            &token(300 * 86_400, None)?,
            "https://hub.example",
        )
        .test_value()?;
        assert_eq!(
            load_effective_identity_from(&path, identity("h1", original.clone()))
                .token
                .expose(),
            original
        );

        Ok(())
    }
}
