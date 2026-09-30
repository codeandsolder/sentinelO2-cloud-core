use crate::{
    AuthToken,
    identity::{Identity, load_identity},
};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use nix::unistd::{AccessFlags, access};
use num_traits::ToPrimitive;
use serde::Serialize;
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

const ROTATED_NAME: &str = "identity.rotated.json";
const SYSTEM_STATE_DIR: &str = "/var/lib/sentinelx";
const LEGACY_HALF_LIFE_SECONDS: f64 = 182.0 * 86_400.0;

#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub identity_path: PathBuf,
    pub host_id: String,
    pub hub_http_base: String,
    pub persisted_hub: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RotationError {
    #[error("rotate request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("rotate response JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rotate response did not contain a well-formed credential")]
    InvalidCredential,
    #[error("could not persist rotated credential: {0}")]
    Persist(#[from] std::io::Error),
}

fn directory_is_writable(path: &Path) -> bool {
    path.is_dir() && access(path, AccessFlags::W_OK).is_ok()
}

fn rotated_path(identity_path: &Path) -> Option<PathBuf> {
    let system = Path::new(SYSTEM_STATE_DIR);
    if directory_is_writable(system) {
        return Some(system.join(ROTATED_NAME));
    }

    let parent = identity_path.parent()?;
    directory_is_writable(parent).then(|| parent.join(ROTATED_NAME))
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
    chrono::Utc::now()
        .timestamp_millis()
        .to_f64()
        .unwrap_or(f64::MAX)
        / 1000.0
}

#[must_use]
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

#[must_use]
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
    let parent = path.parent().ok_or_else(|| {
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
    let temp = parent.join(format!(
        ".idrot-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));

    let write_result = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        if let Err(error) = fs::File::open(parent).and_then(|directory| directory.sync_all()) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "rotated credential was committed, but parent-directory fsync failed; crash durability is not guaranteed"
            );
        }
        Ok(())
    })();

    if let Err(error) = write_result {
        if let Err(cleanup) = fs::remove_file(&temp)
            && cleanup.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %temp.display(),
                %cleanup,
                "failed cleaning credential-rotation temp file"
            );
        }
        return Err(error.into());
    }
    Ok(())
}

/// # Errors
/// Returns an error when credential rotation is required but cannot be completed safely.
pub async fn maybe_rotate(
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

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let url = format!(
        "{}/agent/rotate",
        config.hub_http_base.trim_end_matches('/')
    );
    let response = client
        .post(url)
        .bearer_auth(token.expose())
        .send()
        .await?
        .error_for_status()?;
    let body: Value = serde_json::from_str(&response.text().await?)?;
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
    use crate::test_support::{TestError as _, TestResult, TestValue as _};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn token(exp_offset: i64, iat_offset: Option<i64>) -> String {
        let now = chrono::Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#);
        let mut claims = serde_json::json!({"exp": now + exp_offset});
        if let Some(iat_offset) = iat_offset {
            claims["iat"] = Value::from(now + iat_offset);
        }
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("{header}.{payload}.sig")
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
        ))));
        assert!(!should_rotate(&AuthToken::new(token(
            300 * 86_400,
            Some(-60 * 86_400)
        ))));

        Ok(())
    }

    #[test]
    fn legacy_token_rotates_near_expiry() -> TestResult {
        assert!(should_rotate(&AuthToken::new(token(100 * 86_400, None))));
        assert!(!should_rotate(&AuthToken::new(token(300 * 86_400, None))));
        assert!(!should_rotate(&AuthToken::new("not-a-jwt")));

        Ok(())
    }

    #[test]
    fn persisted_rotated_identity_is_preferred() -> TestResult {
        let dir = tempdir().test_value()?;
        let path = dir.path().join(ROTATED_NAME);
        let new = token(360 * 86_400, Some(0));
        persist_rotated_to(&path, "h1", &new, "https://hub.example").test_value()?;

        let effective =
            load_effective_identity_from(&path, identity("h1", token(300 * 86_400, None)));
        assert_eq!(effective.token.expose(), new);
        assert_eq!(effective.hub, "https://hub.example");
        assert_eq!(
            fs::metadata(&path).test_value()?.permissions().mode() & 0o777,
            0o600
        );
        assert!(fs::read_dir(dir.path()).test_value()?.all(|entry| {
            !entry
                .test_value()?
                .file_name()
                .to_string_lossy()
                .starts_with(".idrot-")
        }));

        Ok(())
    }

    #[test]
    fn corrupt_expired_or_wrong_host_rotated_identity_falls_back() -> TestResult {
        let dir = tempdir().test_value()?;
        let path = dir.path().join(ROTATED_NAME);
        let original = token(300 * 86_400, None);

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
            &token(-10, Some(-360 * 86_400)),
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
            &token(300 * 86_400, None),
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
