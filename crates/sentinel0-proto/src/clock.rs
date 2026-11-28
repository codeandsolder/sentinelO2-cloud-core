//! UTC wall-clock representation and the protocol's timestamp formatting.
use time::{UtcDateTime, format_description::well_known::Rfc3339};

#[derive(Clone, Copy)]
pub enum UtcSuffix {
    Z,
    Colon,
    Compact,
}

pub fn timestamp(value: UtcDateTime, suffix: UtcSuffix, fractional: bool) -> String {
    let (year, month, day) = (value.year(), u8::from(value.month()), value.day());
    let mut result = format!("{year:04}-{month:02}-{day:02}T{}", clock_time(value));
    let nanos = value.nanosecond();
    if fractional && nanos != 0 {
        use std::fmt::Write as _;
        if nanos.is_multiple_of(1_000_000) {
            let _ = write!(result, ".{:03}", nanos / 1_000_000);
        } else if nanos.is_multiple_of(1_000) {
            let _ = write!(result, ".{:06}", nanos / 1_000);
        } else {
            let _ = write!(result, ".{nanos:09}");
        }
    }
    result.push_str(match suffix {
        UtcSuffix::Z => "Z",
        UtcSuffix::Colon => "+00:00",
        UtcSuffix::Compact => "+0000",
    });
    result
}

pub fn clock_time(value: UtcDateTime) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        value.hour(),
        value.minute(),
        value.second()
    )
}

pub fn backup_stamp(value: UtcDateTime) -> String {
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}.{:06}",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.microsecond()
    )
}

pub fn unix_millis(value: UtcDateTime) -> i64 {
    value.unix_timestamp() * 1_000 + i64::from(value.millisecond())
}

pub fn unix_seconds(value: UtcDateTime) -> f64 {
    (value - UtcDateTime::UNIX_EPOCH).as_seconds_f64()
}

pub fn from_system_time(value: std::time::SystemTime) -> Option<UtcDateTime> {
    let nanos = match value.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).ok()?,
        Err(error) => -i128::try_from(error.duration().as_nanos()).ok()?,
    };
    UtcDateTime::from_unix_timestamp_nanos(nanos).ok()
}

pub(crate) mod wire {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};

    pub fn serialize<S: Serializer>(value: &UtcDateTime, serializer: S) -> Result<S::Ok, S::Error> {
        if !(0..=9999).contains(&value.year()) {
            return Err(S::Error::custom("UTC year outside RFC3339 range"));
        }
        serializer.serialize_str(&timestamp(*value, UtcSuffix::Z, true))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<UtcDateTime, D::Error> {
        UtcDateTime::parse(&String::deserialize(deserializer)?, &Rfc3339).map_err(D::Error::custom)
    }

    pub mod option {
        use super::*;
        pub fn serialize<S: Serializer>(
            value: &Option<UtcDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => {
                    if !(0..=9999).contains(&value.year()) {
                        return Err(S::Error::custom("UTC year outside RFC3339 range"));
                    }
                    serializer.serialize_some(&timestamp(*value, UtcSuffix::Z, true))
                }
                None => serializer.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<UtcDateTime>, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|value| UtcDateTime::parse(&value, &Rfc3339).map_err(D::Error::custom))
                .transpose()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Message;
    use serde_json::json;

    #[test]
    fn wire_timestamps_normalize_offsets_and_keep_fractional_precision()
    -> Result<(), Box<dyn std::error::Error>> {
        for (input, expected) in [
            ("2026-09-21T23:00:00+02:00", "2026-09-21T21:00:00Z"),
            ("2026-09-21T21:00:00.1Z", "2026-09-21T21:00:00.100Z"),
            ("2026-09-21T21:00:00.123400Z", "2026-09-21T21:00:00.123400Z"),
            (
                "2026-09-21T21:00:00.123456789Z",
                "2026-09-21T21:00:00.123456789Z",
            ),
        ] {
            let message: Message =
                serde_json::from_value(json!({"type":"ping","timestamp":input}))?;
            assert_eq!(
                serde_json::to_value(message)?,
                json!({"type":"ping","timestamp":expected})
            );
        }
        let request: Message =
            serde_json::from_value(json!({"type":"request","id":"a","op":"ping","payload":{}}))?;
        assert_eq!(
            serde_json::to_value(request)?["deadline"],
            serde_json::Value::Null
        );
        let invalid = serde_json::from_value::<Message>(
            json!({"type":"ping","timestamp":"2026-02-31T12:00:00Z"}),
        );
        assert!(invalid.is_err());
        Ok(())
    }

    #[test]
    fn negative_epoch_conversion_preserves_floor_milliseconds()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = UtcDateTime::from_unix_timestamp_nanos(-1)?;
        assert_eq!(unix_millis(value), -1);
        assert_eq!(
            timestamp(value, UtcSuffix::Z, true),
            "1969-12-31T23:59:59.999999999Z"
        );
        assert_eq!(
            from_system_time(std::time::UNIX_EPOCH - std::time::Duration::from_nanos(1)),
            Some(value)
        );
        Ok(())
    }
}
