use serde::de::Error;
use serde::{Deserialize, Deserializer};

#[derive(Clone, Debug)]
pub enum DataSize {
    WithUnit(usize, String),
    WithoutUnit(usize),
}

impl DataSize {
    pub fn to_usize(&self) -> usize {
        match self {
            Self::WithUnit(size, unit) => match unit.as_str() {
                "K" | "KB" => size * 1000,
                "M" | "MB" => size * 1000 * 1000,
                "G" | "GB" => size * 1000 * 1000 * 1000,
                "KI" | "KIB" => size * 1024,
                "MI" | "MIB" => size * 1024 * 1024,
                "GI" | "GIB" => size * 1024 * 1024 * 1024,
                _ => *size,
            },
            Self::WithoutUnit(size) => *size,
        }
    }

    pub fn to_u64(&self) -> u64 {
        self.to_usize() as u64
    }
}

// StorageSize is serialized as a string with an optional unit (e.g. "10MB") or as a raw number.
impl<'de> Deserialize<'de> for DataSize {
    fn deserialize<D>(deserializer: D) -> Result<DataSize, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let parsed = if let Ok(size) = s.parse::<usize>() {
            Self::WithoutUnit(size)
        } else {
            let size = s
                .trim_end_matches(|c: char| c.is_alphabetic())
                .parse::<usize>()
                .unwrap_or_default();
            let unit = s
                .trim_start_matches(|c: char| c.is_numeric())
                .to_uppercase();

            if unit.is_empty() {
                Self::WithoutUnit(size)
            } else {
                if ![
                    "K", "KB", "M", "MB", "G", "GB", "KI", "KIB", "MI", "MIB", "GI", "GIB",
                ]
                .contains(&unit.as_str())
                {
                    return Err(Error::custom(format!("Invalid unit: {unit}")));
                }

                Self::WithUnit(size, unit)
            }
        };

        Ok(parsed)
    }
}
