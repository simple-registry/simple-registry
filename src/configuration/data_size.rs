use serde::de::Error;
use serde::{Deserialize, Deserializer};

#[derive(Clone, Debug, PartialEq)]
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_data_size_deserialization() {
        for unit in &[
            "K", "KB", "M", "MB", "G", "GB", "KI", "KIB", "MI", "MIB", "GI", "GIB",
        ] {
            let size: DataSize = serde_json::from_str(&format!(r#""10{}""#, unit)).unwrap();
            let DataSize::WithUnit(quantity, u) = size else {
                panic!("Expected DataSize::WithUnit, got {:?}", size);
            };
            assert_eq!(quantity, 10);
            assert_eq!(u, unit.to_string());
        }
    }

    #[test]
    fn test_data_size_deserialization_without_unit() {
        let size: DataSize = serde_json::from_str(r#""10""#).unwrap();
        let DataSize::WithoutUnit(quantity) = size else {
            panic!("Expected DataSize::WithoutUnit, got {:?}", size);
        };
        assert_eq!(quantity, 10);
    }

    #[test]
    fn test_data_size_to_usize() {
        let size = DataSize::WithUnit(10, "KB".to_string());
        assert_eq!(size.to_usize(), 10 * 1000);

        let size = DataSize::WithUnit(10, "MB".to_string());
        assert_eq!(size.to_usize(), 10 * 1000 * 1000);

        let size = DataSize::WithUnit(10, "GB".to_string());
        assert_eq!(size.to_usize(), 10 * 1000 * 1000 * 1000);

        let size = DataSize::WithUnit(10, "KIB".to_string());
        assert_eq!(size.to_usize(), 10 * 1024);

        let size = DataSize::WithUnit(10, "MIB".to_string());
        assert_eq!(size.to_usize(), 10 * 1024 * 1024);

        let size = DataSize::WithUnit(10, "GIB".to_string());
        assert_eq!(size.to_usize(), 10 * 1024 * 1024 * 1024);

        let size = DataSize::WithoutUnit(10);
        assert_eq!(size.to_usize(), 10);
    }
}
