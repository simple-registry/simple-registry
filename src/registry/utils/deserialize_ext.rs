use regex::Captures;
use serde::de::{DeserializeSeed, Error, IntoDeserializer, MapAccess, Visitor};
use serde::{de, Deserialize};

pub trait DeserializeExt {
    fn from_regex(content: &str, regex: &regex::Regex) -> Option<Self>
    where
        Self: Sized;
}

impl<T> DeserializeExt for T
where
    T: for<'a> Deserialize<'a> + Sized,
{
    fn from_regex(content: &str, regex: &regex::Regex) -> Option<Self> {
        let captures = regex.captures(content)?;
        let deserializer = CapturesDeserializer {
            captures: &captures,
        };

        T::deserialize(deserializer).ok()
    }
}

struct CapturesDeserializer<'a> {
    captures: &'a Captures<'a>,
}

impl<'de> serde::Deserializer<'de> for CapturesDeserializer<'_> {
    type Error = de::value::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_map(visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let fields = &[];
        self.deserialize_struct("", fields, visitor)
    }

    fn deserialize_struct<V>(
        self,
        _name: &str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let map_access = CapturesMapAccess {
            captures: self.captures,
            fields,
            field_index: 0,
        };
        visitor.visit_map(map_access)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf option unit unit_struct
        seq tuple tuple_struct enum identifier ignored_any newtype_struct
    }
}

struct CapturesMapAccess<'a> {
    captures: &'a Captures<'a>,
    fields: &'static [&'static str],
    field_index: usize,
}

impl<'de> MapAccess<'de> for CapturesMapAccess<'_> {
    type Error = de::value::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        if self.field_index < self.fields.len() {
            let key = self.fields[self.field_index];
            self.field_index += 1;
            seed.deserialize(key.into_deserializer()).map(Some)
        } else {
            Ok(None)
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let key = self.fields[self.field_index - 1];
        if let Some(value) = self.captures.name(key) {
            seed.deserialize(value.as_str().into_deserializer())
        } else {
            Err(Error::custom(format!(
                "Missing capture group for field '{key}'"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Test {
        foo: String,
        bar: String,
    }

    #[test]
    fn test_deserialize_ext() {
        let regex = Regex::new(r"(?P<foo>\w+) (?P<bar>\w+)").unwrap();
        let content = "hello world";
        let test: Test = Test::from_regex(content, &regex).unwrap();
        assert_eq!(
            test,
            Test {
                foo: "hello".to_string(),
                bar: "world".to_string()
            }
        );
    }
}
