//! Strict JSON observations: duplicate keys, deep trees and trailing data fail.
use anyhow::{Result, ensure};
use serde::{
    Deserializer,
    de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::{cell::Cell, fmt};

struct Seed<'a> {
    depth: usize,
    nodes: &'a Cell<usize>,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<Value, D::Error> {
        if self.depth > 32 || self.nodes.get() >= 65_536 {
            return Err(D::Error::custom("JSON complexity limit"));
        }
        self.nodes.set(self.nodes.get() + 1);
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: Error>(self, v: f64) -> std::result::Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E: Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = a.next_element_seed(Seed {
            depth: self.depth + 1,
            nodes: self.nodes,
        })? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if k.len() > 4096 || out.contains_key(&k) {
                return Err(A::Error::custom("duplicate or oversized key"));
            }
            let v = a.next_value_seed(Seed {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}
pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() <= 2 * 1024 * 1024, "JSON превышает 2 МиБ");
    let nodes = Cell::new(0);
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let v = Seed {
        depth: 0,
        nodes: &nodes,
    }
    .deserialize(&mut d)
    .map_err(|_| anyhow::anyhow!("Некорректный JSON: структура, duplicate key или лимит"))?;
    d.end().map_err(|_| anyhow::anyhow!("Данные после JSON"))?;
    Ok(v)
}
