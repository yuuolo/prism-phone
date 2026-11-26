//! Bound the expanded document during deserialization, before YAML aliases can
//! multiply a small source into a large allocation outside the JS heap quota.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

const MAX_NODES: usize = 131_072;
const MAX_DEPTH: usize = 64;

struct Budget {
    nodes: usize,
    bytes: usize,
}
impl Budget {
    fn node<E: de::Error>(&mut self) -> Result<(), E> {
        self.nodes = self
            .nodes
            .checked_sub(1)
            .ok_or_else(|| E::custom("document node limit"))?;
        Ok(())
    }
    fn text<E: de::Error>(&mut self, len: usize) -> Result<(), E> {
        self.bytes = self
            .bytes
            .checked_sub(len)
            .ok_or_else(|| E::custom("document expansion limit"))?;
        Ok(())
    }
}
struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH {
            return Err(de::Error::custom("document depth limit"));
        }
        self.budget.node()?;
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a bounded configuration value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        self.budget.text(v.len())?;
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        self.budget.text(v.len())?;
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Seed {
            budget: &mut *self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            self.budget.node()?;
            self.budget.text(key.len())?;
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate configuration key"));
            }
            let value = map.next_value_seed(Seed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

pub fn parse(source: &str) -> anyhow::Result<Value> {
    anyhow::ensure!(
        source.len() <= crate::script::MAX_CONFIG,
        "配置超过大小限制"
    );
    let mut documents = serde_yaml::Deserializer::from_str(source);
    let first = documents
        .next()
        .ok_or_else(|| anyhow::anyhow!("配置不能为空"))?;
    let mut budget = Budget {
        nodes: MAX_NODES,
        bytes: crate::script::MAX_CONFIG,
    };
    let value = Seed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(first)
    .map_err(|_| anyhow::anyhow!("配置 YAML/JSON 无效或展开后超过资源限制"))?;
    anyhow::ensure!(documents.next().is_none(), "每个配置只能包含一个 YAML 文档");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_aliases_work_but_expanded_size_is_bounded() {
        let value =
            parse("template: &node {name: edge, server: example.com}\nproxies: [*node]\n").unwrap();
        assert_eq!(value["proxies"][0], value["template"]);
        let source = format!(
            "template: &data '{}'\nexpanded: [{}]\n",
            "x".repeat(32768),
            vec!["*data"; 256].join(",")
        );
        assert!(source.len() < 65536);
        assert!(parse(&source).is_err());
    }
    #[test]
    fn depth_nodes_duplicates_multiple_documents_and_nonfinite_numbers_are_rejected() {
        let deep = format!("{}0{}", "[".repeat(80), "]".repeat(80));
        assert!(parse(&deep).is_err());
        let many = format!("[{}]", vec!["0"; MAX_NODES + 1].join(","));
        assert!(parse(&many).is_err());
        for source in [
            "rules: []\nrules: ['MATCH,DIRECT']",
            "---\na: 1\n---\na: 2",
            "value: .nan",
            "value: .inf",
            "value: -.inf",
        ] {
            assert!(parse(source).is_err());
        }
    }
}
