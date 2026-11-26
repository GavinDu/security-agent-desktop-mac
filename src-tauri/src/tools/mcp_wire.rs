//! Bounded newline-delimited MCP JSON-RPC wire boundary. This is not a
//! complete MCP client: initialization, notifications, subprocess ownership,
//! transport negotiation and registry authorization are separate work.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{fmt, io, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_FRAME: usize = 64 * 1024;
const MAX_DEPTH: usize = 24;
const MAX_NODES: usize = 4096;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum WireError {
    #[error("MCP wire session unavailable")]
    Closed,
    #[error("MCP frame exceeds limit")]
    Oversize,
    #[error("Invalid MCP JSON-RPC message")]
    Invalid,
    #[error("MCP request deadline exceeded")]
    Timeout,
    #[error("MCP server returned an error")]
    Remote,
    #[error("MCP transport unavailable")]
    Transport,
}

// A failed or canceled exchange poisons this connection. Never consume a
// late reply as a new response. A future lifecycle owner must close/reap it.
pub(crate) struct WireSession<R, W> {
    reader: BufReader<R>,
    writer: W,
    next_id: u64,
    unusable: bool,
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> WireSession<R, W> {
    pub(crate) fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            next_id: 1,
            unusable: false,
        }
    }

    pub(crate) async fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, WireError> {
        self.request_with_deadline(method, params, DEADLINE).await
    }

    async fn request_with_deadline(
        &mut self,
        method: &str,
        params: Value,
        deadline: Duration,
    ) -> Result<Value, WireError> {
        if self.unusable {
            return Err(WireError::Closed);
        }
        if !matches!(method, "initialize" | "tools/list" | "tools/call" | "ping")
            || !params.is_object()
        {
            return Err(WireError::Invalid);
        }
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(WireError::Closed)?;
        let frame = encode(&Value::Object(Map::from_iter([
            ("jsonrpc".into(), Value::String("2.0".into())),
            ("id".into(), Value::Number(id.into())),
            ("method".into(), Value::String(method.into())),
            ("params".into(), params),
        ])))?;
        // Set before the first await, so cancellation leaves it unusable.
        self.unusable = true;
        let result = tokio::time::timeout(deadline, async {
            self.writer
                .write_all(&frame)
                .await
                .map_err(|_| WireError::Transport)?;
            self.writer
                .flush()
                .await
                .map_err(|_| WireError::Transport)?;
            let bytes = read_frame(&mut self.reader).await?;
            parse_response(&bytes, id)
        })
        .await
        .unwrap_or(Err(WireError::Timeout));
        if result.is_ok() || result == Err(WireError::Remote) {
            self.unusable = false;
        }
        result
    }
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<Vec<u8>, WireError> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|_| WireError::Transport)?;
        if available.is_empty() {
            return Err(if frame.is_empty() {
                WireError::Closed
            } else {
                WireError::Invalid
            });
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.unwrap_or(available.len());
        if take > MAX_FRAME.saturating_sub(frame.len()) {
            return Err(WireError::Oversize);
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            if frame.is_empty() || frame.contains(&b'\r') {
                return Err(WireError::Invalid);
            }
            return Ok(frame);
        }
    }
}

struct BoundedWriter(Vec<u8>);

impl io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_FRAME.saturating_sub(self.0.len()) {
            return Err(io::Error::other("MCP frame limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode(value: &Value) -> Result<Vec<u8>, WireError> {
    // Validate shape before serialization (including trusted outbound values).
    let mut nodes = MAX_NODES;
    if !bounded_shape(value, 0, &mut nodes) {
        return Err(WireError::Oversize);
    }
    let mut writer = BoundedWriter(Vec::new());
    serde_json::to_writer(&mut writer, value).map_err(|_| WireError::Oversize)?;
    writer.0.push(b'\n');
    Ok(writer.0)
}

fn bounded_shape(value: &Value, depth: usize, nodes: &mut usize) -> bool {
    if depth > MAX_DEPTH || *nodes == 0 {
        return false;
    }
    *nodes -= 1;
    match value {
        Value::Object(map) => map
            .iter()
            .all(|(key, child)| key.len() <= MAX_FRAME && bounded_shape(child, depth + 1, nodes)),
        Value::Array(items) => items
            .iter()
            .all(|child| bounded_shape(child, depth + 1, nodes)),
        Value::String(text) => text.len() <= MAX_FRAME,
        _ => true,
    }
}

// Deserialize with duplicate-key rejection at every level, including escaped
// spellings of the same key. Reject excessive depth/node count before building
// a Value tree. serde_json's default Value would silently keep the last key.
struct Strict<'a> {
    depth: usize,
    nodes: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.depth > MAX_DEPTH || *self.nodes == 0 {
            return Err(de::Error::custom("MCP JSON shape limit"));
        }
        *self.nodes -= 1;
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded unique-key JSON")
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
            .ok_or_else(|| E::custom("invalid number"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Strict {
            depth: self.depth + 1,
            nodes: &mut *self.nodes,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate MCP JSON key"));
            }
            let value = map.next_value_seed(Strict {
                depth: self.depth + 1,
                nodes: &mut *self.nodes,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn parse_response(bytes: &[u8], id: u64) -> Result<Value, WireError> {
    if bytes.len() > MAX_FRAME {
        return Err(WireError::Oversize);
    }
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err(WireError::Invalid);
    }
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let mut nodes = MAX_NODES;
    let value = Strict {
        depth: 0,
        nodes: &mut nodes,
    }
    .deserialize(&mut parser)
    .map_err(|_| WireError::Invalid)?;
    parser.end().map_err(|_| WireError::Invalid)?;
    let mut map = match value {
        Value::Object(map) => map,
        _ => return Err(WireError::Invalid),
    };
    if map.remove("jsonrpc").as_ref().and_then(Value::as_str) != Some("2.0")
        || map.remove("id").as_ref().and_then(Value::as_u64) != Some(id)
        || map.len() != 1
    {
        return Err(WireError::Invalid);
    }
    if let Some(result) = map.remove("result") {
        return Ok(result);
    }
    let error = map.remove("error").ok_or(WireError::Invalid)?;
    let error = error.as_object().ok_or(WireError::Invalid)?;
    if error.get("code").and_then(Value::as_i64).is_none()
        || error.get("message").and_then(Value::as_str).is_none()
        || error
            .keys()
            .any(|key| !matches!(key.as_str(), "code" | "message" | "data"))
    {
        return Err(WireError::Invalid);
    }
    // Remote message/data can contain secrets or malicious instructions.
    Err(WireError::Remote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::io::{duplex, split};

    #[test]
    fn duplicate_keys_and_wrong_response_identity_never_normalize() {
        for bytes in [
            br#"{"jsonrpc":"2.0","id":1,"id":1,"result":{}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"x":1,"\u0078":2}}"#,
            br#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
            br#"{"jsonrpc":"2.0","id":"1","result":{}}"#,
            br#"{"jsonrpc":"2.0","id":1.0,"result":{}}"#,
            br#"{"jsonrpc":"2.0","id":1,"result":{},"error":{}}"#,
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":"bad","message":"secret"}}"#,
            br#"{"jsonrpc":"2.0","id":1,"result":{}} {}"#,
            br#"[{"jsonrpc":"2.0","id":1,"result":{}}]"#,
        ] {
            assert_eq!(parse_response(bytes, 1), Err(WireError::Invalid));
        }
        assert_eq!(
            parse_response(br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#, 1),
            Ok(json!({"tools":[]}))
        );
        assert_eq!(
            parse_response(
                br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"PRIVATE"}}"#,
                1
            ),
            Err(WireError::Remote)
        );
    }

    #[test]
    fn raw_and_structural_limits_are_independent() {
        let oversize = vec![b'x'; MAX_FRAME + 1];
        assert_eq!(parse_response(&oversize, 1), Err(WireError::Oversize));
        let deep = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}null{}}}",
            "[".repeat(MAX_DEPTH + 1),
            "]".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(parse_response(deep.as_bytes(), 1), Err(WireError::Invalid));
        let nodes = json!({"jsonrpc":"2.0","id":1,"result":vec![0;MAX_NODES]});
        assert_eq!(
            parse_response(&serde_json::to_vec(&nodes).unwrap(), 1),
            Err(WireError::Invalid)
        );
        assert_eq!(
            encode(&json!("x".repeat(MAX_FRAME))),
            Err(WireError::Oversize)
        );
    }

    #[tokio::test]
    async fn newline_framing_rejects_partial_and_overlong_and_retains_next_frame() {
        let mut reader = BufReader::new(&b"first\nsecond\npartial"[..]);
        assert_eq!(read_frame(&mut reader).await.unwrap(), b"first");
        assert_eq!(read_frame(&mut reader).await.unwrap(), b"second");
        assert_eq!(read_frame(&mut reader).await, Err(WireError::Invalid));
        let mut bytes = vec![b'x'; MAX_FRAME + 1];
        bytes.push(b'\n');
        assert_eq!(
            read_frame(&mut BufReader::new(bytes.as_slice())).await,
            Err(WireError::Oversize)
        );
    }

    #[tokio::test]
    async fn actual_duplex_exchange_and_late_reply_fence() {
        let (client, server) = duplex(4096);
        let (r, w) = split(client);
        let mut session = WireSession::new(r, w);
        let task = tokio::spawn(async move {
            let (r, mut w) = split(server);
            let mut reader = BufReader::new(r);
            let frame = read_frame(&mut reader).await.unwrap();
            let request: Value = serde_json::from_slice(&frame).unwrap();
            assert_eq!(request["id"], 1);
            assert_eq!(request["method"], "tools/list");
            w.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n")
                .await
                .unwrap();
            let _ = read_frame(&mut reader).await.unwrap();
            std::future::pending::<()>().await;
        });
        assert_eq!(
            session.request("tools/list", json!({})).await,
            Ok(json!({"tools":[]}))
        );
        assert_eq!(
            session
                .request_with_deadline("ping", json!({}), Duration::from_millis(5))
                .await,
            Err(WireError::Timeout)
        );
        assert_eq!(
            session.request("ping", json!({})).await,
            Err(WireError::Closed)
        );
        task.abort();
    }
}
