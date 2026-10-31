//! Network-side helpers for local servers: the shared generation slot,
//! discovery on fixed loopback ports and read-only runtime metadata.
//! Nothing here starts, stops or reconfigures a server.
use crate::local::LocalRuntime;
use futures_util::future::join_all;
use reqwest::{StatusCode, Url};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, Weak},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

/// Short deadline for discovery and metadata probes.
pub const PROBE_DEADLINE: Duration = Duration::from_millis(800);

static SLOTS: LazyLock<Mutex<HashMap<u16, Weak<Semaphore>>>> = LazyLock::new(Default::default);

/// One generation at a time per physical loopback server. Every loopback
/// host alias and every path on a port share the slot, across profiles,
/// clones and newly created clients. A permit is released on drop, so a
/// cancelled wait or generation frees it immediately.
pub fn generation_slot(base: &Url) -> Arc<Semaphore> {
    let port = base.port_or_known_default().unwrap_or_default();
    let mut slots = SLOTS.lock().unwrap_or_else(|error| error.into_inner());
    slots.retain(|_, slot| slot.strong_count() > 0);
    if let Some(slot) = slots.get(&port).and_then(Weak::upgrade) {
        return slot;
    }
    let slot = Arc::new(Semaphore::new(1));
    slots.insert(port, Arc::downgrade(&slot));
    slot
}

/// Server-root URL for runtime endpoints that live outside the `/v1` API.
pub fn origin(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    url.set_path(path);
    url
}

/// Read-only endpoint that reports the context actually loaded by the server.
pub fn context_probe_path(runtime: LocalRuntime) -> Option<&'static str> {
    match runtime {
        LocalRuntime::LlamaCpp => Some("/props"),
        LocalRuntime::Ollama => Some("/api/ps"),
        LocalRuntime::Mlx | LocalRuntime::LmStudio | LocalRuntime::OpenAi => None,
    }
}

/// Extracts a loaded context size; any unexpected shape yields `None`.
pub fn parse_context(runtime: LocalRuntime, value: &Value, model: &str) -> Option<u32> {
    let tokens = match runtime {
        LocalRuntime::LlamaCpp => value
            .pointer("/default_generation_settings/n_ctx")
            .or_else(|| value.get("n_ctx"))
            .and_then(Value::as_u64),
        LocalRuntime::Ollama => value
            .get("models")?
            .as_array()?
            .iter()
            .find(|loaded| {
                ["name", "model"].iter().any(|field| {
                    loaded
                        .get(field)
                        .and_then(Value::as_str)
                        .is_some_and(|name| same_ollama_model(name, model))
                })
            })?
            .get("context_length")
            .and_then(Value::as_u64),
        LocalRuntime::Mlx | LocalRuntime::LmStudio | LocalRuntime::OpenAi => None,
    }?;
    u32::try_from(tokens).ok().filter(|tokens| *tokens > 0)
}

fn same_ollama_model(loaded: &str, configured: &str) -> bool {
    let normalize = |name: &str| {
        if name.contains(':') {
            name.to_owned()
        } else {
            format!("{name}:latest")
        }
    };
    normalize(loaded) == normalize(configured)
}

/// Embedding and reranking models cannot run a chat agent.
pub fn is_embedding_model(id: &str) -> bool {
    let id = id.to_ascii_lowercase();
    let name = id.rsplit('/').next().unwrap_or(&id);
    name.contains("embed") || name.contains("rerank") || name.starts_with("bge-")
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub base_url: String,
    /// `None` means port 8080: llama.cpp or MLX, decided by the server answer.
    pub runtime: Option<LocalRuntime>,
}

/// Fixed literal-IP candidates; no LAN, hostnames or port scans.
pub fn default_candidates() -> Vec<Candidate> {
    [
        ("http://127.0.0.1:11434/v1", Some(LocalRuntime::Ollama)),
        ("http://127.0.0.1:8080/v1", None),
        ("http://127.0.0.1:1234/v1", Some(LocalRuntime::LmStudio)),
    ]
    .into_iter()
    .map(|(base_url, runtime)| Candidate {
        base_url: base_url.into(),
        runtime,
    })
    .collect()
}

#[derive(Clone, Debug, Serialize)]
pub struct Discovered {
    pub base_url: String,
    pub runtime: LocalRuntime,
    pub auth_required: bool,
    pub models: Vec<String>,
}

/// Unauthenticated `GET /models` on each candidate within one shared deadline.
pub async fn discover(candidates: &[Candidate], deadline: Duration) -> Vec<Discovered> {
    let Ok(client) = crate::provider::local_http_client() else {
        return Vec::new();
    };
    let end = Instant::now() + deadline;
    let probes = candidates.iter().map(|candidate| {
        let client = client.clone();
        async move {
            let remaining = end.saturating_duration_since(Instant::now());
            tokio::time::timeout(remaining, probe(&client, candidate, end))
                .await
                .ok()
                .flatten()
        }
    });
    join_all(probes).await.into_iter().flatten().collect()
}

async fn probe(
    client: &reqwest::Client,
    candidate: &Candidate,
    end: Instant,
) -> Option<Discovered> {
    let base = crate::local::validate_local_endpoint(&candidate.base_url).ok()?;
    let mut models_url = base.clone();
    models_url.set_path(&format!("{}/models", base.path().trim_end_matches('/')));
    let response = client
        .get(models_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .ok()?;
    let status = response.status();
    let auth_required = matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN);
    let (models, owned_by_llamacpp) = if status.is_success() {
        let value: Value = serde_json::from_slice(&bounded_body(response).await?).ok()?;
        let entries = value.get("data")?.as_array()?;
        let owned_by_llamacpp = entries
            .iter()
            .any(|model| model.get("owned_by").and_then(Value::as_str) == Some("llamacpp"));
        let models = entries
            .iter()
            .filter_map(|model| model.get("id").and_then(Value::as_str))
            .filter(|id| !id.is_empty() && !id.chars().any(char::is_control))
            .filter(|id| !is_embedding_model(id))
            .take(256)
            .map(str::to_owned)
            .collect();
        (models, owned_by_llamacpp)
    } else if auth_required {
        (Vec::new(), false)
    } else {
        return None;
    };
    let runtime = match candidate.runtime {
        Some(runtime) => runtime,
        None if owned_by_llamacpp => LocalRuntime::LlamaCpp,
        None => guess_llamacpp_or_mlx(client, &base, end).await,
    };
    Some(Discovered {
        base_url: candidate.base_url.clone(),
        runtime,
        auth_required,
        models,
    })
}

/// llama.cpp answers `GET /props` with its server properties; MLX servers do not.
async fn guess_llamacpp_or_mlx(client: &reqwest::Client, base: &Url, end: Instant) -> LocalRuntime {
    let remaining = end.saturating_duration_since(Instant::now());
    let request = client.get(origin(base, "/props")).send();
    let Ok(Ok(response)) = tokio::time::timeout(remaining, request).await else {
        return LocalRuntime::Mlx;
    };
    if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return LocalRuntime::LlamaCpp;
    }
    if !response.status().is_success() {
        return LocalRuntime::Mlx;
    }
    let Some(body) = bounded_body(response).await else {
        return LocalRuntime::Mlx;
    };
    let is_llamacpp = serde_json::from_slice::<Value>(&body).is_ok_and(|value| {
        [
            "default_generation_settings",
            "total_slots",
            "chat_template",
            "build_info",
        ]
        .iter()
        .any(|key| value.get(key).is_some())
    });
    if is_llamacpp {
        LocalRuntime::LlamaCpp
    } else {
        LocalRuntime::Mlx
    }
}

async fn bounded_body(response: reqwest::Response) -> Option<Vec<u8>> {
    const LIMIT: usize = 1024 * 1024;
    if response
        .content_length()
        .is_some_and(|length| length > LIMIT as u64)
    {
        return None;
    }
    let bytes = response.bytes().await.ok()?;
    (bytes.len() <= LIMIT).then(|| bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn localhost_and_ip_aliases_and_paths_share_one_slot_per_port() {
        let first = generation_slot(&Url::parse("http://127.0.0.1:47811/v1").unwrap());
        for alias in [
            "http://localhost:47811/v1",
            "http://[::1]:47811/",
            "http://127.0.0.1:47811/api/v1",
        ] {
            let slot = generation_slot(&Url::parse(alias).unwrap());
            assert!(Arc::ptr_eq(&first, &slot), "{alias}");
        }
        let other = generation_slot(&Url::parse("http://127.0.0.1:47812/v1").unwrap());
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(first.available_permits(), 1);
    }

    #[test]
    fn context_probe_llamacpp_props() {
        let props = json!({"default_generation_settings":{"n_ctx":16384},"total_slots":1});
        assert_eq!(
            parse_context(LocalRuntime::LlamaCpp, &props, "m"),
            Some(16384)
        );
        assert_eq!(
            parse_context(LocalRuntime::LlamaCpp, &json!({"n_ctx":8192}), "m"),
            Some(8192)
        );
        assert_eq!(
            parse_context(LocalRuntime::LlamaCpp, &json!({"x":1}), "m"),
            None
        );
    }

    #[test]
    fn context_probe_ollama_ps_loaded_only() {
        let ps = json!({"models":[
            {"name":"other:7b","model":"other:7b","context_length":2048},
            {"name":"qwen3:latest","model":"qwen3:latest","context_length":8192}
        ]});
        assert_eq!(
            parse_context(LocalRuntime::Ollama, &ps, "qwen3"),
            Some(8192)
        );
        assert_eq!(
            parse_context(LocalRuntime::Ollama, &ps, "qwen3:latest"),
            Some(8192)
        );
        assert_eq!(parse_context(LocalRuntime::Ollama, &ps, "llama3:8b"), None);
        assert_eq!(
            parse_context(
                LocalRuntime::Ollama,
                &json!({"models":[{"name":"qwen3"}]}),
                "qwen3"
            ),
            None,
            "older servers without context_length"
        );
    }

    #[test]
    fn context_probe_unknown_returns_none() {
        for runtime in [
            LocalRuntime::Mlx,
            LocalRuntime::LmStudio,
            LocalRuntime::OpenAi,
        ] {
            assert!(context_probe_path(runtime).is_none());
            assert_eq!(parse_context(runtime, &json!({"n_ctx":4096}), "m"), None);
        }
        assert_eq!(
            parse_context(LocalRuntime::LlamaCpp, &json!({"n_ctx":0}), "m"),
            None
        );
    }

    #[test]
    fn embedding_models_filtered() {
        for id in [
            "nomic-embed-text",
            "text-embedding-3-small",
            "org/bge-m3",
            "qwen3-reranker",
        ] {
            assert!(is_embedding_model(id), "{id}");
        }
        for id in [
            "qwen3:8b",
            "llama-3.1-8b-instruct",
            "mlx-community/Qwen3-4B",
        ] {
            assert!(!is_embedding_model(id), "{id}");
        }
    }
}
