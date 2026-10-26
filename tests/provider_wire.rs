use rcode::{
    config::{Effort, ProviderKind, ProviderSettings},
    protocol::{FailureKind, Message, ProviderFailure, ProviderMeta, ToolCall, ToolDefinition},
    provider::ProviderClient,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};

const FIXTURE_TIMEOUT: Duration = Duration::from_secs(8);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(2);

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    pieces: Vec<Vec<u8>>,
    header_delay: Duration,
    delay: Duration,
    pause_after_first: Duration,
}
impl Reply {
    fn json(value: Value) -> Self {
        Self::body(200, "application/json", value.to_string().into_bytes())
    }
    fn body(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            pieces: vec![body],
            header_delay: Duration::ZERO,
            delay: Duration::ZERO,
            pause_after_first: Duration::ZERO,
        }
    }
    fn sse(body: &str) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), "text/event-stream".into())],
            pieces: body.as_bytes().chunks(1).map(|b| b.to_vec()).collect(),
            header_delay: Duration::ZERO,
            delay: Duration::ZERO,
            pause_after_first: Duration::ZERO,
        }
    }
}
#[derive(Debug)]
struct Request {
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}
impl Request {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}
async fn server(replies: Vec<Reply>) -> (String, JoinHandle<Vec<Request>>) {
    server_checking_retries(replies, false).await
}
async fn server_checking_retries(
    replies: Vec<Reply>,
    reject_extra_requests: bool,
) -> (String, JoinHandle<Vec<Request>>) {
    let listener = timeout(SOCKET_TIMEOUT, TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("fixture bind timed out")
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        timeout(FIXTURE_TIMEOUT, async move {
            let mut requests = vec![];
            for reply in replies {
                let (mut socket, _) = timeout(FIXTURE_TIMEOUT, listener.accept())
                    .await
                    .expect("fixture accept timed out")
                    .unwrap();
                let mut bytes = vec![];
                let end = loop {
                    let mut buf = [0; 1024];
                    let count = timeout(SOCKET_TIMEOUT, socket.read(&mut buf))
                        .await
                        .expect("fixture request read timed out")
                        .unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buf[..count]);
                    if let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let header = String::from_utf8(bytes[..end].to_vec()).unwrap();
                let mut lines = header.lines();
                let path = lines
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .to_owned();
                let headers: BTreeMap<_, _> = lines
                    .filter_map(|line| line.split_once(':'))
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
                    .collect();
                let length = headers
                    .get("content-length")
                    .map(|s| s.parse::<usize>().unwrap())
                    .unwrap_or(0);
                while bytes.len() < end + length {
                    let mut buf = [0; 1024];
                    let count = timeout(SOCKET_TIMEOUT, socket.read(&mut buf))
                        .await
                        .expect("fixture request read timed out")
                        .unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buf[..count]);
                }
                requests.push(Request {
                    path,
                    headers,
                    body: bytes[end..end + length].to_vec(),
                });
                let length: usize = reply.pieces.iter().map(Vec::len).sum();
                let mut header = format!(
                    "HTTP/1.1 {} fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status, length
                );
                for (key, value) in reply.headers {
                    header.push_str(&format!("{key}: {value}\r\n"));
                }
                header.push_str("\r\n");
                tokio::time::sleep(reply.header_delay).await;
                if timeout(SOCKET_TIMEOUT, socket.write_all(header.as_bytes()))
                    .await
                    .expect("fixture response headers write timed out")
                    .is_err()
                {
                    continue;
                }
                for (index, piece) in reply.pieces.into_iter().enumerate() {
                    if index == 1 {
                        tokio::time::sleep(reply.pause_after_first).await;
                    }
                    if !reply.delay.is_zero() {
                        tokio::time::sleep(reply.delay).await;
                    }
                    if timeout(SOCKET_TIMEOUT, socket.write_all(&piece))
                        .await
                        .expect("fixture response body write timed out")
                        .is_err()
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
            if reject_extra_requests {
                assert!(
                    timeout(Duration::from_millis(200), listener.accept())
                        .await
                        .is_err(),
                    "timed out or cancelled generation was unexpectedly retried"
                );
            }
            requests
        })
        .await
        .expect("HTTP fixture exceeded its 8-second deadline")
    });
    (url, task)
}
async fn finish_fixture(mut task: JoinHandle<Vec<Request>>) -> Vec<Request> {
    match timeout(FIXTURE_TIMEOUT, &mut task).await {
        Ok(result) => result.expect("HTTP fixture task failed"),
        Err(_) => {
            task.abort();
            panic!("HTTP fixture join exceeded its 8-second deadline");
        }
    }
}
fn settings(kind: ProviderKind, url: &str, stream: bool) -> ProviderSettings {
    ProviderSettings {
        kind,
        model: "test-model".into(),
        effort: Effort::Auto,
        base_url: Some(format!("{url}/v1")),
        folder_id: Some("folder".into()),
        auth_url: Some(format!("{url}/oauth")),
        scope: None,
        ca_file: None,
        stream,
        max_output_tokens: 1024,
        request_timeout_secs: 1,
        idle_timeout_secs: 1,
    }
}
fn completion() -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":"готово"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"cost":0.001},"model":"wire-model"})
}

fn image_message() -> Message {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("wire.png");
    std::fs::write(&path, b"\x89PNG\r\n\x1a\nwire-image").unwrap();
    rcode::images::user_message(
        &format!("/attach '{}' Explain the screenshot", path.display()),
        temp.path(),
    )
    .unwrap()
}

#[tokio::test]
async fn images_use_compatible_content_parts_for_each_compatible_provider() {
    for kind in [
        ProviderKind::Custom,
        ProviderKind::OpenRouter,
        ProviderKind::Yandex,
    ] {
        let (url, task) = server(vec![Reply::json(completion())]).await;
        let mut client =
            ProviderClient::new(settings(kind, &url, false), "image-key".into()).unwrap();
        client
            .complete(&[image_message()], &[tool()], &mut |_| {})
            .await
            .unwrap();
        let requests = finish_fixture(task).await;
        assert_eq!(requests.len(), 1);
        let body = requests[0].json();
        let parts = body["messages"][0]["content"].as_array().unwrap();
        assert_eq!(parts[0]["text"], "Explain the screenshot");
        assert_eq!(parts[1]["type"], "image_url");
        assert!(
            parts[1]["image_url"]["url"]
                .as_str()
                .unwrap()
                .starts_with("data:image/png;base64,")
        );
        assert!(body["messages"][0].get("images").is_none());
        assert!(body.get("tools").is_some());
    }
}

#[tokio::test]
async fn giga_image_upload_refreshes_auth_and_reuses_ids_in_following_requests() {
    let (url, task) = server(vec![
        Reply::json(json!({"access_token":"first-token","expires_at":4102444800u64})),
        Reply::body(401, "application/json", b"{}".to_vec()),
        Reply::json(json!({"access_token":"new-token","expires_at":4102444800u64})),
        Reply::json(json!({"id":"image-id"})),
        Reply::json(completion()),
        Reply::json(completion()),
    ])
    .await;
    let mut client = ProviderClient::new(
        settings(ProviderKind::GigaChat, &url, false),
        "upload-key".into(),
    )
    .unwrap();
    let mut message = image_message();
    message.images.push(message.images[0].clone());
    client
        .complete(&[message.clone()], &[tool()], &mut |_| {})
        .await
        .unwrap();
    client
        .complete(&[message], &[tool()], &mut |_| {})
        .await
        .unwrap();
    let requests = finish_fixture(task).await;
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[1].path, "/v1/files");
    assert_eq!(requests[1].body, requests[3].body);
    assert_eq!(requests[3].headers["authorization"], "Bearer new-token");
    for request in &requests[4..] {
        let body = request.json();
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        assert!(
            messages
                .iter()
                .all(|m| m["attachments"] == json!(["image-id"]))
        );
        assert_eq!(messages[0]["content"], "Explain the screenshot");
        assert!(body.get("functions").is_some());
    }
}

#[tokio::test]
async fn image_api_errors_preserve_context_failures_and_http_status() {
    for (upstream, expected) in [
        ("maximum context length exceeded", FailureKind::Context),
        ("image input unsupported", FailureKind::Protocol),
    ] {
        let (url, task) = server(vec![Reply::body(
            400,
            "application/json",
            json!({"error":{"message":upstream}})
                .to_string()
                .into_bytes(),
        )])
        .await;
        let mut client = ProviderClient::new(
            settings(ProviderKind::Custom, &url, false),
            "image-key".into(),
        )
        .unwrap();
        let error = client
            .complete(&[image_message()], &[], &mut |_| {})
            .await
            .unwrap_err();
        assert_eq!(failure(&error).kind, expected);
        assert_eq!(failure(&error).status, Some(400));
        assert_eq!(finish_fixture(task).await.len(), 1);
    }
}

#[tokio::test]
async fn real_agent_tools_use_an_optional_string_hash_for_native_giga_schema() {
    let (url, task) = server(vec![
        Reply::json(json!({"access_token":"schema-token","expires_at":4102444800u64})),
        Reply::json(completion()),
    ])
    .await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::GigaChat, &url, false), "key".into()).unwrap();
    let definitions = rcode::tools::Tools::definitions()
        .into_iter()
        .chain(rcode::agents::definitions())
        .collect::<Vec<_>>();
    client
        .complete(&[Message::user("Create a file")], &definitions, &mut |_| {})
        .await
        .unwrap();
    let requests = finish_fixture(task).await;
    let body = requests.last().unwrap().json();
    let write = body["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "write_file")
        .unwrap();
    assert_eq!(
        write["parameters"]["properties"]["expected_sha256"]["type"],
        "string"
    );
    assert!(
        !write["parameters"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("expected_sha256"))
    );
}

#[tokio::test]
async fn giga_schema_errors_are_not_blames_on_images_or_echoed_upstream_text() {
    let secret = "must-not-echo-upstream-secret";
    let upstream = format!(
        "Field 'properties.expected_sha256.type' is of a wrong type. Expected: stringValue, actual: arrayValue {secret}"
    );
    for with_image in [false, true] {
        let (url, task) = server(vec![Reply::body(
            422,
            "application/json",
            json!({"status":422,"message":upstream})
                .to_string()
                .into_bytes(),
        )])
        .await;
        let mut client =
            ProviderClient::new(settings(ProviderKind::Custom, &url, false), "key".into()).unwrap();
        let message = if with_image {
            image_message()
        } else {
            Message::user("hello")
        };
        let error = client
            .complete(&[message], &rcode::tools::Tools::definitions(), &mut |_| {})
            .await
            .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("схему параметров инструмента"), "{text}");
        assert!(!text.contains("изображением") && !text.contains("PNG") && !text.contains(secret));
        assert_eq!(failure(&error).status, Some(422));
        assert_eq!(finish_fixture(task).await.len(), 1);
    }
}
fn tool() -> ToolDefinition {
    ToolDefinition {
        name: "read_file".into(),
        description: "Read".into(),
        parameters: json!({"type":"object","properties":{"path":{"type":"string"}}}),
    }
}
fn failure(error: &anyhow::Error) -> &ProviderFailure {
    error
        .downcast_ref::<ProviderFailure>()
        .expect("structured provider failure")
}

fn with_timeouts(mut settings: ProviderSettings, request: u64, idle: u64) -> ProviderSettings {
    settings.request_timeout_secs = request;
    settings.idle_timeout_secs = idle;
    settings
}

#[test]
fn zero_timeouts_are_rejected_when_creating_the_provider_client() {
    for (request, idle) in [(0, 1), (1, 0)] {
        let error = ProviderClient::new(
            with_timeouts(
                settings(ProviderKind::Custom, "http://127.0.0.1:1", false),
                request,
                idle,
            ),
            "key".into(),
        )
        .err()
        .expect("zero timeout must not disable the deadline");
        assert_eq!(failure(&error).kind, FailureKind::Protocol);
    }
}

#[tokio::test]
async fn delayed_gigachat_headers_use_request_timeout_instead_of_stream_idle() {
    let event = json!({"choices":[{"delta":{"function_call":{"name":"read_file","arguments":{"path":"a.rs"}}},"finish_reason":"function_call"}]});
    let mut reply = Reply::body(
        200,
        "text/event-stream",
        format!("data: {event}\n\ndata: [DONE]\n\n").into_bytes(),
    );
    reply.header_delay = Duration::from_millis(1400);
    let (url, task) = server_checking_retries(
        vec![
            Reply::json(json!({"access_token":"token","expires_at":4102444800000u64})),
            reply,
        ],
        true,
    )
    .await;
    let mut client = ProviderClient::new(
        with_timeouts(settings(ProviderKind::GigaChat, &url, true), 3, 1),
        "key".into(),
    )
    .unwrap();
    let completion = client.complete(&[], &[tool()], &mut |_| {}).await.unwrap();
    assert_eq!(completion.tool_calls.len(), 1);
    assert_eq!(
        completion.tool_calls[0].function.arguments,
        "{\"path\":\"a.rs\"}"
    );
    assert_eq!(finish_fixture(task).await.len(), 2);
}

#[tokio::test]
async fn explicitly_short_request_timeout_is_honored_without_retrying_generation() {
    let mut reply = Reply::json(completion());
    reply.header_delay = Duration::from_millis(1400);
    let (url, task) = server_checking_retries(vec![reply], true).await;
    let mut client = ProviderClient::new(
        with_timeouts(settings(ProviderKind::Custom, &url, false), 1, 3),
        "key".into(),
    )
    .unwrap();
    let error = client.complete(&[], &[], &mut |_| {}).await.unwrap_err();
    assert_eq!(failure(&error).kind, FailureKind::Transport);
    let message = error.to_string();
    assert!(message.contains("1 с"), "{message}");
    assert!(message.contains("request_timeout_secs"), "{message}");
    assert!(message.contains("Ctrl+C"), "{message}");
    assert_eq!(finish_fixture(task).await.len(), 1);
}

#[tokio::test]
async fn stalled_stream_discards_partial_tools_and_keeps_its_idle_timeout() {
    let partial = json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"partial","type":"function","function":{"name":"read_file","arguments":"{\"path\":"}}]}}]});
    let mut reply = Reply::body(200, "text/event-stream", vec![]);
    reply.pieces = vec![
        format!("data: {partial}\n\n").into_bytes(),
        b"data: [DONE]\n\n".to_vec(),
    ];
    reply.pause_after_first = Duration::from_millis(1400);
    let (url, task) = server_checking_retries(vec![reply], true).await;
    let mut client = ProviderClient::new(
        with_timeouts(settings(ProviderKind::Custom, &url, true), 3, 1),
        "key".into(),
    )
    .unwrap();
    let mut emitted = String::new();
    let error = client
        .complete(&[], &[tool()], &mut |text| emitted.push_str(text))
        .await
        .unwrap_err();
    assert_eq!(failure(&error).kind, FailureKind::Transport);
    assert!(error.to_string().contains("idle timeout"));
    assert!(error.to_string().contains("1 с"));
    assert!(emitted.is_empty());
    assert_eq!(finish_fixture(task).await.len(), 1);
}

#[tokio::test]
async fn json_body_uses_idle_timeout_after_headers() {
    let mut reply = Reply::json(completion());
    reply.delay = Duration::from_millis(1400);
    let (url, task) = server_checking_retries(vec![reply], true).await;
    let mut client = ProviderClient::new(
        with_timeouts(settings(ProviderKind::Custom, &url, false), 3, 1),
        "key".into(),
    )
    .unwrap();
    let error = client.complete(&[], &[], &mut |_| {}).await.unwrap_err();
    assert_eq!(failure(&error).kind, FailureKind::Transport);
    assert!(error.to_string().contains("idle timeout"));
    assert!(error.to_string().contains("1 с"));
    assert_eq!(finish_fixture(task).await.len(), 1);
}

#[tokio::test]
async fn active_stream_can_outlive_the_request_timeout() {
    let mut reply = Reply::body(200, "text/event-stream", vec![]);
    reply.pieces = vec![
        b"data: {\"choices\":[{\"delta\":{\"content\":\"a\"}}]}\n\n".to_vec(),
        b"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n".to_vec(),
        b"data: [DONE]\n\n".to_vec(),
    ];
    reply.delay = Duration::from_millis(600);
    let (url, task) = server(vec![reply]).await;
    let mut client = ProviderClient::new(
        with_timeouts(settings(ProviderKind::Custom, &url, true), 1, 2),
        "key".into(),
    )
    .unwrap();
    assert_eq!(
        client
            .complete(&[], &[], &mut |_| {})
            .await
            .unwrap()
            .content,
        "a"
    );
    assert_eq!(finish_fixture(task).await.len(), 1);
}

#[tokio::test]
async fn models_and_oauth_keep_the_shorter_non_generation_wait() {
    for oauth in [false, true] {
        let mut reply = Reply::json(if oauth {
            json!({"access_token":"token","expires_at":4102444800000u64})
        } else {
            json!({"data":[]})
        });
        reply.header_delay = Duration::from_millis(1400);
        let (url, task) = server_checking_retries(vec![reply], true).await;
        let mut client = ProviderClient::new(
            with_timeouts(
                settings(
                    if oauth {
                        ProviderKind::GigaChat
                    } else {
                        ProviderKind::Custom
                    },
                    &url,
                    false,
                ),
                3,
                1,
            ),
            "key".into(),
        )
        .unwrap();
        let error = if oauth {
            client.complete(&[], &[], &mut |_| {}).await.unwrap_err()
        } else {
            client.models().await.unwrap_err()
        };
        assert_eq!(failure(&error).kind, FailureKind::Transport);
        assert!(error.to_string().contains("1 с"));
        let requests = finish_fixture(task).await;
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].path,
            if oauth { "/oauth" } else { "/v1/models" }
        );
    }
}

#[tokio::test]
async fn cancelling_header_and_body_waits_does_not_return_tools_or_replay_the_request() {
    for waiting_for_headers in [true, false] {
        let partial = json!({"choices":[{"delta":{"tool_calls":[{"index":0,"id":"partial","type":"function","function":{"name":"read_file","arguments":"{\"path\":"}}]}}]});
        let mut reply = Reply::body(200, "text/event-stream", vec![]);
        reply.pieces = vec![
            format!("data: {partial}\n\n").into_bytes(),
            b"data: [DONE]\n\n".to_vec(),
        ];
        if waiting_for_headers {
            reply.header_delay = Duration::from_millis(1400);
        } else {
            reply.pause_after_first = Duration::from_millis(1400);
        }
        let (url, task) = server_checking_retries(vec![reply], true).await;
        let mut client = ProviderClient::new(
            with_timeouts(settings(ProviderKind::Custom, &url, true), 3, 3),
            "key".into(),
        )
        .unwrap();
        let mut emitted = String::new();
        assert!(
            timeout(
                Duration::from_millis(150),
                client.complete(&[], &[tool()], &mut |text| emitted.push_str(text)),
            )
            .await
            .is_err()
        );
        assert_eq!(finish_fixture(task).await.len(), 1);
        assert!(emitted.is_empty());
    }
}

#[tokio::test]
async fn explicit_effort_is_sent_in_each_providers_native_request_field() {
    for kind in ProviderKind::all() {
        let mut replies = vec![];
        if kind == ProviderKind::GigaChat {
            replies.push(Reply::json(
                json!({"access_token":"access-key","expires_at":4102444800u64}),
            ));
        }
        replies.push(Reply::json(completion()));
        let (url, task) = server(replies).await;
        let mut config = serde_json::to_value(settings(kind, &url, false)).unwrap();
        config["effort"] = json!("high");
        let mut client =
            ProviderClient::new(serde_json::from_value(config).unwrap(), "key".into()).unwrap();
        client
            .complete(&[Message::user("hello")], &[], &mut |_| {})
            .await
            .unwrap();
        let requests = finish_fixture(task).await;
        let body = requests.last().unwrap().json();
        if kind == ProviderKind::OpenRouter {
            assert_eq!(body["reasoning"], json!({"effort":"high"}));
            assert!(body.get("reasoning_effort").is_none());
        } else {
            assert_eq!(body["reasoning_effort"], "high");
            assert!(body.get("reasoning").is_none());
        }
        assert!(body.get("temperature").is_none());
        assert_eq!(body["messages"], json!([{"role":"user","content":"hello"}]));
    }
}

#[tokio::test]
async fn automatic_effort_leaves_wire_requests_unchanged() {
    for kind in ProviderKind::all() {
        let mut replies = vec![];
        if kind == ProviderKind::GigaChat {
            replies.push(Reply::json(
                json!({"access_token":"access-key","expires_at":4102444800u64}),
            ));
        }
        replies.push(Reply::json(completion()));
        let (url, task) = server(replies).await;
        let mut client = ProviderClient::new(settings(kind, &url, false), "key".into()).unwrap();
        client.complete(&[], &[], &mut |_| {}).await.unwrap();
        let requests = finish_fixture(task).await;
        let body = requests.last().unwrap().json();
        assert!(body.get("reasoning").is_none());
        assert!(body.get("reasoning_effort").is_none());
    }
}

#[tokio::test]
async fn openrouter_models_report_reasoning_limits_and_context_metadata() {
    let (url, task) = server(vec![Reply::json(json!({"data":[
        {"id":"explicit", "context_length":200000, "supported_parameters":["tools", "reasoning"], "reasoning":{"supported_efforts":["low", "high"]}},
        {"id":"gateway", "top_provider":{"context_length":64000}, "supported_parameters":["reasoning.effort"], "reasoning":{"supported_efforts":null}},
        {"id":"mandatory", "supported_parameters":["reasoning_effort"], "reasoning":{"supported_efforts":null,"mandatory":true}},
        {"id":"parameters-only", "supported_parameters":["reasoning"]},
        {"id":"unsupported", "supported_parameters":["temperature"]},
        {"id":"unknown"}
    ]}))]).await;
    let mut client = ProviderClient::new(
        settings(ProviderKind::OpenRouter, &url, false),
        "key".into(),
    )
    .unwrap();
    let models = serde_json::to_value(client.models().await.unwrap()).unwrap();
    assert_eq!(models[0]["context_length"], 200000);
    assert_eq!(models[0]["supports_reasoning"], true);
    assert_eq!(models[0]["supported_efforts"], json!(["low", "high"]));
    assert_eq!(models[1]["context_length"], 64000);
    assert_eq!(models[1]["supports_reasoning"], true);
    assert_eq!(
        models[1]["supported_efforts"],
        json!(["none", "minimal", "low", "medium", "high", "xhigh", "max"])
    );
    assert_eq!(
        models[2]["supported_efforts"],
        json!(["minimal", "low", "medium", "high", "xhigh", "max"])
    );
    assert_eq!(models[3]["supports_reasoning"], true);
    assert!(models[3]["supported_efforts"].is_null());
    assert_eq!(models[4]["supports_reasoning"], false);
    assert!(models[5]["supports_reasoning"].is_null());
    finish_fixture(task).await;
}

#[tokio::test]
async fn other_model_catalogs_only_report_explicit_reasoning_metadata() {
    let (url, task) = server(vec![Reply::json(json!({"data":[
        {"id":"unknown", "supported_parameters":["tools"]},
        {"id":"explicit", "supports_reasoning":true,"supported_efforts":["medium","high"],"context_length":32768},
        {"id":"unsupported", "supports_reasoning":false}
    ]}))]).await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::Custom, &url, false), "key".into()).unwrap();
    let models = serde_json::to_value(client.models().await.unwrap()).unwrap();
    assert!(models[0]["supports_reasoning"].is_null());
    assert_eq!(models[1]["supports_reasoning"], true);
    assert_eq!(models[1]["supported_efforts"], json!(["medium", "high"]));
    assert_eq!(models[1]["context_length"], 32768);
    assert_eq!(models[2]["supports_reasoning"], false);
    finish_fixture(task).await;
}

#[tokio::test]
async fn openrouter_json_headers_usage_and_metadata_isolation() {
    let (url, task) = server(vec![Reply::json(completion())]).await;
    let mut client = ProviderClient::new(
        settings(ProviderKind::OpenRouter, &url, false),
        "secret".into(),
    )
    .unwrap();
    let mut message = Message::user("hello");
    message.provider_meta = Some(ProviderMeta {
        kind: "gigachat".into(),
        data: json!({"functions_state_id":"private-state"}),
    });
    let mut emitted = String::new();
    let result = client
        .complete(&[message], &[tool()], &mut |s| emitted.push_str(s))
        .await
        .unwrap();
    assert_eq!(result.content, "готово");
    assert_eq!(emitted, "готово");
    assert_eq!(result.usage.input_tokens, 3);
    assert_eq!(result.usage.cost_usd, Some(0.001));
    let requests = finish_fixture(task).await;
    assert_eq!(requests[0].path, "/v1/chat/completions");
    assert_eq!(requests[0].headers["authorization"], "Bearer secret");
    assert_eq!(requests[0].headers["x-title"], "rcode");
    let body = requests[0].json();
    assert_eq!(body["tools"][0]["function"]["name"], "read_file");
    assert!(body["messages"][0].get("provider_meta").is_none());
}

#[tokio::test]
async fn fragmented_utf8_sse_collects_tool_arguments_and_final_usage() {
    let events = [
        json!({"choices":[{"delta":{"content":"Привет","tool_calls":[{"index":0,"id":"wire-id","type":"function","function":{"name":"read_file","arguments":"{\"path\":"}}]}}]}),
        json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"a.rs\"}"}}]},"finish_reason":"tool_calls"}]}),
        json!({"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":4}}),
    ];
    let sse = events
        .iter()
        .map(|v| format!("data: {v}\r\n\r\n"))
        .collect::<String>()
        + "data: [DONE]\n\n";
    let (url, task) = server(vec![Reply::sse(&sse)]).await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::Custom, &url, true), "secret".into()).unwrap();
    let mut emitted = String::new();
    let result = client
        .complete(&[Message::user("hello")], &[tool()], &mut |s| {
            emitted.push_str(s)
        })
        .await
        .unwrap();
    assert_eq!(emitted, "Привет");
    assert_eq!(result.tool_calls[0].id, "wire-id");
    assert_eq!(
        result.tool_calls[0].function.arguments,
        "{\"path\":\"a.rs\"}"
    );
    assert_eq!(result.usage.input_tokens, 9);
    finish_fixture(task).await;
}

#[tokio::test]
async fn incomplete_stream_and_length_never_return_partial_tool_calls() {
    for sse in [
        "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n\ndata: [DONE]\n\n",
    ] {
        let (url, task) = server(vec![Reply::sse(sse)]).await;
        let mut client =
            ProviderClient::new(settings(ProviderKind::Custom, &url, true), "secret".into())
                .unwrap();
        let error = client.complete(&[], &[], &mut |_| {}).await.unwrap_err();
        assert_eq!(failure(&error).kind, FailureKind::Protocol);
        finish_fixture(task).await;
    }
}

#[tokio::test]
async fn yandex_uses_compatible_wire_and_official_project_header() {
    let (url, task) = server(vec![Reply::json(completion())]).await;
    let mut client = ProviderClient::new(
        settings(ProviderKind::Yandex, &url, false),
        "yc-secret".into(),
    )
    .unwrap();
    client
        .complete(&[Message::user("hello")], &[], &mut |_| {})
        .await
        .unwrap();
    let requests = finish_fixture(task).await;
    assert_eq!(requests[0].headers["authorization"], "Api-Key yc-secret");
    assert_eq!(requests[0].headers["openai-project"], "folder");
    assert_eq!(requests[0].json()["model"], "gpt://folder/test-model");
    assert!(requests[0].json().get("modelUri").is_none());
}

#[tokio::test]
async fn giga_oauth_and_multiple_tools_are_native_sequential_pairs() {
    let response = json!({"choices":[{"message":{"role":"assistant","content":"","function_call":{"name":"read_file","arguments":{"path":"c.rs"}},"functions_state_id":"new-state"},"finish_reason":"function_call"}]});
    let (url, task) = server(vec![
        Reply::json(json!({"access_token":"access-secret","expires_at":4102444800000u64})),
        Reply::json(response),
    ])
    .await;
    let mut client = ProviderClient::new(
        settings(ProviderKind::GigaChat, &url, false),
        "base64-key".into(),
    )
    .unwrap();
    let a = ToolCall::new("read_file", json!({"path":"a.rs"}));
    let b = ToolCall::new("read_file", json!({"path":"b.rs"}));
    let assistant = Message {
        role: "assistant".into(),
        content: Some("read both".into()),
        tool_calls: vec![a.clone(), b.clone()],
        provider_meta: Some(ProviderMeta {
            kind: "gigachat".into(),
            data: json!({"functions_state_id":"old-state"}),
        }),
        ..Message::default()
    };
    let result = client
        .complete(
            &[
                Message::user("read"),
                assistant,
                Message::tool(&a, "plain result"),
                Message::tool(&b, "{\"ok\":true}"),
            ],
            &[tool()],
            &mut |_| {},
        )
        .await
        .unwrap();
    assert_eq!(result.tool_calls.len(), 1);
    assert!(!result.tool_calls[0].id.is_empty());
    assert_eq!(
        result.provider_meta.unwrap().data["functions_state_id"],
        "new-state"
    );
    let requests = finish_fixture(task).await;
    assert_eq!(requests[0].path, "/oauth");
    assert_eq!(requests[0].headers["authorization"], "Basic base64-key");
    uuid::Uuid::parse_str(&requests[0].headers["rquid"]).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&requests[0].body),
        "scope=GIGACHAT_API_PERS"
    );
    assert_eq!(requests[1].headers["authorization"], "Bearer access-secret");
    let body = requests[1].json();
    assert!(body.get("tools").is_none());
    assert_eq!(body["functions"][0]["name"], "read_file");
    let messages = body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 5);
    assert_eq!(
        messages[1]["function_call"]["arguments"],
        json!({"path":"a.rs"})
    );
    assert_eq!(messages[1]["functions_state_id"], "old-state");
    assert_eq!(messages[2]["role"], "function");
    assert_eq!(
        serde_json::from_str::<Value>(messages[2]["content"].as_str().unwrap()).unwrap(),
        json!({"result":"plain result"})
    );
    assert_eq!(
        messages[3]["function_call"]["arguments"],
        json!({"path":"b.rs"})
    );
    assert_eq!(messages[4]["role"], "function");
}

#[tokio::test]
async fn giga_refreshes_once_after_unauthorized() {
    let token = |s| Reply::json(json!({"access_token":s,"expires_at":4102444800u64}));
    let (url, task) = server(vec![
        token("old-token"),
        Reply::body(401, "application/json", b"{}".to_vec()),
        token("new-token"),
        Reply::json(completion()),
    ])
    .await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::GigaChat, &url, false), "key".into()).unwrap();
    client.complete(&[], &[], &mut |_| {}).await.unwrap();
    let requests = finish_fixture(task).await;
    assert_eq!(requests[1].headers["authorization"], "Bearer old-token");
    assert_eq!(requests[3].headers["authorization"], "Bearer new-token");
}

#[tokio::test]
async fn models_report_tools_from_live_supported_parameters() {
    let (url, task) = server(vec![Reply::json(json!({"data":[{"id":"a","name":"Alpha","supported_parameters":["tools"]},{"id":"b","name":"Beta","supported_parameters":[]}]}))]).await;
    let mut client = ProviderClient::new(
        settings(ProviderKind::OpenRouter, &url, false),
        "key".into(),
    )
    .unwrap();
    let models = client.models().await.unwrap();
    assert_eq!(models[0].supports_tools, Some(true));
    assert_eq!(models[1].supports_tools, Some(false));
    assert_eq!(finish_fixture(task).await[0].path, "/v1/models");
}

#[tokio::test]
async fn retries_only_retryable_status_before_reading_body() {
    let mut retry = Reply::body(
        429,
        "application/json",
        b"secret echoed by upstream".to_vec(),
    );
    retry.headers.push(("Retry-After".into(), "0".into()));
    let (url, task) = server(vec![retry, Reply::json(completion())]).await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::Custom, &url, false), "secret".into()).unwrap();
    client.complete(&[], &[], &mut |_| {}).await.unwrap();
    assert_eq!(finish_fixture(task).await.len(), 2);
}

#[tokio::test]
async fn redirect_is_an_error_and_auth_errors_do_not_echo_body() {
    let mut redirect = Reply::body(302, "text/plain", vec![]);
    redirect
        .headers
        .push(("Location".into(), "http://127.0.0.1:1/stolen".into()));
    for (reply, kind) in [
        (redirect, FailureKind::Protocol),
        (
            Reply::body(
                401,
                "application/json",
                b"{\"message\":\"secret token and private prompt\"}".to_vec(),
            ),
            FailureKind::Auth,
        ),
        (
            Reply::body(
                400,
                "application/json",
                b"{\"error\":{\"code\":\"context_length_exceeded\",\"message\":\"secret\"}}"
                    .to_vec(),
            ),
            FailureKind::Context,
        ),
    ] {
        let (url, task) = server(vec![reply]).await;
        let mut client =
            ProviderClient::new(settings(ProviderKind::Custom, &url, false), "secret".into())
                .unwrap();
        let error = client.complete(&[], &[], &mut |_| {}).await.unwrap_err();
        assert_eq!(failure(&error).kind, kind);
        assert!(!format!("{error:#}").contains("secret"));
        assert!(!format!("{error:#}").contains("private prompt"));
        finish_fixture(task).await;
    }
}

#[test]
fn rejects_insecure_remote_or_credentialed_urls() {
    for url in [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com?token=secret",
        "https://example.com#secret",
    ] {
        assert!(
            ProviderClient::new(settings(ProviderKind::Custom, url, false), "secret".into())
                .is_err(),
            "{url}"
        );
    }
}

#[tokio::test]
async fn idle_stream_times_out_without_returning_a_completion() {
    let mut reply = Reply::sse("data: [DONE]\n\n");
    reply.delay = Duration::from_secs(2);
    let (url, task) = server(vec![reply]).await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::Custom, &url, true), "secret".into()).unwrap();
    let error = client.complete(&[], &[], &mut |_| {}).await.unwrap_err();
    assert_eq!(failure(&error).kind, FailureKind::Transport);
    task.abort();
    assert!(
        timeout(FIXTURE_TIMEOUT, task)
            .await
            .expect("cancelled idle fixture join timed out")
            .unwrap_err()
            .is_cancelled()
    );
}

#[tokio::test]
async fn yandex_function_name_ids_get_distinct_correlation_ids_without_relaxing_other_providers() {
    for streaming in [true, false] {
        for (kind, id, accepted) in [
            (ProviderKind::Yandex, "read_file", true),
            (ProviderKind::Yandex, "opaque-duplicate", false),
            (ProviderKind::Custom, "read_file", false),
            (ProviderKind::OpenRouter, "read_file", false),
        ] {
            let calls = json!([
                {"index":0,"id":id,"type":"function","function":{"name":"read_file","arguments":"{\"path\":\"a.rs\"}"}},
                {"index":1,"id":id,"type":"function","function":{"name":"read_file","arguments":"{\"path\":\"b.rs\"}"}}
            ]);
            let first = if streaming {
                let event = json!({"choices":[{"index":0,"delta":{"tool_calls":calls},"finish_reason":"tool_calls"}]});
                Reply::sse(&format!("data: {event}\n\ndata: [DONE]\n\n"))
            } else {
                Reply::json(
                    json!({"choices":[{"message":{"role":"assistant","tool_calls":calls},"finish_reason":"tool_calls"}]}),
                )
            };
            let mut replies = vec![first];
            if accepted {
                replies.push(Reply::json(completion()));
            }
            let (url, task) = server(replies).await;
            let mut client =
                ProviderClient::new(settings(kind, &url, streaming), "fixture-key".into()).unwrap();
            let result = client.complete(&[], &[tool()], &mut |_| {}).await;
            if accepted {
                let result = result
                    .expect("Yandex function-name placeholders need distinct correlation IDs");
                assert_eq!(result.tool_calls.len(), 2);
                assert_ne!(result.tool_calls[0].id, result.tool_calls[1].id);
                assert!(
                    result
                        .tool_calls
                        .iter()
                        .all(|call| call.function.name == "read_file")
                );
                assert_eq!(
                    serde_json::from_str::<Value>(&result.tool_calls[0].function.arguments)
                        .unwrap()["path"],
                    "a.rs"
                );
                assert_eq!(
                    serde_json::from_str::<Value>(&result.tool_calls[1].function.arguments)
                        .unwrap()["path"],
                    "b.rs"
                );
                let messages = vec![
                    Message::assistant(&result),
                    Message::tool(&result.tool_calls[0], "first"),
                    Message::tool(&result.tool_calls[1], "second"),
                ];
                client
                    .complete(&messages, &[tool()], &mut |_| {})
                    .await
                    .unwrap();
                let requests = finish_fixture(task).await;
                let messages = requests[1].json()["messages"].as_array().unwrap().clone();
                assert_eq!(
                    messages[0]["tool_calls"][0]["id"],
                    messages[1]["tool_call_id"]
                );
                assert_eq!(
                    messages[0]["tool_calls"][1]["id"],
                    messages[2]["tool_call_id"]
                );
            } else {
                assert_eq!(failure(&result.unwrap_err()).kind, FailureKind::Protocol);
                finish_fixture(task).await;
            }
        }
    }
}

#[tokio::test]
async fn tool_stream_accepts_id_only_fragment_but_rejects_data_after_finish() {
    let events = [
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"id-only","type":"function"}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"name":"read_file","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}),
    ];
    let body = events
        .iter()
        .map(|v| format!("data: {v}\n\n"))
        .collect::<String>()
        + "data: [DONE]\n\n";
    let (url, task) = server(vec![Reply::sse(&body)]).await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::Custom, &url, true), "key".into()).unwrap();
    let result = client.complete(&[], &[tool()], &mut |_| {}).await.unwrap();
    assert_eq!(result.tool_calls[0].id, "id-only");
    finish_fixture(task).await;

    let events = [
        json!({"choices":[{"delta":{"content":"first"},"finish_reason":"stop"}]}),
        json!({"choices":[{"delta":{"content":"must not be accepted"}}]}),
    ];
    let body = events
        .iter()
        .map(|v| format!("data: {v}\n\n"))
        .collect::<String>()
        + "data: [DONE]\n\n";
    let (url, task) = server(vec![Reply::sse(&body)]).await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::Custom, &url, true), "key".into()).unwrap();
    assert_eq!(
        failure(&client.complete(&[], &[], &mut |_| {}).await.unwrap_err()).kind,
        FailureKind::Protocol
    );
    finish_fixture(task).await;
}

#[tokio::test]
async fn giga_streams_native_object_arguments_and_reuses_access_token() {
    let event = json!({"choices":[{"index":0,"delta":{"role":"assistant","function_call":{"name":"read_file","arguments":{"path":"a.rs"}},"functions_state_id":"stream-state"},"finish_reason":"function_call"}]});
    let body = format!("data: {event}\n\ndata: [DONE]\n\n");
    let (url, task) = server(vec![
        Reply::json(json!({"access_token":"memory-token","expires_at":4102444800000u64})),
        Reply::sse(&body),
        Reply::json(completion()),
    ])
    .await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::GigaChat, &url, true), "key".into()).unwrap();
    let result = client.complete(&[], &[tool()], &mut |_| {}).await.unwrap();
    assert_eq!(
        result.tool_calls[0].function.arguments,
        "{\"path\":\"a.rs\"}"
    );
    assert_eq!(
        result.provider_meta.unwrap().data["functions_state_id"],
        "stream-state"
    );
    client.complete(&[], &[], &mut |_| {}).await.unwrap();
    assert_eq!(finish_fixture(task).await.len(), 3);
}

#[tokio::test]
async fn malformed_tool_json_and_sse_error_never_return_a_call_or_retry() {
    for body in [
        format!(
            "data: {}\n\ndata: [DONE]\n\n",
            json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"read_file","arguments":"{\"path\":"}}]},"finish_reason":"tool_calls"}]})
        ),
        format!(
            "data: {}\n\ndata: {}\n\n",
            json!({"choices":[{"delta":{"content":"partial"}}]}),
            json!({"error":{"code":429,"message":"key and prompt should remain private"}})
        ),
    ] {
        let (url, task) = server(vec![Reply::sse(&body)]).await;
        let mut client =
            ProviderClient::new(settings(ProviderKind::Custom, &url, true), "key".into()).unwrap();
        let error = client
            .complete(&[], &[tool()], &mut |_| {})
            .await
            .unwrap_err();
        assert!(matches!(
            failure(&error).kind,
            FailureKind::Protocol | FailureKind::RateLimit
        ));
        assert!(!error.to_string().contains("private"));
        assert_eq!(finish_fixture(task).await.len(), 1);
    }
}

#[tokio::test]
async fn configured_model_fallback_is_labelled_and_not_used_on_auth_failure() {
    let (url, task) = server(vec![Reply::body(404, "application/json", b"{}".to_vec())]).await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::Yandex, &url, false), "key".into()).unwrap();
    let models = client.models().await.unwrap();
    assert_eq!(models[0].id, "gpt://folder/test-model");
    assert!(models[0].name.contains("из конфигурации"));
    assert_eq!(models[0].supports_tools, None);
    assert_eq!(models[0].context_length, None);
    assert_eq!(models[0].supports_reasoning, None);
    assert_eq!(models[0].supported_efforts, None);
    finish_fixture(task).await;

    let (url, task) = server(vec![Reply::body(401, "application/json", b"{}".to_vec())]).await;
    let mut client =
        ProviderClient::new(settings(ProviderKind::Yandex, &url, false), "key".into()).unwrap();
    assert_eq!(
        failure(&client.models().await.unwrap_err()).kind,
        FailureKind::Auth
    );
    finish_fixture(task).await;
}

#[cfg(unix)]
#[tokio::test]
async fn custom_ca_is_required_for_self_signed_https_and_tls_stays_enabled() {
    use std::process::Stdio;
    let openssl_available = timeout(
        SOCKET_TIMEOUT,
        tokio::process::Command::new("openssl")
            .arg("version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|output| output.status.success()));
    if !openssl_available {
        eprintln!("SKIP TLS wire fixture: openssl отсутствует или не запускается");
        assert!(
            std::env::var_os("RCODE_REQUIRE_TLS_TEST").is_none_or(|value| value != "1"),
            "RCODE_REQUIRE_TLS_TEST=1 требует доступный openssl"
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    async fn run(root: &std::path::Path, arguments: &[&str]) {
        assert!(
            timeout(
                FIXTURE_TIMEOUT,
                tokio::process::Command::new("openssl")
                    .args(arguments)
                    .current_dir(root)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .status()
            )
            .await
            .expect("openssl fixture command timed out")
            .unwrap()
            .success()
        );
    }
    run(
        root,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=rcode wire test CA",
        ],
    )
    .await;
    run(
        root,
        &[
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "server.key",
            "-out",
            "server.csr",
            "-subj",
            "/CN=127.0.0.1",
        ],
    )
    .await;
    std::fs::write(root.join("server.ext"), "subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n").unwrap();
    run(
        root,
        &[
            "x509",
            "-req",
            "-in",
            "server.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "server.pem",
            "-days",
            "1",
            "-extfile",
            "server.ext",
        ],
    )
    .await;
    std::fs::create_dir(root.join("v1")).unwrap();
    std::fs::write(
        root.join("v1/models"),
        "{\"data\":[{\"id\":\"tls-model\"}]}",
    )
    .unwrap();
    let listener = timeout(SOCKET_TIMEOUT, TcpListener::bind("127.0.0.1:0"))
        .await
        .expect("fixture bind timed out")
        .unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut child = tokio::process::Command::new("openssl")
        .args([
            "s_server",
            "-quiet",
            "-WWW",
            "-accept",
            &address.to_string(),
            "-cert",
            "server.pem",
            "-key",
            "server.key",
        ])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(FIXTURE_TIMEOUT, async {
        loop {
            if timeout(SOCKET_TIMEOUT, tokio::net::TcpStream::connect(address))
                .await
                .is_ok_and(|result| result.is_ok())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TLS fixture did not start within 8 seconds");
    let url = format!("https://{address}");
    let mut without_ca =
        ProviderClient::new(settings(ProviderKind::Custom, &url, false), "key".into()).unwrap();
    let error = without_ca.models().await.unwrap_err();
    assert_eq!(failure(&error).kind, FailureKind::Transport);
    let mut custom = settings(ProviderKind::Custom, &url, false);
    custom.ca_file = Some(root.join("ca.pem"));
    let mut with_ca = ProviderClient::new(custom, "key".into()).unwrap();
    assert_eq!(with_ca.models().await.unwrap()[0].id, "tls-model");
    timeout(SOCKET_TIMEOUT, child.kill())
        .await
        .expect("TLS fixture kill timed out")
        .unwrap();
    timeout(SOCKET_TIMEOUT, child.wait())
        .await
        .expect("TLS fixture wait timed out")
        .unwrap();
}

#[tokio::test]
async fn rejects_oversized_response_and_invalid_json_without_echoing_input() {
    let oversized = Reply::body(200, "application/json", vec![b' '; 8 * 1024 * 1024 + 1]);
    for reply in [
        oversized,
        Reply::body(
            200,
            "application/json",
            b"private prompt and secret key".to_vec(),
        ),
    ] {
        let (url, task) = server(vec![reply]).await;
        let mut client = ProviderClient::new(
            settings(ProviderKind::Custom, &url, false),
            "secret key".into(),
        )
        .unwrap();
        let error = client.complete(&[], &[], &mut |_| {}).await.unwrap_err();
        assert_eq!(failure(&error).kind, FailureKind::Protocol);
        assert!(!error.to_string().contains("private prompt"));
        assert!(!error.to_string().contains("secret key"));
        finish_fixture(task).await;
    }
}

#[tokio::test]
async fn second_giga_401_stops_refreshing_and_does_not_expose_access_token() {
    let token = || Reply::json(json!({"access_token":"derived-secret","expires_at":4102444800u64}));
    let denied = || {
        Reply::body(
            401,
            "application/json",
            b"derived-secret auth-key private prompt".to_vec(),
        )
    };
    let (url, task) = server(vec![token(), denied(), token(), denied()]).await;
    let mut client = ProviderClient::new(
        settings(ProviderKind::GigaChat, &url, false),
        "auth-key".into(),
    )
    .unwrap();
    let error = client.complete(&[], &[], &mut |_| {}).await.unwrap_err();
    assert_eq!(failure(&error).kind, FailureKind::Auth);
    assert!(!error.to_string().contains("derived-secret"));
    assert!(!error.to_string().contains("auth-key"));
    assert_eq!(finish_fixture(task).await.len(), 4);
}
