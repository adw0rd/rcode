//! Local provider wire behaviour on loopback fixtures (no live model).
mod support;

use rcode::{
    config::{ProviderKind, ProviderSettings},
    local::{LocalRuntime, profile_settings},
    protocol::{FailureKind, Message, ProviderFailure, ToolDefinition},
    provider::ProviderClient,
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use support::{Response, Server, text_reply, tool_reply};

fn profile(base: &str, runtime: LocalRuntime) -> ProviderSettings {
    profile_settings("fixture", base, runtime, "fixture-model")
}

fn tool() -> Vec<ToolDefinition> {
    vec![ToolDefinition {
        name: "read_file".into(),
        description: "Read a file".into(),
        parameters: json!({"type":"object","properties":{"path":{"type":"string"}}}),
    }]
}

fn failure(error: &anyhow::Error) -> &ProviderFailure {
    error
        .downcast_ref::<ProviderFailure>()
        .expect("provider failure")
}

async fn complete(
    client: &mut ProviderClient,
    tools: &[ToolDefinition],
) -> (anyhow::Result<rcode::protocol::Completion>, String) {
    let shown = Arc::new(Mutex::new(String::new()));
    let sink = shown.clone();
    let result = client
        .complete(&[Message::user("привет")], tools, &mut |chunk| {
            sink.lock().unwrap().push_str(chunk)
        })
        .await;
    let shown = shown.lock().unwrap().clone();
    (result, shown)
}

#[tokio::test]
async fn local_noauth_sends_no_authorization_header_and_no_effort() {
    let server = Server::start(|_, _| text_reply("готово"));
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Ollama), None).unwrap();
    let (result, shown) = complete(&mut client, &tool()).await;
    assert_eq!(result.unwrap().content, "готово");
    assert_eq!(shown, "готово");
    let request = &server.generations()[0];
    assert!(request.authorization().is_none());
    let body = request.json();
    assert!(body.get("reasoning_effort").is_none() && body.get("reasoning").is_none());
    assert_eq!(body["stream_options"]["include_usage"], true);
    assert_eq!(body["tool_choice"], "auto");
    assert_eq!(body["max_tokens"], 4096);
    assert!(body.get("chat_template_kwargs").is_none());
}

#[tokio::test]
async fn empty_local_key_is_no_key_but_cloud_requires_one() {
    let server = Server::start(|_, _| text_reply("ok"));
    let mut client = ProviderClient::connect(
        profile(&server.base(), LocalRuntime::LlamaCpp),
        Some("  ".into()),
    )
    .unwrap();
    complete(&mut client, &[]).await.0.unwrap();
    assert!(server.generations()[0].authorization().is_none());
    for kind in [
        ProviderKind::OpenRouter,
        ProviderKind::Custom,
        ProviderKind::Yandex,
    ] {
        let mut settings = ProviderSettings::new(kind);
        settings.folder_id = Some("folder".into());
        let error = ProviderClient::connect(settings, None)
            .err()
            .expect("cloud needs a key");
        assert_eq!(failure(&error).kind, FailureKind::Auth);
    }
}

#[tokio::test]
async fn local_optional_key_sends_bearer_to_its_loopback_endpoint() {
    let server = Server::start(|_, _| text_reply("ok"));
    let base = format!("http://localhost:{}/v1", server.port);
    let mut client = ProviderClient::connect(
        profile(&base, LocalRuntime::LlamaCpp),
        Some("local-fixture-key".into()),
    )
    .unwrap();
    complete(&mut client, &[]).await.0.unwrap();
    assert_eq!(
        server.generations()[0].authorization(),
        Some("Bearer local-fixture-key")
    );
}

#[tokio::test]
async fn local_rejects_non_loopback_endpoint_before_network() {
    for base in [
        "https://example.com/v1",
        "http://10.0.0.5:8080/v1",
        "http://user@127.0.0.1:1/v1",
    ] {
        let error = ProviderClient::connect(profile(base, LocalRuntime::OpenAi), Some("k".into()))
            .err()
            .expect("non-loopback local endpoint");
        assert!(format!("{error:#}").contains("127.0.0.1"), "{base}");
    }
}

#[tokio::test]
async fn local_rejects_redirect_without_following_it() {
    let server = Server::start(|_, _| {
        Response::json(302, json!({})).header("Location", "https://example.com/v1/chat/completions")
    });
    let mut client = ProviderClient::connect(
        profile(&server.base(), LocalRuntime::OpenAi),
        Some("redirect-key".into()),
    )
    .unwrap();
    let error = complete(&mut client, &[]).await.0.unwrap_err();
    assert_eq!(failure(&error).status, Some(302));
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn stream_options_and_thinking_follow_runtime_and_explicit_choice() {
    for (runtime, usage) in [
        (LocalRuntime::Ollama, true),
        (LocalRuntime::LlamaCpp, true),
        (LocalRuntime::LmStudio, true),
        (LocalRuntime::Mlx, false),
        (LocalRuntime::OpenAi, false),
    ] {
        let server = Server::start(|_, _| text_reply("ok"));
        let mut settings = profile(&server.base(), runtime);
        if runtime != LocalRuntime::Ollama {
            settings.local.as_mut().unwrap().thinking = Some(false);
        }
        let mut client = ProviderClient::connect(settings, None).unwrap();
        complete(&mut client, &[]).await.0.unwrap();
        let body = server.generations()[0].json();
        assert_eq!(body.get("stream_options").is_some(), usage, "{runtime}");
        if runtime != LocalRuntime::Ollama {
            assert_eq!(
                body["chat_template_kwargs"]["enable_thinking"], false,
                "{runtime}"
            );
        }
    }
}

#[tokio::test]
async fn local_streaming_tool_calls_chunked_args_with_two_indexes() {
    let first = json!({"path":"src/main.rs"}).to_string();
    let second = json!({"path":"README.md"}).to_string();
    let mut events = vec![
        json!({"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[
            {"index":0,"id":"call_a","type":"function","function":{"name":"read_file","arguments":""}},
            {"index":1,"id":"call_b","type":"function","function":{"name":"read_file","arguments":""}}
        ]}}]}),
    ];
    for (index, arguments) in [(0, &first), (1, &second)] {
        for piece in arguments.as_bytes().chunks(3) {
            events.push(json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":index,"function":{"arguments":String::from_utf8_lossy(piece)}}]}}]}));
        }
    }
    events.push(json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}));
    let server = Server::start(move |_, _| Response::sse(&events));
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::LlamaCpp), None).unwrap();
    let completion = complete(&mut client, &tool()).await.0.unwrap();
    let calls: Vec<(String, Value)> = completion
        .tool_calls
        .iter()
        .map(|call| {
            (
                call.id.clone(),
                serde_json::from_str(&call.function.arguments).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        calls,
        vec![
            ("call_a".into(), json!({"path":"src/main.rs"})),
            ("call_b".into(), json!({"path":"README.md"}))
        ]
    );
}

#[tokio::test]
async fn reasoning_fields_are_hidden_and_not_part_of_the_answer() {
    let server = Server::start(|_, _| {
        Response::sse(&[
            json!({"choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"секретный план "}}]}),
            json!({"choices":[{"index":0,"delta":{"reasoning":"ещё мысли"}}]}),
            json!({"choices":[{"index":0,"delta":{"content":"Ответ"}}]}),
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
        ])
    });
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Ollama), None).unwrap();
    let (result, shown) = complete(&mut client, &[]).await;
    let completion = result.unwrap();
    assert_eq!(completion.content, "Ответ");
    assert_eq!(shown, "Ответ");
    assert_eq!(completion.reasoning, "секретный план ещё мысли");
    let history = serde_json::to_string(&Message::assistant(&completion)).unwrap();
    assert!(!history.contains("секретный"));
}

fn think_stream() -> Response {
    let text = "<think>скрытые рассуждения</think>\n\nИтог: используйте `<think>` как тег.";
    let mut events = vec![json!({"choices":[{"index":0,"delta":{"role":"assistant"}}]})];
    for piece in text.chars().collect::<Vec<_>>().chunks(2) {
        events.push(
            json!({"choices":[{"index":0,"delta":{"content":piece.iter().collect::<String>()}}]}),
        );
    }
    events.push(json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}));
    Response::sse(&events)
}

#[tokio::test]
async fn split_think_block_stripped_for_local_only() {
    let server = Server::start(|_, _| think_stream());
    let mut local =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Mlx), None).unwrap();
    let (result, shown) = complete(&mut local, &[]).await;
    let completion = result.unwrap();
    assert_eq!(completion.content, "Итог: используйте `<think>` как тег.");
    assert_eq!(shown, completion.content);
    assert_eq!(completion.reasoning, "скрытые рассуждения");
    // A cloud-compatible provider keeps its historical behaviour untouched.
    let mut custom = ProviderSettings::new(ProviderKind::Custom);
    custom.base_url = Some(server.base());
    let mut cloud = ProviderClient::new(custom, "custom-key".into()).unwrap();
    let (result, _) = complete(&mut cloud, &[]).await;
    assert!(result.unwrap().content.starts_with("<think>скрытые"));
}

#[tokio::test]
async fn unclosed_think_block_is_an_error_not_an_empty_answer() {
    let server = Server::start(|_, _| {
        Response::sse(&[
            json!({"choices":[{"index":0,"delta":{"content":"<think>бесконечные рассуждения"}}]}),
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
        ])
    });
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Mlx), None).unwrap();
    let (result, shown) = complete(&mut client, &[]).await;
    let error = result.unwrap_err();
    assert!(format!("{error:#}").contains("<think>"));
    assert!(shown.is_empty(), "reasoning must not be shown");
}

#[tokio::test]
async fn non_streaming_json_strips_think_and_reasoning() {
    let server = Server::start(|_, _| {
        Response::json(
            200,
            json!({"choices":[{"index":0,"message":{"role":"assistant","content":"<think>x</think>Ответ","reasoning_content":"y"},"finish_reason":"stop"}]}),
        )
    });
    let mut settings = profile(&server.base(), LocalRuntime::LlamaCpp);
    settings.stream = false;
    let mut client = ProviderClient::connect(settings, None).unwrap();
    let (result, shown) = complete(&mut client, &[]).await;
    assert_eq!(result.unwrap().content, "Ответ");
    assert_eq!(shown, "Ответ");
}

#[tokio::test]
async fn text_tool_call_error_has_llamacpp_jinja_hint() {
    let server = Server::start(|_, _| {
        text_reply("<tool_call>\n{\"name\":\"read_file\",\"arguments\":{}}\n</tool_call>")
    });
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::LlamaCpp), None).unwrap();
    let error = complete(&mut client, &tool()).await.0.unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("--jinja") && text.contains("не исполнялось"),
        "{text}"
    );
    // Ordinary prose that merely mentions the tag is an answer.
    let server = Server::start(|_, _| text_reply("Модель печатает <tool_call> внутри ответа"));
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::LlamaCpp), None).unwrap();
    complete(&mut client, &tool()).await.0.unwrap();
}

#[tokio::test]
async fn ollama_400_does_not_support_tools_is_clear_error_without_retry() {
    let server = Server::start(|_, _| {
        Response::json(
            400,
            json!({"error":{"message":"registry.ollama.ai/library/gemma:2b does not support tools","type":"api_error"}}),
        )
    });
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Ollama), None).unwrap();
    let error = complete(&mut client, &tool()).await.0.unwrap_err();
    assert_eq!(failure(&error).kind, FailureKind::Protocol);
    assert!(format!("{error:#}").contains("function calling"));
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn local_401_points_to_profile_key_command_without_echoing_body() {
    let server =
        Server::start(|_, _| Response::json(401, json!({"error":"echo local-body-secret"})));
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::LlamaCpp), None).unwrap();
    let error = complete(&mut client, &[]).await.0.unwrap_err();
    let text = format!("{error:#}");
    assert_eq!(failure(&error).kind, FailureKind::Auth);
    assert!(text.contains("rcode local key fixture --stdin"), "{text}");
    assert!(!text.contains("local-body-secret"));
}

#[tokio::test]
async fn connection_refused_says_server_not_running_with_url() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let base = format!("http://127.0.0.1:{port}/v1");
    let mut client = ProviderClient::connect(profile(&base, LocalRuntime::Mlx), None).unwrap();
    let error = complete(&mut client, &[]).await.0.unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains(&format!("127.0.0.1:{port}")) && text.contains("не отвечает"),
        "{text}"
    );
    assert!(!text.contains("ключ") && !text.contains("CA"), "{text}");
}

#[tokio::test]
async fn local_models_filter_embeddings_and_404_falls_back_to_profile_model() {
    let server = Server::start(|request, _| {
        assert!(request.authorization().is_none());
        Response::json(
            200,
            json!({"object":"list","data":[
                {"id":"qwen3:8b","object":"model","owned_by":"library"},
                {"id":"nomic-embed-text:latest","object":"model","owned_by":"library"}
            ]}),
        )
    });
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Ollama), None).unwrap();
    let models = client.models().await.unwrap();
    assert_eq!(
        models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        ["qwen3:8b"]
    );
    assert_eq!(
        models[0].supports_tools, None,
        "tools are not confirmed by /models"
    );
    let missing = Server::start(|_, _| Response::json(404, json!({})));
    let mut client =
        ProviderClient::connect(profile(&missing.base(), LocalRuntime::Mlx), None).unwrap();
    let models = client.models().await.unwrap();
    assert_eq!(models[0].id, "fixture-model");
}

#[tokio::test]
async fn local_balance_is_not_applicable_without_network() {
    let server = Server::start(|_, _| panic!("balance must not call the server"));
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Ollama), None).unwrap();
    let report = client.balance().await.unwrap();
    assert!(report.note.unwrap().contains("не применяется"));
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn runtime_context_probe_reads_llamacpp_props_and_shrinks_budget() {
    let server = Server::start(|request, _| {
        assert_eq!(request.path, "/props");
        Response::json(
            200,
            json!({"default_generation_settings":{"n_ctx":8192},"total_slots":1}),
        )
    });
    let client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::LlamaCpp), None).unwrap();
    assert_eq!(client.context_budget(0).limit, 25_396);
    assert_eq!(client.probe_local_context().await, Some(8192));
    let budget = client.clone().context_budget(0);
    assert_eq!(budget.context_tokens, Some(8192));
    assert_eq!(budget.max_output_tokens, Some(2048));
    // MLX has no documented context endpoint: no request, profile value.
    let mlx = Server::start(|_, _| panic!("no probe for mlx"));
    let client = ProviderClient::connect(profile(&mlx.base(), LocalRuntime::Mlx), None).unwrap();
    assert_eq!(client.probe_local_context().await, None);
    assert!(mlx.requests().is_empty());
}

#[tokio::test]
async fn image_without_confirmed_vision_is_refused_before_network() {
    let server = Server::start(|_, _| text_reply("ok"));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pixel.png");
    image::RgbaImage::new(1, 1).save(&path).unwrap();
    let message =
        rcode::images::user_message(&format!("опиши {}", path.display()), directory.path())
            .unwrap();
    assert_eq!(message.images.len(), 1);
    let mut client =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Mlx), None).unwrap();
    let error = client
        .complete(std::slice::from_ref(&message), &[], &mut |_| {})
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("--vision"));
    assert!(server.requests().is_empty());
    let mut settings = profile(&server.base(), LocalRuntime::Mlx);
    settings.local.as_mut().unwrap().vision = true;
    let mut client = ProviderClient::connect(settings, None).unwrap();
    client.complete(&[message], &[], &mut |_| {}).await.unwrap();
    let body = server.generations()[0].json();
    assert_eq!(body["messages"][0]["content"][1]["type"], "image_url");
}

// ---- single flight -------------------------------------------------------

fn slow_reply() -> Response {
    text_reply("медленно").delayed(Duration::from_millis(60))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_single_flight_across_profiles_aliases_clones_and_new_clients() {
    let server = Server::start(|_, _| slow_reply());
    let main =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::LlamaCpp), None).unwrap();
    let mut child_profile = profile_settings(
        "child",
        &format!("http://localhost:{}/v1/", server.port),
        LocalRuntime::LlamaCpp,
        "other-model",
    );
    child_profile.max_output_tokens = 1024;
    let child = ProviderClient::connect(child_profile, Some("child-key".into())).unwrap();
    let path_alias = ProviderClient::connect(
        profile(
            &format!("http://[::1]:{}/api/v1", server.port),
            LocalRuntime::OpenAi,
        ),
        None,
    )
    .unwrap();
    let mut tasks = Vec::new();
    for mut client in [main.clone(), main, child.clone(), child, path_alias] {
        tasks.push(tokio::spawn(async move {
            client
                .complete(&[Message::user("x")], &[], &mut |_| {})
                .await
        }));
    }
    let mut ok = 0;
    for task in tasks {
        // The ::1 alias cannot reach an IPv4-only fixture; it still must wait for the slot.
        if task.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert!(ok >= 4);
    assert_eq!(server.max_concurrent_generations(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn different_ports_do_not_share_a_slot() {
    let slow = Server::start(|_, _| text_reply("a").delayed(Duration::from_millis(400)));
    let fast = Server::start(|_, _| text_reply("b"));
    let mut first =
        ProviderClient::connect(profile(&slow.base(), LocalRuntime::LlamaCpp), None).unwrap();
    let mut second =
        ProviderClient::connect(profile(&fast.base(), LocalRuntime::LlamaCpp), None).unwrap();
    let started = Instant::now();
    let slow_task = tokio::spawn(async move {
        first
            .complete(&[Message::user("x")], &[], &mut |_| {})
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    second
        .complete(&[Message::user("y")], &[], &mut |_| {})
        .await
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "fast server waited for another port"
    );
    slow_task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_releases_slot_for_the_next_generation() {
    let server = Server::start(|_, index| {
        if index == 0 {
            text_reply("долго").delayed(Duration::from_secs(3))
        } else {
            text_reply("быстро")
        }
    });
    let mut first =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Ollama), None).unwrap();
    let mut second = first.clone();
    let cancelled = tokio::time::timeout(
        Duration::from_millis(300),
        first.complete(&[Message::user("x")], &[], &mut |_| {}),
    )
    .await;
    assert!(cancelled.is_err(), "first generation must still be running");
    let started = Instant::now();
    let answer = second
        .complete(&[Message::user("y")], &[], &mut |_| {})
        .await
        .unwrap();
    assert_eq!(answer.content, "быстро");
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_waiter_does_not_keep_a_permit() {
    let server = Server::start(|_, index| {
        if index == 0 {
            text_reply("занято").delayed(Duration::from_millis(150))
        } else {
            text_reply("ok")
        }
    });
    let busy =
        ProviderClient::connect(profile(&server.base(), LocalRuntime::Ollama), None).unwrap();
    let mut holder = busy.clone();
    let holding = tokio::spawn(async move {
        holder
            .complete(&[Message::user("x")], &[], &mut |_| {})
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut waiter = busy.clone();
    // Abandon a queued request while the slot is busy.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            waiter.complete(&[Message::user("w")], &[], &mut |_| {})
        )
        .await
        .is_err()
    );
    holding.await.unwrap().unwrap();
    let mut next = busy.clone();
    tokio::time::timeout(
        Duration::from_secs(2),
        next.complete(&[Message::user("z")], &[], &mut |_| {}),
    )
    .await
    .expect("slot must be free")
    .unwrap();
    assert_eq!(
        server.generations().len(),
        2,
        "abandoned waiter never reached the server"
    );
}

#[tokio::test]
async fn localhost_is_pinned_to_loopback_inside_the_client() {
    let server = Server::start(|_, _| tool_reply("call_1", "read_file", &json!({"path":"a"})));
    let base = format!("http://LOCALHOST:{}/v1", server.port);
    let mut client = ProviderClient::connect(
        profile(&base, LocalRuntime::LlamaCpp),
        Some("pinned-key".into()),
    )
    .unwrap();
    let completion = complete(&mut client, &tool()).await.0.unwrap();
    assert_eq!(completion.tool_calls.len(), 1);
    assert_eq!(
        server.generations()[0].authorization(),
        Some("Bearer pinned-key")
    );
}

/// Counts connections on another loopback address; `None` without IPv6 loopback.
fn ipv6_listener(
    port: u16,
) -> Option<(
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicBool>,
)> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let listener = std::net::TcpListener::bind(("::1", port)).ok()?;
    listener.set_nonblocking(true).unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (count, done) = (accepted.clone(), stop.clone());
    std::thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            if listener.accept().is_ok() {
                count.fetch_add(1, Ordering::SeqCst);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    Some((accepted, stop))
}

#[tokio::test]
async fn localhost_never_falls_back_to_another_loopback_family() {
    use std::sync::atomic::Ordering;
    // A port that is free on 127.0.0.1 but taken by another listener on [::1].
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let Some((accepted, stop)) = ipv6_listener(port) else {
        eprintln!("IPv6 loopback unavailable; skipped");
        return;
    };
    let base = format!("http://localhost:{port}/v1");
    let mut client = ProviderClient::connect(
        profile(&base, LocalRuntime::OpenAi),
        Some("pinned-v4-only-key".into()),
    )
    .unwrap();
    let (result, _) = complete(&mut client, &[]).await;
    stop.store(true, Ordering::SeqCst);
    assert_eq!(failure(&result.unwrap_err()).kind, FailureKind::Transport);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "localhost must not reach [::1]"
    );
}
