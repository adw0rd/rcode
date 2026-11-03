mod quality_support;
mod support;
use quality_support::{Fixture, events};
use rcode::{
    config::{ConfigStore, ProviderKind, ProviderSettings},
    protocol::Message,
    state::Session,
};
use serde_json::{Value, json};
use support::{Server, text_reply, tool_reply};

#[tokio::test]
async fn omitted_tool_output_is_retrievable_without_reexecuting_the_action() {
    let fixture = Fixture::new();
    let mut content = String::new();
    for i in 0..280 {
        content.push_str(&format!(
            "{i:03} {} {}\n",
            "filler data ".repeat(7),
            if i == 200 { "MIDDLE_TOKEN" } else { "" }
        ));
    }
    std::fs::write(fixture.project.join("large.txt"), &content).unwrap();
    let server = Server::start(|request, index| {
        if index == 0 {
            return tool_reply(
                "read-1",
                "read_file",
                &json!({"path":"large.txt","max_lines":300}),
            );
        }
        let messages = request.json()["messages"].as_array().unwrap().clone();
        let receipt: Value = serde_json::from_str(
            messages.iter().rev().find(|m| m["role"] == "tool").unwrap()["content"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        if index == 1 {
            assert!(receipt["artifact_bytes"].as_u64().unwrap() > 16384);
            assert!(!receipt.to_string().contains("MIDDLE_TOKEN"));
            tool_reply(
                "read-2",
                "read_tool_output",
                &json!({"artifact_id":receipt["artifact_id"],"offset":0,"max_bytes":65536}),
            )
        } else {
            assert!(
                receipt["content"]
                    .as_str()
                    .unwrap()
                    .contains("MIDDLE_TOKEN")
            );
            text_reply("Recovered the saved output without repeating the read.")
        }
    });
    let output = fixture
        .run(
            &server,
            &[],
            "Read the file and retrieve its omitted middle",
        )
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(server.generations().len(), 3);
    let events = events(&output);
    assert_eq!(
        events
            .iter()
            .filter(|e| e["type"] == "tool_start" && e["name"] == "read_file")
            .count(),
        1
    );
    assert_eq!(
        std::fs::read_to_string(fixture.project.join("large.txt")).unwrap(),
        content
    );
    let saved = fixture.saved();
    assert!(saved["task_state"]["goal_source"]["artifact_id"].is_string());
}

#[tokio::test]
async fn legacy_resume_uses_the_original_user_goal_and_a_complete_request_journal() {
    let fixture = Fixture::new();
    let store = ConfigStore::at(fixture.home.clone()).unwrap();
    let mut session = Session::new(
        &fixture.project,
        ProviderSettings::new(ProviderKind::Custom),
    )
    .unwrap();
    session
        .messages
        .push(Message::user("ORIGINAL_GOAL preserve all my files"));
    session.messages.push(Message::text("assistant", "Started"));
    session.save(&store).unwrap();
    let path = session.dir(&store).join("session.json");
    let mut legacy: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    legacy.as_object_mut().unwrap().remove("task_state");
    std::fs::write(&path, legacy.to_string()).unwrap();
    let server = Server::start(|request, _| {
        let request = request.json();
        let system = request["messages"][0]["content"].as_str().unwrap();
        assert!(system.contains("ORIGINAL_GOAL"));
        assert!(system.contains("FOLLOWUP"));
        text_reply("Continue original task")
    });
    let output = fixture
        .run(&server, &["--resume", &session.id], "FOLLOWUP add tests")
        .await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let saved = fixture.saved();
    assert_eq!(
        saved["task_state"]["goal"],
        "ORIGINAL_GOAL preserve all my files"
    );
    let mut loaded = Session::load(&store, &session.id, &fixture.project).unwrap();
    loaded.compact().unwrap();
    loaded.save(&store).unwrap();
    assert_eq!(
        Session::load(&store, &session.id, &fixture.project)
            .unwrap()
            .task_state
            .goal(),
        "ORIGINAL_GOAL preserve all my files"
    );
}

#[tokio::test]
async fn malformed_arguments_are_refused_without_leaking_keys() {
    let fixture = Fixture::new();
    let key = quality_support::KEY;
    let encoded: String = key.bytes().map(|b| format!("%{b:02X}")).collect();
    let reflected = encoded.clone();
    let server = Server::start(move |_, index| {
        if index == 0 {
            return support::Response::json(
                200,
                json!({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":format!("call-{key}"),"type":"function","function":{"name":"list_files","arguments":format!("{{broken {key} {reflected}")}}]},"finish_reason":"tool_calls"}]}),
            );
        }
        text_reply("The invalid tool call was refused.")
    });
    let output = fixture.run(&server, &["--plan"], "Inspect safely").await;
    assert_eq!(server.generations().len(), 1);
    assert!(!events(&output).iter().any(|e| e["type"] == "tool_start"));
    let bytes = String::from_utf8_lossy(&output.stdout);
    assert!(!bytes.contains(key));
    assert!(!bytes.contains(&encoded));
    let saved = fixture.saved().to_string();
    assert!(!saved.contains(key));
    assert!(!saved.contains(&encoded));
    for request in server.generations() {
        assert!(!request.json().to_string().contains(key));
        assert!(!request.json().to_string().contains(&encoded));
    }
    assert_eq!(std::fs::read_dir(&fixture.project).unwrap().count(), 0);
}

#[tokio::test]
async fn valid_tool_ids_and_percent_encoded_keys_are_redacted_before_every_sink() {
    let fixture = Fixture::new();
    let key = quality_support::KEY;
    let encoded: String = key.bytes().map(|b| format!("%{b:02X}")).collect();
    let reflected = encoded.clone();
    let server = Server::start(move |_, index| {
        if index == 0 {
            tool_reply(
                &format!("call-{key}"),
                "search",
                &json!({"pattern":reflected}),
            )
        } else {
            text_reply("Inspected")
        }
    });
    let output = fixture.run(&server, &["--plan"], "Inspect safely").await;
    assert_eq!(
        server.generations().len(),
        2,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        events(&output)
            .iter()
            .filter(|e| e["type"] == "tool_start")
            .count(),
        1
    );
    for value in [
        String::from_utf8_lossy(&output.stdout).into_owned(),
        fixture.saved().to_string(),
    ] {
        assert!(!value.contains(key), "raw key leaked");
        assert!(!value.contains(&encoded), "encoded key leaked");
    }
    for request in server.generations() {
        assert!(!request.json().to_string().contains(key));
        assert!(!request.json().to_string().contains(&encoded));
    }
    let saved = fixture.saved();
    let session_id = saved["id"].as_str().unwrap();
    for entry in std::fs::read_dir(
        fixture
            .home
            .join("sessions")
            .join(session_id)
            .join("artifacts"),
    )
    .unwrap()
    {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for secret in [key.as_bytes(), encoded.as_bytes()] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        }
    }
}
#[tokio::test]
async fn failed_stream_does_not_flush_a_partial_credential_lookbehind() {
    let fixture = Fixture::new();
    let server = Server::start(|_, _| support::Response {
        status: 200,
        content_type: "text/event-stream".into(),
        chunks: vec![
            format!(
                "data: {}\n\n",
                json!({"choices":[{"delta":{"content":"BEGIN quality-fixture-"}}]})
            )
            .into_bytes(),
        ],
        chunk_delay: std::time::Duration::ZERO,
        headers: vec![],
    });
    let output = fixture.run(&server, &[], "Inspect safely").await;
    assert!(!output.status.success());
    assert_eq!(server.generations().len(), 1);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("quality-fixture-"));
    assert!(!fixture.saved().to_string().contains("quality-fixture-"));
}
#[tokio::test]
async fn worker_history_redacts_encoded_credentials_before_the_next_generation() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let fixture = Fixture::new();
    let key = quality_support::KEY;
    let encoded: String = key.bytes().map(|b| format!("%{b:02X}")).collect();
    let reflected = encoded.clone();
    let child = Arc::new(AtomicUsize::new(0));
    let count = child.clone();
    let server = Server::start(move |request, _| {
        let value = request.json();
        let messages = value["messages"].as_array().unwrap();
        if messages[1]["content"] == "CHILD_BOUNDED" {
            count.fetch_add(1, Ordering::SeqCst);
            if !messages.iter().any(|m| m["role"] == "tool") {
                return tool_reply(
                    &format!("call-{key}"),
                    "search",
                    &json!({"pattern":reflected}),
                );
            }
            // Inspect the actual next worker request, not only its final report.
            assert!(
                !value.to_string().contains(&reflected),
                "encoded key in worker request"
            );
            return text_reply("Child inspected");
        }
        if let Some(result) = messages.iter().rev().find(|m| m["role"] == "tool") {
            if result["name"] == "spawn_agent" {
                let receipt: Value =
                    serde_json::from_str(result["content"].as_str().unwrap()).unwrap();
                return tool_reply(
                    "wait-1",
                    "wait_agent",
                    &json!({"agent_id":receipt["agent_id"]}),
                );
            }
            text_reply("Collected child result")
        } else {
            tool_reply(
                "spawn-1",
                "spawn_agent",
                &json!({"task":"CHILD_BOUNDED","role":"explorer"}),
            )
        }
    });
    let output = fixture.run(&server, &[], "Delegate safely").await;
    assert_eq!(child.load(Ordering::SeqCst), 2);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    for request in server.generations() {
        assert!(!request.json().to_string().contains(key));
        assert!(!request.json().to_string().contains(&encoded));
    }
    assert_eq!(fixture.saved()["agents"][0]["status"], "completed");
}
