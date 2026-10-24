use rcode::{
    config::{ProviderKind, ProviderSettings},
    protocol::Message,
    provider::ProviderClient,
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Barrier, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const IO_TIMEOUT: Duration = Duration::from_secs(3);

struct Incoming {
    body: Value,
    release_body: oneshot::Sender<()>,
}

struct ServerTask(JoinHandle<()>);

impl Drop for ServerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn read_request(socket: &mut TcpStream) -> Value {
    let mut bytes = Vec::new();
    let split = loop {
        let mut buffer = [0_u8; 4096];
        let count = socket.read(&mut buffer).await.unwrap();
        assert!(count > 0, "fixture request header ended early");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 64 * 1024, "fixture request is too large");
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..split]).unwrap();
    let length = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .expect("fixture request must contain content-length");
    assert!(length <= 16 * 1024, "fixture body is too large");
    while bytes.len() < split + length {
        let mut buffer = [0_u8; 4096];
        let count = socket.read(&mut buffer).await.unwrap();
        assert!(count > 0, "fixture request body ended early");
        bytes.extend_from_slice(&buffer[..count]);
        assert!(bytes.len() <= 80 * 1024, "fixture request is too large");
    }
    serde_json::from_slice(&bytes[split..split + length]).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yandex_clones_share_two_generation_slots_until_response_body_finishes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/v1", listener.local_addr().unwrap());
    let (incoming, mut received) = mpsc::channel::<Incoming>(3);
    let mut server = ServerTask(tokio::spawn(async move {
        let mut connections = JoinSet::new();
        for _ in 0..3 {
            let (mut socket, _) = timeout(IO_TIMEOUT, listener.accept())
                .await
                .expect("fixture did not receive the expected connection")
                .unwrap();
            let incoming = incoming.clone();
            connections.spawn(async move {
                let body = timeout(IO_TIMEOUT, read_request(&mut socket))
                    .await
                    .expect("fixture request read timed out");
                let reply = json!({
                    "choices": [{"message": {"role": "assistant", "content": "completed"},
                                 "finish_reason": "stop"}]
                })
                .to_string();
                // Headers are delivered immediately. Holding only the JSON body
                // catches a permit incorrectly released after send()/headers.
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                socket.write_all(header.as_bytes()).await.unwrap();
                let (release_body, held) = oneshot::channel();
                incoming.send(Incoming { body, release_body }).await.unwrap();
                if timeout(IO_TIMEOUT, held).await.is_ok_and(|held| held.is_ok()) {
                    socket.write_all(reply.as_bytes()).await.unwrap();
                }
            });
        }
        while let Some(result) = connections.join_next().await {
            result.unwrap();
        }
    }));

    let mut settings = ProviderSettings::new(ProviderKind::Yandex);
    settings.base_url = Some(endpoint);
    settings.folder_id = Some("fixture-folder".into());
    settings.model = "fixture-model".into();
    settings.stream = false;
    settings.idle_timeout_secs = 3;
    let client = ProviderClient::new(settings, "concurrency-fixture-key".into()).unwrap();
    let start = Arc::new(Barrier::new(4));
    let mut completions = JoinSet::new();
    for index in 0..3 {
        let mut client = client.clone();
        let start = start.clone();
        completions.spawn(async move {
            start.wait().await;
            client
                .complete(
                    &[Message::user(format!("request-{index}"))],
                    &[],
                    &mut |_| {},
                )
                .await
        });
    }
    start.wait().await;

    let first = timeout(IO_TIMEOUT, received.recv()).await.unwrap().unwrap();
    let second = timeout(IO_TIMEOUT, received.recv()).await.unwrap().unwrap();
    for request in [&first, &second] {
        assert_eq!(request.body["model"], "gpt://fixture-folder/fixture-model");
    }
    let early_third = timeout(Duration::from_millis(250), received.recv()).await;
    assert!(
        early_third.is_err(),
        "third cloned Yandex request reached the API before either response body completed"
    );

    first.release_body.send(()).unwrap();
    let third = timeout(IO_TIMEOUT, received.recv())
        .await
        .expect("third generation did not acquire the released slot")
        .unwrap();
    second.release_body.send(()).unwrap();
    third.release_body.send(()).unwrap();
    let mut completed = 0;
    while let Some(result) = timeout(IO_TIMEOUT, completions.join_next()).await.unwrap() {
        assert_eq!(result.unwrap().unwrap().content, "completed");
        completed += 1;
    }
    assert_eq!(completed, 3);
    timeout(IO_TIMEOUT, &mut server.0).await.unwrap().unwrap();
}
