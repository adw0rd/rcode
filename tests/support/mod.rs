//! Loopback HTTP fixture for local-server tests: routes by method and path,
//! records every request and counts overlapping generations.
#![allow(dead_code)]
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub received: Instant,
}

impl Request {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    pub fn authorization(&self) -> Option<&str> {
        self.headers.get("authorization").map(String::as_str)
    }
    pub fn is_generation(&self) -> bool {
        self.method == "POST" && self.path.ends_with("/chat/completions")
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub chunks: Vec<Vec<u8>>,
    pub chunk_delay: Duration,
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json".into(),
            chunks: vec![value.to_string().into_bytes()],
            chunk_delay: Duration::ZERO,
            headers: vec![],
        }
    }
    /// One SSE event per JSON value, then `[DONE]`; each event is a chunk.
    pub fn sse(events: &[Value]) -> Self {
        let mut chunks: Vec<Vec<u8>> = events
            .iter()
            .map(|event| format!("data: {event}\n\n").into_bytes())
            .collect();
        chunks.push(b"data: [DONE]\n\n".to_vec());
        Self {
            status: 200,
            content_type: "text/event-stream".into(),
            chunks,
            chunk_delay: Duration::ZERO,
            headers: vec![],
        }
    }
    pub fn delayed(mut self, delay: Duration) -> Self {
        self.chunk_delay = delay;
        self
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Final assistant answer as SSE deltas.
pub fn text_reply(text: &str) -> Response {
    Response::sse(&[
        serde_json::json!({"choices":[{"index":0,"delta":{"role":"assistant","content":text}}]}),
        serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":120,"completion_tokens":5}}),
    ])
}

/// A single tool call streamed with arguments split into tiny pieces.
pub fn tool_reply(id: &str, name: &str, arguments: &Value) -> Response {
    let arguments = arguments.to_string();
    let mut events = vec![
        serde_json::json!({"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":id,"type":"function","function":{"name":name,"arguments":""}}]}}]}),
    ];
    for piece in arguments.as_bytes().chunks(2) {
        let piece = String::from_utf8_lossy(piece).into_owned();
        events.push(serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":piece}}]}}]}));
    }
    events
        .push(serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}));
    Response::sse(&events)
}

type Handler = dyn Fn(&Request, usize) -> Response + Send + Sync;

pub struct Server {
    pub url: String,
    pub port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    accept: Option<thread::JoinHandle<()>>,
}

impl Server {
    /// `handler(request, index)` gets the 0-based index among generations
    /// (POST …/chat/completions) or other requests respectively.
    pub fn start(handler: impl Fn(&Request, usize) -> Response + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<Handler> = Arc::new(handler);
        let generations = Arc::new(AtomicUsize::new(0));
        let others = Arc::new(AtomicUsize::new(0));
        let accept = {
            let (requests, active, max_active, stop) = (
                requests.clone(),
                active.clone(),
                max_active.clone(),
                stop.clone(),
            );
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            let (requests, active, max_active, handler, generations, others) = (
                                requests.clone(),
                                active.clone(),
                                max_active.clone(),
                                handler.clone(),
                                generations.clone(),
                                others.clone(),
                            );
                            thread::spawn(move || {
                                serve(
                                    socket,
                                    &requests,
                                    &active,
                                    &max_active,
                                    &*handler,
                                    &generations,
                                    &others,
                                )
                            });
                        }
                        Err(_) => thread::sleep(Duration::from_millis(2)),
                    }
                }
            })
        };
        Self {
            url: format!("http://127.0.0.1:{port}"),
            port,
            requests,
            active,
            max_active,
            stop,
            accept: Some(accept),
        }
    }

    pub fn base(&self) -> String {
        format!("{}/v1", self.url)
    }

    pub fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    pub fn generations(&self) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(Request::is_generation)
            .collect()
    }

    pub fn max_concurrent_generations(&self) -> usize {
        self.max_active.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

fn serve(
    mut socket: TcpStream,
    requests: &Mutex<Vec<Request>>,
    active: &AtomicUsize,
    max_active: &AtomicUsize,
    handler: &Handler,
    generations: &AtomicUsize,
    others: &AtomicUsize,
) {
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let split = loop {
        let mut buffer = [0; 4096];
        let Ok(count) = socket.read(&mut buffer) else {
            return;
        };
        if count == 0 {
            return;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = String::from_utf8_lossy(&bytes[..split]).into_owned();
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or_default().split_whitespace();
    let method = first.next().unwrap_or_default().to_owned();
    let path = first.next().unwrap_or_default().to_owned();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    while bytes.len() < split + length {
        let mut buffer = [0; 8192];
        match socket.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
        }
    }
    let request = Request {
        method,
        path,
        headers,
        body: bytes[split..split + length].to_vec(),
        received: Instant::now(),
    };
    let generation = request.is_generation();
    if generation {
        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
        max_active.fetch_max(now, Ordering::SeqCst);
    }
    requests.lock().unwrap().push(request.clone());
    let index = if generation { generations } else { others }.fetch_add(1, Ordering::SeqCst);
    let response = handler(&request, index);
    let mut head = format!(
        "HTTP/1.1 {} fixture\r\nContent-Type: {}\r\nConnection: close\r\n",
        response.status, response.content_type
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let mut ok = socket.write_all(head.as_bytes()).is_ok();
    for chunk in &response.chunks {
        if !ok {
            break;
        }
        if !response.chunk_delay.is_zero() {
            thread::sleep(response.chunk_delay);
        }
        ok = socket
            .write_all(chunk)
            .and_then(|()| socket.flush())
            .is_ok();
    }
    let _ = socket.shutdown(std::net::Shutdown::Both);
    if generation {
        active.fetch_sub(1, Ordering::SeqCst);
    }
}
