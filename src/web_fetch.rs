//! Инструмент `web_fetch`: GET-запрос к http(s)-странице, текст — в контекст
//! модели. Только чтение, без диалогов разрешений: как `search`. Запросы не
//! несут ключей rcode; TLS не отключается; редиректы ограничены и каждый hop
//! проверяется по схеме. Размер ответа ограничен, HTML приводится к тексту.
use crate::protocol::{ToolDefinition, ToolOutcome};
use serde_json::{Value, json};
use std::sync::OnceLock;
use std::time::Duration;

pub(crate) const TOOL_NAME: &str = "web_fetch";
/// Cap of the downloaded body before text conversion.
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Cap of the text admitted to the model receipt.
const MAX_TEXT_CHARS: usize = 50_000;
const USER_AGENT: &str = "rcode/0.8 (+https://github.com/adw0rd/rcode)";

pub(crate) fn definition() -> ToolDefinition {
    ToolDefinition {
        name: TOOL_NAME.into(),
        description: "Получить содержимое веб-страницы по URL (http/https): GET без ключей и авторизации, текст в контекст. HTML приводится к тексту; скрипты и стили отбрасываются. Только чтение. Для не-текстовых файлов (изображения, архивы) используйте shell-инструменты."
            .into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 8, "maxLength": 2048}
            },
            "required": ["url"],
            "additionalProperties": false
        }),
    }
}

fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 5 {
                    attempt.error("слишком много перенаправлений")
                } else if attempt.url().scheme() != "https" && attempt.url().scheme() != "http" {
                    attempt.error("перенаправление на не-http(s) адрес отклонено")
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .expect("конфигурация HTTP-клиента web_fetch")
    })
}

fn validate_url(input: &str) -> Result<reqwest::Url, String> {
    if input.chars().any(char::is_control) || input.trim() != input {
        return Err("URL содержит пробельные или управляющие символы".into());
    }
    let url = reqwest::Url::parse(input).map_err(|error| format!("Некорректный URL: {error}"))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err("Поддерживаются только http и https".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL с логином и паролем не принимается".into());
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("В URL нет узла".into());
    }
    Ok(url)
}

fn text_allowed(content_type: &str) -> bool {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media.starts_with("text/")
        || matches!(
            media.as_str(),
            "application/json"
                | "application/xml"
                | "application/javascript"
                | "application/x-yaml"
                | "application/yaml"
        )
        || media.ends_with("+xml")
        || media.ends_with("+json")
}

/// Comments, script and style bodies are dropped, block tags become line
/// breaks, remaining tags are stripped, entities are decoded.
pub fn html_to_text(html: &str) -> String {
    let mut cleaned = String::with_capacity(html.len());
    drop_block(&html.to_ascii_lowercase(), html, "script", &mut cleaned);
    let without_script = cleaned;
    cleaned = String::with_capacity(without_script.len());
    drop_block(
        &without_script.to_ascii_lowercase(),
        &without_script,
        "style",
        &mut cleaned,
    );
    let without_style = cleaned;
    cleaned = String::with_capacity(without_style.len());
    drop_block(
        &without_style.to_ascii_lowercase(),
        &without_style,
        "noscript",
        &mut cleaned,
    );
    let without_comments = remove_comments(&cleaned);
    let tagged = strip_tags(&without_comments);
    let decoded = decode_entities(&tagged);
    collapse_blank_lines(&decoded)
}

/// Removes `<tag …>…</tag>` blocks, case-insensitive, without nesting.
fn drop_block(source: &str, original: &str, tag: &str, output: &mut String) {
    let mut scan = 0;
    let mut emit_from = 0;
    while let Some(start) = source[scan..].find('<') {
        let absolute = scan + start;
        let rest = &source[absolute..];
        if !rest[1..]
            .trim_start()
            .strip_prefix(tag)
            .is_some_and(|after| after.starts_with(['>', ' ', '\t', '\n', '\r', '/']))
        {
            scan = absolute + 1;
            continue;
        }
        let Some(close_marker) = rest.find("</") else {
            break;
        };
        let close = absolute + close_marker;
        let Some(end_rel) = source[close..].find('>') else {
            break;
        };
        output.push_str(&original[emit_from..absolute]);
        scan = close + end_rel + 1;
        emit_from = scan;
    }
    output.push_str(&original[emit_from..]);
}

fn remove_comments(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("<!--") {
        result.push_str(&rest[..start]);
        rest = &rest[start..];
        match rest.find("-->") {
            Some(end) => rest = &rest[end + 3..],
            None => return result,
        }
    }
    result.push_str(rest);
    result
}

const BLOCK_TAGS: &[&str] = &[
    "br",
    "p",
    "div",
    "li",
    "tr",
    "td",
    "th",
    "ul",
    "ol",
    "table",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "section",
    "article",
    "header",
    "footer",
    "blockquote",
    "pre",
    "hr",
    "dt",
    "dd",
];

fn strip_tags(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut inside = false;
    let mut quote = '\0';
    let mut tag = String::new();
    for ch in source.chars() {
        if inside {
            if quote != '\0' {
                if ch == quote {
                    quote = '\0';
                }
            } else if ch == '"' || ch == '\'' {
                quote = ch;
            } else if ch == '>' {
                inside = false;
                let name: String = tag
                    .trim_start_matches('/')
                    .chars()
                    .take_while(char::is_ascii_alphanumeric)
                    .map(|ch| ch.to_ascii_lowercase())
                    .collect();
                tag.clear();
                if BLOCK_TAGS.contains(&name.as_str()) {
                    result.push('\n');
                } else {
                    result.push(' ');
                }
            } else if tag.len() < 16 {
                tag.push(ch);
            }
            continue;
        }
        if ch == '<' {
            inside = true;
            tag.clear();
            continue;
        }
        result.push(ch);
    }
    result
}

fn decode_entities(source: &str) -> String {
    if !source.contains('&') {
        return source.to_owned();
    }
    let mut result = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find('&') {
        result.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest.find(';').unwrap_or(0);
        if end == 0 || end > 12 {
            result.push('&');
            rest = &rest[1..];
            continue;
        }
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            "mdash" => Some('—'),
            "ndash" => Some('–'),
            "hellip" => Some('…'),
            "laquo" => Some('«'),
            "raquo" => Some('»'),
            "ldquo" => Some('“'),
            "rdquo" => Some('”'),
            "rsquo" => Some('’'),
            "lsquo" => Some('‘'),
            "copy" => Some('©'),
            "reg" => Some('®'),
            "trade" => Some('™'),
            _ => {
                if let Some(hex) = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                {
                    u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                } else if let Some(decimal) = entity.strip_prefix('#') {
                    decimal.parse::<u32>().ok().and_then(char::from_u32)
                } else {
                    None
                }
            }
        };
        match decoded {
            Some(ch) => {
                result.push(ch);
                rest = &rest[end + 1..];
            }
            None => {
                result.push('&');
                rest = &rest[1..];
            }
        }
    }
    result.push_str(rest);
    result
}

fn collapse_blank_lines(source: &str) -> String {
    let mut result = String::with_capacity(source.len());
    let mut blank = 0;
    for line in source.lines() {
        let collapsed: String = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if collapsed.is_empty() {
            blank += 1;
            if blank > 1 {
                continue;
            }
        } else {
            blank = 0;
        }
        result.push_str(&collapsed);
        result.push('\n');
    }
    result.trim_end().to_owned()
}

fn truncate(text: &str) -> (String, bool) {
    if text.chars().count() <= MAX_TEXT_CHARS {
        return (text.to_owned(), false);
    }
    let head: String = text.chars().take(MAX_TEXT_CHARS).collect();
    (
        format!(
            "{head}\n[rcode: текст страницы укорочен до {MAX_TEXT_CHARS} символов; запросите более конкретный источник или раздел]"
        ),
        true,
    )
}

pub(crate) async fn execute(
    args: &Value,
    cancel: &tokio_util::sync::CancellationToken,
) -> ToolOutcome {
    let Some(url) = args.get("url").and_then(Value::as_str) else {
        return ToolOutcome::error("Некорректный JSON аргументов; нужен url");
    };
    let url = match validate_url(url) {
        Ok(url) => url,
        Err(message) => {
            return ToolOutcome::error(
                json!({"error": "invalid_url", "message": message}).to_string(),
            );
        }
    };
    let request = async {
        let response = match client().get(url.clone()).send().await {
            Ok(response) => response,
            Err(error) => {
                return ToolOutcome::error(
                    json!({"error": "fetch_failed", "message": format!("{error}")}).to_string(),
                );
            }
        };
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        if !response.status().is_success() {
            return ToolOutcome::error(
                json!({"error": "http_error", "status": status, "url": url.as_str(), "message": "Сервер вернул ошибку; текст тела не читается как страница"}).to_string(),
            );
        }
        if let Some(length) = response.content_length()
            && length as usize > MAX_BODY_BYTES
        {
            return ToolOutcome::error(
                json!({"error": "too_large", "status": status, "bytes": length}).to_string(),
            );
        }
        if !text_allowed(&content_type) {
            return ToolOutcome::error(
                json!({"error": "unsupported_content_type", "status": status, "content_type": content_type, "message": "Страница не является текстом; для файлов используйте shell-инструменты"}).to_string(),
            );
        }
        let body = match response.text().await {
            Ok(body) => body,
            Err(error) => {
                return ToolOutcome::error(
                    json!({"error": "fetch_failed", "message": format!("{error}")}).to_string(),
                );
            }
        };
        if body.len() > MAX_BODY_BYTES {
            return ToolOutcome::error(
                json!({"error": "too_large", "status": status, "bytes": body.len()}).to_string(),
            );
        }
        let is_html = content_type.contains("html") || body.trim_start().starts_with('<');
        let text = if is_html { html_to_text(&body) } else { body };
        let (content, truncated) = truncate(&text);
        let mut receipt = json!({
            "url": url.as_str(),
            "status": status,
            "content_type": content_type,
            "bytes": content.len(),
            "content": content,
        });
        if truncated {
            receipt["truncated"] = json!(true);
        }
        ToolOutcome::success(receipt.to_string())
    };
    tokio::select! {
        outcome = request => outcome,
        _ = cancel.cancelled() => ToolOutcome::error(
            json!({"error": "interrupted", "message": "Загрузка страницы отменена"}).to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_url_accepts_http_and_https_only() {
        assert!(validate_url("https://example.com/page?q=1").is_ok());
        assert!(validate_url("http://example.com").is_ok());
        for bad in [
            "ftp://example.com",
            "file:///etc/passwd",
            "https://user:token@example.com",
            "https://user@example.com",
            "https://exa mple.com",
            "not a url",
            "https://example.com\n",
        ] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn html_to_text_drops_script_style_and_comments() {
        let html = "<!doctype html>\n<html><head>\n<title>Заголовок</title>\n<script>var a=1<2&&3>1;</script>\n<style>body{color:red}</style>\n</head>\n<body>\n<!-- скрытый комментарий -->\n<p>Первый   абзац &amp; ещё &mdash; текст</p>\n<div>Второй<br>строкой</div>\n<noscript>без js</noscript>\n<img src=\"a.png\" alt=\"x\">\n</body></html>\n";
        let text = html_to_text(html);
        assert!(text.contains("Заголовок"), "{text}");
        assert!(text.contains("Первый абзац & ещё — текст"), "{text}");
        assert!(text.contains("Второй\nстрокой"), "{text}");
        assert!(!text.contains("var a"), "{text}");
        assert!(!text.contains("color:red"), "{text}");
        assert!(!text.contains("скрытый"), "{text}");
        assert!(!text.contains("без js"), "{text}");
        assert!(!text.contains("img"), "{text}");
        assert!(!text.contains("\n\n\n"), "{text}");
    }

    #[test]
    fn html_to_text_handles_angle_brackets_in_attributes() {
        let text = html_to_text("<a data-x=\"a>b\">текст</a>");
        assert_eq!(text, "текст");
    }

    #[test]
    fn numeric_entities_are_decoded() {
        assert_eq!(decode_entities("&#65; &#x42; &#x44D;"), "A B э");
        assert_eq!(
            decode_entities("&#zz; &unknown; a&b"),
            "&#zz; &unknown; a&b"
        );
    }

    #[test]
    fn truncate_marks_the_cut() {
        let (text, truncated) = truncate(&"x".repeat(MAX_TEXT_CHARS));
        assert!(!truncated);
        assert_eq!(text.chars().count(), MAX_TEXT_CHARS);
        let (text, truncated) = truncate(&"x".repeat(MAX_TEXT_CHARS + 1));
        assert!(truncated);
        assert!(text.contains("[rcode:"));
    }

    #[test]
    fn text_allowed_accepts_text_and_rejects_binaries() {
        for good in [
            "text/html; charset=utf-8",
            "text/plain",
            "application/json",
            "application/atom+xml",
            "application/vnd.api+json",
            "application/javascript",
        ] {
            assert!(text_allowed(good), "{good}");
        }
        for bad in [
            "image/png",
            "application/pdf",
            "application/octet-stream",
            "",
        ] {
            assert!(!text_allowed(bad), "{bad}");
        }
    }

    async fn serve_once(responses: Vec<Vec<u8>>) -> (u16, std::net::SocketAddr) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buffer = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut buffer);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        (address.port(), address)
    }

    #[tokio::test]
    async fn fetches_html_and_reports_the_receipt() {
        let body = "<html><body><h1>Привет</h1><p>Мир</p></body></html>";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut response = head.into_bytes();
        response.extend_from_slice(body.as_bytes());
        let (port, _) = serve_once(vec![response]).await;
        let outcome = execute(
            &json!({"url": format!("http://127.0.0.1:{port}/page")}),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(!outcome.is_error, "{}", outcome.content);
        let receipt: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(receipt["status"], 200);
        assert!(receipt["content"].as_str().unwrap().contains("Привет"));
        assert!(receipt["content"].as_str().unwrap().contains("Мир"));
        assert!(!receipt["content"].as_str().unwrap().contains("<h1>"));
    }

    #[tokio::test]
    async fn http_error_and_content_type_are_honest_errors() {
        let (port, _) = serve_once(vec![b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno".to_vec()]).await;
        let outcome = execute(
            &json!({"url": format!("http://127.0.0.1:{port}/missing")}),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        let receipt: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(receipt["error"], "http_error");
        assert_eq!(receipt["status"], 404);

        let (port, _) = serve_once(vec![b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\nConnection: close\r\n\r\nPNG!".to_vec()]).await;
        let outcome = execute(
            &json!({"url": format!("http://127.0.0.1:{port}/img")}),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        let receipt: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(receipt["error"], "unsupported_content_type");
    }

    #[tokio::test]
    async fn json_pages_pass_through_without_html_conversion() {
        let body = "{\"key\": \"значение\"}";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut response = head.into_bytes();
        response.extend_from_slice(body.as_bytes());
        let (port, _) = serve_once(vec![response]).await;
        let outcome = execute(
            &json!({"url": format!("http://127.0.0.1:{port}/api")}),
            &tokio_util::sync::CancellationToken::new(),
        )
        .await;
        assert!(!outcome.is_error, "{}", outcome.content);
        let receipt: Value = serde_json::from_str(&outcome.content).unwrap();
        assert_eq!(receipt["content"], "{\"key\": \"значение\"}");
    }
}
