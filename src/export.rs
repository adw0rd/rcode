//! Локальный Markdown-экспорт сохранённой части диалога.
use crate::{protocol::Message, state::Session};
use anyhow::{Context, Result, bail, ensure};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const LEGACY_COMPACTION_NOTE: &str =
    "Память предыдущих ходов (может быть неполной; проверь файлы перед изменениями):\n";
const LEGACY_TOOLS_PREFIX: &str =
    "[Результаты завершённых инструментов сокращены командой /compact: ";
const LEGACY_TOOLS_SUFFIX: &str = ". Перед изменениями перечитай файлы.]";

pub(crate) fn write(
    session: &Session,
    argument: &str,
    redact: impl Fn(&str) -> String,
) -> Result<PathBuf> {
    let argument = argument.trim();
    ensure!(
        redact(argument) == argument,
        "Путь экспорта содержит известный секрет; выберите другое имя"
    );
    let filename = parse_path(argument)?;
    let explicit = filename.is_some();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let filename =
        filename.unwrap_or_else(|| PathBuf::from(format!("rcode-export-{timestamp}.md")));
    let path = session.root.join(filename);
    let displayed = path.to_string_lossy();
    ensure!(
        redact(&displayed) == displayed,
        "Путь экспорта содержит известный секрет; выберите другой каталог"
    );
    ensure!(
        !path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .contains(&session.id),
        "Имя файла экспорта не должно содержать ID сессии"
    );
    // Resolve existing parent aliases (including /tmp on macOS) once. The final
    // filename is never followed, and no missing directories are created.
    let parent = path
        .parent()
        .context("Укажите имя файла Markdown")?
        .canonicalize()
        .context("Не удалось открыть каталог экспорта; каталог должен существовать")?;
    ensure!(
        parent.is_dir(),
        "Путь экспорта должен указывать в существующий каталог"
    );
    let path = parent.join(path.file_name().context("Укажите имя файла Markdown")?);
    ensure!(
        redact(&path.to_string_lossy()) == path.to_string_lossy(),
        "Путь экспорта содержит известный секрет; выберите другой каталог"
    );
    if explicit {
        ensure_absent(&path)?;
    }
    // Redact the complete document, including model labels, tool names and JSON
    // escapes, immediately before writing. Do not serialize provider metadata.
    let text = redact(&render(session, &redact));
    let mut temporary = tempfile::Builder::new()
        .prefix(".rcode-export-")
        .tempfile_in(&parent)
        .context("Не удалось создать временный файл экспорта")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("Не удалось установить права файла экспорта")?;
    }
    temporary
        .write_all(text.as_bytes())
        .context("Не удалось записать экспорт")?;
    temporary
        .as_file()
        .sync_all()
        .context("Не удалось сохранить экспорт")?;
    // persist_noclobber reserves the final name atomically; a concurrent file,
    // directory or symlink can never be replaced, including dangling symlinks.
    for index in 0..1000 {
        let target = if explicit || index == 0 {
            path.clone()
        } else {
            parent.join(format!("rcode-export-{timestamp}-{index}.md"))
        };
        match temporary.persist_noclobber(&target) {
            Ok(_) => return Ok(target),
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                if explicit {
                    bail!("Файл экспорта уже существует; выберите другое имя");
                }
                temporary = error.file;
            }
            Err(error) => bail!("Не удалось сохранить экспорт: {}", error.error),
        }
    }
    bail!("Не удалось выбрать свободное имя экспорта; укажите путь явно")
}

fn parse_path(argument: &str) -> Result<Option<PathBuf>> {
    if argument.is_empty() {
        return Ok(None);
    }
    ensure!(
        !argument.chars().any(char::is_control),
        "Путь экспорта не должен содержать управляющие символы"
    );
    let path = if argument.starts_with(['\'', '"']) {
        let quote = argument.chars().next().unwrap();
        ensure!(
            argument.len() >= 2 && argument.ends_with(quote),
            "Закройте кавычки: /export [\"путь с пробелами.md\"]"
        );
        let path = &argument[1..argument.len() - 1];
        ensure!(
            !path.contains(quote),
            "Укажите один путь: /export [\"путь с пробелами.md\"]"
        );
        path
    } else {
        argument
    };
    ensure!(!path.is_empty(), "Укажите непустое имя файла Markdown");
    Ok(Some(PathBuf::from(path)))
}

fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("Файл экспорта уже существует; выберите другое имя"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Не удалось проверить путь экспорта"),
    }
}

fn render(session: &Session, redact: impl Fn(&str) -> String) -> String {
    let clean = |text: &str| redact(text).replace(&session.id, "[ID сессии скрыт]");
    // Older Session::compact stored its local summary as the first assistant
    // message. Match only that exact shape, preserving ordinary quoted text.
    let legacy_summary = session.messages.first().is_some_and(|message| {
        message.role == "assistant"
            && message.tool_calls.is_empty()
            && message.provider_meta.is_none()
            && message
                .content
                .as_deref()
                .is_some_and(|content| content.starts_with(LEGACY_COMPACTION_NOTE))
    });
    // Legacy compaction could also replace any completed tool batch, even
    // without an earlier history summary. Its first line has a fixed wrapper.
    let legacy_tools = |message: &Message| {
        message.role == "assistant"
            && message.tool_calls.is_empty()
            && message.provider_meta.is_none()
            && message
                .content
                .as_deref()
                .and_then(|content| content.lines().next())
                .and_then(|line| line.strip_prefix(LEGACY_TOOLS_PREFIX))
                .is_some_and(|tail| tail.ends_with(LEGACY_TOOLS_SUFFIX))
    };
    let mut output = format!(
        "# Диалог rcode\n\nПровайдер: {}  \nМодель: {}\n\nЭкспорт содержит сохранённую часть диалога и результаты инструментов.\n\n",
        label(&clean(&session.provider.kind.to_string())),
        label(&clean(&session.provider.model))
    );
    if legacy_summary
        || session.messages.iter().any(|message| {
            legacy_tools(message)
                || message
                    .provider_meta
                    .as_ref()
                    .is_some_and(|meta| meta.kind == "rcode_compaction")
        })
    {
        output.push_str("> Часть истории была сокращена; прежние исходные сообщения недоступны. Экспорт содержит только оставшиеся сообщения, без внутренней сводки.\n\n");
    }
    let mut count = 0;
    for (index, message) in session.messages.iter().enumerate() {
        if (legacy_summary && index == 0)
            || legacy_tools(message)
            || message.provider_meta.as_ref().is_some_and(|meta| {
                matches!(meta.kind.as_str(), "rcode_runtime" | "rcode_compaction")
            })
        {
            continue;
        }
        match message.role.as_str() {
            "user" | "assistant" => {
                output.push_str(if message.role == "user" {
                    "## Пользователь\n\n"
                } else if message
                    .provider_meta
                    .as_ref()
                    .is_some_and(|meta| meta.kind == "rcode_user_shell")
                {
                    "## Локальная команда пользователя\n\n"
                } else {
                    "## Ассистент\n\n"
                });
                if let Some(content) = &message.content
                    && !content.is_empty()
                {
                    quoted(&mut output, &clean(content));
                }
                for image in &message.images {
                    quoted(
                        &mut output,
                        &format!(
                            "{}. Байты изображения хранятся в локальной сессии и не включены в Markdown.",
                            clean(&image.label())
                        ),
                    );
                }
                for call in &message.tool_calls {
                    output.push_str(&format!(
                        "### Вызов инструмента: {}\n\n",
                        label(&clean(&call.function.name))
                    ));
                    json_or_text(&mut output, &clean(&call.function.arguments));
                }
                count += 1;
            }
            "tool" => {
                let name = message
                    .name
                    .as_deref()
                    .or_else(|| {
                        session
                            .messages
                            .iter()
                            .flat_map(|message| &message.tool_calls)
                            .find(|call| Some(call.id.as_str()) == message.tool_call_id.as_deref())
                            .map(|call| call.function.name.as_str())
                    })
                    .unwrap_or("без названия");
                output.push_str(&format!(
                    "### Результат инструмента: {}\n\n",
                    label(&clean(name))
                ));
                // is_error is not retained in Message: preserve errors/denials
                // verbatim without guessing whether arbitrary text is success.
                json_or_text(
                    &mut output,
                    &clean(message.content.as_deref().unwrap_or_default()),
                );
                count += 1;
            }
            _ => {}
        }
    }
    if count == 0 {
        output.push_str("В сохранённой части диалога пока нет сообщений.\n");
    }
    output.replace(&session.id, "[ID сессии скрыт]")
}

fn quoted(output: &mut String, text: &str) {
    for line in crate::ui::safe(text).split('\n') {
        output.push_str("> ");
        output.push_str(line);
        output.push('\n');
    }
    output.push('\n');
}

fn label(text: &str) -> String {
    let mut output = String::new();
    for character in crate::ui::safe(text).chars() {
        if character.is_whitespace() {
            output.push(' ');
        } else {
            if "\\`*_{}[]<>()#+-.!|>".contains(character) {
                output.push('\\');
            }
            output.push(character);
        }
    }
    output
}

fn json_or_text(output: &mut String, text: &str) {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        fenced(
            output,
            "json",
            &serde_json::to_string_pretty(&value).expect("JSON value serialization"),
        );
    } else {
        fenced(output, "text", text);
    }
}

fn fenced(output: &mut String, language: &str, text: &str) {
    let text = crate::ui::safe(text);
    let longest = text
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or_default();
    let fence = "`".repeat(3.max(longest.saturating_add(1)));
    output.push_str(&format!("{fence}{language}\n{text}"));
    if !text.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(&format!("{fence}\n\n"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app::Events,
        config::{ProviderKind, ProviderSettings},
        protocol::{Message, ProviderMeta, ToolCall},
    };
    use serde_json::json;
    use std::fs;

    fn session(root: &std::path::Path) -> Session {
        Session::new(root, ProviderSettings::new(ProviderKind::Custom)).unwrap()
    }

    fn render(session: &Session) -> String {
        super::render(session, str::to_owned)
    }

    #[test]
    fn renders_retained_conversation_and_tool_results_without_internal_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        session.title = "PRIVATE_TITLE".into();
        session.provider.model = session.id.clone();
        let call = ToolCall::new("read_file", json!({"path":"main.rs"}));
        session.messages = vec![
            Message::text("system", "PRIVATE_SYSTEM_PROMPT"),
            Message::user(format!("Прочитай файл {}", session.id)),
            Message {
                role: "assistant".into(),
                content: Some("Проверяю исходники".into()),
                tool_calls: vec![call.clone()],
                provider_meta: Some(ProviderMeta {
                    kind: "gigachat".into(),
                    data: json!({"secret":"PRIVATE_PROVIDER_DATA"}),
                }),
                ..Message::default()
            },
            Message::tool(&call, r#"{"content":"fn main() {}"}"#),
            Message::tool(&call, r#"{"error":"denied","hint":"Разрешение не выдано"}"#),
            Message::tool(&call, "old_text не найден; перечитайте файл"),
            Message {
                provider_meta: Some(ProviderMeta {
                    kind: "rcode_runtime".into(),
                    data: json!({}),
                }),
                ..Message::user("PRIVATE_RUNTIME_FEEDBACK")
            },
            Message::text("assistant", "Готово"),
        ];
        let text = render(&session);
        for expected in [
            "# Диалог rcode",
            "Провайдер",
            "custom",
            "Модель",
            "## Пользователь",
            "## Ассистент",
            "Вызов инструмента",
            "read\\_file",
            "main.rs",
            "fn main() {}",
            "denied",
            "Разрешение не выдано",
            "old_text не найден",
            "Готово",
        ] {
            assert!(text.contains(expected), "missing {expected:?}: {text}");
        }
        for hidden in [
            &session.id,
            &session.title,
            "PRIVATE_SYSTEM_PROMPT",
            "PRIVATE_RUNTIME_FEEDBACK",
            "PRIVATE_PROVIDER_DATA",
            &call.id,
        ] {
            assert!(!text.contains(hidden), "leaked {hidden:?}: {text}");
        }
        assert!(
            !text.contains(&session.id.replace('-', "\\-")),
            "Escaping must not expose a session ID: {text}"
        );
    }
    #[test]
    fn manual_shell_is_identified_as_user_action_without_model_attribution() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let call = ToolCall::new("run_command", json!({"command":"pwd"}));
        session.messages = vec![
            Message {
                role: "assistant".into(),
                content: Some("Локальная команда".into()),
                tool_calls: vec![call.clone()],
                provider_meta: Some(ProviderMeta {
                    kind: "rcode_user_shell".into(),
                    data: json!({}),
                }),
                ..Message::default()
            },
            Message::tool(&call, r#"{"stdout":"/project","exit_code":0}"#),
        ];
        let text = render(&session);
        assert!(text.contains("## Локальная команда пользователя"));
        assert!(!text.contains("## Ассистент"));
        assert!(text.contains("pwd") && text.contains("/project"));
    }

    #[test]
    fn message_markdown_renders_inside_quotes_and_unclosed_fences_do_not_hide_next_role() {
        use pulldown_cmark::{Event, Parser, Tag, TagEnd};
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let content = "**Ответ**\n\n- первый пункт\n- второй пункт\n\n```rust\nfn main() {}\n";
        session.messages = vec![
            Message::user(content),
            Message::text("assistant", "После незакрытого кода"),
        ];
        session.provider.model = "<img src=x> *model* [link](url)".into();
        let text = render(&session);
        assert!(text.contains("> **Ответ**\n> \n> - первый пункт"), "{text}");
        let mut quote_depth = 0;
        let mut headings = 0;
        let mut strong = false;
        let mut list = false;
        let mut second_role = false;
        for event in Parser::new(&text) {
            match event {
                Event::Start(Tag::BlockQuote(_)) => quote_depth += 1,
                Event::End(TagEnd::BlockQuote(_)) => quote_depth -= 1,
                Event::Start(Tag::Heading { .. }) if quote_depth == 0 => headings += 1,
                Event::Start(Tag::Strong) if quote_depth > 0 => strong = true,
                Event::Start(Tag::List(_)) if quote_depth > 0 => list = true,
                Event::Text(text) if text.as_ref() == "После незакрытого кода" => {
                    second_role = quote_depth > 0
                }
                Event::Html(html) | Event::InlineHtml(html) => panic!("Unescaped HTML: {html}"),
                _ => {}
            }
        }
        assert!(
            strong && list && second_role,
            "Message Markdown was not retained: {text}"
        );
        assert_eq!(headings, 3, "Unclosed code hid the following role: {text}");
    }

    #[test]
    fn tool_result_fences_safely_contain_nested_fences_and_headings() {
        use pulldown_cmark::{Event, Parser, Tag};
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let content =
            "```rust\nfn main() {}\n```\n````\n# INJECTED_HEADER\n~~~\n<script>evil()</script>";
        let call = ToolCall::new("read_file", json!({"path":"main.rs"}));
        session.messages = vec![Message::tool(&call, content)];
        let text = render(&session);
        assert!(text.contains("`````text\n"), "{text}");
        let mut headings = 0;
        let mut recovered = String::new();
        for event in Parser::new(&text) {
            match event {
                Event::Start(Tag::Heading { .. }) => headings += 1,
                Event::Text(text) => recovered.push_str(&text),
                Event::Html(html) | Event::InlineHtml(html) => panic!("Unescaped HTML: {html}"),
                _ => {}
            }
        }
        assert!(recovered.contains(content));
        assert_eq!(headings, 2);
    }

    #[test]
    fn compaction_is_explained_without_raw_memory_or_old_history_claims() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        session.messages.push(Message {
            provider_meta: Some(ProviderMeta {
                kind: "rcode_compaction".into(),
                data: json!({}),
            }),
            ..Message::user("PRIVATE_RAW_FACTS_JSON restricted_receipts")
        });
        session.messages.push(Message::user("Текущий запрос"));
        let text = render(&session);
        assert!(text.contains("Часть истории была сокращена"), "{text}");
        assert!(text.contains("исходные сообщения недоступны"), "{text}");
        assert!(text.contains("Текущий запрос"));
        assert!(!text.contains("PRIVATE_RAW_FACTS_JSON"));
        assert!(!text.contains("restricted_receipts"));
    }

    #[test]
    fn legacy_first_assistant_compaction_is_hidden_and_explained() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        session.messages = vec![
            Message::text(
                "assistant",
                "Память предыдущих ходов (может быть неполной; проверь файлы перед изменениями):\nPRIVATE_LEGACY_MEMORY",
            ),
            Message::user("Продолжи текущую задачу"),
            Message::text("assistant", "Текущий ответ"),
        ];
        let text = render(&session);
        assert!(text.contains("Часть истории была сокращена"), "{text}");
        assert!(text.contains("исходные сообщения недоступны"), "{text}");
        assert!(!text.contains("PRIVATE_LEGACY_MEMORY"));
        assert!(!text.contains("Память предыдущих ходов"));
        assert_eq!(text.matches("## Ассистент").count(), 1);
        assert!(text.contains("Продолжи текущую задачу") && text.contains("Текущий ответ"));
    }

    #[test]
    fn legacy_prefix_in_ordinary_user_or_assistant_messages_is_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let content = "Память предыдущих ходов (может быть неполной; проверь файлы перед изменениями):\nORDINARY_MESSAGE";
        let cases = [
            vec![Message::user(content)],
            vec![Message::text("assistant", format!("> {content}"))],
            vec![Message::user("Запрос"), Message::text("assistant", content)],
            vec![Message {
                provider_meta: Some(ProviderMeta {
                    kind: "gigachat".into(),
                    data: json!({"native":"hidden"}),
                }),
                ..Message::text("assistant", content)
            }],
            vec![Message {
                tool_calls: vec![ToolCall::new("read_file", json!({"path":"main.rs"}))],
                ..Message::text("assistant", content)
            }],
        ];
        for messages in cases {
            session.messages = messages;
            let text = render(&session);
            assert!(
                text.contains("ORDINARY_MESSAGE"),
                "Ordinary conversation hidden: {text}"
            );
            assert!(
                !text.contains("Часть истории была сокращена"),
                "Incorrect legacy detection: {text}"
            );
        }
    }

    #[test]
    fn legacy_collapsed_tools_without_a_first_summary_are_hidden_and_explained() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let stub = Message::text(
            "assistant",
            "[Результаты завершённых инструментов сокращены командой /compact: write_file, read_file. Перед изменениями перечитай файлы.]\nPRIVATE_LEGACY_TOOL_RECEIPTS",
        );
        for messages in [
            vec![stub.clone()],
            vec![
                Message::user("Текущая задача"),
                stub,
                Message::text("assistant", "Текущий ответ"),
            ],
        ] {
            session.messages = messages;
            let text = render(&session);
            assert!(text.contains("Часть истории была сокращена"), "{text}");
            assert!(text.contains("исходные сообщения недоступны"), "{text}");
            assert!(!text.contains("PRIVATE_LEGACY_TOOL_RECEIPTS"), "{text}");
            assert!(
                !text.contains("Результаты завершённых инструментов"),
                "{text}"
            );
            assert_eq!(
                text.matches("## Ассистент").count(),
                usize::from(session.messages.len() > 1)
            );
        }
    }

    #[test]
    fn ordinary_quoted_or_native_legacy_tool_markers_are_preserved() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let content = "[Результаты завершённых инструментов сокращены командой /compact: read_file. Перед изменениями перечитай файлы.]\nORDINARY_MESSAGE";
        let messages = [
            Message::user(content),
            Message::text("assistant", format!("> {content}")),
            Message::text("assistant", format!("Цитата:\n{content}")),
            Message::text("assistant", content.replace("файлы.]", "файлы?]")),
            Message {
                provider_meta: Some(ProviderMeta {
                    kind: "gigachat".into(),
                    data: json!({"native":"hidden"}),
                }),
                ..Message::text("assistant", content)
            },
            Message {
                tool_calls: vec![ToolCall::new("read_file", json!({"path":"main.rs"}))],
                ..Message::text("assistant", content)
            },
        ];
        for message in messages {
            session.messages = vec![message];
            let text = render(&session);
            assert!(
                text.contains("ORDINARY_MESSAGE"),
                "Ordinary conversation hidden: {text}"
            );
            assert!(
                !text.contains("Часть истории была сокращена"),
                "Incorrect legacy tool marker detection: {text}"
            );
        }
    }

    #[test]
    fn writes_unique_private_files_redacts_the_entire_document_and_keeps_session_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let mut events = Events::new(false);
        let secrets = ["first-export-secret", "second-\"secret"];
        for key in secrets {
            events.remember(key.into());
        }
        session.provider.model = secrets[0].into();
        let call = ToolCall::new(secrets[0], json!({"key": secrets[1]}));
        session.messages = vec![
            Message::user(secrets.join(" ")),
            Message {
                tool_calls: vec![call.clone()],
                ..Message::text("assistant", secrets.join(" "))
            },
            Message::tool(&call, json!({"secret": secrets[1]}).to_string()),
        ];
        let before = serde_json::to_vec(&session).unwrap();
        let first = write(&session, "", |text| events.redact(text)).unwrap();
        let second = write(&session, "", |text| events.redact(text)).unwrap();
        assert_ne!(first, second);
        for path in [first, second] {
            assert_eq!(path.parent(), Some(session.root.as_path()));
            assert!(
                path.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("rcode-export-")
            );
            assert_eq!(path.extension().unwrap(), "md");
            let text = fs::read_to_string(&path).unwrap();
            assert!(text.contains("[REDACTED]"));
            for key in secrets {
                assert!(!text.contains(key));
            }
            assert!(!text.contains("second-\\\"secret"));
            assert!(
                !text.contains("first\\-export\\-secret"),
                "Formatting must not hide a key from redaction: {text}"
            );
            assert!(!text.contains(&session.id));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert_eq!(serde_json::to_vec(&session).unwrap(), before);
    }

    #[test]
    fn accepts_operator_paths_with_spaces_without_creating_missing_directories() {
        let directory = tempfile::tempdir().unwrap();
        let session = session(directory.path());
        let relative = write(&session, "\"мой диалог.md\"", str::to_owned).unwrap();
        assert_eq!(relative, session.root.join("мой диалог.md"));
        let external = tempfile::tempdir().unwrap();
        let absolute = external
            .path()
            .canonicalize()
            .unwrap()
            .join("absolute export.md");
        assert_eq!(
            write(&session, absolute.to_str().unwrap(), str::to_owned).unwrap(),
            absolute
        );
        #[cfg(unix)]
        {
            let alias = session.root.join("directory-alias");
            std::os::unix::fs::symlink(external.path(), &alias).unwrap();
            let path = alias.join("alias export.md");
            let written = write(&session, path.to_str().unwrap(), str::to_owned).unwrap();
            assert_eq!(
                written,
                external
                    .path()
                    .canonicalize()
                    .unwrap()
                    .join("alias export.md")
            );
        }
        assert!(write(&session, "missing/export.md", str::to_owned).is_err());
        assert!(!directory.path().join("missing").exists());
        assert!(write(&session, "\"unclosed.md", str::to_owned).is_err());
        assert!(write(&session, "bad\nname.md", str::to_owned).is_err());
    }

    #[test]
    fn refuses_existing_files_and_directories_without_modifying_them() {
        let directory = tempfile::tempdir().unwrap();
        let session = session(directory.path());
        let existing = directory.path().join("source.rs");
        fs::write(&existing, "unchanged source").unwrap();
        fs::create_dir(directory.path().join("existing-dir")).unwrap();
        assert!(
            write(&session, "source.rs", str::to_owned)
                .unwrap_err()
                .to_string()
                .contains("уже существует")
        );
        assert!(
            write(&session, "existing-dir", str::to_owned)
                .unwrap_err()
                .to_string()
                .contains("уже существует")
        );
        assert_eq!(fs::read_to_string(existing).unwrap(), "unchanged source");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_existing_and_dangling_symlink_targets() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let session = session(directory.path());
        let existing = directory.path().join("credentials.json");
        fs::write(&existing, "private credentials").unwrap();
        symlink(&existing, directory.path().join("link.md")).unwrap();
        symlink(
            directory.path().join("missing"),
            directory.path().join("dangling.md"),
        )
        .unwrap();
        for path in ["link.md", "dangling.md"] {
            assert!(
                write(&session, path, str::to_owned)
                    .unwrap_err()
                    .to_string()
                    .contains("уже существует")
            );
            assert!(
                fs::symlink_metadata(directory.path().join(path))
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
        assert_eq!(fs::read_to_string(existing).unwrap(), "private credentials");
        assert!(!directory.path().join("missing").exists());
    }

    #[test]
    fn never_uses_known_secrets_in_an_export_filename_or_error() {
        let directory = tempfile::tempdir().unwrap();
        let session = session(directory.path());
        let redact = |text: &str| text.replace("export-secret-key", "[REDACTED]");
        let error = write(&session, "export-secret-key.md", redact).unwrap_err();
        assert!(error.to_string().contains("секрет"));
        assert!(!format!("{error:#}").contains("export-secret-key"));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn export_removes_terminal_controls_and_escapes_bidi_from_messages_and_results() {
        let directory = tempfile::tempdir().unwrap();
        let mut session = session(directory.path());
        let dangerous = "before\u{1b}]52;c;clipboard\u{7}\u{202e}after";
        let call = ToolCall::new("read_file", json!({"path":"main.rs"}));
        session.messages = vec![Message::user(dangerous), Message::tool(&call, dangerous)];
        let text = render(&session);
        assert!(!text.contains('\u{1b}') && !text.contains('\u{7}') && !text.contains('\u{202e}'));
        assert!(text.contains("before") && text.contains("after") && text.contains("\\u{202e}"));
    }
}
