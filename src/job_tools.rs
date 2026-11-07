//! Схемы и строгий разбор аргументов; разрешения и исполнение принадлежат хосту.

use crate::protocol::ToolDefinition;
use anyhow::{Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

const TEXT_LIMIT: usize = 16_384;
const UUID_PATTERN: &str = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobRequest {
    Start(StartArgs),
    Poll(PollArgs),
    Input(InputArgs),
    Stop(StopArgs),
    Handoff(StopArgs),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartArgs {
    pub command: String,
    #[serde(default = "default_lifetime")]
    pub lifetime_minutes: u64,
    #[serde(default = "default_idle")]
    pub idle_minutes: u64,
    #[serde(default)]
    pub stdin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollArgs {
    pub command_id: String,
    #[serde(default)]
    pub stdout_offset: usize,
    #[serde(default)]
    pub stderr_offset: usize,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputArgs {
    pub command_id: String,
    /// Точные байты после wire-нормализации; downstream не добавляет LF повторно.
    pub text: String,
    #[serde(default)]
    pub close: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInputArgs {
    command_id: String,
    text: String,
    #[serde(default)]
    close: bool,
    #[serde(default)]
    append_newline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopArgs {
    pub command_id: String,
}

fn default_lifetime() -> u64 {
    30
}
fn default_idle() -> u64 {
    10
}
fn default_max_bytes() -> usize {
    16_384
}

/// Parse only the named tool's arguments, without coercion or host-side effects.
pub fn parse(name: &str, args: &Value) -> Result<JobRequest> {
    // Serde also accepts positional sequences for structs; tool arguments must be objects.
    ensure!(
        args.is_object(),
        "Аргументы инструмента должны быть JSON-объектом"
    );
    match name {
        "start_command" => {
            let a: StartArgs = serde_json::from_value(args.clone())?;
            validate_text(&a.command)?;
            ensure!(
                !a.command.trim().is_empty(),
                "Команда не должна быть пустой"
            );
            ensure!(
                (1..=120).contains(&a.lifetime_minutes),
                "lifetime_minutes должен быть от 1 до 120"
            );
            ensure!(
                (1..=120).contains(&a.idle_minutes),
                "idle_minutes должен быть от 1 до 120"
            );
            Ok(JobRequest::Start(a))
        }
        "poll_command" => {
            let a: PollArgs = serde_json::from_value(args.clone())?;
            validate_id(&a.command_id)?;
            ensure!(
                (4..=65_536).contains(&a.max_bytes),
                "max_bytes должен быть от 4 до 65536"
            );
            Ok(JobRequest::Poll(a))
        }
        "send_command_input" => {
            let mut a: WireInputArgs = serde_json::from_value(args.clone())?;
            validate_id(&a.command_id)?;
            validate_text(&a.text)?;
            if a.append_newline {
                a.text.push('\n');
            }
            validate_text(&a.text)?;
            ensure!(
                !a.text.is_empty() || a.close || a.append_newline,
                "Пустой text допустим только при close=true или append_newline=true"
            );
            Ok(JobRequest::Input(InputArgs {
                command_id: a.command_id,
                text: a.text,
                close: a.close,
            }))
        }
        "stop_command" | "handoff_command" => {
            let a: StopArgs = serde_json::from_value(args.clone())?;
            validate_id(&a.command_id)?;
            Ok(if name == "handoff_command" {
                JobRequest::Handoff(a)
            } else {
                JobRequest::Stop(a)
            })
        }
        _ => bail!("Неизвестный инструмент управления процессами"),
    }
}

fn validate_text(text: &str) -> Result<()> {
    ensure!(
        text.len() <= TEXT_LIMIT,
        "Текст превышает 16384 байта UTF-8"
    );
    ensure!(!text.contains('\0'), "Текст содержит NUL");
    Ok(())
}

// Canonical textual form: lowercase ASCII, hyphenated, version 4, RFC variant.
// Checking bytes avoids adding a UUID runtime dependency for this parser.
fn validate_id(id: &str) -> Result<()> {
    let b = id.as_bytes();
    let valid = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        })
        && b[14] == b'4'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b');
    ensure!(
        valid,
        "command_id должен быть каноническим UUIDv4 в нижнем регистре"
    );
    Ok(())
}

fn id_schema() -> Value {
    json!({"type":"string", "format":"uuid", "pattern":UUID_PATTERN,
        "minLength":36, "maxLength":36})
}

fn definition(
    name: &str,
    description: &str,
    required: &[&str],
    properties: Value,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        parameters: json!({
            "type":"object", "additionalProperties":false,
            "required":required, "properties":properties
        }),
    }
}

pub(crate) fn is_tool(name: &str) -> bool {
    matches!(
        name,
        "start_command"
            | "poll_command"
            | "send_command_input"
            | "stop_command"
            | "handoff_command"
    )
}

pub(crate) fn offered(writable: bool) -> Vec<ToolDefinition> {
    if writable && cfg!(any(target_os = "macos", target_os = "linux")) {
        definitions()
    } else {
        Vec::new()
    }
}

pub(crate) fn handoff_definition() -> ToolDefinition {
    definition(
        "handoff_command",
        "Передаёт собственную работающую команду родителю по отдельному решению хоста. Доступно только worker. Происхождение, срок действия и прежние артефакты не меняются; после передачи worker не управляет процессом и не получает новый вывод. Ответ status=transferred подтверждает передачу: верните command_id родителю и завершитесь.",
        &["command_id"],
        json!({"command_id":id_schema()}),
    )
}

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        definition(
            "start_command",
            "Запускает команду в оболочке только с разрешения хоста. Доступ к stdin требует отдельного одобрения. Среду и текущий каталог проекта выбирает хост вне этого инструмента; argv, cwd и env не задаются моделью.",
            &["command"],
            json!({
                "command": {"type":"string", "minLength":1, "maxLength":16384,
                    "allOf":[{"pattern":r"[^\s]"},{"not":{"pattern":"\u{0000}"}}],
                    "description":"Непустая и не только пробельная команда; не более 16384 байт UTF-8, без NUL. Хост дополнительно проверяет размер в байтах."},
                "lifetime_minutes":{"type":"integer", "minimum":1, "maximum":120, "default":30},
                "idle_minutes":{"type":"integer", "minimum":1, "maximum":120, "default":10},
                "stdin":{"type":"boolean", "default":false}
            }),
        ),
        definition(
            "poll_command",
            "Читает состояние и вывод существующей команды; не запускает команды, не ожидает и не повторяет запросы.",
            &["command_id"],
            json!({
                "command_id":id_schema(),
                "stdout_offset":{"type":"integer", "minimum":0, "maximum":crate::jobs::STREAM, "default":0},
                "stderr_offset":{"type":"integer", "minimum":0, "maximum":crate::jobs::STREAM, "default":0},
                "max_bytes":{"type":"integer", "minimum":4, "maximum":65536, "default":16384}
            }),
        ),
        definition(
            "send_command_input",
            "Send text only to separately host-approved command stdin. close closes stdin; append_newline adds exactly one LF. No escape decoding. Empty text needs close or append_newline.",
            &["command_id", "text"],
            json!({
                "command_id":id_schema(),
                "text":{"type":"string", "maxLength":16384, "not":{"pattern":"\u{0000}"},
                    "description":"Final UTF-8 payload including added LF: at most 16384 bytes, no NUL; checked by host."},
                "close":{"type":"boolean", "default":false},
                "append_newline":{"type":"boolean", "default":false}
            }),
        ),
        definition(
            "stop_command",
            "Останавливает существующую команду; повторное одобрение запуска не требуется. Проверку полномочий на остановку выполняет хост.",
            &["command_id"],
            json!({"command_id":id_schema()}),
        ),
    ].into_iter().map(|mut d| {
        if d.name == "send_command_input" {
            d.parameters["allOf"] = json!([{
                "if":{"properties":{"text":{"maxLength":0}}, "required":["text"]},
                "then":{"anyOf":[
                    {"properties":{"close":{"const":true}}, "required":["close"]},
                    {"properties":{"append_newline":{"const":true}}, "required":["append_newline"]}
                ]}
            }]);
        }
        d
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "12345678-abcd-4abc-8abc-123456789abc";

    fn base(name: &str) -> Value {
        match name {
            "start_command" => json!({"command":"echo hello"}),
            "send_command_input" => json!({"command_id":ID,"text":"hello"}),
            _ => json!({"command_id":ID}),
        }
    }

    #[test]
    fn handoff_accepts_only_command_id_and_is_not_offered_to_main() {
        assert!(matches!(
            parse("handoff_command", &json!({"command_id":ID})).unwrap(),
            JobRequest::Handoff(_)
        ));
        for field in [
            "actor",
            "epoch",
            "parent_scope_id",
            "lifetime_id",
            "operation_id",
            "owner",
            "approved",
            "cancel",
        ] {
            let mut value = json!({"command_id":ID});
            value[field] = json!("spoofed");
            assert!(parse("handoff_command", &value).is_err());
        }
        assert!(parse("handoff_command", &json!({"command_id":"bad"})).is_err());
        assert!(!offered(true).iter().any(|d| d.name == "handoff_command"));
        assert_eq!(
            handoff_definition().parameters["additionalProperties"],
            false
        );
    }

    #[test]
    fn all_operations_and_defaults() {
        assert_eq!(
            parse("start_command", &base("start_command")).unwrap(),
            JobRequest::Start(StartArgs {
                command: "echo hello".into(),
                lifetime_minutes: 30,
                idle_minutes: 10,
                stdin: false
            })
        );
        assert_eq!(
            parse("poll_command", &base("poll_command")).unwrap(),
            JobRequest::Poll(PollArgs {
                command_id: ID.into(),
                stdout_offset: 0,
                stderr_offset: 0,
                max_bytes: 16384
            })
        );
        assert_eq!(
            parse("send_command_input", &base("send_command_input")).unwrap(),
            JobRequest::Input(InputArgs {
                command_id: ID.into(),
                text: "hello".into(),
                close: false
            })
        );
        assert_eq!(
            parse("stop_command", &base("stop_command")).unwrap(),
            JobRequest::Stop(StopArgs {
                command_id: ID.into()
            })
        );
        assert!(
            parse(
                "send_command_input",
                &json!({"command_id":ID,"text":"","close":true})
            )
            .is_ok()
        );
        assert!(parse("send_command_input", &json!({"command_id":ID,"text":""})).is_err());
    }

    #[test]
    fn rejects_host_fields_on_every_operation() {
        for name in [
            "start_command",
            "poll_command",
            "send_command_input",
            "stop_command",
        ] {
            for field in [
                "env",
                "cwd",
                "argv",
                "actor",
                "turn",
                "lifecycle",
                "owner",
                "lifecycle_owner",
                "pid",
                "PID",
                "wait",
                "retries",
            ] {
                let mut args = base(name);
                args[field] = json!("untrusted");
                assert!(parse(name, &args).is_err(), "{name}: {field}");
            }
        }
    }

    #[test]
    fn strict_types_and_object_shape() {
        for (name, field) in [
            ("start_command", "lifetime_minutes"),
            ("start_command", "idle_minutes"),
            ("poll_command", "stdout_offset"),
            ("poll_command", "stderr_offset"),
            ("poll_command", "max_bytes"),
        ] {
            for bad in [
                json!(-1),
                json!(1.5),
                json!(1.0),
                json!(true),
                json!("4"),
                Value::Null,
            ] {
                let mut args = base(name);
                args[field] = bad;
                assert!(parse(name, &args).is_err(), "{name}: {field}: {args}");
            }
        }
        for (name, field) in [("start_command", "stdin"), ("send_command_input", "close")] {
            for bad in [json!(0), json!(1), json!("true"), Value::Null] {
                let mut args = base(name);
                args[field] = bad;
                assert!(parse(name, &args).is_err());
            }
        }
        for name in [
            "start_command",
            "poll_command",
            "send_command_input",
            "stop_command",
        ] {
            for bad in [json!([]), json!([ID]), json!(null), json!(true), json!({})] {
                assert!(parse(name, &bad).is_err());
            }
        }
        assert!(parse("unknown", &json!({})).is_err());
    }

    #[test]
    fn numeric_bounds() {
        for field in ["lifetime_minutes", "idle_minutes"] {
            for (n, ok) in [(0, false), (1, true), (120, true), (121, false)] {
                let mut args = base("start_command");
                args[field] = json!(n);
                assert_eq!(parse("start_command", &args).is_ok(), ok);
            }
        }
        for (n, ok) in [
            (0, false),
            (3, false),
            (4, true),
            (65536, true),
            (65537, false),
        ] {
            let mut args = base("poll_command");
            args["max_bytes"] = json!(n);
            assert_eq!(parse("poll_command", &args).is_ok(), ok);
        }
        let mut args = base("poll_command");
        args["stdout_offset"] = json!(usize::MAX);
        args["stderr_offset"] = json!(usize::MAX);
        assert!(parse("poll_command", &args).is_ok());
    }

    #[test]
    fn utf8_byte_bounds_and_nul() {
        for (name, field) in [("start_command", "command"), ("send_command_input", "text")] {
            for (text, ok) in [
                ("a".repeat(16384), true),
                ("a".repeat(16385), false),
                ("é".repeat(8192), true),
                ("é".repeat(8193), false),
                ("x\0y".into(), false),
            ] {
                let mut args = base(name);
                args[field] = json!(text);
                assert_eq!(parse(name, &args).is_ok(), ok);
            }
        }
        for blank in ["", " \t\n", "\u{2003}"] {
            assert!(parse("start_command", &json!({"command":blank})).is_err());
        }
    }

    #[test]
    fn canonical_uuid_v4_only() {
        for name in ["poll_command", "send_command_input", "stop_command"] {
            for bad in [
                ID.to_uppercase(),
                ID.replace('-', ""),
                format!(" {ID}"),
                ID.replacen("4abc", "1abc", 1),
                ID.replacen("4abc", "7abc", 1),
                ID.replacen("8abc", "cabc", 1),
                "é".repeat(18),
                String::new(),
            ] {
                let mut args = base(name);
                args["command_id"] = json!(bad);
                assert!(parse(name, &args).is_err());
            }
            for variant in ["8abc", "9abc", "aabc", "babc"] {
                let mut args = base(name);
                args["command_id"] = json!(ID.replacen("8abc", variant, 1));
                assert!(parse(name, &args).is_ok());
            }
        }
    }

    #[test]
    fn poll_schema_offsets_are_bounded_by_the_retained_output_quota() {
        let defs = definitions();
        let poll = defs.iter().find(|d| d.name == "poll_command").unwrap();
        for field in ["stdout_offset", "stderr_offset"] {
            assert_eq!(
                poll.parameters["properties"][field]["maximum"],
                16 * 1024 * 1024
            );
        }
    }

    #[test]
    fn schema_contract() {
        let defs = definitions();
        assert_eq!(defs.len(), 4);
        for d in &defs {
            assert_eq!(d.parameters["type"], "object");
            assert_eq!(d.parameters["additionalProperties"], false);
            assert!(d.parameters["required"].is_array());
            assert!(!d.description.is_empty());
        }
        assert_eq!(defs[0].parameters["required"], json!(["command"]));
        assert_eq!(
            defs[0].parameters["properties"]["lifetime_minutes"]["default"],
            30
        );
        assert_eq!(
            defs[0].parameters["properties"]["idle_minutes"]["default"],
            10
        );
        assert_eq!(defs[0].parameters["properties"]["stdin"]["default"], false);
        assert_eq!(defs[1].parameters["properties"]["max_bytes"]["minimum"], 4);
        assert_eq!(
            defs[1].parameters["properties"]["max_bytes"]["maximum"],
            65536
        );
        assert_eq!(
            defs[1].parameters["properties"]["command_id"]["pattern"],
            UUID_PATTERN
        );
        assert_eq!(
            defs[2].parameters["required"],
            json!(["command_id", "text"])
        );
        assert_eq!(
            defs[2].parameters["properties"]["append_newline"]["type"],
            "boolean"
        );
        assert_eq!(
            defs[2].parameters["properties"]["append_newline"]["default"],
            false
        );
        assert_eq!(
            defs[2].parameters["allOf"][0]["then"]["anyOf"][0]["required"],
            json!(["close"])
        );
        assert_eq!(
            defs[2].parameters["allOf"][0]["then"]["anyOf"][1]["required"],
            json!(["append_newline"])
        );
        assert_eq!(defs[3].parameters["required"], json!(["command_id"]));
    }

    #[test]
    fn explicit_stdin_newline_contract() {
        let cases = [
            (json!({"text":"abc"}), "abc", true),
            (json!({"text":"abc","append_newline":false}), "abc", true),
            (json!({"text":"abc","append_newline":true}), "abc\n", true),
            (json!({"text":"","append_newline":true}), "\n", true),
            (
                json!({"text":"abc\n","append_newline":true}),
                "abc\n\n",
                true,
            ),
            (
                json!({"text":"abc\\n","append_newline":true}),
                "abc\\n\n",
                true,
            ),
            (json!({"text":"","close":true}), "", true),
            (json!({"text":""}), "", false),
        ];
        for (fields, expected, ok) in cases {
            let mut args = json!({"command_id":ID});
            for (key, value) in fields.as_object().unwrap() {
                args[key] = value.clone();
            }
            let parsed = parse("send_command_input", &args);
            assert_eq!(parsed.is_ok(), ok, "{args}");
            if let Ok(JobRequest::Input(input)) = parsed {
                assert_eq!(input.text, expected, "{args}");
            }
        }
        let mut nul = json!({"command_id":ID,"text":"a\0b","append_newline":true});
        assert!(parse("send_command_input", &nul).is_err());
        nul["text"] = json!("a\0b");
        nul["append_newline"] = json!(false);
        assert!(parse("send_command_input", &nul).is_err());

        for (text, append, ok) in [
            ("a".repeat(16383), true, true),
            ("a".repeat(16384), true, false),
            ("a".repeat(16384), false, true),
            (format!("{}a", "é".repeat(8191)), true, true),
            ("é".repeat(8192), true, false),
        ] {
            assert_eq!(
                parse(
                    "send_command_input",
                    &json!({"command_id":ID,"text":text,"append_newline":append})
                )
                .is_ok(),
                ok
            );
        }
        for bad in [
            json!(0),
            json!(1),
            json!("true"),
            Value::Null,
            json!([]),
            json!({}),
        ] {
            assert!(
                parse(
                    "send_command_input",
                    &json!({"command_id":ID,"text":"x","append_newline":bad})
                )
                .is_err()
            );
        }
        assert!(
            parse(
                "send_command_input",
                &json!({"command_id":ID,"text":"x","extra":true})
            )
            .is_err()
        );
    }
}
