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
    pub text: String,
    #[serde(default)]
    pub close: bool,
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
            let a: InputArgs = serde_json::from_value(args.clone())?;
            validate_id(&a.command_id)?;
            validate_text(&a.text)?;
            ensure!(
                !a.text.is_empty() || a.close,
                "Пустой text допустим только при close=true"
            );
            Ok(JobRequest::Input(a))
        }
        "stop_command" => {
            let a: StopArgs = serde_json::from_value(args.clone())?;
            validate_id(&a.command_id)?;
            Ok(JobRequest::Stop(a))
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
        "start_command" | "poll_command" | "send_command_input" | "stop_command"
    )
}

pub(crate) fn offered(writable: bool) -> Vec<ToolDefinition> {
    if writable && cfg!(any(target_os = "macos", target_os = "linux")) {
        definitions()
    } else {
        Vec::new()
    }
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
                "stdout_offset":{"type":"integer", "minimum":0, "maximum":usize::MAX, "default":0},
                "stderr_offset":{"type":"integer", "minimum":0, "maximum":usize::MAX, "default":0},
                "max_bytes":{"type":"integer", "minimum":4, "maximum":65536, "default":16384}
            }),
        ),
        definition(
            "send_command_input",
            "Передаёт текст в stdin существующей команды только при отдельно одобренном хостом доступе к stdin; close закрывает ввод. Пустой текст допустим лишь с close=true.",
            &["command_id", "text"],
            json!({
                "command_id":id_schema(),
                "text":{"type":"string", "maxLength":16384, "not":{"pattern":"\u{0000}"},
                    "description":"Не более 16384 байт UTF-8, без NUL; хост дополнительно проверяет размер в байтах."},
                "close":{"type":"boolean", "default":false}
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
                "then":{"properties":{"close":{"const":true}}, "required":["close"]}
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
            defs[2].parameters["allOf"][0]["then"]["required"],
            json!(["close"])
        );
        assert_eq!(defs[3].parameters["required"], json!(["command_id"]));
    }
}
