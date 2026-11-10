//! Host runner is an explicit optional dependency. No project code runs on host.
use super::{json as strict_json, manifest};
use crate::{
    app::Events,
    cli::{Cli, EvalRun},
    config::{ConfigStore, ProviderKind},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const HOST: &str = include_str!("../../evals/host.py");
const PROVIDER: &str = include_str!("../../evals/host_provider.py");
const DOCKER: &str = include_str!("../../evals/host_docker.py");
const SNAPSHOT: &str = include_str!("../../evals/host_snapshot.py");
const POLICY: &str = include_str!("../../evals/policy.py");
const RUNTIME: &str = include_str!("../../evals/runtime/runtime.py");
const HTTP: &str = include_str!("../../evals/runtime/runtime_http.py");
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut f = fs::File::open(path)?;
    ensure!(f.metadata()?.is_file(), "Ожидался обычный файл");
    let mut out = Vec::new();
    (&mut f).take((limit + 1) as u64).read_to_end(&mut out)?;
    ensure!(out.len() <= limit, "Превышен размер файла eval");
    Ok(out)
}
fn executable(path: &Path) -> Result<PathBuf> {
    let selected = if path.is_absolute() || path.components().count() > 1 {
        path.to_owned()
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| p.join(path))
            .find(|p| p.is_file())
            .context("Не найден Python/Docker; укажите абсолютный путь")?
    };
    // Validate the target, preserve argv[0]: OrbStack and other multicall
    // executables dispatch by the symlink's invocation name.
    let absolute = std::path::absolute(selected)?;
    ensure!(
        fs::canonicalize(&absolute)?.is_file(),
        "Не найден исполняемый файл"
    );
    Ok(absolute)
}
#[cfg(unix)]
fn mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
#[cfg(not(unix))]
fn mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}
fn fixture(root: &Path, files: &[manifest::Fixture]) -> Result<()> {
    fs::create_dir(root)?;
    for f in files {
        let dest = root.join(&f.path);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
        }
        fs::write(&dest, &f.bytes)?;
        mode(&dest, if f.executable { 0o555 } else { 0o444 })?;
    }
    fn seal(path: &Path) -> Result<()> {
        for e in fs::read_dir(path)? {
            let p = e?.path();
            if p.is_dir() {
                seal(&p)?;
            }
        }
        mode(path, 0o755)
    }
    seal(root)
}
// Oracle is Deserialize-only. Only this explicit trusted-host DTO contains
// expectations; the host constructs a different ProbeRequest for the helper.
fn oracle(value: &manifest::Oracle) -> Value {
    let commands: Vec<_> = value
        .prepare
        .iter()
        .map(|c| json!({"argv":c.argv,"stdin":c.stdin,"timeout_secs":c.timeout_secs}))
        .collect();
    let checks:Vec<_>=value.checks.iter().map(|c|{let mut v=json!({"id":c.id,"argv":c.argv,"stdin":c.stdin,"timeout_secs":c.timeout_secs,"expected_exit":c.expected_exit});
        if let Some(s)=&c.expected_stdout{v["expected_stdout"]=json!(s);}else{v["expected_json"]=c.expected_json.clone().expect("validated expectation");}v}).collect();
    json!({"prepare":commands,"checks":checks})
}
#[cfg(unix)]
fn snapshots_root(path: Option<&Path>) -> Result<Option<String>> {
    use std::os::unix::fs::DirBuilderExt;
    let Some(path) = path else { return Ok(None) };
    let name = path.file_name().context("Нужен новый каталог snapshots")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let expected = fs::canonicalize(parent)?.join(name);
    let mut builder = fs::DirBuilder::new();
    builder
        .mode(0o700)
        .create(path)
        .context("Создание нового каталога snapshots")?;
    let root = fs::canonicalize(path)?;
    ensure!(root == expected, "Путь snapshots изменился при создании");
    let root = root
        .to_str()
        .context("Путь snapshots должен быть UTF-8")?
        .to_owned();
    ensure!(
        !root.contains(','),
        "Путь snapshots не должен содержать запятую"
    );
    Ok(Some(root))
}

#[cfg(not(unix))]
fn snapshots_root(_path: Option<&Path>) -> Result<Option<String>> {
    anyhow::bail!("Защищённый eval поддерживается только на Unix host")
}

fn attach_snapshots(invocation: &mut Value, snapshots: Option<String>) {
    if let Some(path) = snapshots {
        invocation["snapshots"] = json!(path);
    }
}

#[derive(Debug, Clone)]
struct DiagnosticsTarget {
    path: String,
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
fn normalized_output(path: &Path) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    ensure!(
        !path.as_os_str().as_bytes().ends_with(b"/"),
        "Diagnostics должен быть файлом, не каталогом"
    );
    let name = path.file_name().context("Нужен путь к новому файлу")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(fs::canonicalize(parent)?.join(name))
}

#[cfg(unix)]
fn diagnostics_target(
    path: Option<&Path>,
    report: &Path,
    snapshots: Option<&str>,
) -> Result<Option<DiagnosticsTarget>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let Some(path) = path else {
        return Ok(None);
    };
    let expected = normalized_output(path)?;
    ensure!(
        expected != normalized_output(report)?,
        "Diagnostics и report должны различаться"
    );
    if let Some(root) = snapshots {
        ensure!(
            !expected.starts_with(root),
            "Diagnostics должен находиться вне snapshots"
        );
    }
    let path = expected
        .to_str()
        .context("Путь diagnostics должен быть UTF-8")?
        .to_owned();
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&expected)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.permissions().mode() & 0o777 == 0o600,
        "Некорректные права diagnostics"
    );
    Ok(Some(DiagnosticsTarget {
        path,
        dev: metadata.dev(),
        ino: metadata.ino(),
    }))
}

#[cfg(not(unix))]
fn diagnostics_target(
    path: Option<&Path>,
    _report: &Path,
    _snapshots: Option<&str>,
) -> Result<Option<DiagnosticsTarget>> {
    if path.is_some() {
        anyhow::bail!("Защищённый eval поддерживается только на Unix host")
    }
    Ok(None)
}

fn attach_diagnostics(invocation: &mut Value, target: Option<DiagnosticsTarget>) {
    if let Some(target) = target {
        invocation["diagnostics"] = json!({
            "path": target.path, "dev": target.dev, "ino": target.ino,
        });
    }
}

pub(super) async fn run(args: &EvalRun, cli: &Cli, events: &Events) -> Result<i32> {
    ensure!(args.yes, "Для eval run требуется явное согласие --yes");
    let name = cli
        .profile
        .as_deref()
        .context("Для eval run требуется явный --profile local или gigachat")?;
    ensure!(
        cli.model.is_none()
            && cli.base_url.is_none()
            && cli.effort.is_none()
            && cli.folder_id.is_none()
            && cli.ca_file.is_none()
            && cli.resume.is_none()
            && !cli.compact
            && !cli.plan
            && cli.add_dir.is_empty()
            && cli.approval_mode.is_none()
            && !cli.allow_shell
            && cli.prompt.is_none()
            && cli.max_steps == 32
            && cli.directory == Path::new("."),
        "Eval использует только явно выбранный профиль и собственные изолированные разрешения; несовместимые глобальные флаги"
    );
    ensure!(
        args.image.strip_prefix("sha256:").is_some_and(hex),
        "Требуется полный локальный image ID sha256:…"
    );
    ensure!(
        !args.series.is_empty()
            && args.series.len() <= 64
            && args
                .series
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "Некорректная серия eval"
    );
    ensure!(
        args.source_sha256.as_deref().is_none_or(hex),
        "Некорректный SHA-256 исходного дерева"
    );
    ensure!(
        !args.report.try_exists()?,
        "Отчёт уже существует; выберите новый путь"
    );
    let snapshots = snapshots_root(args.snapshots.as_deref())?;
    let suite = manifest::validate(&args.suite)?;
    let store = ConfigStore::new()?;
    let settings = store.load()?;
    let saved = if let Some(profile) = settings.local.profiles.get(name) {
        Some(profile)
    } else if name == "gigachat" {
        settings.providers.get("gigachat")
    } else {
        None
    }
    .context("Нет выбранного local или GigaChat profile")?
    .clone();
    let credential = store.credential_for(&saved)?;
    let selected = super::profile::select(&settings, name, credential)?;
    ensure!(
        cli.provider
            .is_none_or(|provider| provider == selected.selected.kind),
        "Глобальный --provider должен соответствовать явно выбранному eval profile"
    );
    ensure!(
        !selected.selected.stream || args.non_streaming,
        "Профиль использует streaming. Для явного JSON transport добавьте --non-streaming; профиль не изменяется"
    );
    let super::profile::Selected {
        selected,
        effective,
        credential,
    } = selected;
    if selected.kind == ProviderKind::Local {
        let endpoint = effective
            .base_url
            .as_deref()
            .context("Нет endpoint local")?;
        let url = crate::local::validate_local_endpoint(endpoint)?;
        ensure!(
            matches!(
                url.host_str(),
                Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
            ),
            "V1 eval требует literal loopback 127.0.0.1/localhost/::1"
        );
    }
    let binary = read(&args.agent_binary, 128 * 1024 * 1024)?;
    ensure!(
        binary.starts_with(b"\x7fELF"),
        "Нужен Linux ELF binary; macOS baseline не подменяется Linux rebuild"
    );
    let artifact = json!({"series":args.series,"binary_sha256":sha(&binary),"platform":"linux","source_sha256":args.source_sha256,"source_hash_verified_by_runner":false});
    let docker = executable(&args.docker)?;
    let python = executable(&args.python)?;
    let socket = fs::canonicalize(&args.docker_socket)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        ensure!(
            fs::metadata(&socket)?.file_type().is_socket(),
            "Нужен локальный Unix Docker socket"
        );
    }
    ensure!(cfg!(unix), "Защищённый eval v1 требует Unix host");
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let runtime = root.join("runtime");
    fs::create_dir(&runtime)?;
    mode(&runtime, 0o755)?;
    let modules = [
        ("host.py", HOST),
        ("host_provider.py", PROVIDER),
        ("host_docker.py", DOCKER),
        ("host_snapshot.py", SNAPSHOT),
        ("policy.py", POLICY),
        ("runtime.py", RUNTIME),
        ("runtime_http.py", HTTP),
    ];
    for (name, text) in modules {
        let p = if name.starts_with("runtime") {
            runtime.join(name)
        } else {
            root.join(name)
        };
        fs::write(&p, text)?;
        mode(&p, 0o444)?;
    }
    let frozen = root.join("rcode");
    fs::write(&frozen, &binary)?;
    mode(&frozen, 0o555)?;
    let budgets:Vec<_>=suite.cases.iter().map(|c|json!({"id":c.case.id,"sha256":c.sha256,"max_steps":c.case.max_steps,"max_requests":c.case.max_requests,"timeout_secs":c.case.timeout_secs,"require_skills":c.case.require_skills})).collect();
    let helper_hashes: BTreeMap<_, _> = modules
        .iter()
        .map(|(n, s)| (*n, sha(s.as_bytes())))
        .collect();
    let key = json!({"suite_sha256":suite.sha256,"selected_profile":selected,"effective_profile":effective,"image":args.image,"helpers":helper_hashes,"case_budgets":budgets,"protocol":2,"steps_definition":"forwarded_model_generations_all_contexts","permissions":{"approval_mode":"auto-edit","allow_shell":true},"transport":"explicit_non_streaming_json"});
    let mut cases = Vec::new();
    for c in &suite.cases {
        let path = root.join(format!("fixture-{}", c.case.id));
        fixture(&path, &c.files)?;
        cases.push(json!({"case":c.case,"sha256":c.sha256,"task":c.task,"fixture":path,"oracle":oracle(&c.oracle)}));
    }
    let mut invocation = json!({"version":1,"comparison_key":key,"artifact":artifact,"effective_profile":effective,"provider_credential":credential,"docker":docker,"socket":socket,"image":args.image,"runtime":runtime,"binary":frozen,"cases":cases});
    attach_snapshots(&mut invocation, snapshots);
    let input = serde_json::to_vec(&invocation)?;
    ensure!(
        input.len() <= 16 * 1024 * 1024,
        "Превышен лимит host invocation 16 МиБ"
    );
    // Only the trusted Python host receives the provider credential, via stdin.
    // Docker receives no ambient Docker context or provider environment.
    // Keep stdin/out bounded. SIGINT goes to the same foreground process group;
    // Python owns cleanup and produces the honest interrupted report.
    let path = root.to_owned();
    let runtime_path = runtime.clone();
    let output=tokio::task::spawn_blocking(move || ->Result<(std::process::ExitStatus,Vec<u8>)>{
        let mut child=Command::new(python).args(["-I","-S","-c","import sys;sys.path[:0]=[sys.argv[1],sys.argv[2]];import host;raise SystemExit(host.main())"]).arg(&path).arg(runtime_path)
            .env_clear().env("PATH","/usr/bin:/bin").env("HOME",&path).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
        let mut stdin=child.stdin.take().context("host stdin")?;let mut stdout=child.stdout.take().context("host stdout")?;
        let writer=std::thread::spawn(move ||stdin.write_all(&input));
        let mut bytes=Vec::new();stdout.by_ref().take(2*1024*1024+1).read_to_end(&mut bytes)?;
        if bytes.len()>2*1024*1024{child.kill()?;let _=child.wait();anyhow::bail!("Отчёт host превысил 2 МиБ; cleanup не подтверждён");}
        let status=child.wait()?;writer.join().map_err(|_|anyhow::anyhow!("host writer failed"))??;Ok((status,bytes))
    }).await??;
    let report = strict_json::parse(&output.1)?;
    let counts = validate_report(&report)?;
    ensure!(
        report["comparison_key"] == key && report["artifact"] == artifact,
        "Host report identity mismatch"
    );
    let parent = args
        .report
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec_pretty(&report)?)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&args.report)?;
    fs::File::open(parent)?.sync_all()?;
    events.emit("eval_finished",json!({"report":args.report,"counts":counts,"cleanup":report["cleanup"],"binary_sha256":artifact["binary_sha256"]}));
    Ok(
        if output.0.success() && counts.get("passed") == Some(&(suite.cases.len() as u64)) {
            0
        } else {
            1
        },
    )
}
fn validate_report(report: &Value) -> Result<BTreeMap<String, u64>> {
    let obj = report.as_object().context("Eval report object")?;
    ensure!(
        obj.keys().all(|k| matches!(
            k.as_str(),
            "version"
                | "comparison_key"
                | "artifact"
                | "isolation"
                | "cases"
                | "cleanup"
                | "counts"
                | "residual_resources"
        )) && report["version"] == 1,
        "Неизвестная версия/поля отчёта"
    );
    ensure!(
        report["comparison_key"].is_object()
            && matches!(
                report["cleanup"].as_str(),
                Some("confirmed_absent" | "unknown")
            ),
        "Некорректный отчёт"
    );
    let rows = report["cases"].as_array().context("cases")?;
    ensure!(!rows.is_empty() && rows.len() <= 100, "Размер отчёта");
    let budgets = validate_key(&report["comparison_key"])?;
    let artifact = &report["artifact"];
    ensure!(
        artifact["binary_sha256"].as_str().is_some_and(hex)
            && artifact["platform"] == "linux"
            && artifact["series"].as_str().is_some_and(|s| !s.is_empty())
            && (artifact["source_sha256"].is_null()
                || artifact["source_sha256"].as_str().is_some_and(hex))
            && artifact["source_hash_verified_by_runner"] == false
            && obj.contains_key("isolation"),
        "Отсутствует идентичность бинарника или результат проверки изоляции"
    );
    ensure!(
        budgets.len() == rows.len(),
        "Количество кейсов не совпадает с ключом"
    );
    let mut ids = BTreeSet::new();
    let mut counts: BTreeMap<String, u64> = ["passed", "failed", "blocked", "unknown", "not_run"]
        .map(|k| (k.into(), 0))
        .into();
    for row in rows {
        let id = row["id"].as_str().context("Case ID")?;
        ensure!(ids.insert(id), "Повторный case ID");
        ensure!(
            row["case_sha256"].as_str() == budgets.get(id).map(String::as_str),
            "Case hash не совпадает с ключом"
        );
        let status = row["status"].as_str().context("Case status")?;
        let n = counts.get_mut(status).context("Неизвестный case status")?;
        *n += 1;
        ensure!(
            status != "passed" || (row["cleanup"] == "confirmed_absent"),
            "PASS с неподтверждённой очисткой"
        );
        if status == "passed" {
            validate_pass(
                row,
                report["comparison_key"]["case_budgets"]
                    .as_array()
                    .and_then(|rows| rows.iter().find(|b| b["id"] == id))
                    .context("Отсутствует бюджет PASS")?,
                &report["isolation"],
            )?;
        }
    }
    ensure!(
        serde_json::to_value(&counts)? == report["counts"],
        "Счётчики отчёта не совпадают с кейсами"
    );
    Ok(counts)
}

fn validate_pass(row: &Value, budget: &Value, isolation: &Value) -> Result<()> {
    ensure!(
        isolation["type"] == "probe_result"
            && isolation["uid"] == 10001
            && isolation["gid"] == 10001
            && isolation["groups"] == json!([])
            && isolation["interfaces"] == json!(["lo"])
            && [
                "capabilities_empty",
                "no_new_privileges",
                "seccomp_active",
                "root_stdout_denied",
                "signal_probe_denied",
                "external_network_denied",
            ]
            .iter()
            .all(|k| isolation[*k] == true),
        "PASS без подтверждённой изоляции"
    );
    let required_skills = row["required_skills"]
        .as_array()
        .context("Required skills PASS")?;
    let budget_skills = budget["require_skills"]
        .as_array()
        .context("Required skills budget")?;
    let violations = row["formal_violations"]
        .as_array()
        .context("Formal violations PASS")?;
    ensure!(
        row["required_skills_observed"].as_bool() == Some(true)
            && violations.is_empty()
            && required_skills == budget_skills,
        "PASS без соблюдения формальных ограничений и required skills"
    );
    let generations = row["generations"].as_u64().context("Generations PASS")?;
    let attempts = row["request_attempts"]
        .as_u64()
        .context("Request attempts PASS")?;
    ensure!(
        generations > 0
            && generations <= budget["max_steps"].as_u64().unwrap_or(0)
            && attempts >= generations
            && attempts <= budget["max_requests"].as_u64().unwrap_or(0)
            && row["seconds"].as_f64().is_some_and(|s| s.is_finite()
                && s >= 0.0
                && s <= budget["timeout_secs"].as_f64().unwrap_or(0.0))
            && row["operator_cancelled"] == false
            && row["tool_requirement_observed"] == true,
        "PASS противоречит бюджету или наблюдениям"
    );
    let agent = &row["agent"];
    ensure!(
        agent["type"] == "agent_done"
            && agent["exit_code"] == 0
            && agent.get("signal") == Some(&Value::Null)
            && ["leader_reaped", "pipes_complete"]
                .iter()
                .all(|k| agent[*k] == true)
            && ["timed_out", "cancelled", "truncated", "forced"]
                .iter()
                .all(|k| agent[*k] == false)
            && agent["log_sha256"].as_str().is_some_and(hex)
            && agent["log_bytes"].as_u64().is_some(),
        "PASS без успешного завершения агента"
    );
    let checks = row["checks"].as_array().context("Checks PASS")?;
    ensure!(
        !checks.is_empty()
            && checks.iter().all(|c| {
                c["id"].as_str().is_some_and(|s| !s.is_empty())
                && c["passed"] == true
                // A hidden check may deliberately expect a nonzero exit.
                && c["exit_code"].as_i64().is_some()
                && c.get("signal") == Some(&Value::Null)
                && ["timed_out", "truncated", "prepare_failed"].iter().all(|k| c[*k] == false)
                && c["stdout_sha256"].as_str().is_some_and(hex)
            }),
        "PASS без успешных независимых проверок"
    );
    let lifecycle = &row["lifecycle"];
    let resumed = [
        "sentinel_observed",
        "cancel_sent",
        "cancel_signal_sent",
        "first_container_absent",
        "explicit_resume_argument",
        "agent_reported_same_session",
    ]
    .iter()
    .all(|k| lifecycle[*k] == true)
        && lifecycle["first_forced"] == false;
    ensure!(
        row.get("lifecycle").is_none() || resumed,
        "PASS с неполным resume"
    );
    let requests = row["requests"].as_array().context("Requests PASS")?;
    ensure!(
        requests.len() as u64 == generations
            && requests.iter().enumerate().all(|(i, r)| {
                r["generation"].as_u64() == Some(i as u64 + 1)
                    && ((r["status"] == "received"
                        && r["http_status"]
                            .as_u64()
                            .is_some_and(|s| (200..300).contains(&s)))
                        || (r["status"] == "cancelled_by_case" && resumed))
                    && r.get("http_status").is_none_or(|s| {
                        s.is_null() || s.as_u64().is_some_and(|n| (200..300).contains(&n))
                    })
            }),
        "PASS без подтверждённых модельных запросов"
    );
    Ok(())
}
fn validate_key(key: &Value) -> Result<BTreeMap<String, String>> {
    let fields = [
        "suite_sha256",
        "selected_profile",
        "effective_profile",
        "image",
        "helpers",
        "case_budgets",
        "protocol",
        "steps_definition",
        "permissions",
        "transport",
    ];
    let object = key.as_object().context("Comparison key object")?;
    ensure!(
        object.len() == fields.len() && fields.iter().all(|k| object.contains_key(*k)),
        "Неполный или неизвестный comparison key"
    );
    ensure!(
        key["suite_sha256"].as_str().is_some_and(hex)
            && key["image"]
                .as_str()
                .and_then(|s| s.strip_prefix("sha256:"))
                .is_some_and(hex)
            && key["protocol"] == 2
            && key["steps_definition"] == "forwarded_model_generations_all_contexts"
            && key["permissions"] == json!({"approval_mode":"auto-edit","allow_shell":true})
            && key["transport"] == "explicit_non_streaming_json",
        "Некорректный comparison key"
    );
    for profile in [&key["selected_profile"], &key["effective_profile"]] {
        let fields = profile.as_object().context("Profile object")?;
        ensure!(
            fields.keys().all(|field| matches!(
                field.as_str(),
                "kind"
                    | "model"
                    | "effort"
                    | "base_url"
                    | "folder_id"
                    | "auth_url"
                    | "scope"
                    | "ca_file"
                    | "stream"
                    | "max_output_tokens"
                    | "request_timeout_secs"
                    | "idle_timeout_secs"
                    | "local"
            )),
            "Неизвестные поля профиля comparison key"
        );
        if let Some(local) = fields.get("local").and_then(Value::as_object) {
            ensure!(
                local.keys().all(|field| matches!(
                    field.as_str(),
                    "profile"
                        | "runtime"
                        | "context_tokens"
                        | "vision"
                        | "key_required"
                        | "thinking"
                )),
                "Неизвестные поля local профиля comparison key"
            );
        }
    }
    let selected: crate::config::ProviderSettings =
        serde_json::from_value(key["selected_profile"].clone())
            .map_err(|_| anyhow::anyhow!("Некорректный selected_profile comparison key"))?;
    let effective: crate::config::ProviderSettings =
        serde_json::from_value(key["effective_profile"].clone())
            .map_err(|_| anyhow::anyhow!("Некорректный effective_profile comparison key"))?;
    selected.validate()?;
    effective.validate()?;
    ensure!(
        !effective.stream && selected.ca_file.is_none(),
        "Профиль comparison key не поддерживается"
    );
    match selected.kind {
        ProviderKind::Local => ensure!(
            selected
                .local
                .as_ref()
                .is_some_and(|local| !local.key_required),
            "Профиль comparison key не поддерживается"
        ),
        ProviderKind::GigaChat => super::profile::validate_gigachat_endpoints(&selected)?,
        _ => anyhow::bail!("Профиль comparison key не поддерживается"),
    }
    let mut expected = key["selected_profile"].clone();
    expected["stream"] = json!(false);
    ensure!(
        expected == key["effective_profile"],
        "Effective profile не соответствует выбранному"
    );
    let helpers = key["helpers"].as_object().context("Helper hashes")?;
    ensure!(
        helpers.len() == 7
            && [
                "host.py",
                "host_provider.py",
                "host_docker.py",
                "host_snapshot.py",
                "policy.py",
                "runtime.py",
                "runtime_http.py"
            ]
            .iter()
            .all(|k| helpers.get(*k).and_then(Value::as_str).is_some_and(hex)),
        "Неполные hashes helper"
    );
    let rows = key["case_budgets"].as_array().context("Case budgets")?;
    ensure!(!rows.is_empty() && rows.len() <= 100, "Case budgets size");
    let mut out = BTreeMap::new();
    for c in rows {
        let fields = c.as_object().context("Case budget object")?;
        ensure!(
            fields.len() == 6
                && [
                    "id",
                    "sha256",
                    "max_steps",
                    "max_requests",
                    "timeout_secs",
                    "require_skills"
                ]
                .iter()
                .all(|k| fields.contains_key(*k)),
            "Неполный case budget"
        );
        let id = c["id"].as_str().context("Budget ID")?;
        let hash = c["sha256"].as_str().context("Case SHA")?;
        let required_skills = c["require_skills"].as_array().context("Required skills")?;
        let mut skill_ids = BTreeSet::new();
        ensure!(
            required_skills.iter().all(|skill| {
                skill
                    .as_str()
                    .is_some_and(|id| manifest::valid_skill_id(id) && skill_ids.insert(id))
            }),
            "Некорректный или повторный required skill ID"
        );
        ensure!(
            !id.is_empty()
                && id.len() <= 64
                && id.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'-'
                    || b == b'_')
                && hex(hash)
                && c["max_steps"]
                    .as_u64()
                    .is_some_and(|v| (1..=64).contains(&v))
                && c["max_requests"]
                    .as_u64()
                    .is_some_and(|v| (1..=128).contains(&v))
                && c["timeout_secs"]
                    .as_u64()
                    .is_some_and(|v| (30..=600).contains(&v)),
            "Некорректный case budget"
        );
        ensure!(
            out.insert(id.to_owned(), hash.to_owned()).is_none(),
            "Повтор budget ID"
        );
    }
    Ok(out)
}
pub(super) fn compare(baseline: &Path, candidate: &Path, events: &Events) -> Result<i32> {
    let a = strict_json::parse(&read(baseline, 2 * 1024 * 1024)?)?;
    let b = strict_json::parse(&read(candidate, 2 * 1024 * 1024)?)?;
    let ac = validate_report(&a)?;
    let bc = validate_report(&b)?;
    ensure!(
        a["comparison_key"] == b["comparison_key"],
        "Корпус, бюджет, модель, transport или isolation различаются; сравнение отклонено"
    );
    let ids = |r: &Value| -> Result<BTreeSet<String>> {
        Ok(r["cases"]
            .as_array()
            .context("cases")?
            .iter()
            .map(|c| c["id"].as_str().unwrap_or_default().to_owned())
            .collect())
    };
    ensure!(ids(&a)? == ids(&b)?, "Наборы case ID различаются");
    events.emit("eval_comparison",json!({"baseline":ac,"candidate":bc,"delta_passed":bc["passed"] as i64-ac["passed"] as i64,"baseline_cleanup":a["cleanup"],"candidate_cleanup":b["cleanup"]}));
    Ok(0)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt},
    };

    #[test]
    fn diagnostics_target_is_new_private_and_identified() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        let target = super::diagnostics_target(
            Some(&path),
            &temp.path().join("report.json"),
            None,
        )
        .unwrap()
        .unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 0);
        assert_eq!(target.dev, metadata.dev());
        assert_eq!(target.ino, metadata.ino());
        assert!(target.path.ends_with("/events.jsonl"));
        assert!(
            super::diagnostics_target(Some(&path), &temp.path().join("report.json"), None).is_err()
        );
        assert!(
            super::diagnostics_target(None, &temp.path().join("report.json"), None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn diagnostics_target_rejects_alias_collision_and_snapshots_nesting() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, temp.path().join("alias")).unwrap();
        assert!(
            super::diagnostics_target(
                Some(&temp.path().join("alias/report.json")),
                &real.join("report.json"),
                None,
            )
            .is_err()
        );
        let snapshots = temp.path().join("snapshots");
        std::fs::create_dir(&snapshots).unwrap();
        let root = std::fs::canonicalize(&snapshots)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let nested = snapshots.join("events.jsonl");
        assert!(
            super::diagnostics_target(
                Some(&nested),
                &temp.path().join("report.json"),
                Some(&root),
            )
            .is_err()
        );
        assert!(!nested.exists());
    }

    #[test]
    fn diagnostics_target_rejects_symlink_non_utf8_and_directory_path() {
        let temp = tempfile::tempdir().unwrap();
        let report = temp.path().join("report.json");
        let dangling = temp.path().join("dangling");
        std::os::unix::fs::symlink(temp.path().join("missing"), &dangling).unwrap();
        assert!(super::diagnostics_target(Some(&dangling), &report, None).is_err());
        let non_utf8 = temp
            .path()
            .join(std::ffi::OsString::from_vec(vec![b'e', 0xff]));
        assert!(super::diagnostics_target(Some(&non_utf8), &report, None).is_err());
        let directory = temp.path().join("directory");
        std::fs::create_dir(&directory).unwrap();
        assert!(super::diagnostics_target(Some(&directory), &report, None).is_err());
        let trailing = std::path::PathBuf::from(format!("{}/", directory.display()));
        assert!(super::diagnostics_target(Some(&trailing), &report, None).is_err());
    }

    #[test]
    fn invocation_diagnostics_contains_only_path_and_identity() {
        let mut invocation = serde_json::json!({"version":1,"comparison_key":{"protocol":2}});
        let key = invocation["comparison_key"].clone();
        super::attach_diagnostics(&mut invocation, None);
        assert!(invocation.get("diagnostics").is_none());
        super::attach_diagnostics(
            &mut invocation,
            Some(super::DiagnosticsTarget {
                path: "/absolute/events.jsonl".into(),
                dev: 11,
                ino: 12,
            }),
        );
        assert_eq!(
            invocation["diagnostics"],
            serde_json::json!({"path":"/absolute/events.jsonl","dev":11,"ino":12})
        );
        assert_eq!(invocation["comparison_key"], key);
    }

    #[test]
    fn snapshots_root_is_new_private_and_canonical() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("snapshots");
        let root = super::snapshots_root(Some(&path)).unwrap().unwrap();
        assert_eq!(
            root,
            std::fs::canonicalize(&path).unwrap().to_str().unwrap()
        );
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(super::snapshots_root(Some(&path)).is_err());
        assert!(super::snapshots_root(None).unwrap().is_none());
    }

    #[test]
    fn snapshots_root_rejects_symlinks_and_docker_unsafe_paths() {
        let temp = tempfile::tempdir().unwrap();
        let broken = temp.path().join("broken");
        std::os::unix::fs::symlink(temp.path().join("missing"), &broken).unwrap();
        assert!(super::snapshots_root(Some(&broken)).is_err());
        let target = temp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let valid = temp.path().join("valid");
        std::os::unix::fs::symlink(&target, &valid).unwrap();
        assert!(super::snapshots_root(Some(&valid)).is_err());
        assert!(super::snapshots_root(Some(&temp.path().join("with,comma"))).is_err());
        let non_utf8 = temp
            .path()
            .join(std::ffi::OsString::from_vec(vec![b's', 0xff]));
        assert!(super::snapshots_root(Some(&non_utf8)).is_err());
    }

    #[test]
    fn invocation_snapshots_are_opt_in() {
        let mut invocation = serde_json::json!({"version":1});
        super::attach_snapshots(&mut invocation, None);
        assert!(invocation.get("snapshots").is_none());
        super::attach_snapshots(&mut invocation, Some("/absolute/snapshots".to_owned()));
        assert_eq!(invocation["snapshots"], "/absolute/snapshots");
    }

    #[test]
    fn executable_preserves_the_invocation_name_for_multicall_docker() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("docker-tools");
        std::fs::write(&real, b"fixture").unwrap();
        let link = temp.path().join("docker");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(super::executable(&link).unwrap(), link);
    }
}
