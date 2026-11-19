use crate::{
    app::{
        Events, catalog_unit, catalog_unit_for_client, configured_tools,
        context_budget_with_memory, discover_memory, discover_skills, prepare_context,
        skill_catalog_redacted, turn, user_shell,
    },
    balance::BalanceMonitor,
    cli::{ApprovalMode, Cli},
    config::{ConfigStore, Effort, ProviderKind, ProviderSettings, Settings},
    context::ContextBudget,
    local_app,
    memory::{MemoryId, MemoryPolicy, MemoryProblem, MemorySnapshot, MemoryStore},
    presentation,
    protocol::{Message, ModelInfo, ProviderMeta},
    provider::ProviderClient,
    skills::{CatalogEntry, CatalogUnit, LookupError, RenderedCatalog, SkillCatalog, SkillProblem},
    state::Session,
    terminal::{self, Choice, Footer, Input},
    tools::Tools,
    ui,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::{Duration, Instant};

macro_rules! notice {($($arg:tt)*)=>{crate::screen::notice(format!($($arg)*))};}

fn model_target(current: ProviderKind, args: &[&str]) -> (ProviderKind, Option<String>) {
    match args.first().and_then(|s| s.parse::<ProviderKind>().ok()) {
        Some(kind) => (kind, args.get(1).map(|s| (*s).to_owned())),
        None => (current, args.first().map(|s| (*s).to_owned())),
    }
}
fn efforts(p: &ProviderSettings, model: Option<&ModelInfo>) -> Vec<Effort> {
    if model.is_some_and(|m| m.supports_reasoning == Some(false)) {
        return vec![Effort::Auto];
    }
    let mut options = vec![Effort::Auto];
    for effort in Effort::all().into_iter().filter(|e| *e != Effort::Auto) {
        let mut candidate = p.clone();
        candidate.effort = effort;
        if candidate.validate_effort().is_err() {
            continue;
        }
        if let Some(allowed) = model.and_then(|m| m.supported_efforts.as_ref()) {
            if !allowed.contains(&effort) {
                continue;
            }
        } else if !matches!(effort, Effort::Low | Effort::Medium | Effort::High) {
            continue;
        }
        options.push(effort);
    }
    options
}
pub(crate) fn choose(
    title: &str,
    choices: &[Choice],
    current: usize,
    rich: bool,
) -> Result<Option<usize>> {
    if rich {
        return terminal::select(title, choices, current);
    }
    notice!("\n{title}");
    for (i, c) in choices.iter().enumerate() {
        notice!(
            "{}. {} — {}{}",
            i + 1,
            ui::safe(&c.label),
            ui::safe(&c.detail),
            if c.enabled {
                ""
            } else {
                " (недоступно)"
            }
        );
    }
    let answer = ui::line("Номер (0 — отмена)", &(current + 1).to_string())?;
    let index = answer.parse::<usize>().ok().and_then(|n| n.checked_sub(1));
    Ok(index.filter(|i| choices.get(*i).is_some_and(|c| c.enabled)))
}
async fn provider_choice(
    store: &ConfigStore,
    settings: &Settings,
    active: &ProviderSettings,
    rich: bool,
    events: &Events,
) -> Result<Option<ProviderKind>> {
    let _ = events.refresh_keys(store);
    let base_secrets = events.secret_snapshot();
    let kinds = ProviderKind::all();
    let (send, updates) = std::sync::mpsc::channel();
    // The menu owns all requests: leaving it aborts the JoinSet's tasks.
    let mut pending = tokio::task::JoinSet::new();
    let mut choices = Vec::new();
    for (index, kind) in kinds.iter().copied().enumerate() {
        if kind == ProviderKind::Local {
            // Local servers have no balance API and no request is made here.
            choices.push(Choice {
                label: kind.to_string(),
                detail: crate::local_ui::summary_with_secrets(settings, store, &base_secrets),
                enabled: true,
            });
            continue;
        }
        let Ok((fresh_settings, credential)) = store.read_consistent_cloud(kind) else {
            choices.push(Choice {
                label: kind.to_string(),
                detail: "конфигурация недоступна".into(),
                enabled: true,
            });
            continue;
        };
        let detail = match credential {
            None => "настроить ключ доступа".into(),
            Some(_) if kind == ProviderKind::Yandex => "ключ подключён (баланс в кабинете)".into(),
            Some(_) if kind == ProviderKind::Custom => {
                "ключ подключён (баланс API недоступен)".into()
            }
            Some(key) => {
                let mut combined_secrets = base_secrets.clone();
                crate::redaction::push_secret_variants(&mut combined_secrets, &key.value);
                let provider = crate::model_route::configured_cloud_provider(&fresh_settings, kind)
                    .ok()
                    .flatten()
                    .filter(|p| {
                        crate::model_route::ensure_connection_free_of_secrets(
                            store,
                            p,
                            &combined_secrets,
                        )
                        .is_ok()
                    });
                if let Some(p) = provider.filter(|p| p.kind == kind) {
                    let send = send.clone();
                    let sink = events.shared_secrets();
                    pending.spawn(async move {
                        // Never forward a key through a copied, stale, or inconsistent provider entry.
                        let label = match ProviderClient::new(p.clone(), key.value) {
                            Ok(mut client) => {
                                client.bind_secret_sink(sink);
                                match crate::balance::fetch(&mut client).await {
                                    Ok(report) => report.footer(&p.model),
                                    Err(_) => "Баланс: недоступен".into(),
                                }
                            }
                            Err(_) => "Баланс: недоступен".into(),
                        };
                        let _ = send.send((index, format!("ключ подключён ({label})")));
                    });
                    "ключ подключён (баланс: …)".into()
                } else {
                    "ключ подключён (Баланс: недоступен)".into()
                }
            }
        };
        choices.push(Choice {
            label: kind.to_string(),
            detail,
            enabled: true,
        });
    }
    drop(send);
    let current = kinds
        .iter()
        .position(|k| *k == active.kind)
        .unwrap_or_default();
    let selected = if rich {
        terminal::select_with_updates("Провайдер", &choices, current, Some(&updates))?
    } else {
        tokio::select! {
            _ = async { while pending.join_next().await.is_some() {} } => {},
            _ = tokio::signal::ctrl_c() => return Ok(None),
        }
        for (index, detail) in updates.try_iter() {
            choices[index].detail = detail;
        }
        choose("Провайдер", &choices, current, false)?
    };
    Ok(selected.map(|i| kinds[i]))
}
async fn catalog(client: &mut ProviderClient, events: &Events) -> Result<Option<Vec<ModelInfo>>> {
    let cancel = tokio_util::sync::CancellationToken::new();
    if let Some(screen) = crate::screen::current() {
        screen.bind_cancel(cancel.clone());
    }
    events.busy("Получаю список моделей");
    let result = tokio::select! {value=client.models()=>value.map(Some),_=tokio::signal::ctrl_c()=>Ok(None),_=cancel.cancelled()=>Ok(None)};
    events.pause();
    result
}

enum ProviderEdit {
    Switch(ProviderSettings),
    Model {
        disk_expected: ProviderSettings,
        session_base: ProviderSettings,
        model: String,
    },
    Effort {
        disk_expected: ProviderSettings,
        session_base: ProviderSettings,
        effort: Effort,
    },
    Thinking {
        disk_expected: ProviderSettings,
        session_base: ProviderSettings,
        thinking: Option<bool>,
    },
}

/// Computes `(verified_disk_provider, persist_disk, session_provider_to_activate)`.
/// When the session runs under a temporary CLI connection or model override that differs from
/// `config.json`, `persist_disk` is `false` so `/model` and `/effort` update the running session
/// without overwriting an unrelated saved connection/model on disk.
fn resolve_provider_edit(
    current: &Settings,
    edit: &ProviderEdit,
) -> Result<(ProviderSettings, bool, ProviderSettings)> {
    match edit {
        ProviderEdit::Switch(p) => {
            p.validate()?;
            if p.kind == ProviderKind::Local {
                local_app::check_commit(current, p)?;
                let name = local_app::profile_name(p);
                let mut base = crate::model_route::configured_local_profile(current, name)?
                    .context("Профиль local больше не сохранён")?;
                base.model = p.model.clone();
                base.validate()?;
                Ok((base.clone(), true, base))
            } else {
                let mut base = crate::model_route::configured_cloud_provider(current, p.kind)?
                    .unwrap_or_else(|| current.provider(p.kind));
                if !crate::model_route::RouteIdentity::same_connection(p, &base) {
                    bail!(
                        "Параметры подключения провайдера {} изменились в другом процессе; повторите команду",
                        p.kind
                    );
                }
                if p.model != base.model {
                    base.effort = p.effort;
                    base.model = p.model.clone();
                }
                base.validate()?;
                Ok((base.clone(), true, base))
            }
        }
        ProviderEdit::Model {
            disk_expected,
            session_base,
            model,
        } => {
            let mut next_session = session_base.clone();
            if *model != next_session.model {
                next_session.effort = Effort::Auto;
            }
            next_session.model = model.clone();
            next_session.validate()?;

            if disk_expected.kind == ProviderKind::Local {
                let name = local_app::profile_name(disk_expected);
                let mut disk_base = crate::model_route::configured_local_profile(current, name)?
                    .context("Профиль local больше не сохранён")?;
                if !crate::model_route::RouteIdentity::disk_unchanged(disk_expected, &disk_base) {
                    bail!(
                        "Параметры подключения локального профиля «{name}» изменились в другом процессе; переключите профиль через /provider local"
                    );
                }
                if let (Some(disk_local), Some(sess_local)) =
                    (&disk_base.local, next_session.local.as_mut())
                {
                    sess_local.key_required = disk_local.key_required;
                }
                if crate::model_route::RouteIdentity::same_connection(&next_session, &disk_base)
                    && disk_base.model == session_base.model
                    && *model != disk_base.model
                {
                    disk_base.model = model.clone();
                    disk_base.validate()?;
                    Ok((disk_base, true, next_session))
                } else {
                    Ok((disk_base, false, next_session))
                }
            } else {
                let mut disk_base =
                    crate::model_route::configured_cloud_provider(current, disk_expected.kind)?
                        .unwrap_or_else(|| current.provider(disk_expected.kind));
                if !crate::model_route::RouteIdentity::disk_unchanged(disk_expected, &disk_base) {
                    bail!(
                        "Параметры подключения провайдера {} изменились в другом процессе; переключите провайдера через /provider или /connect",
                        disk_expected.kind
                    );
                }
                if crate::model_route::RouteIdentity::same_connection(&next_session, &disk_base)
                    && disk_base.model == session_base.model
                    && (*model != disk_base.model || current.active != disk_base.kind)
                {
                    if *model != disk_base.model {
                        disk_base.effort = Effort::Auto;
                    }
                    disk_base.model = model.clone();
                    disk_base.validate()?;
                    Ok((disk_base, true, next_session))
                } else {
                    Ok((disk_base, false, next_session))
                }
            }
        }
        ProviderEdit::Effort {
            disk_expected,
            session_base,
            effort,
        } => {
            let mut next_session = session_base.clone();
            next_session.effort = *effort;
            next_session.validate()?;

            let mut disk_base =
                crate::model_route::configured_cloud_provider(current, disk_expected.kind)?
                    .unwrap_or_else(|| current.provider(disk_expected.kind));
            if !crate::model_route::RouteIdentity::disk_unchanged(disk_expected, &disk_base) {
                bail!(
                    "Параметры подключения провайдера {} изменились в другом процессе; переключите провайдера через /provider или /connect",
                    disk_expected.kind
                );
            }
            if crate::model_route::RouteIdentity::same_connection(&next_session, &disk_base)
                && disk_base.model == next_session.model
            {
                disk_base.effort = *effort;
                disk_base.validate()?;
                Ok((disk_base, true, next_session))
            } else {
                Ok((disk_base, false, next_session))
            }
        }
        ProviderEdit::Thinking {
            disk_expected,
            session_base,
            thinking,
        } => {
            let mut next_session = session_base.clone();
            if let Some(local) = next_session.local.as_mut() {
                local.thinking = *thinking;
            }
            next_session.validate()?;

            let name = local_app::profile_name(disk_expected);
            let mut disk_base = crate::model_route::configured_local_profile(current, name)?
                .context("Профиль local больше не сохранён")?;
            if !crate::model_route::RouteIdentity::disk_unchanged(disk_expected, &disk_base) {
                bail!(
                    "Параметры подключения локального профиля «{name}» изменились в другом процессе; переключите профиль через /provider local"
                );
            }
            if let (Some(disk_local), Some(sess_local)) =
                (&disk_base.local, next_session.local.as_mut())
            {
                sess_local.key_required = disk_local.key_required;
            }
            if crate::model_route::RouteIdentity::same_connection(&next_session, &disk_base)
                && disk_base.model == session_base.model
            {
                if let Some(local) = disk_base.local.as_mut() {
                    local.thinking = *thinking;
                }
                disk_base.validate()?;
                Ok((disk_base, true, next_session))
            } else {
                Ok((disk_base, false, next_session))
            }
        }
    }
}

fn commit_provider(
    store: &ConfigStore,
    settings: &mut Settings,
    active_disk_origin: &mut ProviderSettings,
    session: &mut Session,
    client: &mut ProviderClient,
    events: &mut Events,
    edit: ProviderEdit,
) -> Result<()> {
    let target_kind = match &edit {
        ProviderEdit::Switch(p) => p.kind,
        ProviderEdit::Model { disk_expected, .. }
        | ProviderEdit::Effort { disk_expected, .. }
        | ProviderEdit::Thinking { disk_expected, .. } => disk_expected.kind,
    };
    let (preview_settings, preview_cred) = if target_kind == ProviderKind::Local {
        let probe = match &edit {
            ProviderEdit::Switch(p) => p,
            ProviderEdit::Model { disk_expected, .. }
            | ProviderEdit::Effort { disk_expected, .. }
            | ProviderEdit::Thinking { disk_expected, .. } => disk_expected,
        };
        store.read_consistent_local(probe)?
    } else {
        let (s, c) = store.read_consistent_cloud(target_kind)?;
        let state = match c {
            Some(cred) => crate::config::CredentialState::Present(cred),
            None => crate::config::CredentialState::Missing,
        };
        (s, state)
    };
    let (preview_disk, preview_persist, preview_session) =
        resolve_provider_edit(&preview_settings, &edit)?;
    let is_switch = matches!(edit, ProviderEdit::Switch(_));
    if !is_switch
        && let crate::config::CredentialState::Present(ref cred) = preview_cred
        && cred.source == "credentials.json"
        && !crate::model_route::RouteIdentity::same_connection(&preview_session, &preview_disk)
        && !client.credential_matches(Some(cred.value.as_str()))
    {
        bail!(
            "Ключ провайдера {} в credentials.json изменился в другом процессе и не отправляется на временный endpoint сессии; переключите провайдера через /provider или /connect",
            preview_session.kind
        );
    }
    let mut next = local_app::client_with_credential(
        &preview_session,
        preview_cred,
        events,
        "Нет ключа — сначала /connect",
    )?;
    let mut committed_disk = preview_disk.clone();
    let mut committed_session = preview_session.clone();
    let mut committed_cred: Option<crate::config::CredentialState> = None;
    let updated = if preview_persist {
        store.update_settings_with_credentials(|current, providers_creds| {
            let (resolved_disk, resolved_persist, resolved_session) =
                resolve_provider_edit(current, &edit)?;
            if !crate::model_route::RouteIdentity::disk_unchanged(&preview_disk, &resolved_disk) {
                bail!(
                    "Параметры подключения провайдера {} изменились в другом процессе; повторите команду",
                    resolved_disk.kind
                );
            }
            if let Some(ref ca) = resolved_session.ca_file
                && !crate::model_route::is_usable_ca_file(ca)
            {
                bail!(
                    "Файл корневого сертификата ca_file провайдера {} недоступен, пуст или не содержит PEM-сертификатов",
                    resolved_session.kind
                );
            }
            let tx_cred = if resolved_session.kind == ProviderKind::Local {
                let cred_state = ConfigStore::local_credential_state_from_snapshot(
                    current,
                    providers_creds,
                    &resolved_session,
                )?;
                let name = local_app::profile_name(&resolved_session);
                if !is_switch
                    && let crate::config::CredentialState::Present(ref cred) = cred_state
                    && !crate::model_route::RouteIdentity::same_connection(
                        &resolved_session,
                        &resolved_disk,
                    )
                    && !client.credential_matches(Some(cred.value.as_str()))
                {
                    bail!(
                        "Ключ локального профиля «{name}» изменился в другом процессе и не отправляется на временные параметры сессии; переключите профиль через /provider local"
                    );
                }
                if matches!(cred_state, crate::config::CredentialState::Missing) {
                    bail!("Нет ключа — сначала /connect");
                }
                cred_state
            } else {
                let c =
                    ConfigStore::cloud_credential_from_map(resolved_session.kind, providers_creds)?;
                if !is_switch
                    && let Some(ref cred) = c
                    && cred.source == "credentials.json"
                    && !crate::model_route::RouteIdentity::same_connection(
                        &resolved_session,
                        &resolved_disk,
                    )
                    && !client.credential_matches(Some(cred.value.as_str()))
                {
                    bail!(
                        "Ключ провайдера {} в credentials.json изменился в другом процессе и не отправляется на временный endpoint сессии; переключите провайдера через /provider или /connect",
                        resolved_session.kind
                    );
                }
                match c {
                    Some(cred) => crate::config::CredentialState::Present(cred),
                    None => bail!("Нет ключа — сначала /connect"),
                }
            };
            let live_extra = events.secret_snapshot();
            let route_dict = crate::model_route::build_route_secret_dictionary_from_raw(
                providers_creds.values().cloned(),
                &live_extra,
            )?;
            crate::model_route::check_route_against_secret_dictionary(
                route_dict.as_ref(),
                &resolved_disk,
            )?;
            crate::model_route::check_route_against_secret_dictionary(
                route_dict.as_ref(),
                &resolved_session,
            )?;
            if resolved_persist {
                current.remember_provider(&resolved_disk);
            }
            for secret in providers_creds.values().filter(|v| !v.is_empty()) {
                events.remember(secret.clone());
            }
            committed_disk = resolved_disk;
            committed_session = resolved_session;
            committed_cred = Some(tx_cred);
            Ok(())
        })?
    } else {
        preview_settings
    };
    if let Some(tx_cred) = committed_cred {
        let tx_cred_str = match &tx_cred {
            crate::config::CredentialState::Present(c) => Some(c.value.as_str()),
            crate::config::CredentialState::NotRequired
            | crate::config::CredentialState::Missing => None,
        };
        if committed_session != preview_session
            || !next.credential_matches(tx_cred_str)
            || !next.ca_bundle_matches_disk()
        {
            next = local_app::client_with_credential(
                &committed_session,
                tx_cred,
                events,
                "Нет ключа — сначала /connect",
            )?;
        }
    }
    session.share_connection_peers_into(&mut next, Some(client));
    let mut candidate_session = session.clone();
    candidate_session.provider = committed_session;
    candidate_session.save(store)?;
    *settings = updated;
    *active_disk_origin = committed_disk;
    *session = candidate_session;
    *client = next;
    if session.provider.kind == ProviderKind::Local {
        let thinking = crate::local::ThinkingMode::from_option(
            session
                .provider
                .local
                .as_ref()
                .and_then(|local| local.thinking),
        );
        notice!(
            "✓ local · профиль {} / {} · thinking {}",
            ui::safe(&events.redact(local_app::profile_name(&session.provider))),
            ui::safe(&events.redact(&session.provider.model)),
            thinking
        );
    } else {
        notice!(
            "✓ {} / {} · effort {}",
            session.provider.kind,
            ui::safe(&events.redact(&session.provider.model)),
            session.provider.effort
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn select_model(
    args: &[&str],
    force_provider: bool,
    rich: bool,
    store: &ConfigStore,
    settings: &mut Settings,
    active_disk_origin: &mut ProviderSettings,
    session: &mut Session,
    client: &mut ProviderClient,
    events: &mut Events,
    models: &mut Vec<ModelInfo>,
) -> Result<()> {
    let (kind, model) = if force_provider {
        let selected = match args.first() {
            Some(s) => Some(s.parse::<ProviderKind>()?),
            None => provider_choice(store, settings, &session.provider, rich, events).await?,
        };
        let Some(kind) = selected else {
            return Ok(());
        };
        (kind, None)
    } else {
        model_target(session.provider.kind, args)
    };
    let mut switching_provider = force_provider || kind != session.provider.kind;
    let mut disk_baseline = if !switching_provider {
        active_disk_origin.clone()
    } else if kind == ProviderKind::Local {
        session.provider.clone()
    } else {
        crate::model_route::configured_cloud_provider(settings, kind)?
            .unwrap_or_else(|| settings.provider(kind))
    };
    let mut cloud_cred_snapshot: Option<crate::config::Credential> = None;
    let mut local_cred_snapshot: Option<String> = None;
    let mut pending_draft_local: Option<(Option<String>, bool)> = None;
    let mut existing_local_protected = false;
    let mut next = if kind == ProviderKind::Local && switching_provider {
        // /provider local: saved profiles, discovery or a manual address.
        let Some(chosen) = crate::local_ui::choose_profile_choice_with_secrets(
            store,
            settings,
            rich,
            None,
            &events.secret_snapshot(),
        )
        .await?
        else {
            return Ok(());
        };
        match chosen {
            crate::local_ui::ChosenLocalProfile::Existing {
                profile,
                server_known_protected,
            } => {
                existing_local_protected = server_known_protected;
                let (fresh, cred_state) = store.read_consistent_local(&profile)?;
                let name = local_app::profile_name(&profile);
                if let Some(disk_p) = crate::model_route::configured_local_profile(&fresh, name)?
                    && !crate::model_route::RouteIdentity::same_connection(&profile, &disk_p)
                {
                    bail!(
                        "Параметры подключения локального профиля «{name}» изменились в другом процессе; повторите /provider local"
                    );
                }
                *settings = fresh;
                events.refresh_keys(store)?;
                local_cred_snapshot = cred_state.into_key();
                disk_baseline = profile.clone();
                profile
            }
            crate::local_ui::ChosenLocalProfile::DraftNew {
                profile,
                typed_key,
                auth_challenged,
            } => {
                pending_draft_local = Some((typed_key, auth_challenged));
                disk_baseline = profile.clone();
                profile
            }
        }
    } else if !switching_provider {
        if kind == ProviderKind::Local {
            let (fresh, cred_state) = store.read_consistent_local(&session.provider)?;
            let name = local_app::profile_name(&session.provider);
            if let Some(disk_p) = crate::model_route::configured_local_profile(&fresh, name)? {
                if !crate::model_route::RouteIdentity::disk_unchanged(&disk_baseline, &disk_p) {
                    bail!(
                        "Параметры подключения локального профиля «{name}» изменились в другом процессе; переключите профиль явно через /provider local"
                    );
                }
                if let crate::config::CredentialState::Present(ref cred) = cred_state
                    && !crate::model_route::RouteIdentity::same_connection(
                        &session.provider,
                        &disk_p,
                    )
                    && !client.credential_matches(Some(cred.value.as_str()))
                {
                    bail!(
                        "Ключ локального профиля «{name}» изменился в другом процессе и не отправляется с временными параметрами TLS/адреса сессии; переключите профиль через /provider local"
                    );
                }
                disk_baseline = disk_p;
            }
            *settings = fresh;
            events.refresh_keys(store)?;
            local_cred_snapshot = cred_state.into_key();
            session.provider.clone()
        } else {
            let (fresh, cred_opt) = store.read_consistent_cloud(kind)?;
            let disk_p = crate::model_route::configured_cloud_provider(&fresh, kind)?
                .unwrap_or_else(|| fresh.provider(kind));
            if !crate::model_route::RouteIdentity::disk_unchanged(&disk_baseline, &disk_p) {
                bail!(
                    "Параметры подключения провайдера {kind} изменились в другом процессе; переключите провайдера явно через /provider {kind} или /connect {kind}"
                );
            }
            if let Some(ref cred) = cred_opt
                && cred.source == "credentials.json"
                && !crate::model_route::RouteIdentity::same_connection(&session.provider, &disk_p)
                && !client.credential_matches(Some(cred.value.as_str()))
            {
                bail!(
                    "Ключ провайдера {kind} в credentials.json изменился в другом процессе и не отправляется на временный endpoint сессии; переключите провайдера явно через /provider {kind} или /connect {kind}"
                );
            }
            *settings = fresh;
            events.refresh_keys(store)?;
            disk_baseline = disk_p;
            cloud_cred_snapshot = cred_opt;
            session.provider.clone()
        }
    } else {
        let (fresh, cred_opt) = store.read_consistent_cloud(kind)?;
        *settings = fresh;
        events.refresh_keys(store)?;
        let disk_p = crate::model_route::configured_cloud_provider(settings, kind)?
            .unwrap_or_else(|| settings.provider(kind));
        disk_baseline = disk_p.clone();
        cloud_cred_snapshot = cred_opt;
        disk_p
    };
    let unconfigured_custom_with_disk_key = kind == ProviderKind::Custom
        && crate::model_route::configured_cloud_provider(settings, ProviderKind::Custom)?.is_none()
        && cloud_cred_snapshot
            .as_ref()
            .is_some_and(|c| c.source == "credentials.json");
    if kind != ProviderKind::Local
        && (cloud_cred_snapshot.is_none() || unconfigured_custom_with_disk_key)
    {
        next = ui::connect_with_secrets(
            store,
            settings,
            Some(kind),
            rich,
            None,
            &events.secret_snapshot(),
            Some(events.shared_secrets()),
        )
        .await?;
        let (fresh_after, cred_after) = store.read_consistent_cloud(kind)?;
        let disk_after = crate::model_route::configured_cloud_provider(&fresh_after, kind)?
            .unwrap_or_else(|| fresh_after.provider(kind));
        if !crate::model_route::RouteIdentity::same_connection(&next, &disk_after) {
            bail!(
                "Параметры подключения провайдера {kind} изменились в другом процессе; повторите /provider {kind}"
            );
        }
        *settings = fresh_after;
        events.refresh_keys(store)?;
        disk_baseline = disk_after;
        switching_provider = true;
        cloud_cred_snapshot = cred_after;
    }
    if kind == ProviderKind::Local && pending_draft_local.is_none() {
        // A session snapshot whose profile moved or was removed neither lists
        // models nor asks for a key: that key would be saved under the name.
        local_app::check_current_with_baseline(store, &next, &disk_baseline)?;
    }
    if let Some(id) = model {
        let mut extra_secrets = events.secret_snapshot();
        if let Some((draft_key, auth_challenged)) = pending_draft_local.take() {
            let mut key_to_save = draft_key.clone();
            if let Some(ref k) = draft_key {
                extra_secrets.push(k.clone());
            }
            if auth_challenged {
                let _ = events.refresh_keys(store);
                let mut probe_secrets = events.secret_snapshot();
                if let Some(ref k) = draft_key {
                    probe_secrets.push(k.clone());
                }
                match crate::local_ui::catalog_for_connect(
                    store,
                    None,
                    &next,
                    draft_key,
                    auth_challenged,
                    auth_challenged,
                    &probe_secrets,
                )
                .await
                {
                    Ok(out) => {
                        if let Some(ref k) = out.newly_entered_key {
                            extra_secrets.push(k.clone());
                        }
                        key_to_save = out.newly_entered_key;
                    }
                    Err(crate::local_ui::ConnectCatalogError::Fatal(err))
                    | Err(crate::local_ui::ConnectCatalogError::Unreachable(err)) => {
                        return Err(err);
                    }
                }
            }
            next.model = id.clone();
            next.validate()?;
            let _ = events.refresh_keys(store);
            let mut commit_secrets = events.secret_snapshot();
            if let Some(ref k) = key_to_save {
                commit_secrets.push(k.clone());
            }
            crate::model_route::ensure_route_free_of_secrets(store, &next, &commit_secrets)?;
            let name = local_app::profile_name(&next).to_owned();
            let (updated, _) = store.commit_local_profile_add_with_secrets(
                &name,
                false,
                false,
                false,
                next.clone(),
                key_to_save.as_deref(),
                || events.secret_snapshot(),
            )?;
            next = updated.local.profiles[&name].clone();
            *settings = updated;
            events.refresh_keys(store)?;
        }
        let mut candidate_check = next.clone();
        candidate_check.model = id.clone();
        crate::model_route::ensure_route_free_of_secrets(store, &candidate_check, &extra_secrets)?;
        let edit = if switching_provider {
            if id != next.model {
                next.effort = Effort::Auto;
            }
            next.model = id;
            next.validate()?;
            ProviderEdit::Switch(next)
        } else {
            let mut preview = next.clone();
            preview.model = id.clone();
            preview.validate()?;
            ProviderEdit::Model {
                disk_expected: disk_baseline,
                session_base: next,
                model: id,
            }
        };
        // A direct model ID works even when /models is unavailable.
        commit_provider(
            store,
            settings,
            active_disk_origin,
            session,
            client,
            events,
            edit,
        )?;
        models.clear();
        return Ok(());
    }
    let mut draft_key_to_save: Option<String> = None;
    let is_draft_local = pending_draft_local.is_some();
    let Some(mut fetched) = (if let Some((draft_key, auth_challenged)) = pending_draft_local.take()
    {
        match local_draft_catalog(store, &next, draft_key, auth_challenged, events).await? {
            Some((list, key_opt)) => {
                draft_key_to_save = key_opt;
                Some(list)
            }
            None => None,
        }
    } else if kind == ProviderKind::Local {
        local_catalog(
            store,
            &mut next,
            &disk_baseline,
            local_cred_snapshot,
            existing_local_protected,
            events,
        )
        .await?
    } else {
        let cred_state = match cloud_cred_snapshot {
            Some(c) => crate::config::CredentialState::Present(c),
            None => crate::config::CredentialState::Missing,
        };
        let mut candidate_client = local_app::client_with_credential(
            &next,
            cred_state,
            events,
            "Нет ключа выбранного провайдера",
        )?;
        let _ = events.refresh_keys(store);
        crate::model_route::ensure_connection_free_of_secrets(
            store,
            &next,
            &events.secret_snapshot(),
        )?;
        let out = catalog(&mut candidate_client, events).await?;
        for s in candidate_client.redaction_secrets() {
            events.remember(s);
        }
        out
    }) else {
        return Ok(());
    };
    let _ = events.refresh_keys(store);
    let mut extra_secrets = events.secret_snapshot();
    if let Some(ref k) = draft_key_to_save {
        extra_secrets.push(k.clone());
    }
    let secret_dict = crate::model_route::build_route_secret_dictionary(store, &extra_secrets)?;
    let contains_secret = |text: &str| -> bool {
        secret_dict.as_ref().is_some_and(|dict| {
            crate::redaction::redact_text_with(dict, text)
                .ok()
                .as_deref()
                != Some(text)
        })
    };
    fetched = fetched
        .into_iter()
        .filter(|m| !m.id.chars().any(char::is_control) && !contains_secret(&m.id))
        .map(|mut m| {
            if let Some(ref dict) = secret_dict {
                m.name = crate::redaction::redact_text_idempotent_with(dict, &m.name)
                    .unwrap_or_else(|_| "[скрыто]".into());
            }
            m.name = ui::safe(&m.name);
            m
        })
        .collect();
    fetched.sort_by(|a, b| {
        (a.id != next.model)
            .cmp(&(b.id != next.model))
            .then_with(|| a.id.cmp(&b.id))
    });
    if !next.model.is_empty()
        && !contains_secret(&next.model)
        && !fetched.iter().any(|m| m.id == next.model)
    {
        fetched.insert(
            0,
            ModelInfo {
                id: next.model.clone(),
                name: "текущая модель из настроек".into(),
                ..ModelInfo::default()
            },
        );
    }
    let mut choices = fetched
        .iter()
        .map(|m| {
            let mut parts = vec![m.id.clone()];
            if let Some(n) = m.context_length {
                parts.push(format!("контекст {}", presentation::number(n)));
            }
            if m.supports_reasoning == Some(true) {
                parts.push("reasoning".into());
            }
            if m.supports_tools == Some(false) {
                parts.push("нет вызова инструментов".into());
            } else if kind == ProviderKind::Local && m.supports_tools.is_none() {
                parts.push("инструменты не подтверждены".into());
            }
            if m.supports_images == Some(true) {
                parts.push("изображения".into());
            }
            Choice {
                label: m.name.clone(),
                detail: parts.join(" · "),
                enabled: m.supports_tools != Some(false),
            }
        })
        .collect::<Vec<_>>();
    choices.push(Choice {
        label: "Ввести ID модели вручную".into(),
        detail: "для новых или отсутствующих в списке моделей".into(),
        enabled: true,
    });
    let current = fetched
        .iter()
        .position(|m| m.id == next.model)
        .unwrap_or_default();
    let Some(selected) = choose(&format!("Модель · {kind}"), &choices, current, rich)?
    else {
        return Ok(());
    };
    let id = if selected == fetched.len() {
        let _ = events.refresh_keys(store);
        let mut live_manual_secrets = events.secret_snapshot();
        if let Some(ref k) = draft_key_to_save {
            live_manual_secrets.push(k.clone());
        }
        let manual_default =
            if crate::model_route::ensure_route_free_of_secrets(store, &next, &live_manual_secrets)
                .is_ok()
            {
                next.model.as_str()
            } else {
                ""
            };
        ui::line("ID модели", manual_default)?
    } else {
        fetched[selected].id.clone()
    };
    let _ = events.refresh_keys(store);
    let mut post_pick_secrets = events.secret_snapshot();
    if let Some(ref k) = draft_key_to_save {
        post_pick_secrets.push(k.clone());
    }
    let mut candidate_check = next.clone();
    candidate_check.model = id.clone();
    crate::model_route::ensure_route_free_of_secrets(store, &candidate_check, &post_pick_secrets)?;
    if is_draft_local {
        next.model = id.clone();
        next.validate()?;
        let name = local_app::profile_name(&next).to_owned();
        let (updated, _) = store.commit_local_profile_add_with_secrets(
            &name,
            false,
            false,
            false,
            next.clone(),
            draft_key_to_save.as_deref(),
            || events.secret_snapshot(),
        )?;
        next = updated.local.profiles[&name].clone();
        *settings = updated;
        events.refresh_keys(store)?;
    }
    let edit = if switching_provider {
        if id != next.model {
            next.effort = Effort::Auto;
        }
        next.model = id;
        ProviderEdit::Switch(next)
    } else {
        ProviderEdit::Model {
            disk_expected: disk_baseline,
            session_base: next,
            model: id,
        }
    };
    commit_provider(
        store,
        settings,
        active_disk_origin,
        session,
        client,
        events,
        edit,
    )?;
    *models = fetched;
    Ok(())
}
async fn local_draft_catalog(
    store: &ConfigStore,
    profile: &ProviderSettings,
    initial_key: Option<String>,
    pre_challenged_auth: bool,
    events: &Events,
) -> Result<Option<(Vec<ModelInfo>, Option<String>)>> {
    let cancel = tokio_util::sync::CancellationToken::new();
    if let Some(screen) = crate::screen::current() {
        screen.bind_cancel(cancel.clone());
    }
    let _ = events.refresh_keys(store);
    let caller_secrets = events.secret_snapshot();
    events.busy("Получаю список моделей локального сервера");
    let result = tokio::select! {
        value = crate::local_ui::catalog_for_connect(store, None, profile, initial_key, pre_challenged_auth, pre_challenged_auth, &caller_secrets) => Some(value),
        _ = tokio::signal::ctrl_c() => None,
        _ = cancel.cancelled() => None,
    };
    events.pause();
    let (fetched, key_opt) = match result {
        None => return Ok(None),
        Some(Ok(out)) => (out.models, out.newly_entered_key),
        Some(Err(crate::local_ui::ConnectCatalogError::Fatal(error))) => return Err(error),
        Some(Err(crate::local_ui::ConnectCatalogError::Unreachable(error))) => {
            notice!(
                "Список моделей недоступен: {}. Можно ввести ID модели вручную.",
                ui::safe(&events.redact(&format!("{error:#}")))
            );
            (Vec::new(), None)
        }
    };
    Ok(Some((
        crate::local_ui::local_models(fetched, &profile.model),
        key_opt,
    )))
}
/// Models of a local profile endpoint; a 401/403 asks once for the profile key.
/// Unreachable servers still allow a manual model ID.
async fn local_catalog(
    store: &ConfigStore,
    profile: &mut ProviderSettings,
    expected_disk: &ProviderSettings,
    initial_key: Option<String>,
    server_known_protected: bool,
    events: &Events,
) -> Result<Option<Vec<ModelInfo>>> {
    let cancel = tokio_util::sync::CancellationToken::new();
    if let Some(screen) = crate::screen::current() {
        screen.bind_cancel(cancel.clone());
    }
    let _ = events.refresh_keys(store);
    let caller_secrets = events.secret_snapshot();
    events.busy("Получаю список моделей локального сервера");
    let result = tokio::select! {
        value = crate::local_ui::catalog_with_key(store, profile, Some(expected_disk), initial_key, server_known_protected, &caller_secrets) => Some(value),
        _ = tokio::signal::ctrl_c() => None,
        _ = cancel.cancelled() => None,
    };
    events.pause();
    let fetched = match result {
        None => return Ok(None),
        Some(Ok((models, _))) => models,
        Some(Err(crate::local_ui::ConnectCatalogError::Fatal(error))) => return Err(error),
        Some(Err(crate::local_ui::ConnectCatalogError::Unreachable(error))) => {
            // A profile moved meanwhile is an error, not a missing catalog.
            local_app::check_current_with_baseline(store, profile, expected_disk)?;
            notice!(
                "Список моделей недоступен: {}. Можно ввести ID модели вручную.",
                ui::safe(&events.redact(&format!("{error:#}")))
            );
            Vec::new()
        }
    };
    Ok(Some(crate::local_ui::local_models(fetched, &profile.model)))
}

#[allow(clippy::too_many_arguments)]
async fn select_effort(
    args: &[&str],
    rich: bool,
    store: &ConfigStore,
    settings: &mut Settings,
    active_disk_origin: &mut ProviderSettings,
    session: &mut Session,
    client: &mut ProviderClient,
    events: &mut Events,
    models: &mut Vec<ModelInfo>,
) -> Result<()> {
    if session.provider.kind == ProviderKind::Local {
        if args.is_empty() || args == ["auto"] {
            notice!(
                "Для локальных моделей effort всегда auto. Управлять шаблонными рассуждениями (<think>) можно командой /thinking [auto|on|off]."
            );
            return Ok(());
        }
        bail!(
            "Для local effort не настраивается (всегда auto); используйте /thinking [auto|on|off]"
        );
    }
    if models.is_empty() {
        let Some(fetched) = catalog(client, events).await? else {
            return Ok(());
        };
        *models = fetched;
    }
    let meta = models.iter().find(|m| {
        m.id == session.provider.model || session.provider.model.ends_with(&format!("/{}", m.id))
    });
    let options = efforts(&session.provider, meta);
    if options.len() == 1 {
        notice!(
            "Модель не сообщает о поддержке effort. Доступен auto — настройки модели по умолчанию."
        );
    } else if meta.is_none_or(|m| m.supports_reasoning.is_none()) {
        notice!(
            "API не сообщил возможности reasoning этой модели. Уровень будет отправлен явно; модель может его отклонить."
        );
    }
    let effort = if let Some(value) = args.first() {
        value.parse::<Effort>()?
    } else {
        let choices = options
            .iter()
            .map(|e| Choice {
                label: e.to_string(),
                detail: match e {
                    Effort::Auto => "настройки модели по умолчанию; параметр не отправляется",
                    Effort::None => "отключить рассуждения, если модель разрешает",
                    Effort::Minimal | Effort::Low => "быстрее, меньше токенов рассуждений",
                    Effort::Medium => "баланс скорости и глубины",
                    _ => "больше рассуждений; выше задержка и расход токенов",
                }
                .into(),
                enabled: true,
            })
            .collect::<Vec<_>>();
        let current = options
            .iter()
            .position(|e| *e == session.provider.effort)
            .unwrap_or_default();
        let Some(index) = choose("Глубина рассуждений · effort", &choices, current, rich)?
        else {
            return Ok(());
        };
        options[index]
    };
    if !options.contains(&effort) {
        bail!(
            "Effort {effort} недоступен для выбранной модели. Допустимы: {}",
            options
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let disk_baseline = active_disk_origin.clone();
    commit_provider(
        store,
        settings,
        active_disk_origin,
        session,
        client,
        events,
        ProviderEdit::Effort {
            disk_expected: disk_baseline,
            session_base: session.provider.clone(),
            effort,
        },
    )
}
#[allow(clippy::too_many_arguments)]
fn select_thinking(
    args: &[&str],
    rich: bool,
    store: &ConfigStore,
    settings: &mut Settings,
    active_disk_origin: &mut ProviderSettings,
    session: &mut Session,
    client: &mut ProviderClient,
    events: &mut Events,
) -> Result<()> {
    if session.provider.kind != ProviderKind::Local {
        bail!(
            "Команда /thinking доступна только для провайдера local; для облачных провайдеров используйте /effort"
        );
    }
    if args.len() > 1 {
        bail!("Использование: /thinking [auto|on|off]");
    }
    local_app::check_current_with_baseline(store, &session.provider, active_disk_origin)?;
    let runtime = session
        .provider
        .local
        .as_ref()
        .map_or(crate::local::LocalRuntime::OpenAi, |local| local.runtime);
    if runtime == crate::local::LocalRuntime::Ollama && args.is_empty() {
        notice!(
            "Для Ollama rcode не передаёт управление thinking; настройте модель на сервере (режим: auto)."
        );
        return Ok(());
    }
    let options = crate::local::ThinkingMode::all();
    let current_mode = crate::local::ThinkingMode::from_option(
        session
            .provider
            .local
            .as_ref()
            .and_then(|local| local.thinking),
    );
    let mode = if let Some(value) = args.first() {
        value.parse::<crate::local::ThinkingMode>()?
    } else {
        let choices = options
            .iter()
            .map(|mode| Choice {
                label: mode.to_string(),
                detail: match mode {
                    crate::local::ThinkingMode::Auto => {
                        "настройки сервера и шаблона по умолчанию; параметр не отправляется"
                    }
                    crate::local::ThinkingMode::On => {
                        "явно включить рассуждения (enable_thinking = true) и скрывать блок <think>"
                    }
                    crate::local::ThinkingMode::Off => {
                        "явно отключить рассуждения (enable_thinking = false)"
                    }
                }
                .into(),
                enabled: true,
            })
            .collect::<Vec<_>>();
        let current = options
            .iter()
            .position(|mode| *mode == current_mode)
            .unwrap_or_default();
        let Some(index) = choose("Режим рассуждений · thinking", &choices, current, rich)?
        else {
            return Ok(());
        };
        options[index]
    };
    commit_provider(
        store,
        settings,
        active_disk_origin,
        session,
        client,
        events,
        ProviderEdit::Thinking {
            disk_expected: active_disk_origin.clone(),
            session_base: session.provider.clone(),
            thinking: mode.into_option(),
        },
    )
}
fn footer(
    session: &Session,
    runtime: &Cli,
    plan: bool,
    budget: &ContextBudget,
    events: &Events,
) -> Footer {
    let base_permissions = if runtime.permissions() == ApprovalMode::FullAccess {
        "full-access"
    } else if runtime.allow_shell {
        if runtime.permissions() == ApprovalMode::AutoEdit {
            "auto-edit + shell"
        } else {
            "ask + shell"
        }
    } else if runtime.permissions() == ApprovalMode::AutoEdit {
        "auto-edit"
    } else {
        "ask"
    };
    let permissions = if runtime.effective_sandbox.is_active() {
        format!(
            "{base_permissions} · {}",
            runtime.effective_sandbox.short_badge()
        )
    } else {
        base_permissions.into()
    };
    let effort = if session.provider.kind == ProviderKind::Local {
        match session
            .provider
            .local
            .as_ref()
            .and_then(|local| local.thinking)
        {
            Some(true) => "thinking:on".into(),
            Some(false) => "thinking:off".into(),
            None => "auto".into(),
        }
    } else {
        session.provider.effort.to_string()
    };
    Footer {
        model: events.redact(&session.provider.model),
        provider: session.provider.kind.to_string(),
        effort,
        permissions,
        plan,
        context_chars: budget.request_used(&session.messages),
        context_limit: budget.limit,
        context_tokens: budget.is_tokens(),
        input_tokens: session.usage.input_tokens,
        output_tokens: session.usage.output_tokens,
        workspace: session.root.display().to_string(),
    }
}
#[allow(clippy::too_many_arguments)]
fn status(
    session: &Session,
    runtime: &Cli,
    settings: &Settings,
    plan: bool,
    models: &[ModelInfo],
    budget: &ContextBudget,
    skills: &str,
    memory_line: &str,
    events: &Events,
) {
    notice!(
        "\nМодель       {} / {}\nEffort       {}\nРежим        {} · shell {}\nПесочница    {}\nПапка        {}\nСессия       {}",
        session.provider.kind,
        ui::safe(&events.redact(&session.provider.model)),
        session.provider.effort,
        if plan {
            "план (только чтение)"
        } else if runtime.permissions() == ApprovalMode::FullAccess {
            "full-access (без подтверждений)"
        } else if runtime.permissions() == ApprovalMode::AutoEdit {
            "auto-edit"
        } else {
            "подтверждения"
        },
        if plan {
            "запрещён в плане"
        } else if runtime.shell_allowed() {
            "разрешён явно"
        } else {
            "по подтверждению"
        },
        runtime.effective_sandbox.status_label_ru(),
        session.root.display(),
        session.id
    );
    if session.provider.kind == ProviderKind::Local {
        let thinking = crate::local::ThinkingMode::from_option(
            session
                .provider
                .local
                .as_ref()
                .and_then(|local| local.thinking),
        );
        notice!(
            "Профиль      local · {} @{} · thinking {}",
            ui::safe(&events.redact(local_app::profile_name(&session.provider))),
            ui::safe(&events.redact(session.provider.base_url.as_deref().unwrap_or_default())),
            thinking
        );
    }
    context(session, models, budget, skills, memory_line);
    let mode = runtime.final_review_mode();
    let review = crate::final_review::model_target_summary_for_mode(settings, mode);
    notice!(
        "Финальное ревью {} · {} / {}",
        mode.label_ru(),
        review["provider"].as_str().unwrap_or("same"),
        ui::safe(&events.redact(review["model"].as_str().unwrap_or_default()))
    );
    let total_adv_calls = session.effective_advisor_calls();
    let advisor_calls_suffix = if total_adv_calls > 0 {
        let last_status = session
            .advisor_calls
            .last()
            .map(|r| ui::safe(&events.redact(&r.status)))
            .unwrap_or_else(|| String::from("compacted"));
        format!(" · вызовов в сессии: {total_adv_calls} (последний: {last_status})")
    } else {
        String::new()
    };
    notice!(
        "Советник     {}{}",
        ui::safe(&events.redact(&crate::advisor::runtime_status_line_ru(runtime))),
        advisor_calls_suffix
    );
}
/// `skills`: the catalog line of `catalog_summary`.
fn context(
    session: &Session,
    models: &[ModelInfo],
    budget: &ContextBudget,
    skills: &str,
    memory_line: &str,
) {
    if budget.is_tokens() {
        // Local: estimated tokens against the server context; nothing is invented.
        notice!(
            "Контекст     ~{} / {} оценочных токенов (вместе с системным промптом и инструментами)",
            budget.request_used(&session.messages),
            budget.limit
        );
        notice!("{}", budget.limit_sentence());
        if session.last_usage.input_tokens > 0 {
            notice!(
                "Последний запрос — {} входных токенов по данным сервера",
                session.last_usage.input_tokens
            );
        }
        notice!("{skills}");
        notice!("{memory_line}");
        notice!(
            "История сокращается автоматически перед запросом, когда приближается к лимиту. /compact сокращает её вручную, /clear создаёт новую сессию."
        );
        return;
    }
    // Cloud: history plus the fixed overhead (skill catalog and load_skill
    // schema) against the request limit, as in the footer.
    notice!(
        "Контекст     {} / {} символов — локальный бюджет CLI",
        budget.request_used(&session.messages),
        budget.limit
    );
    if budget.overhead > 0 {
        notice!(
            "             из них ~{} — каталог скиллов, память и дополнительные схемы в каждом запросе",
            budget.overhead
        );
    }
    if let Some(m) = models.iter().find(|m| m.id == session.provider.model)
        && let Some(window) = m.context_length
    {
        notice!(
            "Окно API     {} токенов; последний запрос — {} входных токенов",
            presentation::number(window),
            session.last_usage.input_tokens
        );
    }
    notice!("{skills}");
    notice!("{memory_line}");
    notice!(
        "При {} символах история сокращается автоматически перед запросом к API. /compact сокращает её вручную, /clear создаёт новую сессию.",
        budget.threshold()
    );
}
fn unit_label(unit: CatalogUnit) -> &'static str {
    match unit {
        CatalogUnit::Chars => "символов",
        CatalogUnit::EstimatedTokens { .. } => "оценочных токенов",
    }
}
/// The skills line of `/context` and `/status` (DESIGN §9.1).
fn catalog_summary(
    catalog: &SkillCatalog,
    rendered: Option<&RenderedCatalog>,
    unit: CatalogUnit,
) -> String {
    let listed = catalog
        .skills
        .iter()
        .filter(|skill| skill.in_catalog)
        .count();
    let mut line = match rendered {
        Some(rendered) => {
            let mut line = format!(
                "Скиллы       {} в каталоге, ~{} {}",
                rendered.entries + rendered.omitted_ids.len(),
                rendered.cost,
                unit_label(unit)
            );
            if !rendered.omitted_ids.is_empty() {
                line.push_str(&format!(" · без описаний {}", rendered.omitted_ids.len()));
            }
            if rendered.omitted_count > 0 {
                line.push_str(&format!(" · не вошли {}", rendered.omitted_count));
            }
            line
        }
        None if listed > 0 => format!(
            "Скиллы       каталог из {listed} не помещается в бюджет и модели не отправляется"
        ),
        None if catalog.skills.is_empty() => "Скиллы       не найдены".into(),
        None => format!(
            "Скиллы       в каталоге нет; найдено {}",
            catalog.skills.len()
        ),
    };
    line.push_str(" · /skills — подробности");
    line
}
fn memory_summary(memory: &MemorySnapshot, unit: CatalogUnit, secrets: &[String]) -> String {
    let mut line = match &memory.policy {
        MemoryPolicy::DisabledForEval => "Память       отключена в eval".to_owned(),
        MemoryPolicy::DisabledByConfig => "Память       выключена глобально".to_owned(),
        MemoryPolicy::DisabledForProject => "Память       выключена для этого проекта".to_owned(),
        MemoryPolicy::ManifestError(_) => "Память       недоступна (ошибка memory.json)".to_owned(),
        MemoryPolicy::Enabled if memory.notes.is_empty() => {
            "Память       пуста (0 заметок)".to_owned()
        }
        MemoryPolicy::Enabled => match memory.render_index(unit, secrets) {
            Some(rendered) if !rendered.budget_exhausted => {
                let mut s = format!(
                    "Память       {} заметок, индекс ~{} {}",
                    memory.notes.len(),
                    rendered.cost,
                    unit_label(unit)
                );
                if !rendered.omitted_ids.is_empty() {
                    s.push_str(&format!(" · только id {}", rendered.omitted_ids.len()));
                }
                if rendered.omitted_count > 0 {
                    s.push_str(&format!(" · опущено {}", rendered.omitted_count));
                }
                s
            }
            _ => format!(
                "Память       индекс из {} не помещается в бюджет и опущен",
                memory.notes.len()
            ),
        },
    };
    line.push_str(" · /memory — подробности");
    line
}
fn size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} Б")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} КиБ", bytes as f64 / 1024.)
    } else {
        format!("{:.1} МиБ", bytes as f64 / (1024. * 1024.))
    }
}
/// Pads `text` to `width` characters; longer text is clipped with `…`.
fn cell(text: &str, width: usize) -> String {
    let mut clipped: String = text.chars().take(width).collect();
    if text.chars().count() > width {
        clipped.pop();
        clipped.push('…');
    }
    format!("{clipped:<width$}")
}
/// `/skills`: id, scope, status, size and catalog cost of every skill of the
/// snapshot, then discovery errors (DESIGN §6.5). Terminal-safe; the caller
/// redacts known secrets.
fn skills_view(
    catalog: &SkillCatalog,
    unit: CatalogUnit,
    rendered: Option<&RenderedCatalog>,
    secrets: &[String],
) -> String {
    const SHOWN_PROBLEMS: usize = 10;
    // Shadowed skills are rows of the table with their winner.
    let problems: Vec<&SkillProblem> = catalog
        .problems
        .iter()
        .filter(|problem| problem.code != "shadowed")
        .collect();
    if catalog.skills.is_empty() && problems.is_empty() {
        return "Скиллы не найдены. rcode читает каталоги <имя>/SKILL.md из RCODE_HOME/skills и .rcode/skills проекта.".into();
    }
    let label = unit_label(unit);
    let mut output = match rendered {
        Some(rendered) => format!(
            "Скиллы · {} · в каталоге {} · блок ~{} из {} {label}",
            catalog.skills.len(),
            rendered.entries + rendered.omitted_ids.len(),
            rendered.cost,
            catalog.limits.max_cost(unit)
        ),
        None if catalog.skills.iter().any(|skill| skill.in_catalog) => format!(
            "Скиллы · {} · каталог не помещается в бюджет ({} {label}) и модели не отправляется",
            catalog.skills.len(),
            catalog.limits.max_cost(unit)
        ),
        None => format!(
            "Скиллы · {} · каталог пуст: модель видит скиллы только по /skill",
            catalog.skills.len()
        ),
    };
    if !catalog.skills.is_empty() {
        let compiled_dict =
            (!secrets.is_empty()).then(|| crate::redaction::SecretDictionary::new(secrets));
        let redact_cell = |text: &str| -> String {
            match &compiled_dict {
                None => text.to_owned(),
                Some(Ok(dict)) => crate::redaction::redact_text_idempotent_with(dict, text)
                    .unwrap_or_else(|_| "[rcode: текст скрыт из-за ошибки redaction]".into()),
                Some(Err(_)) => "[rcode: текст скрыт из-за ошибки redaction]".into(),
            }
        };
        let entries = catalog.entries_redacted(&catalog.limits, unit, rendered, secrets);
        let rows: Vec<[String; 5]> = catalog
            .skills
            .iter()
            .zip(entries)
            .map(|(skill, entry)| {
                let status = match (&skill.shadowed_by, entry) {
                    (Some(winner), _) => format!("перекрыт: {}", redact_cell(winner)),
                    _ if skill.disabled => "отключён".into(),
                    _ if skill.disable_model_invocation => "только /skill".into(),
                    (_, CatalogEntry::Described(_)) => "в каталоге".into(),
                    (_, CatalogEntry::IdOnly(_)) => "только id".into(),
                    (_, CatalogEntry::Counted | CatalogEntry::Absent) => "не вошёл".into(),
                };
                let cost = match entry {
                    CatalogEntry::Described(cost) | CatalogEntry::IdOnly(cost) => {
                        format!("~{cost}")
                    }
                    CatalogEntry::Counted | CatalogEntry::Absent => "—".into(),
                };
                [
                    ui::safe(&redact_cell(&skill.id)),
                    skill.scope.as_str().into(),
                    ui::safe(&redact_cell(&status)),
                    size(skill.bytes),
                    cost,
                ]
            })
            .collect();
        let width = |column: usize, minimum: usize, maximum: usize| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or_default()
                .clamp(minimum, maximum)
        };
        let (id, scope, status) = (width(0, 2, 48), width(1, 7, 7), width(2, 6, 32));
        output.push_str(&format!(
            "\n  {} {} {} {:>9} {:>7}",
            cell("ID", id),
            cell("Область", scope),
            cell("Статус", status),
            "Размер",
            "Каталог"
        ));
        for row in &rows {
            output.push_str(&format!(
                "\n  {} {} {} {:>9} {:>7}",
                cell(&row[0], id),
                cell(&row[1], scope),
                cell(&row[2], status),
                row[3],
                row[4]
            ));
        }
    }
    if !problems.is_empty() {
        output.push_str(&format!(
            "\nОшибки ({}) — эти скиллы не загружаются:",
            problems.len()
        ));
        for problem in problems.iter().take(SHOWN_PROBLEMS) {
            output.push_str(&format!(
                "\n  ! {}",
                ui::safe(&problem.warning_redacted(secrets))
            ));
        }
        if problems.len() > SHOWN_PROBLEMS {
            output.push_str(&format!("\n  … ещё {}", problems.len() - SHOWN_PROBLEMS));
        }
    }
    output.push_str(&format!(
        "\n«Каталог» — сколько {label} скилл занимает в блоке каталога. /skill ID [запрос] — явно выбрать скилл, в том числе отключённый или «только /skill»."
    ));
    output
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct SkillRequest {
    id: String,
    prompt: String,
}

/// `/skill ID [запрос]` (DESIGN §6.5): the user request for a skill the
/// snapshot can load. The host preloads the first page via a synthetic
/// `load_skill` call before the first model request; unknown and ambiguous ids
/// fail here, without a model request.
fn skill_request(catalog: &SkillCatalog, rest: &str) -> Result<SkillRequest> {
    skill_request_with_secrets(catalog, rest, &[])
}

fn skill_request_with_secrets(
    catalog: &SkillCatalog,
    rest: &str,
    secrets: &[String],
) -> Result<SkillRequest> {
    let rest = rest.trim();
    let (id, request) = rest
        .split_once(char::is_whitespace)
        .map_or((rest, ""), |(id, request)| (id, request.trim()));
    let redact_item = |text: &str| -> String {
        if secrets.is_empty() {
            text.to_owned()
        } else {
            crate::redaction::redact_text_idempotent(text, secrets)
                .unwrap_or_else(|_| "[rcode: текст скрыт из-за ошибки redaction]".into())
        }
    };
    let shown = || ui::safe(&presentation::inline(&redact_item(id), 80));
    let skill = match catalog.find(id) {
        Ok(skill) => skill,
        Err(LookupError::Unknown { suggestions }) if suggestions.is_empty() => {
            bail!(
                "Скилл {} не найден: скиллов нет. /skills покажет, откуда они читаются",
                shown()
            )
        }
        Err(LookupError::Unknown { suggestions }) => bail!(
            "Скилл {} не найден. Похожие: {}. /skills — список",
            shown(),
            suggestions
                .iter()
                .map(|s| redact_item(s))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Err(LookupError::Ambiguous { candidates }) => bail!(
            "Имя {} есть у нескольких скиллов: {}. Укажите полный id",
            shown(),
            candidates
                .iter()
                .map(|s| redact_item(s))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let mut prompt = format!(
        "Пользователь явно выбрал скилл {}; rcode уже загрузил его через load_skill (результат ниже). Если есть next_line — дочитай через load_skill. Действуй по скиллу",
        skill.id
    );
    if request.is_empty() {
        prompt.push('.');
    } else {
        prompt.push_str(": ");
        prompt.push_str(request);
    }
    Ok(SkillRequest {
        id: skill.id.clone(),
        prompt,
    })
}

#[cfg(test)]
fn skill_menu(
    catalog: &SkillCatalog,
    registry: &crate::commands::CommandRegistry,
) -> Vec<terminal::MenuCommand> {
    skill_menu_redacted(catalog, registry, &[])
}

fn skill_menu_redacted(
    catalog: &SkillCatalog,
    registry: &crate::commands::CommandRegistry,
    secrets: &[String],
) -> Vec<terminal::MenuCommand> {
    let compiled_dict =
        (!secrets.is_empty()).then(|| crate::redaction::SecretDictionary::new(secrets));
    let redact_item = |text: &str| -> Option<String> {
        match &compiled_dict {
            None => Some(text.to_owned()),
            Some(Ok(dict)) => crate::redaction::redact_text_idempotent_with(dict, text).ok(),
            Some(Err(_)) => None,
        }
    };
    let available: Vec<_> = catalog
        .skills
        .iter()
        .filter(|skill| skill.shadowed_by.is_none())
        .collect();
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for skill in &available {
        *counts.entry(skill.name.as_str()).or_default() += 1;
    }
    let occupied: std::collections::BTreeSet<String> = crate::commands::builtin_names()
        .into_iter()
        .chain(registry.menu().into_iter().map(|command| command.name))
        .collect();
    let mut menu = Vec::new();
    for skill in available {
        let Some(clean_id) = redact_item(&skill.id) else {
            continue;
        };
        if clean_id != skill.id {
            continue;
        }
        let canonical = format!("/{}", skill.id);
        if occupied.contains(&canonical) {
            continue;
        }
        let status = if skill.disabled {
            " · выключен, явный выбор"
        } else if skill.disable_model_invocation {
            " · только явный выбор"
        } else {
            ""
        };
        let clean_desc: String = redact_item(&skill.raw_description)
            .unwrap_or_else(|| "[скрыто]".into())
            .chars()
            .take(1024)
            .collect();
        let description = format!("{clean_desc}{status}");
        menu.push(terminal::MenuCommand {
            name: canonical,
            description: description.clone(),
            custom: false,
            skill: Some(skill.id.clone()),
        });
        let alias = format!("/{}", skill.name);
        if skill.name != skill.id
            && counts.get(skill.name.as_str()) == Some(&1)
            && !occupied.contains(&alias)
            && redact_item(&skill.name).as_deref() == Some(skill.name.as_str())
        {
            menu.push(terminal::MenuCommand {
                name: alias,
                description,
                custom: false,
                skill: Some(skill.id.clone()),
            });
        }
    }
    menu
}

fn start_skill_request(
    catalog: &SkillCatalog,
    menu: &[terminal::MenuCommand],
    input: &str,
) -> Result<Option<SkillRequest>> {
    let mut words = input.splitn(2, char::is_whitespace);
    let first = words.next().unwrap_or_default();
    let arguments = words.next().unwrap_or_default().trim();
    let reserved = menu
        .iter()
        .any(|command| command.name == first && command.skill.is_none())
        || crate::commands::builtin_names()
            .iter()
            .any(|name| name == first);
    let canonical = if reserved {
        None
    } else {
        menu.iter()
            .find(|command| command.skill.is_some() && command.name == first)
            .and_then(|command| command.skill.as_deref())
            .or_else(|| {
                catalog
                    .skills
                    .iter()
                    .find(|skill| skill.shadowed_by.is_none() && format!("/{}", skill.id) == first)
                    .map(|skill| skill.id.as_str())
            })
    };
    canonical
        .map(|id| skill_request(catalog, &format!("{id} {arguments}")))
        .transpose()
}
fn cost(session: &Session, events: &Events) {
    notice!(
        "\nТокены API за сессию: ↑{} входных · ↓{} выходных · {} кэшированных",
        session.usage.input_tokens,
        session.usage.output_tokens,
        session.usage.cached_input_tokens
    );
    match session.last_usage.cost_usd {
        Some(value) => notice!("Стоимость последнего вызова API: ${value:.6}"),
        None => {
            notice!("Стоимость: API не сообщил цену последнего вызова; оценку не подставляем.")
        }
    }
    let mut review_totals: std::collections::BTreeMap<(String, String), (u64, u64)> =
        Default::default();
    for review in &session.final_reviews {
        if let Some(usage) = &review.usage {
            let totals = review_totals
                .entry((review.provider.clone(), review.model.clone()))
                .or_default();
            totals.0 = totals.0.saturating_add(usage.input_tokens);
            totals.1 = totals.1.saturating_add(usage.output_tokens);
        }
    }
    if !review_totals.is_empty() {
        notice!("Отдельное финальное ревью:");
        for ((provider, model), (input, output)) in review_totals {
            notice!(
                "  {} / {} · ↑{} входных · ↓{} выходных",
                ui::safe(&events.redact(&provider)),
                ui::safe(&events.redact(&model)),
                input,
                output
            );
        }
    }
    for (source_key, title) in [
        ("advisor", "Советник (/advisor):"),
        ("subagent", "Маршрутизированные субагенты:"),
    ] {
        let rows: Vec<_> = session
            .auxiliary_usage
            .iter()
            .filter(|entry| entry.source == source_key)
            .collect();
        if !rows.is_empty() {
            notice!("{title}");
            for row in rows {
                let route = match &row.local_profile {
                    Some(profile) => {
                        format!(
                            "local:{} / {}",
                            ui::safe(&events.redact(profile)),
                            ui::safe(&events.redact(&row.model))
                        )
                    }
                    None => format!(
                        "{} / {}",
                        ui::safe(&events.redact(&row.provider)),
                        ui::safe(&events.redact(&row.model))
                    ),
                };
                let cost_suffix = match row.usage.cost_usd {
                    Some(usd) if row.priced_calls > 0 && row.priced_calls < row.calls => {
                        format!(
                            " · ${usd:.6} (цена для {}/{} выз.)",
                            row.priced_calls, row.calls
                        )
                    }
                    Some(usd) => format!(" · ${usd:.6}"),
                    None => String::new(),
                };
                notice!(
                    "  {route} ({} выз.) · ↑{} входных · ↓{} выходных{cost_suffix}",
                    row.calls,
                    row.usage.input_tokens,
                    row.usage.output_tokens,
                );
            }
        }
    }
}

fn review_model_command(
    args: &[&str],
    store: &ConfigStore,
    settings: &mut Settings,
    mode: crate::final_review::FinalReviewMode,
    events: &Events,
) -> Result<()> {
    match args {
        [] | ["status"] => {
            let _ = events.refresh_keys(store);
            let value = crate::final_review::redacted_model_target_summary_for_mode(
                store,
                settings,
                mode,
                &events.secret_snapshot(),
            );
            notice!(
                "Финальное ревью: {} · {} / {}",
                mode.label_ru(),
                value["provider"].as_str().unwrap_or("same"),
                ui::safe(value["model"].as_str().unwrap_or_default())
            );
        }
        ["same"] => {
            crate::final_review::set_same(store, settings)?;
            notice!("✓ Цель финального ревью: текущая основная модель");
        }
        [provider, model] => {
            let _ = events.refresh_keys(store);
            crate::final_review::set_selected_with_secrets(
                store,
                settings,
                provider,
                None,
                model,
                || events.secret_snapshot(),
            )?;
            let _ = events.refresh_keys(store);
            notice!(
                "✓ Цель финального ревью сохранена для {} / {}",
                ui::safe(&events.redact(provider)),
                ui::safe(&events.redact(model))
            );
        }
        ["local", profile, model] => {
            let _ = events.refresh_keys(store);
            crate::final_review::set_selected_with_secrets(
                store,
                settings,
                "local",
                Some(profile),
                model,
                || events.secret_snapshot(),
            )?;
            let _ = events.refresh_keys(store);
            notice!(
                "✓ Цель финального ревью сохранена для local / {} / {}",
                ui::safe(&events.redact(profile)),
                ui::safe(&events.redact(model))
            );
        }
        _ => bail!("Использование: /review-model [status|same|PROVIDER MODEL|local PROFILE MODEL]"),
    }
    Ok(())
}
fn agents_view(records: &[Value], selector: Option<&str>) -> Result<String> {
    if let Some(selector) = selector {
        if selector.is_empty() {
            bail!("Укажите ID субагента или однозначный префикс: /agents ID");
        }
        let selected = records.iter().find(|record| record["id"] == selector);
        let selected = match selected {
            Some(record) => record,
            None => {
                let mut matches = records.iter().filter(|record| {
                    record["id"]
                        .as_str()
                        .is_some_and(|id| id.starts_with(selector))
                });
                let record = matches
                    .next()
                    .context("Субагент не найден. /agents покажет доступные ID.")?;
                if matches.next().is_some() {
                    bail!(
                        "Префикс ID неоднозначен. Укажите больше символов; /agents покажет задачи."
                    );
                }
                record
            }
        };
        let task = bounded_agent_text(selected["task"].as_str().unwrap_or_default(), 4_000);
        let result = bounded_agent_text(selected["result"].as_str().unwrap_or_default(), 8_000);
        return Ok(format!(
            "{}\nID: {}\nЗадача:\n{}\nРезультат:\n{}",
            presentation::agent_heading(selected),
            presentation::inline(selected["id"].as_str().unwrap_or_default(), 80),
            task,
            if result.is_empty() {
                "Результат пока не получен."
            } else {
                &result
            },
        ));
    }
    if records.is_empty() {
        return Ok(
            "В этой сессии субагенты ещё не запускались. Попросите делегировать часть задачи."
                .into(),
        );
    }
    let mut output = format!(
        "Субагенты · {} задач · /agents ID — подробности",
        records.len().min(24)
    );
    for record in records.iter().rev().take(24) {
        output.push_str(&format!("\n  {}", presentation::agent_heading(record)));
        if let Some(result) = record["result"]
            .as_str()
            .and_then(|text| text.lines().find(|line| !line.trim().is_empty()))
        {
            output.push_str(&format!("\n    ↳ {}", presentation::inline(result, 160)));
        }
    }
    Ok(output)
}
fn bounded_agent_text(text: &str, limit: usize) -> String {
    let text = ui::safe(text);
    let mut characters = text.chars();
    let mut result: String = characters.by_ref().take(limit).collect();
    if characters.next().is_some() {
        result.push_str("\n… сокращено");
    }
    result
}
fn help(registry: &crate::commands::CommandRegistry, events: &Events) {
    use std::fmt::Write as _;
    let mut out = String::from("\nКоманды rcode\n");
    for c in terminal::COMMANDS {
        let _ = writeln!(out, "  {:15} {}", c.name, c.description);
    }
    out.push_str(
        "  !команда       Выполнить локальную shell-команду без запроса к модели; Ctrl+C/Esc — прервать\n",
    );
    let custom: Vec<_> = registry.loadable().collect();
    if !custom.is_empty() {
        let secrets = events.secret_snapshot();
        out.push_str("\nПользовательские команды\n");
        for c in custom {
            let hint = c
                .hint
                .as_deref()
                .map(|hint| format!(" [{}]", events.redact(hint)))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  {:15} {} · {}",
                ui::safe(&events.redact(&format!("/{}", c.name))),
                ui::safe(&format!("{}{hint}", c.description_redacted(&secrets))),
                c.scope.as_str()
            );
        }
        let unsupported: Vec<_> = registry
            .loadable()
            .filter(|c| !c.unsupported.is_empty())
            .map(|c| ui::safe(&events.redact(&format!("/{}", c.name))))
            .collect();
        if !unsupported.is_empty() {
            let _ = writeln!(
                out,
                "  {} — синтаксис !-shell и @файл не исполняется, текст уходит модели как есть",
                unsupported.join(", ")
            );
        }
    }
    if registry
        .commands
        .iter()
        .any(|c| c.shadowed_by == Some(crate::commands::Shadow::Builtin))
    {
        out.push_str(
            "  Файлы с именами встроенных команд не используются (например, permissions.md).\n",
        );
    }
    out.push_str(
        "\n/model [ID] | /model [провайдер] [ID] · /effort [уровень] · /thinking [auto|on|off]\n/advisor [status|off|СЕЛЕКТОР] — модель-советник · /review-model status|same|ПРОВАЙДЕР МОДЕЛЬ\n/final-review on|off|status — включить ревью для следующих ходов этого запуска\n/resume [ID|latest] · /permissions [ask|auto-edit|full-access]\n/sandbox [status|off|workspace-write|read-only|network on|off] — OS-песочница shell модели\n/export [\"путь.md\"] — сохранённый диалог и отдельные ревью в Markdown\n/attach \"путь.png\" [запрос] — изображение; также можно вставить путь к PNG/JPEG/TIFF\n/agents [ID] — задачи и результаты субагентов; ID можно сократить\n/skills — найденные скиллы и стоимость каталога · /skill ID [запрос] — явно выбрать скилл\n/memory [status|show|log|undo|rm|on|off] — межсессионная память и ревизии\n/btw <вопрос> — быстрый вопрос по контексту без инструментов и записи в историю\nВвод: / меню · Tab дополнение · ↑↓ выбор/история · Shift+Enter / Alt+Enter / Ctrl+J новая строка · Enter в ходе — дорулить задачу\nМышь: колесо — история; выделение — копирование; Ctrl+C копирует выделение; Esc снимает.\nCtrl+O раскрыть/свернуть вывод команд в полноэкранном интерфейсе\nCtrl+C отменить без выделения · Ctrl+D выход · Esc закрыть меню\nФинальное ревью выключено по умолчанию; это отдельный запрос к выбранной модели без инструментов.\nИзменения файлов — через diff/подтверждение; full-access выполняет файлы и shell без запросов.",
    );
    notice!("{out}");
}

fn permissions_choice(
    args: &[&str],
    rich: bool,
    current: ApprovalMode,
) -> Result<Option<ApprovalMode>> {
    if args.len() > 1 {
        bail!("/permissions [ask|auto-edit|full-access]");
    }
    if let Some(mode) = args.first() {
        return Ok(Some(match *mode {
            "ask" => ApprovalMode::Ask,
            "auto-edit" => ApprovalMode::AutoEdit,
            "full-access" => ApprovalMode::FullAccess,
            _ => bail!("Доступны ask, auto-edit и full-access"),
        }));
    }
    let modes = [
        ApprovalMode::Ask,
        ApprovalMode::AutoEdit,
        ApprovalMode::FullAccess,
    ];
    let choices = [
        Choice {
            label: "ask".into(),
            detail: "подтверждать изменения файлов, внешние каталоги и shell".into(),
            enabled: true,
        },
        Choice {
            label: "auto-edit".into(),
            detail: "файловые правки автоматически; внешние каталоги и shell по подтверждению"
                .into(),
            enabled: true,
        },
        Choice {
            label: "full-access · Полный доступ".into(),
            detail: "без подтверждений: файлы, внешние каталоги и shell с вашими правами".into(),
            enabled: true,
        },
    ];
    let selected = choose(
        "Разрешения · выбор сохраняется для этого проекта",
        &choices,
        modes.iter().position(|m| *m == current).unwrap_or_default(),
        rich,
    )?;
    Ok(selected.map(|i| modes[i]))
}

fn apply_permissions(
    mode: ApprovalMode,
    store: &ConfigStore,
    session: &Session,
    runtime: &mut Cli,
    tools: &mut Tools,
) -> Result<()> {
    let mut next = runtime.clone();
    next.approval_mode = Some(mode);
    next.allow_shell = false;
    // Drop directory grants from the prior mode, retaining checkpoints and
    // directories explicitly supplied by the operator with --add-dir.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Reconfigure directory capabilities in place: opening a second Tools
        // for this checkpoint would conflict with its lifetime WAL lease.
        let next_grants = tools.prepare_directory_grants(&next.add_dir)?;
        store.save_permissions(&session.root, mode)?;
        *runtime = next;
        tools.replace_directory_grants(next_grants);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Other platforms retain their existing best-effort Tools backend,
        // which has no lifetime WAL lease to transfer.
        let next_tools = configured_tools(
            &session.root,
            &session.dir(store).join("checkpoints"),
            &next,
        )?;
        store.save_permissions(&session.root, mode)?;
        *runtime = next;
        *tools = next_tools;
    }
    notice!(
        "✓ Разрешения: {} · {} · сохранено для этого проекта",
        mode.as_str(),
        if mode == ApprovalMode::FullAccess {
            "без подтверждений"
        } else {
            "shell по подтверждению"
        }
    );
    Ok(())
}

fn sandbox_command(
    args: &[&str],
    rich: bool,
    store: &ConfigStore,
    session: &Session,
    runtime: &mut Cli,
    events: &Events,
) -> Result<()> {
    use crate::cli::Toggle;
    use crate::sandbox::{
        EffectiveSandboxPolicy, ProjectSandbox, SandboxMode, ensure_mode_supported, probe_support,
    };

    if crate::memory::is_eval_environment(runtime, store.root()) {
        bail!("Управление песочницей отключено в изолированном режиме rcode eval");
    }

    match args {
        ["status"] => {
            let support = probe_support();
            let saved = store.project_sandbox(&session.root)?;
            let text = crate::sandbox_cli::render_status_text(
                &session.root,
                &support,
                saved,
                runtime.effective_sandbox,
            );
            notice!("\n{}", events.redact(&text));
            Ok(())
        }
        [] => {
            let support = probe_support();
            let presets = [
                ProjectSandbox {
                    mode: SandboxMode::Off,
                    network: false,
                },
                ProjectSandbox {
                    mode: SandboxMode::WorkspaceWrite,
                    network: false,
                },
                ProjectSandbox {
                    mode: SandboxMode::WorkspaceWrite,
                    network: true,
                },
                ProjectSandbox {
                    mode: SandboxMode::ReadOnly,
                    network: false,
                },
            ];
            let choices = [
                Choice {
                    label: "off".into(),
                    detail: "выключена: shell запускается с правами пользователя".into(),
                    enabled: true,
                },
                Choice {
                    label: "workspace-write".into(),
                    detail: "запись только в проект и TMPDIR задания, сеть заблокирована".into(),
                    enabled: support.available,
                },
                Choice {
                    label: "workspace-write + network".into(),
                    detail: "запись в проект и TMPDIR задания, разрешена только IP-сеть".into(),
                    enabled: support.available,
                },
                Choice {
                    label: "read-only".into(),
                    detail: "проект только на чтение, запись только в TMPDIR задания, сеть заблокирована"
                        .into(),
                    enabled: support.available,
                },
            ];
            let default_idx = match (
                runtime.effective_sandbox.mode,
                runtime.effective_sandbox.network,
            ) {
                (SandboxMode::Off, _) => 0,
                (SandboxMode::WorkspaceWrite, false) => 1,
                (SandboxMode::WorkspaceWrite, true) => 2,
                (SandboxMode::ReadOnly, _) => 3,
            };
            let Some(idx) = choose(
                "OS-песочница shell модели · выбор сохраняется для этого проекта",
                &choices,
                default_idx,
                rich,
            )?
            else {
                return Ok(());
            };
            let chosen = presets[idx];
            ensure_mode_supported(chosen.mode)?;
            store.save_project_sandbox(&session.root, chosen)?;
            runtime.sandbox = Some(chosen.mode);
            runtime.sandbox_network = Some(if chosen.network {
                Toggle::On
            } else {
                Toggle::Off
            });
            runtime.effective_sandbox = EffectiveSandboxPolicy {
                mode: chosen.mode,
                network: if chosen.mode == SandboxMode::Off {
                    false
                } else {
                    chosen.network
                },
            };
            notice!(
                "✓ OS-песочница: {} · сохранено для этого проекта",
                runtime.effective_sandbox.status_label_ru()
            );
            Ok(())
        }
        [mode_raw @ ("off" | "workspace-write" | "read-only")] => {
            let mode: SandboxMode = mode_raw.parse()?;
            ensure_mode_supported(mode)?;
            let mut saved = store.project_sandbox(&session.root)?;
            saved.mode = mode;
            let next_net_flag = if mode == SandboxMode::Off {
                None
            } else {
                runtime.sandbox_network
            };
            let effective = EffectiveSandboxPolicy::resolve(saved, Some(mode), next_net_flag)?;
            if effective.is_active() {
                ensure_mode_supported(effective.mode)?;
            }
            store.save_project_sandbox(&session.root, saved)?;
            runtime.sandbox = Some(mode);
            runtime.sandbox_network = next_net_flag;
            runtime.effective_sandbox = effective;
            notice!(
                "✓ OS-песочница: {} · сохранено для этого проекта",
                runtime.effective_sandbox.status_label_ru()
            );
            Ok(())
        }
        ["network", state_raw @ ("on" | "off")] => {
            let net = *state_raw == "on";
            let mut saved = store.project_sandbox(&session.root)?;
            saved.network = net;
            let next_net_flag = if runtime.effective_sandbox.is_active() {
                Some(if net { Toggle::On } else { Toggle::Off })
            } else {
                None
            };
            let effective = EffectiveSandboxPolicy::resolve(saved, runtime.sandbox, next_net_flag)?;
            if effective.is_active() {
                ensure_mode_supported(effective.mode)?;
            }
            store.save_project_sandbox(&session.root, saved)?;
            runtime.sandbox_network = next_net_flag;
            runtime.effective_sandbox = effective;
            notice!(
                "✓ Сеть песочницы проекта: {} · эффективная политика: {}",
                if net {
                    "разрешена (IPv4/IPv6)"
                } else {
                    "заблокирована"
                },
                runtime.effective_sandbox.status_label_ru()
            );
            Ok(())
        }
        _ => bail!(
            "Использование: /sandbox [status|off|workspace-write|read-only|network on|network off]"
        ),
    }
}
/// Discovery warnings, at most ten lines; shown again only when the set changes.
fn skill_problems(problems: &[SkillProblem], events: &Events) {
    const SHOWN: usize = 10;
    let secrets = events.secret_snapshot();
    for problem in problems.iter().take(SHOWN) {
        notice!("! {}", ui::safe(&problem.warning_redacted(&secrets)));
    }
    if problems.len() > SHOWN {
        notice!("! Скиллы: ещё предупреждений — {}", problems.len() - SHOWN);
    }
}

/// Command-file warnings, at most ten lines; shown again only when the set changes.
fn command_problems(problems: &[crate::commands::CommandProblem], events: &Events) {
    const SHOWN: usize = 10;
    for problem in problems.iter().take(SHOWN) {
        notice!(
            "! {}: {} ({})",
            ui::safe(&events.redact(&problem.path.display().to_string())),
            ui::safe(&events.redact(&problem.message)),
            problem.code
        );
    }
    if problems.len() > SHOWN {
        notice!("! Команды: ещё предупреждений — {}", problems.len() - SHOWN);
    }
}

/// Memory discovery warnings, at most ten lines; shown again only when the set changes.
fn memory_problems(problems: &[MemoryProblem], events: &Events) {
    const SHOWN: usize = 10;
    for problem in problems.iter().take(SHOWN) {
        notice!("! {}", ui::safe(&events.redact(&problem.warning())));
    }
    if problems.len() > SHOWN {
        notice!("! Память: ещё предупреждений — {}", problems.len() - SHOWN);
    }
}

fn emit_memory_warnings(warnings: &[String], events: &Events) -> Result<()> {
    for w in warnings {
        let safe = events.redact_checked(w)?;
        notice!("⚠ {safe}");
    }
    Ok(())
}

fn memory_command(
    args: &[&str],
    cli: &Cli,
    plan: bool,
    store: &ConfigStore,
    session: &Session,
    client: &ProviderClient,
    events: &Events,
) -> Result<()> {
    if crate::memory::is_eval_environment(cli, store.root()) {
        bail!("Межсессионная память отключена в изолированном режиме rcode eval");
    }
    crate::memory::ensure_storage_outside_project(store.root(), &session.root)?;
    events.refresh_keys(store)?;
    let secrets = events.secret_snapshot();
    let mem_store = MemoryStore::new(store.root());
    match args {
        [] | ["status"] => {
            let unit = catalog_unit_for_client(client, session);
            let (_, text) = crate::memory_cli::build_status_report(
                &session.root,
                store,
                &mem_store,
                unit,
                &secrets,
                Some((session, cli, plan)),
                plan,
            )?;
            let safe = events.redact_checked(&text)?;
            notice!("\n{safe}");
            Ok(())
        }
        ["show", id] => {
            let (_, text) =
                crate::memory_cli::format_note_show(&session.root, &mem_store, id, &secrets)?;
            let safe = events.redact_checked(&text)?;
            notice!("\n{safe}");
            Ok(())
        }
        ["log", id] => {
            let (_, text) =
                crate::memory_cli::format_note_log(&session.root, &mem_store, id, &secrets)?;
            let safe = events.redact_checked(&text)?;
            notice!("\n{safe}");
            Ok(())
        }
        ["undo", id] => {
            let parsed = MemoryId::parse(id)?;
            let out = mem_store.undo(&session.root, &parsed, None, false, &secrets, None)?;
            emit_memory_warnings(&out.warnings, events)?;
            notice!("✓ Откат заметки {parsed} выполнен.");
            Ok(())
        }
        ["rm", "--purge", id] | ["rm", id, "--purge"] => {
            let parsed = MemoryId::parse(id)?;
            let deleted = mem_store.commit_delete(
                &session.root,
                &parsed,
                crate::memory::DeleteCas::Any,
                true,
                &secrets,
                None,
            )?;
            emit_memory_warnings(&deleted.warnings, events)?;
            if deleted.deleted_sha256.is_some() {
                notice!(
                    "✓ Заметка {parsed} и её ревизии удалены (--purge). Уже отправленные сообщения текущей сессии остаются в истории диалога."
                );
            } else {
                notice!(
                    "✓ Оставшиеся ревизии уже удалённой заметки {parsed} очищены (--purge). Уже отправленные сообщения текущей сессии остаются в истории диалога."
                );
            }
            Ok(())
        }
        ["rm", id] => {
            let parsed = MemoryId::parse(id)?;
            let deleted = mem_store.commit_delete(
                &session.root,
                &parsed,
                crate::memory::DeleteCas::Any,
                false,
                &secrets,
                None,
            )?;
            emit_memory_warnings(&deleted.warnings, events)?;
            notice!("✓ Заметка {parsed} удалена (доступен откат через /memory undo {parsed}).");
            Ok(())
        }
        ["on"] | ["on", "--project"] | ["off"] | ["off", "--project"] => {
            let enable = args[0] == "on";
            let project_only = args.len() == 2;
            let (outcome, project_id) = crate::memory_cli::apply_enable_toggle(
                &session.root,
                &mem_store,
                enable,
                project_only,
            )?;
            emit_memory_warnings(&outcome.warnings, events)?;
            let scope_label = if project_only {
                format!("для проекта {project_id}")
            } else {
                "глобально".to_owned()
            };
            notice!(
                "✓ Межсессионная память {scope_label}: {}. Уже отправленные сообщения текущей сессии остаются в истории диалога; настройка действует со следующего хода.",
                if enable {
                    "включена"
                } else {
                    "выключена"
                }
            );
            Ok(())
        }
        _ => bail!(
            "Использование: /memory [status | show <scope/slug> | log <scope/slug> | undo <scope/slug> | rm [--purge] <scope/slug> | on [--project] | off [--project]]"
        ),
    }
}
fn validate_restored_cloud_connection(
    same_session: bool,
    credential_unchanged: bool,
    current_session_provider: &ProviderSettings,
    current_disk_origin: &ProviderSettings,
    provider: &ProviderSettings,
    disk_origin: &ProviderSettings,
    cred_source: Option<&str>,
) -> Result<()> {
    let unchanged_in_process_override = same_session
        && credential_unchanged
        && provider.kind == current_session_provider.kind
        && crate::model_route::RouteIdentity::same_connection(provider, current_session_provider)
        && crate::model_route::RouteIdentity::disk_unchanged(current_disk_origin, disk_origin);
    if cred_source == Some("credentials.json")
        && !unchanged_in_process_override
        && !crate::model_route::RouteIdentity::same_connection(provider, disk_origin)
    {
        bail!(
            "Параметры подключения провайдера {} изменились после сохранения сессии; переключите провайдера через /provider {} или /connect {}",
            provider.kind,
            provider.kind,
            provider.kind
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn restore_session_client(
    store: &ConfigStore,
    settings: &mut Settings,
    same_session: bool,
    current_client: &ProviderClient,
    current_session_provider: &ProviderSettings,
    current_disk_origin: &ProviderSettings,
    provider: &ProviderSettings,
    events: &mut Events,
) -> Result<(ProviderClient, ProviderSettings)> {
    if provider.kind == ProviderKind::Local {
        let (fresh, cred) = store.read_consistent_local(provider)?;
        let name = local_app::profile_name(provider);
        let disk_origin = crate::model_route::configured_local_profile(&fresh, name)?
            .unwrap_or_else(|| provider.clone());
        let credential_unchanged = match &cred {
            crate::config::CredentialState::Present(c) => {
                current_client.credential_matches(Some(c.value.as_str()))
            }
            _ => current_client.credential_matches(None),
        };
        if matches!(cred, crate::config::CredentialState::Present(_)) {
            validate_restored_cloud_connection(
                same_session,
                credential_unchanged,
                current_session_provider,
                current_disk_origin,
                provider,
                &disk_origin,
                Some("credentials.json"),
            )?;
        } else if same_session
            && fresh.local.profiles.contains_key(name)
            && !crate::model_route::RouteIdentity::disk_unchanged(current_disk_origin, &disk_origin)
        {
            bail!(
                "Параметры подключения локального профиля «{name}» изменились в другом процессе; переключите профиль через /provider local"
            );
        }
        *settings = fresh;
        events.refresh_keys(store)?;
        let next = local_app::client_with_credential(
            provider,
            cred,
            events,
            "Нет ключа провайдера сохранённой сессии",
        )?;
        crate::model_route::ensure_route_free_of_secrets(
            store,
            provider,
            &events.secret_snapshot(),
        )?;
        Ok((next, disk_origin))
    } else {
        let (fresh, cred) = store.read_consistent_cloud(provider.kind)?;
        let configured_on_disk =
            crate::model_route::configured_cloud_provider(&fresh, provider.kind)?;
        if provider.kind == ProviderKind::Custom
            && configured_on_disk.is_none()
            && cred
                .as_ref()
                .is_some_and(|c| c.source == "credentials.json")
        {
            bail!(
                "Провайдер custom не настроен в config.json; сохранённый ключ в credentials.json не отправляется на адрес по умолчанию. Выполните /connect custom"
            );
        }
        let disk_origin = configured_on_disk.unwrap_or_else(|| fresh.provider(provider.kind));
        let credential_unchanged =
            current_client.credential_matches(cred.as_ref().map(|c| c.value.as_str()));
        validate_restored_cloud_connection(
            same_session,
            credential_unchanged,
            current_session_provider,
            current_disk_origin,
            provider,
            &disk_origin,
            cred.as_ref().map(|c| c.source.as_str()),
        )?;
        *settings = fresh;
        events.refresh_keys(store)?;
        let state = match cred {
            Some(c) => crate::config::CredentialState::Present(c),
            None => crate::config::CredentialState::Missing,
        };
        let next = local_app::client_with_credential(
            provider,
            state,
            events,
            "Нет ключа провайдера сохранённой сессии",
        )?;
        crate::model_route::ensure_route_free_of_secrets(
            store,
            provider,
            &events.secret_snapshot(),
        )?;
        Ok((next, disk_origin))
    }
}

/// `skills`: the snapshot `dispatch` discovered; later inputs rediscover.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run(
    cli: &Cli,
    store: &ConfigStore,
    settings: &mut Settings,
    session: &mut Session,
    tools: &mut Tools,
    client: &mut ProviderClient,
    events: &mut Events,
    skills: SkillCatalog,
    execution: &mut crate::session_runtime::SessionRuntime,
) -> Result<i32> {
    session.bind_secret_source(events.shared_secrets());
    execution.activate()?;
    execution.reconcile_receipts(session)?;
    let rich = events.display.is_rich();
    let initial_memory = discover_memory(store, cli, &session.root, &events.secret_snapshot());
    let _screen = if rich {
        Some(crate::screen::start(footer(
            session,
            cli,
            cli.plan,
            &context_budget_with_memory(
                client,
                session,
                cli,
                cli.plan,
                &skills,
                &initial_memory,
                &events.secret_snapshot(),
            ),
            events,
        ))?)
    } else {
        None
    };
    let mut runtime = cli.clone();
    let mut active_disk_origin = if session.provider.kind == ProviderKind::Local {
        crate::model_route::configured_local_profile(
            settings,
            local_app::profile_name(&session.provider),
        )
        .ok()
        .flatten()
        .unwrap_or_else(|| session.provider.clone())
    } else {
        crate::model_route::configured_cloud_provider(settings, session.provider.kind)
            .ok()
            .flatten()
            .unwrap_or_else(|| settings.provider(session.provider.kind))
    };
    let mut balance_monitor = start_balance_monitor(client, session);
    let mut plan = cli.plan;
    let mut composer = terminal::Editor::new();
    let mut input_history =
        match crate::input_history::InputHistory::load(store, &session.root, |text| {
            events.redact(text)
        }) {
            Ok((history, entries)) => {
                for entry in entries {
                    composer.add_history(&entry);
                }
                Some(history)
            }
            Err(error) => {
                notice!(
                    "Не удалось загрузить историю ввода: {}",
                    events.redact(&format!("{error:#}"))
                );
                None
            }
        };
    let mut models = Vec::<ModelInfo>::new();
    let mut pending: std::collections::VecDeque<String> = cli.prompt.clone().into_iter().collect();
    let mut interrupted: Option<Instant> = None;
    presentation::welcome(
        &session.root,
        &session.provider.kind.to_string(),
        &events.redact(&session.provider.model),
        rich,
    );
    if !rich && runtime.effective_sandbox.is_active() {
        notice!(
            "OS-песочница: {}",
            runtime.effective_sandbox.status_label_ru()
        );
    }
    let restored_context = if cli.resume.is_some() {
        // Compact before hydration, then announce below the restored conversation.
        // An oversized protected task remains available for /compact or /new.
        Some(prepare_context(
            session,
            store,
            0,
            &context_budget_with_memory(
                client,
                session,
                cli,
                plan,
                &skills,
                &initial_memory,
                &events.secret_snapshot(),
            ),
            events,
        )?)
    } else {
        None
    };
    hydrate(session, events);
    if let Some(context) = restored_context {
        context.report(events);
    }
    let mut shown_problems = Vec::new();
    let mut shown_memory_problems = Vec::new();
    let mut shown_command_problems: Vec<String> = Vec::new();
    let mut unsupported_shown: HashSet<String> = HashSet::new();
    let mut snapshot = Some(skills);
    let mut memory_snapshot = Some(initial_memory);
    loop {
        // New and changed skills/memory notes are picked up without a restart;
        // one turn keeps one snapshot.
        let skills = snapshot
            .take()
            .unwrap_or_else(|| discover_skills(store, &session.root));
        if skills.problems != shown_problems {
            skill_problems(&skills.problems, events);
            shown_problems = skills.problems.clone();
        }
        let memory = memory_snapshot.take().unwrap_or_else(|| {
            discover_memory(store, &runtime, &session.root, &events.secret_snapshot())
        });
        if memory.problems != shown_memory_problems {
            memory_problems(&memory.problems, events);
            shown_memory_problems = memory.problems.clone();
        }
        let registry = crate::commands::CommandRegistry::discover(store.root(), &session.root);
        let command_fingerprints: Vec<String> = registry
            .problems
            .iter()
            .map(|problem| {
                format!(
                    "{}|{}|{}",
                    problem.path.display(),
                    problem.code,
                    problem.message
                )
            })
            .collect();
        if command_fingerprints != shown_command_problems {
            command_problems(&registry.problems, events);
            shown_command_problems = command_fingerprints;
        }
        let live_menu_secrets = events.secret_snapshot();
        let mut menu: Vec<terminal::MenuCommand> = registry.menu_redacted(&live_menu_secrets);
        menu.extend(skill_menu_redacted(&skills, &registry, &live_menu_secrets));
        composer.set_commands(menu.clone());
        let budget = context_budget_with_memory(
            client,
            session,
            &runtime,
            plan,
            &skills,
            &memory,
            &events.secret_snapshot(),
        );
        if let Some(screen) = crate::screen::current() {
            screen.set_footer(footer(session, &runtime, plan, &budget, events));
        }
        let input = if let Some(p) = pending.pop_front() {
            if let Some(screen) = crate::screen::current() {
                screen.line(&format!("\n❯ {}", events.redact(&p)));
            }
            Input::Submit(p)
        } else {
            // One input owner. Keep the async host available to persist natural
            // command completion while the user is composing or simply idle.
            let mut editor = std::mem::take(&mut composer);
            let current_footer = footer(session, &runtime, plan, &budget, events);
            let prompt = if plan {
                "rcode [план] › "
            } else if runtime.permissions() == ApprovalMode::FullAccess {
                "rcode [полный доступ] › "
            } else {
                "rcode › "
            };
            let mut input = tokio::task::spawn_blocking(move || {
                let result = if rich {
                    editor.read(&current_footer)
                } else {
                    editor.read_plain(prompt)
                };
                (editor, result)
            });
            let mut timer = tokio::time::interval(Duration::from_millis(250));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut failed_runtime = false;
            let (editor, result) = loop {
                tokio::select! {
                    result = &mut input => break result?,
                    _ = timer.tick(), if !failed_runtime => {
                        let settled = async {
                            events.refresh_keys(store)?;
                            execution.settle_jobs(session, store, &events.secret_snapshot()).await
                        }.await;
                        if let Err(error) = settled {
                            let cleanup = execution.shutdown_saved(session, store, &events.secret_snapshot()).await;
                            let error = match cleanup { Ok(()) => error, Err(cleanup) => error.context(format!("Остановка процессов: {cleanup:#}")) };
                            events.emit("error", json!({"message":events.redact(&format!("{error:#}. Исполнение закрыто. Введите /exit; после перезапуска можно восстановить сессию через /resume."))}));
                            // Keep the existing editor as the recovery prompt. A closed
                            // runtime rejects actions; exit preserves Unknown receipts for recovery.
                            failed_runtime = true;
                        }
                    }
                }
            };
            composer = editor;
            result?
        };
        let input = match input {
            Input::Submit(s) => {
                interrupted = None;
                s
            }
            Input::Eof => break,
            Input::Interrupt => {
                if interrupted.is_some_and(|t| t.elapsed() < Duration::from_secs(2)) {
                    break;
                }
                interrupted = Some(Instant::now());
                notice!("Ещё раз Ctrl+C для выхода, либо /exit.");
                continue;
            }
        };
        let input = input.trim();
        if input.is_empty() {
            continue;
        }
        let first_word = input.split_whitespace().next().unwrap_or_default();
        if !matches!(
            first_word,
            "/new"
                | "/clear"
                | "/resume"
                | "/help"
                | "/status"
                | "/advisor"
                | "/memory"
                | "/sandbox"
                | "/btw"
                | "/exit"
                | "/quit"
        ) && let Err(error) = execution.activate()
        {
            events.emit("error", json!({"message":events.redact(&format!("{error:#}. Исполнение сессии недоступно. Введите /exit; после перезапуска восстановите сессию через /resume."))}));
            continue;
        }
        if let Some(screen) = crate::screen::current() {
            screen.follow_tail();
        }
        let redacted = events.redact(input);
        composer.add_history(&redacted);
        if let Some(history) = &input_history
            && let Err(error) = history.record(&redacted, |text| events.redact(text))
        {
            notice!(
                "Не удалось сохранить историю ввода: {}. В этом запуске история останется в памяти.",
                events.redact(&format!("{error:#}"))
            );
            input_history = None;
        }
        if let Some(command) = input.strip_prefix('!') {
            if let Err(error) =
                user_shell(session, store, tools, execution, events, command, &budget).await
            {
                events.emit(
                    "error",
                    json!({"message":events.redact(&format!("{error:#}"))}),
                );
            }
            events.pause();
            continue;
        }
        if let Some(skill) = start_skill_request(&skills, &menu, input)? {
            if rich {
                notice!(
                    "\n{} {}",
                    presentation::tone("❯", "1;38;5;110", true),
                    ui::safe(&redacted)
                );
            }
            if let Err(error) = crate::app::skill_turn(
                session,
                store,
                tools,
                client,
                events,
                &runtime,
                &skill.prompt,
                &skill.id,
                plan,
                &skills,
                execution,
            )
            .await
            {
                events.emit(
                    "error",
                    json!({"message":events.redact(&format!("{error:#}"))}),
                );
            }
            events.pause();
            if let Some(screen) = crate::screen::current() {
                pending.extend(screen.take_queue());
            }
            continue;
        }
        // /var/folders/.../screen.png is a user path, not a slash command.
        // /attach is parsed with the user prompt so its images reach the same turn.
        if input.starts_with('/')
            && first_word != "/attach"
            && !first_word[1..].contains(['/', '\\', '.'])
        {
            let mut words = input.split_whitespace();
            let command = words.next().unwrap_or_default();
            let args = words.collect::<Vec<_>>();
            if matches!(command, "/exit" | "/quit") {
                break;
            }
            let custom = command
                .strip_prefix('/')
                .and_then(|name| registry.find(name))
                .map(|entry| (entry.name.clone(), entry.unsupported.to_vec()));
            let result:Result<()>=async{match command{
                "/help"=>{help(&registry,events);Ok(())},
                "/model"|"/models"=>{select_model(&args,false,rich,store,settings,&mut active_disk_origin,session,client,events,&mut models).await?;runtime.refresh_routing_soft(store,settings,&session.provider,events);Ok(())},
                "/provider"=>{select_model(&args,true,rich,store,settings,&mut active_disk_origin,session,client,events,&mut models).await?;runtime.refresh_routing_soft(store,settings,&session.provider,events);Ok(())},
                "/effort"=>{select_effort(&args,rich,store,settings,&mut active_disk_origin,session,client,events,&mut models).await?;runtime.refresh_routing_soft(store,settings,&session.provider,events);Ok(())},
                "/thinking"=>{select_thinking(&args,rich,store,settings,&mut active_disk_origin,session,client,events)?;runtime.refresh_routing_soft(store,settings,&session.provider,events);Ok(())},
                "/advisor"=>{
                    if runtime.in_eval {
                        bail!("Команда /advisor отключена в изолированном режиме rcode eval");
                    }
                    crate::advisor::interactive_command(&args,rich,store,settings,session,&mut runtime.advisor_override,events).await?;
                    if args.as_slice() == ["status"] {
                        runtime.refresh_routing_soft(store,settings,&session.provider,events);
                        Ok(())
                    } else {
                        runtime.refresh_routing(store,settings,&session.provider,events)
                    }
                },
                "/review-model"=>review_model_command(&args,store,settings,runtime.final_review_mode(),events),
                "/final-review"=>{
                    match args.as_slice() {
                        [] | ["status"] => {
                            let _ = events.refresh_keys(store);
                            let mode=runtime.final_review_mode();
                            let target=crate::final_review::redacted_model_target_summary_for_mode(store,settings,mode,&events.secret_snapshot());
                            notice!("Финальное ревью: {} · {} / {}",mode.label_ru(),target["provider"].as_str().unwrap_or("same"),ui::safe(target["model"].as_str().unwrap_or_default()));
                        }
                        ["on"] => {
                            crate::final_review::ensure_user_controlled()?;
                            let _ = events.refresh_keys(store);
                            let route=crate::final_review::resolve_target(settings,&session.provider,&settings.final_review)?;
                            crate::final_review::selected_credentials(store,&route)?;
                            crate::model_route::ensure_route_free_of_secrets(store,&route,&events.secret_snapshot())?;
                            runtime.set_final_review_mode(crate::final_review::FinalReviewMode::OneShot);
                            notice!("✓ Финальное ревью включено для последующих ходов этого запуска");
                        }
                        ["repair"] => {
                            crate::final_review::ensure_user_controlled()?;
                            let _ = events.refresh_keys(store);
                            let route=crate::final_review::resolve_target(settings,&session.provider,&settings.final_review)?;
                            crate::final_review::selected_credentials(store,&route)?;
                            crate::model_route::ensure_route_free_of_secrets(store,&route,&events.secret_snapshot())?;
                            runtime.set_final_review_mode(crate::final_review::FinalReviewMode::Repair);
                            notice!("✓ Финальное ревью с исправлением (repair) включено для последующих ходов этого запуска");
                        }
                        ["off"] => { runtime.set_final_review_mode(crate::final_review::FinalReviewMode::Off); notice!("✓ Финальное ревью выключено"); }
                        _ => bail!("Использование: /final-review [on|repair|off|status]"),
                    }
                    Ok(())
                },
                "/vision"=>crate::vision::choose(rich,store,settings,events).await,
                "/websearch"=>crate::web_search::choose(rich,store,settings,events).await,
                "/connect"|"/login"=>{let kind=args.first().map(|s|s.parse::<ProviderKind>()).transpose()?;let next=ui::connect_with_secrets(store,settings,kind,rich,None,&events.secret_snapshot(),Some(events.shared_secrets())).await?;commit_provider(store,settings,&mut active_disk_origin,session,client,events,ProviderEdit::Switch(next))?;runtime.refresh_routing_soft(store,settings,&session.provider,events);models.clear();Ok(())},
                "/permissions"=>{
                    if let Some(mode)=permissions_choice(&args,rich,runtime.permissions())? {
                        apply_permissions(mode,store,session,&mut runtime,tools)?;
                    }Ok(())
                },
                "/sandbox"=>sandbox_command(&args,rich,store,session,&mut runtime,events),
                "/plan"=>{plan=match args.first().copied(){Some("on")=>true,Some("off")=>false,None=>!plan,_=>bail!("/plan [on|off]")};notice!("✓ Режим плана: {}",if plan{"включён"}else{"выключен"});Ok(())},
                "/btw"=>{
                    let rest=input.strip_prefix(command).unwrap_or_default();
                    match crate::app::btw_question(session,store,client,events,&runtime,plan,&skills,&memory,rest).await {
                        Ok(())=>Ok(()),
                        Err(err) if crate::app::exit_code(&err)==130=>{notice!("Запрос /btw отменён.");Ok(())},
                        Err(err)=>Err(err),
                    }
                },
                "/status"=>{
                    match store.load() {
                        Ok(fresh) => {
                            *settings = fresh;
                            runtime.refresh_routing_soft(store, settings, &session.provider, events);
                        }
                        Err(err) => {
                            runtime.effective_advisor = None;
                            runtime.advisor_unavailable_reason = Some(events.redact(&format!("{err:#}")));
                        }
                    }
                    let live_sec=events.secret_snapshot();let rendered=skill_catalog_redacted(session,&skills,&live_sec);let mem_unit=catalog_unit_for_client(client,session);let mem_line=events.redact(&memory_summary(&memory,mem_unit,&live_sec));status(session,&runtime,settings,plan,&models,&budget,&catalog_summary(&skills,rendered.as_ref(),catalog_unit(session)),&mem_line,events);Ok(())
                },
                "/memory"=>memory_command(&args,&runtime,plan,store,session,client,events),
                "/balance"=>{
                    if !args.is_empty(){bail!("/balance — баланс текущего провайдера; сменить провайдера: /provider");}
                    let cancel=tokio_util::sync::CancellationToken::new();
                    if let Some(screen)=crate::screen::current(){screen.bind_cancel(cancel.clone());}
                    events.busy("Обновляю баланс…");
                    let fetch=async {
                        if let Some(monitor)=&balance_monitor{monitor.refresh().await}
                        else{crate::balance::fetch(client).await}
                    };
                    let report=tokio::select!{result=fetch=>result?,_=cancel.cancelled()=>bail!("Обновление баланса отменено"),_=tokio::signal::ctrl_c()=>bail!("Обновление баланса отменено")};
                    notice!("{}",events.redact(&report.details(&session.provider.model)));Ok(())
                },
                "/agents"=>{
                    if args.len()>1{bail!("/agents [ID или однозначный префикс]");}
                    let mut records=serde_json::to_value(&session.agents)?;
                    events.redact_value(&mut records);
                    let records=records.as_array().context("Не удалось прочитать список субагентов")?;
                    notice!("{}",events.redact(&agents_view(records,args.first().copied())?));
                    Ok(())
                },
                "/context"=>{let live_sec=events.secret_snapshot();let rendered=skill_catalog_redacted(session,&skills,&live_sec);let mem_unit=catalog_unit_for_client(client,session);let mem_line=events.redact(&memory_summary(&memory,mem_unit,&live_sec));context(session,&models,&budget,&catalog_summary(&skills,rendered.as_ref(),catalog_unit(session)),&mem_line);Ok(())},
                "/skills"=>{
                    if !args.is_empty(){bail!("/skills — список скиллов; выбрать скилл: /skill ID [запрос]");}
                    let live_sec=events.secret_snapshot();
                    let rendered=skill_catalog_redacted(session,&skills,&live_sec);
                    notice!("{}",events.redact(&skills_view(&skills,catalog_unit(session),rendered.as_ref(),&live_sec)));
                    Ok(())
                },
                "/skill"=>{
                    let rest=input.strip_prefix(command).unwrap_or_default();
                    if rest.trim().is_empty(){
                        let live_sec=events.secret_snapshot();
                        let rendered=skill_catalog_redacted(session,&skills,&live_sec);
                        notice!("{}",events.redact(&skills_view(&skills,catalog_unit(session),rendered.as_ref(),&live_sec)));
                        notice!("Укажите скилл: /skill ID [запрос]");
                        return Ok(());
                    }
                    // Checked locally first: an unknown id never reaches the model.
                    let skill=skill_request_with_secrets(&skills,rest,&events.secret_snapshot())?;
                    if rich{notice!("\n{} {}",presentation::tone("❯","1;38;5;110",true),ui::safe(&redacted));}
                    crate::app::skill_turn(session,store,tools,client,events,&runtime,&skill.prompt,&skill.id,plan,&skills,execution).await.map(drop)
                },
                "/export"=>{
                    events.refresh_keys(store)?;
                    let art_store=crate::artifacts::ArtifactStore::open(&session.dir(store),&session.id).ok();
                    let path=crate::export::write_with_tool_sanitizer(
                        session,
                        input.strip_prefix(command).unwrap_or_default(),
                        |text|events.redact(text),
                        |tool_name,raw|events.sanitize_tool_result_for_export(tool_name,raw,art_store.as_ref()),
                    )?;
                    notice!("✓ Диалог сохранён: {}",ui::safe(&events.redact(&path.to_string_lossy())));
                    Ok(())
                },
                "/cost"=>{cost(session,events);Ok(())},
                "/diff"=>{notice!("{}",ui::safe(&tools.diff()?));Ok(())},
                "/undo"=>{let text=tools.undo()?;notice!("{}",ui::safe(&text));let mut message=Message::user(format!("Пользователь выполнил /undo: {text}. Перечитай файлы перед изменениями."));message.provider_meta=Some(ProviderMeta{kind:"rcode_runtime".into(),data:json!({"undo":true})});session.messages.push(message);session.save(store)},
                "/compact"=>{events.refresh_keys(store)?;let saved=session.compact_within_redacted(&budget,&events.secret_snapshot())?;session.save(store)?;notice!("✓ История сокращена на {saved} {}",budget.unit_label());Ok(())},
                "/clear"|"/new"=>{
                    let mut next=Session::new_clean(&session.root,session.provider.clone(),&events.secret_snapshot())?;
                    next.bind_secret_source(events.shared_secrets());
                    crate::config::ensure_private_directory(&next.dir(store))?;
                    let mut next_execution=crate::session_runtime::SessionRuntime::new(&next.dir(store),&next.id,events.secret_snapshot())?;
                    execution.shutdown_saved(session,store,&events.secret_snapshot()).await?;
                    next_execution.activate().context("Предыдущее исполнение остановлено; повторите /new или /resume")?;
                    let next_tools=configured_tools(&next.root,&next.dir(store).join("checkpoints"),&runtime)?;
                    next.save(store)?;
                    *session=next;*tools=next_tools;*execution=next_execution;
                    notice!("✓ Новая сессия: {}",session.id);Ok(())
                },
                "/resume"=>{
                    let id=if let Some(id)=args.first(){Some((*id).to_owned())}else{
                        let saved=Session::list(store)?.into_iter().filter(|s|s.root==session.root).collect::<Vec<_>>();
                        if saved.is_empty(){notice!("В этой папке пока нет сохранённых сессий.");None}else{
                            let choices=saved.iter().map(|s|Choice{label:if s.title.is_empty(){"Новая сессия".into()}else{s.title.clone()},detail:format!("{} · {}",s.provider,s.id),enabled:true}).collect::<Vec<_>>();choose("Восстановить сессию",&choices,0,rich)?.map(|i|saved[i].id.clone())
                        }
                    };
                    let id=if id.as_deref()==Some("latest"){
                        Session::list(store)?.into_iter().find(|saved|saved.root==session.root).map(|saved|saved.id)
                    }else{id};
                    if id.as_deref()==Some(session.id.as_str()){
                        // Reload session data without constructing a second
                        // Tools or SessionRuntime for their already leased
                        // directories, while preserving in-process route consent/denials,
                        // cached route clients, and monotone local prompt calibrations.
                        let mut restored=Session::load(store,&session.id,&session.root)?;
                        restored.bind_secret_source(events.shared_secrets());
                        restored.approved_routes=session.approved_routes.clone();
                        restored.denied_routes=session.denied_routes.clone();
                        let (mut next,next_origin)=restore_session_client(store,settings,true,client,&session.provider,&active_disk_origin,&restored.provider,events)?;
                        execution.reconcile_receipts(&mut restored)?;
                        restored.save(store)?;
                        restored.route_clients=std::mem::take(&mut session.route_clients);
                        restored.local_route_budgets=session.local_route_budgets.clone();
                        restored.share_connection_peers_into(&mut next, Some(client));
                        if next.is_local()
                            && client.is_local()
                            && crate::model_route::RouteIdentity::of(next.settings())
                                == crate::model_route::RouteIdentity::of(client.settings())
                            && let Some((_, cal)) = client.local_budget_snapshot()
                        {
                            next.restore_local_budget_snapshot((None, cal));
                        }
                        active_disk_origin=next_origin;*session=restored;*client=next;models.clear();if let Some(screen)=crate::screen::current(){screen.clear_history();}let resumed_mem=discover_memory(store,&runtime,&session.root,&events.secret_snapshot());let context=prepare_context(session,store,0,&context_budget_with_memory(client,session,&runtime,plan,&skills,&resumed_mem,&events.secret_snapshot()),events)?;hydrate(session,events);context.report(events);notice!("✓ Сессия восстановлена: {}",session.id);
                    }else if let Some(id)=id{
                        // The snapshot's provider and endpoint are kept; the key is resolved for that endpoint.
                        let mut restored=Session::load(store,&id,&session.root)?;
                        restored.bind_secret_source(events.shared_secrets());
                        let (next,next_origin)=restore_session_client(store,settings,false,client,&session.provider,&active_disk_origin,&restored.provider,events)?;
                        let mut next_execution=crate::session_runtime::SessionRuntime::new(&restored.dir(store),&restored.id,events.secret_snapshot())?;
                        execution.shutdown_saved(session,store,&events.secret_snapshot()).await?;
                        next_execution.activate().context("Предыдущее исполнение остановлено; повторите /new или /resume")?;
                        next_execution.reconcile_receipts(&mut restored)?;
                        let next_tools=configured_tools(&restored.root,&restored.dir(store).join("checkpoints"),&runtime)?;restored.save(store)?;
                        active_disk_origin=next_origin;*session=restored;*client=next;*tools=next_tools;*execution=next_execution;models.clear();if let Some(screen)=crate::screen::current(){screen.clear_history();}let resumed_mem=discover_memory(store,&runtime,&session.root,&events.secret_snapshot());let context=prepare_context(session,store,0,&context_budget_with_memory(client,session,&runtime,plan,&skills,&resumed_mem,&events.secret_snapshot()),events)?;hydrate(session,events);context.report(events);notice!("✓ Сессия восстановлена: {}",session.id);
                    }Ok(())
                },
                _ if custom.is_some() => {
                    let (name, unsupported) = custom.unwrap();
                    if !unsupported.is_empty() && unsupported_shown.insert(name.clone()) {
                        notice!(
                            "Команда «/{name}» содержит !-shell или @файл — это не исполняется: rcode передаёт текст модели, а команды выполняются только инструментами с подтверждением"
                        );
                    }
                    let arguments = input.strip_prefix(command).unwrap_or_default().trim_start();
                    let prompt = registry
                        .find(&name)
                        .context("Команда исчезла при перечитывании")?
                        .expand(arguments)?;
                    if rich {
                        notice!(
                            "\n{} {}",
                            presentation::tone("❯", "1;38;5;110", true),
                            ui::safe(&redacted)
                        );
                    }
                    turn(session, store, tools, client, events, &runtime, &prompt, plan, &skills, execution)
                        .await
                        .map(drop)
                }
                _=>bail!("Неизвестная команда. / открывает меню, /help — справку"),
            }}.await;
            if matches!(
                command,
                "/model"
                    | "/models"
                    | "/provider"
                    | "/connect"
                    | "/login"
                    | "/effort"
                    | "/resume"
                    | "/clear"
                    | "/new"
            ) {
                let _ = runtime.refresh_routing(store, settings, &session.provider, events);
                drop(balance_monitor.take());
                balance_monitor = start_balance_monitor(client, session);
            }
            events.pause();
            if let Some(screen) = crate::screen::current() {
                pending.extend(screen.take_queue());
            }
            if let Err(e) = result {
                events.emit("error", json!({"message":format!("{e:#}")}));
            }
            continue;
        }
        if rich {
            notice!(
                "\n{} {}",
                presentation::tone("❯", "1;38;5;110", true),
                ui::safe(&redacted)
            );
        }
        if let Err(e) = turn(
            session, store, tools, client, events, &runtime, input, plan, &skills, execution,
        )
        .await
        {
            events.emit("error", json!({"message":format!("{e:#}")}));
        }
        events.pause();
        if let Some(screen) = crate::screen::current() {
            pending.extend(screen.take_queue());
        }
    }
    events.pause();
    Ok(0)
}

/// Background balance for cloud providers; a local server has no balance API.
fn start_balance_monitor(client: &ProviderClient, session: &Session) -> Option<BalanceMonitor> {
    if session.provider.kind == ProviderKind::Local {
        return None;
    }
    crate::screen::current()
        .map(|screen| BalanceMonitor::start(client.clone(), session.provider.model.clone(), screen))
}

fn hydrate(session: &Session, events: &Events) {
    let Some(screen) = crate::screen::current() else {
        return;
    };
    for message in session
        .messages
        .iter()
        .skip(session.messages.len().saturating_sub(100))
    {
        if message
            .provider_meta
            .as_ref()
            .is_some_and(|meta| meta.kind == "rcode_user_shell")
        {
            for call in &message.tool_calls {
                if let Ok(args) = serde_json::from_str::<Value>(&call.function.arguments) {
                    events.emit(
                        "shell_start",
                        json!({"command":args["command"].as_str().unwrap_or_default()}),
                    );
                }
                if let Some(result) = session.messages.iter().find(|m| {
                    m.role == "tool" && m.tool_call_id.as_deref() == Some(call.id.as_str())
                }) {
                    events.emit("shell_result",json!({"content":result.content.as_deref().unwrap_or_default(),"restored":true}));
                }
            }
            continue;
        }
        if message
            .provider_meta
            .as_ref()
            .is_some_and(|meta| meta.kind == "rcode_compaction")
        {
            screen.line("Часть предыдущей истории сокращена; показаны сохранённые сообщения.");
            continue;
        }
        if message
            .provider_meta
            .as_ref()
            .is_none_or(|meta| meta.kind != "rcode_runtime")
            && matches!(message.role.as_str(), "user" | "assistant")
            && let Some(text) = message.content.as_deref().filter(|t| !t.is_empty())
        {
            if message.role == "assistant" {
                screen.line("\n✦ rcode");
                screen.append_markdown(&events.redact(text));
                screen.finish_markdown();
            } else {
                screen.line(&format!("\n❯ {}", events.redact(text)));
                for image in &message.images {
                    screen.line(&format!("  {}", ui::safe(&events.redact(&image.label()))));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::{CatalogLimits, Skill, SkillScope};
    use std::path::PathBuf;

    fn skill(id: &str, scope: SkillScope) -> Skill {
        let name = id.rsplit(':').next().unwrap().to_owned();
        Skill {
            id: id.into(),
            source: id.split_once(':').map(|(label, _)| label.into()),
            scope,
            dir: PathBuf::from("/skills").join(&name),
            file: PathBuf::from("/skills").join(&name).join("SKILL.md"),
            description: format!("Use {name} for its workflow. {}", "w".repeat(200)),
            raw_description: String::new(),
            name,
            bytes: 2560,
            in_catalog: true,
            disabled: false,
            disable_model_invocation: false,
            shadowed_by: None,
            fields: Default::default(),
            ignored_fields: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn catalog(skills: Vec<Skill>) -> SkillCatalog {
        SkillCatalog {
            skills,
            ..SkillCatalog::default()
        }
    }

    fn no_commands() -> crate::commands::CommandRegistry {
        crate::commands::CommandRegistry {
            commands: Vec::new(),
            problems: Vec::new(),
        }
    }

    #[test]
    fn skill_menu_keeps_canonical_ids_and_only_unique_bare_aliases() {
        let skills = catalog(vec![
            skill("rstack:browse", SkillScope::Source),
            skill("other:browse", SkillScope::Source),
            skill("rstack:review", SkillScope::Source),
        ]);
        let menu = skill_menu(&skills, &no_commands());
        let names: Vec<_> = menu.iter().map(|entry| entry.name.as_str()).collect();
        assert!(names.contains(&"/rstack:browse"));
        assert!(names.contains(&"/other:browse"));
        assert!(names.contains(&"/rstack:review"));
        assert!(names.contains(&"/review"));
        assert!(
            !names.contains(&"/browse"),
            "ambiguous alias must be omitted"
        );
    }

    #[test]
    fn start_skill_alias_and_canonical_id_use_the_explicit_skill_request() {
        let skills = catalog(vec![skill("rstack:browse", SkillScope::Source)]);
        let menu = skill_menu(&skills, &no_commands());
        for input in [
            "/browse открыть страницу",
            "/rstack:browse открыть страницу",
        ] {
            let request = start_skill_request(&skills, &menu, input).unwrap().unwrap();
            assert_eq!(request.id, "rstack:browse");
            assert!(request.prompt.contains("явно выбрал скилл rstack:browse"));
            assert!(
                request
                    .prompt
                    .contains("rcode уже загрузил его через load_skill (результат ниже)")
            );
            assert!(request.prompt.contains("открыть страницу"));
        }
    }

    #[test]
    fn skills_view_shows_status_size_and_catalog_cost_safely() {
        let mut disabled = skill("superpowers:debugging", SkillScope::Source);
        disabled.disabled = true;
        disabled.in_catalog = false;
        let mut hidden = skill("careful", SkillScope::Project);
        hidden.disable_model_invocation = true;
        hidden.in_catalog = false;
        // A same-root loser names the winner's directory, which is any text.
        let mut shadowed = skill("review", SkillScope::Project);
        shadowed.shadowed_by = Some("evil\x1b[2J\u{202e}dir".into());
        shadowed.in_catalog = false;
        let mut skills = vec![skill("brainstorming", SkillScope::User)];
        skills.extend((0..30).map(|index| skill(&format!("guide-{index:02}"), SkillScope::User)));
        skills.extend([disabled, hidden, shadowed]);
        let mut catalog = catalog(skills);
        catalog.limits = CatalogLimits {
            cloud_chars: 4000,
            ..CatalogLimits::default()
        };
        catalog.problems = vec![
            SkillProblem {
                path: PathBuf::from("/skills/bad\x1b]52;c;AAAA\x07\u{202e}/SKILL.md"),
                code: "duplicate_key",
                message: "Ошибка frontmatter: повтор ключа name в строке 3".into(),
                raw_invalid_name: None,
            },
            SkillProblem {
                path: PathBuf::from("/skills/review/SKILL.md"),
                code: "shadowed",
                message: "Скилл review перекрыт файлом /home/skills/review/SKILL.md".into(),
                raw_invalid_name: None,
            },
        ];
        let unit = CatalogUnit::Chars;
        let rendered = catalog.render(&catalog.limits, unit).unwrap();
        assert!(rendered.entries > 0 && !rendered.omitted_ids.is_empty());
        let view = skills_view(&catalog, unit, Some(&rendered), &[]);
        assert!(!view.contains('\x1b') && !view.contains('\u{202e}') && !view.contains('\x07'));
        assert!(
            view.contains("\\u{202e}"),
            "bidi controls are shown escaped:\n{view}"
        );
        let named = rendered.entries + rendered.omitted_ids.len();
        assert!(view.starts_with(&format!(
            "Скиллы · 34 · в каталоге {named} · блок ~{} из 4000 символов",
            rendered.cost
        )));
        let row = |id: &str| {
            view.lines()
                .find(|line| line.trim_start().starts_with(&format!("{id} ")))
                .unwrap_or_else(|| panic!("no row {id}:\n{view}"))
                .to_owned()
        };
        let entries = catalog.entries(&catalog.limits, unit, Some(&rendered));
        let CatalogEntry::Described(cost) = entries[0] else {
            panic!("{entries:?}");
        };
        let first = row("brainstorming");
        assert!(
            first.contains("user") && first.contains("в каталоге"),
            "{first}"
        );
        assert!(
            first.contains("2.5 КиБ") && first.ends_with(&format!("~{cost}")),
            "{first}"
        );
        let last = rendered.omitted_ids.last().unwrap();
        assert!(row(last).contains("только id"), "{}", row(last));
        let disabled = row("superpowers:debugging");
        assert!(
            disabled.contains("source") && disabled.contains("отключён") && disabled.ends_with('—')
        );
        assert!(row("careful").contains("только /skill"));
        assert!(row("review").contains("перекрыт: evil"));
        // Discovery errors are listed; shadowing is already a table row.
        assert!(view.contains("Ошибки (1)") && view.contains("(duplicate_key)"));
        assert!(!view.contains("перекрыт файлом"));
        assert!(view.contains("/skill ID [запрос]"));
        // Without a block every catalog skill is reported as not sent.
        let none = skills_view(&catalog, unit, None, &[]);
        assert!(none.contains("не помещается в бюджет"));
        assert!(row_in(&none, "brainstorming").contains("не вошёл"));
        // Local units are named as such.
        let local = CatalogUnit::EstimatedTokens {
            history_limit: 25_396,
        };
        let rendered = catalog.render(&catalog.limits, local).unwrap();
        assert!(
            skills_view(&catalog, local, Some(&rendered), &[])
                .contains("из 2539 оценочных токенов")
        );
        assert!(
            skills_view(&SkillCatalog::empty(), unit, None, &[]).starts_with("Скиллы не найдены")
        );
    }

    fn row_in(view: &str, id: &str) -> String {
        view.lines()
            .find(|line| line.trim_start().starts_with(&format!("{id} ")))
            .unwrap_or_else(|| panic!("no row {id}:\n{view}"))
            .to_owned()
    }

    #[test]
    fn skill_request_names_the_resolved_id_and_keeps_the_request() {
        let mut disabled = skill("off", SkillScope::User);
        disabled.disabled = true;
        disabled.in_catalog = false;
        let mut shadowed = skill("brainstorming", SkillScope::Project);
        shadowed.shadowed_by = Some("user".into());
        shadowed.in_catalog = false;
        let catalog = catalog(vec![
            skill("brainstorming", SkillScope::User),
            disabled,
            shadowed,
            skill("superpowers:debugging", SkillScope::Source),
            skill("gstack:review", SkillScope::Source),
            skill("team:review", SkillScope::Source),
        ]);
        assert_eq!(
            skill_request(&catalog, " brainstorming  новая\nкоманда /export ").unwrap(),
            SkillRequest {
                id: "brainstorming".into(),
                prompt: "Пользователь явно выбрал скилл brainstorming; rcode уже загрузил его через load_skill (результат ниже). Если есть next_line — дочитай через load_skill. Действуй по скиллу: новая\nкоманда /export".into(),
            }
        );
        // A unique bare name resolves to the full id; no request — no colon.
        assert_eq!(
            skill_request(&catalog, "debugging").unwrap(),
            SkillRequest {
                id: "superpowers:debugging".into(),
                prompt: "Пользователь явно выбрал скилл superpowers:debugging; rcode уже загрузил его через load_skill (результат ниже). Если есть next_line — дочитай через load_skill. Действуй по скиллу.".into(),
            }
        );
        // Explicit choice also works for skills outside the catalog.
        let explicit_off = skill_request(&catalog, "off проверь").unwrap();
        assert_eq!(explicit_off.id, "off");
        assert!(explicit_off.prompt.contains("скилл off;"));
        let ambiguous = skill_request(&catalog, "review").unwrap_err().to_string();
        assert!(
            ambiguous.contains("gstack:review, team:review"),
            "{ambiguous}"
        );
        let unknown = skill_request(&catalog, "brainstormin\x1b[2J идея")
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("Похожие: brainstorming"), "{unknown}");
        assert!(!unknown.contains('\x1b'), "{unknown}");
        let none = skill_request(&SkillCatalog::empty(), "x")
            .unwrap_err()
            .to_string();
        assert!(none.contains("скиллов нет"), "{none}");
    }

    #[test]
    fn catalog_summary_reports_the_block_in_its_unit() {
        let mut catalog = catalog(
            (0..30)
                .map(|index| skill(&format!("guide-{index:02}"), SkillScope::User))
                .collect(),
        );
        let limits = CatalogLimits {
            cloud_chars: 3000,
            ..CatalogLimits::default()
        };
        let rendered = catalog.render(&limits, CatalogUnit::Chars).unwrap();
        let line = catalog_summary(&catalog, Some(&rendered), CatalogUnit::Chars);
        assert!(
            line.starts_with(&format!(
                "Скиллы       30 в каталоге, ~{} символов · без описаний {}",
                rendered.cost,
                rendered.omitted_ids.len()
            )),
            "{line}"
        );
        let local = CatalogUnit::EstimatedTokens {
            history_limit: 25_396,
        };
        let rendered = catalog.render(&limits, local).unwrap();
        assert!(catalog_summary(&catalog, Some(&rendered), local).contains("оценочных токенов"));
        assert!(catalog_summary(&catalog, None, local).contains("не помещается"));
        for skill in &mut catalog.skills {
            skill.in_catalog = false;
        }
        assert!(catalog_summary(&catalog, None, local).contains("в каталоге нет; найдено 30"));
        assert!(
            catalog_summary(&SkillCatalog::empty(), None, local)
                .starts_with("Скиллы       не найдены")
        );
    }
    #[test]
    fn agent_selection_requires_unique_prefix_and_prefers_exact_id() {
        let records = [
            json!({"id":"abc", "name":"Точный", "role":"explorer", "status":"completed", "result":"Проверка A"}),
            json!({"id":"abcdef", "name":"Длинный", "role":"worker", "status":"failed", "result":"Проверка B"}),
            json!({"id":"other-id", "name":"Третий", "role":"reviewer", "status":"cancelled", "result":"Проверка C"}),
        ];
        assert!(agents_view(&records, Some("ab")).is_err());
        assert!(agents_view(&records, Some("missing")).is_err());
        assert!(agents_view(&records, Some("")).is_err());
        let selected = agents_view(&records, Some("abc")).unwrap();
        assert!(selected.contains("Проверка A"));
        assert!(!selected.contains("Проверка B"));
        let selected = agents_view(&records, Some("oth")).unwrap();
        assert!(selected.contains("Проверка C"));
    }

    #[test]
    fn agent_list_and_details_sanitize_outputs_and_preserve_usage() {
        let records = [json!({
            "id":"12345678-rest", "name":"Исполнитель\n\x1b[2J\u{202e}",
            "task":"Проверить\x1b[2J проект", "role":"worker", "status":"interrupted",
            "result":"Строка 1\nСтрока 2\x1b[2J\u{202e}",
            "usage":{"input_tokens":1234,"output_tokens":56}
        })];
        let list = agents_view(&records, None).unwrap();
        assert!(list.contains("↑1.2k ↓56"));
        assert!(list.contains("прерван"));
        assert!(list.contains("Исполнитель\\n"));
        let details = agents_view(&records, Some("1234")).unwrap();
        assert!(details.contains("Строка 1\nСтрока 2"));
        assert!(details.contains("12345678-rest"));
        assert!(!list.contains('\x1b') && !details.contains('\x1b'));
        assert!(!list.contains('\u{202e}') && !details.contains('\u{202e}'));
        assert!(agents_view(&[], None).unwrap().contains("не запускались"));
    }
    #[test]
    fn model_argument_supports_both_current_and_explicit_provider() {
        assert_eq!(
            model_target(ProviderKind::Yandex, &["qwen/coder"]),
            (ProviderKind::Yandex, Some("qwen/coder".into()))
        );
        assert_eq!(
            model_target(ProviderKind::Yandex, &["openrouter", "qwen/coder"]),
            (ProviderKind::OpenRouter, Some("qwen/coder".into()))
        );
    }
    #[test]
    fn efforts_for_local_is_only_auto() {
        let local = crate::local::profile_settings(
            "box",
            "http://127.0.0.1:8080/v1",
            crate::local::LocalRuntime::LlamaCpp,
            "m",
        );
        let reasoning = ModelInfo {
            supports_reasoning: Some(true),
            supported_efforts: Some(vec![Effort::Low, Effort::High]),
            ..ModelInfo::default()
        };
        assert_eq!(efforts(&local, None), vec![Effort::Auto]);
        assert_eq!(efforts(&local, Some(&reasoning)), vec![Effort::Auto]);
    }

    #[test]
    fn unsupported_effort_is_not_offered() {
        let p = ProviderSettings::new(ProviderKind::OpenRouter);
        let m = ModelInfo {
            supports_reasoning: Some(false),
            ..ModelInfo::default()
        };
        assert_eq!(efforts(&p, Some(&m)), vec![Effort::Auto]);
        let m = ModelInfo {
            supports_reasoning: Some(true),
            supported_efforts: Some(vec![Effort::Low, Effort::High]),
            ..ModelInfo::default()
        };
        assert_eq!(
            efforts(&p, Some(&m)),
            vec![Effort::Auto, Effort::Low, Effort::High]
        );
    }

    #[test]
    fn active_disk_origin_blocks_stale_credential_pairing_after_settings_reload() {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::at(dir.path().join("home")).unwrap();

        let mut custom_a = ProviderSettings::new(ProviderKind::Custom);
        custom_a.base_url = Some("https://endpoint-a.example/v1".into());
        custom_a.model = "model-a".into();
        store
            .commit_cloud_connection(
                &ProviderSettings::new(ProviderKind::Custom),
                &custom_a,
                "secret-key-endpoint-a",
                true,
            )
            .unwrap();

        let workspace = dir.path().join("ws");
        std::fs::create_dir_all(&workspace).unwrap();
        let mut session = Session::new(&workspace, custom_a.clone()).unwrap();
        let mut events = Events::new(true);
        let mut client = local_app::client(&store, &session.provider, &mut events, "missing")
            .expect("initial client A");
        let mut active_disk_origin = custom_a.clone();

        // Another process switches custom on disk to endpoint B + key B.
        let mut custom_b = ProviderSettings::new(ProviderKind::Custom);
        custom_b.base_url = Some("https://endpoint-b.example/v1".into());
        custom_b.model = "model-b".into();
        store
            .commit_cloud_connection(&custom_a, &custom_b, "secret-key-endpoint-b", true)
            .unwrap();

        // Simulate `/status` or `/advisor` reloading `settings` from disk before `/effort` or `/model`.
        let mut settings = store.load().unwrap();
        let disk_expected = active_disk_origin.clone();
        let session_base = session.provider.clone();

        let err = commit_provider(
            &store,
            &mut settings,
            &mut active_disk_origin,
            &mut session,
            &mut client,
            &mut events,
            ProviderEdit::Effort {
                disk_expected,
                session_base,
                effort: Effort::High,
            },
        )
        .expect_err("must reject pairing key B with session endpoint A");
        assert!(
            format!("{err:#}").contains("изменились в другом процессе"),
            "unexpected error: {err:#}"
        );
        assert_eq!(
            session.provider.base_url.as_deref(),
            Some("https://endpoint-a.example/v1")
        );

        let resume_err = validate_restored_cloud_connection(
            true,
            true,
            &session.provider,
            &active_disk_origin,
            &custom_a,
            &custom_b,
            Some("credentials.json"),
        )
        .expect_err("disk-stored key B must not be paired with saved endpoint A");
        assert!(
            format!("{resume_err:#}").contains("изменились после сохранения сессии"),
            "unexpected resume error: {resume_err:#}"
        );
        // Even if the on-disk endpoint A did not change, rotating key A -> A2 on disk must block
        // sending A2 to a temporary `--base-url B` session (`credential_unchanged == false`).
        validate_restored_cloud_connection(
            true,
            false,
            &custom_b,
            &custom_a,
            &custom_b,
            &custom_a,
            Some("credentials.json"),
        )
        .expect_err("rotated disk key for A must not be sent to temporary --base-url B");
        validate_restored_cloud_connection(
            true,
            false,
            &session.provider,
            &active_disk_origin,
            &custom_a,
            &custom_b,
            Some("env:OPENAI_API_KEY"),
        )
        .expect("env-sourced credential remains valid across temporary --base-url /resume");

        // Temporary `--folder-id` on Yandex updates `next_session` without failing `disk_base.validate()`.
        let default_settings = Settings::default();
        let disk_yandex = default_settings.provider(ProviderKind::Yandex);
        let mut session_yandex = disk_yandex.clone();
        session_yandex.folder_id = Some("b1gtempfolder".into());
        let (_, persist_yandex, updated_yandex) = resolve_provider_edit(
            &default_settings,
            &ProviderEdit::Model {
                disk_expected: disk_yandex,
                session_base: session_yandex,
                model: "yandexgpt/latest".into(),
            },
        )
        .expect("temporary --folder-id should allow switching Yandex model in session");
        assert!(!persist_yandex);
        assert_eq!(updated_yandex.model, "yandexgpt/latest");

        // Temporary `--model` override does not persist `effort` onto a different default model.
        let disk_or = default_settings.provider(ProviderKind::OpenRouter);
        let mut session_or = disk_or.clone();
        session_or.model = "anthropic/claude-opus-4.6".into();
        let (unchanged_or, persist_or, updated_or) = resolve_provider_edit(
            &default_settings,
            &ProviderEdit::Effort {
                disk_expected: disk_or.clone(),
                session_base: session_or,
                effort: Effort::High,
            },
        )
        .unwrap();
        assert!(!persist_or);
        assert_eq!(unchanged_or.effort, disk_or.effort);
        assert_eq!(updated_or.effort, Effort::High);

        // `commit_cloud_connection` rejects `save_key = false` when endpoint changes (`custom_b -> custom_a`).
        let mut custom_c = custom_b.clone();
        custom_c.base_url = Some("https://endpoint-c.example/v1".into());
        assert!(
            store
                .commit_cloud_connection(&custom_b, &custom_c, "secret-key-endpoint-b", false)
                .is_err(),
            "stored credentials.json key must never be rebound to a new endpoint with save_key=false"
        );

        // Legacy relative `ca_file` on disk + absolute `--ca-file` in session allows `/model`,
        // `/effort`, and `/thinking` in-memory (`persist_disk == false`) without false drift errors!
        let mut rel_settings = Settings::default();
        let mut rel_cloud = ProviderSettings::new(ProviderKind::OpenRouter);
        rel_cloud.model = "qwen/qwen-old".into();
        rel_cloud.ca_file = Some("legacy-rel.pem".into());
        rel_settings.remember_provider(&rel_cloud);
        let mut abs_cloud = rel_cloud.clone();
        abs_cloud.ca_file = Some(dir.path().join("abs-ca.pem"));
        let (_, persist_rel_model, next_rel_cloud) = resolve_provider_edit(
            &rel_settings,
            &ProviderEdit::Model {
                disk_expected: rel_cloud.clone(),
                session_base: abs_cloud,
                model: "qwen/qwen-new".into(),
            },
        )
        .expect("/model must succeed when session overrides legacy relative ca_file");
        assert!(!persist_rel_model);
        assert_eq!(next_rel_cloud.model, "qwen/qwen-new");

        let mut rel_local = crate::local::profile_settings(
            "relbox",
            "http://127.0.0.1:18280/v1",
            crate::local::LocalRuntime::Mlx,
            "mlx-old",
        );
        rel_local.ca_file = Some("legacy-local.pem".into());
        rel_settings.remember_provider(&rel_local);
        store.save(&rel_settings).unwrap();
        let mut abs_local = rel_local.clone();
        abs_local.ca_file = Some(dir.path().join("abs-local.pem"));
        local_app::check_current_with_baseline(&store, &abs_local, &rel_local).expect(
            "check_current_with_baseline must accept unchanged legacy relative disk baseline",
        );
        let (_, persist_rel_local, next_rel_local) = resolve_provider_edit(
            &rel_settings,
            &ProviderEdit::Model {
                disk_expected: rel_local,
                session_base: abs_local,
                model: "mlx-new".into(),
            },
        )
        .expect("local /model must succeed when session overrides legacy relative ca_file");
        assert!(!persist_rel_local);
        assert_eq!(next_rel_local.model, "mlx-new");

        // `/resume latest` (`same_session == true`) succeeds when `config.json` has a legacy
        // relative `ca_file` overridden in-process by `--ca-file /abs/ca.pem`!
        let mut abs_cloud_for_resume = rel_cloud.clone();
        abs_cloud_for_resume.ca_file = Some(dir.path().join("abs-ca.pem"));
        validate_restored_cloud_connection(
            true,
            true,
            &abs_cloud_for_resume,
            &rel_cloud,
            &abs_cloud_for_resume,
            &rel_cloud,
            Some("credentials.json"),
        )
        .expect("/resume latest must accept unchanged legacy relative disk ca_file");

        // Missing `config.json` + leftover `credentials.json` `"custom"` key MUST NOT allow
        // `commit_cloud_connection(..., save_key = false)` onto `Settings::default()`'s `localhost:11434`!
        let orphan_store = ConfigStore::at(dir.path().join("orphan-home")).unwrap();
        orphan_store
            .save_credential(ProviderKind::Custom, "leftover-custom-secret-key")
            .unwrap();
        let default_custom = ProviderSettings::new(ProviderKind::Custom);
        assert!(
            orphan_store
                .commit_cloud_connection(
                    &default_custom,
                    &default_custom,
                    "leftover-custom-secret-key",
                    false,
                )
                .is_err(),
            "missing config.json must not rebind leftover credentials.json key to default custom URL"
        );

        // `/skills` redacts a 49-character skill ID matching a secret BEFORE 48-char table clipping!
        let ws_skills_root = dir.path().join("ws-long-skill");
        let long_secret_id = format!("sk-{}", "a".repeat(46)); // 49 chars (> 48-char column max)
        let skill_dir = ws_skills_root
            .join(".rcode")
            .join("skills")
            .join(&long_secret_id);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!("---\nname: {long_secret_id}\ndescription: Safe skill\n---\nBody\n"),
        )
        .unwrap();
        let long_cat = SkillCatalog::discover(
            &dir.path().join("empty-home"),
            &ws_skills_root,
            &crate::skills::SkillsConfig::default(),
        );
        let sec_vec = vec![long_secret_id.clone()];
        let rendered = long_cat.render_redacted(&long_cat.limits, CatalogUnit::Chars, &sec_vec);
        let table = skills_view(&long_cat, CatalogUnit::Chars, rendered.as_ref(), &sec_vec);
        assert!(
            !table.contains(&long_secret_id[..47]) && table.contains("[REDACTED]"),
            "skills_view must redact 49-char skill ID before 48-char table column clipping: {table}"
        );
    }
}
