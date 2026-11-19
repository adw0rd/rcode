//! Glue between the app/interactive flows and local profiles: `--profile`
//! resolution, client creation through the single key resolver, redaction of
//! profile keys, doctor fields and the read-only server context refresh.
use crate::{
    app::Events,
    cli::Cli,
    config::{ConfigStore, CredentialState, ProviderKind, ProviderSettings, Settings},
    local::endpoint_identity,
    provider::ProviderClient,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const NO_PROFILE: &str = "Профиль local не выбран. Добавьте его: rcode local add ИМЯ --base-url http://127.0.0.1:ПОРТ/v1 --activate, или rcode connect local";

/// Resolves the active local profile with slot/kind validation, or returns an
/// unsaved draft `Local` snapshot when no active profile is configured.
pub(crate) fn active_local_or_draft(settings: &Settings) -> Result<ProviderSettings> {
    if let Some(active) = settings.local.active.as_deref() {
        return profile(settings, active);
    }
    Ok(ProviderSettings::new(ProviderKind::Local))
}

/// The provider chosen on the command line. `--profile` implies local and
/// conflicts with any other `--provider`.
pub(crate) fn requested_provider(
    settings: &Settings,
    cli: &Cli,
) -> Result<Option<ProviderSettings>> {
    match (&cli.profile, cli.provider) {
        (Some(_), Some(kind)) if kind != ProviderKind::Local => {
            bail!("--profile выбирает локальный профиль и несовместим с --provider {kind}")
        }
        (Some(name), _) => profile(settings, name).map(Some),
        (None, Some(ProviderKind::Local)) => active_local_or_draft(settings).map(Some),
        (None, Some(kind)) => Ok(Some(
            crate::model_route::configured_cloud_provider(settings, kind)?
                .unwrap_or_else(|| settings.provider(kind)),
        )),
        (None, None) => Ok(None),
    }
}

pub(crate) fn profile(settings: &Settings, name: &str) -> Result<ProviderSettings> {
    crate::model_route::configured_local_profile(settings, name)?
        .with_context(|| format!("Профиль local «{name}» не найден: rcode local list"))
}

/// A local selection without any saved profile is an unsaved draft.
pub(crate) fn ensure_profile(provider: &ProviderSettings) -> Result<()> {
    if provider.kind == ProviderKind::Local && provider.model.trim().is_empty() {
        bail!("{NO_PROFILE}");
    }
    Ok(())
}

/// Every accepted local key is a secret (empty values are ignored by `Events`).
pub(crate) fn remember_key(events: &mut Events, key: &str) {
    events.remember(key.to_owned());
}

pub(crate) fn remember_keys(store: &ConfigStore, settings: &Settings, events: &mut Events) {
    for name in settings.local.profiles.keys() {
        if let Ok(Some(credential)) = store.local_credential(name) {
            remember_key(events, &credential.value);
        }
    }
}

#[cfg(test)]
pub(crate) fn client(
    store: &ConfigStore,
    provider: &ProviderSettings,
    events: &mut Events,
    missing: &str,
) -> Result<ProviderClient> {
    let cred = store.credential_for(provider)?;
    client_with_credential(provider, cred, events, missing)
}

pub(crate) fn client_with_credential(
    provider: &ProviderSettings,
    cred: CredentialState,
    events: &mut Events,
    missing: &str,
) -> Result<ProviderClient> {
    let local = provider.kind == ProviderKind::Local;
    match cred {
        CredentialState::Present(credential) => {
            events.remember(credential.value.clone());
            let mut client = ProviderClient::connect(provider.clone(), Some(credential.value))?;
            client.bind_secret_sink(events.shared_secrets());
            Ok(client)
        }
        CredentialState::NotRequired => {
            let mut client = ProviderClient::connect(provider.clone(), None)?;
            client.bind_secret_sink(events.shared_secrets());
            Ok(client)
        }
        CredentialState::Missing if local => {
            let name = profile_name(provider);
            bail!("Сервер профиля local «{name}» требует ключ: rcode local key {name} --stdin")
        }
        CredentialState::Missing => bail!("{missing}"),
    }
}

/// Verifies that the local profile still exists and points to the same loopback
/// endpoint identity (ignoring temporary session `--ca-file` / model overrides).
pub(crate) fn check_endpoint(settings: &Settings, provider: &ProviderSettings) -> Result<()> {
    if provider.kind != ProviderKind::Local {
        return Ok(());
    }
    let name = profile_name(provider);
    let Some(saved) = settings.local.profiles.get(name) else {
        bail!("Профиль local «{name}» больше не сохранён. Выберите профиль через /provider local");
    };
    let identity =
        |settings: &ProviderSettings| settings.base_url.as_deref().and_then(endpoint_identity);
    if identity(saved) != identity(provider) {
        bail!(
            "Адрес профиля local «{name}» изменился после начала сессии. Выберите профиль заново через /provider local"
        );
    }
    Ok(())
}

/// Before persisting a local selection: the snapshot must still describe the
/// saved profile (both endpoint and TLS/CA connection parameters). A resumed or
/// mid-menu session whose profile moved, changed CA, or was deleted must not
/// rewrite it, otherwise a key or model chosen for one connection would follow another.
pub(crate) fn check_commit(settings: &Settings, provider: &ProviderSettings) -> Result<()> {
    if provider.kind != ProviderKind::Local {
        return Ok(());
    }
    check_endpoint(settings, provider)?;
    let name = profile_name(provider);
    if let Some(saved) = settings.local.profiles.get(name)
        && !crate::model_route::RouteIdentity::same_connection(saved, provider)
    {
        bail!(
            "Параметры подключения профиля local «{name}» изменились после начала сессии. Выберите профиль заново через /provider local"
        );
    }
    Ok(())
}

/// Verifies both that `session_provider` still points to the saved loopback
/// endpoint AND that `disk_baseline` (the profile snapshot on disk when the
/// session/menu started, including any legacy relative `ca_file` overridden by
/// `--ca-file`) has not drifted in another process.
pub(crate) fn check_current_with_baseline(
    store: &ConfigStore,
    session_provider: &ProviderSettings,
    disk_baseline: &ProviderSettings,
) -> Result<Settings> {
    let settings = store.load()?;
    check_endpoint(&settings, session_provider)?;
    if disk_baseline.kind == ProviderKind::Local {
        let name = profile_name(disk_baseline);
        let saved = crate::model_route::configured_local_profile(&settings, name)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Профиль local «{name}» больше не сохранён. Выберите профиль через /provider local"
                )
            })?;
        if !crate::model_route::RouteIdentity::disk_unchanged(&saved, disk_baseline) {
            bail!(
                "Параметры подключения профиля local «{name}» изменились после начала сессии. Выберите профиль заново через /provider local"
            );
        }
    }
    Ok(settings)
}

pub(crate) fn profile_name(provider: &ProviderSettings) -> &str {
    provider
        .local
        .as_ref()
        .map_or(crate::local::DRAFT_PROFILE, |local| local.profile.as_str())
}

/// Doctor fields for a local profile. The key value is never included.
pub(crate) fn doctor_fields(
    store: &ConfigStore,
    provider: &ProviderSettings,
    client: Option<&ProviderClient>,
) -> (Value, bool) {
    let (credential, usable, error) = match store.credential_for(provider) {
        Ok(CredentialState::Present(_)) => ("stored", true, None),
        Ok(CredentialState::NotRequired) => ("not_required", true, None),
        Ok(CredentialState::Missing) => ("missing", false, None),
        Err(error) => ("blocked", false, Some(format!("{error:#}"))),
    };
    let budget = match client {
        Some(client) => client.context_budget(0),
        None => crate::context::ContextBudget::for_provider(provider, None, 1.0, 0),
    };
    let local = provider
        .local
        .clone()
        .unwrap_or_else(crate::local::draft_settings);
    let clean_profile = crate::model_route::redact_route_display_field(store, &[], &local.profile);
    let clean_endpoint = provider
        .base_url
        .as_deref()
        .map(|u| crate::model_route::redact_route_display_field(store, &[], u));
    let clean_error = error
        .as_deref()
        .map(|e| crate::model_route::redact_route_display_field(store, &[], e));
    (
        json!({
            "local": true,
            "profile": clean_profile,
            "runtime": local.runtime,
            "endpoint": clean_endpoint,
            "credential": credential,
            "credential_error": clean_error,
            "context_tokens": budget.context_tokens,
            "context_source": budget.source.as_str(),
            "input_budget_tokens": budget.limit,
            "thinking": local.thinking,
        }),
        usable,
    )
}

/// Read-only context probe with a short deadline; a smaller server context
/// lowers the budget and is reported once.
pub(crate) async fn refresh_context(client: &ProviderClient, events: &Events) {
    if !client.is_local() {
        return;
    }
    if let Some(warning) = client.refresh_local_context().await {
        events.emit("warning", json!({"message": warning}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{LocalRuntime, profile_settings};

    #[test]
    fn commit_requires_the_snapshot_to_match_the_saved_profile() {
        let mut settings = Settings::default();
        let saved = profile_settings("box", "http://127.0.0.1:8080/v1", LocalRuntime::Mlx, "m");
        settings.remember_provider(&saved);
        let mut other_model = saved.clone();
        other_model.model = "m2".into();
        assert!(check_commit(&settings, &other_model).is_ok());
        let mut alias = saved.clone();
        alias.base_url = Some("http://localhost:8080/v1/".into());
        assert!(
            check_commit(&settings, &alias).is_ok(),
            "same 127.0.0.1 endpoint"
        );
        for moved in ["http://127.0.0.1:8081/v1", "http://[::1]:8080/v1"] {
            let mut snapshot = saved.clone();
            snapshot.base_url = Some(moved.into());
            assert!(check_commit(&settings, &snapshot).is_err(), "{moved}");
        }
        let deleted = profile_settings("gone", "http://127.0.0.1:8080/v1", LocalRuntime::Mlx, "m");
        assert!(check_commit(&settings, &deleted).is_err());
        assert!(check_commit(&settings, &ProviderSettings::new(ProviderKind::Custom)).is_ok());
    }

    #[test]
    fn profile_flag_implies_local_and_rejects_other_providers() {
        use clap::Parser;
        let mut settings = Settings::default();
        settings.remember_provider(&profile_settings(
            "box",
            "http://127.0.0.1:8080/v1",
            LocalRuntime::Mlx,
            "m",
        ));
        let cli = |args: &[&str]| Cli::parse_from([&["rcode"], args].concat());
        let chosen = requested_provider(&settings, &cli(&["--profile", "box"]))
            .unwrap()
            .unwrap();
        assert_eq!(profile_name(&chosen), "box");
        assert!(
            requested_provider(
                &settings,
                &cli(&["--provider", "local", "--profile", "box"])
            )
            .is_ok()
        );
        assert!(
            requested_provider(
                &settings,
                &cli(&["--provider", "custom", "--profile", "box"])
            )
            .is_err()
        );
        assert!(requested_provider(&settings, &cli(&["--profile", "nope"])).is_err());
        assert!(requested_provider(&settings, &cli(&[])).unwrap().is_none());
        assert!(ensure_profile(&settings.provider(ProviderKind::Local)).is_ok());
        assert!(ensure_profile(&Settings::default().provider(ProviderKind::Local)).is_err());
    }
}
