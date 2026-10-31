//! Glue between the app/interactive flows and local profiles: `--profile`
//! resolution, client creation through the single key resolver, redaction of
//! profile keys, doctor fields and the read-only server context refresh.
use crate::{
    app::Events,
    cli::Cli,
    config::{ConfigStore, CredentialState, ProviderKind, ProviderSettings, Settings},
    local::{endpoint_identity, validate_profile_name},
    provider::ProviderClient,
};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

const NO_PROFILE: &str = "Профиль local не выбран. Добавьте его: rcode local add ИМЯ --base-url http://127.0.0.1:ПОРТ/v1 --activate, или rcode connect local";

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
        (None, Some(kind)) => Ok(Some(settings.provider(kind))),
        (None, None) => Ok(None),
    }
}

pub(crate) fn profile(settings: &Settings, name: &str) -> Result<ProviderSettings> {
    validate_profile_name(name)?;
    settings
        .local
        .profiles
        .get(name)
        .cloned()
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

/// Creates a client for `provider` with the key the resolver binds to its
/// endpoint. `missing` explains a missing cloud key in the caller's context.
pub(crate) fn client(
    store: &ConfigStore,
    provider: &ProviderSettings,
    events: &mut Events,
    missing: &str,
) -> Result<ProviderClient> {
    let local = provider.kind == ProviderKind::Local;
    match store.credential_for(provider)? {
        CredentialState::Present(credential) => {
            events.remember(credential.value.clone());
            ProviderClient::connect(provider.clone(), Some(credential.value))
        }
        CredentialState::NotRequired => ProviderClient::connect(provider.clone(), None),
        CredentialState::Missing if local => {
            let name = profile_name(provider);
            bail!("Сервер профиля local «{name}» требует ключ: rcode local key {name} --stdin")
        }
        CredentialState::Missing => bail!("{missing}"),
    }
}

/// Before persisting a local selection: the snapshot must still describe the
/// saved profile. A resumed session whose profile moved or was deleted must not
/// rewrite it, otherwise a key entered for one address would follow another.
pub(crate) fn check_commit(settings: &Settings, provider: &ProviderSettings) -> Result<()> {
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

/// `check_commit` against the settings on disk, not the ones this process
/// loaded earlier: `rcode local add --force` or `remove` in another process
/// may have moved or deleted the profile since.
pub(crate) fn check_current(store: &ConfigStore, provider: &ProviderSettings) -> Result<Settings> {
    let settings = store.load()?;
    check_commit(&settings, provider)?;
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
    (
        json!({
            "local": true,
            "profile": local.profile,
            "runtime": local.runtime,
            "endpoint": provider.base_url,
            "credential": credential,
            "credential_error": error,
            "context_tokens": budget.context_tokens,
            "context_source": budget.source.as_str(),
            "input_budget_tokens": budget.limit,
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
