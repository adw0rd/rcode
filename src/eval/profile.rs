use crate::config::{CredentialState, ProviderKind, ProviderSettings, Settings};
use anyhow::{Context, Result, ensure};

const GIGACHAT_BASE_URL: &str = "https://api.giga.chat/v1";
const GIGACHAT_AUTH_URL: &str = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth";

pub(crate) struct Selected {
    pub selected: ProviderSettings,
    pub effective: ProviderSettings,
    pub credential: Option<String>,
}

pub(crate) fn select(
    settings: &Settings,
    name: &str,
    credential: CredentialState,
) -> Result<Selected> {
    let local_profile = settings.local.profiles.contains_key(name);
    let selected = if local_profile {
        settings.local.profiles.get(name)
    } else if name == "gigachat" {
        settings.providers.get("gigachat")
    } else {
        None
    }
    .context("Для eval run выберите сохранённый local profile или gigachat")?
    .clone();
    selected.validate()?;
    ensure!(selected.ca_file.is_none(), "Eval не поддерживает custom CA");
    let credential = match (local_profile, selected.kind, credential) {
        (true, ProviderKind::Local, CredentialState::NotRequired) => {
            ensure!(
                selected
                    .local
                    .as_ref()
                    .is_some_and(|local| !local.key_required),
                "Eval поддерживает только credential-free local profile"
            );
            None
        }
        (false, ProviderKind::GigaChat, CredentialState::Present(credential)) => {
            validate_gigachat_endpoints(&selected)?;
            Some(credential.value)
        }
        (true, ProviderKind::Local, _) => {
            anyhow::bail!("Credential-free local profile требует CredentialState::NotRequired")
        }
        (false, ProviderKind::GigaChat, _) => {
            anyhow::bail!("Для GigaChat eval требуется сохранённый ключ")
        }
        _ => anyhow::bail!("Выбранный profile не является local или GigaChat"),
    };
    let mut effective = selected.clone();
    effective.stream = false;
    Ok(Selected {
        selected,
        effective,
        credential,
    })
}

pub(crate) fn validate_gigachat_endpoints(profile: &ProviderSettings) -> Result<()> {
    ensure!(
        profile
            .base_url
            .as_deref()
            .is_none_or(|url| url == GIGACHAT_BASE_URL)
            && profile
                .auth_url
                .as_deref()
                .is_none_or(|url| url == GIGACHAT_AUTH_URL),
        "GigaChat eval поддерживает только официальные base_url и auth_url"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::select;
    use crate::config::{Credential, CredentialState, ProviderKind, ProviderSettings, Settings};
    use serde_json::json;

    const SECRET: &str = "eval-synthetic-secret-7f4c9a";

    fn credential() -> CredentialState {
        CredentialState::Present(Credential {
            value: SECRET.into(),
            source: "test".into(),
        })
    }

    fn gigachat() -> ProviderSettings {
        let mut profile = ProviderSettings::new(ProviderKind::GigaChat);
        profile.model = "GigaChat-3-Ultra".into();
        profile
    }

    fn with_gigachat(profile: ProviderSettings) -> Settings {
        let mut settings = Settings::default();
        settings.providers.insert("gigachat".into(), profile);
        settings
    }

    #[test]
    fn gigachat_requires_official_endpoints_and_present_key() {
        let mut profile = gigachat();
        profile.stream = false;
        let settings = with_gigachat(profile);
        assert!(select(&settings, "gigachat", CredentialState::Missing).is_err());
    }

    #[test]
    fn arbitrary_provider_names_are_rejected() {
        let settings = Settings::default();
        assert!(select(&settings, "openrouter", credential()).is_err());
        assert!(select(&settings, "missing", CredentialState::Missing).is_err());
    }

    #[test]
    fn gigachat_is_selected_without_mutating_the_saved_stream_setting() {
        let mut profile = gigachat();
        profile.stream = true;
        let settings = with_gigachat(profile);
        let selected = select(&settings, "gigachat", credential()).unwrap();
        assert_eq!(selected.selected.kind, ProviderKind::GigaChat);
        assert!(selected.selected.stream);
        assert!(!selected.effective.stream);
        assert_eq!(selected.credential.as_deref(), Some(SECRET));
    }

    #[test]
    fn gigachat_rejects_custom_endpoints_and_ca() {
        for mutate in [
            (|profile: &mut ProviderSettings| {
                profile.base_url = Some("https://example.com/v1".into());
            }) as fn(&mut ProviderSettings),
            |profile| {
                profile.auth_url = Some("https://example.com/oauth".into());
            },
            |profile| {
                profile.ca_file = Some("custom-ca.pem".into());
            },
        ] {
            let mut profile = gigachat();
            mutate(&mut profile);
            let settings = with_gigachat(profile);
            assert!(select(&settings, "gigachat", credential()).is_err());
        }
    }

    #[test]
    fn gigachat_accepts_default_and_explicit_official_endpoints() {
        for (base_url, auth_url) in [
            (None, None),
            (
                Some("https://api.giga.chat/v1".into()),
                Some("https://ngw.devices.sberbank.ru:9443/api/v2/oauth".into()),
            ),
        ] {
            let mut profile = gigachat();
            profile.base_url = base_url;
            profile.auth_url = auth_url;
            let settings = with_gigachat(profile);
            assert!(select(&settings, "gigachat", credential()).is_ok());
        }
    }

    #[test]
    fn credential_free_local_profile_remains_supported() {
        let mut settings = Settings::default();
        let profile = crate::local::profile_settings(
            "fixture",
            "http://127.0.0.1:8080/v1",
            crate::local::LocalRuntime::Mlx,
            "fixture",
        );
        settings
            .local
            .profiles
            .insert("fixture".into(), profile.clone());
        let selected = select(&settings, "fixture", CredentialState::NotRequired).unwrap();
        assert_eq!(selected.selected.kind, ProviderKind::Local);
        assert!(selected.selected.stream);
        assert!(!selected.effective.stream);
        assert_eq!(selected.credential, None);
    }

    #[test]
    fn unsupported_credential_combinations_are_rejected() {
        let settings = with_gigachat(gigachat());
        assert!(select(&settings, "gigachat", CredentialState::NotRequired).is_err());

        let mut settings = Settings::default();
        let mut profile = crate::local::profile_settings(
            "fixture",
            "http://127.0.0.1:8080/v1",
            crate::local::LocalRuntime::Mlx,
            "fixture",
        );
        settings
            .local
            .profiles
            .insert("fixture".into(), profile.clone());
        assert!(select(&settings, "fixture", credential()).is_err());
        assert!(select(&settings, "fixture", CredentialState::Missing).is_err());
        profile.local.as_mut().unwrap().key_required = true;
        settings.local.profiles.insert("fixture".into(), profile);
        assert!(select(&settings, "fixture", CredentialState::NotRequired).is_err());
    }

    #[test]
    fn public_metadata_excludes_the_host_only_credential() {
        let settings = with_gigachat(gigachat());
        let selected = select(&settings, "gigachat", credential()).unwrap();
        let comparison_key = json!({
            "selected_profile": selected.selected,
            "effective_profile": selected.effective,
        });
        let mut invocation = json!({
            "provider_credential": selected.credential,
            "comparison_key": comparison_key,
            "effective_profile": selected.effective,
            "helpers": {"host.py": "a".repeat(64)},
            "artifact": {"series": "candidate", "platform": "linux"},
        });
        assert_eq!(invocation["provider_credential"], SECRET);
        invocation
            .as_object_mut()
            .unwrap()
            .remove("provider_credential");
        let serialized = serde_json::to_string(&invocation).unwrap();
        assert!(!serialized.contains(SECRET));
        assert!(!serialized.contains("credential"));
    }
}
