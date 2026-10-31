use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) const MANIFEST_VERSION: u32 = 1;

/// `RCODE_HOME/skills.json`: installed skill sources and catalog settings.
/// Kept out of `config.json` so older rcode versions never overwrite it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Manifest {
    version: u32,
    #[serde(default)]
    sources: BTreeMap<String, SourceRecord>,
    #[serde(default)]
    disabled: BTreeSet<String>,
    #[serde(default)]
    project_roots: Vec<PathBuf>,
    #[serde(default)]
    linked: BTreeMap<String, LinkedRoot>,
    #[serde(default)]
    catalog: CatalogOverrides,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SourceRecord {
    pub(crate) kind: String,
    pub(crate) url: String,
    #[serde(rename = "ref")]
    pub(crate) reference: Option<String>,
    pub(crate) commit: String,
    pub(crate) skills_root: String,
    pub(crate) tree_sha256: String,
    pub(crate) package_version: Option<String>,
    pub(crate) installed_at: u64,
    pub(crate) updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LinkedRoot {
    pub(crate) path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct CatalogOverrides {
    pub(crate) description_chars: Option<usize>,
    pub(crate) cloud_chars: Option<usize>,
    pub(crate) local_share_percent: Option<usize>,
}

impl Manifest {
    pub(crate) fn path(rcode_home: &Path) -> PathBuf {
        rcode_home.join("skills.json")
    }

    /// Defaults when the file is missing; a damaged or unknown-version file is
    /// an error and is never rewritten.
    pub(crate) fn read(rcode_home: &Path) -> Result<Self> {
        let path = Self::path(rcode_home);
        if std::fs::symlink_metadata(&path).is_err() {
            return Ok(Self {
                version: MANIFEST_VERSION,
                ..Self::default()
            });
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("Не удалось прочитать {}", path.display()))?;
        let manifest: Self =
            serde_json::from_str(&text).with_context(|| format!("Повреждён {}", path.display()))?;
        if manifest.version != MANIFEST_VERSION {
            bail!(
                "{} имеет версию {}, эта версия rcode понимает только {}",
                path.display(),
                manifest.version,
                MANIFEST_VERSION
            );
        }
        Ok(manifest)
    }

    pub(crate) fn save(&self, rcode_home: &Path) -> Result<()> {
        let path = Self::path(rcode_home);
        let _lock = crate::config::lock_state_file(&rcode_home.join("skills.lock"))?;
        crate::config::write_private_json(&path, self)
    }

    pub(crate) fn sources(&self) -> &BTreeMap<String, SourceRecord> {
        &self.sources
    }

    pub(crate) fn disabled(&self) -> &BTreeSet<String> {
        &self.disabled
    }

    pub(crate) fn set_disabled(&mut self, disabled: BTreeSet<String>) {
        self.disabled = disabled;
    }

    pub(crate) fn project_roots(&self) -> &[PathBuf] {
        &self.project_roots
    }

    #[expect(dead_code, reason = "linked-корни подключает T12")]
    pub(crate) fn linked(&self) -> &BTreeMap<String, LinkedRoot> {
        &self.linked
    }

    pub(crate) fn catalog_overrides(&self) -> &CatalogOverrides {
        &self.catalog
    }

    #[expect(dead_code, reason = "каталог переопределяет установщик T11")]
    pub(crate) fn set_catalog(&mut self, catalog: CatalogOverrides) {
        self.catalog = catalog;
    }
}
