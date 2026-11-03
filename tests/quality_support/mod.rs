#![allow(dead_code)]
use std::{path::PathBuf, process::Output, time::Duration};
pub const KEY: &str = "quality-fixture-key";
pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub project: PathBuf,
    pub home: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("project");
        let home = temp.path().join("state");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(temp.path().join("user-home")).unwrap();
        Self {
            temp,
            project,
            home,
        }
    }
    pub async fn run(
        &self,
        server: &crate::support::Server,
        options: &[&str],
        prompt: &str,
    ) -> Output {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_rcode"));
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("RCODE_HOME", &self.home)
            .env("HOME", self.temp.path().join("user-home"))
            .env("USERPROFILE", self.temp.path().join("user-home"))
            .env("RCODE_CUSTOM_API_KEY", KEY)
            .args([
                "-C",
                self.project.to_str().unwrap(),
                "--provider",
                "custom",
                "--base-url",
                &server.base(),
                "--model",
                "fixture",
                "--json",
                "--max-steps",
                "8",
            ])
            .args(options)
            .args(["exec", prompt])
            .kill_on_drop(true);
        for name in ["SYSTEMROOT", "TMPDIR", "TEMP", "TMP"] {
            if let Some(v) = std::env::var_os(name) {
                command.env(name, v);
            }
        }
        tokio::time::timeout(Duration::from_secs(20), command.output())
            .await
            .expect("CLI fixture deadline")
            .unwrap()
    }
    pub fn saved(&self) -> serde_json::Value {
        let dir = std::fs::read_dir(self.home.join("sessions"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        serde_json::from_slice(&std::fs::read(dir.join("session.json")).unwrap()).unwrap()
    }
}
pub fn events(output: &Output) -> Vec<serde_json::Value> {
    output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_slice(s).expect("valid JSONL"))
        .collect()
}
