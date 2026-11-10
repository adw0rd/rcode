//! Explicit eval CLI. No provider/settings/process setup on metadata-only paths.
mod json;
mod manifest;
mod profile;
mod runner;
use crate::{
    app::Events,
    cli::{Cli, EvalCommand},
};
use anyhow::Result;
use serde_json::json;
pub(crate) async fn run(command: &EvalCommand, cli: &Cli, events: &Events) -> Result<i32> {
    match command {
        EvalCommand::Validate { suite } => {
            let data = manifest::validate(suite)?;
            events.emit(
                "eval_validated",
                json!({"cases":data.cases.len(),"suite_sha256":data.sha256}),
            );
            Ok(0)
        }
        EvalCommand::Run(args) => runner::run(args, cli, events).await,
        EvalCommand::Compare {
            baseline,
            candidate,
        } => runner::compare(baseline, candidate, events),
    }
}
