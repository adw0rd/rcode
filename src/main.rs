use clap::Parser;
#[tokio::main]
async fn main() {
    let cli = rcode::cli::Cli::parse();
    std::process::exit(rcode::app::run(cli).await);
}
