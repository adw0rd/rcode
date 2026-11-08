use clap::Parser;

fn main() {
    let cli = rcode::cli::Cli::parse();
    let code = std::thread::Builder::new()
        .name("rcode-main".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 * 1024 * 1024)
                .build()
                .expect("tokio runtime")
                .block_on(Box::pin(rcode::app::run(cli)))
        })
        .expect("main thread")
        .join()
        .unwrap_or(1);
    std::process::exit(code);
}
