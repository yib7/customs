use clap::Parser;

fn main() {
    // Before the runtime starts its threads, so they share the capped arenas.
    customs::util::limit_malloc_arenas();
    let cli = customs::cli::Cli::parse();
    let code = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("starting the tokio runtime")
        .block_on(customs::cli::run(cli));
    std::process::exit(code);
}
