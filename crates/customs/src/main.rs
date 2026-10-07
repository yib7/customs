use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = customs::cli::Cli::parse();
    let code = customs::cli::run(cli).await;
    std::process::exit(code);
}
