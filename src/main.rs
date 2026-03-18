use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use android_log_analyzer::analyze_text;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "android-log-analyzer")]
#[command(about = "Analyze Android logs and surface likely crash-related findings")]
struct Cli {
    #[arg(value_name = "LOG_FILE")]
    input: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let input = read_input(cli.input)?;
    let report = analyze_text(&input);

    println!("{report}");
    Ok(())
}

fn read_input(path: Option<PathBuf>) -> Result<String, Box<dyn std::error::Error>> {
    match path {
        Some(path) => Ok(fs::read_to_string(path)?),
        None => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;
            Ok(buffer)
        }
    }
}
