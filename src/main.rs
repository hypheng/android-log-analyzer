use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use android_log_analyzer::{OutputFormat, analyze_text, render_report};
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "android-log-analyzer")]
#[command(about = "Analyze Android logs and surface likely crash-related findings")]
struct Cli {
    #[arg(value_name = "LOG_FILE")]
    input: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    #[arg(long, value_name = "OUTPUT_FILE")]
    output: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let input = read_input(cli.input)?;
    let report = analyze_text(&input);
    let rendered = render_report(
        &report,
        match cli.format {
            Format::Text => OutputFormat::Text,
            Format::Json => OutputFormat::Json,
        },
    )?;
    write_output(cli.output, &rendered)?;
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

fn write_output(path: Option<PathBuf>, rendered: &str) -> Result<(), Box<dyn std::error::Error>> {
    match path {
        Some(path) => {
            fs::write(path, rendered)?;
        }
        None => {
            println!("{rendered}");
        }
    }

    Ok(())
}
