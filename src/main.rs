use rustaccio::{
    config::Config,
    runtime::{run_from_env, run_standalone},
};
use std::path::PathBuf;

const USAGE: &str = "\
Usage: rustaccio [OPTIONS]

Options:
  -c, --config <path>  Path to Verdaccio-style YAML config file
  -h, --help           Print help
";

#[derive(Debug, Default, PartialEq, Eq)]
struct CliOptions {
    config_path: Option<PathBuf>,
    help: bool,
}

fn parse_cli_args<I>(args: I) -> Result<CliOptions, String>
where
    I: IntoIterator<Item = String>,
{
    let mut options = CliOptions::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                options.help = true;
            }
            "-c" | "--config" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value for --config".to_string())?;
                options.config_path = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--config=") => {
                let value = arg.trim_start_matches("--config=");
                if value.is_empty() {
                    return Err("missing value for --config".to_string());
                }
                options.config_path = Some(PathBuf::from(value));
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    Ok(options)
}

#[tokio::main]
async fn main() {
    let options = match parse_cli_args(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("{err}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    if options.help {
        println!("{USAGE}");
        return;
    }

    let run_result = if let Some(config_path) = options.config_path {
        match Config::from_env_with_config_file(config_path) {
            Ok(config) => run_standalone(config).await,
            Err(err) => {
                eprintln!("invalid --config value: {err}");
                std::process::exit(2);
            }
        }
    } else {
        run_from_env().await
    };

    if let Err(err) = run_result {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_cli_args;
    use std::path::PathBuf;

    #[test]
    fn parses_config_flag_with_space_delimited_value() {
        let parsed = parse_cli_args(vec!["--config".to_string(), "./config.yml".to_string()])
            .expect("parse args");
        assert_eq!(parsed.config_path, Some(PathBuf::from("./config.yml")));
        assert!(!parsed.help);
    }

    #[test]
    fn parses_config_flag_with_equals_value() {
        let parsed = parse_cli_args(vec!["--config=./config.yml".to_string()]).expect("parse args");
        assert_eq!(parsed.config_path, Some(PathBuf::from("./config.yml")));
    }

    #[test]
    fn parses_short_config_flag() {
        let parsed =
            parse_cli_args(vec!["-c".to_string(), "./config.yml".to_string()]).expect("parse args");
        assert_eq!(parsed.config_path, Some(PathBuf::from("./config.yml")));
    }

    #[test]
    fn parses_help_flag() {
        let parsed = parse_cli_args(vec!["--help".to_string()]).expect("parse args");
        assert!(parsed.help);
    }

    #[test]
    fn errors_when_config_value_is_missing() {
        let err = parse_cli_args(vec!["--config".to_string()]).expect_err("missing value");
        assert_eq!(err, "missing value for --config");
    }

    #[test]
    fn errors_on_unknown_flag() {
        let err = parse_cli_args(vec!["--wat".to_string()]).expect_err("unknown arg");
        assert_eq!(err, "unknown argument: --wat");
    }
}
