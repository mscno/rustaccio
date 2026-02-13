use rustaccio::examples::{discover_env_vars, render_config_example, render_env_example};
use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn env_example_matches_generated_content() {
    let root = repo_root();
    let expected = render_env_example(&root).expect("generate .env.example");
    let actual = fs::read_to_string(root.join(".env.example")).unwrap_or_default();
    assert_eq!(
        normalize_newlines(&actual),
        normalize_newlines(&expected),
        "`.env.example` is out of sync. Run `cargo run --bin sync_examples`."
    );
}

#[test]
fn config_example_matches_generated_content() {
    let root = repo_root();
    let expected = render_config_example();
    let actual = fs::read_to_string(root.join("config.example.yml")).unwrap_or_default();
    assert_eq!(
        normalize_newlines(&actual),
        normalize_newlines(&expected),
        "`config.example.yml` is out of sync. Run `cargo run --bin sync_examples`."
    );
}

#[test]
fn env_example_covers_discovered_runtime_env_vars() {
    let root = repo_root();
    let vars = discover_env_vars(&root).expect("discover vars");
    let rendered = render_env_example(&root).expect("generate env example");
    for var in vars {
        assert!(
            rendered.contains(&format!("{var}=")),
            "missing env var in .env.example: {var}"
        );
    }
}

fn normalize_newlines(value: &str) -> String {
    value.replace("\r\n", "\n")
}

