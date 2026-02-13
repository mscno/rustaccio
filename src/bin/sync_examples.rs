use rustaccio::examples::sync_example_files;
use std::path::Path;

fn main() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    if let Err(err) = sync_example_files(repo_root) {
        eprintln!("{err}");
        std::process::exit(1);
    }
    println!("synced .env.example and config.example.yml");
}

