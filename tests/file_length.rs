use std::{
    env,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

const MAX_LINES: usize = 400;
const ENFORCE_ENV: &str = "RUSTACCIO_ENFORCE_FILE_LENGTH";

#[test]
fn rust_source_files_are_limited_to_400_lines() {
    let enforce = env::var(ENFORCE_ENV)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    if !enforce {
        eprintln!(
            "skipping file-length gate (set {ENFORCE_ENV}=1 to enforce {MAX_LINES}-line limit)"
        );
        return;
    }

    let mut offenders = Vec::new();
    for root in ["src", "tests"] {
        collect_rs_files(Path::new(root), &mut offenders);
    }

    let offenders: Vec<String> = offenders
        .into_iter()
        .filter_map(|path| {
            let lines = count_lines(&path).ok()?;
            if lines > MAX_LINES {
                Some(format!("{} ({lines} lines)", path.display()))
            } else {
                None
            }
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "files over {MAX_LINES} lines:\n{}",
        offenders.join("\n")
    );
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn count_lines(path: &Path) -> Result<usize, std::io::Error> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count())
}
