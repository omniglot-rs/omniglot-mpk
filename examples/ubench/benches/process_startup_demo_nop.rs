use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

fn extract_bench_executable_line(target_name: &str, line: &str) -> Option<PathBuf> {
    let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
    let obj = parsed.as_object()?;

    if obj.get("reason")?.as_str()? != "compiler-artifact" {
        //eprintln!("Not compiler artifact: {}", line);
        return None;
    }

    let target = obj.get("target")?.as_object()?;
    //println!("Got target: {:?}", target);

    let target_kind = target.get("kind")?.as_array()?;
    //println!("Got target kind: {:?}, {}, {}", target_kind, target_kind.len(), target_kind.get(0)?.as_str()?);
    if target_kind.len() != 1 || target_kind.get(0)?.as_str()?.trim() != "bench".trim() {
        //eprintln!("Wrong target kind: {}", line);
        return None;
    }

    if target.get("name")?.as_str()?.trim() != target_name.trim() {
        //eprintln!("Wrong name: {}", line);
        return None;
    }

    let executable = PathBuf::from(obj.get("executable")?.as_str()?);
    eprintln!(
        "Found target executable for {}: {:?}",
        target_name, executable
    );
    Some(executable)
}

fn extract_bench_executable(target_name: &str, output: &str) -> Option<PathBuf> {
    output
        .lines()
        .find_map(|line| extract_bench_executable_line(target_name, line))
}

fn build_bench_executable(target_name: &str) -> PathBuf {
    eprintln!("Building {} benchmark executable...", target_name);
    let output = Command::new("cargo")
        .args([
            "build",
            "--message-format=json",
            "--release",
            "--bench",
            target_name,
        ])
        .output()
        .expect(&format!(
            "Failed to build {} benchmark executable",
            target_name
        ));
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    extract_bench_executable(target_name, stdout).expect(&format!(
        "Failed to find {} executable in Cargo output:\n{}",
        target_name, stdout
    ))
}

pub fn criterion_benchmark(c: &mut Criterion) {
    // Build all binaries in release mode and determine their target paths:
    let unsafe_executable = build_bench_executable("process_startup_demo_nop_unsafe");
    let og_mpk_executable = build_bench_executable("process_startup_demo_nop_og_mpk");
    let sandcrust_executable = build_bench_executable("process_startup_demo_nop_sandcrust");

    let mut group = c.benchmark_group("runtime_setup");

    group.bench_function("unsafe", |b| {
        b.iter(|| Command::new(&unsafe_executable).output().unwrap());
    });

    group.bench_function("og_mpk", |b| {
        b.iter(|| Command::new(&og_mpk_executable).output().unwrap());
    });

    group.bench_function("sandcrust", |b| {
        b.iter(|| Command::new(&sandcrust_executable).output().unwrap());
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(60));
    targets = criterion_benchmark
}
criterion_main!(benches);
