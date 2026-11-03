use rcode::diagnostics::{Parser, discover, parse};
#[test]
fn valid_multiline_manifests_are_discovered_without_running_scripts() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    std::fs::write(root.join("Cargo.toml"),"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n[dependencies]\nfeatures = [\n \"one\",\n \"two\",\n]\n").unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{"scripts":{"check":"touch OWNED; curl invalid","test":"exit 7"}}"#,
    )
    .unwrap();
    let commands = discover(&root).unwrap();
    assert!(commands.iter().any(|c| c.id == "cargo-check"));
    assert!(commands.iter().any(|c| c.id == "npm-check"));
    assert!(!root.join("OWNED").exists());
}
#[test]
fn quiet_typecheck_is_a_known_process_result_and_unknown_output_is_not_clean() {
    let ok = parse(Parser::TypeScript, "", "", Some(0)).unwrap();
    assert!(ok.success);
    assert!(!ok.unparsed);
    for (out, exit) in [("garbled output", Some(0)), ("", Some(1)), ("", None)] {
        assert!(!parse(Parser::TypeScript, out, "", exit).unwrap().success);
    }
    let failed = parse(
        Parser::TypeScript,
        "src/ёж.ts(4,2): error TS2322: Bad type",
        "",
        Some(2),
    )
    .unwrap();
    assert_eq!(failed.diagnostics[0].line, Some(4));
    assert!(!failed.success);
}
#[test]
fn compiler_failure_and_test_collection_error_override_claimed_success() {
    let rust = r#"{"reason":"compiler-message","message":{"level":"error","message":"bad type","spans":[{"is_primary":true,"file_name":"src/main.rs","line_start":3,"column_start":5}]}}
{"reason":"build-finished","success":false}"#;
    let report = parse(Parser::Rust, rust, "", Some(0)).unwrap();
    assert!(!report.success);
    assert_eq!(report.diagnostics[0].file.as_deref(), Some("src/main.rs"));
    let py = parse(
        Parser::Pytest,
        "ERROR collecting test_demo.py\n1 passed in 0.01s",
        "",
        Some(0),
    )
    .unwrap();
    assert!(!py.success);
    assert!(!parse(Parser::Raw, "PASS", "", Some(0)).unwrap().success);
}
