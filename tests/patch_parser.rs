use rcode::patch::{Operation, Patch, apply_hunks};

#[test]
fn patch_has_no_side_effects_and_applies_exact_context() {
    let patch = Patch::parse("*** Begin Patch\n*** Update File: src/main.rs\n@@\n-fn old() {}\n+fn new() {}\n*** Add File: note.txt\n+Привет\n*** End Patch\n").unwrap();
    let Operation::Update { hunks, .. } = &patch.operations()[0] else {
        panic!("wrong operation")
    };
    assert_eq!(
        apply_hunks("fn old() {}\n", hunks).unwrap(),
        "fn new() {}\n"
    );
    assert_eq!(patch.operations().len(), 2);
}

#[test]
fn ambiguity_and_unsafe_paths_are_rejected() {
    let patch = Patch::parse(
        "*** Begin Patch\n*** Update File: data.txt\n@@\n-same\n+new\n*** End Patch\n",
    )
    .unwrap();
    let Operation::Update { hunks, .. } = &patch.operations()[0] else {
        panic!("wrong operation")
    };
    assert!(apply_hunks("same\nsame\n", hunks).is_err());
    for path in [
        "../outside",
        "/absolute",
        "C:/file",
        "dir/../outside",
        ".git/config",
        "credentials.json",
    ] {
        assert!(
            Patch::parse(&format!(
                "*** Begin Patch\n*** Delete File: {path}\n*** End Patch\n"
            ))
            .is_err()
        );
    }
}

#[test]
fn rename_intent_conflicts_and_exact_newline_state_are_checked() {
    assert!(Patch::parse("*** Begin Patch\n*** Update File: a\n*** Move to: b\n*** Add File: b\n+collision\n*** End Patch\n").is_err());
    let patch = Patch::parse(
        "*** Begin Patch\n*** Update File: a\n@@\n-old\n+новое\n*** End of File\n*** End Patch\n",
    )
    .unwrap();
    let Operation::Update { hunks, .. } = &patch.operations()[0] else {
        panic!("wrong operation")
    };
    assert_eq!(apply_hunks("old", hunks).unwrap(), "новое");
}

#[test]
fn adding_an_empty_file_is_a_valid_patch_intent() {
    let patch = Patch::parse("*** Begin Patch\n*** Add File: empty.txt\n*** End Patch\n").unwrap();
    assert_eq!(
        patch.operations(),
        &[Operation::Add {
            path: "empty.txt".into(),
            content: String::new()
        }]
    );
}

#[test]
fn deleting_final_line_preserves_surviving_line_ending() {
    let patch = Patch::parse(
        "*** Begin Patch\n*** Update File: a\n@@\n-b\n*** End of File\n*** End Patch\n",
    )
    .unwrap();
    let Operation::Update { hunks, .. } = &patch.operations()[0] else {
        panic!("wrong operation")
    };
    assert_eq!(apply_hunks("a\r\nb\n", hunks).unwrap(), "a\r\n");
}

#[test]
fn total_hunk_search_has_a_deterministic_work_budget() {
    use rcode::patch::{Hunk, HunkLine};
    let lines: Vec<String> = (0..5000).map(|n| format!("L{n:05}")).collect();
    let original = lines.join("\n") + "\n";
    let hunks: Vec<_> = lines
        .into_iter()
        .map(|line| Hunk {
            heading: None,
            lines: vec![HunkLine::Remove(line)],
            eof: false,
        })
        .collect();
    let error = apply_hunks(&original, &hunks)
        .expect_err("bounded parser must refuse excessive total search");
    assert!(error.to_string().contains("бюджет"));
}
