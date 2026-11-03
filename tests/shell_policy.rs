use rcode::shell_policy::{ShellGrant, literal_argv};

#[test]
fn a_status_grant_does_not_grant_push_or_shell_syntax() {
    let grant = ShellGrant::from_command("git status").unwrap();
    assert!(grant.permits("git status --short"));
    for command in [
        "git push",
        "git statusx",
        "git status; git push",
        "git status && git push",
        "git status $(touch marker)",
        "GIT_SSH_COMMAND=bad git status",
        "git status > marker",
    ] {
        assert!(!grant.permits(command), "{command}");
    }
    assert!(ShellGrant::from_command("git").is_none());
}

#[test]
fn literal_argv_is_bounded_and_does_not_interpret_quoted_expansion() {
    assert_eq!(
        literal_argv(r#"git status "путь с пробелом""#).unwrap(),
        vec!["git", "status", "путь с пробелом"]
    );
    for command in [
        "",
        "git status\nwhoami",
        r#"git status "$HOME""#,
        "git status `whoami`",
        "git status | sh",
        "git status %PATH%",
        "git status !PATH!",
        "git status \\outside",
    ] {
        assert!(literal_argv(command).is_none(), "{command}");
    }
    assert!(literal_argv(&"x".repeat(16385)).is_none());
}
