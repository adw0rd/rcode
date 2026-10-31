#[tokio::test]
async fn echo_captured() {
    let mut command = tokio::process::Command::new("/bin/echo");
    command
        .arg("hello")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let race = async {
        tokio::select! {
            status = child.wait() => { status }
            _ = tokio::signal::ctrl_c() => { unreachable!() }
        }
    };
    let status = race.await;
    let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
    println!("status={status:?} a={a:?} b={b:?} out={out:?} err={err:?}");
    assert_eq!(out, b"hello\n");
}
