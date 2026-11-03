use rcode::redaction::StreamingRedactor;

fn decode(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

#[test]
fn secret_is_redacted_at_every_chunk_boundary() {
    let secret = "sk-fixture-secret-123456".to_owned();
    let input = format!("before {secret} after");
    for cut in 0..=input.len() {
        let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
        let mut output = stream.push(&input.as_bytes()[..cut]).unwrap();
        output.extend(stream.push(&input.as_bytes()[cut..]).unwrap());
        output.extend(stream.finish().unwrap());
        assert_eq!(decode(output), "before [REDACTED] after", "cut={cut}");
    }
}

#[test]
fn json_and_url_forms_are_redacted() {
    let secret = "key/a+b=1234".to_owned();
    let json = serde_json::to_string(&secret).unwrap();
    let encoded = "key%2Fa%2Bb%3D1234";
    for value in [
        secret.as_str(),
        &json[1..json.len() - 1],
        encoded,
        "key%2fa%2bb%3d1234",
    ] {
        let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
        let mut output = Vec::new();
        for byte in value.as_bytes() {
            output.extend(stream.push(std::slice::from_ref(byte)).unwrap());
        }
        output.extend(stream.finish().unwrap());
        assert_eq!(decode(output), "[REDACTED]");
    }
}

#[test]
fn aborted_tail_never_publishes_partial_secret() {
    let secret = "fixture-long-secret".to_owned();
    for count in 1..secret.len() {
        let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
        let mut output = stream.push(&secret.as_bytes()[..count]).unwrap();
        output.extend(stream.abort());
        assert!(stream.redaction_incomplete());
        assert_eq!(decode(output), "[REDACTED_PENDING]");
        assert!(stream.push(b"more").is_err());
    }
}

#[test]
fn unrelated_unicode_output_is_lossless_and_streams_are_independent() {
    let secret = "fixture-secret-key".to_owned();
    let input = "Ошибок нет: проверено 🦀\n";
    let mut first = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
    let mut second = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
    let mut output = Vec::new();
    for byte in input.as_bytes() {
        output.extend(first.push(std::slice::from_ref(byte)).unwrap());
    }
    assert!(second.push(b"fixture-sec").unwrap().is_empty());
    output.extend(first.finish().unwrap());
    assert_eq!(decode(output), input);
    assert_eq!(decode(second.abort()), "[REDACTED_PENDING]");
}

#[test]
fn longest_secret_match_and_constructor_limits_are_explicit() {
    let mut stream = StreamingRedactor::new(&["prefix".into(), "prefix-long".into()]).unwrap();
    let mut output = stream.push(b"prefix-long prefix").unwrap();
    output.extend(stream.finish().unwrap());
    assert_eq!(decode(output), "[REDACTED] [REDACTED]");
    assert!(StreamingRedactor::new(&[String::new()]).is_err());
    assert!(StreamingRedactor::new(&["s".repeat(8193)]).is_err());
    let mut empty = StreamingRedactor::new(&[]).unwrap();
    assert_eq!(empty.push(b"normal").unwrap(), b"normal");
    assert!(empty.finish().unwrap().is_empty());
}

#[test]
fn long_output_streams_before_eof_without_exposing_cross_chunk_matches() {
    let secret = "fixture-stream-secret-123".to_owned();
    for chunk_size in [1, 2, 7, 31, 1024, 16384] {
        let prefix = "x".repeat(16380);
        let suffix = "y".repeat(16000);
        let input = format!("{prefix}{secret}{suffix}");
        let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
        let mut output = Vec::new();
        for chunk in input.as_bytes().chunks(chunk_size) {
            output.extend(stream.push(chunk).unwrap());
        }
        assert!(
            output.len() > 30000,
            "nonsecret output must not wait until EOF"
        );
        output.extend(stream.finish().unwrap());
        assert_eq!(decode(output), format!("{prefix}[REDACTED]{suffix}"));
    }
}

#[test]
fn debug_and_invalid_utf8_do_not_expose_known_secrets() {
    let secret = "fixture-debug-secret".to_owned();
    let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
    assert!(!format!("{stream:?}").contains(&secret));
    let mut input = vec![0xff];
    input.extend_from_slice(secret.as_bytes());
    input.push(0xfe);
    let mut output = stream.push(&input).unwrap();
    output.extend(stream.finish().unwrap());
    assert_eq!(output, b"\xff[REDACTED]\xfe");
}

#[test]
fn abort_marks_incomplete_even_when_no_raw_tail_is_pending() {
    for (keys, input) in [
        (vec![], b"normal".as_slice()),
        (vec!["abc".to_owned()], b"".as_slice()),
        (vec!["abc".to_owned()], b"%61%62%63%61%62%63".as_slice()),
    ] {
        let mut stream = StreamingRedactor::new(&keys).unwrap();
        let _ = stream.push(input).unwrap();
        let aborted = stream.abort();
        assert!(stream.redaction_incomplete());
        assert!(!aborted.windows(3).any(|part| part == b"abc"));
        assert!(stream.push(b"later").is_err());
        assert!(stream.finish().unwrap().is_empty());
    }
    let mut complete = StreamingRedactor::new(&[]).unwrap();
    complete.finish().unwrap();
    complete.abort();
    assert!(!complete.redaction_incomplete());
}

#[test]
fn escaping_forms_are_masked_before_eof_and_secret_quotas_fail_closed() {
    let secret = "fixture/quote\"back\\line\n-key".to_owned();
    let json = serde_json::to_string(&secret).unwrap();
    let escaped = json[1..json.len() - 1].to_owned();
    let upper: String = secret.bytes().map(|byte| format!("%{byte:02X}")).collect();
    let lower: String = secret.bytes().map(|byte| format!("%{byte:02x}")).collect();
    for form in [escaped.clone(), escaped.replace('/', r"\/"), upper, lower] {
        let mut stream = StreamingRedactor::new(std::slice::from_ref(&secret)).unwrap();
        let mut output = Vec::new();
        for chunk in form.as_bytes().chunks(2) {
            output.extend(stream.push(chunk).unwrap());
        }
        output.extend(stream.push(&vec![b'x'; 4096]).unwrap());
        assert!(output.starts_with(b"[REDACTED]"), "mask must precede EOF");
        output.extend(stream.finish().unwrap());
        assert_eq!(decode(output), format!("[REDACTED]{}", "x".repeat(4096)));
    }
    let keys: Vec<String> = (0..128).map(|n| format!("fixture-key-{n:03}")).collect();
    assert!(StreamingRedactor::new(&keys).is_ok());
    let mut too_many = keys;
    too_many.push("one-too-many".into());
    assert!(StreamingRedactor::new(&too_many).is_err());
    let large: Vec<String> = (0..128)
        .map(|n| format!("{}{n:03}", "z".repeat(8189)))
        .collect();
    assert!(StreamingRedactor::new(&large).is_err());
}

#[test]
fn tiny_chunks_with_a_long_secret_remain_bounded_and_lossless() {
    let key = format!("{}b", "a".repeat(8191));
    let started = std::time::Instant::now();
    let mut stream = StreamingRedactor::new(&[key]).unwrap();
    let constructed = started.elapsed();
    let mut output = Vec::new();
    for _ in 0..500_000 {
        output.extend(stream.push(b"a").unwrap());
    }
    assert!(output.len() > 400_000);
    output.extend(stream.finish().unwrap());
    assert_eq!(output, vec![b'a'; 500_000]);
    eprintln!(
        "long-key redaction: construction={constructed:?}, total={:?}",
        started.elapsed()
    );
}

#[test]
fn safe_text_is_visible_before_eof_even_with_a_long_credential() {
    let mut stream = StreamingRedactor::new(&["k".repeat(8192)]).unwrap();
    let text = b"visible safe output\n";
    assert_eq!(stream.push(text).unwrap(), text);
    assert!(stream.finish().unwrap().is_empty());
}

#[test]
fn disproved_secret_prefix_is_released_in_the_same_push() {
    let mut stream = StreamingRedactor::new(&["secret-long-key".into()]).unwrap();
    assert_eq!(stream.push(b"safe ").unwrap(), b"safe ");
    assert!(stream.push(b"secr").unwrap().is_empty());
    assert_eq!(stream.push(b"x\n").unwrap(), b"secrx\n");
    assert!(stream.finish().unwrap().is_empty());
}

#[test]
fn markdown_code_line_does_not_wait_for_a_later_sse_chunk() {
    let mut stream = StreamingRedactor::new(&["md-fixture-secret-key-42".into()]).unwrap();
    let text = b"```bash\npython3 /tmp/saper/saper.py\n```\n";
    let mut output = Vec::new();
    for chunk in text.chunks(3) {
        output.extend(stream.push(chunk).unwrap());
    }
    assert_eq!(output, text);
    assert!(stream.finish().unwrap().is_empty());
}

#[test]
fn large_dictionaries_fail_closed_before_oversized_prefix_tables_are_built() {
    // Four valid maximum-length keys stay below the encoded-form limit, but
    // exceed the separate 8 MiB prefix-table construction budget.
    let keys: Vec<String> = (0..4)
        .map(|index| format!("{index:03}{}", "0".repeat(8189)))
        .collect();
    let result = StreamingRedactor::new(&keys);
    assert!(
        result.is_err(),
        "constructor must reject excessive compiled metadata"
    );
}
