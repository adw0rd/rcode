//! GigaChat's extra trust anchor is cached locally, never installed into the OS.
use crate::config::{self, ConfigStore, ProviderKind, ProviderSettings};
use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use reqwest::{Certificate, Url};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::Read, path::Path, time::Duration};

const SOURCE: &str = "https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt";
// Official PEM verified 2026-10-24; certificate expires 2032-02-27.
const PEM_SHA256: &str = "936a43fea6e8e525bcc0f81acd9c3d21b4fc4b9b68acea7906d698005afc6504";
const MAX_PEM: usize = 64 * 1024;
const CACHE_NAME: &str = "gigachat-root-936a43fea6e8.pem";
static DOWNLOAD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) fn official_gigachat_url(url: &Url) -> bool {
    url.scheme() == "https"
        && matches!(
            url.host_str(),
            Some("api.giga.chat" | "gigachat.devices.sberbank.ru" | "ngw.devices.sberbank.ru")
        )
}

pub(crate) fn automatic_gigachat_ca(
    settings: &ProviderSettings,
    base: &Url,
    auth: Option<&Url>,
) -> bool {
    settings.kind == ProviderKind::GigaChat
        && settings.ca_file.is_none()
        && (official_gigachat_url(base) || auth.is_some_and(official_gigachat_url))
}

pub(crate) async fn gigachat_root() -> Result<Certificate> {
    // Cloned subagent clients share the first download in this process.
    let _download = DOWNLOAD.lock().await;
    let store = ConfigStore::new()?;
    let pem = cached_root(store.root(), SOURCE, PEM_SHA256).await?;
    Certificate::from_pem(&pem).context("Некорректный сертификат GigaChat")
}

fn verified(pem: &[u8], expected: &str) -> bool {
    pem.len() <= MAX_PEM
        && format!("{:x}", Sha256::digest(pem)) == expected
        && Certificate::from_pem(pem).is_ok()
}

async fn cached_root(root: &Path, source: &str, expected: &str) -> Result<Vec<u8>> {
    let directory = root.join("certificates");
    config::ensure_private_directory(&directory)?;
    let path = directory.join(CACHE_NAME);
    if config::check_file(&path)? {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let mut pem = Vec::new();
        options
            .open(&path)
            .context("Не удалось прочитать кэш сертификата")?
            .take((MAX_PEM + 1) as u64)
            .read_to_end(&mut pem)?;
        if verified(&pem, expected) {
            return Ok(pem);
        }
    }

    // A separate client carries no provider key, OAuth token or custom trust.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(12))
        .user_agent(concat!("rcode/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("Не удалось создать загрузчик сертификата")?;
    let response =
        client.get(source).send().await.map_err(|_| {
            anyhow::anyhow!("Не удалось скачать официальный CA-сертификат GigaChat")
        })?;
    if !response.status().is_success() {
        bail!(
            "Сервер сертификатов вернул HTTP {}",
            response.status().as_u16()
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PEM as u64)
    {
        bail!("Файл сертификата превышает допустимый размер");
    }
    let mut pem = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| anyhow::anyhow!("Загрузка сертификата прервана"))?;
        if pem.len().saturating_add(chunk.len()) > MAX_PEM {
            bail!("Файл сертификата превышает допустимый размер");
        }
        pem.extend_from_slice(&chunk);
    }
    if !verified(&pem, expected) {
        bail!("Официальный CA-сертификат GigaChat не прошёл проверку SHA-256");
    }
    config::write_private_bytes(&path, &pem)?;
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const PEM: &[u8] = include_bytes!("../tests/fixtures/russian-trusted-root-ca.pem");

    async fn server(
        status: &str,
        body: Vec<u8>,
        headers: &str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
            body.len()
        );
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(3), async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut buf = [0; 1024];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() < 16 * 1024);
                }
                socket.write_all(response.as_bytes()).await.unwrap();
                let _ = socket.write_all(&body).await;
                String::from_utf8(request).unwrap()
            })
            .await
            .expect("certificate fixture timed out")
        });
        (url, task)
    }

    #[tokio::test]
    async fn pinned_download_is_cached_and_works_without_network_on_next_use() {
        let root = tempfile::tempdir().unwrap();
        let (url, request) = server("200 OK", PEM.to_vec(), "").await;
        assert_eq!(
            cached_root(root.path(), &url, PEM_SHA256).await.unwrap(),
            PEM
        );
        let request = request.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get / http/1.1"));
        assert!(!request.contains("authorization:") && !request.contains("cookie:"));
        let path = root.path().join("certificates").join(CACHE_NAME);
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        // The fixture has closed its listener. No second network request can succeed.
        assert_eq!(
            cached_root(root.path(), &url, PEM_SHA256).await.unwrap(),
            PEM
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn tampered_download_never_replaces_an_existing_cache() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("certificates");
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join(CACHE_NAME);
        std::fs::write(&path, b"damaged previous cache").unwrap();
        let mut tampered = PEM.to_vec();
        tampered.push(b'\n');
        let (url, request) = server("200 OK", tampered, "").await;
        let error = cached_root(root.path(), &url, PEM_SHA256)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("SHA-256"));
        assert_eq!(std::fs::read(path).unwrap(), b"damaged previous cache");
        request.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_responses_and_redirects_are_rejected() {
        for (status, body, headers, expected) in [
            ("200 OK", vec![b'x'; MAX_PEM + 1], "", "размер"),
            (
                "302 Found",
                vec![],
                "Location: http://127.0.0.1:9/\r\n",
                "HTTP 302",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let (url, request) = server(status, body, headers).await;
            assert!(
                cached_root(root.path(), &url, PEM_SHA256)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains(expected)
            );
            assert!(!root.path().join("certificates").join(CACHE_NAME).exists());
            request.await.unwrap();
        }
    }

    #[tokio::test]
    async fn concurrent_downloads_leave_one_complete_verified_cache() {
        let root = tempfile::tempdir().unwrap();
        let (a, ra) = server("200 OK", PEM.to_vec(), "").await;
        let (b, rb) = server("200 OK", PEM.to_vec(), "").await;
        let (a, b) = tokio::join!(
            cached_root(root.path(), &a, PEM_SHA256),
            cached_root(root.path(), &b, PEM_SHA256)
        );
        assert_eq!(a.unwrap(), PEM);
        assert_eq!(b.unwrap(), PEM);
        // Either request may have reused the first writer's cache.
        ra.abort();
        rb.abort();
        let _ = tokio::join!(ra, rb);
        assert_eq!(
            std::fs::read(root.path().join("certificates").join(CACHE_NAME)).unwrap(),
            PEM
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cache_file_and_directory_symlinks_are_refused() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("target.pem");
        std::fs::write(&target, PEM).unwrap();
        let directory = root.path().join("certificates");
        symlink(outside.path(), &directory).unwrap();
        assert!(
            cached_root(root.path(), "http://127.0.0.1:9/", PEM_SHA256)
                .await
                .is_err()
        );
        std::fs::remove_file(&directory).unwrap();
        std::fs::create_dir(&directory).unwrap();
        symlink(&target, directory.join(CACHE_NAME)).unwrap();
        assert!(
            cached_root(root.path(), "http://127.0.0.1:9/", PEM_SHA256)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(target).unwrap(), PEM);
    }

    #[test]
    fn automatic_trust_is_limited_to_official_gigachat_and_respects_override() {
        let url = Url::parse("https://api.giga.chat/v1").unwrap();
        let local = Url::parse("http://127.0.0.1:8080").unwrap();
        let mut settings = ProviderSettings::new(ProviderKind::GigaChat);
        assert!(automatic_gigachat_ca(&settings, &url, None));
        assert!(automatic_gigachat_ca(&settings, &local, Some(&url)));
        assert!(!automatic_gigachat_ca(&settings, &local, Some(&local)));
        for invalid in [
            "http://api.giga.chat",
            "https://api.giga.chat.evil.example",
            "https://example.org",
            "https://api.giga.chat@evil.example",
        ] {
            assert!(!official_gigachat_url(&Url::parse(invalid).unwrap()));
        }
        settings.ca_file = Some("custom.pem".into());
        assert!(!automatic_gigachat_ca(&settings, &url, None));
        settings.ca_file = None;
        for kind in [
            ProviderKind::Yandex,
            ProviderKind::OpenRouter,
            ProviderKind::Custom,
        ] {
            settings.kind = kind;
            assert!(!automatic_gigachat_ca(&settings, &url, None));
        }
    }
}
