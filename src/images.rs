//! Явно приложенные пользователем картинки. Исходный путь нужен только при вводе;
//! дальше используются проверенные снимки байтов в каталоге сессии.
use crate::{config, protocol::Message};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Cursor, Read, Write},
    path::Path,
    sync::Arc,
};

pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_TIFF_SOURCE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_IMAGES: usize = 10;
// Резерв локального бюджета, а не оценка оплаченных API-токенов.
pub const IMAGE_CONTEXT_CHARS: usize = 8192;
const MAX_DECODED_PIXELS: u64 = 16_000_000;

fn is_tiff(data: &[u8]) -> bool {
    [b"II*\0", b"MM\0*", b"II+\0", b"MM\0+"]
        .iter()
        .any(|header| data.starts_with(*header))
}

struct PngBytes(Vec<u8>);
impl Write for PngBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > MAX_IMAGE_BYTES {
            return Err(io::Error::other(
                "PNG после преобразования превышает 10 МиБ",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Нормализуем TIFF при явном вводе пользователя. В сессии и API остаются
/// одинаковые PNG-байты, независимо от исходника и выбранного провайдера.
fn normalize_tiff(data: Vec<u8>) -> Result<Vec<u8>> {
    use image::{ImageDecoder, ImageEncoder};
    let mut reader = image::ImageReader::with_format(Cursor::new(data), image::ImageFormat::Tiff);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let decoder = reader
        .into_decoder()
        .context("Не удалось прочитать TIFF: файл повреждён или превышает ограничения размера")?;
    let (width, height) = decoder.dimensions();
    if u64::from(width) * u64::from(height) > MAX_DECODED_PIXELS {
        bail!("Слишком большое TIFF-изображение: максимум 16 миллионов пикселей");
    }
    let pixels = image::DynamicImage::from_decoder(decoder)
        .context("Не удалось прочитать TIFF: файл повреждён или превышает ограничения памяти")?
        .into_rgba8();
    let mut png = PngBytes(Vec::new());
    image::codecs::png::PngEncoder::new(&mut png)
        .write_image(&pixels, width, height, image::ColorType::Rgba8.into())
        .context(
            "Не удалось преобразовать TIFF в PNG; итоговый файл должен быть не больше 10 МиБ",
        )?;
    Ok(png.0)
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ImageAttachment {
    pub name: String,
    pub mime_type: String,
    pub sha256: String,
    pub bytes: usize,
    #[serde(skip)]
    pub data: Arc<Vec<u8>>,
}

impl std::fmt::Debug for ImageAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageAttachment")
            .field("name", &self.name)
            .field("mime_type", &self.mime_type)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

fn mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else {
        None
    }
}

fn read_image(path: &Path, source: bool) -> Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .context("Не удалось прочитать изображение")?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("Изображение должно быть обычным PNG/JPEG/TIFF-файлом");
    }
    let mut data = Vec::new();
    Read::by_ref(&mut file).take(8).read_to_end(&mut data)?;
    let tiff_source = source && is_tiff(&data);
    let limit = if tiff_source {
        MAX_TIFF_SOURCE_BYTES
    } else {
        MAX_IMAGE_BYTES
    };
    if meta.len() > limit as u64 {
        bail!("Слишком большой файл изображения: PNG/JPEG до 10 МиБ, исходный TIFF до 64 МиБ");
    }
    file.take((limit - data.len()) as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > limit || (mime(&data).is_none() && !tiff_source) {
        bail!(
            "Неподдерживаемое или слишком большое изображение: нужны PNG/JPEG до 10 МиБ или TIFF до 64 МиБ"
        );
    }
    Ok(data)
}

impl ImageAttachment {
    fn read(path: &Path) -> Result<Self> {
        let data = read_image(path, true)?;
        let data = if is_tiff(&data) {
            normalize_tiff(data)?
        } else {
            data
        };
        Ok(Self {
            name: path
                .file_name()
                .context("Нет имени изображения")?
                .to_string_lossy()
                .into_owned(),
            mime_type: mime(&data).unwrap().into(),
            sha256: format!("{:x}", Sha256::digest(&data)),
            bytes: data.len(),
            data: Arc::new(data),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.data.len() != self.bytes
            || self.bytes > MAX_IMAGE_BYTES
            || mime(&self.data) != Some(self.mime_type.as_str())
            || format!("{:x}", Sha256::digest(&*self.data)) != self.sha256
        {
            bail!("Сохранённое изображение повреждено; приложите его заново");
        }
        Ok(())
    }

    pub fn label(&self) -> String {
        format!(
            "Изображение: {} · {:.1} КиБ",
            self.name,
            self.bytes as f64 / 1024.0
        )
    }
}

fn image_path(text: &str) -> bool {
    let extension = Path::new(text)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "png" | "jpg" | "jpeg" | "tif" | "tiff" | "bmp" | "webp" | "gif" | "heic" | "heif" | "avif"
    ) && !text.contains("://")
}

/// Сохраняет исходные кавычки/пробелы обычного текста. Декодирует только пути
/// в кавычках и экранирование пробелов, которые терминалы вставляют при drop.
fn tokens(text: &str) -> Vec<(std::ops::Range<usize>, String)> {
    let mut result = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((start, first)) = chars.next() {
        if first.is_whitespace() {
            continue;
        }
        let quote = matches!(first, '\'' | '"').then_some(first);
        let mut value = String::new();
        if quote.is_none() {
            value.push(first);
        }
        let mut end = start + first.len_utf8();
        while let Some(&(index, ch)) = chars.peek() {
            if quote.is_none() && ch.is_whitespace() {
                break;
            }
            chars.next();
            end = index + ch.len_utf8();
            if quote == Some(ch) {
                break;
            }
            if ch == '\\'
                && quote != Some('\'')
                && chars
                    .peek()
                    .is_some_and(|(_, c)| c.is_whitespace() || matches!(c, '\\' | '"' | '\''))
            {
                let (index, escaped) = chars.next().unwrap();
                value.push(escaped);
                end = index + escaped.len_utf8();
            } else {
                value.push(ch);
            }
        }
        result.push((start..end, value));
    }
    result
}

/// Вызывается только на пользовательском вводе, никогда на ответе модели или tool output.
pub fn user_message(input: &str, root: &Path) -> Result<Message> {
    let explicit = input
        .strip_prefix("/attach")
        .filter(|tail| tail.is_empty() || tail.starts_with(char::is_whitespace));
    let text = explicit.unwrap_or(input).trim();
    let mut selected = Vec::new();
    // Путь целиком без кавычек, с пробелами: типичная вставка скриншота на macOS.
    if image_path(text)
        && (Path::new(text).is_absolute() || root.join(text).is_file())
        && !text.starts_with(['\'', '"'])
    {
        let path = Path::new(text);
        if path.is_absolute() && (!path.exists() && text.contains(char::is_whitespace)) {
            // Возможно, это подпись с путём; ниже разберём отдельные токены.
        } else {
            selected.push((0..text.len(), text.to_owned()));
        }
    }
    if selected.is_empty() {
        selected = tokens(text)
            .into_iter()
            .filter(|(_, token)| {
                image_path(token)
                    && (explicit.is_some()
                        || Path::new(token).is_absolute()
                        || ["./", "../", "~/"]
                            .iter()
                            .any(|prefix| token.starts_with(prefix))
                        || root.join(token).is_file())
            })
            .collect();
    }
    if selected.len() > MAX_IMAGES {
        bail!("За один запрос можно приложить до 10 изображений");
    }
    if explicit.is_some() && selected.is_empty() {
        bail!("/attach \"путь.png\" [текст запроса] — приложить PNG/JPEG/TIFF");
    }
    let mut message = Message::user(text);
    if selected.is_empty() {
        return Ok(message);
    }
    let mut caption = String::new();
    let mut end = 0;
    for (span, filename) in selected {
        caption.push_str(&text[end..span.start]);
        end = span.end;
        let path = if let Some(tail) = filename.strip_prefix("~/") {
            directories::BaseDirs::new()
                .context("Не найден домашний каталог")?
                .home_dir()
                .join(tail)
        } else {
            root.join(&filename)
        };
        message.images.push(ImageAttachment::read(&path)?);
    }
    caption.push_str(&text[end..]);
    message.content = Some(if caption.trim().is_empty() {
        "Посмотри на приложенное изображение и помоги разобраться с его содержимым.".into()
    } else {
        caption.trim().to_owned()
    });
    Ok(message)
}

/// Check the complete request before appending it or writing any snapshots.
/// Checked sums also bound untrusted metadata before attachment validation.
pub(crate) fn validate_limits<'a>(
    images: impl IntoIterator<Item = &'a ImageAttachment>,
) -> Result<()> {
    let mut count = 0usize;
    let mut bytes = 0usize;
    for image in images {
        count = count.checked_add(1).context("Слишком много изображений")?;
        if count > MAX_IMAGES {
            bail!(
                "В контексте запроса может быть до {MAX_IMAGES} изображений; выполните /compact или /new перед добавлением нового вложения"
            );
        }
        bytes = bytes
            .checked_add(image.bytes)
            .context("Слишком большой объём изображений в сессии")?;
        if bytes > MAX_IMAGES * MAX_IMAGE_BYTES {
            bail!("Слишком большой объём изображений в сессии");
        }
    }
    Ok(())
}

pub fn save(messages: &[Message], session_dir: &Path) -> Result<()> {
    validate_limits(messages.iter().flat_map(|message| &message.images))?;
    let dir = session_dir.join("images");
    for image in messages.iter().flat_map(|m| &m.images) {
        image.validate()?;
        config::ensure_private_directory(&dir)?;
        let path = dir.join(&image.sha256);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {}
            Ok(_) => bail!("Небезопасный файл сохранённого изображения"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                config::write_private_bytes(&path, &image.data)?
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn restore(messages: &mut [Message], session_dir: &Path) -> Result<()> {
    let dir = session_dir.join("images");
    let mut total = 0usize;
    for image in messages.iter_mut().flat_map(|m| &mut m.images) {
        if image.sha256.len() != 64 || !image.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("Некорректный идентификатор сохранённого изображения");
        }
        total = total
            .checked_add(image.bytes)
            .context("Слишком большой объём изображений в сессии")?;
        if total > MAX_IMAGES * MAX_IMAGE_BYTES {
            bail!("Слишком большой объём изображений в сессии");
        }
        config::ensure_private_directory(&dir)?;
        image.data = Arc::new(read_image(&dir.join(&image.sha256), false)?);
        image.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfixture";

    #[test]
    fn save_rejects_too_many_images_before_creating_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("screen.png"), PNG).unwrap();
        let message = user_message("screen.png", tmp.path()).unwrap();
        let session_dir = tmp.path().join("saved-session");
        let messages = vec![message; MAX_IMAGES + 1];
        let error = save(&messages, &session_dir).unwrap_err();
        assert!(error.to_string().contains("10 изображений"));
        assert!(!session_dir.exists());
    }

    #[test]
    fn save_rejects_aggregate_byte_limit_and_overflow_before_creating_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("screen.png"), PNG).unwrap();
        let message = user_message("screen.png", tmp.path()).unwrap();
        let session_dir = tmp.path().join("saved-session");
        for bytes in [MAX_IMAGES * MAX_IMAGE_BYTES, usize::MAX] {
            let mut excessive = message.clone();
            excessive.images[0].bytes = bytes;
            let error = save(&[message.clone(), excessive], &session_dir).unwrap_err();
            assert!(error.to_string().contains("объём изображений"));
            assert!(!session_dir.exists());
        }
    }

    fn tiff(width: u32, height: u32) -> Vec<u8> {
        let tags: [(u16, u16, u32, u32); 10] = [
            (256, 4, 1, width),
            (257, 4, 1, height),
            (258, 3, 3, 134),
            (259, 3, 1, 1),
            (262, 3, 1, 2),
            (273, 4, 1, 140),
            (277, 3, 1, 3),
            (278, 4, 1, height),
            (279, 4, 1, width * height * 3),
            (284, 3, 1, 1),
        ];
        let mut data = b"II*\0\x08\0\0\0\x0a\0".to_vec();
        for (tag, kind, count, value) in tags {
            data.extend(tag.to_le_bytes());
            data.extend(kind.to_le_bytes());
            data.extend(count.to_le_bytes());
            data.extend(value.to_le_bytes());
        }
        data.extend(b"\0\0\0\0\x08\0\x08\0\x08\0\xff\0\0");
        data
    }

    #[test]
    fn pasted_macos_tiff_with_caption_is_normalized_to_png_with_the_same_pixels() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("2026-10-26_00-57-54.tiff");
        let original = tiff(1, 1);
        fs::write(&path, &original).unwrap();
        let message = user_message(
            &format!("{} что тут нарисовано?", path.display()),
            tmp.path(),
        )
        .unwrap();
        assert_eq!(
            message.images.len(),
            1,
            "TIFF must be an attachment, not plain model text"
        );
        assert_eq!(message.content.as_deref(), Some("что тут нарисовано?"));
        let image = &message.images[0];
        assert_eq!(image.mime_type, "image/png");
        image.validate().unwrap();
        assert_eq!(image.name, "2026-10-26_00-57-54.tiff");
        let decoded = image::load_from_memory_with_format(&image.data, image::ImageFormat::Png)
            .unwrap()
            .into_rgba8();
        assert_eq!(decoded.get_pixel(0, 0).0, [255, 0, 0, 255]);
        assert_eq!(fs::read(path).unwrap(), original);
    }

    #[test]
    fn big_endian_tiff_from_macos_is_normalized_without_losing_pixels() {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD.decode("TU0AKgAAAAgACgEAAAQAAAABAAAAAQEBAAQAAAABAAAAAQECAAMAAAADAAAAhgEDAAMAAAABAAEAAAEGAAMAAAABAAIAAAERAAQAAAABAAAAjAEVAAMAAAABAAMAAAEWAAQAAAABAAAAAQEXAAQAAAABAAAAAwEcAAMAAAABAAEAAAAAAAAACAAIAAj/AAA=").unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clipboard.tif");
        fs::write(&path, bytes).unwrap();
        let message = user_message(path.to_str().unwrap(), tmp.path()).unwrap();
        assert_eq!(message.images.len(), 1);
        let image = &message.images[0];
        assert_eq!(image.mime_type, "image/png");
        let decoded = image::load_from_memory_with_format(&image.data, image::ImageFormat::Png)
            .unwrap()
            .into_rgba8();
        assert_eq!(decoded.get_pixel(0, 0).0, [255, 0, 0, 255]);
    }

    #[test]
    fn unsupported_and_corrupt_images_do_not_silently_become_model_text() {
        let tmp = tempfile::tempdir().unwrap();
        for (name, data) in [
            ("unsupported.heic", &b"not an image"[..]),
            ("broken.tiff", &b"II*\0bad"[..]),
        ] {
            let path = tmp.path().join(name);
            fs::write(&path, data).unwrap();
            assert!(
                user_message(
                    &format!("{} что тут нарисовано?", path.display()),
                    tmp.path()
                )
                .is_err()
            );
        }
        let path = tmp.path().join("enormous.tif");
        fs::write(&path, tiff(40_000, 1)).unwrap();
        assert!(user_message(path.to_str().unwrap(), tmp.path()).is_err());
    }

    #[test]
    fn uncompressed_tiff_can_exceed_the_png_limit_but_the_saved_png_stays_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("large-source.tiff");
        let mut original = tiff(1, 1);
        original.resize(MAX_IMAGE_BYTES + 1, 0);
        fs::write(&path, original).unwrap();
        let message = user_message(path.to_str().unwrap(), tmp.path()).unwrap();
        assert_eq!(message.images.len(), 1);
        assert!(message.images[0].bytes < MAX_IMAGE_BYTES);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(&tiff(1, 1)).unwrap();
        file.set_len(64 * 1024 * 1024 + 1).unwrap();
        assert!(user_message(path.to_str().unwrap(), tmp.path()).is_err());
    }

    #[test]
    fn absolute_paste_with_spaces_survives_source_removal_and_detects_snapshot_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("скрин с пробелом.png");
        fs::write(&path, PNG).unwrap();
        let message = user_message(path.to_str().unwrap(), tmp.path()).unwrap();
        assert_eq!(message.images.len(), 1);
        let dir = tmp.path().join("session");
        save(std::slice::from_ref(&message), &dir).unwrap();
        let json = serde_json::to_string(&message).unwrap();
        assert!(!json.contains("fixture") && !json.contains("data"));
        fs::remove_file(path).unwrap();
        let mut restored = vec![serde_json::from_str::<Message>(&json).unwrap()];
        restore(&mut restored, &dir).unwrap();
        assert_eq!(&**restored[0].images[0].data, PNG);
        fs::write(dir.join("images").join(&message.images[0].sha256), b"bad").unwrap();
        assert!(restore(&mut restored, &dir).is_err());
        restored[0].images[0].sha256 = "../secret".into();
        assert!(restore(&mut restored, &dir).is_err());
    }

    #[test]
    fn caption_quotes_and_escaped_paths_are_preserved_without_interpreting_prose_or_urls() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("мой скрин.png"), PNG).unwrap();
        for input in [
            "/attach 'мой скрин.png' Что значит **ошибка**?",
            "Что значит **ошибка**? мой\\ скрин.png",
        ] {
            let message = user_message(input, tmp.path()).unwrap();
            assert_eq!(message.content.as_deref(), Some("Что значит **ошибка**?"));
            assert_eq!(message.images.len(), 1);
        }
        for input in [
            "Не найден example.png",
            "https://example.org/image.png",
            "Обычный 'текст' без картинки",
        ] {
            let message = user_message(input, tmp.path()).unwrap();
            assert_eq!(message.content.as_deref(), Some(input));
            assert!(message.images.is_empty());
        }
        let legacy: Message = serde_json::from_str(r#"{"role":"user","content":"old"}"#).unwrap();
        assert!(legacy.images.is_empty());
    }

    #[test]
    fn invalid_oversized_and_non_regular_images_are_rejected_before_network_io() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("bad.png");
        fs::write(&bad, b"API-key-is-text-not-an-image").unwrap();
        assert!(user_message("/attach bad.png", tmp.path()).is_err());
        let file = fs::File::create(&bad).unwrap();
        file.set_len(MAX_IMAGE_BYTES as u64 + 1).unwrap();
        assert!(user_message("/attach bad.png", tmp.path()).is_err());
        fs::create_dir(tmp.path().join("dir.png")).unwrap();
        assert!(user_message("/attach dir.png", tmp.path()).is_err());
        assert!(user_message("/attach missing.png", tmp.path()).is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&bad, tmp.path().join("link.png")).unwrap();
            assert!(user_message("/attach link.png", tmp.path()).is_err());
            let path =
                std::ffi::CString::new(tmp.path().join("pipe.png").to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            assert!(user_message("/attach pipe.png", tmp.path()).is_err());
        }
    }

    #[test]
    fn compaction_reserves_image_budget_and_preserves_the_current_image_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("screen.png");
        fs::write(&path, PNG).unwrap();
        let message = user_message(path.to_str().unwrap(), tmp.path()).unwrap();
        let mut session = crate::state::Session::new(
            tmp.path(),
            crate::config::ProviderSettings::new(crate::config::ProviderKind::Custom),
        )
        .unwrap();
        let mut old = message.clone();
        old.images = vec![message.images[0].clone(); 3];
        session.messages.push(old);
        assert!(session.context_chars() >= IMAGE_CONTEXT_CHARS);
        session
            .messages
            .push(Message::text("assistant", "old answer ".repeat(20_000)));
        session.messages.push(message);
        assert!(session.auto_compact(0).unwrap() > 0);
        assert_eq!(&**session.messages.last().unwrap().images[0].data, PNG);
        assert!(session.compact().unwrap() > 0);
        assert_eq!(session.messages.iter().flat_map(|m| &m.images).count(), 1);
        assert_eq!(&**session.messages.last().unwrap().images[0].data, PNG);
        assert!(
            session.messages[0]
                .content
                .as_deref()
                .unwrap()
                .contains("визуального содержимого")
        );
    }
}
