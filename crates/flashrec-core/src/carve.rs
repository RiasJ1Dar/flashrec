//! Carving за сигнатурами — останній засіб, коли метаданих файлової системи
//! не лишилось.
//!
//! Carving знаходить *вміст* файлів за їхніми магічними байтами. Він не
//! повертає ні імен, ні тек, ні міток часу, і відновлює лише ті файли, чиї дані
//! випадково лежать неперервно, — тому пропонується після сканування MFT, а не
//! замість нього.

use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::device::human_bytes;
use crate::reader::BlockDevice;

/// Як упізнати один тип файлу.
pub struct Signature {
    pub extension: &'static str,
    pub magic: &'static [u8],
    /// Байти, що позначають кінець; `None` означає «брати `max_size`».
    pub footer: Option<&'static [u8]>,
    /// Чи включати сам кінцевий маркер у результат.
    pub footer_inclusive: bool,
    pub max_size: u64,
}

/// Формати, які flashrec уміє вирізати.
pub const SIGNATURES: &[Signature] = &[
    Signature {
        extension: "jpg",
        magic: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        footer_inclusive: true,
        max_size: 64 << 20,
    },
    Signature {
        extension: "png",
        magic: &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(b"IEND\xAE\x42\x60\x82"),
        footer_inclusive: true,
        max_size: 128 << 20,
    },
    Signature {
        extension: "gif",
        magic: b"GIF89a",
        footer: Some(&[0x00, 0x3B]),
        footer_inclusive: true,
        max_size: 32 << 20,
    },
    Signature {
        extension: "pdf",
        magic: b"%PDF-",
        footer: Some(b"%%EOF"),
        footer_inclusive: true,
        max_size: 256 << 20,
    },
    // Охоплює і .zip, і .docx/.xlsx/.pptx, які є zip-контейнерами.
    Signature {
        extension: "zip",
        magic: &[0x50, 0x4B, 0x03, 0x04],
        footer: None,
        footer_inclusive: false,
        max_size: 512 << 20,
    },
    Signature {
        extension: "rar",
        magic: b"Rar!\x1A\x07",
        footer: None,
        footer_inclusive: false,
        max_size: 512 << 20,
    },
    Signature {
        extension: "7z",
        magic: &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
        footer: None,
        footer_inclusive: false,
        max_size: 512 << 20,
    },
    // Старі двійкові формати Office та інші складені документи OLE (.doc/.xls/.ppt).
    Signature {
        extension: "ole",
        magic: &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        footer: None,
        footer_inclusive: false,
        max_size: 256 << 20,
    },
    Signature {
        extension: "mp3",
        magic: b"ID3",
        footer: None,
        footer_inclusive: false,
        max_size: 64 << 20,
    },
    Signature {
        extension: "sqlite",
        magic: b"SQLite format 3\0",
        footer: None,
        footer_inclusive: false,
        max_size: 256 << 20,
    },
];

/// MP4/MOV знаходяться за блоком `ftyp`, що стоїть через чотири байти від початку.
const FTYP_OFFSET: usize = 4;
const FTYP_MAGIC: &[u8] = b"ftyp";
const FTYP_MAX_SIZE: u64 = 2 << 30;

/// Один вирізаний файл.
#[derive(Debug, Clone)]
pub struct CarvedFile {
    pub offset: u64,
    pub len: u64,
    pub extension: String,
    pub path: PathBuf,
    /// Істина, коли кінцевого маркера не знайдено й узято `max_size`.
    pub length_is_a_guess: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CarveProgress {
    pub offset: u64,
    pub total: u64,
    pub found: u64,
}

#[derive(Debug, Clone, Default)]
pub struct CarveReport {
    pub files: Vec<CarvedFile>,
    pub bytes_written: u64,
    pub read_errors: u64,
    pub cancelled: bool,
}

impl CarveReport {
    pub fn summary(&self) -> String {
        let guessed = self.files.iter().filter(|f| f.length_is_a_guess).count();
        let mut s = format!(
            "вирізано файлів: {}, {}",
            self.files.len(),
            human_bytes(self.bytes_written)
        );
        if guessed > 0 {
            s.push_str(&format!(
                " — у {guessed} з них довжину ВГАДАНО (кінцевого маркера немає; у кінці може бути сміття)"
            ));
        }
        if self.read_errors > 0 {
            s.push_str(&format!(
                " — під час перебору пропущено помилок читання: {}",
                self.read_errors
            ));
        }
        if self.cancelled {
            s.push_str(" — ЗУПИНЕНО до кінця");
        }
        s
    }
}

/// Перебрати `dev` у пошуках відомих сигнатур і записати знайдене в `dest`.
pub fn carve<D: BlockDevice>(
    dev: &mut D,
    dest: impl AsRef<Path>,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(CarveProgress),
) -> io::Result<CarveReport> {
    const WINDOW: usize = 4 << 20;
    const OVERLAP: usize = 64;

    let dest = dest.as_ref();
    fs::create_dir_all(dest)?;

    let total = dev.len();
    let mut report = CarveReport::default();
    let mut buf = vec![0u8; WINDOW];
    let mut at = 0u64;
    let mut counter = 0u64;

    while at < total {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        let want = WINDOW.min((total - at) as usize);
        let window = &mut buf[..want];
        if dev.read_at(at, window).is_err() {
            report.read_errors += 1;
            at += want as u64;
            continue;
        }

        // Шукати всі сигнатури в цьому вікні, пропускаючи збіги, що починаються
        // в зоні перекриття, — щоб не знайти їх двічі.
        let scan_limit = if at + want as u64 >= total {
            want
        } else {
            want.saturating_sub(OVERLAP)
        };

        let mut i = 0usize;
        while i < scan_limit {
            let mut matched = None;

            for sig in SIGNATURES {
                if window[i..].starts_with(sig.magic) {
                    matched = Some((sig.extension, sig.footer, sig.footer_inclusive, sig.max_size));
                    break;
                }
            }
            // MP4/MOV: "ftyp" через чотири байти від початку блоку.
            if matched.is_none()
                && i + FTYP_OFFSET + FTYP_MAGIC.len() <= window.len()
                && &window[i + FTYP_OFFSET..i + FTYP_OFFSET + FTYP_MAGIC.len()] == FTYP_MAGIC
            {
                matched = Some(("mp4", None, false, FTYP_MAX_SIZE));
            }

            let Some((ext, footer, footer_inclusive, max_size)) = matched else {
                i += 1;
                continue;
            };

            let start = at + i as u64;
            let available = total - start;
            let cap = max_size.min(available);

            let (len, guessed) = match footer {
                Some(f) => match find_footer(dev, start, cap, f)? {
                    Some(end_at) => {
                        let len = end_at - start + if footer_inclusive { f.len() as u64 } else { 0 };
                        (len.min(cap), false)
                    }
                    None => (cap, true),
                },
                None => (cap, true),
            };

            counter += 1;
            let name = format!("{counter:06}_{}.{}", start, ext);
            let path = dest.join(&name);
            match write_range(dev, start, len, &path) {
                Ok(written) => {
                    report.bytes_written += written;
                    report.files.push(CarvedFile {
                        offset: start,
                        len: written,
                        extension: ext.to_string(),
                        path,
                        length_is_a_guess: guessed,
                    });
                }
                Err(_) => report.read_errors += 1,
            }

            // Іти далі за заголовок цього файлу: вкладені файли всередині архіву
            // не варті дублікатів у результаті.
            i += len.max(1).min(scan_limit as u64 - i as u64) as usize;
        }

        progress(CarveProgress {
            offset: at + want as u64,
            total,
            found: report.files.len() as u64,
        });

        // Крок із перекриттям, щоб упіймати сигнатуру на межі вікон.
        if at + want as u64 >= total {
            break;
        }
        at += (want - OVERLAP) as u64;
    }

    Ok(report)
}

/// Шукати `footer` у межах `cap` байтів від `start`.
fn find_footer<D: BlockDevice>(
    dev: &mut D,
    start: u64,
    cap: u64,
    footer: &[u8],
) -> io::Result<Option<u64>> {
    const CHUNK: usize = 1 << 20;
    let mut buf = vec![0u8; CHUNK + footer.len()];
    let mut at = 0u64;

    while at < cap {
        let want = (CHUNK as u64).min(cap - at) as usize + footer.len().min(1) * (footer.len() - 1);
        let want = want.min(buf.len()).min((cap - at) as usize);
        if want < footer.len() {
            break;
        }
        let slice = &mut buf[..want];
        if dev.read_at(start + at, slice).is_err() {
            return Ok(None);
        }
        if let Some(pos) = slice.windows(footer.len()).position(|w| w == footer) {
            return Ok(Some(start + at + pos as u64));
        }
        // Відступити на довжину маркера, щоб знайти й розірваний межею.
        at += (want - (footer.len() - 1)) as u64;
    }
    Ok(None)
}

fn write_range<D: BlockDevice>(
    dev: &mut D,
    start: u64,
    len: u64,
    path: &Path,
) -> io::Result<u64> {
    const CHUNK: usize = 1 << 20;
    let mut out = BufWriter::new(fs::File::create(path)?);
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;

    while done < len {
        let want = (CHUNK as u64).min(len - done) as usize;
        let slice = &mut buf[..want];
        if dev.read_at(start + done, slice).is_err() {
            break;
        }
        out.write_all(slice)?;
        done += want as u64;
    }
    out.flush()?;
    Ok(done)
}
