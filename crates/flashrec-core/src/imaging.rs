//! Копіювання диска, що відмовляє, в образ — разом зі збійними секторами.
//!
//! Правило, на якому тримається весь модуль: жодна помилка читання не
//! проходить мовчки. Нечитаний сектор пишеться нулями, щоб усі подальші зсуви
//! лишились правильними, але його також рахують, записують у супровідний файл
//! `.map` і повертають у звіті — щоб ніхто не прийняв дірку за дані.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::device::{human_bytes, RawDisk};

/// Як читати і наскільки наполегливо.
#[derive(Debug, Clone)]
pub struct ImagingOptions {
    /// Байтів за одне масове читання. Має бути кратним розміру сектора.
    pub block_size: usize,
    /// Додаткові спроби для блоку, що не прочитався, перш ніж перейти на
    /// посекторне читання.
    pub retries: u32,
    /// Продовжити перерване зняття, дописуючи наявний образ.
    pub resume: bool,
}

impl Default for ImagingOptions {
    fn default() -> Self {
        Self {
            block_size: 1 << 20, // 1 МіБ
            retries: 2,
            resume: false,
        }
    }
}

/// Неперервна смуга секторів, які так і не прочиталися.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadRange {
    pub offset: u64,
    pub len: u64,
}

/// Поточний поступ, що передається у зворотний виклик.
#[derive(Debug, Clone, Copy)]
pub struct ImagingProgress {
    pub offset: u64,
    pub total: u64,
    pub bad_bytes: u64,
    pub bad_ranges: usize,
    pub elapsed_secs: f64,
    /// Звідки почався цей прогін: 0 для нового образу, більше — для продовження.
    pub resumed_from: u64,
}

impl ImagingProgress {
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.offset as f64 / self.total as f64 * 100.0
        }
    }

    /// Швидкість саме цього прогону: байти, зняті до продовження, не рахуються.
    pub fn bytes_per_sec(&self) -> f64 {
        if self.elapsed_secs <= 0.0 {
            0.0
        } else {
            self.offset.saturating_sub(self.resumed_from) as f64 / self.elapsed_secs
        }
    }

    /// Скільки секунд лишилось за поточної швидкості; `None`, поки її не видно.
    pub fn eta_secs(&self) -> Option<u64> {
        let rate = self.bytes_per_sec();
        if rate < 1.0 {
            return None;
        }
        Some((self.total.saturating_sub(self.offset) as f64 / rate) as u64)
    }
}

/// `1 год 05 хв`, `7 хв 30 с`, `45 с` — для оцінки часу, що лишився.
pub fn format_duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h} год {m:02} хв")
    } else if m > 0 {
        format!("{m} хв {s:02} с")
    } else {
        format!("{s} с")
    }
}

/// Що дав прогін.
#[derive(Debug, Clone)]
pub struct ImagingReport {
    pub image_path: PathBuf,
    pub map_path: PathBuf,
    pub total_bytes: u64,
    pub bad_bytes: u64,
    pub bad_ranges: Vec<BadRange>,
    pub elapsed_secs: f64,
    pub cancelled: bool,
}

impl ImagingReport {
    pub fn is_complete_and_clean(&self) -> bool {
        !self.cancelled && self.bad_bytes == 0
    }

    /// Однорядковий висновок, що прямо називає втрати.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "знято {} з {}",
            human_bytes(self.total_bytes.saturating_sub(self.bad_bytes)),
            human_bytes(self.total_bytes)
        );
        if self.bad_bytes > 0 {
            s.push_str(&format!(
                " — НЕ ПРОЧИТАНО: {} у {} смузі(ах), записано нулями",
                human_bytes(self.bad_bytes),
                self.bad_ranges.len()
            ));
        }
        if self.cancelled {
            s.push_str(" — ЗУПИНЕНО до кінця, образ неповний");
        }
        s
    }
}

/// Прочитати `disk` від початку до кінця в `image_path`.
///
/// `progress` викликається приблизно на кожен блок; `cancel` перевіряється так
/// само часто, тож GUI може зупинити прогін, не вбиваючи процес.
pub fn create_image(
    disk: &mut RawDisk,
    image_path: impl AsRef<Path>,
    opts: &ImagingOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(ImagingProgress),
) -> io::Result<ImagingReport> {
    use crate::reader::BlockDevice;

    let image_path = image_path.as_ref().to_path_buf();
    let map_path = append_extension(&image_path, "map");

    let sector = disk.sector_size().max(512) as usize;
    let block_size = if opts.block_size < sector {
        sector
    } else {
        opts.block_size - (opts.block_size % sector)
    };
    let total = disk.len();

    let mut out = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(!opts.resume)
        .open(&image_path)?;

    // Продовження стартує з останнього повністю записаного блоку.
    let mut offset = if opts.resume {
        let written = out.metadata()?.len();
        written - (written % block_size as u64)
    } else {
        0
    };
    out.seek(SeekFrom::Start(offset))?;
    let resumed_from = offset;
    let mut out = BufWriter::with_capacity(block_size.min(8 << 20), out);

    let mut buf = vec![0u8; block_size];
    let mut bad_ranges: Vec<BadRange> = Vec::new();
    let mut bad_bytes: u64 = 0;
    let started = Instant::now();
    let mut cancelled = false;

    while offset < total {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }

        let want = block_size.min((total - offset) as usize);
        let chunk = &mut buf[..want];

        match read_with_retries(disk, offset, chunk, opts.retries) {
            Ok(()) => out.write_all(chunk)?,
            Err(_) => {
                // Блок не прочитався цілком; з'ясувати, які саме сектори в ньому
                // нечитані, замість того щоб викинути весь блок.
                let mut sector_buf = vec![0u8; sector];
                let mut at = 0usize;
                while at < want {
                    let this = sector.min(want - at);
                    let sbuf = &mut sector_buf[..this];
                    match read_with_retries(disk, offset + at as u64, sbuf, opts.retries) {
                        Ok(()) => out.write_all(sbuf)?,
                        Err(_) => {
                            // Нулі — щоб усі наступні зсуви лишились правильними,
                            // а втрату записати гучно.
                            sbuf.fill(0);
                            out.write_all(sbuf)?;
                            bad_bytes += this as u64;
                            record_bad(&mut bad_ranges, offset + at as u64, this as u64);
                        }
                    }
                    at += this;
                }
            }
        }

        offset += want as u64;
        progress(ImagingProgress {
            offset,
            total,
            bad_bytes,
            bad_ranges: bad_ranges.len(),
            elapsed_secs: started.elapsed().as_secs_f64(),
            resumed_from,
        });
    }

    out.flush()?;
    out.into_inner()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
        .sync_all()?;

    let report = ImagingReport {
        image_path,
        map_path: map_path.clone(),
        total_bytes: total,
        bad_bytes,
        bad_ranges,
        elapsed_secs: started.elapsed().as_secs_f64(),
        cancelled,
    };
    write_map_file(&map_path, &report)?;
    Ok(report)
}

fn read_with_retries(
    disk: &mut RawDisk,
    offset: u64,
    buf: &mut [u8],
    retries: u32,
) -> io::Result<()> {
    let mut last = None;
    for _ in 0..=retries {
        match disk.read_block_at(offset, buf) {
            Ok(n) if n == buf.len() => return Ok(()),
            Ok(n) => {
                last = Some(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("неповне читання: {n} з {} байтів", buf.len()),
                ))
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "читання не вдалося")))
}

/// Злити з попередньою смугою, якщо втрата неперервна.
fn record_bad(ranges: &mut Vec<BadRange>, offset: u64, len: u64) {
    if let Some(last) = ranges.last_mut() {
        if last.offset + last.len == offset {
            last.len += len;
            return;
        }
    }
    ranges.push(BadRange { offset, len });
}

/// Записати супровідний файл, де сказано, які частини образу — не справжні дані.
fn write_map_file(path: &Path, report: &ImagingReport) -> io::Result<()> {
    let mut f = BufWriter::new(File::create(path)?);
    writeln!(f, "# карта образу flashrec")?;
    writeln!(f, "# образ: {}", report.image_path.display())?;
    writeln!(f, "# total_bytes: {}", report.total_bytes)?;
    writeln!(f, "# bad_bytes: {}", report.bad_bytes)?;
    writeln!(f, "# cancelled: {}", report.cancelled)?;
    writeln!(f, "# заповнено нулями, це НЕ відновлені дані:")?;
    for r in &report.bad_ranges {
        writeln!(f, "bad {} {}", r.offset, r.len)?;
    }
    f.flush()
}

fn append_extension(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contiguous_losses_merge() {
        let mut r = Vec::new();
        record_bad(&mut r, 512, 512);
        record_bad(&mut r, 1024, 512);
        record_bad(&mut r, 4096, 512);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0], BadRange { offset: 512, len: 1024 });
        assert_eq!(r[1], BadRange { offset: 4096, len: 512 });
    }

    #[test]
    fn resumed_speed_ignores_bytes_taken_earlier() {
        let p = ImagingProgress {
            offset: 1_000 + 500,
            total: 3_000,
            bad_bytes: 0,
            bad_ranges: 0,
            elapsed_secs: 5.0,
            resumed_from: 1_000,
        };
        assert_eq!(p.bytes_per_sec(), 100.0);
        assert_eq!(p.eta_secs(), Some(15));
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(format_duration(45), "45 с");
        assert_eq!(format_duration(450), "7 хв 30 с");
        assert_eq!(format_duration(3_900), "1 год 05 хв");
    }

    #[test]
    fn map_path_keeps_the_image_extension() {
        let p = append_extension(Path::new(r"E:\flash.img"), "map");
        assert!(p.to_string_lossy().ends_with("flash.img.map"));
    }
}
