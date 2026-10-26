//! Довгі завдання, кожне у власному потоці.
//!
//! Зняття образу 16-гігабайтної флешки чи перебір її в пошуках записів MFT
//! тривають хвилинами, тому інтерфейс цієї роботи сам не робить. Завдання
//! звітує через канал і будить інтерфейс через `request_repaint`; інтерфейс
//! зупиняє його через спільний прапорець.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use eframe::egui;
use flashrec_core::carve::{carve, CarveReport};
use flashrec_core::device::{human_bytes, list_disks, RawDisk};
use flashrec_core::imaging::{create_image, format_duration, ImagingOptions, ImagingReport};
use flashrec_core::ntfs::format_filetime;
use flashrec_core::ntfs::volume::{recover_files, RecoveryOptions, RecoveryReport, ScanResult};
use flashrec_core::reader::{BlockDevice, SubDevice};
use flashrec_core::source::{open_ntfs, open_source, Source};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Good,
    Warn,
    Error,
}

/// Усе, що завдання може повідомити інтерфейсу.
pub enum Msg {
    Log(Level, String),
    Progress { fraction: f32, text: String },
    ImageDone(Result<ImagingReport, String>),
    ScanDone(Result<ScanOutcome, String>),
    RecoverDone(Result<RecoveryReport, String>),
    CarveDone(Result<CarveReport, String>),
}

/// Сканування, сплющене в рядки, які таблиця файлів швидко малює.
pub struct ScanOutcome {
    pub source: Source,
    pub offset: u64,
    pub result: ScanResult,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone)]
pub struct Row {
    pub record: u64,
    pub path: String,
    /// Малими літерами один раз, щоб фільтр великої таблиці лишався дешевим.
    pub path_lower: String,
    pub size: u64,
    pub in_use: bool,
    pub modified: String,
    /// Чому файл не повернеться цілим, якщо це вже відомо.
    pub note: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Image,
    Scan,
    Recover,
    Carve,
}

impl JobKind {
    pub fn label(&self) -> &'static str {
        match self {
            JobKind::Image => "Знімаю образ",
            JobKind::Scan => "Сканую",
            JobKind::Recover => "Відновлюю",
            JobKind::Carve => "Вирізаю",
        }
    }

    fn thread_name(&self) -> &'static str {
        match self {
            JobKind::Image => "flashrec-image",
            JobKind::Scan => "flashrec-scan",
            JobKind::Recover => "flashrec-recover",
            JobKind::Carve => "flashrec-carve",
        }
    }
}

/// Завдання, що виконується, — так, як його бачить інтерфейс.
pub struct Job {
    pub kind: JobKind,
    pub cancel: Arc<AtomicBool>,
    pub started: Instant,
}

impl Job {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelling(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// Надсилає повідомлення і тримає частоту оновлень поступу в розумних межах.
struct Reporter {
    tx: Sender<Msg>,
    ctx: egui::Context,
    last: Instant,
}

impl Reporter {
    fn new(tx: Sender<Msg>, ctx: egui::Context) -> Self {
        Self {
            tx,
            ctx,
            last: Instant::now() - Duration::from_secs(1),
        }
    }

    fn send(&self, msg: Msg) {
        // Приймач зникає лише тоді, коли вікно закривається.
        let _ = self.tx.send(msg);
        self.ctx.request_repaint();
    }

    fn log(&self, level: Level, text: impl Into<String>) {
        self.send(Msg::Log(level, text.into()));
    }

    fn progress(&mut self, fraction: f32, text: String) {
        if self.last.elapsed() < Duration::from_millis(100) && fraction < 1.0 {
            return;
        }
        self.last = Instant::now();
        self.send(Msg::Progress { fraction, text });
    }
}

fn start(kind: JobKind, body: impl FnOnce(&AtomicBool) + Send + 'static) -> Job {
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    thread::Builder::new()
        .name(kind.thread_name().to_string())
        .spawn(move || body(&flag))
        .expect("не вдалося запустити робочий потік");
    Job {
        kind,
        cancel,
        started: Instant::now(),
    }
}

/// Скопіювати фізичний диск в образ.
///
/// `expected_serial` — серійний номер, показаний, коли користувач обирав диск:
/// номери дисків можуть зсунутися, якщо тим часом підключили пристрій, а
/// серійні номери — ні.
pub fn spawn_image(
    ctx: egui::Context,
    tx: Sender<Msg>,
    index: u32,
    expected_serial: Option<String>,
    out: PathBuf,
    resume: bool,
) -> Job {
    start(JobKind::Image, move |cancel| {
        let mut r = Reporter::new(tx, ctx);
        let result = (|| -> Result<ImagingReport, String> {
            let info = list_disks()
                .into_iter()
                .find(|d| d.index == index)
                .ok_or_else(|| format!("диска {index} більше немає — його вийняли?"))?;
            if let Some(expected) = &expected_serial {
                if info.serial.as_deref().map(str::trim) != Some(expected.trim()) {
                    return Err(format!(
                        "СЕРІЙНИЙ НОМЕР НЕ ЗБІГАЄТЬСЯ: диск {index} тепер повідомляє {:?}, а під час \
                         вибору був {expected:?}. Відмовляюсь знімати образ, бо це може бути інший \
                         диск — натисніть «Оновити» й оберіть його знову.",
                        info.serial
                    ));
                }
            }
            r.log(Level::Info, format!("джерело: {info}"));
            r.log(Level::Info, format!("образ: {}", out.display()));

            let mut disk = RawDisk::open_index(index).map_err(|e| e.to_string())?;
            let opts = ImagingOptions {
                resume,
                ..ImagingOptions::default()
            };
            create_image(&mut disk, &out, &opts, cancel, &mut |p| {
                r.progress(
                    (p.percent() / 100.0) as f32,
                    format!(
                        "{} / {}  ·  {}/с  ·  лишилось {}  ·  нечитано: {}",
                        human_bytes(p.offset),
                        human_bytes(p.total),
                        human_bytes(p.bytes_per_sec() as u64),
                        p.eta_secs().map(format_duration).unwrap_or_else(|| "—".into()),
                        human_bytes(p.bad_bytes)
                    ),
                );
            })
            .map_err(|e| e.to_string())
        })();
        r.send(Msg::ImageDone(result));
    })
}

/// Знайти том NTFS і перелічити його файли.
pub fn spawn_scan(ctx: egui::Context, tx: Sender<Msg>, source: Source, sweep: bool) -> Job {
    start(JobKind::Scan, move |cancel| {
        let mut r = Reporter::new(tx, ctx);
        let result = (|| -> Result<ScanOutcome, String> {
            if source.is_live_disk() {
                r.log(
                    Level::Warn,
                    "читаю живий диск — з образом безпечніше: зніміть його один раз і більше не чіпайте диск",
                );
            }
            let mut opened = open_ntfs(&source, None).map_err(|e| e.to_string())?;
            for line in opened.describe() {
                r.log(Level::Info, line);
            }

            let mut on_progress = |p: flashrec_core::ntfs::volume::ScanProgress| {
                let fraction = if p.total == 0 {
                    0.0
                } else {
                    p.offset as f32 / p.total as f32
                };
                r.progress(
                    fraction,
                    format!(
                        "переглянуто записів: {}  ·  знайдено: {}",
                        p.records_examined, p.entries_found
                    ),
                );
            };
            let result = if sweep {
                opened.volume.scan_by_signature(cancel, &mut on_progress)
            } else {
                opened.volume.scan(cancel, &mut on_progress)
            }
            .map_err(|e| e.to_string())?;

            let paths = opened.volume.build_paths(&result);
            let mut rows: Vec<Row> = result
                .files()
                .map(|e| {
                    let path = paths
                        .get(&e.record_number)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| e.name.clone());
                    Row {
                        record: e.record_number,
                        path_lower: path.to_lowercase(),
                        path,
                        size: e.size,
                        in_use: e.in_use,
                        modified: e
                            .timestamps
                            .map(|t| format_filetime(t.modified))
                            .unwrap_or_else(|| "-".into()),
                        note: e.data.as_ref().and_then(|d| d.unsupported_encoding()),
                    }
                })
                .collect();
            rows.sort_by(|a, b| a.path_lower.cmp(&b.path_lower));

            Ok(ScanOutcome {
                source,
                offset: opened.offset,
                result,
                rows,
            })
        })();
        r.send(Msg::ScanDone(result));
    })
}

/// Записати знайдені файли — за бажання лише ті, що обрав користувач.
#[allow(clippy::too_many_arguments)]
pub fn spawn_recover(
    ctx: egui::Context,
    tx: Sender<Msg>,
    source: Source,
    offset: u64,
    scan: ScanResult,
    out: PathBuf,
    include_deleted: bool,
    only_records: Option<HashSet<u64>>,
) -> Job {
    start(JobKind::Recover, move |cancel| {
        let mut r = Reporter::new(tx, ctx);
        let result = (|| -> Result<RecoveryReport, String> {
            // Відкрити знову на тому самому зсуві, що й сканування, — щоб записи збіглися точно.
            let mut opened = open_ntfs(&source, Some(offset)).map_err(|e| e.to_string())?;
            let opts = RecoveryOptions {
                include_deleted,
                only_records,
                ..RecoveryOptions::default()
            };
            r.log(Level::Info, format!("записую в {}", out.display()));
            recover_files(&mut opened.volume, &scan, &out, &opts, cancel, &mut |p| {
                let fraction = if p.files_total == 0 {
                    1.0
                } else {
                    p.files_done as f32 / p.files_total as f32
                };
                r.progress(
                    fraction,
                    format!(
                        "{}/{}  ·  {}  ·  {}",
                        p.files_done,
                        p.files_total,
                        human_bytes(p.bytes_written),
                        p.current
                    ),
                );
            })
            .map_err(|e| e.to_string())
        })();
        r.send(Msg::RecoverDone(result));
    })
}

/// Перебрати сирі байти в пошуках відомих сигнатур файлів.
pub fn spawn_carve(
    ctx: egui::Context,
    tx: Sender<Msg>,
    source: Source,
    offset: Option<u64>,
    out: PathBuf,
) -> Job {
    start(JobKind::Carve, move |cancel| {
        let mut r = Reporter::new(tx, ctx);
        let result = (|| -> Result<CarveReport, String> {
            let mut dev = open_source(&source).map_err(|e| e.to_string())?;
            if let Some(off) = offset {
                let len = dev.len().saturating_sub(off);
                dev = Box::new(SubDevice::new(dev, off, len));
            }
            r.log(
                Level::Info,
                format!("вирізаю з {} у {}", human_bytes(dev.len()), out.display()),
            );
            carve(&mut dev, &out, cancel, &mut |p| {
                r.progress(
                    p.offset as f32 / p.total.max(1) as f32,
                    format!(
                        "{} / {}  ·  знайдено: {}",
                        human_bytes(p.offset),
                        human_bytes(p.total),
                        p.found
                    ),
                );
            })
            .map_err(|e| e.to_string())
        })();
        r.send(Msg::CarveDone(result));
    })
}
