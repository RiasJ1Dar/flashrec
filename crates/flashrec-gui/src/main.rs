//! Графічний інтерфейс flashrec.
//!
//! Ліва панель веде через порятунок по порядку: обрати джерело, зняти образ,
//! просканувати, відновити й, в останню чергу, вирізати за сигнатурами.
//! Таблиця посередині показує, що знайшло сканування; журнал унизу тримає на
//! виду кожне попередження.

#![windows_subsystem = "windows"]

mod worker;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use flashrec_core::device::{check_output_not_on_disk, human_bytes, list_disks, DiskInfo};
use flashrec_core::ntfs::volume::{ScanMethod, DELETED_DIR, LIVE_DIR, PARTIAL_SUFFIX};
use flashrec_core::source::Source;
use worker::{Job, Level, Msg, Row, ScanOutcome};

const REPO_URL: &str = "https://github.com/RiasJ1Dar/flashrec";

/// Ширини колонок таблиці файлів.
const COL_STATE: f32 = 92.0;
const COL_SIZE: f32 = 92.0;
const COL_MODIFIED: f32 = 140.0;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([900.0, 560.0])
            .with_title(format!("flashrec {}", flashrec_core::VERSION)),
        ..Default::default()
    };
    eframe::run_native(
        "flashrec",
        options,
        Box::new(|cc| {
            install_fonts(&cc.egui_ctx);
            Ok(Box::new(App::new()))
        }),
    )
}

/// Вбудовані шрифти egui покривають латиницю й кирилицю. Імена файлів на
/// флешці можуть бути будь-якими, тож шрифти самої Windows додаються як
/// запасні, якщо вони є.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let fallbacks = [
        ("segoe-ui", r"C:\Windows\Fonts\segoeui.ttf"),
        ("segoe-symbol", r"C:\Windows\Fonts\seguisym.ttf"),
        ("ms-yahei", r"C:\Windows\Fonts\msyh.ttc"),
    ];
    for (name, path) in fallbacks {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        fonts
            .font_data
            .insert(name.to_string(), Arc::new(egui::FontData::from_owned(bytes)));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push(name.to_string());
        }
    }
    ctx.set_fonts(fonts);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Disk,
    Image,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sort {
    Path,
    SizeDesc,
    Modified,
}

struct LogLine {
    at: Duration,
    level: Level,
    text: String,
}

struct App {
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    started: Instant,

    disks: Vec<DiskInfo>,
    source_kind: SourceKind,
    disk_sel: Option<u32>,
    image_path: String,

    image_out: String,
    image_resume: bool,
    scan_sweep: bool,
    recover_out: String,
    recover_deleted: bool,
    recover_only_shown: bool,
    carve_out: String,

    job: Option<Job>,
    progress: f32,
    progress_text: String,

    scan: Option<ScanOutcome>,
    filter: String,
    show_live: bool,
    show_deleted: bool,
    sort: Sort,
    filtered: Vec<usize>,
    filter_dirty: bool,

    log: Vec<LogLine>,
    verdict: Option<(Level, String)>,
}

impl App {
    fn new() -> Self {
        let (tx, rx) = channel();
        let mut app = Self {
            tx,
            rx,
            started: Instant::now(),
            disks: Vec::new(),
            source_kind: SourceKind::Disk,
            disk_sel: None,
            image_path: String::new(),
            image_out: String::new(),
            image_resume: false,
            scan_sweep: false,
            recover_out: String::new(),
            recover_deleted: true,
            recover_only_shown: false,
            carve_out: String::new(),
            job: None,
            progress: 0.0,
            progress_text: String::new(),
            scan: None,
            filter: String::new(),
            show_live: true,
            show_deleted: true,
            sort: Sort::Path,
            filtered: Vec::new(),
            filter_dirty: true,
            log: Vec::new(),
            verdict: None,
        };
        app.log(
            Level::Info,
            "flashrec ніколи нічого не пише на диск, який відновлюється. Спершу зніміть образ, далі працюйте з ним.",
        );
        app.refresh_disks();
        app
    }

    fn log(&mut self, level: Level, text: impl Into<String>) {
        self.log.push(LogLine {
            at: self.started.elapsed(),
            level,
            text: text.into(),
        });
    }

    fn refresh_disks(&mut self) {
        self.disks = list_disks();
        // Знімні носії першими: майже завжди рятують саме їх.
        self.disks
            .sort_by_key(|d| (!d.is_likely_removable_media(), d.index));
        if self.disks.is_empty() {
            self.log(
                Level::Warn,
                "не вдалося відкрити жодного фізичного диска — щоб читати диск, запустіть flashrec \
                 від імені адміністратора. Файли образів відкриваються й без цього.",
            );
        } else {
            self.log(
                Level::Info,
                format!("знайдено фізичних дисків: {}", self.disks.len()),
            );
        }
        if let Some(sel) = self.disk_sel {
            if !self.disks.iter().any(|d| d.index == sel) {
                self.disk_sel = None;
            }
        }
        // Обрати диск самостійно лише тоді, коли знімний рівно один. Коли їх
        // кілька, серед них майже напевно й той, куди пишеться результат, —
        // вгадувати тут не можна.
        if self.disk_sel.is_none() {
            let mut removable = self.disks.iter().filter(|d| d.is_likely_removable_media());
            match (removable.next(), removable.next()) {
                (Some(only), None) => self.disk_sel = Some(only.index),
                (Some(_), Some(_)) => self.log(
                    Level::Warn,
                    "знімних дисків кілька — оберіть потрібний вручну, звіривши модель і серійний номер",
                ),
                _ => {}
            }
        }
    }

    fn selected_disk(&self) -> Option<&DiskInfo> {
        self.disk_sel
            .and_then(|i| self.disks.iter().find(|d| d.index == i))
    }

    fn current_source(&self) -> Option<Source> {
        match self.source_kind {
            SourceKind::Disk => self.disk_sel.map(Source::Disk),
            SourceKind::Image => {
                let p = self.image_path.trim();
                (!p.is_empty()).then(|| Source::Image(PathBuf::from(p)))
            }
        }
    }

    fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Коли читаємо живий диск, результат мусить лягти на інший диск.
    fn guard_output(&mut self, out: &str) -> bool {
        if out.trim().is_empty() {
            self.log(Level::Error, "спершу оберіть, куди записувати");
            return false;
        }
        if let Some(Source::Disk(n)) = self.current_source() {
            if let Err(e) = check_output_not_on_disk(std::path::Path::new(out.trim()), n) {
                self.log(Level::Error, e);
                return false;
            }
        }
        true
    }

    fn begin(&mut self, job: Job) {
        self.progress = 0.0;
        self.progress_text = format!("{}…", job.kind.label());
        self.verdict = None;
        self.job = Some(job);
    }

    // ---- приймання повідомлень ----------------------------------------------

    fn poll(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Log(level, text) => self.log(level, text),
                Msg::Progress { fraction, text } => {
                    self.progress = fraction.clamp(0.0, 1.0);
                    self.progress_text = text;
                }
                Msg::ImageDone(r) => self.finish_image(r),
                Msg::ScanDone(r) => self.finish_scan(r),
                Msg::RecoverDone(r) => {
                    // Окремі збої — перед рядком висновку.
                    if let Ok(rep) = &r {
                        for fail in rep.failures.iter().take(200) {
                            self.log(
                                Level::Warn,
                                format!("не відновлено: {} — {}", fail.path, fail.reason),
                            );
                        }
                        if rep.failures.len() > 200 {
                            self.log(
                                Level::Warn,
                                format!("… і ще збоїв: {}", rep.failures.len() - 200),
                            );
                        }
                    }
                    self.finish(r.map(|rep| {
                        let level = if rep.files_partial > 0 || !rep.failures.is_empty() {
                            Level::Warn
                        } else {
                            Level::Good
                        };
                        (level, rep.summary())
                    }));
                    if self.verdict.as_ref().is_some_and(|(l, _)| *l != Level::Error) {
                        self.log(
                            Level::Info,
                            format!(
                                "наявні файли — у {0}\\{LIVE_DIR}, видалені — у {0}\\{DELETED_DIR}; \
                                 файли з дірками мають суфікс {PARTIAL_SUFFIX}",
                                self.recover_out.trim()
                            ),
                        );
                    }
                }
                Msg::CarveDone(r) => self.finish(r.map(|rep| {
                    let level = if rep.files.is_empty() {
                        Level::Warn
                    } else {
                        Level::Good
                    };
                    (level, rep.summary())
                })),
            }
        }
    }

    fn finish(&mut self, result: Result<(Level, String), String>) {
        let cancelled = self.job.as_ref().is_some_and(|j| j.is_cancelling());
        let took = self
            .job
            .take()
            .map(|j| j.started.elapsed().as_secs())
            .unwrap_or(0);
        let (level, text) = match result {
            Ok((level, text)) => (level, format!("{text}  ({took} с)")),
            Err(e) => (Level::Error, e),
        };
        self.log(level, text.clone());
        if cancelled {
            self.log(Level::Warn, "зупинено на ваше прохання — результат вище неповний");
        }
        self.progress_text = text.clone();
        self.verdict = Some((level, text));
    }

    fn finish_image(&mut self, r: Result<flashrec_core::imaging::ImagingReport, String>) {
        let image = r.as_ref().ok().map(|rep| rep.image_path.clone());
        let complete = r.as_ref().is_ok_and(|rep| !rep.cancelled);
        self.finish(r.map(|rep| {
            let level = if rep.is_complete_and_clean() {
                Level::Good
            } else {
                Level::Warn
            };
            (level, rep.summary())
        }));
        // Далі працювати з образом — диск можна не чіпати.
        if let (Some(path), true) = (image, complete) {
            self.source_kind = SourceKind::Image;
            self.image_path = path.to_string_lossy().to_string();
            self.log(
                Level::Good,
                "джерело перемкнено на щойно знятий образ — далі «Сканувати». Флешку можна вийняти.",
            );
        }
    }

    fn finish_scan(&mut self, r: Result<ScanOutcome, String>) {
        match r {
            Ok(outcome) => {
                let res = &outcome.result;
                let files = outcome.rows.len();
                let level = if files == 0 || res.damaged_records > 0 {
                    Level::Warn
                } else {
                    Level::Good
                };
                let summary = res.summary();
                let method = res.method;
                self.scan = Some(outcome);
                self.filter_dirty = true;
                self.finish(Ok((level, summary)));
                if files == 0 {
                    let hint = match method {
                        ScanMethod::MftRunlist => {
                            "через MFT нічого не знайдено — спробуйте ще раз з увімкненим «Перебором підписів»"
                        }
                        ScanMethod::SignatureSweep => {
                            "записів MFT не лишилось — скористайтеся «Вирізати», щоб дістати файли за вмістом"
                        }
                    };
                    self.log(Level::Warn, hint);
                } else {
                    self.log(Level::Info, "далі: оберіть теку для результату й натисніть «Відновити»");
                }
            }
            Err(e) => self.finish(Err(e)),
        }
    }

    // ---- фільтр ------------------------------------------------------------

    fn refilter(&mut self) {
        self.filter_dirty = false;
        let Some(scan) = &self.scan else {
            self.filtered.clear();
            return;
        };
        let needle = self.filter.trim().to_lowercase();
        let mut idx: Vec<usize> = scan
            .rows
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                (r.in_use && self.show_live || !r.in_use && self.show_deleted)
                    && (needle.is_empty() || r.path_lower.contains(&needle))
            })
            .map(|(i, _)| i)
            .collect();
        let rows = &scan.rows;
        match self.sort {
            Sort::Path => {} // рядки вже впорядковано за шляхом
            Sort::SizeDesc => idx.sort_by(|a, b| rows[*b].size.cmp(&rows[*a].size)),
            Sort::Modified => idx.sort_by(|a, b| rows[*b].modified.cmp(&rows[*a].modified)),
        }
        self.filtered = idx;
    }

    // ---- дії ---------------------------------------------------------------

    fn start_image(&mut self, ctx: &egui::Context) {
        let Some(disk) = self.selected_disk().cloned() else {
            self.log(Level::Error, "оберіть фізичний диск, з якого знімати образ");
            return;
        };
        let out = self.image_out.trim().to_string();
        if !self.guard_output(&out) {
            return;
        }
        let out_path = PathBuf::from(&out);
        if out_path.exists() && !self.image_resume {
            self.log(
                Level::Error,
                format!("{out} уже існує — позначте «Продовжити», щоб дописати його, або оберіть інше ім'я"),
            );
            return;
        }
        if let Some(parent) = out_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                self.log(
                    Level::Error,
                    format!("не вдалося створити {}: {e}", parent.display()),
                );
                return;
            }
        }
        let job = worker::spawn_image(
            ctx.clone(),
            self.tx.clone(),
            disk.index,
            disk.serial.clone(),
            out_path,
            self.image_resume,
        );
        self.begin(job);
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        let Some(src) = self.current_source() else {
            self.log(Level::Error, "спершу оберіть диск або файл образу");
            return;
        };
        self.scan = None;
        self.filter_dirty = true;
        let job = worker::spawn_scan(ctx.clone(), self.tx.clone(), src, self.scan_sweep);
        self.begin(job);
    }

    fn start_recover(&mut self, ctx: &egui::Context) {
        let out = self.recover_out.trim().to_string();
        if !self.guard_output(&out) {
            return;
        }
        let Some(scan) = &self.scan else {
            self.log(Level::Error, "спершу скануйте, потім відновлюйте");
            return;
        };
        let only = self.recover_only_shown.then(|| {
            self.filtered
                .iter()
                .map(|&i| scan.rows[i].record)
                .collect::<HashSet<u64>>()
        });
        if let Some(only) = &only {
            self.log.push(LogLine {
                at: self.started.elapsed(),
                level: Level::Info,
                text: format!("відновлюю лише показані в таблиці файли: {}", only.len()),
            });
        }
        let job = worker::spawn_recover(
            ctx.clone(),
            self.tx.clone(),
            scan.source.clone(),
            scan.offset,
            scan.result.clone(),
            PathBuf::from(out),
            self.recover_deleted,
            only,
        );
        self.begin(job);
    }

    fn start_carve(&mut self, ctx: &egui::Context) {
        let Some(src) = self.current_source() else {
            self.log(Level::Error, "спершу оберіть диск або файл образу");
            return;
        };
        let out = self.carve_out.trim().to_string();
        if !self.guard_output(&out) {
            return;
        }
        // Вирізати лише розділ NTFS, якщо сканування його вже знайшло.
        let offset = self
            .scan
            .as_ref()
            .filter(|s| s.source == src)
            .map(|s| s.offset);
        let job = worker::spawn_carve(ctx.clone(), self.tx.clone(), src, offset, PathBuf::from(out));
        self.begin(job);
    }

    // ---- малювання ---------------------------------------------------------

    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new("flashrec").strong());
            ui.label(RichText::new("відновлення файлів із флешок, що відмовляють").weak());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.hyperlink_to("GitHub", REPO_URL);
                ui.label(RichText::new(format!("версія {}", flashrec_core::VERSION)).weak());
            });
        });
    }

    fn steps(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let busy = self.busy();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // 1. Джерело
                section(ui, "1", "Джерело");
                ui.add_enabled_ui(!busy, |ui| {
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.source_kind, SourceKind::Disk, "Фізичний диск");
                        ui.radio_value(&mut self.source_kind, SourceKind::Image, "Файл образу");
                    });
                    match self.source_kind {
                        SourceKind::Disk => self.disk_picker(ui),
                        SourceKind::Image => {
                            path_row(ui, &mut self.image_path, "E:\\відновлення\\flash.img", || {
                                rfd::FileDialog::new()
                                    .add_filter("Образ диска", &["img", "dd", "raw", "bin", "iso"])
                                    .add_filter("Усі файли", &["*"])
                                    .pick_file()
                            });
                        }
                    }
                });

                // 2. Образ
                section(ui, "2", "Зняти образ");
                hint(ui, "Скопіюйте диск один раз і більше його не чіпайте. Нечитані сектори записуються в журнал, а не ховаються.");
                let can_image = self.source_kind == SourceKind::Disk && self.disk_sel.is_some();
                ui.add_enabled_ui(!busy && can_image, |ui| {
                    path_row(ui, &mut self.image_out, "E:\\відновлення\\flash.img", || {
                        rfd::FileDialog::new()
                            .add_filter("Образ диска", &["img"])
                            .set_file_name("flash.img")
                            .save_file()
                    });
                    ui.checkbox(&mut self.image_resume, "Продовжити перерваний образ");
                    if ui.button("Зняти образ").clicked() {
                        self.start_image(&ctx);
                    }
                });
                if self.source_kind == SourceKind::Image {
                    hint(ui, "Джерело вже є образом — переходьте до сканування.");
                }

                // 3. Сканування
                section(ui, "3", "Сканувати");
                ui.add_enabled_ui(!busy, |ui| {
                    ui.checkbox(&mut self.scan_sweep, "Перебір підписів").on_hover_text(
                        "Перечитати кожен сектор у пошуках записів MFT, а не довіряти $MFT. \
                         Повільніше, зате знаходить файли, на які пошкоджений MFT уже не вказує.",
                    );
                    if ui.button("Сканувати").clicked() {
                        self.start_scan(&ctx);
                    }
                });

                // 4. Відновлення
                section(ui, "4", "Відновити");
                let has_scan = self.scan.as_ref().is_some_and(|s| !s.rows.is_empty());
                ui.add_enabled_ui(!busy && has_scan, |ui| {
                    path_row(ui, &mut self.recover_out, "E:\\відновлення\\файли", || {
                        rfd::FileDialog::new().pick_folder()
                    });
                    ui.checkbox(&mut self.recover_deleted, "Разом із видаленими файлами");
                    ui.checkbox(&mut self.recover_only_shown, "Лише те, що показує таблиця");
                    if ui.button("Відновити").clicked() {
                        self.start_recover(&ctx);
                    }
                });

                // 5. Вирізання
                section(ui, "5", "Вирізати (останній засіб)");
                hint(ui, "Знаходить файли за вмістом. Без імен і тек — лише якщо сканування нічого не дало.");
                ui.add_enabled_ui(!busy, |ui| {
                    path_row(ui, &mut self.carve_out, "E:\\відновлення\\вирізане", || {
                        rfd::FileDialog::new().pick_folder()
                    });
                    if ui.button("Вирізати").clicked() {
                        self.start_carve(&ctx);
                    }
                });
            });
    }

    fn disk_picker(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let selected = self
                .selected_disk()
                .map(|d| format!("{} · {} · {}", d.index, d.model, d.size_human()))
                .unwrap_or_else(|| "— оберіть диск —".into());
            egui::ComboBox::from_id_salt("disk")
                .selected_text(selected)
                .width(ui.available_width() - 80.0)
                .show_ui(ui, |ui| {
                    for d in &self.disks {
                        let text = format!(
                            "{} · {} · {} · {}{}",
                            d.index,
                            d.model,
                            d.size_human(),
                            d.bus,
                            if d.is_likely_removable_media() {
                                " · знімний"
                            } else {
                                ""
                            }
                        );
                        ui.selectable_value(&mut self.disk_sel, Some(d.index), text);
                    }
                });
            if ui.button("Оновити").clicked() {
                self.refresh_disks();
            }
        });

        if let Some(d) = self.selected_disk() {
            let serial = d.serial.clone().unwrap_or_else(|| "не повідомляє".into());
            hint(ui, &format!("серійний {serial} · сектор {} Б", d.sector_size));
            if !d.is_likely_removable_media() {
                ui.colored_label(
                    color(Level::Warn),
                    "Це не знімний носій — переконайтеся, що обрали потрібний диск.",
                );
            }
        } else if self.disks.is_empty() {
            ui.colored_label(
                color(Level::Warn),
                "Дисків не видно. Запустіть flashrec від імені адміністратора.",
            );
        }
    }

    fn status(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let running = self.job.as_ref().map(|j| (j.kind, j.is_cancelling(), j.started));
            match running {
                Some((kind, cancelling, started)) => {
                    ui.add(egui::Spinner::new());
                    ui.label(RichText::new(kind.label()).strong());
                    ui.label(RichText::new(format!("{} с", started.elapsed().as_secs())).weak());
                    if cancelling {
                        ui.label(RichText::new("зупиняю…").color(color(Level::Warn)));
                    } else if ui.button("Зупинити").clicked() {
                        if let Some(j) = &self.job {
                            j.cancel();
                        }
                    }
                }
                None => match &self.verdict {
                    Some((level, text)) => {
                        ui.label(RichText::new(text).color(color(*level)));
                    }
                    None => {
                        ui.label(RichText::new("Готово до роботи").weak());
                    }
                },
            }
        });
        if self.busy() {
            ui.add(
                egui::ProgressBar::new(self.progress)
                    .text(format!("{:.1}%  ·  {}", self.progress * 100.0, self.progress_text)),
            );
        }
    }

    fn log_view(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.log {
                    let secs = line.at.as_secs();
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!("{:02}:{:02}", secs / 60, secs % 60))
                                .monospace()
                                .weak(),
                        );
                        ui.label(RichText::new(&line.text).color(color(line.level)));
                    });
                }
            });
    }

    fn file_table(&mut self, ui: &mut egui::Ui) {
        if self.filter_dirty {
            self.refilter();
        }
        let Some(scan) = &self.scan else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new("Оберіть джерело й натисніть «Сканувати» — знайдені файли з'являться тут.")
                        .weak(),
                );
            });
            return;
        };

        let total = scan.rows.len();
        let deleted = scan.rows.iter().filter(|r| !r.in_use).count();
        let shown_bytes: u64 = self.filtered.iter().map(|&i| scan.rows[i].size).sum();

        let mut changed = false;
        ui.horizontal(|ui| {
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("фільтр за ім'ям або текою, напр. .jpg чи Документи")
                        .desired_width(340.0),
                )
                .changed();
            changed |= ui.checkbox(&mut self.show_live, "наявні").changed();
            changed |= ui.checkbox(&mut self.show_deleted, "видалені").changed();
            egui::ComboBox::from_id_salt("sort")
                .selected_text(match self.sort {
                    Sort::Path => "за шляхом",
                    Sort::SizeDesc => "найбільші",
                    Sort::Modified => "найновіші",
                })
                .show_ui(ui, |ui| {
                    changed |= ui.selectable_value(&mut self.sort, Sort::Path, "за шляхом").changed();
                    changed |= ui
                        .selectable_value(&mut self.sort, Sort::SizeDesc, "найбільші")
                        .changed();
                    changed |= ui
                        .selectable_value(&mut self.sort, Sort::Modified, "найновіші")
                        .changed();
                });
        });
        hint(
            ui,
            &format!(
                "файлів {total} · наявних {} · видалених {deleted} · показано {} ({})",
                total - deleted,
                self.filtered.len(),
                human_bytes(shown_bytes)
            ),
        );
        if changed {
            self.filter_dirty = true;
        }
        ui.separator();

        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        table_row(ui, row_h, |ui| {
            for (w, text) in [(COL_STATE, "СТАН"), (COL_SIZE, "РОЗМІР"), (COL_MODIFIED, "ЗМІНЕНО")] {
                ui.add_sized([w, row_h], egui::Label::new(RichText::new(text).small().strong()));
            }
            ui.label(RichText::new("ШЛЯХ").small().strong());
        });

        let rows = &scan.rows;
        let filtered = &self.filtered;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_h, filtered.len(), |ui, range| {
                for &i in &filtered[range] {
                    draw_row(ui, row_h, &rows[i]);
                }
            });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        if self.busy() {
            // Лічильник часу має йти навіть між повідомленнями про поступ.
            ui.ctx().request_repaint_after(Duration::from_millis(250));
        }

        egui::Panel::top("header").show(ui, |ui| {
            ui.add_space(4.0);
            self.header(ui);
            ui.add_space(2.0);
        });
        egui::Panel::bottom("log")
            .resizable(true)
            .default_size(190.0)
            .min_size(90.0)
            .show(ui, |ui| {
                ui.add_space(4.0);
                self.status(ui);
                ui.separator();
                self.log_view(ui);
            });
        egui::Panel::left("steps")
            .resizable(true)
            .default_size(340.0)
            .min_size(290.0)
            .show(ui, |ui| self.steps(ui));
        egui::CentralPanel::default().show(ui, |ui| self.file_table(ui));
    }
}

// ---- дрібні віджети ---------------------------------------------------------

fn color(level: Level) -> Color32 {
    match level {
        Level::Info => Color32::from_gray(200),
        Level::Good => Color32::from_rgb(120, 205, 130),
        Level::Warn => Color32::from_rgb(235, 185, 75),
        Level::Error => Color32::from_rgb(240, 100, 90),
    }
}

fn section(ui: &mut egui::Ui, number: &str, title: &str) {
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new(number).strong().color(color(Level::Good)));
        ui.label(RichText::new(title).strong());
    });
    ui.add_space(2.0);
}

/// Приглушена підказка під елементом.
fn hint(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).weak());
}

/// Поле шляху з кнопкою «…», що відкриває системне вікно вибору.
fn path_row(ui: &mut egui::Ui, value: &mut String, hint: &str, pick: impl FnOnce() -> Option<PathBuf>) {
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(ui.available_width() - 36.0),
        );
        if ui.button("…").on_hover_text("Огляд").clicked() {
            if let Some(p) = pick() {
                *value = p.to_string_lossy().to_string();
            }
        }
    });
}

fn table_row(ui: &mut egui::Ui, row_h: f32, add: impl FnOnce(&mut egui::Ui)) {
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), row_h),
        egui::Layout::left_to_right(egui::Align::Center),
        add,
    );
}

fn draw_row(ui: &mut egui::Ui, row_h: f32, row: &Row) {
    table_row(ui, row_h, |ui| {
        let (state, state_color) = if row.in_use {
            ("наявний", color(Level::Info))
        } else {
            ("ВИДАЛЕНИЙ", color(Level::Warn))
        };
        ui.add_sized(
            [COL_STATE, row_h],
            egui::Label::new(RichText::new(state).small().color(state_color)),
        );
        ui.add_sized(
            [COL_SIZE, row_h],
            egui::Label::new(RichText::new(human_bytes(row.size)).monospace().small()),
        );
        ui.add_sized(
            [COL_MODIFIED, row_h],
            egui::Label::new(RichText::new(&row.modified).monospace().small().weak()),
        );
        let text = match row.note {
            Some(note) => RichText::new(format!("{}   [{note}: буде пропущено]", row.path))
                .color(color(Level::Error)),
            None => RichText::new(&row.path),
        };
        ui.add(egui::Label::new(text).truncate());
    });
}
