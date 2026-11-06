//! Спільне для всіх файлових систем: знайдені файли, їхні шляхи й запис на диск.
//!
//! Кожна файлова система ([`crate::ntfs`], [`crate::fat`], [`crate::exfat`])
//! розбирає свої структури сама, але видає однаковий [`ScanResult`] — перелік
//! [`FileEntry`] із посиланнями на батьківські теки. Далі шляхи, фільтри й запис
//! файлів однакові для всіх.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::device::human_bytes;
use crate::ntfs::record::{DataAttribute, Timestamps};

/// Підтека результату для наявних файлів.
pub const LIVE_DIR: &str = "наявні";
/// Підтека результату для видалених файлів, чиї записи ще не перезаписано.
pub const DELETED_DIR: &str = "видалені";
/// Суфікс файлу, в якому нечитані кластери заповнено нулями.
pub const PARTIAL_SUFFIX: &str = ".НЕПОВНИЙ";

/// Файлова система тому.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Filesystem {
    Ntfs,
    Fat12,
    Fat16,
    Fat32,
    ExFat,
}

impl Filesystem {
    pub fn name(&self) -> &'static str {
        match self {
            Filesystem::Ntfs => "NTFS",
            Filesystem::Fat12 => "FAT12",
            Filesystem::Fat16 => "FAT16",
            Filesystem::Fat32 => "FAT32",
            Filesystem::ExFat => "exFAT",
        }
    }
}

/// Яка копія завантажувального запису виявилась придатною.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSource {
    Primary,
    Backup { offset: u64 },
}

impl BootSource {
    pub fn describe(&self) -> String {
        match self {
            BootSource::Primary => "основний".to_string(),
            BootSource::Backup { offset } => {
                format!("РЕЗЕРВНИЙ на зсуві {offset} (основний пошкоджено)")
            }
        }
    }
}

/// Один файл або тека.
///
/// `record_number` — стійкий номер у межах одного сканування: номер запису MFT
/// для NTFS, байтовий зсув запису теки для FAT і exFAT. `parent_number` вказує
/// на теку, що його містить; корінь тому — [`ScanResult::root`].
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub record_number: u64,
    pub sequence: u16,
    pub parent_number: u64,
    pub name: String,
    pub is_directory: bool,
    /// `false` для видаленого файлу, чий запис ще не використано повторно.
    pub in_use: bool,
    pub size: u64,
    /// Де лежить вміст. Номери кластерів у runlist-і — у нумерації тієї
    /// файлової системи, що знайшла файл; читає їх лише вона.
    pub data: Option<DataAttribute>,
    pub timestamps: Option<Timestamps>,
    pub named_streams: Vec<String>,
    /// Застереження, яке треба показати поруч із файлом: наприклад, що
    /// розташування вмісту видаленого файлу відтворено припущенням.
    pub caveat: Option<&'static str>,
}

impl FileEntry {
    /// Чому файл не повернеться цілим або що про нього варто знати.
    pub fn note(&self) -> Option<&'static str> {
        self.data
            .as_ref()
            .and_then(|d| d.unsupported_encoding())
            .or(self.caveat)
    }
}

/// Як знайдено файли.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMethod {
    /// NTFS: за runlist-ом `$DATA` у `$MFT` — шлях для справного тому.
    MftRunlist,
    /// NTFS: перебором тому в пошуках підписів `FILE`.
    SignatureSweep,
    /// FAT/exFAT: обходом дерева тек від кореня.
    DirectoryTree,
    /// FAT/exFAT: обходом дерева і перебором усіх кластерів у пошуках тек,
    /// до яких від кореня вже не дістатися.
    DirectorySweep,
}

impl ScanMethod {
    pub fn describe(&self) -> &'static str {
        match self {
            ScanMethod::MftRunlist => "за runlist-ом $MFT",
            ScanMethod::SignatureSweep => {
                "перебором тому в пошуках підписів FILE ($MFT непридатний)"
            }
            ScanMethod::DirectoryTree => "обходом тек від кореня",
            ScanMethod::DirectorySweep => "обходом тек і перебором усіх кластерів",
        }
    }
}

/// Що знайшло сканування і чого воно не змогло зрозуміти.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub filesystem: Filesystem,
    pub boot_source: BootSource,
    pub method: ScanMethod,
    /// Номер кореневої теки, на якій зупиняється побудова шляхів.
    pub root: u64,
    pub entries: Vec<FileEntry>,
    /// Записи, які не вдалося розібрати (запис MFT, тека, набір записів exFAT).
    pub damaged_records: u64,
    /// Розібрані записи без придатного імені.
    pub nameless_records: u64,
    pub cancelled: bool,
}

impl ScanResult {
    pub fn files(&self) -> impl Iterator<Item = &FileEntry> {
        self.entries.iter().filter(|e| !e.is_directory)
    }

    pub fn summary(&self) -> String {
        let files = self.files().count();
        let dirs = self.entries.len() - files;
        let deleted = self.entries.iter().filter(|e| !e.in_use).count();
        let mut s = format!(
            "{}, {} (завантажувальний запис: {}): файлів {files}, тек {dirs}, з них видалених {deleted}",
            self.filesystem.name(),
            self.method.describe(),
            self.boot_source.describe()
        );
        if self.damaged_records > 0 || self.nameless_records > 0 {
            s.push_str(&format!(
                " — ПРОПУЩЕНО: пошкоджених записів {}, без придатного імені {}",
                self.damaged_records, self.nameless_records
            ));
        }
        if self.cancelled {
            s.push_str(" — ЗУПИНЕНО до кінця");
        }
        s
    }

    /// Чи це службовий файл самої файлової системи, а не дані користувача.
    /// Такі є лише в NTFS; у FAT і exFAT службові структури файлами не є.
    pub fn is_metadata(&self, entry: &FileEntry, path: &Path) -> bool {
        self.filesystem == Filesystem::Ntfs
            && crate::ntfs::volume::is_ntfs_metadata(entry.record_number, path)
    }

    /// Відновити повні шляхи для кожного запису, ідучи за батьківськими посиланнями.
    pub fn paths(&self) -> HashMap<u64, PathBuf> {
        let by_number: HashMap<u64, &FileEntry> = self
            .entries
            .iter()
            .map(|e| (e.record_number, e))
            .collect();

        let mut paths: HashMap<u64, PathBuf> = HashMap::new();
        for entry in &self.entries {
            let mut components: Vec<&str> = Vec::new();
            let mut current = entry;
            let mut guard = 0;

            loop {
                components.push(&current.name);
                if current.parent_number == self.root
                    || current.parent_number == current.record_number
                {
                    break;
                }
                guard += 1;
                // Пошкоджені структури можуть містити цикли батьківських посилань.
                if guard > 64 {
                    components.push("_цикл_тек");
                    break;
                }
                match by_number.get(&current.parent_number) {
                    Some(parent) if parent.is_directory => current = parent,
                    _ => {
                        components.push("_без_теки");
                        break;
                    }
                }
            }

            components.reverse();
            paths.insert(entry.record_number, components.iter().collect());
        }
        paths
    }
}

/// Поступ сканування.
#[derive(Debug, Clone, Copy)]
pub struct ScanProgress {
    pub records_examined: u64,
    pub entries_found: u64,
    pub offset: u64,
    pub total: u64,
}

/// Те, з чого можна прочитати вміст знайденого файлу.
pub trait ReadFiles {
    /// Прочитати вміст файлу; повертає дані і скільки байтів втрачено.
    ///
    /// Нечитані кластери заповнюються нулями, щоб решта файлу лягла на свої
    /// зсуви, а втрата повертається, а не ховається.
    fn read_file_data(&mut self, entry: &FileEntry) -> io::Result<(Vec<u8>, u64)>;
}

/// Фільтри, що застосовуються під час запису файлів.
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// Записувати й файли, позначені видаленими.
    pub include_deleted: bool,
    /// Записувати й службові файли NTFS (`$MFT`, `$LogFile`, записи < 16).
    pub include_system: bool,
    pub min_size: u64,
    pub max_size: Option<u64>,
    /// Лишити тільки файли, чиє ім'я закінчується одним із цих розширень
    /// (малими літерами, без крапки).
    pub extensions: Vec<String>,
    /// Лишити тільки ці записи — те, що користувач обрав у списку.
    /// Теки однаково беруться з повного сканування, тож шляхи не ламаються.
    pub only_records: Option<HashSet<u64>>,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            include_deleted: true,
            include_system: false,
            min_size: 1,
            max_size: None,
            extensions: Vec::new(),
            only_records: None,
        }
    }
}

impl RecoveryOptions {
    fn accepts(&self, entry: &FileEntry) -> bool {
        if entry.is_directory {
            return false;
        }
        if let Some(only) = &self.only_records {
            if !only.contains(&entry.record_number) {
                return false;
            }
        }
        if !self.include_deleted && !entry.in_use {
            return false;
        }
        if entry.size < self.min_size {
            return false;
        }
        if let Some(max) = self.max_size {
            if entry.size > max {
                return false;
            }
        }
        if !self.extensions.is_empty() {
            let name = entry.name.to_lowercase();
            if !self
                .extensions
                .iter()
                .any(|ext| name.ends_with(&format!(".{ext}")))
            {
                return false;
            }
        }
        true
    }
}

/// Файл, який не вдалося записати, і чому.
#[derive(Debug, Clone)]
pub struct RecoveryFailure {
    pub path: String,
    pub reason: String,
}

/// Підсумок запису файлів.
#[derive(Debug, Clone, Default)]
pub struct RecoveryReport {
    pub files_written: u64,
    pub bytes_written: u64,
    /// Файли, записані з дірками, заповненими нулями на місці нечитаних кластерів.
    pub files_partial: u64,
    pub bytes_lost: u64,
    pub skipped_by_filter: u64,
    pub failures: Vec<RecoveryFailure>,
    pub cancelled: bool,
}

impl RecoveryReport {
    /// Висновок, що ніколи не ховає втрат.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "записано файлів: {}, {}",
            self.files_written,
            human_bytes(self.bytes_written)
        );
        if self.files_partial > 0 {
            s.push_str(&format!(
                " — НЕПОВНІ: у {} файлах дірки, не прочитано {}",
                self.files_partial,
                human_bytes(self.bytes_lost)
            ));
        }
        if !self.failures.is_empty() {
            s.push_str(&format!(" — НЕ ВДАЛОСЯ: {} файлів", self.failures.len()));
        }
        if self.cancelled {
            s.push_str(" — ЗУПИНЕНО до кінця");
        }
        s
    }
}

/// Поступ запису файлів.
#[derive(Debug, Clone)]
pub struct RecoveryProgress {
    pub current: String,
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_written: u64,
}

/// Записати всі прийняті файли з `result` у `dest`.
pub fn recover_files<V: ReadFiles + ?Sized>(
    volume: &mut V,
    result: &ScanResult,
    dest: impl AsRef<Path>,
    opts: &RecoveryOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(RecoveryProgress),
) -> io::Result<RecoveryReport> {
    let dest = dest.as_ref();
    fs::create_dir_all(dest)?;
    let paths = result.paths();

    let candidates: Vec<&FileEntry> = result
        .entries
        .iter()
        .filter(|e| opts.accepts(e))
        .filter(|e| {
            opts.include_system
                || paths
                    .get(&e.record_number)
                    .is_none_or(|p| !result.is_metadata(e, p))
        })
        .collect();
    let files_total = candidates.len() as u64;
    let mut report = RecoveryReport {
        skipped_by_filter: result.entries.len() as u64 - files_total,
        ..Default::default()
    };

    for entry in candidates {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }

        let relative = paths
            .get(&entry.record_number)
            .cloned()
            .unwrap_or_else(|| PathBuf::from(&entry.name));
        let mut target = dest.join(if entry.in_use {
            PathBuf::from(LIVE_DIR).join(&relative)
        } else {
            PathBuf::from(DELETED_DIR).join(&relative)
        });

        progress(RecoveryProgress {
            current: relative.to_string_lossy().to_string(),
            files_done: report.files_written,
            files_total,
            bytes_written: report.bytes_written,
        });

        let (bytes, lost) = match volume.read_file_data(entry) {
            Ok(v) => v,
            Err(e) => {
                report.failures.push(RecoveryFailure {
                    path: relative.to_string_lossy().to_string(),
                    reason: e.to_string(),
                });
                continue;
            }
        };

        // Видалений файл із самих нулів майже напевно стерто: SSD і частина
        // флешок обнуляють звільнені кластери (TRIM). Записати його — значить
        // видати порожнечу за відновлений файл.
        if !entry.in_use && !bytes.is_empty() && bytes.iter().all(|&b| b == 0) {
            report.failures.push(RecoveryFailure {
                path: relative.to_string_lossy().to_string(),
                reason: "вміст видаленого файлу — суцільні нулі: носій стер звільнені кластери \
                         (TRIM) або їх перезаписано"
                    .to_string(),
            });
            continue;
        }

        // Позначити файл із дірками в імені, щоб його ніколи не сприйняли за цілий.
        if lost > 0 {
            let marked = format!(
                "{}{PARTIAL_SUFFIX}",
                target.file_name().unwrap_or_default().to_string_lossy()
            );
            target.set_file_name(marked);
        }

        if let Some(parent) = target.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                report.failures.push(RecoveryFailure {
                    path: relative.to_string_lossy().to_string(),
                    reason: format!("не вдалося створити теку: {e}"),
                });
                continue;
            }
        }

        // Два видалені файли з однаковою назвою в одній теці — звична справа для
        // FAT. Не перезаписувати перший другим.
        let target = unique_path(target);

        match fs::File::create(&target) {
            Ok(f) => {
                let mut w = BufWriter::new(f);
                if let Err(e) = w.write_all(&bytes).and_then(|_| w.flush()) {
                    report.failures.push(RecoveryFailure {
                        path: relative.to_string_lossy().to_string(),
                        reason: format!("запис не вдався: {e}"),
                    });
                    continue;
                }
            }
            Err(e) => {
                report.failures.push(RecoveryFailure {
                    path: relative.to_string_lossy().to_string(),
                    reason: format!("не вдалося створити файл: {e}"),
                });
                continue;
            }
        }

        report.files_written += 1;
        report.bytes_written += bytes.len() as u64;
        if lost > 0 {
            report.files_partial += 1;
            report.bytes_lost += lost;
        }
    }

    Ok(report)
}

/// Якщо `path` уже існує, додати до назви ` (2)`, ` (3)`, … перед розширенням.
fn unique_path(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    // Розширення — після останньої крапки, але не в `.НЕПОВНИЙ`, щоб позначка
    // лишалась у кінці назви.
    let (base, tail) = match name.strip_suffix(PARTIAL_SUFFIX) {
        Some(stem) => (stem.to_string(), PARTIAL_SUFFIX.to_string()),
        None => (name.clone(), String::new()),
    };
    let (stem, ext) = match base.rfind('.') {
        Some(i) if i > 0 => (base[..i].to_string(), base[i..].to_string()),
        _ => (base.clone(), String::new()),
    };
    for n in 2u32.. {
        let candidate = path.with_file_name(format!("{stem} ({n}){ext}{tail}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("лічильник u32 вичерпано")
}

/// Зробити один компонент шляху безпечним для Windows.
///
/// Заборонені символи й крапки/пробіли в кінці замінюються; ім'я, що збіглося б
/// з назвою пристрою (`CON`, `NUL`, …), отримує префікс.
pub fn sanitize_component(name: &str) -> String {
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    let mut out: String = name
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();

    while out.ends_with('.') || out.ends_with(' ') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("_без_назви");
    }

    let stem = out.split('.').next().unwrap_or("").to_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        out.insert(0, '_');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(record_number: u64, name: &str, in_use: bool) -> FileEntry {
        FileEntry {
            record_number,
            sequence: 1,
            parent_number: 5,
            name: name.into(),
            is_directory: false,
            in_use,
            size: 1024,
            data: None,
            timestamps: None,
            named_streams: Vec::new(),
            caveat: None,
        }
    }

    #[test]
    fn sanitizes_windows_hostile_names() {
        assert_eq!(sanitize_component("a:b"), "a_b");
        assert_eq!(sanitize_component("report."), "report");
        assert_eq!(sanitize_component("NUL"), "_NUL");
        assert_eq!(sanitize_component("con.txt"), "_con.txt");
        assert_eq!(sanitize_component(""), "_без_назви");
        assert_eq!(sanitize_component("нормальна назва.jpg"), "нормальна назва.jpg");
    }

    #[test]
    fn filters_reject_what_they_should() {
        let entry = entry(100, "photo.jpg", false);

        let mut opts = RecoveryOptions::default();
        assert!(opts.accepts(&entry));

        opts.include_deleted = false;
        assert!(!opts.accepts(&entry));

        opts.include_deleted = true;
        opts.extensions = vec!["png".into()];
        assert!(!opts.accepts(&entry));
        opts.extensions = vec!["jpg".into()];
        assert!(opts.accepts(&entry));

        opts.extensions.clear();
        opts.min_size = 2048;
        assert!(!opts.accepts(&entry));

        opts.min_size = 1;
        opts.only_records = Some(HashSet::from([7]));
        assert!(!opts.accepts(&entry));
        opts.only_records = Some(HashSet::from([100]));
        assert!(opts.accepts(&entry));
    }

    fn result(filesystem: Filesystem, entries: Vec<FileEntry>) -> ScanResult {
        ScanResult {
            filesystem,
            boot_source: BootSource::Primary,
            method: ScanMethod::DirectoryTree,
            root: 5,
            entries,
            damaged_records: 0,
            nameless_records: 0,
            cancelled: false,
        }
    }

    #[test]
    fn only_ntfs_has_metadata_files() {
        let mft = entry(0, "$MFT", true);
        let ntfs = result(Filesystem::Ntfs, vec![mft.clone()]);
        assert!(ntfs.is_metadata(&mft, Path::new("$MFT")));
        // У FAT ім'я на `$` — звичайний файл користувача.
        let fat = result(Filesystem::Fat32, vec![mft.clone()]);
        assert!(!fat.is_metadata(&mft, Path::new("$MFT")));
    }

    #[test]
    fn paths_follow_parents_up_to_the_root() {
        let mut dir = entry(10, "Фото", true);
        dir.is_directory = true;
        let mut file = entry(20, "кіт.jpg", true);
        file.parent_number = 10;
        let mut orphan = entry(30, "сирота.txt", true);
        orphan.parent_number = 999;
        let paths = result(Filesystem::Fat32, vec![dir, file, orphan]).paths();
        assert_eq!(paths[&20], PathBuf::from("Фото").join("кіт.jpg"));
        assert_eq!(paths[&30], PathBuf::from("_без_теки").join("сирота.txt"));
    }

    #[test]
    fn duplicate_names_get_a_counter_before_the_extension() {
        let dir = std::env::temp_dir().join(format!("flashrec-unique-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let first = dir.join("звіт.docx");
        fs::write(&first, b"1").unwrap();
        assert_eq!(unique_path(first.clone()), dir.join("звіт (2).docx"));

        let partial = dir.join(format!("фото.jpg{PARTIAL_SUFFIX}"));
        fs::write(&partial, b"1").unwrap();
        assert_eq!(
            unique_path(partial),
            dir.join(format!("фото (2).jpg{PARTIAL_SUFFIX}"))
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
