//! Читання цілого тому NTFS: знайти MFT, перелічити файли, записати їх.
//!
//! Шляхів два. Звичайний іде за runlist-ом самого `$MFT`. Коли той не
//! читається — а на диску, що став RAW, так і буває, — том перебирається в
//! пошуках підписів `FILE`, і це знаходить записи, на які зламаний MFT уже не
//! вказує. В обох випадках дерево тек відновлюють посилання на батьківську теку.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use super::record::{DataAttribute, MftRecord, Timestamps};
use super::{
    bad, read_boot, BootSource, NtfsBoot, FIRST_USER_RECORD, MFT_RECORD_MFT, MFT_RECORD_ROOT,
};
use crate::device::human_bytes;
use crate::reader::BlockDevice;

/// Підтека результату для наявних файлів.
pub const LIVE_DIR: &str = "наявні";
/// Підтека результату для видалених файлів, чиї записи ще не перезаписано.
pub const DELETED_DIR: &str = "видалені";
/// Суфікс файлу, в якому нечитані кластери заповнено нулями.
pub const PARTIAL_SUFFIX: &str = ".НЕПОВНИЙ";

/// Один файл або тека, знайдені в MFT.
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
    pub data: Option<DataAttribute>,
    pub timestamps: Option<Timestamps>,
    pub named_streams: Vec<String>,
}

impl FileEntry {
    fn from_record(rec: &MftRecord) -> Option<Self> {
        let name_attr = rec.file_name()?;
        let data = rec.data_attribute();
        Some(Self {
            record_number: rec.record_number,
            sequence: rec.sequence,
            parent_number: name_attr.parent.number(),
            name: sanitize_component(&name_attr.name),
            is_directory: rec.is_directory,
            in_use: rec.in_use,
            size: data.as_ref().map(|d| d.size()).unwrap_or(0),
            data,
            timestamps: rec.timestamps(),
            named_streams: rec.named_streams(),
        })
    }
}

/// Як знайдено MFT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMethod {
    /// За runlist-ом `$DATA` у `$MFT` — шлях для справного тому.
    MftRunlist,
    /// Перебором тому в пошуках підписів `FILE`.
    SignatureSweep,
}

impl ScanMethod {
    pub fn describe(&self) -> &'static str {
        match self {
            ScanMethod::MftRunlist => "за runlist-ом $MFT",
            ScanMethod::SignatureSweep => {
                "перебором тому в пошуках підписів FILE ($MFT непридатний)"
            }
        }
    }
}

/// Що знайшло сканування і чого воно не змогло зрозуміти.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub boot: NtfsBoot,
    pub boot_source: BootSource,
    pub method: ScanMethod,
    pub entries: Vec<FileEntry>,
    /// Записи з підписом `FILE`, які не вдалося розібрати.
    pub damaged_records: u64,
    /// Розібрані записи без придатного `$FILE_NAME`.
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
            "{} (завантажувальний запис: {}): файлів {files}, тек {dirs}, з них видалених {deleted}",
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
}

/// Поступ сканування.
#[derive(Debug, Clone, Copy)]
pub struct ScanProgress {
    pub records_examined: u64,
    pub entries_found: u64,
    pub offset: u64,
    pub total: u64,
}

/// Том NTFS, відкритий на читання.
pub struct NtfsVolume<D: BlockDevice> {
    dev: D,
    pub boot: NtfsBoot,
    pub boot_source: BootSource,
}

impl<D: BlockDevice> NtfsVolume<D> {
    /// Відкрити том, погоджуючись на резервний завантажувальний сектор, якщо
    /// основного немає.
    pub fn open(mut dev: D) -> io::Result<Self> {
        let (boot, boot_source) = read_boot(&mut dev)?;
        Ok(Self {
            dev,
            boot,
            boot_source,
        })
    }

    fn cluster_offset(&self, lcn: i64) -> u64 {
        lcn as u64 * self.boot.cluster_size as u64
    }

    /// Прочитати запис MFT за байтовим зсувом.
    fn read_record_at(&mut self, offset: u64) -> io::Result<MftRecord> {
        let size = self.boot.mft_record_size as usize;
        let buf = self.dev.read_vec(offset, size)?;
        MftRecord::parse(buf, self.boot.bytes_per_sector)
    }

    /// Знайти всі байтові діапазони, які займає MFT.
    ///
    /// Повертає `None`, коли запис 0 (`$MFT`) не читається або не має
    /// придатного runlist-а в `$DATA` — це сигнал перейти на перебір підписів.
    fn mft_extents(&mut self) -> Option<Vec<(u64, u64)>> {
        let primary = self.boot.mft_offset();
        let record = self
            .read_record_at(primary)
            .or_else(|_| self.read_record_at(self.boot.mft_mirror_offset()))
            .ok()?;

        if record.record_number != MFT_RECORD_MFT && record.record_number != 0 {
            // Це не $MFT; вказівник у завантажувальному записі хибний.
            return None;
        }

        match record.data_attribute()? {
            DataAttribute::NonResident { runs, .. } => {
                let cluster = self.boot.cluster_size as u64;
                let mut extents = Vec::new();
                for run in runs {
                    let lcn = run.lcn?; // розріджений $MFT не має сенсу
                    extents.push((
                        self.cluster_offset(lcn),
                        run.length_clusters.saturating_mul(cluster),
                    ));
                }
                if extents.is_empty() {
                    None
                } else {
                    Some(extents)
                }
            }
            DataAttribute::Resident { .. } => None,
        }
    }

    /// Перелічити файли найкращим доступним способом.
    pub fn scan(
        &mut self,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        match self.mft_extents() {
            Some(extents) => self.scan_extents(extents, ScanMethod::MftRunlist, cancel, progress),
            None => {
                // Перебрати весь том з кроком у розмір запису MFT.
                let total = self.dev.len();
                self.scan_extents(
                    vec![(0, total)],
                    ScanMethod::SignatureSweep,
                    cancel,
                    progress,
                )
            }
        }
    }

    /// Примусово перебрати підписи, навіть коли `$MFT` здається читабельним.
    ///
    /// Корисно, коли MFT цілий лише частково: перебір ловить і ті записи, яких
    /// runlist уже не охоплює.
    pub fn scan_by_signature(
        &mut self,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        let total = self.dev.len();
        self.scan_extents(
            vec![(0, total)],
            ScanMethod::SignatureSweep,
            cancel,
            progress,
        )
    }

    fn scan_extents(
        &mut self,
        extents: Vec<(u64, u64)>,
        method: ScanMethod,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        let rec_size = self.boot.mft_record_size as u64;
        let volume_len = self.dev.len();
        // Записи розміщуються по межах свого розміру; перебір іде з кроком у
        // два сектори, щоб знайти навіть зсунутий MFT.
        let step = match method {
            ScanMethod::MftRunlist => rec_size,
            ScanMethod::SignatureSweep => rec_size.min(self.boot.bytes_per_sector as u64 * 2),
        };

        let total: u64 = extents.iter().map(|(_, len)| *len).sum();
        let mut entries: Vec<FileEntry> = Vec::new();
        let mut seen: HashMap<u64, usize> = HashMap::new();
        let mut records_examined = 0u64;
        let mut damaged_records = 0u64;
        let mut nameless_records = 0u64;
        let mut cancelled = false;
        let mut signature = vec![0u8; 4];

        'outer: for (base, len) in extents {
            let mut at = base;
            let end = (base + len).min(volume_len);
            while at + rec_size <= end {
                if records_examined % 512 == 0 {
                    if cancel.load(Ordering::Relaxed) {
                        cancelled = true;
                        break 'outer;
                    }
                    progress(ScanProgress {
                        records_examined,
                        entries_found: entries.len() as u64,
                        offset: at,
                        total,
                    });
                }
                records_examined += 1;

                // Дешева перевірка підпису, перш ніж читати запис цілком.
                if self.dev.read_at(at, &mut signature).is_err() {
                    at += step;
                    continue;
                }
                if &signature != b"FILE" {
                    at += step;
                    continue;
                }

                match self.read_record_at(at) {
                    Ok(rec) => {
                        // Записи-продовження описують атрибути базового запису.
                        if rec.base_record.number() != 0 {
                            at += step;
                            continue;
                        }
                        match FileEntry::from_record(&rec) {
                            Some(entry) => {
                                // Перебір може натрапити на той самий запис двічі;
                                // перевага — копії, що використовується.
                                match seen.get(&entry.record_number) {
                                    Some(&idx) => {
                                        if entry.in_use && !entries[idx].in_use {
                                            entries[idx] = entry;
                                        }
                                    }
                                    None => {
                                        seen.insert(entry.record_number, entries.len());
                                        entries.push(entry);
                                    }
                                }
                            }
                            None => nameless_records += 1,
                        }
                    }
                    Err(_) => damaged_records += 1,
                }

                at += step;
            }
        }

        progress(ScanProgress {
            records_examined,
            entries_found: entries.len() as u64,
            offset: total,
            total,
        });

        Ok(ScanResult {
            boot: self.boot.clone(),
            boot_source: self.boot_source,
            method,
            entries,
            damaged_records,
            nameless_records,
            cancelled,
        })
    }

    /// Прочитати вміст файлу; повертає дані і скільки байтів втрачено.
    ///
    /// Нечитані кластери заповнюються нулями, щоб решта файлу лягла на свої
    /// зсуви, а втрата повертається, а не ховається.
    pub fn read_file_data(&mut self, entry: &FileEntry) -> io::Result<(Vec<u8>, u64)> {
        let Some(data) = &entry.data else {
            return Err(bad("у записі немає атрибута $DATA"));
        };
        if let Some(kind) = data.unsupported_encoding() {
            return Err(bad(format!(
                "потік {kind} — flashrec не вміє його розкодувати, файл пропущено, щоб не записати сміття"
            )));
        }

        match data {
            DataAttribute::Resident { bytes } => Ok((bytes.clone(), 0)),
            DataAttribute::NonResident {
                real_size, runs, ..
            } => {
                let cluster = self.boot.cluster_size as usize;
                let want = *real_size as usize;
                let mut out = Vec::with_capacity(want.min(64 << 20));
                let mut lost = 0u64;
                let mut buf = vec![0u8; cluster];

                'runs: for run in runs {
                    for i in 0..run.length_clusters {
                        if out.len() >= want {
                            break 'runs;
                        }
                        match run.lcn {
                            // Розріджений фрагмент справді складається з нулів — це не втрата.
                            None => buf.fill(0),
                            Some(lcn) => {
                                let offset = self.cluster_offset(lcn + i as i64);
                                if self.dev.read_at(offset, &mut buf).is_err() {
                                    buf.fill(0);
                                    lost += cluster as u64;
                                }
                            }
                        }
                        let take = cluster.min(want - out.len());
                        out.extend_from_slice(&buf[..take]);
                    }
                }

                // Runlist коротший за записаний розмір — значить, бракує фрагментів.
                if out.len() < want {
                    lost += (want - out.len()) as u64;
                    out.resize(want, 0);
                }
                Ok((out, lost))
            }
        }
    }

    /// Відновити повні шляхи для кожного запису, ідучи за батьківськими посиланнями.
    pub fn build_paths(&self, result: &ScanResult) -> HashMap<u64, PathBuf> {
        let by_number: HashMap<u64, &FileEntry> = result
            .entries
            .iter()
            .map(|e| (e.record_number, e))
            .collect();

        let mut paths: HashMap<u64, PathBuf> = HashMap::new();
        for entry in &result.entries {
            let mut components: Vec<&str> = Vec::new();
            let mut current = entry;
            let mut guard = 0;

            loop {
                components.push(&current.name);
                // Запис 5 — корінь тому; тут зупиняємось.
                if current.parent_number == MFT_RECORD_ROOT
                    || current.parent_number == current.record_number
                {
                    break;
                }
                guard += 1;
                // Пошкоджений MFT може містити цикли батьківських посилань.
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

/// Фільтри, що застосовуються під час запису файлів.
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// Записувати й файли, чий запис MFT позначено видаленим.
    pub include_deleted: bool,
    /// Записувати й службові файли NTFS (`$MFT`, `$LogFile`, записи < 16).
    pub include_system: bool,
    pub min_size: u64,
    pub max_size: Option<u64>,
    /// Лишити тільки файли, чиє ім'я закінчується одним із цих розширень
    /// (малими літерами, без крапки).
    pub extensions: Vec<String>,
    /// Лишити тільки ці записи MFT — те, що користувач обрав у списку.
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
        if !self.include_system && entry.record_number < FIRST_USER_RECORD {
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
pub fn recover_files<D: BlockDevice>(
    volume: &mut NtfsVolume<D>,
    result: &ScanResult,
    dest: impl AsRef<Path>,
    opts: &RecoveryOptions,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(RecoveryProgress),
) -> io::Result<RecoveryReport> {
    let dest = dest.as_ref();
    fs::create_dir_all(dest)?;
    let paths = volume.build_paths(result);

    let candidates: Vec<&FileEntry> = result.entries.iter().filter(|e| opts.accepts(e)).collect();
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

/// Зробити один компонент шляху безпечним для Windows.
///
/// Заборонені символи й крапки/пробіли в кінці замінюються; ім'я, що збіглося б
/// з назвою пристрою (`CON`, `NUL`, …), отримує префікс.
fn sanitize_component(name: &str) -> String {
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
        out.insert_str(0, "_");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let entry = FileEntry {
            record_number: 100,
            sequence: 1,
            parent_number: 5,
            name: "photo.jpg".into(),
            is_directory: false,
            in_use: false,
            size: 1024,
            data: None,
            timestamps: None,
            named_streams: Vec::new(),
        };

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

    #[test]
    fn system_records_are_excluded_by_default() {
        let entry = FileEntry {
            record_number: 0,
            sequence: 1,
            parent_number: 5,
            name: "$MFT".into(),
            is_directory: false,
            in_use: true,
            size: 4096,
            data: None,
            timestamps: None,
            named_streams: Vec::new(),
        };
        assert!(!RecoveryOptions::default().accepts(&entry));
    }
}
