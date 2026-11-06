//! Читання цілого тому NTFS: знайти MFT і перелічити файли.
//!
//! Шляхів два. Звичайний іде за runlist-ом самого `$MFT`. Коли той не
//! читається — а на диску, що став RAW, так і буває, — том перебирається в
//! пошуках підписів `FILE`, і це знаходить записи, на які зламаний MFT уже не
//! вказує. В обох випадках дерево тек відновлюють посилання на батьківську теку.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::record::{DataAttribute, MftRecord};
use super::{bad, read_boot, NtfsBoot, FIRST_USER_RECORD, MFT_RECORD_MFT, MFT_RECORD_ROOT};
use crate::files::{
    sanitize_component, BootSource, FileEntry, Filesystem, ReadFiles, ScanMethod, ScanProgress,
    ScanResult,
};
use crate::reader::BlockDevice;

/// Чи це службовий файл NTFS, а не дані користувача.
///
/// Номера записів замало: `$Extend\$RmMetadata\$TxfLog\…` мають номери вище 16,
/// хоча належать самій файловій системі. Тому службовим вважається й усе, чий
/// перший компонент шляху починається з `$` — у корені тому такі імена має
/// лише NTFS.
pub fn is_ntfs_metadata(record_number: u64, path: &Path) -> bool {
    record_number < FIRST_USER_RECORD
        || path
            .components()
            .next()
            .is_some_and(|c| c.as_os_str().to_string_lossy().starts_with('$'))
}

/// Файл або тека з одного запису MFT.
fn entry_from_record(rec: &MftRecord) -> Option<FileEntry> {
    let name_attr = rec.file_name()?;
    let data = rec.data_attribute();
    Some(FileEntry {
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
        caveat: None,
    })
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
            ScanMethod::SignatureSweep => rec_size.min(self.boot.bytes_per_sector as u64 * 2),
            _ => rec_size,
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
                        match entry_from_record(&rec) {
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
            filesystem: Filesystem::Ntfs,
            boot_source: self.boot_source,
            method,
            root: MFT_RECORD_ROOT,
            entries,
            damaged_records,
            nameless_records,
            cancelled,
        })
    }
}

impl<D: BlockDevice> ReadFiles for NtfsVolume<D> {
    fn read_file_data(&mut self, entry: &FileEntry) -> io::Result<(Vec<u8>, u64)> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_recognised_by_number_and_by_path() {
        assert!(is_ntfs_metadata(0, Path::new("$MFT")));
        assert!(is_ntfs_metadata(
            40,
            Path::new(r"$Extend\$RmMetadata\$TxfLog\$TxfLogContainer00000000000000000001")
        ));
        assert!(!is_ntfs_metadata(40, Path::new(r"all\scripts\trace.log")));
        // `$` усередині шляху, а не в корені, — звичайний файл користувача.
        assert!(!is_ntfs_metadata(40, Path::new(r"звіти\$чернетка.docx")));
    }
}
