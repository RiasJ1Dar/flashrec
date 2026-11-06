//! exFAT — файлова система флешок і карт пам'яті понад 32 ГіБ.
//!
//! Будова схожа на FAT32: таблиця FAT і область кластерів. Але теки складаються
//! з наборів записів: основний запис файлу (`0x85`), запис потоку (`0xC0`) з
//! першим кластером і розміром і записи імені (`0xC1`). Набір захищено
//! контрольною сумою, тож у сирих байтах його легко впізнати. Видалення лише
//! знімає старший біт типу (`0x85` → `0x05`), а все інше лишається.
//!
//! Файли, що лежать підряд, позначено прапорцем «без ланцюжка FAT» — їхній
//! вміст знаходиться і після видалення, і після втрати таблиці FAT. Котрі
//! кластери зайняті, каже окрема бітова карта; нею перевіряється, чи вміст
//! видаленого файлу ще не віддано іншому.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::cluster::{
    assemble, bad, contiguous_runs, data_attribute, read_clusters, read_runs, runs_from_clusters,
    FatTable, Found, Geometry, BAD, CAVEAT_CONTIGUOUS, END, ROOT_ID,
};
use crate::files::{
    BootSource, FileEntry, Filesystem, ReadFiles, ScanMethod, ScanProgress, ScanResult,
};
use crate::ntfs::civil_to_filetime;
use crate::ntfs::record::{DataRun, Timestamps};
use crate::reader::{u16_at, u32_at, u64_at, BlockDevice};

/// Тека exFAT може мати до 256 МіБ записів, але справжні теки на флешках
/// значно менші; далі цього ланцюжок вважається зіпсованим.
const MAX_DIR_BYTES: u64 = 32 << 20;

const TYPE_BITMAP: u8 = 0x81;
const TYPE_FILE: u8 = 0x85;
const TYPE_STREAM: u8 = 0xC0;
const TYPE_NAME: u8 = 0xC1;
/// Старший біт типу — «запис використовується».
const IN_USE: u8 = 0x80;

const FLAG_NO_FAT_CHAIN: u8 = 0x02;
const ATTR_DIRECTORY: u16 = 0x10;

/// Завантажувальний сектор exFAT.
#[derive(Debug, Clone)]
pub struct ExFatBoot {
    pub bytes_per_sector: u32,
    pub cluster_size: u64,
    pub fat_offset: u64,
    pub fat_length: u64,
    pub heap_offset: u64,
    pub cluster_count: u32,
    pub root_cluster: u32,
    pub num_fats: u32,
    pub volume_length: u64,
}

impl ExFatBoot {
    pub fn parse(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < 512 {
            return Err(bad("буфер завантажувального сектора коротший за 512 байтів"));
        }
        if &buf[3..11] != b"EXFAT   " {
            return Err(bad("немає підпису EXFAT на зсуві 3"));
        }
        if buf[510] != 0x55 || buf[511] != 0xAA {
            return Err(bad("немає підпису 0x55AA"));
        }
        // У exFAT поля старого BPB мусять бути нулями — так його не сплутати з FAT.
        if buf[0x0B..0x40].iter().any(|&b| b != 0) {
            return Err(bad("поля BPB не нульові — це не exFAT"));
        }
        let bps_shift = buf[0x6C] as u32;
        let spc_shift = buf[0x6D] as u32;
        if !(9..=12).contains(&bps_shift) || bps_shift + spc_shift > 25 {
            return Err(bad("неправдоподібний розмір сектора або кластера"));
        }
        let bytes_per_sector = 1u32 << bps_shift;
        let sector = bytes_per_sector as u64;
        let num_fats = buf[0x6E] as u32;
        if !(1..=2).contains(&num_fats) {
            return Err(bad("неправдоподібна кількість таблиць FAT"));
        }
        let cluster_count = u32_at(buf, 0x5C);
        let root_cluster = u32_at(buf, 0x60);
        if cluster_count == 0 || root_cluster < 2 || root_cluster as u64 >= cluster_count as u64 + 2 {
            return Err(bad("неправдоподібна кількість кластерів або корінь"));
        }
        Ok(Self {
            bytes_per_sector,
            cluster_size: sector << spc_shift,
            fat_offset: u32_at(buf, 0x50) as u64 * sector,
            fat_length: u32_at(buf, 0x54) as u64 * sector,
            heap_offset: u32_at(buf, 0x58) as u64 * sector,
            cluster_count,
            root_cluster,
            num_fats,
            volume_length: u64_at(buf, 0x48) * sector,
        })
    }

    fn geometry(&self) -> Geometry {
        Geometry {
            heap_offset: self.heap_offset,
            cluster_size: self.cluster_size,
            cluster_count: self.cluster_count,
        }
    }

    fn decode_fat(&self, raw: &[u8]) -> Vec<u32> {
        let n = (self.cluster_count as usize + 2).min(raw.len() / 4);
        (0..n)
            .map(|i| match u32_at(raw, i * 4) {
                0xFFFF_FFF7 => BAD,
                v if v >= 0xFFFF_FFF8 => END,
                v => v,
            })
            .collect()
    }
}

/// Основний завантажувальний сектор, а якщо він пошкоджений — резервний із
/// сектора 12 (exFAT тримає повну копію завантажувальної області).
pub fn read_boot<D: BlockDevice>(dev: &mut D) -> io::Result<(ExFatBoot, BootSource)> {
    let mut buf = vec![0u8; 512];
    if dev.read_at(0, &mut buf).is_ok() {
        if let Ok(boot) = ExFatBoot::parse(&buf) {
            return Ok((boot, BootSource::Primary));
        }
    }
    for sector in [512u64, 1024, 2048, 4096] {
        let offset = 12 * sector;
        if dev.read_at(offset, &mut buf).is_ok() {
            if let Ok(boot) = ExFatBoot::parse(&buf) {
                if boot.bytes_per_sector as u64 == sector {
                    return Ok((boot, BootSource::Backup { offset }));
                }
            }
        }
    }
    Err(bad(
        "не вдалося розібрати ні основний, ні резервний завантажувальний сектор exFAT",
    ))
}

/// Контрольна сума набору записів; байти 2–3 першого запису — сама сума.
fn set_checksum(set: &[u8]) -> u16 {
    set.iter().enumerate().fold(0u16, |sum, (i, &b)| {
        if i == 2 || i == 3 {
            sum
        } else {
            sum.rotate_right(1).wrapping_add(b as u16)
        }
    })
}

/// Мітка часу exFAT → FILETIME, переведений в UTC, якщо записано пояс.
fn exfat_time(stamp: u32, centis: u8, utc_offset: u8) -> Option<u64> {
    if stamp == 0 {
        return None;
    }
    let ft = civil_to_filetime(
        1980 + (stamp >> 25) as i64,
        (stamp >> 21) & 0x0F,
        (stamp >> 16) & 0x1F,
        (stamp >> 11) & 0x1F,
        (stamp >> 5) & 0x3F,
        (stamp & 0x1F) * 2 + centis as u32 / 100,
        centis as u32 % 100,
    )?;
    if utc_offset & 0x80 == 0 {
        return Some(ft); // пояс не записано — місцевий час як є
    }
    // Сім бітів зі знаком, кроками по 15 хвилин.
    let quarters = ((utc_offset << 1) as i8 >> 1) as i64;
    let shifted = ft as i64 - quarters * 15 * 60 * 10_000_000;
    u64::try_from(shifted).ok()
}

/// Чи позначено кластер зайнятим у бітовій карті. Без карти — невідомо, і
/// тоді вміст не відкидається.
fn is_allocated(bitmap: &Option<Vec<u8>>, cluster: u32) -> bool {
    match bitmap {
        Some(map) if cluster >= 2 => {
            let i = (cluster - 2) as usize;
            map.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0)
        }
        _ => false,
    }
}

/// Один розібраний набір записів файлу.
struct EntrySet {
    offset: u64,
    name: String,
    is_dir: bool,
    deleted: bool,
    no_fat_chain: bool,
    first_cluster: u32,
    valid_length: u64,
    length: u64,
    timestamps: Option<Timestamps>,
}

/// Спробувати розібрати набір записів, що починається з `buf[at]`.
///
/// Повертає набір і скільки записів він займає, або `None`, якщо це не
/// цілий набір із правильною контрольною сумою.
fn parse_set(buf: &[u8], at: usize) -> Option<(EntrySet, usize, usize)> {
    let primary = &buf[at..at + 32];
    let deleted = primary[0] & IN_USE == 0;
    if primary[0] | IN_USE != TYPE_FILE {
        return None;
    }
    let secondary = primary[1] as usize;
    if !(2..=18).contains(&secondary) {
        return None;
    }
    let len = (secondary + 1) * 32;
    if at + len > buf.len() {
        return None;
    }
    // Сума рахувалась, поки набір був живий: повернути біти «використовується».
    let mut set = buf[at..at + len].to_vec();
    for e in set.chunks_exact_mut(32) {
        if deleted {
            if e[0] & IN_USE != 0 {
                return None; // живий запис посеред видаленого набору — чужий
            }
            e[0] |= IN_USE;
        } else if e[0] & IN_USE == 0 {
            return None;
        }
    }
    if set_checksum(&set) != u16_at(&set, 2) {
        return None;
    }

    let stream = &set[32..64];
    if stream[0] != TYPE_STREAM {
        return None;
    }
    let name_length = stream[3] as usize;
    let mut units: Vec<u16> = Vec::with_capacity(name_length);
    let mut name_entries = 0usize;
    for e in set[64..].chunks_exact(32) {
        if e[0] != TYPE_NAME {
            break; // далі необов'язкові записи постачальників
        }
        name_entries += 1;
        for j in 0..15 {
            if units.len() < name_length {
                units.push(u16_at(e, 2 + j * 2));
            }
        }
    }
    if name_entries == 0 {
        return None;
    }

    let p = &set[..32];
    let modified = exfat_time(u32_at(p, 12), p[21], p[23]);
    Some((
        EntrySet {
            offset: 0,
            name: String::from_utf16_lossy(&units),
            is_dir: u16_at(p, 4) & ATTR_DIRECTORY != 0,
            deleted,
            no_fat_chain: stream[1] & FLAG_NO_FAT_CHAIN != 0,
            first_cluster: u32_at(stream, 20),
            valid_length: u64_at(stream, 8),
            length: u64_at(stream, 24),
            timestamps: modified.map(|m| Timestamps {
                created: exfat_time(u32_at(p, 8), p[20], p[22]).unwrap_or(0),
                modified: m,
                mft_changed: m,
                accessed: exfat_time(u32_at(p, 16), 0, p[24]).unwrap_or(0),
            }),
        },
        secondary + 1,
        name_length,
    ))
}

/// Том exFAT, відкритий на читання.
pub struct ExFatVolume<D: BlockDevice> {
    dev: D,
    pub boot: ExFatBoot,
    pub boot_source: BootSource,
    fat: FatTable,
    geo: Geometry,
    /// Бітова карта зайнятих кластерів; `None`, якщо її не знайдено.
    bitmap: Option<Vec<u8>>,
}

struct Walk {
    found: Vec<Found>,
    ids: HashSet<u64>,
    visited: HashSet<u32>,
    owner: HashMap<u32, u32>,
    queue: VecDeque<Dir>,
    damaged: u64,
    nameless: u64,
}

/// Тека, яку ще треба прочитати.
#[derive(Clone, Copy)]
struct Dir {
    first: u32,
    length: u64,
    no_fat_chain: bool,
    live: bool,
}

impl<D: BlockDevice> ExFatVolume<D> {
    pub fn open(mut dev: D) -> io::Result<Self> {
        let (boot, boot_source) = read_boot(&mut dev)?;
        let copies: Vec<u64> = (0..boot.num_fats)
            .map(|i| boot.fat_offset + i as u64 * boot.fat_length)
            .collect();
        let fat_bytes = ((boot.cluster_count as u64 + 2) * 4).min(boot.fat_length);
        let fat = FatTable::load(&mut dev, &copies, fat_bytes, |raw| boot.decode_fat(raw));
        let geo = boot.geometry();
        let mut vol = Self {
            dev,
            boot,
            boot_source,
            fat,
            geo,
            bitmap: None,
        };
        vol.bitmap = vol.load_bitmap();
        Ok(vol)
    }

    pub fn describe(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "завантажувальний запис: {}; exFAT, кластер {} байтів, кластерів {}",
            self.boot_source.describe(),
            self.boot.cluster_size,
            self.boot.cluster_count
        )];
        if self.fat.unreadable_bytes > 0 {
            lines.push(format!(
                "УВАГА: {} байтів таблиці FAT не прочиталися — фрагментовані файли там обірвані",
                self.fat.unreadable_bytes
            ));
        }
        if self.bitmap.is_none() {
            lines.push(
                "УВАГА: бітової карти кластерів не знайдено — не перевірити, чи вміст видалених файлів ще не перезаписано"
                    .to_string(),
            );
        }
        lines
    }

    /// Кластери теки: за FAT, або підряд, якщо так позначено.
    fn dir_clusters(&self, dir: Dir) -> Vec<u32> {
        let limit = if dir.length > 0 {
            self.geo.clusters_for(dir.length.min(MAX_DIR_BYTES))
        } else {
            self.geo.clusters_for(MAX_DIR_BYTES)
        };
        if dir.no_fat_chain {
            return (0..limit)
                .map(|i| dir.first.saturating_add(i as u32))
                .take_while(|&c| self.geo.is_valid(c))
                .collect();
        }
        let chain = self.fat.chain(&self.geo, dir.first, limit);
        if dir.live || chain.complete {
            chain.clusters
        } else {
            vec![dir.first]
        }
    }

    /// Знайти в корені запис бітової карти й прочитати її.
    fn load_bitmap(&mut self) -> Option<Vec<u8>> {
        let root = Dir {
            first: self.boot.root_cluster,
            length: 0,
            no_fat_chain: false,
            live: true,
        };
        let clusters = self.dir_clusters(root);
        let (buf, _) = read_clusters(&mut self.dev, &self.geo, &clusters);
        let e = buf
            .chunks_exact(32)
            .take_while(|e| e[0] != 0)
            .find(|e| e[0] == TYPE_BITMAP && e[1] & 1 == 0)?;
        let first = u32_at(e, 20);
        let length = u64_at(e, 24);
        if length < (self.geo.cluster_count as u64).div_ceil(8) || length > 64 << 20 {
            return None;
        }
        let needed = self.geo.clusters_for(length);
        let chain = self.fat.chain(&self.geo, first, needed);
        let clusters = if chain.complete && chain.clusters.len() as u64 == needed {
            chain.clusters
        } else {
            (0..needed).map(|i| first + i as u32).collect()
        };
        let (mut bytes, damaged) = read_clusters(&mut self.dev, &self.geo, &clusters);
        if damaged {
            return None;
        }
        bytes.truncate(length as usize);
        Some(bytes)
    }

    pub fn scan(
        &mut self,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        self.run(false, cancel, progress)
    }

    /// Обійти дерево і перебрати всі кластери в пошуках наборів записів із
    /// правильною контрольною сумою.
    pub fn scan_deep(
        &mut self,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        self.run(true, cancel, progress)
    }

    fn run(
        &mut self,
        sweep: bool,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        let mut w = Walk {
            found: Vec::new(),
            ids: HashSet::new(),
            visited: HashSet::new(),
            owner: HashMap::new(),
            queue: VecDeque::new(),
            damaged: 0,
            nameless: 0,
        };
        let total = self.dev.len();
        w.queue.push_back(Dir {
            first: self.boot.root_cluster,
            length: 0,
            no_fat_chain: false,
            live: true,
        });
        let mut cancelled = self.drain(&mut w, cancel, progress, total);

        if sweep && !cancelled {
            let cs = self.geo.cluster_size as usize;
            let mut buf = vec![0u8; cs];
            for c in 2..self.geo.cluster_count + 2 {
                if c % 1024 == 0 {
                    if cancel.load(Ordering::Relaxed) {
                        cancelled = true;
                        break;
                    }
                    progress(ScanProgress {
                        records_examined: c as u64,
                        entries_found: w.found.len() as u64,
                        offset: self.geo.offset(c),
                        total,
                    });
                }
                if w.owner.contains_key(&c) {
                    continue;
                }
                if self.dev.read_at(self.geo.offset(c), &mut buf).is_err() {
                    continue;
                }
                // Дешевий відсів: у кластері теки є хоч один запис файлу.
                if !buf
                    .chunks_exact(32)
                    .any(|e| e[0] | IN_USE == TYPE_FILE)
                {
                    continue;
                }
                let base = self.geo.offset(c);
                let before = w.found.len();
                self.take_sets(&mut w, &buf, &|i| base + i as u64, c, true, false);
                if w.found.len() > before {
                    cancelled |= self.drain(&mut w, cancel, progress, total);
                    if cancelled {
                        break;
                    }
                }
            }
        }

        progress(ScanProgress {
            records_examined: w.found.len() as u64,
            entries_found: w.found.len() as u64,
            offset: total,
            total,
        });

        let owner = w.owner;
        let entries: Vec<FileEntry> =
            assemble(w.found, &|c| owner.get(&c).copied(), &HashMap::new());
        Ok(ScanResult {
            filesystem: Filesystem::ExFat,
            boot_source: self.boot_source,
            method: if sweep {
                ScanMethod::DirectorySweep
            } else {
                ScanMethod::DirectoryTree
            },
            root: ROOT_ID,
            entries,
            damaged_records: w.damaged,
            nameless_records: w.nameless,
            cancelled,
        })
    }

    fn drain(
        &mut self,
        w: &mut Walk,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
        total: u64,
    ) -> bool {
        while let Some(dir) = w.queue.pop_front() {
            if cancel.load(Ordering::Relaxed) {
                return true;
            }
            if !w.visited.insert(dir.first) {
                continue;
            }
            progress(ScanProgress {
                records_examined: w.found.len() as u64,
                entries_found: w.found.len() as u64,
                offset: self.geo.offset(dir.first).min(total),
                total,
            });
            let clusters = self.dir_clusters(dir);
            let is_root = dir.first == self.boot.root_cluster;
            for &c in &clusters {
                w.owner
                    .entry(c)
                    .or_insert(if is_root { 0 } else { dir.first });
            }
            let (buf, damaged) = read_clusters(&mut self.dev, &self.geo, &clusters);
            w.damaged += damaged as u64;
            let geo = self.geo;
            let offset_of = |i: usize| {
                geo.offset(clusters[i / geo.cluster_size as usize]) + (i as u64 % geo.cluster_size)
            };
            let container = if is_root { 0 } else { dir.first };
            self.take_sets(w, &buf, &offset_of, container, dir.live, true);
        }
        false
    }

    /// Знайти в байтах теки набори записів і поставити підтеки в чергу.
    fn take_sets(
        &self,
        w: &mut Walk,
        buf: &[u8],
        offset_of: &dyn Fn(usize) -> u64,
        container: u32,
        parent_live: bool,
        // Запис типу 0 позначає кінець теки. Кластер, знайдений перебором, —
        // не обов'язково початок теки, тож його читають до кінця.
        stop_at_end: bool,
    ) {
        let mut at = 0usize;
        while at + 32 <= buf.len() {
            if buf[at] == 0 && stop_at_end {
                break; // далі тека не використовувалась
            }
            if buf[at] | IN_USE != TYPE_FILE {
                at += 32;
                continue;
            }
            let Some((mut set, count, name_length)) = parse_set(buf, at) else {
                // У справжній теці це зіпсований набір. У кластері, знайденому
                // перебором, байт 0x85 — найчастіше просто вміст чужого файлу.
                if buf[at] == TYPE_FILE && stop_at_end {
                    w.damaged += 1;
                }
                at += 32;
                continue;
            };
            set.offset = offset_of(at);
            at += count * 32;
            if name_length == 0 || set.name.is_empty() {
                w.nameless += 1;
                continue;
            }
            if !w.ids.insert(set.offset) {
                continue;
            }
            let deleted = set.deleted || !parent_live;
            if set.is_dir && self.geo.is_valid(set.first_cluster) {
                w.queue.push_back(Dir {
                    first: set.first_cluster,
                    length: set.length,
                    no_fat_chain: set.no_fat_chain,
                    live: !deleted,
                });
            }
            let (data, caveat) = if set.is_dir {
                (None, None)
            } else {
                let (runs, caveat) = self.file_runs(&set, deleted);
                (
                    Some(data_attribute(
                        set.length,
                        set.valid_length,
                        runs,
                        self.geo.cluster_size,
                    )),
                    caveat,
                )
            };
            w.found.push(Found {
                id: set.offset,
                container,
                name: set.name,
                is_dir: set.is_dir,
                deleted,
                size: set.length,
                first_cluster: set.first_cluster,
                data,
                timestamps: set.timestamps,
                caveat,
            });
        }
    }

    /// Де лежить вміст файлу. Позначений «без ланцюжка» лежить підряд —
    /// це точне знання, а не здогад. Інакше — за FAT; коли ланцюжка там уже
    /// немає, кластери беруться підряд.
    fn file_runs(&self, set: &EntrySet, deleted: bool) -> (Vec<DataRun>, Option<&'static str>) {
        let needed = self.geo.clusters_for(set.length);
        if needed == 0 || !self.geo.is_valid(set.first_cluster) {
            return (Vec::new(), None);
        }
        if set.no_fat_chain {
            return (contiguous_runs(set.first_cluster, needed), None);
        }
        let chain = self.fat.chain(&self.geo, set.first_cluster, needed);
        if chain.complete && chain.clusters.len() as u64 == needed {
            return (runs_from_clusters(&chain.clusters), None);
        }
        if !deleted && chain.clusters.len() > 1 {
            return (runs_from_clusters(&chain.clusters), None);
        }
        (contiguous_runs(set.first_cluster, needed), Some(CAVEAT_CONTIGUOUS))
    }
}

impl<D: BlockDevice> ReadFiles for ExFatVolume<D> {
    fn read_file_data(&mut self, entry: &FileEntry) -> io::Result<(Vec<u8>, u64)> {
        let Some(data) = &entry.data else {
            return Err(bad("це тека, а не файл"));
        };
        // Кластер видаленого файлу, який бітова карта вже показує зайнятим,
        // належить іншому файлу.
        let check = !entry.in_use;
        let bitmap = &self.bitmap;
        let occupied = |c: u32| check && is_allocated(bitmap, c);
        Ok(read_runs(&mut self.dev, &self.geo, data, &occupied))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_skips_its_own_bytes() {
        let mut set = vec![0u8; 96];
        set[0] = TYPE_FILE;
        set[1] = 2;
        set[32] = TYPE_STREAM;
        set[64] = TYPE_NAME;
        let sum = set_checksum(&set);
        set[2..4].copy_from_slice(&sum.to_le_bytes());
        assert_eq!(set_checksum(&set), sum);
    }

    fn file_set(name: &str, deleted: bool) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let name_entries = units.len().div_ceil(15);
        let mut set = vec![0u8; (2 + name_entries) * 32];
        set[0] = TYPE_FILE;
        set[1] = (1 + name_entries) as u8;
        set[32] = TYPE_STREAM;
        set[33] = 0x01 | FLAG_NO_FAT_CHAIN;
        set[35] = units.len() as u8;
        set[40..48].copy_from_slice(&1000u64.to_le_bytes());
        set[52..56].copy_from_slice(&7u32.to_le_bytes());
        set[56..64].copy_from_slice(&1000u64.to_le_bytes());
        for (k, u) in units.iter().enumerate() {
            let e = 64 + (k / 15) * 32;
            set[e] = TYPE_NAME;
            let at = e + 2 + (k % 15) * 2;
            set[at..at + 2].copy_from_slice(&u.to_le_bytes());
        }
        let sum = set_checksum(&set);
        set[2..4].copy_from_slice(&sum.to_le_bytes());
        if deleted {
            for e in set.chunks_exact_mut(32) {
                e[0] &= !IN_USE;
            }
        }
        set
    }

    #[test]
    fn parses_live_and_deleted_sets() {
        let name = "дуже довга назва файлу для exFAT.jpg";
        let (set, count, _) = parse_set(&file_set(name, false), 0).unwrap();
        assert_eq!(set.name, name);
        assert!(!set.deleted);
        assert!(set.no_fat_chain);
        assert_eq!(set.first_cluster, 7);
        assert_eq!(count, 2 + name.encode_utf16().count().div_ceil(15));

        let (gone, _, _) = parse_set(&file_set(name, true), 0).unwrap();
        assert!(gone.deleted);
        assert_eq!(gone.name, name);

        let mut broken = file_set(name, false);
        broken[70] ^= 0xFF;
        assert!(parse_set(&broken, 0).is_none());
    }

    #[test]
    fn timestamps_apply_the_utc_offset() {
        // 2026-11-06 12:00:00, пояс +02:00 (8 чвертей години) → 10:00 UTC.
        let stamp = (46u32 << 25) | (11 << 21) | (6 << 16) | (12 << 11);
        let ft = exfat_time(stamp, 0, 0x80 | 8).unwrap();
        assert_eq!(crate::ntfs::format_filetime(ft), "2026-11-06 10:00:00");
        // -03:00 → 15:00 UTC
        let ft = exfat_time(stamp, 0, 0x80 | (-12i8 as u8 & 0x7F)).unwrap();
        assert_eq!(crate::ntfs::format_filetime(ft), "2026-11-06 15:00:00");
    }
}
