//! FAT12, FAT16 і FAT32 — файлові системи, якими відформатовано більшість флешок.
//!
//! Том складається з завантажувального сектора, однієї-двох копій таблиці FAT,
//! (для FAT12/16) кореневої теки фіксованого розміру і області даних. Тека — це
//! масив 32-байтних записів; довге ім'я зберігається в записах-попередниках
//! (LFN), а сам файл описує короткий запис 8.3 з першим кластером і розміром.
//!
//! Що рятує flashrec:
//! - пошкоджений завантажувальний сектор FAT32 — є резервний у секторі 6;
//! - нечитану першу копію FAT — читається друга;
//! - видалені файли (перший байт імені `0xE5`): вміст беруть підряд від
//!   першого кластера, бо ланцюжок видаленого файлу FAT уже стерто;
//! - теки після швидкого форматування: корінь і FAT порожні, але підтеки ще
//!   лежать в області даних і впізнаються за записами `.` і `..`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::cluster::{
    assemble, bad, contiguous_runs, data_attribute, read_clusters, read_runs, runs_from_clusters,
    FatTable, Found, Geometry, CAVEAT_CONTIGUOUS, BAD, END, FREE, ROOT_ID,
};
use crate::files::{
    BootSource, FileEntry, Filesystem, ReadFiles, ScanMethod, ScanProgress, ScanResult,
};
use crate::ntfs::civil_to_filetime;
use crate::ntfs::record::Timestamps;
use crate::reader::{u16_at, u32_at, BlockDevice};

/// Розмір теки, далі якого ланцюжок вважається зіпсованим: FAT дозволяє не
/// більше 65 536 записів по 32 байти.
const MAX_DIR_BYTES: u64 = 65_536 * 32;

/// Завантажувальний сектор (BPB) тому FAT.
#[derive(Debug, Clone)]
pub struct FatBoot {
    pub kind: Filesystem,
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_size: u32,
    pub reserved_sectors: u32,
    pub num_fats: u32,
    pub root_entries: u32,
    pub total_sectors: u64,
    pub fat_sectors: u64,
    /// Перший кластер кореневої теки (лише FAT32).
    pub root_cluster: u32,
    pub cluster_count: u32,
}

impl FatBoot {
    /// Розібрати завантажувальний сектор, відкинувши все, що не схоже на FAT.
    ///
    /// Перевірок багато навмисно: цим самим розбором шукають том у сирих
    /// байтах, і випадковий сектор не повинен пройти за FAT.
    pub fn parse(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < 512 {
            return Err(bad("буфер завантажувального сектора коротший за 512 байтів"));
        }
        if buf[510] != 0x55 || buf[511] != 0xAA {
            return Err(bad("немає підпису 0x55AA"));
        }
        if !matches!(buf[0], 0xEB | 0xE9) {
            return Err(bad("немає інструкції переходу на початку сектора"));
        }
        if &buf[3..11] == b"NTFS    " || &buf[3..11] == b"EXFAT   " {
            return Err(bad("це не FAT"));
        }

        let bytes_per_sector = u16_at(buf, 0x0B) as u32;
        if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
            return Err(bad(format!("неправдоподібний розмір сектора {bytes_per_sector}")));
        }
        let sectors_per_cluster = buf[0x0D] as u32;
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(bad(format!(
                "неправдоподібна кількість секторів на кластер {sectors_per_cluster}"
            )));
        }
        let reserved_sectors = u16_at(buf, 0x0E) as u32;
        let num_fats = buf[0x10] as u32;
        if reserved_sectors == 0 || !(1..=2).contains(&num_fats) {
            return Err(bad("неправдоподібні зарезервовані сектори або кількість FAT"));
        }
        let media = buf[0x15];
        if media != 0xF0 && media < 0xF8 {
            return Err(bad(format!("невідомий тип носія {media:#04x}")));
        }

        let root_entries = u16_at(buf, 0x11) as u32;
        let total16 = u16_at(buf, 0x13) as u64;
        let fat16 = u16_at(buf, 0x16) as u64;
        let total_sectors = if total16 != 0 {
            total16
        } else {
            u32_at(buf, 0x20) as u64
        };
        let fat_sectors = if fat16 != 0 {
            fat16
        } else {
            u32_at(buf, 0x24) as u64
        };
        if total_sectors == 0 || fat_sectors == 0 {
            return Err(bad("нульовий розмір тому або таблиці FAT"));
        }

        let root_dir_sectors = (root_entries as u64 * 32).div_ceil(bytes_per_sector as u64);
        let data_start = reserved_sectors as u64 + num_fats as u64 * fat_sectors + root_dir_sectors;
        if data_start >= total_sectors {
            return Err(bad("область даних починається за кінцем тому"));
        }
        let cluster_count = ((total_sectors - data_start) / sectors_per_cluster as u64)
            .min(0x0FFF_FFF5) as u32;

        // Тип FAT визначає лише кількість кластерів — так каже специфікація Microsoft.
        let kind = if cluster_count < 4085 {
            Filesystem::Fat12
        } else if cluster_count < 65_525 {
            Filesystem::Fat16
        } else {
            Filesystem::Fat32
        };
        let root_cluster = if kind == Filesystem::Fat32 {
            if root_entries != 0 || fat16 != 0 {
                return Err(bad("FAT32 із кореневою текою фіксованого розміру — суперечність"));
            }
            u32_at(buf, 0x2C)
        } else {
            if root_entries == 0 {
                return Err(bad("FAT12/16 без кореневої теки"));
            }
            0
        };

        let entry_bits: u64 = match kind {
            Filesystem::Fat12 => 12,
            Filesystem::Fat16 => 16,
            _ => 32,
        };
        if fat_sectors * bytes_per_sector as u64 * 8 < (cluster_count as u64 + 2) * entry_bits {
            return Err(bad("таблиця FAT замала для такої кількості кластерів"));
        }

        Ok(Self {
            kind,
            bytes_per_sector,
            sectors_per_cluster,
            cluster_size: bytes_per_sector * sectors_per_cluster,
            reserved_sectors,
            num_fats,
            root_entries,
            total_sectors,
            fat_sectors,
            root_cluster,
            cluster_count,
        })
    }

    fn fat_offset(&self, copy: u32) -> u64 {
        (self.reserved_sectors as u64 + copy as u64 * self.fat_sectors)
            * self.bytes_per_sector as u64
    }

    /// Зсув кореневої теки FAT12/16.
    fn root_dir_offset(&self) -> u64 {
        self.fat_offset(self.num_fats)
    }

    fn geometry(&self) -> Geometry {
        let root_bytes = (self.root_entries as u64 * 32)
            .div_ceil(self.bytes_per_sector as u64)
            * self.bytes_per_sector as u64;
        Geometry {
            heap_offset: self.root_dir_offset() + root_bytes,
            cluster_size: self.cluster_size as u64,
            cluster_count: self.cluster_count,
        }
    }

    /// Розкодувати таблицю в 32-бітні значення з позначками кінця й збою.
    fn decode_fat(&self, raw: &[u8]) -> Vec<u32> {
        let n = self.cluster_count as usize + 2;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            let (v, bad_mark, end_from) = match self.kind {
                Filesystem::Fat12 => {
                    let at = i * 3 / 2;
                    if at + 1 >= raw.len() {
                        break;
                    }
                    let pair = u16_at(raw, at) as u32;
                    let v = if i % 2 == 0 { pair & 0x0FFF } else { pair >> 4 };
                    (v, 0xFF7, 0xFF8)
                }
                Filesystem::Fat16 => {
                    if i * 2 + 1 >= raw.len() {
                        break;
                    }
                    (u16_at(raw, i * 2) as u32, 0xFFF7, 0xFFF8)
                }
                _ => {
                    if i * 4 + 3 >= raw.len() {
                        break;
                    }
                    (u32_at(raw, i * 4) & 0x0FFF_FFFF, 0x0FFF_FFF7, 0x0FFF_FFF8)
                }
            };
            out.push(if v >= end_from {
                END
            } else if v == bad_mark {
                BAD
            } else {
                v
            });
        }
        out
    }
}

/// Прочитати завантажувальний сектор, а якщо основний пошкоджено — резервну
/// копію FAT32 із сектора 6. FAT12/16 резервної копії не мають.
pub fn read_boot<D: BlockDevice>(dev: &mut D) -> io::Result<(FatBoot, BootSource)> {
    let mut buf = vec![0u8; 512];
    if dev.read_at(0, &mut buf).is_ok() {
        if let Ok(boot) = FatBoot::parse(&buf) {
            return Ok((boot, BootSource::Primary));
        }
    }
    for sector in [512u64, 1024, 2048, 4096] {
        let offset = 6 * sector;
        if dev.read_at(offset, &mut buf).is_ok() {
            if let Ok(boot) = FatBoot::parse(&buf) {
                if boot.kind == Filesystem::Fat32 && boot.bytes_per_sector as u64 == sector {
                    return Ok((boot, BootSource::Backup { offset }));
                }
            }
        }
    }
    Err(bad(
        "не вдалося розібрати ні основний завантажувальний сектор FAT, ні резервний FAT32",
    ))
}

/// Короткі імена 8.3 записано в OEM-кодуванні; для української Windows це CP866.
const CP866_HIGH: &str = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмноп\
░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀\
рстуфхцчшщъыьэюяЁёЄєЇїЎў°∙·√№¤■\u{A0}";

fn oem_char(b: u8) -> char {
    if b < 0x80 {
        b as char
    } else {
        CP866_HIGH.chars().nth(b as usize - 0x80).unwrap_or('_')
    }
}

/// Контрольна сума короткого імені, якою записи LFN прив'язані до свого файлу.
fn lfn_checksum(short: &[u8]) -> u8 {
    short[..11]
        .iter()
        .fold(0u8, |sum, &b| sum.rotate_right(1).wrapping_add(b))
}

/// Ім'я 8.3 з урахуванням позначок малих літер, які ставить Windows NT.
fn short_name(raw: &[u8], nt_flags: u8, first: u8) -> String {
    let decode = |bytes: &[u8], lower: bool| -> String {
        let s: String = bytes.iter().map(|&b| oem_char(b)).collect();
        let s = s.trim_end().to_string();
        if lower {
            s.to_lowercase()
        } else {
            s
        }
    };
    let mut base_bytes = raw[..8].to_vec();
    base_bytes[0] = first;
    let base = decode(&base_bytes, nt_flags & 0x08 != 0);
    let ext = decode(&raw[8..11], nt_flags & 0x10 != 0);
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// Частина довгого імені з одного запису LFN.
struct LfnPart {
    order: u8,
    checksum: u8,
    chars: [u16; 13],
}

impl LfnPart {
    fn parse(e: &[u8]) -> Self {
        let mut chars = [0u16; 13];
        let spans = [(1usize, 5usize), (14, 6), (28, 2)];
        let mut k = 0;
        for (start, count) in spans {
            for j in 0..count {
                chars[k] = u16_at(e, start + j * 2);
                k += 1;
            }
        }
        Self {
            order: e[0],
            checksum: e[13],
            chars,
        }
    }
}

/// Зібрати довге ім'я з частин, що передують короткому запису.
///
/// У живого файлу частини мусять іти від останньої (`0x40 | N`) до першої, і
/// контрольна сума — збігатися з коротким ім'ям. У видаленого порядкові номери
/// затерто `0xE5`, а перша літера короткого імені невідома, тож сума
/// перевіряється перебором цієї літери.
fn assemble_lfn(parts: &[LfnPart], short_raw: &[u8], deleted: bool) -> Option<String> {
    if parts.is_empty() || parts.len() > 20 {
        return None;
    }
    let checksum = parts[0].checksum;
    if parts.iter().any(|p| p.checksum != checksum) {
        return None;
    }
    if deleted {
        if parts.iter().any(|p| p.order != 0xE5) {
            return None;
        }
        let mut probe = short_raw[..11].to_vec();
        let matches = (0u8..=255).any(|c| {
            probe[0] = c;
            lfn_checksum(&probe) == checksum
        });
        if !matches {
            return None;
        }
    } else {
        let n = parts.len() as u8;
        if parts[0].order != (0x40 | n) {
            return None;
        }
        for (i, p) in parts.iter().enumerate().skip(1) {
            if p.order != n - i as u8 {
                return None;
            }
        }
        if lfn_checksum(short_raw) != checksum {
            return None;
        }
    }

    let mut units: Vec<u16> = Vec::new();
    for p in parts.iter().rev() {
        for &u in &p.chars {
            if u == 0x0000 || u == 0xFFFF {
                break;
            }
            units.push(u);
        }
    }
    let name = String::from_utf16_lossy(&units);
    (!name.is_empty()).then_some(name)
}

/// Дата й час у форматі DOS → FILETIME. FAT зберігає місцевий час без поясу,
/// тож показується він як є.
fn dos_time(date: u16, time: u16, centis: u8) -> Option<u64> {
    if date == 0 {
        return None;
    }
    civil_to_filetime(
        1980 + (date >> 9) as i64,
        ((date >> 5) & 0x0F) as u32,
        (date & 0x1F) as u32,
        (time >> 11) as u32,
        ((time >> 5) & 0x3F) as u32,
        (time & 0x1F) as u32 * 2 + centis as u32 / 100,
        centis as u32 % 100,
    )
}

/// Короткий запис теки разом із довгим ім'ям, якщо воно ціле.
struct DirItem {
    offset: u64,
    name: String,
    attr: u8,
    first_cluster: u32,
    size: u64,
    deleted: bool,
    timestamps: Option<Timestamps>,
}

/// Чи це запис `.` або `..`.
fn is_dot_entry(e: &[u8]) -> bool {
    e[0] == b'.' && (&e[1..11] == b"          " || &e[1..11] == b".         ")
}

fn first_cluster(e: &[u8], kind: Filesystem) -> u32 {
    let lo = u16_at(e, 26) as u32;
    if kind == Filesystem::Fat32 {
        ((u16_at(e, 20) as u32) << 16) | lo
    } else {
        lo
    }
}

/// Розібрати байти теки. `offset_of` переводить позицію в `buf` у зсув від
/// початку тому: кластери теки не обов'язково лежать підряд.
fn parse_dir(buf: &[u8], offset_of: &dyn Fn(usize) -> u64, kind: Filesystem) -> (Vec<DirItem>, u64) {
    let mut items = Vec::new();
    let mut nameless = 0u64;
    let mut parts: Vec<LfnPart> = Vec::new();

    for (i, e) in buf.chunks_exact(32).enumerate() {
        if e[0] == 0x00 {
            break; // далі тека не використовувалась
        }
        let attr = e[11];
        if attr & 0x3F == 0x0F {
            parts.push(LfnPart::parse(e));
            continue;
        }
        let lfn = std::mem::take(&mut parts);
        if attr & 0x08 != 0 || is_dot_entry(e) {
            continue; // мітка тому або `.` / `..`
        }

        let deleted = e[0] == 0xE5;
        let long = assemble_lfn(&lfn, e, deleted);
        let first = match e[0] {
            0x05 => 0xE5,
            0xE5 => b'_',
            b => b,
        };
        let short = short_name(&e[..11], e[12], first);
        let name = match long {
            Some(n) => n,
            None if short.trim_matches(['_', '.']).is_empty() => {
                nameless += 1;
                continue;
            }
            None => short,
        };

        let modified = dos_time(u16_at(e, 24), u16_at(e, 22), 0);
        items.push(DirItem {
            offset: offset_of(i * 32),
            name,
            attr,
            first_cluster: first_cluster(e, kind),
            size: u32_at(e, 28) as u64,
            deleted,
            timestamps: modified.map(|m| Timestamps {
                created: dos_time(u16_at(e, 16), u16_at(e, 14), e[13]).unwrap_or(0),
                modified: m,
                mft_changed: m,
                accessed: dos_time(u16_at(e, 18), 0, 0).unwrap_or(0),
            }),
        });
    }
    (items, nameless)
}

/// Том FAT, відкритий на читання.
pub struct FatVolume<D: BlockDevice> {
    dev: D,
    pub boot: FatBoot,
    pub boot_source: BootSource,
    fat: FatTable,
    geo: Geometry,
}

/// Стан одного сканування: що знайдено і які теки вже пройдено.
struct Walk {
    found: Vec<Found>,
    ids: HashSet<u64>,
    visited: HashSet<u32>,
    /// Кластер → перший кластер теки, якій він належить.
    owner: HashMap<u32, u32>,
    dotdot: HashMap<u32, u32>,
    queue: VecDeque<(u32, bool)>,
    damaged: u64,
    nameless: u64,
}

impl<D: BlockDevice> FatVolume<D> {
    pub fn open(mut dev: D) -> io::Result<Self> {
        let (boot, boot_source) = read_boot(&mut dev)?;
        let copies: Vec<u64> = (0..boot.num_fats).map(|i| boot.fat_offset(i)).collect();
        let fat_bytes = boot.fat_sectors * boot.bytes_per_sector as u64;
        let fat = FatTable::load(&mut dev, &copies, fat_bytes, |raw| boot.decode_fat(raw));
        let geo = boot.geometry();
        Ok(Self {
            dev,
            boot,
            boot_source,
            fat,
            geo,
        })
    }

    /// Рядки для користувача: що це за том і в якому він стані.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "завантажувальний запис: {}; {}, кластер {} байтів, кластерів {}, копій FAT {}",
            self.boot_source.describe(),
            self.boot.kind.name(),
            self.boot.cluster_size,
            self.boot.cluster_count,
            self.boot.num_fats
        )];
        if self.fat.unreadable_bytes > 0 {
            lines.push(format!(
                "УВАГА: {} байтів таблиці FAT не прочиталися з жодної копії — ланцюжки там обірвані",
                self.fat.unreadable_bytes
            ));
        }
        lines
    }

    /// Обійти дерево тек від кореня.
    pub fn scan(
        &mut self,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        self.run(false, cancel, progress)
    }

    /// Обійти дерево і додатково перебрати всі кластери в пошуках тек, на які
    /// вже ніщо не вказує, — після швидкого форматування чи знищеного кореня.
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
            dotdot: HashMap::new(),
            queue: VecDeque::new(),
            damaged: 0,
            nameless: 0,
        };
        let total = self.dev.len();
        let mut cancelled = false;

        self.read_root(&mut w);
        cancelled |= self.drain(&mut w, cancel, progress, total);

        if sweep && !cancelled {
            // Перший кластер кожної підтеки починається записами `.` і `..`.
            let mut head = [0u8; 64];
            for c in 2..self.geo.cluster_count + 2 {
                if c % 4096 == 0 {
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
                if w.visited.contains(&c) || w.owner.contains_key(&c) {
                    continue;
                }
                if self.dev.read_at(self.geo.offset(c), &mut head).is_err() {
                    continue;
                }
                let (dot, dotdot) = (&head[..32], &head[32..]);
                if !(is_dot_entry(dot) && dot[1] == b' ' && dot[11] & 0x10 != 0)
                    || !(is_dot_entry(dotdot) && dotdot[1] == b'.' && dotdot[11] & 0x10 != 0)
                    || first_cluster(dot, self.boot.kind) & 0xFFFF != c & 0xFFFF
                {
                    continue;
                }
                w.dotdot.insert(c, first_cluster(dotdot, self.boot.kind));
                // Видалена це тека чи ні, тут не відомо; її записи скажуть самі.
                w.queue.push_back((c, true));
                cancelled |= self.drain(&mut w, cancel, progress, total);
                if cancelled {
                    break;
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
        let entries: Vec<FileEntry> = assemble(w.found, &|c| owner.get(&c).copied(), &w.dotdot);
        Ok(ScanResult {
            filesystem: self.boot.kind,
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

    fn read_root(&mut self, w: &mut Walk) {
        if self.boot.kind == Filesystem::Fat32 {
            let limit = self.geo.clusters_for(MAX_DIR_BYTES);
            let chain = self.fat.chain(&self.geo, self.boot.root_cluster, limit);
            for &c in &chain.clusters {
                w.owner.insert(c, 0);
            }
            w.visited.insert(self.boot.root_cluster);
            let (buf, damaged) = read_clusters(&mut self.dev, &self.geo, &chain.clusters);
            w.damaged += damaged as u64;
            let geo = self.geo;
            let clusters = chain.clusters;
            let offset_of =
                |i: usize| geo.offset(clusters[i / geo.cluster_size as usize]) + (i as u64 % geo.cluster_size);
            self.take_items(w, &buf, &offset_of, 0, true);
        } else {
            let base = self.boot.root_dir_offset();
            let len = self.boot.root_entries as usize * 32;
            let mut buf = vec![0u8; len];
            if self.dev.read_at(base, &mut buf).is_err() {
                // Читати по секторах, щоб один збійний сектор не забрав увесь корінь.
                let s = self.boot.bytes_per_sector as usize;
                for (i, chunk) in buf.chunks_mut(s).enumerate() {
                    if self.dev.read_at(base + (i * s) as u64, chunk).is_err() {
                        chunk.fill(0);
                        w.damaged += 1;
                    }
                }
            }
            self.take_items(w, &buf, &|i| base + i as u64, 0, true);
        }
    }

    /// Пройти теки з черги; повертає `true`, якщо зупинено.
    fn drain(
        &mut self,
        w: &mut Walk,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
        total: u64,
    ) -> bool {
        while let Some((dir, live)) = w.queue.pop_front() {
            if cancel.load(Ordering::Relaxed) {
                return true;
            }
            if !w.visited.insert(dir) {
                continue;
            }
            progress(ScanProgress {
                records_examined: w.found.len() as u64,
                entries_found: w.found.len() as u64,
                offset: self.geo.offset(dir).min(total),
                total,
            });

            let limit = self.geo.clusters_for(MAX_DIR_BYTES);
            let chain = self.fat.chain(&self.geo, dir, limit);
            // Ланцюжок видаленої теки стерто, а її кластери могли вже віддати
            // іншим файлам; тоді береться лише перший — його перевіряє `.`.
            let clusters = if live && (chain.complete || chain.clusters.len() > 1) {
                chain.clusters
            } else {
                vec![dir]
            };
            let (buf, damaged) = read_clusters(&mut self.dev, &self.geo, &clusters);
            w.damaged += damaged as u64;
            // Перший кластер теки мусить починатися з `.`; інакше його вже перезаписано.
            if !is_dot_entry(&buf[..32]) {
                continue;
            }
            for &c in &clusters {
                w.owner.entry(c).or_insert(dir);
            }
            let geo = self.geo;
            let offset_of = |i: usize| {
                geo.offset(clusters[i / geo.cluster_size as usize]) + (i as u64 % geo.cluster_size)
            };
            self.take_items(w, &buf, &offset_of, dir, live);
        }
        false
    }

    /// Перетворити записи теки на [`Found`] і поставити підтеки в чергу.
    fn take_items(
        &self,
        w: &mut Walk,
        buf: &[u8],
        offset_of: &dyn Fn(usize) -> u64,
        container: u32,
        parent_live: bool,
    ) {
        let (items, nameless) = parse_dir(buf, offset_of, self.boot.kind);
        w.nameless += nameless;
        for item in items {
            if !w.ids.insert(item.offset) {
                continue;
            }
            let is_dir = item.attr & 0x10 != 0;
            let deleted = item.deleted || !parent_live;
            let (data, caveat) = if is_dir {
                (None, None)
            } else {
                let (runs, caveat) = self.file_runs(item.first_cluster, item.size, deleted);
                (
                    Some(data_attribute(item.size, item.size, runs, self.geo.cluster_size)),
                    caveat,
                )
            };
            if is_dir && self.geo.is_valid(item.first_cluster) {
                w.queue.push_back((item.first_cluster, !deleted));
            }
            w.found.push(Found {
                id: item.offset,
                container,
                name: item.name,
                is_dir,
                deleted,
                size: item.size,
                first_cluster: item.first_cluster,
                data,
                timestamps: item.timestamps,
                caveat,
            });
        }
    }

    /// Де лежить вміст файлу.
    ///
    /// Живий файл — за ланцюжком у FAT. Якщо ланцюжка немає (файл видалено,
    /// таблицю FAT стерто форматуванням), вміст береться підряд від першого
    /// кластера: так файли й лежать, коли флешку не фрагментовано.
    fn file_runs(
        &self,
        first: u32,
        size: u64,
        deleted: bool,
    ) -> (Vec<crate::ntfs::record::DataRun>, Option<&'static str>) {
        let needed = self.geo.clusters_for(size);
        if needed == 0 || !self.geo.is_valid(first) {
            return (Vec::new(), None);
        }
        if !deleted {
            let chain = self.fat.chain(&self.geo, first, needed);
            if chain.complete && chain.clusters.len() as u64 == needed {
                return (runs_from_clusters(&chain.clusters), None);
            }
            if self.fat.get(first) != FREE {
                // Ланцюжок є, але обірваний: беремо, що є; решту порахує читання.
                return (runs_from_clusters(&chain.clusters), None);
            }
        }
        (contiguous_runs(first, needed), Some(CAVEAT_CONTIGUOUS))
    }
}

impl<D: BlockDevice> ReadFiles for FatVolume<D> {
    fn read_file_data(&mut self, entry: &FileEntry) -> io::Result<(Vec<u8>, u64)> {
        let Some(data) = &entry.data else {
            return Err(bad("це тека, а не файл"));
        };
        // Вгадане розташування перевіряється: кластер, який FAT уже віддала
        // іншому файлу, містить чужі дані.
        let guessed = entry.caveat == Some(CAVEAT_CONTIGUOUS);
        let fat = &self.fat;
        let occupied = |c: u32| guessed && fat.get(c) != FREE;
        Ok(read_runs(&mut self.dev, &self.geo, data, &occupied))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cp866_table_covers_the_upper_half() {
        assert_eq!(CP866_HIGH.chars().count(), 128);
        assert_eq!(oem_char(0x80), 'А');
        assert_eq!(oem_char(0xF4), 'Ї');
        assert_eq!(oem_char(0xFC), '№');
    }

    #[test]
    fn lfn_checksum_matches_the_specification_example() {
        // «FILE    TXT»: обчислено вручну за алгоритмом із специфікації FAT.
        let mut sum = 0u8;
        for &b in b"FILE    TXT" {
            sum = (if sum & 1 != 0 { 0x80u8 } else { 0 })
                .wrapping_add(sum >> 1)
                .wrapping_add(b);
        }
        assert_eq!(lfn_checksum(b"FILE    TXT"), sum);
    }

    #[test]
    fn short_names_respect_nt_lowercase_flags() {
        assert_eq!(short_name(b"README  TXT", 0x18, b'R'), "readme.txt");
        assert_eq!(short_name(b"README  TXT", 0x00, b'R'), "README.TXT");
        assert_eq!(short_name(b"NOEXT      ", 0x00, b'N'), "NOEXT");
    }

    #[test]
    fn dos_dates_decode() {
        // 2026-11-06 17:45:30 → дата (46<<9)|(11<<5)|6, час (17<<11)|(45<<5)|15
        let date = (46 << 9) | (11 << 5) | 6;
        let time = (17 << 11) | (45 << 5) | 15;
        let ft = dos_time(date, time, 0).unwrap();
        assert_eq!(crate::ntfs::format_filetime(ft), "2026-11-06 17:45:30");
        assert!(dos_time(0, 0, 0).is_none());
    }
}
