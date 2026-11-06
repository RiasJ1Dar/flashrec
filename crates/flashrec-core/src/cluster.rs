//! Спільне для FAT і exFAT: таблиця FAT, ланцюжки кластерів, читання вмісту і
//! збирання знайденого в дерево тек.
//!
//! Обидві файлові системи ділять область даних на кластери, нумеровані з 2, і
//! тримають таблицю, де для кожного кластера записано наступний. Різняться
//! вони записами тек — їх розбирають [`crate::fat`] і [`crate::exfat`], а сюди
//! віддають однакові [`Found`].

use std::collections::{HashMap, HashSet};
use std::io;

use crate::files::{sanitize_component, FileEntry};
use crate::ntfs::record::{DataAttribute, DataRun, Timestamps};
use crate::reader::BlockDevice;

/// Значення таблиці після нормалізації: вільний кластер.
pub(crate) const FREE: u32 = 0;
/// Кінець ланцюжка.
pub(crate) const END: u32 = u32::MAX;
/// Кластер позначено збійним.
pub(crate) const BAD: u32 = u32::MAX - 1;

/// Номер кореня в [`FileEntry::parent_number`]. Нуль не може бути зсувом
/// запису теки: там завантажувальний сектор.
pub(crate) const ROOT_ID: u64 = 0;
/// Батьківська тека невідома зовсім — шлях почнеться з `_без_теки`.
const LOST_ID: u64 = u64::MAX;
/// Позначка номерів тек, відтворених лише з кластера, без власного запису.
const SYNTHETIC_BIT: u64 = 1 << 62;

/// Застереження для файлу, чиє розташування вгадано: кластери взято підряд від
/// першого, бо ланцюжка в таблиці FAT немає.
pub(crate) const CAVEAT_CONTIGUOUS: &str =
    "ланцюжка кластерів немає — вміст прочитано підряд від першого кластера";

/// Розмітка області даних.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Geometry {
    /// Зсув кластера 2 від початку тому.
    pub heap_offset: u64,
    pub cluster_size: u64,
    pub cluster_count: u32,
}

impl Geometry {
    pub fn is_valid(&self, cluster: u32) -> bool {
        cluster >= 2 && (cluster as u64) < self.cluster_count as u64 + 2
    }

    pub fn offset(&self, cluster: u32) -> u64 {
        self.heap_offset + (cluster as u64 - 2) * self.cluster_size
    }

    /// Скільки кластерів займає `bytes`.
    pub fn clusters_for(&self, bytes: u64) -> u64 {
        bytes.div_ceil(self.cluster_size)
    }
}

/// Таблиця FAT, уже переведена в 32-бітні значення з [`FREE`], [`END`], [`BAD`].
pub(crate) struct FatTable {
    entries: Vec<u32>,
    /// Байти таблиці, яких не вдалося прочитати з жодної копії.
    pub unreadable_bytes: u64,
}

/// Ланцюжок кластерів і чи дійшов він до потрібної довжини чи до кінця.
pub(crate) struct Chain {
    pub clusters: Vec<u32>,
    pub complete: bool,
}

impl FatTable {
    /// Прочитати таблицю шматками: що не прочиталося з першої копії, береться
    /// з другої; чого немає в жодній, лишається нулями й рахується.
    pub fn load<D: BlockDevice>(
        dev: &mut D,
        copies: &[u64],
        bytes: u64,
        decode: impl Fn(&[u8]) -> Vec<u32>,
    ) -> Self {
        const CHUNK: u64 = 64 << 10;
        let mut raw = vec![0u8; bytes as usize];
        let mut unreadable_bytes = 0u64;
        let mut at = 0u64;
        while at < bytes {
            let n = CHUNK.min(bytes - at) as usize;
            let slot = &mut raw[at as usize..at as usize + n];
            let ok = copies
                .iter()
                .any(|base| dev.read_at(base + at, slot).is_ok());
            if !ok {
                slot.fill(0);
                unreadable_bytes += n as u64;
            }
            at += n as u64;
        }
        Self {
            entries: decode(&raw),
            unreadable_bytes,
        }
    }

    #[cfg(test)]
    pub fn from_entries(entries: Vec<u32>) -> Self {
        Self {
            entries,
            unreadable_bytes: 0,
        }
    }

    pub fn get(&self, cluster: u32) -> u32 {
        self.entries.get(cluster as usize).copied().unwrap_or(BAD)
    }

    /// Пройти ланцюжок від `start`, але не далі `limit` кластерів.
    ///
    /// `complete` означає, що зібрано `limit` кластерів або ланцюжок чесно
    /// закінчився позначкою кінця. Вільний, збійний чи неможливий кластер
    /// посеред ланцюжка — обрив.
    pub fn chain(&self, geo: &Geometry, start: u32, limit: u64) -> Chain {
        let mut clusters = Vec::new();
        let mut current = start;
        loop {
            if !geo.is_valid(current) {
                return Chain {
                    clusters,
                    complete: false,
                };
            }
            clusters.push(current);
            if clusters.len() as u64 >= limit {
                return Chain {
                    clusters,
                    complete: true,
                };
            }
            match self.get(current) {
                END => {
                    return Chain {
                        clusters,
                        complete: true,
                    }
                }
                FREE | BAD => {
                    return Chain {
                        clusters,
                        complete: false,
                    }
                }
                next => current = next,
            }
        }
    }
}

/// Стиснути перелік кластерів у runlist: сусідні кластери — один фрагмент.
pub(crate) fn runs_from_clusters(clusters: &[u32]) -> Vec<DataRun> {
    let mut runs: Vec<DataRun> = Vec::new();
    for &c in clusters {
        if let Some(last) = runs.last_mut() {
            if last.lcn == Some(c as i64 - last.length_clusters as i64) {
                last.length_clusters += 1;
                continue;
            }
        }
        runs.push(DataRun {
            lcn: Some(c as i64),
            length_clusters: 1,
        });
    }
    runs
}

/// Один фрагмент із `count` кластерів підряд від `first`.
pub(crate) fn contiguous_runs(first: u32, count: u64) -> Vec<DataRun> {
    if count == 0 {
        return Vec::new();
    }
    vec![DataRun {
        lcn: Some(first as i64),
        length_clusters: count,
    }]
}

/// Опис вмісту для [`FileEntry::data`]. `valid` — скільки байтів справді
/// записано; далі файл за визначенням складається з нулів.
pub(crate) fn data_attribute(size: u64, valid: u64, runs: Vec<DataRun>, cluster_size: u64) -> DataAttribute {
    let allocated = runs.iter().map(|r| r.length_clusters).sum::<u64>() * cluster_size;
    DataAttribute::NonResident {
        real_size: size,
        allocated_size: allocated,
        initialized_size: valid.min(size),
        runs,
        flags: 0,
    }
}

/// Прочитати вміст за runlist-ом.
///
/// Кластер, що не прочитався або, як каже `occupied`, уже належить іншому
/// файлу, заповнюється нулями й рахується втраченим.
pub(crate) fn read_runs<D: BlockDevice>(
    dev: &mut D,
    geo: &Geometry,
    data: &DataAttribute,
    occupied: &dyn Fn(u32) -> bool,
) -> (Vec<u8>, u64) {
    let DataAttribute::NonResident {
        real_size,
        initialized_size,
        runs,
        ..
    } = data
    else {
        // FAT і exFAT резидентних даних не мають.
        return (Vec::new(), 0);
    };
    let want = *real_size as usize;
    let valid = *initialized_size as usize;
    let cluster = geo.cluster_size as usize;
    let mut out = Vec::with_capacity(want.min(64 << 20));
    let mut lost = 0u64;
    let mut buf = vec![0u8; cluster];

    'runs: for run in runs {
        let Some(first) = run.lcn else { continue };
        for i in 0..run.length_clusters {
            if out.len() >= want {
                break 'runs;
            }
            let take = cluster.min(want - out.len());
            if out.len() >= valid {
                // За межею записаних даних — нулі за визначенням, не втрата.
                out.resize(out.len() + take, 0);
                continue;
            }
            let c = (first + i as i64) as u32;
            let readable = geo.is_valid(c)
                && !occupied(c)
                && dev.read_at(geo.offset(c), &mut buf).is_ok();
            if !readable {
                buf.fill(0);
                lost += take.min(valid - out.len()) as u64;
            }
            out.extend_from_slice(&buf[..take]);
        }
    }

    if out.len() < want {
        lost += valid.saturating_sub(out.len()) as u64;
        out.resize(want, 0);
    }
    if valid < want {
        // Хвіст за межею записаного — нулі, навіть якщо кластер щось містив.
        out[valid..].fill(0);
    }
    (out, lost)
}

/// Запис теки, уже розібраний файловою системою.
#[derive(Debug, Clone)]
pub(crate) struct Found {
    /// Байтовий зсув запису від початку тому — стійкий і унікальний номер.
    pub id: u64,
    /// Перший кластер теки, де лежить запис, або 0 для кореня. Під час перебору
    /// кластерів це може бути будь-який кластер теки — його зведе `owner`.
    pub container: u32,
    pub name: String,
    pub is_dir: bool,
    pub deleted: bool,
    pub size: u64,
    pub first_cluster: u32,
    pub data: Option<DataAttribute>,
    pub timestamps: Option<Timestamps>,
    pub caveat: Option<&'static str>,
}

/// Звести знайдені записи в [`FileEntry`] з посиланнями на батьківські теки.
///
/// `owner` каже, якій теці (за першим кластером) належить кластер, у якому
/// знайдено запис. `dotdot` — відомі з записів `..` батьківські теки для тек,
/// чий власний запис втрачено.
pub(crate) fn assemble(
    found: Vec<Found>,
    owner: &dyn Fn(u32) -> Option<u32>,
    dotdot: &HashMap<u32, u32>,
) -> Vec<FileEntry> {
    // Тека за першим кластером; живий запис важить більше за видалений.
    let mut dir_ids: HashMap<u32, (u64, bool)> = HashMap::new();
    for f in found.iter().filter(|f| f.is_dir && f.first_cluster >= 2) {
        let live = !f.deleted;
        match dir_ids.get(&f.first_cluster) {
            Some(&(_, existing_live)) if existing_live || !live => {}
            _ => {
                dir_ids.insert(f.first_cluster, (f.id, live));
            }
        }
    }

    let container_of = |raw: u32| -> u32 {
        if raw == 0 {
            0
        } else {
            owner(raw).unwrap_or(raw)
        }
    };

    // Теки, у яких знайдено вміст, але не власний запис, — їх доведеться відтворити.
    let mut synthetic: Vec<u32> = Vec::new();
    let mut synthetic_set: HashSet<u32> = HashSet::new();
    for f in &found {
        let c = container_of(f.container);
        if c != 0 && !dir_ids.contains_key(&c) && synthetic_set.insert(c) {
            synthetic.push(c);
        }
    }
    let mut i = 0;
    while i < synthetic.len() {
        if let Some(&p) = dotdot.get(&synthetic[i]) {
            if p != 0 && !dir_ids.contains_key(&p) && synthetic_set.insert(p) {
                synthetic.push(p);
            }
        }
        i += 1;
    }

    let id_of_dir = |c: u32| -> u64 {
        if c == 0 {
            ROOT_ID
        } else if let Some(&(id, _)) = dir_ids.get(&c) {
            id
        } else if synthetic_set.contains(&c) {
            SYNTHETIC_BIT | c as u64
        } else {
            LOST_ID
        }
    };

    // Видалене все, що лежить у видаленій теці, навіть якщо запис так не каже.
    let deleted_dirs: HashSet<u64> = found
        .iter()
        .filter(|f| f.is_dir && f.deleted)
        .map(|f| f.id)
        .collect();

    let mut entries: Vec<FileEntry> = found
        .into_iter()
        .map(|f| {
            let parent = id_of_dir(container_of(f.container));
            FileEntry {
                record_number: f.id,
                sequence: 0,
                parent_number: parent,
                name: sanitize_component(&f.name),
                is_directory: f.is_dir,
                in_use: !f.deleted && !deleted_dirs.contains(&parent),
                size: if f.is_dir { 0 } else { f.size },
                data: f.data,
                timestamps: f.timestamps,
                named_streams: Vec::new(),
                caveat: f.caveat,
            }
        })
        .collect();

    for c in synthetic {
        let parent = match dotdot.get(&c) {
            Some(&p) => id_of_dir(p),
            None => LOST_ID,
        };
        entries.push(FileEntry {
            record_number: SYNTHETIC_BIT | c as u64,
            sequence: 0,
            parent_number: parent,
            name: format!("_тека_кластер_{c}"),
            is_directory: true,
            in_use: true,
            size: 0,
            data: None,
            timestamps: None,
            named_streams: Vec::new(),
            caveat: None,
        });
    }
    entries
}

/// Прочитати вміст теки за кластерами; нечитане — нулями (у теці це «кінець»).
pub(crate) fn read_clusters<D: BlockDevice>(
    dev: &mut D,
    geo: &Geometry,
    clusters: &[u32],
) -> (Vec<u8>, bool) {
    let cs = geo.cluster_size as usize;
    let mut out = vec![0u8; clusters.len() * cs];
    let mut damaged = false;
    for (i, &c) in clusters.iter().enumerate() {
        let slot = &mut out[i * cs..(i + 1) * cs];
        if dev.read_at(geo.offset(c), slot).is_err() {
            slot.fill(0);
            damaged = true;
        }
    }
    (out, damaged)
}

pub(crate) fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geo() -> Geometry {
        Geometry {
            heap_offset: 0,
            cluster_size: 512,
            cluster_count: 20,
        }
    }

    #[test]
    fn chains_stop_at_the_end_marker_and_report_breaks() {
        let mut t = vec![FREE; 22];
        t[2] = 3;
        t[3] = 7;
        t[7] = END;
        t[10] = 11; // 11 вільний — обрив
        let fat = FatTable::from_entries(t);
        let c = fat.chain(&geo(), 2, 100);
        assert_eq!(c.clusters, vec![2, 3, 7]);
        assert!(c.complete);
        let broken = fat.chain(&geo(), 10, 100);
        assert_eq!(broken.clusters, vec![10, 11]);
        assert!(!broken.complete);
        // Ланцюжок, що замкнувся в цикл, зупиняє ліміт.
        let mut looped = vec![FREE; 22];
        looped[4] = 5;
        looped[5] = 4;
        assert_eq!(
            FatTable::from_entries(looped).chain(&geo(), 4, 6).clusters.len(),
            6
        );
    }

    #[test]
    fn neighbouring_clusters_merge_into_one_run() {
        let runs = runs_from_clusters(&[5, 6, 7, 10, 11, 3]);
        let got: Vec<_> = runs.iter().map(|r| (r.lcn, r.length_clusters)).collect();
        assert_eq!(got, vec![(Some(5), 3), (Some(10), 2), (Some(3), 1)]);
    }

    fn found(id: u64, container: u32, name: &str, dir_cluster: Option<u32>) -> Found {
        Found {
            id,
            container,
            name: name.into(),
            is_dir: dir_cluster.is_some(),
            deleted: false,
            size: 10,
            first_cluster: dir_cluster.unwrap_or(0),
            data: None,
            timestamps: None,
            caveat: None,
        }
    }

    #[test]
    fn orphaned_directories_are_recreated_from_their_clusters() {
        let items = vec![
            found(100, 0, "Документи", Some(5)),
            found(200, 5, "лист.txt", None),
            // Тека в кластері 9 — її запис втрачено, але `..` каже, що вона в 5.
            found(300, 9, "фото.jpg", None),
        ];
        let dotdot = HashMap::from([(9u32, 5u32)]);
        let entries = assemble(items, &|_| None, &dotdot);
        let result = crate::files::ScanResult {
            filesystem: crate::files::Filesystem::Fat32,
            boot_source: crate::files::BootSource::Primary,
            method: crate::files::ScanMethod::DirectorySweep,
            root: ROOT_ID,
            entries,
            damaged_records: 0,
            nameless_records: 0,
            cancelled: false,
        };
        let paths = result.paths();
        assert_eq!(
            paths[&200],
            std::path::PathBuf::from("Документи").join("лист.txt")
        );
        assert_eq!(
            paths[&300],
            std::path::PathBuf::from("Документи")
                .join("_тека_кластер_9")
                .join("фото.jpg")
        );
    }

    struct Mem(Vec<u8>);
    impl BlockDevice for Mem {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            let o = offset as usize;
            if o + buf.len() > self.0.len() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            buf.copy_from_slice(&self.0[o..o + buf.len()]);
            Ok(())
        }
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn sector_size(&self) -> u32 {
            512
        }
    }

    #[test]
    fn occupied_clusters_count_as_lost_and_tail_past_valid_is_zero() {
        // Кластери 2..=4 по 512 байтів, заповнені 1, 2, 3.
        let mut disk = Vec::new();
        for v in 1..=3u8 {
            disk.extend(std::iter::repeat_n(v, 512));
        }
        let g = Geometry {
            heap_offset: 0,
            cluster_size: 512,
            cluster_count: 3,
        };
        let data = data_attribute(1500, 1500, contiguous_runs(2, 3), 512);
        let (bytes, lost) = read_runs(&mut Mem(disk.clone()), &g, &data, &|c| c == 3);
        assert_eq!(lost, 512);
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[600], 0);
        assert_eq!(bytes[1400], 3);

        // Записано лише 700 байтів — решта нулі, і це не втрата.
        let data = data_attribute(1500, 700, contiguous_runs(2, 3), 512);
        let (bytes, lost) = read_runs(&mut Mem(disk), &g, &data, &|_| false);
        assert_eq!(lost, 0);
        assert_eq!(bytes[699], 2);
        assert_eq!(bytes[700], 0);
        assert_eq!(bytes[1400], 0);
    }
}
