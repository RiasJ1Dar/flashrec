//! Пошук файлової системи всередині образу цілого диска.
//!
//! Образ фізичного диска починається з таблиці розділів, тож том лежить десь
//! далі. Замість того щоб змушувати користувача вираховувати зсув, flashrec
//! читає MBR, а якщо й таблиці немає — шукає завантажувальний запис напряму.
//! Флешки часто відформатовано взагалі без таблиці розділів: тоді том
//! починається з байта 0.

use std::io;

use crate::files::Filesystem;
use crate::reader::{u32_at, BlockDevice};

/// Один запис розділу, вартий уваги.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    pub index: u8,
    pub mbr_type: u8,
    pub offset: u64,
    pub len: u64,
}

impl Partition {
    /// Типи розділів, де буває NTFS, FAT або exFAT.
    pub fn is_candidate(&self) -> bool {
        matches!(
            self.mbr_type,
            0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E | 0x07 | 0x11 | 0x14 | 0x16 | 0x17 | 0x1B
                | 0x1C | 0x1E | 0x27
        )
    }

    pub fn type_name(&self) -> &'static str {
        match self.mbr_type {
            0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E => "FAT",
            0x11 | 0x14 | 0x16 | 0x1B | 0x1C | 0x1E => "FAT, прихований",
            0x07 => "NTFS/exFAT (IFS)",
            0x17 => "NTFS, прихований",
            0x27 => "NTFS, відновлення",
            0x83 => "Linux",
            0xEE => "захисний GPT",
            0x05 | 0x0F => "розширений",
            _ => "інший",
        }
    }
}

/// Прочитати таблицю розділів MBR.
pub fn read_mbr<D: BlockDevice>(dev: &mut D) -> io::Result<Vec<Partition>> {
    let mut buf = vec![0u8; 512];
    dev.read_at(0, &mut buf)?;
    if buf[510] != 0x55 || buf[511] != 0xAA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "немає підпису 0x55AA — таблиця розділів відсутня або знищена",
        ));
    }

    let sector = dev.sector_size().max(512) as u64;
    let mut parts = Vec::new();
    for i in 0..4u8 {
        let base = 446 + i as usize * 16;
        let mbr_type = buf[base + 4];
        if mbr_type == 0 {
            continue;
        }
        let start_lba = u32_at(&buf, base + 8) as u64;
        let sectors = u32_at(&buf, base + 12) as u64;
        if sectors == 0 {
            continue;
        }
        parts.push(Partition {
            index: i,
            mbr_type,
            offset: start_lba * sector,
            len: sectors * sector,
        });
    }
    Ok(parts)
}

/// Яку файлову систему описує один завантажувальний сектор.
pub fn identify_boot_sector(buf: &[u8]) -> Option<Filesystem> {
    if crate::ntfs::NtfsBoot::parse(buf).is_ok() {
        return Some(Filesystem::Ntfs);
    }
    if crate::exfat::ExFatBoot::parse(buf).is_ok() {
        return Some(Filesystem::ExFat);
    }
    crate::fat::FatBoot::parse(buf).ok().map(|b| b.kind)
}

/// Визначити файлову систему тому, що починається з `base`, — за основним
/// завантажувальним сектором, а коли той знищено, за резервними копіями:
/// NTFS тримає її в кінці тому, FAT32 — у секторі 6, exFAT — у секторі 12.
pub fn probe_filesystem<D: BlockDevice>(dev: &mut D, base: u64, len: u64) -> Option<Filesystem> {
    let mut buf = vec![0u8; 512];
    let mut at = |offset: u64, buf: &mut Vec<u8>| -> Option<Filesystem> {
        if offset + 512 > base + len || dev.read_at(offset, buf).is_err() {
            return None;
        }
        identify_boot_sector(buf)
    };
    if let Some(fs) = at(base, &mut buf) {
        return Some(fs);
    }
    if len >= 1024 {
        for backup in [base + len - 512, base + len - 1024] {
            if at(backup, &mut buf) == Some(Filesystem::Ntfs) {
                return Some(Filesystem::Ntfs);
            }
        }
    }
    for sector in [512u64, 1024, 2048, 4096] {
        if at(base + 12 * sector, &mut buf) == Some(Filesystem::ExFat) {
            return Some(Filesystem::ExFat);
        }
        if at(base + 6 * sector, &mut buf) == Some(Filesystem::Fat32) {
            return Some(Filesystem::Fat32);
        }
    }
    None
}

/// Визначити, де починається том і яка на ньому файлова система.
///
/// Пробує по черзі: том на зсуві 0 (образ тому або флешка без таблиці
/// розділів); розділи з MBR; потім обмежений пошук завантажувального запису,
/// що рятує, коли таблицю розділів знищено.
pub fn locate_volume<D: BlockDevice>(dev: &mut D) -> io::Result<VolumeLocation> {
    let total = dev.len();

    // Завантажувальний сектор тому теж закінчується 0x55AA, тому том на зсуві
    // 0 перевіряється раніше, ніж його байти приймуть за таблицю розділів.
    let mut probe = vec![0u8; 512];
    if dev.read_at(0, &mut probe).is_ok() {
        if let Some(filesystem) = identify_boot_sector(&probe) {
            return Ok(VolumeLocation {
                offset: 0,
                len: total,
                filesystem,
                how: LocationSource::VolumeImage,
            });
        }
    }

    if let Ok(parts) = read_mbr(dev) {
        for p in parts.iter().filter(|p| p.is_candidate()) {
            let len = p.len.min(total.saturating_sub(p.offset));
            if let Some(filesystem) = probe_filesystem(dev, p.offset, len) {
                return Ok(VolumeLocation {
                    offset: p.offset,
                    len,
                    filesystem,
                    how: LocationSource::PartitionTable {
                        index: p.index,
                        mbr_type: p.mbr_type,
                    },
                });
            }
        }
        // Таблиця є, але жоден розділ не впізнано — пошук однаково вартий спроби.
    }

    // Резервні копії на зсуві 0: том без таблиці розділів зі знищеним першим сектором.
    if let Some(filesystem) = probe_filesystem(dev, 0, total) {
        return Ok(VolumeLocation {
            offset: 0,
            len: total,
            filesystem,
            how: LocationSource::VolumeImage,
        });
    }

    // Перебрати перші 256 МіБ по межах секторів у пошуках завантажувального запису.
    let sector = dev.sector_size().max(512) as u64;
    let limit = (256u64 << 20).min(total);
    let mut at = sector;
    while at + 512 <= limit {
        if dev.read_at(at, &mut probe).is_ok() {
            if let Some(filesystem) = identify_boot_sector(&probe) {
                return Ok(VolumeLocation {
                    offset: at,
                    len: total - at,
                    filesystem,
                    how: LocationSource::SignatureSearch,
                });
            }
        }
        at += sector;
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "завантажувального запису NTFS, FAT чи exFAT немає ні на зсуві 0, ні в MBR, \
         ні в перших 256 МіБ — залишається «Вирізати»",
    ))
}

#[derive(Debug, Clone, Copy)]
pub struct VolumeLocation {
    pub offset: u64,
    pub len: u64,
    pub filesystem: Filesystem,
    pub how: LocationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationSource {
    /// Том починається з байта 0: образ тому або флешка без таблиці розділів.
    VolumeImage,
    PartitionTable { index: u8, mbr_type: u8 },
    /// Знайдено пошуком — таблиця розділів не допомогла.
    SignatureSearch,
}

impl LocationSource {
    pub fn describe(&self) -> String {
        match self {
            LocationSource::VolumeImage => {
                "том починається з зсуву 0 (образ тому або носій без таблиці розділів)".to_string()
            }
            LocationSource::PartitionTable { index, mbr_type } => format!(
                "з MBR, розділ {} (тип {:#04x})",
                index + 1,
                mbr_type
            ),
            LocationSource::SignatureSearch => {
                "ЗНАЙДЕНО ПОШУКОМ — таблиця розділів сюди не вказувала".to_string()
            }
        }
    }
}
