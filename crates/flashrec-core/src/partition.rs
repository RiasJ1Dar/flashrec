//! Пошук файлової системи всередині образу цілого диска.
//!
//! Образ фізичного диска починається з таблиці розділів, тож том NTFS лежить
//! десь далі. Замість того щоб змушувати користувача вираховувати зсув,
//! flashrec читає MBR, а якщо й таблиці немає — шукає завантажувальний запис
//! NTFS напряму.

use std::io;

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
    /// Типи розділів, де буває NTFS (або exFAT, що ділить із ним тип 7).
    pub fn is_ntfs_candidate(&self) -> bool {
        matches!(self.mbr_type, 0x07 | 0x17 | 0x27)
    }

    pub fn type_name(&self) -> &'static str {
        match self.mbr_type {
            0x01 | 0x04 | 0x06 | 0x0B | 0x0C | 0x0E => "FAT",
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

/// Визначити, де починається том NTFS.
///
/// Пробує по черзі: завантажувальний запис NTFS на зсуві 0 (образ тому, а не
/// диска); розділи NTFS із MBR; потім обмежений пошук підпису NTFS, що
/// рятує, коли таблицю розділів знищено.
pub fn locate_ntfs<D: BlockDevice>(dev: &mut D) -> io::Result<NtfsLocation> {
    let mut probe = vec![0u8; 512];

    if dev.read_at(0, &mut probe).is_ok() && crate::ntfs::NtfsBoot::parse(&probe).is_ok() {
        return Ok(NtfsLocation {
            offset: 0,
            len: dev.len(),
            how: LocationSource::VolumeImage,
        });
    }

    if let Ok(parts) = read_mbr(dev) {
        if let Some(p) = parts.iter().find(|p| p.is_ntfs_candidate()) {
            return Ok(NtfsLocation {
                offset: p.offset,
                len: p.len.min(dev.len().saturating_sub(p.offset)),
                how: LocationSource::PartitionTable {
                    index: p.index,
                    mbr_type: p.mbr_type,
                },
            });
        }
        // Таблиця є, але розділу NTFS у ній немає — пошук однаково вартий спроби.
    }

    // Перебрати перші 256 МіБ по межах секторів у пошуках завантажувального запису.
    let sector = dev.sector_size().max(512) as u64;
    let limit = (256u64 << 20).min(dev.len());
    let mut at = 0u64;
    while at + 512 <= limit {
        if dev.read_at(at, &mut probe).is_ok() && crate::ntfs::NtfsBoot::parse(&probe).is_ok() {
            return Ok(NtfsLocation {
                offset: at,
                len: dev.len() - at,
                how: LocationSource::SignatureSearch,
            });
        }
        at += sector;
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "завантажувального запису NTFS немає ні на зсуві 0, ні в MBR, ні в перших 256 МіБ",
    ))
}

#[derive(Debug, Clone, Copy)]
pub struct NtfsLocation {
    pub offset: u64,
    pub len: u64,
    pub how: LocationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationSource {
    /// Образ тому; NTFS починається з байта 0.
    VolumeImage,
    PartitionTable { index: u8, mbr_type: u8 },
    /// Знайдено пошуком — таблиця розділів не допомогла.
    SignatureSearch,
}

impl LocationSource {
    pub fn describe(&self) -> String {
        match self {
            LocationSource::VolumeImage => "NTFS починається з зсуву 0 (образ тому)".to_string(),
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
