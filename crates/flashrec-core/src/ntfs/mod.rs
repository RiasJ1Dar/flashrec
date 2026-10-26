//! Дискові структури NTFS — рівно стільки, скільки треба, щоб підняти
//! пошкоджений том.
//!
//! Будова звичайна, три шари: завантажувальний запис каже, де лежить MFT; кожен
//! запис MFT описує один файл; атрибути запису містять ім'я, батьківську теку і
//! або самі дані, або runlist, що вказує, де вони.

pub mod record;
pub mod volume;

use std::io;

use crate::reader::{u16_at, u64_at, BlockDevice};

/// Запис `$Boot` на початку тому NTFS.
#[derive(Debug, Clone)]
pub struct NtfsBoot {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_size: u32,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mft_mirror_lcn: u64,
    pub mft_record_size: u32,
    pub index_record_size: u32,
    pub volume_serial: u64,
}

impl NtfsBoot {
    /// Розібрати завантажувальний сектор, відкинувши все, що не схоже на NTFS.
    pub fn parse(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < 512 {
            return Err(bad("буфер завантажувального сектора коротший за 512 байтів"));
        }
        if &buf[3..11] != b"NTFS    " {
            return Err(bad(
                "немає підпису NTFS на зсуві 3 — це не том NTFS, або завантажувальний сектор знищено",
            ));
        }

        let bytes_per_sector = u16_at(buf, 0x0B) as u32;
        if !(512..=4096).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
            return Err(bad(format!(
                "неправдоподібний розмір сектора {bytes_per_sector}"
            )));
        }

        // Значення 0x80 і більше кодує 2^(256-значення) секторів на кластер.
        let raw_spc = buf[0x0D];
        let sectors_per_cluster = if raw_spc >= 0x80 {
            1u32 << (256 - raw_spc as u32)
        } else {
            raw_spc as u32
        };
        if sectors_per_cluster == 0 {
            return Err(bad("секторів на кластер — нуль"));
        }

        // Так само від'ємний розмір означає степінь двійки в байтах.
        let decode_size = |raw: u8, cluster_size: u32| -> u32 {
            let signed = raw as i8;
            if signed < 0 {
                1u32 << (-signed as u32)
            } else {
                signed as u32 * cluster_size
            }
        };

        let cluster_size = bytes_per_sector * sectors_per_cluster;
        let mft_record_size = decode_size(buf[0x40], cluster_size);
        let index_record_size = decode_size(buf[0x44], cluster_size);

        if mft_record_size == 0 || mft_record_size % bytes_per_sector != 0 {
            return Err(bad(format!(
                "неправдоподібний розмір запису MFT {mft_record_size}"
            )));
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            cluster_size,
            total_sectors: u64_at(buf, 0x28),
            mft_lcn: u64_at(buf, 0x30),
            mft_mirror_lcn: u64_at(buf, 0x38),
            mft_record_size,
            index_record_size,
            volume_serial: u64_at(buf, 0x48),
        })
    }

    /// Зсув першого запису MFT у байтах.
    pub fn mft_offset(&self) -> u64 {
        self.mft_lcn * self.cluster_size as u64
    }

    /// Зсув дзеркала MFT — запасний шлях, коли сам `$MFT` не читається.
    pub fn mft_mirror_offset(&self) -> u64 {
        self.mft_mirror_lcn * self.cluster_size as u64
    }

    pub fn volume_size(&self) -> u64 {
        self.total_sectors * self.bytes_per_sector as u64
    }
}

/// Прочитати завантажувальний запис, а якщо основний пошкоджено — резервну
/// копію з останнього сектора тому.
///
/// NTFS тримає цю копію саме для такого випадку, і в RAW-тома дуже часто
/// пошкоджено лише перший сектор, а все інше ціле.
pub fn read_boot<D: BlockDevice>(dev: &mut D) -> io::Result<(NtfsBoot, BootSource)> {
    let mut buf = vec![0u8; 512];
    if dev.read_at(0, &mut buf).is_ok() {
        if let Ok(boot) = NtfsBoot::parse(&buf) {
            return Ok((boot, BootSource::Primary));
        }
    }

    // Резервна копія лежить в останньому секторі розділу.
    let len = dev.len();
    if len >= 512 {
        for candidate in [len - 512, len.saturating_sub(1024)] {
            if dev.read_at(candidate, &mut buf).is_ok() {
                if let Ok(boot) = NtfsBoot::parse(&buf) {
                    return Ok((boot, BootSource::Backup { offset: candidate }));
                }
            }
        }
    }

    Err(bad(
        "не вдалося розібрати ні основний, ні резервний завантажувальний сектор NTFS",
    ))
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

/// 64-бітне посилання MFT: 48 бітів номера запису і 16 бітів послідовності.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MftRef(pub u64);

impl MftRef {
    pub fn number(&self) -> u64 {
        self.0 & 0x0000_FFFF_FFFF_FFFF
    }

    pub fn sequence(&self) -> u16 {
        (self.0 >> 48) as u16
    }
}

/// Відомі номери записів MFT.
pub const MFT_RECORD_MFT: u64 = 0;
pub const MFT_RECORD_ROOT: u64 = 5;
/// Записи з меншим номером — службові файли NTFS (`$MFT`, `$LogFile`, …).
pub const FIRST_USER_RECORD: u64 = 16;

/// Перевести FILETIME Windows у секунди Unix, або `None`, якщо час не задано
/// чи він безглуздий.
pub fn filetime_to_unix(ft: u64) -> Option<i64> {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if ft < EPOCH_DIFF {
        return None;
    }
    Some(((ft - EPOCH_DIFF) / 10_000_000) as i64)
}

/// Показати FILETIME як `РРРР-ММ-ДД ГГ:ХХ:СС` UTC без окремого crate для дат.
pub fn format_filetime(ft: u64) -> String {
    let Some(secs) = filetime_to_unix(ft) else {
        return "-".to_string();
    };
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Алгоритм Говарда Гіннанта: дні від епохи → календарна дата.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub(crate) fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_boot() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        b[0x0D] = 8; // кластери по 4 КіБ
        b[0x28..0x30].copy_from_slice(&30_310_399u64.to_le_bytes());
        b[0x30..0x38].copy_from_slice(&786_432u64.to_le_bytes());
        b[0x38..0x40].copy_from_slice(&2u64.to_le_bytes());
        b[0x40] = 0xF6; // -10 => записи по 1024 байти
        b[0x44] = 0x01;
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    #[test]
    fn parses_a_normal_boot_record() {
        let boot = NtfsBoot::parse(&synthetic_boot()).unwrap();
        assert_eq!(boot.cluster_size, 4096);
        assert_eq!(boot.mft_record_size, 1024);
        assert_eq!(boot.mft_offset(), 786_432 * 4096);
    }

    #[test]
    fn rejects_a_non_ntfs_sector() {
        let mut b = synthetic_boot();
        b[3..11].copy_from_slice(b"MSDOS5.0");
        assert!(NtfsBoot::parse(&b).is_err());
    }

    #[test]
    fn mft_reference_splits_into_number_and_sequence() {
        let r = MftRef(0x0001_0000_0000_0005);
        assert_eq!(r.number(), 5);
        assert_eq!(r.sequence(), 1);
    }

    #[test]
    fn filetime_converts_to_a_readable_date() {
        // 2021-01-01 00:00:00 UTC = unix 1_609_459_200
        let ft = 132_539_328_000_000_000u64;
        assert_eq!(format_filetime(ft), "2021-01-01 00:00:00");
    }
}
