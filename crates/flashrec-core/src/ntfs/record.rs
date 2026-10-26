//! Записи MFT, їхні атрибути і runlist-и, що вказують, де лежать дані файлу.

use std::io;

use super::{bad, MftRef};
use crate::reader::{u16_at, u32_at, u64_at};

pub const ATTR_STANDARD_INFORMATION: u32 = 0x10;
pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_INDEX_ROOT: u32 = 0x90;
pub const ATTR_END: u32 = 0xFFFF_FFFF;

const FLAG_RECORD_IN_USE: u16 = 0x0001;
const FLAG_RECORD_IS_DIRECTORY: u16 = 0x0002;

pub const ATTR_FLAG_COMPRESSED: u16 = 0x0001;
pub const ATTR_FLAG_ENCRYPTED: u16 = 0x4000;
pub const ATTR_FLAG_SPARSE: u16 = 0x8000;

/// Один розібраний запис MFT, з уже застосованим виправленням послідовності.
#[derive(Debug, Clone)]
pub struct MftRecord {
    /// Байти запису після виправлення.
    pub data: Vec<u8>,
    pub record_number: u64,
    pub sequence: u16,
    pub in_use: bool,
    pub is_directory: bool,
    /// Не нуль, коли це продовження іншого запису.
    pub base_record: MftRef,
    first_attr_offset: usize,
    used_size: usize,
}

impl MftRecord {
    /// Розібрати запис із сирих байтів, скасувавши масив послідовності оновлень.
    ///
    /// `sector_size` — розмір сектора тому: виправлення замінює два останні байти
    /// кожного сектора в записі.
    pub fn parse(mut data: Vec<u8>, sector_size: u32) -> io::Result<Self> {
        if data.len() < 48 {
            return Err(bad("запис MFT коротший за свій заголовок"));
        }
        if &data[0..4] != b"FILE" {
            return Err(bad("немає підпису FILE — це не запис MFT"));
        }

        let usa_offset = u16_at(&data, 0x04) as usize;
        let usa_count = u16_at(&data, 0x06) as usize;
        apply_fixup(&mut data, usa_offset, usa_count, sector_size)?;

        let flags = u16_at(&data, 0x16);
        let first_attr_offset = u16_at(&data, 0x14) as usize;
        let used_size = u32_at(&data, 0x18) as usize;

        if first_attr_offset < 24 || first_attr_offset >= data.len() {
            return Err(bad(format!(
                "зсув першого атрибута {first_attr_offset} поза межами запису"
            )));
        }

        Ok(Self {
            record_number: u32_at(&data, 0x2C) as u64,
            sequence: u16_at(&data, 0x10),
            in_use: flags & FLAG_RECORD_IN_USE != 0,
            is_directory: flags & FLAG_RECORD_IS_DIRECTORY != 0,
            base_record: MftRef(u64_at(&data, 0x20)),
            first_attr_offset,
            used_size: used_size.min(data.len()),
            data,
        })
    }

    /// Обійти атрибути запису.
    pub fn attributes(&self) -> AttributeIter<'_> {
        AttributeIter {
            data: &self.data,
            at: self.first_attr_offset,
            limit: if self.used_size > self.first_attr_offset {
                self.used_size
            } else {
                self.data.len()
            },
        }
    }

    /// Найкраще ім'я файлу: Win32 має перевагу над коротким псевдонімом DOS 8.3.
    pub fn file_name(&self) -> Option<FileNameAttr> {
        let mut best: Option<FileNameAttr> = None;
        for attr in self.attributes() {
            if attr.type_id != ATTR_FILE_NAME {
                continue;
            }
            let Some(value) = attr.resident_value(&self.data) else {
                continue;
            };
            let Some(parsed) = FileNameAttr::parse(value) else {
                continue;
            };
            // Простір імен 2 — коротке ім'я DOS; будь-яке інше краще.
            let better = match &best {
                None => true,
                Some(current) => current.namespace == 2 && parsed.namespace != 2,
            };
            if better {
                best = Some(parsed);
            }
        }
        best
    }

    /// Мітки часу з `$STANDARD_INFORMATION`, якщо він є.
    pub fn timestamps(&self) -> Option<Timestamps> {
        for attr in self.attributes() {
            if attr.type_id != ATTR_STANDARD_INFORMATION {
                continue;
            }
            let value = attr.resident_value(&self.data)?;
            if value.len() < 0x20 {
                return None;
            }
            return Some(Timestamps {
                created: u64_at(value, 0x00),
                modified: u64_at(value, 0x08),
                mft_changed: u64_at(value, 0x10),
                accessed: u64_at(value, 0x18),
            });
        }
        None
    }

    /// Безіменний атрибут `$DATA` — власне вміст файлу.
    pub fn data_attribute(&self) -> Option<DataAttribute> {
        for attr in self.attributes() {
            if attr.type_id != ATTR_DATA || !attr.name(&self.data).is_empty() {
                continue;
            }
            return Some(if attr.non_resident {
                DataAttribute::NonResident {
                    real_size: attr.real_size,
                    allocated_size: attr.allocated_size,
                    initialized_size: attr.initialized_size,
                    runs: attr.runlist(&self.data).unwrap_or_default(),
                    flags: attr.flags,
                }
            } else {
                DataAttribute::Resident {
                    bytes: attr.resident_value(&self.data).unwrap_or(&[]).to_vec(),
                }
            });
        }
        None
    }

    /// Іменовані альтернативні потоки даних — щоб нічого не губилось мовчки.
    pub fn named_streams(&self) -> Vec<String> {
        self.attributes()
            .filter(|a| a.type_id == ATTR_DATA)
            .map(|a| a.name(&self.data))
            .filter(|n| !n.is_empty())
            .collect()
    }
}

/// Скасувати масив послідовності оновлень: NTFS перезаписує два останні байти
/// кожного сектора контрольним значенням, а оригінали тримає в масиві.
fn apply_fixup(
    data: &mut [u8],
    usa_offset: usize,
    usa_count: usize,
    sector_size: u32,
) -> io::Result<()> {
    if usa_count == 0 {
        return Ok(());
    }
    let sector_size = sector_size.max(512) as usize;
    let array_bytes = usa_count * 2;
    if usa_offset + array_bytes > data.len() {
        return Err(bad("масив послідовності оновлень виходить за кінець запису"));
    }

    let usn = [data[usa_offset], data[usa_offset + 1]];
    // Елемент 0 — сам номер послідовності; елементи 1.. — збережені байти.
    for i in 1..usa_count {
        let sector_end = i * sector_size;
        if sector_end < 2 || sector_end > data.len() {
            return Err(bad(format!(
                "виправлення для сектора {i} виходить за межі {}-байтного запису",
                data.len()
            )));
        }
        let tail = sector_end - 2;
        // Заповнювач мусить збігатися, інакше запис розірваний.
        if data[tail] != usn[0] || data[tail + 1] != usn[1] {
            return Err(bad(format!(
                "розбіжність послідовності оновлень на зсуві {tail} — запис пошкоджено або обірвано посеред запису"
            )));
        }
        let saved = usa_offset + i * 2;
        data[tail] = data[saved];
        data[tail + 1] = data[saved + 1];
    }
    Ok(())
}

/// Заголовок одного атрибута всередині запису.
#[derive(Debug, Clone, Copy)]
pub struct Attribute {
    pub type_id: u32,
    pub length: usize,
    pub non_resident: bool,
    pub flags: u16,
    pub id: u16,
    name_offset: usize,
    name_len_chars: usize,
    /// Лише для резидентних.
    value_offset: usize,
    value_len: usize,
    /// Лише для нерезидентних.
    pub start_vcn: u64,
    pub last_vcn: u64,
    runlist_offset: usize,
    pub allocated_size: u64,
    pub real_size: u64,
    pub initialized_size: u64,
    /// Де цей атрибут починається в записі.
    base: usize,
}

impl Attribute {
    /// Ім'я атрибута (порожнє для безіменного потоку `$DATA`).
    pub fn name(&self, record: &[u8]) -> String {
        if self.name_len_chars == 0 {
            return String::new();
        }
        let start = self.base + self.name_offset;
        let end = start + self.name_len_chars * 2;
        if end > record.len() {
            return String::new();
        }
        utf16le_to_string(&record[start..end])
    }

    /// Значення атрибута — лише для резидентних.
    pub fn resident_value<'a>(&self, record: &'a [u8]) -> Option<&'a [u8]> {
        if self.non_resident {
            return None;
        }
        let start = self.base + self.value_offset;
        let end = start.checked_add(self.value_len)?;
        if end > record.len() {
            return None;
        }
        Some(&record[start..end])
    }

    /// Розкодувати runlist нерезидентного атрибута.
    pub fn runlist(&self, record: &[u8]) -> Option<Vec<DataRun>> {
        if !self.non_resident {
            return None;
        }
        let start = self.base + self.runlist_offset;
        let end = (self.base + self.length).min(record.len());
        if start >= end {
            return None;
        }
        decode_runlist(&record[start..end]).ok()
    }
}

pub struct AttributeIter<'a> {
    data: &'a [u8],
    at: usize,
    limit: usize,
}

impl<'a> Iterator for AttributeIter<'a> {
    type Item = Attribute;

    fn next(&mut self) -> Option<Attribute> {
        // Потрібна щонайменше фіксована частина заголовка.
        if self.at + 16 > self.limit {
            return None;
        }
        let base = self.at;
        let type_id = u32_at(self.data, base);
        if type_id == ATTR_END {
            return None;
        }
        let length = u32_at(self.data, base + 4) as usize;
        // Нульова чи завелика довжина зациклила б обхід — краще зупинитись.
        if length < 16 || base + length > self.limit {
            return None;
        }

        let non_resident = self.data[base + 8] != 0;
        let name_len_chars = self.data[base + 9] as usize;
        let name_offset = u16_at(self.data, base + 10) as usize;
        let flags = u16_at(self.data, base + 12);
        let id = u16_at(self.data, base + 14);

        let mut attr = Attribute {
            type_id,
            length,
            non_resident,
            flags,
            id,
            name_offset,
            name_len_chars,
            value_offset: 0,
            value_len: 0,
            start_vcn: 0,
            last_vcn: 0,
            runlist_offset: 0,
            allocated_size: 0,
            real_size: 0,
            initialized_size: 0,
            base,
        };

        if non_resident {
            if base + 0x40 <= self.limit {
                attr.start_vcn = u64_at(self.data, base + 0x10);
                attr.last_vcn = u64_at(self.data, base + 0x18);
                attr.runlist_offset = u16_at(self.data, base + 0x20) as usize;
                attr.allocated_size = u64_at(self.data, base + 0x28);
                attr.real_size = u64_at(self.data, base + 0x30);
                attr.initialized_size = u64_at(self.data, base + 0x38);
            }
        } else if base + 0x18 <= self.limit {
            attr.value_len = u32_at(self.data, base + 0x10) as usize;
            attr.value_offset = u16_at(self.data, base + 0x14) as usize;
        }

        self.at = base + length;
        Some(attr)
    }
}

/// Один фрагмент файлу: `length_clusters` кластерів, починаючи з `lcn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataRun {
    /// `None` для розрідженого фрагмента — дірки, що читається нулями.
    pub lcn: Option<i64>,
    pub length_clusters: u64,
}

/// Розкодувати runlist NTFS.
///
/// Кожен елемент починається з байта-заголовка: молодший півбайт — кількість
/// байтів поля довжини, старший — кількість байтів дельти LCN. Нульовий
/// заголовок завершує список; дельта нульової ширини означає розріджений фрагмент.
pub fn decode_runlist(buf: &[u8]) -> io::Result<Vec<DataRun>> {
    let mut runs = Vec::new();
    let mut at = 0usize;
    let mut current_lcn: i64 = 0;

    while at < buf.len() {
        let header = buf[at];
        if header == 0 {
            break;
        }
        at += 1;

        let len_bytes = (header & 0x0F) as usize;
        let lcn_bytes = (header >> 4) as usize;
        if len_bytes == 0 || len_bytes > 8 || lcn_bytes > 8 {
            return Err(bad(format!("зіпсований байт-заголовок runlist {header:#04x}")));
        }
        if at + len_bytes + lcn_bytes > buf.len() {
            return Err(bad("елемент runlist обрізано"));
        }

        let length_clusters = read_le_unsigned(&buf[at..at + len_bytes]);
        at += len_bytes;

        if lcn_bytes == 0 {
            runs.push(DataRun {
                lcn: None,
                length_clusters,
            });
        } else {
            current_lcn += read_le_signed(&buf[at..at + lcn_bytes]);
            at += lcn_bytes;
            if current_lcn < 0 {
                return Err(bad("runlist вказує на від'ємний кластер"));
            }
            runs.push(DataRun {
                lcn: Some(current_lcn),
                length_clusters,
            });
        }
    }

    Ok(runs)
}

fn read_le_unsigned(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, b) in bytes.iter().enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    v
}

fn read_le_signed(bytes: &[u8]) -> i64 {
    let mut v = read_le_unsigned(bytes);
    // Розширити знак від старшого біта найстаршого наявного байта.
    let bits = bytes.len() * 8;
    if bits < 64 && v & (1 << (bits - 1)) != 0 {
        v |= !0u64 << bits;
    }
    v as i64
}

/// Вміст файлу: або прямо в записі, або в кластерах.
#[derive(Debug, Clone)]
pub enum DataAttribute {
    Resident {
        bytes: Vec<u8>,
    },
    NonResident {
        real_size: u64,
        allocated_size: u64,
        initialized_size: u64,
        runs: Vec<DataRun>,
        flags: u16,
    },
}

impl DataAttribute {
    pub fn size(&self) -> u64 {
        match self {
            DataAttribute::Resident { bytes } => bytes.len() as u64,
            DataAttribute::NonResident { real_size, .. } => *real_size,
        }
    }

    /// Стиснені й зашифровані потоки flashrec не розкодовує; викликач мусить
    /// так і сказати, а не записати сміття.
    pub fn unsupported_encoding(&self) -> Option<&'static str> {
        match self {
            DataAttribute::NonResident { flags, .. } => {
                if flags & ATTR_FLAG_ENCRYPTED != 0 {
                    Some("зашифрований EFS")
                } else if flags & ATTR_FLAG_COMPRESSED != 0 {
                    Some("стиснений NTFS")
                } else {
                    None
                }
            }
            DataAttribute::Resident { .. } => None,
        }
    }
}

/// Вміст атрибута `$FILE_NAME`.
#[derive(Debug, Clone)]
pub struct FileNameAttr {
    pub parent: MftRef,
    pub name: String,
    /// 0 = POSIX, 1 = Win32, 2 = DOS, 3 = Win32 і DOS.
    pub namespace: u8,
}

impl FileNameAttr {
    pub fn parse(value: &[u8]) -> Option<Self> {
        if value.len() < 0x42 {
            return None;
        }
        let name_len_chars = value[0x40] as usize;
        let start = 0x42;
        let end = start + name_len_chars * 2;
        if end > value.len() {
            return None;
        }
        Some(Self {
            parent: MftRef(u64_at(value, 0x00)),
            name: utf16le_to_string(&value[start..end]),
            namespace: value[0x41],
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Timestamps {
    pub created: u64,
    pub modified: u64,
    pub mft_changed: u64,
    pub accessed: u64,
}

/// Розкодувати UTF-16LE, замінюючи неправильне, а не падаючи.
pub fn utf16le_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_two_extent_runlist() {
        // 0x21 0x18 0x34 0x56 => 0x18 кластерів на LCN 0x5634
        // 0x11 0x10 0x05      => 0x10 кластерів на LCN 0x5634 + 5
        // 0x00                => кінець
        let buf = [0x21, 0x18, 0x34, 0x56, 0x11, 0x10, 0x05, 0x00];
        let runs = decode_runlist(&buf).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].length_clusters, 0x18);
        assert_eq!(runs[0].lcn, Some(0x5634));
        assert_eq!(runs[1].lcn, Some(0x5634 + 5));
    }

    #[test]
    fn decodes_a_negative_lcn_delta() {
        // 0x21 0x30 0x00 0x04 => 0x30 кластерів на LCN 0x0400
        // 0x21 0x10 0x00 0xFF => дельта 0xFF00 = -256, тобто LCN 0x0300
        let buf = [0x21, 0x30, 0x00, 0x04, 0x21, 0x10, 0x00, 0xFF, 0x00];
        let runs = decode_runlist(&buf).unwrap();
        assert_eq!(runs[0].lcn, Some(0x0400));
        assert_eq!(runs[1].lcn, Some(0x0400 - 256));
    }

    #[test]
    fn rejects_a_delta_that_goes_below_cluster_zero() {
        // LCN 0x60, потім дельта -256 => -160: зіпсований runlist, а не файл.
        let buf = [0x11, 0x30, 0x60, 0x21, 0x10, 0x00, 0xFF, 0x00];
        assert!(decode_runlist(&buf).is_err());
    }

    #[test]
    fn recognises_a_sparse_run() {
        let buf = [0x01, 0x20, 0x00];
        let runs = decode_runlist(&buf).unwrap();
        assert_eq!(runs[0].lcn, None);
        assert_eq!(runs[0].length_clusters, 0x20);
    }

    #[test]
    fn rejects_a_truncated_runlist() {
        assert!(decode_runlist(&[0x21, 0x18, 0x34]).is_err());
    }

    #[test]
    fn fixup_restores_the_sector_tail() {
        let mut rec = vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        let usa_offset = 0x30usize;
        rec[0x04..0x06].copy_from_slice(&(usa_offset as u16).to_le_bytes());
        rec[0x06..0x08].copy_from_slice(&3u16.to_le_bytes());
        rec[0x14..0x16].copy_from_slice(&56u16.to_le_bytes());
        rec[0x18..0x1C].copy_from_slice(&1024u32.to_le_bytes());
        // USN, потім два збережені хвостові слова.
        rec[usa_offset] = 0xAA;
        rec[usa_offset + 1] = 0xBB;
        rec[usa_offset + 2] = 0x01;
        rec[usa_offset + 3] = 0x02;
        rec[usa_offset + 4] = 0x03;
        rec[usa_offset + 5] = 0x04;
        // Заповнювачі в кінці секторів 1 і 2.
        rec[510] = 0xAA;
        rec[511] = 0xBB;
        rec[1022] = 0xAA;
        rec[1023] = 0xBB;

        let parsed = MftRecord::parse(rec, 512).unwrap();
        assert_eq!(&parsed.data[510..512], &[0x01, 0x02]);
        assert_eq!(&parsed.data[1022..1024], &[0x03, 0x04]);
    }

    #[test]
    fn fixup_detects_a_torn_record() {
        let mut rec = vec![0u8; 1024];
        rec[0..4].copy_from_slice(b"FILE");
        rec[0x04..0x06].copy_from_slice(&0x30u16.to_le_bytes());
        rec[0x06..0x08].copy_from_slice(&3u16.to_le_bytes());
        rec[0x14..0x16].copy_from_slice(&56u16.to_le_bytes());
        rec[0x30] = 0xAA;
        rec[0x31] = 0xBB;
        // Хвостові заповнювачі лишились нулями — розбіжність мусить бути помічена.
        assert!(MftRecord::parse(rec, 512).is_err());
    }
}
