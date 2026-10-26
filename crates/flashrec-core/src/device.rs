//! Пошук фізичних дисків і відкриття їх на сире читання.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use crate::reader::BlockDevice;

/// Що можна сказати користувачу про диск, перш ніж він його обере.
#[derive(Debug, Clone)]
pub struct DiskInfo {
    /// Номер фізичного диска, як у `\\.\PhysicalDrive2`.
    pub index: u32,
    /// Шлях для сирого доступу.
    pub path: String,
    pub model: String,
    pub serial: Option<String>,
    pub bus: String,
    pub removable: bool,
    pub size_bytes: u64,
    pub sector_size: u32,
}

impl DiskInfo {
    /// `true`, коли це схоже на флешку чи карту пам'яті, а не на системний
    /// диск. GUI ставить такі першими й попереджає, перш ніж чіпати інші.
    pub fn is_likely_removable_media(&self) -> bool {
        self.removable || matches!(self.bus.as_str(), "USB" | "SD" | "MMC")
    }

    pub fn size_human(&self) -> String {
        human_bytes(self.size_bytes)
    }
}

impl fmt::Display for DiskInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "диск {} — {} ({}, {}{})",
            self.index,
            self.model,
            self.size_human(),
            self.bus,
            if self.removable { ", знімний" } else { "" }
        )?;
        if let Some(sn) = &self.serial {
            write!(f, ", серійний {sn}")?;
        }
        Ok(())
    }
}

/// Кількість байтів так, як її читає людина.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["Б", "КіБ", "МіБ", "ГіБ", "ТіБ", "ПіБ"];
    if n < 1024 {
        return format!("{n} Б");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

/// Перелічити фізичні диски, перебравши `\\.\PhysicalDrive0..=31`.
///
/// Диски, які не відкриваються, мовчки пропускаються — це звичайна відповідь
/// для номера, за яким диска немає. Диск, що відкрився, але не каже свого
/// розміру, теж пропускається: знімати з нього образ означало б гадати.
#[cfg(windows)]
pub fn list_disks() -> Vec<DiskInfo> {
    let mut disks = Vec::new();
    for index in 0..32u32 {
        let path = format!(r"\\.\PhysicalDrive{index}");
        let Ok(file) = File::open(&path) else { continue };
        let Ok(size_bytes) = crate::sys::disk_length(&file) else {
            continue;
        };
        if size_bytes == 0 {
            continue;
        }
        let sector_size = crate::sys::disk_sector_size(&file).unwrap_or(512);
        let identity = crate::sys::storage_identity(&file).unwrap_or_default();

        let model = match (&identity.vendor, &identity.product) {
            (Some(v), Some(p)) => format!("{v} {p}"),
            (None, Some(p)) => p.clone(),
            (Some(v), None) => v.clone(),
            (None, None) => "Невідомий пристрій".to_string(),
        };

        disks.push(DiskInfo {
            index,
            path,
            model,
            serial: identity.serial,
            bus: crate::sys::bus_type_name(identity.bus_type).to_string(),
            removable: identity.removable,
            size_bytes,
            sector_size: if sector_size == 0 { 512 } else { sector_size },
        });
    }
    disks
}

/// Поза Windows flashrec так само читає образи; переліку живих дисків немає.
#[cfg(not(windows))]
pub fn list_disks() -> Vec<DiskInfo> {
    Vec::new()
}

/// На якому фізичному диску (дисках) лежить том шляху: `E:\out\x.img` → `[1]`.
///
/// Потрібно, щоб не дати писати результат на той самий диск, який
/// відновлюється: це затерло б дані, що ще чекають на порятунок.
#[cfg(windows)]
pub fn disks_of_path(path: &std::path::Path) -> io::Result<Vec<u32>> {
    // Том визначається літерою найближчого наявного предка.
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        if !probe.pop() {
            break;
        }
    }
    let absolute = std::fs::canonicalize(&probe).unwrap_or(probe);
    let text = absolute.to_string_lossy().replace(r"\\?\", "");
    let letter = text
        .chars()
        .next()
        .filter(|c| c.is_ascii_alphabetic() && text[1..].starts_with(':'))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: шлях не на диску з літерою", path.display()),
            )
        })?;
    let volume = File::open(format!(r"\\.\{letter}:"))?;
    crate::sys::volume_disk_numbers(&volume)
}

#[cfg(not(windows))]
pub fn disks_of_path(_path: &std::path::Path) -> io::Result<Vec<u32>> {
    Ok(Vec::new())
}

/// Відмовити, якщо шлях для результату лежить на диску-джерелі.
///
/// Коли відповідь визначити не вдалося, викликачу про це кажуть прямо, а не
/// пропускають перевірку мовчки.
pub fn check_output_not_on_disk(output: &std::path::Path, source_disk: u32) -> Result<(), String> {
    match disks_of_path(output) {
        Ok(disks) if disks.contains(&source_disk) => Err(format!(
            "{} лежить на диску {source_disk} — тому самому, який відновлюємо. Запис туди \
             затре саме ті дані, які ви рятуєте. Оберіть теку на іншому диску.",
            output.display()
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "не вдалося визначити, на якому диску лежить {} ({e}); вгадувати не буду. \
             Оберіть теку на внутрішньому або іншому USB-диску.",
            output.display()
        )),
    }
}

/// Попередження, якщо шлях для результату лежить на знімному носії.
///
/// Запис образу чи тисяч відновлених файлів на USB-флешку буває в десятки разів
/// повільнішим, ніж на внутрішній SSD: флешки погано тримають дрібні записи, а
/// антивірус перечитує файл, що росте. Під час розробки образ на флешку йшов
/// ~400 КіБ/с проти ~20 МіБ/с на NVMe. Це не помилка, тож запис не забороняється —
/// лише попередження.
pub fn removable_output_warning(output: &std::path::Path) -> Option<String> {
    let disks = disks_of_path(output).ok()?;
    let info = list_disks()
        .into_iter()
        .find(|d| disks.contains(&d.index) && d.is_likely_removable_media())?;
    Some(format!(
        "{} лежить на знімному носії ({}). Запис туди може бути в десятки разів повільнішим, \
         ніж на внутрішній диск; якщо поступ повзе — оберіть теку на внутрішньому SSD.",
        output.display(),
        info.model
    ))
}

/// Фізичний диск, відкритий на читання.
pub struct RawDisk {
    file: File,
    len: u64,
    sector_size: u32,
}

impl RawDisk {
    /// Відкрити диск за фізичним номером.
    ///
    /// Потребує прав адміністратора; без них Windows відповідає «Access is
    /// denied» (os error 5), і це передається як є, без прикрашання.
    pub fn open_index(index: u32) -> io::Result<Self> {
        Self::open_path(&format!(r"\\.\PhysicalDrive{index}"))
    }

    pub fn open_path(path: &str) -> io::Result<Self> {
        let file = File::open(path).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{path}: доступ заборонено — запустіть flashrec від імені адміністратора"
                    ),
                )
            } else {
                io::Error::new(e.kind(), format!("{path}: {e}"))
            }
        })?;

        #[cfg(windows)]
        let (len, sector_size) = {
            let len = crate::sys::disk_length(&file)?;
            let sector_size = crate::sys::disk_sector_size(&file).unwrap_or(512);
            (len, sector_size)
        };
        #[cfg(not(windows))]
        let (len, sector_size) = {
            let mut probe = &file;
            let len = probe.seek(SeekFrom::End(0))?;
            probe.seek(SeekFrom::Start(0))?;
            (len, 512u32)
        };

        Ok(Self {
            file,
            len,
            sector_size: if sector_size == 0 { 512 } else { sector_size },
        })
    }

    /// Прочитати один вирівняний блок і повернути, скільки байтів прийшло.
    ///
    /// На відміну від [`BlockDevice::read_at`] терпить неповне читання — саме це
    /// потрібно при знятті образу, щоб точно звузити, які сектори збійні.
    pub fn read_block_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read(buf)
    }
}

impl BlockDevice for RawDisk {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.sector_size
    }
}
