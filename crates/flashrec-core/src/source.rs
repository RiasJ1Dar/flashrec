//! Відкрити те, на що вказав користувач — образ або живий диск, — і знайти в
//! ньому том NTFS. Спільне для CLI і GUI, щоб обидва описували том однаково.

use std::io;
use std::path::PathBuf;

use crate::device::{human_bytes, RawDisk};
use crate::ntfs::volume::NtfsVolume;
use crate::partition::{locate_ntfs, NtfsLocation};
use crate::reader::{AlignedDevice, BlockDevice, FileDevice, SubDevice};

/// Звідки читати.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Файл образу, знятий `flashrec image`, або будь-яка сира копія на кшталт `dd`.
    Image(PathBuf),
    /// Фізичний диск за номером. Читання потребує прав адміністратора.
    Disk(u32),
}

impl Source {
    pub fn describe(&self) -> String {
        match self {
            Source::Image(p) => format!("образ {}", p.display()),
            Source::Disk(n) => format!("живий диск {n}"),
        }
    }

    pub fn is_live_disk(&self) -> bool {
        matches!(self, Source::Disk(_))
    }
}

/// Відкрити джерело як побайтовий пристрій.
pub fn open_source(src: &Source) -> io::Result<Box<dyn BlockDevice>> {
    Ok(match src {
        Source::Image(path) => Box::new(
            FileDevice::open(path)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?,
        ),
        // Живий диск приймає лише вирівняне за секторами читання.
        Source::Disk(n) => Box::new(AlignedDevice::new(RawDisk::open_index(*n)?)),
    })
}

/// Том NTFS разом із тим, як його знайдено.
pub struct OpenedVolume {
    pub volume: NtfsVolume<Box<dyn BlockDevice>>,
    pub offset: u64,
    pub len: u64,
    /// `None`, коли зсув задав сам викликач.
    pub location: Option<NtfsLocation>,
}

impl OpenedVolume {
    /// Рядки, які варто показати користувачу до початку сканування.
    pub fn describe(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match &self.location {
            Some(loc) => lines.push(format!(
                "том NTFS на зсуві {} ({}), {}",
                self.offset,
                human_bytes(self.len),
                loc.how.describe()
            )),
            None => lines.push(format!("том NTFS на зсуві {} (задано явно)", self.offset)),
        }
        let b = &self.volume.boot;
        lines.push(format!(
            "завантажувальний запис: {}; кластер {}, запис MFT {} байтів, MFT на кластері {}",
            self.volume.boot_source.describe(),
            human_bytes(b.cluster_size as u64),
            b.mft_record_size,
            b.mft_lcn
        ));
        lines
    }
}

/// Відкрити `src` і знайти в ньому том NTFS, якщо `offset` не задає його явно.
pub fn open_ntfs(src: &Source, offset: Option<u64>) -> io::Result<OpenedVolume> {
    let mut dev = open_source(src)?;
    let (offset, len, location) = match offset {
        Some(off) => (off, dev.len().saturating_sub(off), None),
        None => {
            let loc = locate_ntfs(&mut dev)?;
            (loc.offset, loc.len, Some(loc))
        }
    };
    let sub: Box<dyn BlockDevice> = Box::new(SubDevice::new(dev, offset, len));
    Ok(OpenedVolume {
        volume: NtfsVolume::open(sub)?,
        offset,
        len,
        location,
    })
}
