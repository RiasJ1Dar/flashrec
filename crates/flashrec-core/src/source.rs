//! Відкрити те, на що вказав користувач — образ або живий диск, — і знайти в
//! ньому том. Спільне для CLI і GUI, щоб обидва описували том однаково.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use crate::device::{human_bytes, RawDisk};
use crate::exfat::ExFatVolume;
use crate::fat::FatVolume;
use crate::files::{FileEntry, Filesystem, ReadFiles, ScanProgress, ScanResult};
use crate::ntfs::volume::NtfsVolume;
use crate::partition::{locate_volume, probe_filesystem, VolumeLocation};
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

type Dev = Box<dyn BlockDevice>;

/// Відкритий том будь-якої з підтримуваних файлових систем.
pub enum Volume {
    Ntfs(NtfsVolume<Dev>),
    Fat(FatVolume<Dev>),
    ExFat(ExFatVolume<Dev>),
}

impl Volume {
    /// Відкрити том, який почнеться з байта 0 `dev`, як файлову систему `fs`.
    pub fn open(dev: Dev, fs: Filesystem) -> io::Result<Self> {
        Ok(match fs {
            Filesystem::Ntfs => Volume::Ntfs(NtfsVolume::open(dev)?),
            Filesystem::Fat12 | Filesystem::Fat16 | Filesystem::Fat32 => {
                Volume::Fat(FatVolume::open(dev)?)
            }
            Filesystem::ExFat => Volume::ExFat(ExFatVolume::open(dev)?),
        })
    }

    pub fn filesystem(&self) -> Filesystem {
        match self {
            Volume::Ntfs(_) => Filesystem::Ntfs,
            Volume::Fat(v) => v.boot.kind,
            Volume::ExFat(_) => Filesystem::ExFat,
        }
    }

    /// Перелічити файли звичайним для цієї файлової системи способом.
    pub fn scan(
        &mut self,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        match self {
            Volume::Ntfs(v) => v.scan(cancel, progress),
            Volume::Fat(v) => v.scan(cancel, progress),
            Volume::ExFat(v) => v.scan(cancel, progress),
        }
    }

    /// Глибокий пошук: NTFS — перебір записів MFT за підписом, FAT і exFAT —
    /// перебір усіх кластерів у пошуках тек, на які вже ніщо не вказує.
    pub fn scan_deep(
        &mut self,
        cancel: &AtomicBool,
        progress: &mut dyn FnMut(ScanProgress),
    ) -> io::Result<ScanResult> {
        match self {
            Volume::Ntfs(v) => v.scan_by_signature(cancel, progress),
            Volume::Fat(v) => v.scan_deep(cancel, progress),
            Volume::ExFat(v) => v.scan_deep(cancel, progress),
        }
    }

    /// Рядки про сам том: завантажувальний запис і розмітку.
    fn describe(&self) -> Vec<String> {
        match self {
            Volume::Ntfs(v) => {
                let b = &v.boot;
                vec![format!(
                    "завантажувальний запис: {}; кластер {}, запис MFT {} байтів, MFT на кластері {}",
                    v.boot_source.describe(),
                    human_bytes(b.cluster_size as u64),
                    b.mft_record_size,
                    b.mft_lcn
                )]
            }
            Volume::Fat(v) => v.describe(),
            Volume::ExFat(v) => v.describe(),
        }
    }
}

impl ReadFiles for Volume {
    fn read_file_data(&mut self, entry: &FileEntry) -> io::Result<(Vec<u8>, u64)> {
        match self {
            Volume::Ntfs(v) => v.read_file_data(entry),
            Volume::Fat(v) => v.read_file_data(entry),
            Volume::ExFat(v) => v.read_file_data(entry),
        }
    }
}

/// Том разом із тим, як його знайдено.
pub struct OpenedVolume {
    pub volume: Volume,
    pub offset: u64,
    pub len: u64,
    /// `None`, коли зсув задав сам викликач.
    pub location: Option<VolumeLocation>,
}

impl OpenedVolume {
    /// Рядки, які варто показати користувачу до початку сканування.
    pub fn describe(&self) -> Vec<String> {
        let fs = self.volume.filesystem().name();
        let mut lines = Vec::new();
        match &self.location {
            Some(loc) => lines.push(format!(
                "том {fs} на зсуві {} ({}), {}",
                self.offset,
                human_bytes(self.len),
                loc.how.describe()
            )),
            None => lines.push(format!("том {fs} на зсуві {} (задано явно)", self.offset)),
        }
        lines.extend(self.volume.describe());
        lines
    }
}

/// Відкрити `src` і знайти в ньому том, якщо `offset` не задає його явно.
pub fn open_volume(src: &Source, offset: Option<u64>) -> io::Result<OpenedVolume> {
    let mut dev = open_source(src)?;
    let (offset, len, filesystem, location) = match offset {
        Some(off) => {
            let len = dev.len().saturating_sub(off);
            let fs = probe_filesystem(&mut dev, off, len).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "на зсуві {off} немає завантажувального запису NTFS, FAT чи exFAT \
                         (ні основного, ні резервного)"
                    ),
                )
            })?;
            (off, len, fs, None)
        }
        None => {
            let loc = locate_volume(&mut dev)?;
            (loc.offset, loc.len, loc.filesystem, Some(loc))
        }
    };
    let sub: Dev = Box::new(SubDevice::new(dev, offset, len));
    Ok(OpenedVolume {
        volume: Volume::open(sub, filesystem)?,
        offset,
        len,
        location,
    })
}
