//! Побайтове читання з того, що побайтово не читається.
//!
//! Windows відмовляє в невирівняному читанні з сирого диска: і зсув, і довжина
//! мусять бути кратні розміру сектора. А парсеру NTFS треба прочитати
//! 48-байтний заголовок атрибута з довільного зсуву. [`BlockDevice`] ховає цю
//! різницю, тож усі верхні шари однаково працюють і з живим диском, і з образом.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Джерело байтів за довільними зсувами.
pub trait BlockDevice {
    /// Заповнити `buf` байтами від `offset` — або помилка без часткового результату.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Повний розмір у байтах.
    fn len(&self) -> u64;

    /// Розмір сектора, до якого вирівнюється читання.
    fn sector_size(&self) -> u32;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Зручність: прочитати рівно `n` байтів від `offset` у новий буфер.
    fn read_vec(&mut self, offset: u64, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.read_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// Дозволяє обирати джерело під час роботи програми (образ або живий диск).
impl BlockDevice for Box<dyn BlockDevice> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_at(offset, buf)
    }

    fn len(&self) -> u64 {
        (**self).len()
    }

    fn sector_size(&self) -> u32 {
        (**self).sector_size()
    }
}

/// Файл образу або будь-який інший звичайний файл із довільним позиціюванням.
pub struct FileDevice {
    file: File,
    len: u64,
    sector_size: u32,
}

impl FileDevice {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file,
            len,
            sector_size: 512,
        })
    }

    /// Замінити припущений розмір сектора (узятий із завантажувального запису NTFS).
    pub fn with_sector_size(mut self, sector_size: u32) -> Self {
        if sector_size > 0 {
            self.sector_size = sector_size;
        }
        self
    }
}

impl BlockDevice for FileDevice {
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

/// Обгортка над пристроєм, який терпить лише вирівняне за секторами читання.
///
/// Запит розширюється до охопних секторів, читається, а потім обрізається до
/// того, що просив викликач.
pub struct AlignedDevice<D: BlockDevice> {
    inner: D,
    scratch: Vec<u8>,
}

impl<D: BlockDevice> AlignedDevice<D> {
    pub fn new(inner: D) -> Self {
        Self {
            inner,
            scratch: Vec::new(),
        }
    }

    pub fn into_inner(self) -> D {
        self.inner
    }
}

impl<D: BlockDevice> BlockDevice for AlignedDevice<D> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let sector = self.inner.sector_size().max(1) as u64;
        let start = offset - (offset % sector);
        let end_unaligned = offset.checked_add(buf.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "переповнення зсуву читання")
        })?;
        let end = end_unaligned.div_ceil(sector) * sector;
        let span = (end - start) as usize;

        if self.scratch.len() < span {
            self.scratch.resize(span, 0);
        }
        self.inner.read_at(start, &mut self.scratch[..span])?;

        let from = (offset - start) as usize;
        buf.copy_from_slice(&self.scratch[from..from + buf.len()]);
        Ok(())
    }

    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
}

/// Пристрій зі сталим зсувом — розділ усередині образу цілого диска.
pub struct SubDevice<D: BlockDevice> {
    inner: D,
    base: u64,
    len: u64,
}

impl<D: BlockDevice> SubDevice<D> {
    pub fn new(inner: D, base: u64, len: u64) -> Self {
        Self { inner, base, len }
    }
}

impl<D: BlockDevice> BlockDevice for SubDevice<D> {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = offset.saturating_add(buf.len() as u64);
        if end > self.len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "читання {} байтів зі зсуву {} виходить за кінець розділу ({} байтів)",
                    buf.len(),
                    offset,
                    self.len
                ),
            ));
        }
        self.inner.read_at(self.base + offset, buf)
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
}

/// Читання little-endian чисел — ними користуються всі парсери дискових структур.
pub(crate) fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([buf[at], buf[at + 1]])
}

pub(crate) fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

pub(crate) fn u64_at(buf: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        buf[at],
        buf[at + 1],
        buf[at + 2],
        buf[at + 3],
        buf[at + 4],
        buf[at + 5],
        buf[at + 6],
        buf[at + 7],
    ])
}
