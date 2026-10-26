//! Мінімальні біндінги Win32, написані вручну, щоб crate не мав залежностей.
//!
//! Лише те, без чого не обійтись при сирому доступі до диска: обгортка над
//! `DeviceIoControl` і кілька IOCTL, що повідомляють розмір, геометрію та
//! ідентичність диска. Читання й позиціювання йдуть через `std::fs::File` —
//! він уже відкриває сирі пристрої з `FILE_SHARE_READ | FILE_SHARE_WRITE`, і саме
//! цей режим спільного доступу дозволяє читати диск, який Windows уже змонтував.

#![allow(non_snake_case, non_camel_case_types)]
#![cfg(windows)]

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;

pub type HANDLE = *mut c_void;
pub type BOOL = i32;
pub type DWORD = u32;

#[link(name = "kernel32")]
extern "system" {
    fn DeviceIoControl(
        hDevice: HANDLE,
        dwIoControlCode: DWORD,
        lpInBuffer: *const c_void,
        nInBufferSize: DWORD,
        lpOutBuffer: *mut c_void,
        nOutBufferSize: DWORD,
        lpBytesReturned: *mut DWORD,
        lpOverlapped: *mut c_void,
    ) -> BOOL;
}

/// `CTL_CODE(FILE_DEVICE_DISK, 0x17, METHOD_BUFFERED, FILE_READ_ACCESS)`
pub const IOCTL_DISK_GET_LENGTH_INFO: DWORD = 0x0007_405C;
/// `CTL_CODE(FILE_DEVICE_DISK, 0x00, METHOD_BUFFERED, FILE_ANY_ACCESS)`
pub const IOCTL_DISK_GET_DRIVE_GEOMETRY: DWORD = 0x0007_0000;
/// `CTL_CODE(FILE_DEVICE_MASS_STORAGE, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)`
pub const IOCTL_STORAGE_QUERY_PROPERTY: DWORD = 0x002D_1400;
/// `CTL_CODE(IOCTL_VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)`
pub const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: DWORD = 0x0056_0000;

/// Тонка обгортка над `DeviceIoControl` для вже відкритого пристрою.
///
/// Повертає кількість байтів, які драйвер записав у `output`.
pub fn device_io_control(
    file: &File,
    code: DWORD,
    input: &[u8],
    output: &mut [u8],
) -> io::Result<usize> {
    let mut returned: DWORD = 0;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as HANDLE,
            code,
            if input.is_empty() {
                std::ptr::null()
            } else {
                input.as_ptr() as *const c_void
            },
            input.len() as DWORD,
            if output.is_empty() {
                std::ptr::null_mut()
            } else {
                output.as_mut_ptr() as *mut c_void
            },
            output.len() as DWORD,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(returned as usize)
    }
}

fn short_buffer(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{what}: драйвер повернув закороткий буфер"),
    )
}

/// Повний адресований розмір пристрою в байтах (`GET_LENGTH_INFORMATION`).
pub fn disk_length(file: &File) -> io::Result<u64> {
    let mut out = [0u8; 8];
    let n = device_io_control(file, IOCTL_DISK_GET_LENGTH_INFO, &[], &mut out)?;
    if n < 8 {
        return Err(short_buffer("IOCTL_DISK_GET_LENGTH_INFO"));
    }
    Ok(u64::from_le_bytes(out))
}

/// Логічний розмір сектора з `DISK_GEOMETRY.BytesPerSector` (зсув 20).
pub fn disk_sector_size(file: &File) -> io::Result<u32> {
    let mut out = [0u8; 24];
    let n = device_io_control(file, IOCTL_DISK_GET_DRIVE_GEOMETRY, &[], &mut out)?;
    if n < 24 {
        return Err(short_buffer("IOCTL_DISK_GET_DRIVE_GEOMETRY"));
    }
    Ok(u32::from_le_bytes([out[20], out[21], out[22], out[23]]))
}

/// Що `IOCTL_STORAGE_QUERY_PROPERTY` каже про ідентичність пристрою.
#[derive(Debug, Clone, Default)]
pub struct StorageIdentity {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub revision: Option<String>,
    pub serial: Option<String>,
    pub bus_type: u32,
    pub removable: bool,
}

/// Виробник, модель, серійний номер і тип шини відкритого пристрою.
///
/// Драйвер відповідає структурою `STORAGE_DEVICE_DESCRIPTOR`, де рядкові поля —
/// це зсуви в межах того самого буфера. Тому буфер розбирається за зсувами, а не
/// приводиться до структури: жодних припущень про вирівнювання й доповнення.
pub fn storage_identity(file: &File) -> io::Result<StorageIdentity> {
    // STORAGE_PROPERTY_QUERY { StorageDeviceProperty = 0, PropertyStandardQuery = 0, .. }
    let query = [0u8; 12];
    let mut buf = vec![0u8; 1024];
    let n = device_io_control(file, IOCTL_STORAGE_QUERY_PROPERTY, &query, &mut buf)?;
    if n < 36 {
        return Err(short_buffer("STORAGE_DEVICE_DESCRIPTOR"));
    }
    buf.truncate(n);

    let dword = |at: usize| -> u32 {
        u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
    };
    // Зсуви рахуються від початку дескриптора; 0 означає «не надано».
    let string_at = |off: u32| -> Option<String> {
        let start = off as usize;
        if off == 0 || start >= buf.len() {
            return None;
        }
        let end = buf[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(buf.len());
        let s = String::from_utf8_lossy(&buf[start..end]).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    };

    Ok(StorageIdentity {
        removable: buf[10] != 0,
        vendor: string_at(dword(12)),
        product: string_at(dword(16)),
        revision: string_at(dword(20)),
        serial: string_at(dword(24)),
        bus_type: dword(28),
    })
}

/// Номери фізичних дисків, на яких лежить змонтований том (`\\.\E:`).
///
/// `VOLUME_DISK_EXTENTS` — це лічильник, за яким ідуть 24-байтні `DISK_EXTENT`,
/// кожен починається з номера диска; обидва вирівняні на 8 байтів. Складений
/// або дзеркальний том повертає більше одного диска.
pub fn volume_disk_numbers(volume: &File) -> io::Result<Vec<u32>> {
    let mut out = vec![0u8; 8 + 24 * 16];
    let n = device_io_control(volume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &[], &mut out)?;
    if n < 8 {
        return Err(short_buffer("VOLUME_DISK_EXTENTS"));
    }
    let count = u32::from_le_bytes([out[0], out[1], out[2], out[3]]) as usize;
    Ok((0..count)
        .map(|i| 8 + i * 24)
        .take_while(|at| at + 4 <= n)
        .map(|at| u32::from_le_bytes([out[at], out[at + 1], out[at + 2], out[at + 3]]))
        .collect())
}

/// Зрозуміла назва для значення `STORAGE_BUS_TYPE`.
pub fn bus_type_name(bus: u32) -> &'static str {
    match bus {
        0x01 => "SCSI",
        0x02 => "ATAPI",
        0x03 => "ATA",
        0x04 => "IEEE1394",
        0x05 => "SSA",
        0x06 => "Fibre",
        0x07 => "USB",
        0x08 => "RAID",
        0x09 => "iSCSI",
        0x0A => "SAS",
        0x0B => "SATA",
        0x0C => "SD",
        0x0D => "MMC",
        0x0F => "Віртуальний",
        0x10 => "Spaces",
        0x11 => "NVMe",
        0x12 => "SCM",
        0x13 => "UFS",
        _ => "Невідома",
    }
}
