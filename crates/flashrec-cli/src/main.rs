//! Командний рядок `flashrec`.
//!
//! Розбір аргументів написано вручну, щоб рятувальний бінарник не мав залежностей.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use flashrec_core::carve;
use flashrec_core::device::{check_output_not_on_disk, human_bytes, list_disks, RawDisk};
use flashrec_core::imaging::{create_image, format_duration, ImagingOptions};
use flashrec_core::ntfs::format_filetime;
use flashrec_core::ntfs::volume::{
    is_ntfs_metadata, recover_files, NtfsVolume, RecoveryOptions, DELETED_DIR, LIVE_DIR,
    PARTIAL_SUFFIX,
};
use flashrec_core::reader::{BlockDevice, SubDevice};
use flashrec_core::source::{open_ntfs, open_source, Source};

const USAGE: &str = "\
flashrec — відновлення файлів із флешок, що відмовляють

ВИКОРИСТАННЯ:
  flashrec list
      перелічити фізичні диски
  flashrec image   --disk N --out ФАЙЛ [--expect-serial С] [--retries N] [--resume]
      зняти посекторний образ диска
  flashrec scan    (--image ФАЙЛ | --disk N) [--offset БАЙТИ] [--sweep] [--limit N]
      знайти файли й показати список
  flashrec recover (--image ФАЙЛ | --disk N) --out ТЕКА [--offset БАЙТИ] [--sweep]
                   [--no-deleted] [--ext jpg,png,...]
                   [--path ПІДРЯДОК,...] [--exclude-path ПІДРЯДОК,...]
      записати знайдені файли в теку
  flashrec carve   (--image ФАЙЛ | --disk N) --out ТЕКА [--offset БАЙТИ]
      вирізати файли за сигнатурами, коли сканування нічого не дало

ПАРАМЕТРИ:
  --expect-serial С  відмовити, якщо серійний номер диска не збігається
  --resume           продовжити перерване зняття образу
  --sweep            перебрати весь том у пошуках записів MFT, не довіряючи $MFT
  --no-deleted       не відновлювати видалені файли
  --ext              лише файли з цими розширеннями
  --path             лише файли, чий шлях містить один із підрядків
  --exclude-path     пропустити файли, чий шлях містить один із підрядків

Працюйте з образом, де тільки можливо: зніміть його один раз і більше не
чіпайте диск. flashrec ніколи нічого не пише на диск-джерело.

Читання фізичного диска потребує прав адміністратора.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let opts = match parse_flags(&args[1..]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("помилка: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let result = match cmd.as_str() {
        "list" => cmd_list(),
        "image" => cmd_image(&opts),
        "scan" => cmd_scan(&opts),
        "recover" => cmd_recover(&opts),
        "carve" => cmd_carve(&opts),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("невідома команда «{other}»")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nпомилка: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Пари `--ключ значення` і окремі `--перемикачі`.
struct Flags {
    values: HashMap<String, String>,
    switches: Vec<String>,
}

impl Flags {
    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    fn has(&self, key: &str) -> bool {
        self.switches.iter().any(|s| s == key)
    }

    fn require(&self, key: &str) -> Result<&str, String> {
        self.get(key).ok_or_else(|| format!("потрібен параметр --{key}"))
    }

    fn parse_u64(&self, key: &str) -> Result<Option<u64>, String> {
        self.get(key)
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| format!("--{key} очікує число, а отримано «{v}»"))
            })
            .transpose()
    }
}

const SWITCHES: &[&str] = &["resume", "sweep", "no-deleted", "system"];

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut values = HashMap::new();
    let mut switches = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let Some(key) = args[i].strip_prefix("--") else {
            return Err(format!("неочікуваний аргумент «{}»", args[i]));
        };
        if SWITCHES.contains(&key) {
            switches.push(key.to_string());
            i += 1;
            continue;
        }
        let value = args
            .get(i + 1)
            .ok_or_else(|| format!("--{key} потребує значення"))?;
        values.insert(key.to_string(), value.clone());
        i += 2;
    }
    Ok(Flags { values, switches })
}

fn cmd_list() -> Result<(), String> {
    let disks = list_disks();
    if disks.is_empty() {
        return Err(
            "не вдалося відкрити жодного фізичного диска — запустіть flashrec від імені адміністратора"
                .to_string(),
        );
    }
    println!(
        "{:<5} {:<34} {:>11}  {:<6} {}",
        "ДИСК", "МОДЕЛЬ", "РОЗМІР", "ШИНА", "СЕРІЙНИЙ"
    );
    for d in &disks {
        println!(
            "{:<5} {:<34} {:>11}  {:<6} {}{}",
            d.index,
            truncate(&d.model, 34),
            d.size_human(),
            d.bus,
            d.serial.as_deref().unwrap_or("-"),
            if d.is_likely_removable_media() {
                "   <- знімний"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn cmd_image(f: &Flags) -> Result<(), String> {
    let index: u32 = f
        .require("disk")?
        .parse()
        .map_err(|_| "--disk очікує номер диска з `flashrec list`".to_string())?;
    let out = PathBuf::from(f.require("out")?);

    // Запобіжник: не знімати образ не з того диска. Номери дисків зсуваються,
    // коли пристрої підключають чи виймають; серійні номери — ні.
    let info = list_disks()
        .into_iter()
        .find(|d| d.index == index)
        .ok_or_else(|| format!("диск {index} не знайдено (запущено від адміністратора?)"))?;
    println!("джерело: {info}");

    if let Some(expected) = f.get("expect-serial") {
        match &info.serial {
            Some(actual) if actual.trim() == expected.trim() => {
                println!("серійний номер збігається: {actual}");
            }
            Some(actual) => {
                return Err(format!(
                    "СЕРІЙНИЙ НОМЕР НЕ ЗБІГАЄТЬСЯ: диск {index} повідомляє «{actual}», а очікувався \
                     «{expected}». Відмовляюсь знімати образ, бо це може бути інший диск."
                ));
            }
            None => {
                return Err(format!(
                    "диск {index} не повідомляє серійного номера, тож --expect-serial перевірити неможливо"
                ));
            }
        }
    } else if !info.is_likely_removable_media() {
        println!(
            "УВАГА: диск {index} не схожий на знімний носій. \
             Передайте --expect-serial, щоб переконатися, що це потрібний диск."
        );
    }

    check_output_not_on_disk(&out, index)?;

    if out.exists() && !f.has("resume") {
        return Err(format!(
            "{} уже існує; передайте --resume, щоб продовжити його, або оберіть інший шлях",
            out.display()
        ));
    }

    let mut disk = RawDisk::open_index(index).map_err(|e| e.to_string())?;
    let opts = ImagingOptions {
        retries: f.parse_u64("retries")?.map(|r| r as u32).unwrap_or(2),
        resume: f.has("resume"),
        ..ImagingOptions::default()
    };

    println!("образ:   {}", out.display());
    println!(
        "читаю {} блоками по {}, {} повторні спроби на блок, що не прочитався\n",
        human_bytes(info.size_bytes),
        human_bytes(opts.block_size as u64),
        opts.retries
    );

    let cancel = AtomicBool::new(false);
    let mut last = Instant::now();
    let report = create_image(&mut disk, &out, &opts, &cancel, &mut |p| {
        if last.elapsed().as_millis() >= 500 || p.offset >= p.total {
            last = Instant::now();
            print!(
                "\r  {:6.2}%  {:>11} / {:<11}  {:>10}/с  лишилось: {:<12}  нечитано: {}      ",
                p.percent(),
                human_bytes(p.offset),
                human_bytes(p.total),
                human_bytes(p.bytes_per_sec() as u64),
                p.eta_secs().map(format_duration).unwrap_or_else(|| "—".into()),
                human_bytes(p.bad_bytes)
            );
            let _ = io::stdout().flush();
        }
    })
    .map_err(|e| e.to_string())?;

    println!("\n\n{}", report.summary());
    println!("карта: {}", report.map_path.display());
    println!("час:   {:.0} с", report.elapsed_secs);
    if report.bad_bytes > 0 {
        println!(
            "\nСмуги, заповнені нулями, перелічено у файлі карти. Файли, що їх зачіпають, \
             вийдуть із дірками й матимуть суфікс {PARTIAL_SUFFIX}."
        );
    }
    Ok(())
}

/// `--image ФАЙЛ` або `--disk N` — рівно одне з двох.
fn source_from(f: &Flags) -> Result<Source, String> {
    match (f.get("image"), f.get("disk")) {
        (Some(path), None) => Ok(Source::Image(PathBuf::from(path))),
        (None, Some(n)) => n
            .parse()
            .map(Source::Disk)
            .map_err(|_| "--disk очікує номер диска".to_string()),
        (Some(_), Some(_)) => Err("передайте або --image, або --disk, а не обидва".into()),
        (None, None) => Err("передайте --image ФАЙЛ або --disk N".into()),
    }
}

/// Коли читаємо живий диск, `--out` не може лежати на ньому ж.
fn guard_output(f: &Flags, src: &Source) -> Result<(), String> {
    if let (Source::Disk(n), Some(out)) = (src, f.get("out")) {
        check_output_not_on_disk(std::path::Path::new(out), *n)?;
    }
    Ok(())
}

/// Відкрити том NTFS, заданий через `--image`/`--disk` і `--offset`.
fn open_volume(f: &Flags) -> Result<NtfsVolume<Box<dyn BlockDevice>>, String> {
    let src = source_from(f)?;
    guard_output(f, &src)?;
    if src.is_live_disk() {
        println!("читаю живий диск — з образом (`flashrec image`) безпечніше");
    }
    let opened = open_ntfs(&src, f.parse_u64("offset")?).map_err(|e| e.to_string())?;
    for line in opened.describe() {
        println!("{line}");
    }
    Ok(opened.volume)
}

fn run_scan(
    vol: &mut NtfsVolume<Box<dyn BlockDevice>>,
    f: &Flags,
) -> Result<flashrec_core::ntfs::volume::ScanResult, String> {
    let cancel = AtomicBool::new(false);
    let mut last = Instant::now();
    let mut on_progress = |p: flashrec_core::ntfs::volume::ScanProgress| {
        if last.elapsed().as_millis() >= 500 {
            last = Instant::now();
            let pct = if p.total == 0 {
                0.0
            } else {
                p.offset as f64 / p.total as f64 * 100.0
            };
            print!(
                "\r  сканую {pct:6.2}%  переглянуто записів: {}  знайдено: {}      ",
                p.records_examined, p.entries_found
            );
            let _ = io::stdout().flush();
        }
    };
    let result = if f.has("sweep") {
        vol.scan_by_signature(&cancel, &mut on_progress)
    } else {
        vol.scan(&cancel, &mut on_progress)
    }
    .map_err(|e| e.to_string())?;
    println!("\n\n{}", result.summary());
    Ok(result)
}

fn cmd_scan(f: &Flags) -> Result<(), String> {
    let mut vol = open_volume(f)?;
    let result = run_scan(&mut vol, f)?;
    let paths = vol.build_paths(&result);
    let limit = f.parse_u64("limit")?.unwrap_or(200) as usize;

    let all = result.files().count();
    let mut files: Vec<_> = result
        .files()
        .filter(|e| {
            paths
                .get(&e.record_number)
                .is_none_or(|p| !is_ntfs_metadata(e.record_number, p))
        })
        .collect();
    files.sort_by_key(|e| std::cmp::Reverse(e.size));
    if all > files.len() {
        println!(
            "службових файлів NTFS приховано: {} (вони не відновлюються)",
            all - files.len()
        );
    }

    println!("\n{:<9} {:>11}  {:<19}  ШЛЯХ", "СТАН", "РОЗМІР", "ЗМІНЕНО");
    for e in files.iter().take(limit) {
        let path = paths
            .get(&e.record_number)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| e.name.clone());
        println!(
            "{:<9} {:>11}  {:<19}  {}",
            if e.in_use { "наявний" } else { "ВИДАЛЕНИЙ" },
            human_bytes(e.size),
            e.timestamps
                .map(|t| format_filetime(t.modified))
                .unwrap_or_else(|| "-".into()),
            path
        );
    }
    if files.len() > limit {
        println!("… і ще {} (збільште --limit)", files.len() - limit);
    }
    Ok(())
}

fn cmd_recover(f: &Flags) -> Result<(), String> {
    let out = PathBuf::from(f.require("out")?);
    let mut vol = open_volume(f)?;
    let result = run_scan(&mut vol, f)?;

    // Фільтр за шляхом: підрядки без огляду на регістр, через кому.
    let split = |key: &str| -> Vec<String> {
        f.get(key)
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_lowercase())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    let include = split("path");
    let exclude = split("exclude-path");
    let only_records = if include.is_empty() && exclude.is_empty() {
        None
    } else {
        let paths = vol.build_paths(&result);
        let chosen: std::collections::HashSet<u64> = result
            .files()
            .filter(|e| {
                let p = paths
                    .get(&e.record_number)
                    .map(|p| p.to_string_lossy().to_lowercase())
                    .unwrap_or_else(|| e.name.to_lowercase());
                (include.is_empty() || include.iter().any(|s| p.contains(s.as_str())))
                    && !exclude.iter().any(|s| p.contains(s.as_str()))
            })
            .map(|e| e.record_number)
            .collect();
        println!("за фільтром шляху відібрано файлів: {}", chosen.len());
        Some(chosen)
    };

    let opts = RecoveryOptions {
        only_records,
        include_deleted: !f.has("no-deleted"),
        include_system: f.has("system"),
        extensions: f
            .get("ext")
            .map(|s| {
                s.split(',')
                    .map(|e| e.trim().trim_start_matches('.').to_lowercase())
                    .filter(|e| !e.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        ..RecoveryOptions::default()
    };

    println!("\nзаписую в {}", out.display());
    let cancel = AtomicBool::new(false);
    let mut last = Instant::now();
    let report = recover_files(&mut vol, &result, &out, &opts, &cancel, &mut |p| {
        if last.elapsed().as_millis() >= 300 {
            last = Instant::now();
            print!(
                "\r  {}/{}  {}  {}                    ",
                p.files_done,
                p.files_total,
                human_bytes(p.bytes_written),
                truncate(&p.current, 60)
            );
            let _ = io::stdout().flush();
        }
    })
    .map_err(|e| e.to_string())?;

    println!("\n\n{}", report.summary());
    if !report.failures.is_empty() {
        println!("\nфайли, які не вдалося відновити:");
        for fail in report.failures.iter().take(50) {
            println!("  {} — {}", fail.path, fail.reason);
        }
        if report.failures.len() > 50 {
            println!("  … і ще {}", report.failures.len() - 50);
        }
    }
    println!(
        "\nнаявні файли — у {0}\\{LIVE_DIR}, видалені — у {0}\\{DELETED_DIR}",
        out.display()
    );
    Ok(())
}

fn cmd_carve(f: &Flags) -> Result<(), String> {
    let out = PathBuf::from(f.require("out")?);
    let src = source_from(f)?;
    guard_output(f, &src)?;
    let mut dev = open_source(&src).map_err(|e| e.to_string())?;
    if let Some(off) = f.parse_u64("offset")? {
        let len = dev.len().saturating_sub(off);
        dev = Box::new(SubDevice::new(dev, off, len));
    }

    println!("вирізаю з {} у {}", human_bytes(dev.len()), out.display());
    let cancel = AtomicBool::new(false);
    let mut last = Instant::now();
    let report = carve::carve(&mut dev, &out, &cancel, &mut |p| {
        if last.elapsed().as_millis() >= 500 {
            last = Instant::now();
            print!(
                "\r  {:6.2}%  знайдено: {}      ",
                p.offset as f64 / p.total.max(1) as f64 * 100.0,
                p.found
            );
            let _ = io::stdout().flush();
        }
    })
    .map_err(|e| e.to_string())?;
    println!("\n\n{}", report.summary());
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}
