use std::{
    char,
    fmt::Debug,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    MapsFileDoesNotExist,
    FileOpenError(std::io::Error),
    IntParseError(std::num::ParseIntError),
}

#[derive(Debug)]
pub struct Entries {
    entries: Vec<Entry>,
}

#[allow(dead_code)]
impl Entries {
    fn filter_by_pathname(&self, value: &str) -> Vec<&Entry> {
        self.entries
            .iter()
            .filter(|e| e.path.is_some() && e.path.as_ref().unwrap() == value)
            .collect::<Vec<&Entry>>()
    }
}

#[derive(Clone)]
pub struct Entry {
    pub start_addr: u64,
    pub end_addr: u64,
    pub perms: Permissions,
    pub offset: u64,
    pub dev_maj: u32,
    pub dev_min: u32,
    pub inode: u32,
    pub path: Option<String>,
}

#[allow(dead_code)]
impl Entry {
    fn is_readable(&self) -> bool {
        self.perms.read
    }

    fn is_writable(&self) -> bool {
        self.perms.write
    }

    fn is_executable(&self) -> bool {
        self.perms.execute
    }
}

impl Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Entry {{ start_addr: 0x{:x}, end_addr: 0x{:x}, permissions: {:?}, offset: 0x{:x}, dev_maj: {}, dev_min: {}, inode: {}, path: {:?} }}",
            self.start_addr, self.end_addr, self.perms, self.offset,
            self.dev_maj, self.dev_min, self.inode, self.path)
    }
}

#[derive(Clone)]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Debug for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Permissions {{ read: {}, write: {}, execute: {} }}",
            self.read, self.write, self.execute
        )
    }
}

fn parse_addresses(addresses: &str) -> (u64, u64) {
    let splitaddr = addresses
        .split('-')
        .collect::<Vec<&str>>()
        .iter()
        .map(|str_val| u64::from_str_radix(str_val, 16).unwrap())
        .collect::<Vec<u64>>();

    (splitaddr[0], splitaddr[1])
}

fn parse_params(params: &str) -> Permissions {
    let chars = params.chars().collect::<Vec<char>>();

    Permissions {
        read: chars[0] == 'r',
        write: chars[1] == 'w',
        execute: chars[2] == 'x',
    }
}

fn parse_offset(offset: &str) -> Result<u64> {
    u64::from_str_radix(offset, 16).map_err(Error::IntParseError)
}

fn parse_device(device: &str) -> (u32, u32) {
    let splitdev = device
        .split(':')
        .collect::<Vec<&str>>()
        .iter()
        .map(|str_val| u32::from_str_radix(str_val, 16).unwrap())
        .collect::<Vec<u32>>();

    (splitdev[0], splitdev[1])
}

pub fn parse(pid: u32) -> Result<Entries> {
    let mut entries: Vec<Entry> = vec![];

    let maps_file_name = format!("/proc/{}/maps", pid);
    let maps_file_exists = Path::new(&maps_file_name).exists();

    if !maps_file_exists {
        return Err(Error::MapsFileDoesNotExist);
    }

    let maps_file = File::open(maps_file_name).map_err(Error::FileOpenError)?;
    let lines = BufReader::new(maps_file).lines();

    for line in lines.flatten() {
        let splitted: Vec<&str> = line.split_whitespace().collect();

        if splitted.len() >= 5 {
            let (start_addr, end_addr) = match splitted.get(0) {
                Some(v) => parse_addresses(v),
                None => continue,
            };

            let perms: Permissions = match splitted.get(1) {
                Some(v) => parse_params(v),
                None => continue,
            };

            let offset = match splitted.get(2) {
                Some(v) => parse_offset(v)?,
                None => continue,
            };

            let (dev_maj, dev_min) = match splitted.get(3) {
                Some(v) => parse_device(v),
                None => continue,
            };

            let inode = match splitted.get(4) {
                Some(v) => v.parse::<u32>().unwrap(),
                None => continue,
            };

            let path = splitted.get(5).map(|v| v.to_string());

            entries.push(Entry {
                start_addr,
                end_addr,
                perms,
                offset,
                dev_maj,
                dev_min,
                inode,
                path,
            });
        }
    }

    Ok(Entries { entries })
}

#[cfg(test)]
mod tests {
    use crate::parse;

    #[test]
    fn it_works() {
        let parsed = parse(1).unwrap();
        let heap = parsed.filter_by_pathname("/usr/lib/libc.so.6");
        println!("{:?}", heap);
    }

    // #[test]
    // fn fuzzit() {
    //     const PID_MAX: u32 = 4194304;
    //     for i in 0..PID_MAX {
    //         let _ = parse(i);
    //     }
    // }
}
