use std::{ffi::{c_void, OsStr, OsString}, fmt, io, iter::once, mem, os::windows::ffi::{OsStrExt, OsStringExt}};

use windows::{core::{PCWSTR, PWSTR}, Win32::{Foundation::LocalFree, Security::{Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW}, CreateWellKnownSid, FreeSid, PSID, WELL_KNOWN_SID_TYPE}}};

#[derive(Clone)]
pub enum Sid {
    Raw(PSID),
    WellKnown(Vec<u8>),
    String(PSID),
}

impl Sid {
    pub fn new(raw_ptr: PSID) -> Sid {
        Sid::Raw(raw_ptr)
    }

    pub fn well_known(sid_type: WELL_KNOWN_SID_TYPE, domain: Option<&Sid>) -> io::Result<Sid> {
        let domain = domain.map(|d| d.as_ptr());
        let mut data = Vec::new();
        let mut size = 0u32;
        unsafe {
            let _ = CreateWellKnownSid(sid_type, domain, None, &mut size);
            data.resize(usize::try_from(size).map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid SID size"))?, 0);
            CreateWellKnownSid(sid_type, domain, Some(PSID(data.as_mut_ptr() as *mut c_void)), &mut size)?;
        }

        Ok(Sid::WellKnown(data))
    }

    pub fn as_ptr(&self) -> PSID {
        match self {
            Sid::Raw(raw_ptr) => *raw_ptr,
            Sid::WellKnown(data) => PSID(data.as_ptr() as *mut u8 as *mut c_void),
            Sid::String(raw_ptr) => *raw_ptr,
        }
    }
}

impl TryFrom<&OsStr> for Sid {
    type Error = io::Error;

    fn try_from(string: &OsStr) -> io::Result<Sid> {
        let mut raw_ptr = PSID::default();

        let chars : Vec<u16> = string.encode_wide()
                .chain(once(0))
                .collect();
        unsafe {
            ConvertStringSidToSidW(PCWSTR(chars.as_ptr()), &mut raw_ptr)?;
        }

        Ok(Sid::String(raw_ptr))
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        match self {
            Sid::Raw(raw_ptr) => {
                if !raw_ptr.is_invalid() {
                    unsafe {
                        FreeSid(*raw_ptr);
                    }
                }
            },
            Sid::String(raw_ptr) => {
                if !raw_ptr.is_invalid() {
                    unsafe {
                        LocalFree(Some(mem::transmute(raw_ptr)));
                    }
                }
            },
            Sid::WellKnown(_) => (),
        }
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let mut stringsid = PWSTR::default();
            if let Err(_) = ConvertSidToStringSidW(self.as_ptr(), &mut stringsid) {
                return write!(f, "<Error converting SID to string representation>");
            }
            let stringsid_size = (0 .. ).take_while(|&idx| stringsid.0.add(idx).read() != 0).count();
            let stringsid_slice = std::slice::from_raw_parts(stringsid.0, stringsid_size);
            let stringsid_str = OsString::from_wide(stringsid_slice);
            if let Some(s) = stringsid_str.to_str() {
                write!(f, "{}", s)
            } else {
                write!(f, "<Invalid SID string representation>")
            }
        }
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string_representation = self.to_string();
        match self {
            Self::Raw(_) => f.debug_tuple("Raw").field(& string_representation).finish(),
            Self::WellKnown(_) => f.debug_tuple("WellKnown").field(& string_representation).finish(),
            Self::String(_) => f.debug_tuple("String").field(& string_representation).finish(),
        }
    }
}