mod proc_thread_attribute_list;
mod sid;

use std::{collections::{BTreeSet, HashMap}, ffi::{OsStr, OsString}, io, iter, mem, ops::{Deref, DerefMut}, os::windows::{ffi::{OsStrExt, OsStringExt}, process::{CommandExt, ProcThreadAttributeList}}, path::{self, Path, PathBuf}, process::Command, ptr};

use windows::{core::{HRESULT, PCWSTR, PWSTR}, Win32::{Foundation::{LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND}, Security::{Authorization::{ConvertSecurityDescriptorToStringSecurityDescriptorW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, ACCESS_MODE, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SDDL_REVISION_1, SET_ACCESS, SE_FILE_OBJECT, SE_OBJECT_TYPE, SE_REGISTRY_KEY, SE_REGISTRY_WOW64_32KEY, SE_REGISTRY_WOW64_64KEY, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W}, IsValidAcl, Isolation::{CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName}, WinCapabilityInternetClientSid, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, NO_INHERITANCE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, SECURITY_CAPABILITIES, SUB_CONTAINERS_AND_OBJECTS_INHERIT}, Storage::FileSystem::{FILE_ACCESS_RIGHTS, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_EXECUTE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_READ_EA, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, STANDARD_RIGHTS_READ, SYNCHRONIZE}, System::{Registry::{KEY_EXECUTE, KEY_READ, KEY_WRITE, REG_SAM_FLAGS}, SystemServices::SE_GROUP_ENABLED, Threading::PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES}}};

use crate::{windows::sid::Sid, Exception, Sandbox};

struct PathException {
    write: bool,
    execute: bool,
}

/// Windows sandboxing.
pub struct WindowsSandbox {
    env_exceptions: Vec<String>,
    path_exceptions: HashMap<PathBuf, PathException>,
    allow_networking: bool,
    full_env: bool,
    app_container_name: OsString,
    app_container_profile: AppContainerProfile,
}

const fn compute_registry_access_masks(write: bool, execute: bool) -> u32 {
    match (write, execute) {
        (false, false) => KEY_READ.0,
        (false, true) => KEY_READ.0 | KEY_EXECUTE.0,
        (true, false) => KEY_READ.0 | KEY_WRITE.0,
        (true, true) => KEY_READ.0 | KEY_WRITE.0 | KEY_EXECUTE.0,
    }
}

fn compute_file_access_masks(write: bool, execute: bool, is_dir: bool) -> u32 {
    match (write, execute, is_dir) {
        (false, false, false) => FILE_GENERIC_READ.0,
        (false, false, true) => (FILE_GENERIC_READ | FILE_LIST_DIRECTORY | FILE_TRAVERSE).0,
        (true, false, false) => (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
        (true, false, true) => (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_DELETE_CHILD).0,
        (false, true, false) => (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE).0,
        (false, true, true) => (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | FILE_LIST_DIRECTORY | FILE_TRAVERSE).0,
        (true, true, false) => (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE).0,
        (true, true, true) => (FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_DELETE_CHILD).0,
    }
}

enum PathType {
    Filesystem(PathBuf),
    Registry(PathBuf),
    RegistryWow64_32(PathBuf),
    RegistryWow64_64(PathBuf),
}

impl PathType {
    pub fn from_exception(path: &Path) -> Self {
        if path.to_str().and_then(|path| Some(path.to_uppercase().starts_with("REGISTRY:"))).unwrap_or(false) {
            PathType::Registry(path.to_path_buf())
        }
        else if path.to_str().and_then(|path| Some(path.to_uppercase().starts_with("REGISTRY+WOW64_32KEY:"))).unwrap_or(false) {
            PathType::RegistryWow64_32(path.to_path_buf())
        }
        else if path.to_str().and_then(|path| Some(path.to_uppercase().starts_with("REGISTRY+WOW64_64KEY:"))).unwrap_or(false) {
            PathType::RegistryWow64_64(path.to_path_buf())
        }
        else {
            match path.canonicalize() {
                Ok(path) => PathType::Filesystem(path.to_path_buf()),
                Err(_) => PathType::Filesystem(path.to_path_buf()),
            }
        }
    }

    pub fn object_type(&self) -> SE_OBJECT_TYPE {
        match self {
            PathType::Filesystem(_) => SE_FILE_OBJECT,
            PathType::Registry(_) => SE_REGISTRY_KEY,
            PathType::RegistryWow64_32(_) => SE_REGISTRY_WOW64_32KEY,
            PathType::RegistryWow64_64(_) => SE_REGISTRY_WOW64_64KEY,
        }
    }

    pub fn path(&self) -> PathBuf {
        match self {
            PathType::Filesystem(path) => path.to_path_buf(),
            PathType::Registry(path) => path.to_path_buf(),
            PathType::RegistryWow64_32(path) => path.to_path_buf(),
            PathType::RegistryWow64_64(path) => path.to_path_buf(),
        }
    }

    pub fn access_mask(&self, write: bool, execute: bool) -> u32 {
        match self {
            PathType::Filesystem(_) => compute_file_access_masks(write, execute, self.path().is_dir()),
            PathType::Registry(_) => compute_registry_access_masks(write, execute),
            PathType::RegistryWow64_32(_) => compute_registry_access_masks(write, execute),
            PathType::RegistryWow64_64(_) => compute_registry_access_masks(write, execute),
        }
    }
}

impl Sandbox for WindowsSandbox {
    fn try_new() -> Result<Self, crate::error::Error> {
        let app_container_name = unique_app_container_name();
        Ok(Self {
            env_exceptions: Vec::new(),
            path_exceptions: HashMap::new(),
            allow_networking: false,
            full_env: false,
            app_container_profile: AppContainerProfile::new(&app_container_name, "Birdcage Application", "Application container for Birdcage sandboxing")?,
            app_container_name,
        })
    }

    fn add_exception(&mut self, exception: Exception) -> crate::error::Result<&mut Self> {
        match exception {
            Exception::Read(path) => {
                let path_type = PathType::from_exception(&path);
                grant_access(self.app_container_profile.sid(), path_type.path(), path_type.object_type(), path_type.access_mask(false, false), true)?;
                Ok(self)
            },
            Exception::WriteAndRead(path) => {
                let path_type = PathType::from_exception(&path);
                let access_mask = path_type.access_mask(true, false);
                grant_access(self.app_container_profile.sid(), path_type.path(), path_type.object_type(), access_mask, true)?;
                self.path_exceptions.insert(path, PathException {write: true, execute: false});
                Ok(self)
            }
            Exception::ExecuteAndRead(path) => {
                let path_type = PathType::from_exception(&path);
                let access_mask = path_type.access_mask(false, true);
                grant_access(self.app_container_profile.sid(), path_type.path(), path_type.object_type(), access_mask, true)?;
                self.path_exceptions.insert(path, PathException {write: false, execute: true});
                Ok(self)
            }
            Exception::Environment(key) => {self.env_exceptions.push(key); Ok(self)}
            Exception::FullEnvironment => {self.full_env = true; Ok(self)}
            Exception::Networking => {self.allow_networking = true; Ok(self)}
        }
    }

    fn spawn(self, mut sandboxee: crate::process::Command) -> crate::error::Result<crate::process::Child> {
        //Set up AppContainer
        let mut capabilities = Vec::new();
        if self.allow_networking {
            let inet_client_sid = Sid::well_known(WinCapabilityInternetClientSid, None)?;
            capabilities.push((inet_client_sid, SE_GROUP_ENABLED as u32));
        }

        let app_container_name = unique_app_container_name();
        let app_container_profile = AppContainerProfile::new(&app_container_name, "Birdcage Application", "Application container for Birdcage sandboxing")?;

'path_exception_loop:
        for (path, &PathException {write, execute}) in self.path_exceptions.iter() {
            for (prefix, object_type) in [("REGISTRY:", SE_REGISTRY_KEY), ("REGISTRY+WOW64_32KEY:", SE_REGISTRY_WOW64_32KEY), ("REGISTRY+WOW64_64KEY:", SE_REGISTRY_WOW64_64KEY)] {
                if path.to_str().and_then(|path| Some(path.to_uppercase().starts_with(prefix))).unwrap_or(false) {
                    let path: OsString = OsString::from_wide(& path.as_os_str().encode_wide().skip(prefix.len()).collect::<Vec<_>>());
                    let access_mask = compute_registry_access_masks(write, execute);
                    grant_access(app_container_profile.sid(), &path, object_type, access_mask, true)?;
                    continue 'path_exception_loop;
                }
            }

            let access_mask = compute_file_access_masks(write, execute, path.is_dir());
            eprintln!("Granting access to path {:?} with access_mask: {:#x}", path, access_mask);
            grant_access(app_container_profile.sid(), path.as_os_str(), SE_FILE_OBJECT, access_mask, path.is_dir())?;
        }

        if !self.full_env {
            const ALWAYS_ALLOWED_ENVIRONMENT_VARIABLES: &[&str] = &["LOCALAPPDATA", ];
            let current_envs = sandboxee.get_envs().map(|(n, _)| n.to_os_string()).chain(std::env::vars_os().map(|(n, _)| n)).collect::<Vec<_>>();
            let allowed_envs: BTreeSet<OsString> = self.env_exceptions.iter().map(|x| OsString::from(x)).chain(ALWAYS_ALLOWED_ENVIRONMENT_VARIABLES.iter().map(OsString::from)).collect();
            for name in & current_envs {
                if !allowed_envs.contains(name) {
                    sandboxee.env_remove(name);
                }
            }
        }

        let security_capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: app_container_profile.sid().as_ptr(),
            Capabilities: if capabilities.is_empty() { ptr::null_mut() } else { capabilities.as_ptr() as *mut _ },
            CapabilityCount: capabilities.len() as u32,
            Reserved: 0,
        };

        let proc_thread_attributes_builder = unsafe {
            ProcThreadAttributeList::build().raw_attribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize, &security_capabilities, mem::size_of::<SECURITY_CAPABILITIES>())
        };

        let proc_thread_attribute_list = proc_thread_attributes_builder.finish()?;

        Ok(sandboxee.spawn_with_attributes(&proc_thread_attribute_list)?)
    }
}

fn map_to_birdcage_error(err: windows::core::Error, path: &OsStr) -> crate::error::Error {
    match err {
        err if err.code() == HRESULT::from(ERROR_PATH_NOT_FOUND) => crate::error::Error::InvalidPath(PathBuf::from(path)),
        err if err.code() == HRESULT::from(ERROR_FILE_NOT_FOUND) => crate::error::Error::InvalidPath(PathBuf::from(path)),
        err => crate::error::Error::Io(err.into()),
    }
}

// fn zeroed_startupinfo() -> STARTUPINFOEXW {
//     let mut startup_info = STARTUPINFOEXW::default();
//     startup_info.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
//     startup_info.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
//     startup_info.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
//     startup_info.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
//     startup_info
// }

fn grant_access<N: AsRef<OsStr>, A: Into<u32>>(app_container_sid: &Sid, name: N, object_type: SE_OBJECT_TYPE, access_mask: A, inherit: bool) -> Result<(), crate::error::Error> {
    let access_mask: u32 = access_mask.into();
    let access  = &mut [
        EXPLICIT_ACCESS_W {
            grfAccessMode: SET_ACCESS,
            grfAccessPermissions: access_mask,
            grfInheritance: if inherit {SUB_CONTAINERS_AND_OBJECTS_INHERIT.into()} else {NO_INHERITANCE},
            Trustee: TRUSTEE_W {
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                pMultipleTrustee: ptr::null_mut(),
                ptstrName: unsafe { std::mem::transmute(app_container_sid.as_ptr()) },
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
            },
        },
    ];
    log::info!("Granting access on {:?} in app container {:?} with access_mask: {:#x},", name.as_ref(), app_container_sid, access_mask);

    let security_descriptor = SecurityDescriptor::named_security_info(name.as_ref(), object_type).map_err(|err| map_to_birdcage_error(err, name.as_ref()))?;
    let dacl = security_descriptor.discretionary_access_control_list();
    let updated_dacl = dacl.set_entries_in_acl(access).map_err(|err| map_to_birdcage_error(err, name.as_ref()))?;
    updated_dacl.set_named_security_info(name.as_ref(), object_type).map_err(|err| map_to_birdcage_error(err, name.as_ref()))
}

fn unique_app_container_name() -> OsString {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let executable_name = std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_os_string())).unwrap_or_default();
    let pid = std::process::id();
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|t| t.as_millis()).unwrap_or_default();
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    OsString::from(format!("Birdcage-{}-{}-{}-{}", executable_name.to_string_lossy(), pid, timestamp, counter))
}

// fn set_handle_inheritable(handle: & RawHandle, inheritable: bool) -> io::Result<()> {
//     if unsafe {
//         SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, if inheritable {HANDLE_FLAG_INHERIT} else {0})
//     } == FALSE {
//         Err(io::Error::last_os_error())
//     }
//     else {
//         Ok(())
//     }
// }

// fn duplicate_handle(handle: RawHandle, inheritable: bool) -> io::Result<OwnedHandle> {
//     let mut duplicated_handle = INVALID_HANDLE_VALUE;
//     if unsafe {
//         DuplicateHandle(
//             GetCurrentProcess(),
//             handle,
//             GetCurrentProcess(),
//             &mut duplicated_handle,
//             0,
//             if inheritable {TRUE} else {FALSE},
//             DUPLICATE_SAME_ACCESS)} == FALSE
//     {
//         Err(io::Error::last_os_error())
//     }
//     else {
//         Ok(OwnedHandle::new(duplicated_handle))
//     }
// }


// fn open_nul(write: bool) -> io::Result<OwnedHandle> {
//     let nul : Vec<u16> = OsStr::new("NUL").encode_wide().chain(once(0)).collect();
//     let size = mem::size_of::<SECURITY_ATTRIBUTES>();
//     let mut sa = SECURITY_ATTRIBUTES {
//         nLength: size as DWORD,
//         lpSecurityDescriptor: ptr::null_mut(),
//         bInheritHandle: 1,
//     };
//     let handle = unsafe {
//         CreateFileW(
//             nul.as_ptr(),
//             if write {GENERIC_WRITE} else {GENERIC_READ},
//             0,
//             & mut sa,
//             OPEN_EXISTING,
//             0,
//             ptr::null_mut(),
//         )
//     };
//     if handle == INVALID_HANDLE_VALUE {
//         Err(io::Error::last_os_error())
//     }
//     else {
//         Ok(OwnedHandle::new(handle))
//     }
// }

// fn get_std_handle(id: u32) -> io::Result<OwnedHandle> {
//     let handle = unsafe { GetStdHandle(id) };
//     if handle == INVALID_HANDLE_VALUE {
//         return Err(io::Error::last_os_error());
//     } else if handle.is_null() {
//         return Err(io::Error::from_raw_os_error(ERROR_INVALID_HANDLE as i32));
//     } 

//     let mut duplicated_handle = INVALID_HANDLE_VALUE;
//     if unsafe { DuplicateHandle(GetCurrentProcess(),
//                                 handle,
//                                 GetCurrentProcess(),
//                                 &mut duplicated_handle,
//                                 0,
//                                 TRUE,
//                                 DUPLICATE_SAME_ACCESS) } == FALSE {
//         return Err(io::Error::last_os_error());
//     }

//     Ok(OwnedHandle::new(duplicated_handle))
// }

// impl Stdio {
//     fn to_handle(& self, stdio_id: u32) -> io::Result<(OwnedHandle, Option<OwnedHandle>)> { 
//         match &self.0 {
//             StdioType::Inherit => get_std_handle(stdio_id).map(|x| (x, None)),
//             StdioType::Null => open_nul(stdio_id != STD_INPUT_HANDLE).map(|x| (x, None)),
//             StdioType::MakePipe => anon_pipe(stdio_id != STD_INPUT_HANDLE, true).map(|(a, b)| (b, Some(a))),
//             StdioType::FileDescriptor(handle) => duplicate_handle(handle.as_raw_handle(), true).map(|x| (x, None)),
//         }                                                                                  
//     }
// }


// fn ensure_no_nuls<T: AsRef<OsStr>>(str: T) -> io::Result<T> {
//     if str.as_ref().encode_wide().find(|b| *b == 0).is_some() {
//         Err(io::Error::new(io::ErrorKind::InvalidInput, "nul byte found in provided data"))
//     } else {
//         Ok(str)
//     }
// }

// // Produces a wide string *without terminating null*; returns an error if
// // `prog` or any of the `args` contain a nul.
// fn make_command_line<'a, T: Iterator<Item = &'a OsStr>>(prog: &OsStr, args: T) -> io::Result<Vec<u16>> {
//     // Encode the command and arguments in a command line string such
//     // that the spawned process may recover them using CommandLineToArgvW.
//     let mut cmd: Vec<u16> = Vec::new();
//     // Always quote the program name so CreateProcess doesn't interpret args as
//     // part of the name if the binary wasn't found first time.
//     append_arg(&mut cmd, prog, true)?;
//     for arg in args {
//         cmd.push(' ' as u16);
//         append_arg(&mut cmd, arg, false)?;
//     }
//     return Ok(cmd);

//     fn append_arg(cmd: &mut Vec<u16>, arg: &OsStr, force_quotes: bool) -> io::Result<()>
//     {
//         // If an argument has 0 characters then we need to quote it to ensure
//         // that it actually gets passed through on the command line or otherwise
//         // it will be dropped entirely when parsed on the other end.
//         ensure_no_nuls(arg)?;
//         let arg_str = arg.to_str();
//         let quote = force_quotes
//             || (if let Some(arg_str) = arg_str {arg_str.contains(" ") || arg_str.contains("\t")} else {true})
//             || arg.is_empty();
//         if quote {
//             cmd.push('"' as u16);
//         }

//         let mut backslashes: usize = 0;
//         for x in arg.encode_wide() {
//             if x == '\\' as u16 {
//                 backslashes += 1;
//             } else {
//                 if x == '"' as u16 {
//                     // Add n+1 backslashes to total 2n+1 before internal '"'.
//                     cmd.extend((0..=backslashes).map(|_| '\\' as u16));
//                 }
//                 backslashes = 0;
//             }
//             cmd.push(x);
//         }

//         if quote {
//             // Add n backslashes to total 2n before ending '"'.
//             cmd.extend((0..backslashes).map(|_| '\\' as u16));
//             cmd.push('"' as u16);
//         }
//         Ok(())
//     }
// }

#[derive(Debug, Clone)]
pub struct AppContainerProfile {
    pub name: OsString,
    pub sid: Sid,
}

impl AppContainerProfile {
    pub fn new<S0: AsRef<OsStr>, S1: AsRef<OsStr>, S2: AsRef<OsStr>>(name: S0, display_name: S1, description: S2) -> io::Result<Self> {
        let name_with_nul : Vec<u16> = name.as_ref().encode_wide()
            .chain(iter::once(0))
            .collect();
        let display_name_with_nul : Vec<u16> = display_name.as_ref().encode_wide()
            .chain(iter::once(0))
            .collect();
        let description_with_nul : Vec<u16> = description.as_ref().encode_wide()
            .chain(iter::once(0))
            .collect();   

        unsafe {
            match CreateAppContainerProfile(PCWSTR(name_with_nul.as_ptr()),
                PCWSTR(display_name_with_nul.as_ptr()),
                PCWSTR(description_with_nul.as_ptr()),
                None)
            {
                Ok(sid) => Ok(Self {name: name.as_ref().to_os_string(), sid: Sid::new(sid)}),
                Err(err) => Err(err.into()),
            }
        }
    }

    pub fn existing<S: AsRef<OsStr>>(name: S) -> io::Result<Self> {
        let name_with_nul : Vec<u16> = name.as_ref().encode_wide()
            .chain(iter::once(0))
            .collect();
        unsafe {
            Ok(Self{name: name.as_ref().to_os_string(), sid: DeriveAppContainerSidFromAppContainerName(PCWSTR(name_with_nul.as_ptr())).map(Sid::new)?})
        }
    }

    pub fn delete(self) -> io::Result<()> {
        let name_with_nul : Vec<u16> = self.name.encode_wide()
            .chain(iter::once(0))
            .collect();
        unsafe {
            DeleteAppContainerProfile(PCWSTR(name_with_nul.as_ptr()))?;
        }

        Ok(())
    }

    pub fn sid(&self) -> &Sid {
        & self.sid
    }
}

// fn make_envp<'a, T: Iterator<Item = (&'a OsStr, Option<&'a OsStr>)>>(env: T) -> io::Result<Option<Vec<u16>>> {
//     // On Windows we pass an "environment block" which is not a char**, but
//     // rather a concatenation of null-terminated k=v\0 sequences, with a final
//     // \0 to terminate.
//     let mut blk = Vec::new();

//     for (k, v) in env {
//         blk.extend(ensure_no_nuls(k)?.encode_wide());
//         blk.push('=' as u16);
//         if let Some(v) = v {
//             blk.extend(ensure_no_nuls(v)?.encode_wide());
//         }
//         blk.push(0);
//     }
//     if blk.is_empty() {
//         Ok(None)
//     }
//     else {
//         blk.push(0);
//         Ok(Some(blk))
//     }
// }

// fn make_dirp(d: Option<&path::Path>) -> io::Result<Option<Vec<u16>>> {
//     match d {
//         Some(dir) => {
//             let mut dir_str: Vec<u16> = ensure_no_nuls(dir)?.as_os_str().encode_wide().collect();
//             dir_str.push(0);
//             Ok(Some(dir_str))
//         }
//         None => Ok(None),
//     }
// }

#[derive(Debug, Clone, Default)]
pub struct SecurityDescriptor {
    descriptor: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
}

impl SecurityDescriptor {
    pub fn named_security_info(name: &OsStr, object_type: SE_OBJECT_TYPE) -> windows::core::Result<Self> {
        let name_vec = name.encode_wide().chain(std::iter::once(0)).collect::<Vec<_>>();
        let mut security_descriptor = SecurityDescriptor::default();
        unsafe {
            if let Err(err) = GetNamedSecurityInfoW(PCWSTR(name_vec.as_ptr()), object_type, DACL_SECURITY_INFORMATION, None, None, Some(&mut security_descriptor.dacl), None, security_descriptor.deref_mut()).ok() {
                log::error!("GetNamedSecurityInfoW({:?}, {:?}, DACL_SECURITY_INFORMATION, ...) failed: {}", name, object_type, err);
                return Err(err);
            }
        }

        Ok(security_descriptor)
    }

    pub fn discretionary_access_control_list<'a>(&'a self) ->  ReferencedAccessControlList<'a> {
        ReferencedAccessControlList { acl: self.dacl, _marker: std::marker::PhantomData::<&'a ()>}
    }
}

impl Deref for SecurityDescriptor {
    type Target = PSECURITY_DESCRIPTOR;

    fn deref(&self) -> &Self::Target {
        &self.descriptor
    }
}

impl DerefMut for SecurityDescriptor {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.descriptor
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.descriptor.0.is_null() {
            unsafe { LocalFree(Some(mem::transmute(self.0))) };
        }
    }
}

impl std::fmt::Display for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut string = PWSTR::default();
        let mut len = 0;
        unsafe {
            if let Err(err) = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut string,
                Some(&mut len),
            )
            {
                return write!(f, "Error converting security descriptor to string: {}", err);
            }

            let string = OsString::from_wide(std::slice::from_raw_parts(string.as_ptr(), len as usize));
            let Some(string) = string.to_str() else {
                return write!(f, "Error converting security descriptor to string: invalid UTF-16");
            };
            write!(f, "{}", string)
        }
    }
}

pub trait AccessControlListExt {
    fn as_ptr(&self) -> *mut ACL;

    fn set_named_security_info(&self, name: &OsStr, object_type: SE_OBJECT_TYPE) -> windows::core::Result<()> {
        let name = name.encode_wide().chain(std::iter::once(0)).collect::<Vec<_>>();
        unsafe {
            if let Err(err) = SetNamedSecurityInfoW(PCWSTR(name.as_ptr()), object_type, DACL_SECURITY_INFORMATION, None, None, Some(self.as_ptr()), None).ok() {
                log::error!("SetNamedSecurityInfoW({:?}, {:?}, DACL_SECURITY_INFORMATION, ...) failed: {}", name, object_type, err);
                return Err(err.into());
            }
        }

        Ok(())    
    }

    fn get_effective_rights_from_acl(&self, trustee: &TRUSTEE_W) -> Result<u32, io::Error> {
        let mut access_rights = 0;
        unsafe {
            if let Err(err) = GetEffectiveRightsFromAclW(self.as_ptr(), trustee, &mut access_rights).ok() {
                log::error!("GetEffectiveRightsFromAclW failed: {}", err);
                return Err(err.into());
            }
        }
        Ok(access_rights)
    }

    fn set_entries_in_acl(&self, entries: &[EXPLICIT_ACCESS_W]) -> windows::core::Result<OwnedAccessControlList> {
        let mut new_acl: *mut ACL = ptr::null_mut();
        unsafe {
            if let Err(err) = SetEntriesInAclW(Some(entries), Some(self.as_ptr()), &mut new_acl).ok() {
                log::error!("SetEntriesInAclW failed: {}", err);
                return Err(err.into());
            }
        }
        Ok(OwnedAccessControlList(new_acl))
    }

    fn is_valid(&self) -> bool {
        unsafe {
            IsValidAcl(self.as_ptr()).into()
        }
    }
}

pub struct OwnedAccessControlList(*mut ACL);

impl AccessControlListExt for OwnedAccessControlList {
    fn as_ptr(&self) -> *mut ACL {
        self.0
    }
}

impl Drop for OwnedAccessControlList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(Some(mem::transmute(self.0))) };
        }
    }
}

pub struct ReferencedAccessControlList<'a> {
    acl: *mut ACL,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> AccessControlListExt for ReferencedAccessControlList<'a> {
    fn as_ptr(&self) -> *mut ACL {
        self.acl
    }
}
