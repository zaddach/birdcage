use std::{ffi::c_void, io, mem, os::windows::io::RawHandle};

use windows::Win32::{Security::{SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES}, System::Threading::{DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, UpdateProcThreadAttribute, LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES}};

use crate::windows::sid::Sid;

pub struct ProcThreadAttributeList {
    buf: Vec<u8>,
    inherit_handles: Option<Vec<RawHandle>>,
    app_container_sid: Option<Sid>,
    capability_sids: Vec<Sid>,
    capabilities: Vec<SID_AND_ATTRIBUTES>,
    security_capabilities: SECURITY_CAPABILITIES,
}

impl ProcThreadAttributeList {
    pub fn try_new(max_attributes: u32) -> io::Result<ProcThreadAttributeList> {
        let mut list_size = 0;
        //Returns an error when used to assess list size.
        unsafe {
            InitializeProcThreadAttributeList(None,
            max_attributes,
            None,
            & mut list_size)?;
        }

        let mut proc_attrs = ProcThreadAttributeList { 
            buf: vec![0u8; list_size],
            inherit_handles: None,
            app_container_sid: None,
            capability_sids: Vec::new(),
            capabilities: Vec::new(),
            security_capabilities: SECURITY_CAPABILITIES::default(),
         };
        unsafe {
            InitializeProcThreadAttributeList(Some(proc_attrs.raw()),
            max_attributes,
            None,
            & mut list_size)?;
        }

        Ok(proc_attrs)
    }

    pub(crate) fn inherit_handles(&mut self, handles: Vec<RawHandle>) -> io::Result<()> {
        assert!(self.inherit_handles.is_none(), "Function may only be called once");

        let handles_size = mem::size_of::<RawHandle>() * handles.len();
        self.inherit_handles = Some(handles);
        let handles_ptr: *mut c_void = self.inherit_handles.as_deref_mut().unwrap().as_mut_ptr() as *mut _ as *mut c_void;


		unsafe {
			UpdateProcThreadAttribute(self.raw(), 
                0, 
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize, 
                Some(handles_ptr), 
                handles_size, 
                None,
                None)?;
        }
        
        Ok(())
    }

    pub(crate) fn set_security_capabilities(&mut self, app_container_sid: Sid, capabilities: Vec<(Sid, u32)>) -> io::Result<()> {
        assert!(self.app_container_sid.is_none(), "Function may only be called once");

        self.security_capabilities.AppContainerSid = app_container_sid.as_ptr();
        self.app_container_sid = Some(app_container_sid);
        
        for (sid, attrs) in capabilities {
            self.capabilities.push(SID_AND_ATTRIBUTES { Sid: sid.as_ptr(), Attributes: attrs });
            self.capability_sids.push(sid);
        }

        if !self.capabilities.is_empty() {
            self.security_capabilities.Capabilities = self.capabilities.as_mut_ptr();
            self.security_capabilities.CapabilityCount = self.capabilities.len().try_into().unwrap();
        }

		unsafe {
			UpdateProcThreadAttribute(self.raw(), 
                0, 
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize, 
                Some(&mut self.security_capabilities as *mut _ as *mut c_void), 
                mem::size_of::<SECURITY_CAPABILITIES>().try_into().unwrap(), 
                None,
                None)?;
        }
        Ok(())
    }

    pub(crate) fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.buf.as_mut_ptr() as *mut c_void)
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.raw())
        };
    }
}