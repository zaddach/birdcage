use std::path::PathBuf;

use birdcage::error::Error;
use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup(tempdir: PathBuf) -> TestSetup {
    let mut sandbox = Birdcage::try_new().unwrap();

    // Add a path that doesn't exist.
    let result = sandbox.add_exception(Exception::Read(tempdir.join("does/not/exist").into()));

    // Ensure it is appropriately reported that exception was NOT added.
    match result {
        Err(Error::InvalidPath(path)) => assert_eq!(path, tempdir.join("does/not/exist")),
        _ => panic!("expected path error"),
    }

    TestSetup { sandbox, data: String::new() }
}

pub fn validate(_data: String) {
    // Ensure locking is always successful.
}
