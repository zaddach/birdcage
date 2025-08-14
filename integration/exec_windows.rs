use std::path::PathBuf;
use std::fs;
use std::process::Command;

use birdcage::{Birdcage, Exception, Sandbox};

use crate::TestSetup;

pub fn setup(tempdir: PathBuf) -> TestSetup {
    let mut sandbox = Birdcage::try_new().unwrap();
    let current_exe = std::env::current_exe().unwrap();
    let temp_file = tempdir.join("harness.exe");
    std::fs::copy(&current_exe, &temp_file).unwrap();
    sandbox.add_exception(Exception::ExecuteAndRead(temp_file.to_path_buf())).unwrap();

    TestSetup { sandbox, data: temp_file.to_str().unwrap().to_string() }
}

pub fn validate(data: String) {
    let temp_file = PathBuf::from(data);
    let cmd = Command::new(& temp_file)
        .args(&["emulate_bin_true"])
        .status()
        .unwrap();
    assert!(cmd.success());

    // Check for success on reading the `true` file.
    let cmd_file = fs::read(& temp_file);
    assert!(cmd_file.is_ok());
}
