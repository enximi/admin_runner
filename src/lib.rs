//! 检查管理员权限、以管理员身份运行程序。用于Windows平台。

use std::os::windows::ffi::OsStrExt;

use windows::core::{w, PCWSTR};
use windows::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteExW, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;

/// 检查当前进程是否以管理员身份运行。
pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() }.as_bool()
}

/// 以管理员身份运行当前进程。
pub fn run_as_admin() -> Result<(), Error> {
    let exe = std::env::current_exe()
        .unwrap()
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe.as_ptr()),
        nShow: SW_SHOW.0,
        ..Default::default()
    };

    match unsafe { ShellExecuteExW(&mut sei) } {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::ShellExecuteExWFailed {
            error_code: e.code().0,
        }),
    }
}

/// 如果当前进程尚未以管理员身份运行，则以管理员身份重新运行。
/// 建议在程序启动时调用。
pub fn rerun_as_admin_if_not_admin() -> Result<(), Error> {
    if !is_admin() {
        run_as_admin()?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ShellExecuteExW failed, error code: 0x{error_code:X}")]
    ShellExecuteExWFailed { error_code: i32 },
}
