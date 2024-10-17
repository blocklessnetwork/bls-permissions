use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use bls_permissions::AnyError;
use bls_permissions::BlsPermissionsContainer;
use bls_permissions::ModuleSpecifier;
use bls_permissions::Permissions;
use bls_permissions::Url;
use once_cell::sync::Lazy;
use wasm_bindgen::prelude::wasm_bindgen;
pub use macros::*;

#[macro_use]
mod macros;
mod prompter;

#[derive(Clone, Debug)]
pub struct PermissionsContainer(BlsPermissionsContainer);

impl PermissionsContainer {
    pub fn new(perms: Permissions) -> Self {
        Self(BlsPermissionsContainer::new(perms))
    }

    #[inline(always)]
    pub fn allow_hrtime(&self) -> bool {
        self.0.allow_hrtime()
    }

    pub fn allow_all() -> Self {
        Self::new(Permissions::allow_all())
    }

    #[inline(always)]
    pub fn check_specifier(&self, specifier: &ModuleSpecifier) -> Result<(), AnyError> {
        self.0.check_specifier(specifier)
    }

    #[inline(always)]
    pub fn check_read(&self, path: &Path, api_name: &str) -> Result<(), AnyError> {
        self.0.check_read(path, api_name)
    }

    #[inline(always)]
    pub fn check_read_with_api_name(
        &self,
        path: &Path,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        self.0.check_read_with_api_name(path, api_name)
    }

    #[inline(always)]
    pub fn check_read_blind(
        &self,
        path: &Path,
        display: &str,
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_read_blind(path, display, api_name)
    }

    #[inline(always)]
    pub fn check_read_all(&self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_read_all(api_name)
    }

    #[inline(always)]
    pub fn check_write(&self, path: &Path, api_name: &str) -> Result<(), AnyError> {
        self.0.check_write(path, api_name)
    }

    #[inline(always)]
    pub fn check_write_with_api_name(
        &self,
        path: &Path,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        self.0.check_write_with_api_name(path, api_name)
    }

    #[inline(always)]
    pub fn check_write_all(&self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_write_all(api_name)
    }

    #[inline(always)]
    pub fn check_write_blind(
        &self,
        path: &Path,
        display: &str,
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_write_blind(path, display, api_name)
    }

    #[inline(always)]
    pub fn check_write_partial(&self, path: &Path, api_name: &str) -> Result<(), AnyError> {
        self.0.check_write_partial(path, api_name)
    }

    #[inline(always)]
    pub fn check_run(&self, cmd: &str, api_name: &str) -> Result<(), AnyError> {
        self.0.check_run(cmd, api_name)
    }

    #[inline(always)]
    pub fn check_run_all(&self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_run_all(api_name)
    }

    #[inline(always)]
    pub fn check_sys(&self, kind: &str, api_name: &str) -> Result<(), AnyError> {
        self.0.check_sys(kind, api_name)
    }

    #[inline(always)]
    pub fn check_env(&self, var: &str) -> Result<(), AnyError> {
        self.0.check_env(var)
    }

    #[inline(always)]
    pub fn check_env_all(&self) -> Result<(), AnyError> {
        self.0.check_env_all()
    }

    #[inline(always)]
    pub fn check_sys_all(&self) -> Result<(), AnyError> {
        self.0.check_sys_all()
    }

    #[inline(always)]
    pub fn check_ffi_all(&self) -> Result<(), AnyError> {
        self.0.check_ffi_all()
    }

    /// This checks to see if the allow-all flag was passed, not whether all
    /// permissions are enabled!
    #[inline(always)]
    pub fn check_was_allow_all_flag_passed(&self) -> Result<(), AnyError> {
        self.0.check_was_allow_all_flag_passed()
    }

    pub fn check_special_file(&self, path: &Path, api_name: &str) -> Result<(), &'static str> {
        self.0.check_special_file(path, api_name)
    }

    #[inline(always)]
    pub fn check_net_url(&self, url: &Url, api_name: &str) -> Result<(), AnyError> {
        self.0.check_net_url(url, api_name)
    }

    #[inline(always)]
    pub fn check_net<T: AsRef<str>>(
        &mut self,
        host: &(T, Option<u16>),
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_net(host, api_name)
    }

    #[inline(always)]
    pub fn check_ffi(&self, path: Option<&Path>) -> Result<(), AnyError> {
        self.0.check_ffi(path)
    }

    #[inline(always)]
    pub fn check_ffi_partial(&self, path: Option<&Path>) -> Result<(), AnyError> {
        self.0.check_ffi_partial(path)
    }
}

static PERMSSIONSCONTAINER: Lazy<PermissionsContainer> = Lazy::new(|| {
    PermissionsContainer::allow_all()
});

#[wasm_bindgen]
pub fn init_permissions_prompt(b: bool) {
    log!("init_permissions_prompt: {b}");
    *PERMSSIONSCONTAINER.0.0.lock() = if b {
        Permissions::none_with_prompt()
    } else {
        Permissions::none_with_prompt()
    };
}

enum Code {
    Success = 0,
    Failed = -1,
    ParameterError = -2,
}

impl Into<u32> for Code {
    fn into(self) -> u32 {
        self as u32
    }
}

#[wasm_bindgen]
pub fn check_read(path: &str, api_name: &str) -> u32 {
    log!("check read: {path}");
    let path = PathBuf::from(path);
    if let Err(e) = PERMSSIONSCONTAINER.check_read(&path, api_name) {
        log!("Error: {}", e);
        Code::Success.into()
    } else {
        Code::Failed.into()
    }
}

#[wasm_bindgen]
pub fn check_write(path: &str, api_name: &str) -> u32 {
    log!("check write: {path}");
    let path = PathBuf::from(path);
    if let Err(e) = PERMSSIONSCONTAINER.check_write(&path, api_name) {
        log!("Error: {}", e);
        Code::Success.into()
    } else {
        Code::Failed.into()
    }
}

#[wasm_bindgen]
pub fn check_env(env: &str) -> u32 {
    log!("check env: {env}");
    if let Err(e) = PERMSSIONSCONTAINER.check_env(env) {
        log!("Error: {}", e);
        Code::Success.into()
    } else {
        Code::Failed.into()
    }
}

#[wasm_bindgen]
pub fn check_net(net: &str) -> u32 {
    if let Err(e) = Url::from_str(net) {
        log!("parameter {e}");
    } else {
        return Code::ParameterError.into();
    }
    Code::Success.into()
}


