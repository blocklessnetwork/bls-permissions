use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use bls_permissions::is_yield_error_class;
use bls_permissions::AnyError;
use bls_permissions::BlsPermissionsContainer;
use bls_permissions::ModuleSpecifier;
use bls_permissions::Permissions;
use bls_permissions::Url;
use once_cell::sync::Lazy;
use prompter::init_browser_prompter;
use wasm_bindgen::prelude::wasm_bindgen;
pub use macros::*;

#[macro_use]
mod macros;
mod prompter;

#[derive(Clone, Debug)]
pub struct PermissionsContainer(BlsPermissionsContainer);

impl PermissionsContainer {
    pub fn new(perms: Permissions) -> Self {
        init_browser_prompter();
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
    info!("init_permissions_prompt: {b}");
    *PERMSSIONSCONTAINER.0.0.lock() = if b {
        Permissions::none_with_prompt()
    } else {
        Permissions::none_without_prompt()
    };
}

#[derive(Clone, Copy)]
enum Code {
    Success = 0,
    Yield = 255,
    Failed = -1,
    ParameterError = -2,
}

impl Into<u32> for Code {
    fn into(self) -> u32 {
        self as u32
    }
}

#[wasm_bindgen]
pub struct JsCode {
    code: Code,
    msg: Option<String>,
}


#[wasm_bindgen]
impl JsCode {
    #[wasm_bindgen(getter)]
    pub fn is_success(&self) -> bool {
        match self.code {
            Code::Success => true,
            _ => false,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn code(&self) -> i32 {
        self.code as _
    }

    #[wasm_bindgen(getter)]
    pub fn msg(&self) -> Option<String> {
        self.msg.clone()
    }

    fn sucess() -> Self {
        Self {
            code: Code::Success,
            msg: None
        }
    }

    fn jscode_yield() -> Self {
        Self {
            code: Code::Yield,
            msg: None,
        }
    }

    fn error<T: Into<String>>(code: Code, msg: T) -> Self {
        Self {
            code,
            msg: Some(msg.into())
        }
    }
}

macro_rules! error2jscode {
    ($e: expr, $msg: expr) => {
        if is_yield_error_class($e) {
            JsCode::jscode_yield()
        } else {
            info!("Error: {}", $msg);
            JsCode::error(Code::Failed, $msg)
        }
    };
}

#[wasm_bindgen]
pub fn check_read(path: &str, api_name: &str) -> JsCode {
    let path = PathBuf::from(path);
    if let Err(e) = PERMSSIONSCONTAINER.check_read(&path, api_name) {
        let msg = format!("{e}");
        error2jscode!(&e, msg)
    } else {
        JsCode::sucess()
    }
}

#[wasm_bindgen]
pub fn check_write(path: &str, api_name: &str) -> u32 {
    info!("check write: {path}");
    let path = PathBuf::from(path);
    if let Err(e) = PERMSSIONSCONTAINER.check_write(&path, api_name) {
        info!("Error: {}", e);
        if is_yield_error_class(&e) {
            Code::Yield.into()
        } else {
            Code::Failed.into()
        }
    } else {
        Code::Success.into()
    }
}

#[wasm_bindgen]
pub fn check_env(env: &str) -> u32 {
    info!("check env: {env}");
    if let Err(e) = PERMSSIONSCONTAINER.check_env(env) {
        info!("Error: {}", e);
        if is_yield_error_class(&e) {
            Code::Yield.into()
        } else {
            Code::Failed.into()
        }
    } else {
        Code::Success.into()
    }
}


