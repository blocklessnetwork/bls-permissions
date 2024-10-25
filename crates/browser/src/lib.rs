use bls_permissions::is_yield_error_class;
use bls_permissions::AllowRunDescriptor;
use bls_permissions::AllowRunDescriptorParseResult;
use bls_permissions::AnyError;
use bls_permissions::BlsPermissionsContainer;
use bls_permissions::CheckSpecifierKind;
use bls_permissions::ChildPermissionsArg;
use bls_permissions::DenyRunDescriptor;
use bls_permissions::EnvDescriptor;
use bls_permissions::FfiDescriptor;
use bls_permissions::ImportDescriptor;
use bls_permissions::ModuleSpecifier;
use bls_permissions::NetDescriptor;
use bls_permissions::PathQueryDescriptor;
use bls_permissions::PermissionDescriptorParser;
use bls_permissions::PermissionState;
use bls_permissions::Permissions;
use bls_permissions::ReadDescriptor;
use bls_permissions::RunQueryDescriptor;
use bls_permissions::SysDescriptor;
use bls_permissions::Url;
use bls_permissions::WriteDescriptor;
pub use macros::*;
use once_cell::sync::Lazy;
use prompter::init_browser_prompter;
use std::borrow::Cow;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;

#[macro_use]
mod macros;
mod html;
mod prompter;

#[derive(Clone, Debug)]
pub struct PermissionsContainer(pub bls_permissions::BlsPermissionsContainer);

impl PermissionsContainer {
    pub fn new(descriptor_parser: Arc<dyn PermissionDescriptorParser>, perms: Permissions) -> Self {
        init_browser_prompter();
        Self(BlsPermissionsContainer::new(descriptor_parser, perms))
    }

    pub fn create_child_permissions(
        &self,
        child_permissions_arg: ChildPermissionsArg,
    ) -> Result<PermissionsContainer, AnyError> {
        Ok(PermissionsContainer(self.0.create_child_permissions(child_permissions_arg)?))
    }

    pub fn allow_all(descriptor_parser: Arc<dyn PermissionDescriptorParser>) -> Self {
        Self::new(descriptor_parser, Permissions::allow_all())
    }

    #[inline(always)]
    pub fn check_specifier(
        &self,
        specifier: &ModuleSpecifier,
        kind: CheckSpecifierKind,
    ) -> Result<(), AnyError> {
        self.0.check_specifier(specifier, kind)
    }

    #[inline(always)]
    pub fn check_read(&self, path: &str, api_name: &str) -> Result<PathBuf, AnyError> {
        self.0.check_read(path, api_name)
    }

    #[inline(always)]
    pub fn check_read_with_api_name(
        &self,
        path: &str,
        api_name: Option<&str>,
    ) -> Result<PathBuf, AnyError> {
        self.0.check_read_with_api_name(path, api_name)
    }

    #[inline(always)]
    pub fn check_read_path<'a>(
        &self,
        path: &'a Path,
        api_name: Option<&str>,
    ) -> Result<Cow<'a, Path>, AnyError> {
        self.0.check_read_path(path, api_name)
    }

    /// As `check_read()`, but permission error messages will anonymize the path
    /// by replacing it with the given `display`.
    #[inline(always)]
    pub fn check_read_blind(
        &mut self,
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
    pub fn query_read_all(&self) -> bool {
        self.0.query_read_all()
    }

    #[inline(always)]
    pub fn check_write(&self, path: &str, api_name: &str) -> Result<PathBuf, AnyError> {
        self.0.check_write(path, api_name)
    }

    #[inline(always)]
    pub fn check_write_with_api_name(
        &self,
        path: &str,
        api_name: Option<&str>,
    ) -> Result<PathBuf, AnyError> {
        self.0.check_write_with_api_name(path, api_name)
    }

    #[inline(always)]
    pub fn check_write_path<'a>(
        &self,
        path: &'a Path,
        api_name: &str,
    ) -> Result<Cow<'a, Path>, AnyError> {
        self.0.check_write_path(path, api_name)
    }

    #[inline(always)]
    pub fn check_write_all(&self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_write_all(api_name)
    }

    /// As `check_write()`, but permission error messages will anonymize the path
    /// by replacing it with the given `display`.
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
    pub fn check_write_partial(&mut self, path: &str, api_name: &str) -> Result<PathBuf, AnyError> {
        self.0.check_write_partial(path, api_name)
    }

    #[inline(always)]
    pub fn check_run(&mut self, cmd: &RunQueryDescriptor, api_name: &str) -> Result<(), AnyError> {
        self.0.check_run(cmd, api_name)
    }

    #[inline(always)]
    pub fn check_run_all(&mut self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_run_all(api_name)
    }

    #[inline(always)]
    pub fn query_run_all(&mut self, api_name: &str) -> bool {
        self.0.query_run_all(api_name)
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
    pub fn check_env_all(&mut self) -> Result<(), AnyError> {
        self.0.check_env_all()
    }

    #[inline(always)]
    pub fn check_sys_all(&mut self) -> Result<(), AnyError> {
        self.0.check_sys_all()
    }

    #[inline(always)]
    pub fn check_ffi_all(&mut self) -> Result<(), AnyError> {
        self.0.check_ffi_all()
    }

    /// This checks to see if the allow-all flag was passed, not whether all
    /// permissions are enabled!
    #[inline(always)]
    pub fn check_was_allow_all_flag_passed(&mut self) -> Result<(), AnyError> {
        self.0.check_was_allow_all_flag_passed()
    }

    /// Checks special file access, returning the failed permission type if
    /// not successful.
    pub fn check_special_file(&mut self, path: &Path, api_name: &str) -> Result<(), &'static str> {
        self.0.check_special_file(path, api_name)
    }

    #[inline(always)]
    pub fn check_net_url(&self, url: &Url, api_name: &str) -> Result<(), AnyError> {
        self.0.check_net_url(url, api_name)
    }

    #[inline(always)]
    pub fn check_net<T: AsRef<str>>(
        &self,
        host: &(T, Option<u16>),
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_net(host, api_name)
    }

    #[inline(always)]
    pub fn check_ffi(&mut self, path: &str) -> Result<PathBuf, AnyError> {
        self.0.check_ffi(path)
    }

    #[inline(always)]
    pub fn check_ffi_partial_no_path(&mut self) -> Result<(), AnyError> {
        self.0.check_ffi_partial_no_path()
    }

    #[inline(always)]
    pub fn check_ffi_partial_with_path(&mut self, path: &str) -> Result<PathBuf, AnyError> {
        self.0.check_ffi_partial_with_path(path)
    }

    // query

    #[inline(always)]
    pub fn query_read(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_read(path)
    }

    #[inline(always)]
    pub fn query_write(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_write(path)
    }

    #[inline(always)]
    pub fn query_net(&self, host: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_net(host)
    }

    #[inline(always)]
    pub fn query_env(&self, var: Option<&str>) -> PermissionState {
        self.0.query_env(var)
    }

    #[inline(always)]
    pub fn query_sys(&self, kind: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_sys(kind)
    }

    #[inline(always)]
    pub fn query_run(&self, cmd: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_run(cmd)
    }

    #[inline(always)]
    pub fn query_ffi(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.query_ffi(path)
    }

    // revoke

    #[inline(always)]
    pub fn revoke_read(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_read(path)
    }

    #[inline(always)]
    pub fn revoke_write(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_write(path)
    }

    #[inline(always)]
    pub fn revoke_net(&self, host: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_net(host)
    }

    #[inline(always)]
    pub fn revoke_env(&self, var: Option<&str>) -> PermissionState {
        self.0.revoke_env(var)
    }

    #[inline(always)]
    pub fn revoke_sys(&self, kind: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_sys(kind)
    }

    #[inline(always)]
    pub fn revoke_run(&self, cmd: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_run(cmd)
    }

    #[inline(always)]
    pub fn revoke_ffi(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_ffi(path)
    }

    // request

    #[inline(always)]
    pub fn request_read(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_read(path)
    }

    #[inline(always)]
    pub fn request_write(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.revoke_write(path)
    }

    #[inline(always)]
    pub fn request_net(&self, host: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_net(host)
    }

    #[inline(always)]
    pub fn request_env(&self, var: Option<&str>) -> PermissionState {
        self.0.request_env(var)
    }

    #[inline(always)]
    pub fn request_sys(&self, kind: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_sys(kind)
    }

    #[inline(always)]
    pub fn request_run(&self, cmd: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_run(cmd)
    }

    #[inline(always)]
    pub fn request_ffi(&self, path: Option<&str>) -> Result<PermissionState, AnyError> {
        self.0.request_ffi(path)
    }
}

#[derive(Debug, Clone)]
struct BrowserPermissionDescriptorParser;

impl BrowserPermissionDescriptorParser {
    fn join_path_with_root(&self, path: &str) -> PathBuf {
        if path.starts_with("C:\\") {
            PathBuf::from(path)
        } else {
            PathBuf::from("/").join(path)
        }
    }
}

impl PermissionDescriptorParser for BrowserPermissionDescriptorParser {
    fn parse_read_descriptor(&self, text: &str) -> Result<ReadDescriptor, AnyError> {
        Ok(ReadDescriptor(self.join_path_with_root(text)))
    }

    fn parse_write_descriptor(&self, text: &str) -> Result<WriteDescriptor, AnyError> {
        Ok(WriteDescriptor(self.join_path_with_root(text)))
    }

    fn parse_net_descriptor(&self, text: &str) -> Result<NetDescriptor, AnyError> {
        NetDescriptor::parse(text)
    }

    fn parse_import_descriptor(&self, text: &str) -> Result<ImportDescriptor, AnyError> {
        ImportDescriptor::parse(text)
    }

    fn parse_env_descriptor(&self, text: &str) -> Result<EnvDescriptor, AnyError> {
        Ok(EnvDescriptor::new(text))
    }

    fn parse_sys_descriptor(&self, text: &str) -> Result<SysDescriptor, AnyError> {
        SysDescriptor::parse(text.to_string())
    }

    fn parse_allow_run_descriptor(
        &self,
        text: &str,
    ) -> Result<AllowRunDescriptorParseResult, AnyError> {
        Ok(AllowRunDescriptorParseResult::Descriptor(
            AllowRunDescriptor(self.join_path_with_root(text)),
        ))
    }

    fn parse_deny_run_descriptor(&self, text: &str) -> Result<DenyRunDescriptor, AnyError> {
        if text.contains("/") {
            Ok(DenyRunDescriptor::Path(self.join_path_with_root(text)))
        } else {
            Ok(DenyRunDescriptor::Name(text.to_string()))
        }
    }

    fn parse_ffi_descriptor(&self, text: &str) -> Result<FfiDescriptor, AnyError> {
        Ok(FfiDescriptor(self.join_path_with_root(text)))
    }

    fn parse_path_query(&self, path: &str) -> Result<PathQueryDescriptor, AnyError> {
        Ok(PathQueryDescriptor {
            resolved: self.join_path_with_root(path),
            requested: path.to_string(),
        })
    }

    fn parse_run_query(&self, requested: &str) -> Result<RunQueryDescriptor, AnyError> {
        RunQueryDescriptor::parse(requested)
    }
}

static PERMSSIONSCONTAINER: Lazy<PermissionsContainer> =
    Lazy::new(|| PermissionsContainer::allow_all(Arc::new(BrowserPermissionDescriptorParser)));

#[wasm_bindgen]
pub fn init_permissions_prompt(b: bool) {
    info!("init_permissions_prompt: {b}");
    *PERMSSIONSCONTAINER.0.lock() = if b {
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

    fn success() -> Self {
        Self {
            code: Code::Success,
            msg: Some("success".to_string()),
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
            msg: Some(msg.into()),
        }
    }
}

#[wasm_bindgen]
pub fn check_read(path: &str, api_name: &str) -> JsCode {
    permission_check!(PERMSSIONSCONTAINER.check_read(&path, api_name))
}

#[wasm_bindgen]
pub fn check_write(path: &str, api_name: &str) -> JsCode {
    info!("check write: {path}");
    permission_check!(PERMSSIONSCONTAINER.check_write(&path, api_name))
}

#[wasm_bindgen]
pub fn check_env(env: &str) -> JsCode {
    info!("check env: {env}");
    permission_check!(PERMSSIONSCONTAINER.check_env(env))
}

#[wasm_bindgen]
pub fn check_net(net: &str, api_name: &str) -> JsCode {
    info!("check net: {net}");
    let net = match net.rsplit_once(":") {
        Some((a, p)) => {
            let port: Result<u16, _> = p.parse();
            let port = match port {
                Ok(port) => Some(port),
                Err(_) => {
                    return JsCode::error(
                        Code::ParameterError,
                        &format!("{net} parameter is error."),
                    )
                }
            };
            (a, port)
        }
        None => (net, None),
    };
    permission_check!(PERMSSIONSCONTAINER.check_net(&net, api_name))
}

#[wasm_bindgen]
pub fn check_net_url(url: &str, api_name: &str) -> JsCode {
    info!("check net url: {url}");
    let url = match url.parse() {
        Ok(url) => url,
        Err(_) => {
            return JsCode::error(Code::ParameterError, &format!("{url} parameter is error."))
        }
    };
    permission_check!(PERMSSIONSCONTAINER.check_net_url(&url, api_name))
}
