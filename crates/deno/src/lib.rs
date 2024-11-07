use prompter::init_tty_prompter;

use std::borrow::Cow;
use std::fmt::Debug;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

pub mod prompter;
pub use prompter::set_prompt_callbacks;
pub use prompter::PromptCallback;

pub use bls_permissions::*;

#[derive(Clone, Debug)]
pub struct PermissionsContainer(pub bls_permissions::BlsPermissionsContainer);

impl PermissionsContainer {
    pub fn new(descriptor_parser: Arc<dyn PermissionDescriptorParser>, perms: Permissions) -> Self {
        init_tty_prompter();
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
    pub fn check_env(&mut self, var: &str) -> Result<(), AnyError> {
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
    pub fn check_net_url(&mut self, url: &Url, api_name: &str) -> Result<(), AnyError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use deno_core::serde_json::json;
    use deno_core::{parking_lot::Mutex, serde_json};
    use fqdn::fqdn;
    use prompter::{set_prompter, tests::*};
    use std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    // Creates vector of strings, Vec<String>
    macro_rules! svec {
      ($($x:expr),*) => (vec![$($x.to_string()),*]);
    }
    // make the test thread serial process, make set prompter safe(it's global variable).
    static TESTMUTEX: Mutex<()> = Mutex::new(());

    #[derive(Debug, Clone)]
    struct TestPermissionDescriptorParser;

    impl TestPermissionDescriptorParser {
        fn join_path_with_root(&self, path: &str) -> PathBuf {
            if path.starts_with("C:\\") {
                PathBuf::from(path)
            } else {
                PathBuf::from("/").join(path)
            }
        }
    }

    impl PermissionDescriptorParser for TestPermissionDescriptorParser {
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

    #[test]
    fn check_paths() {
        let _locked = TESTMUTEX.lock();
        let allowlist = svec!["/a/specific/dir/name", "/a/specific", "/b/c"];

        let parser = TestPermissionDescriptorParser;
        let perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_read: Some(allowlist.clone()),
                allow_write: Some(allowlist.clone()),
                allow_ffi: Some(allowlist),
                ..Default::default()
            },
        )
        .unwrap();
        let mut perms = PermissionsContainer::new(Arc::new(parser), perms);
        set_prompter(Box::new(TestPrompter));

        let cases = [
            // Inside of /a/specific and /a/specific/dir/name
            ("/a/specific/dir/name", true),
            // Inside of /a/specific but outside of /a/specific/dir/name
            ("/a/specific/dir", true),
            // Inside of /a/specific and /a/specific/dir/name
            ("/a/specific/dir/name/inner", true),
            // Inside of /a/specific but outside of /a/specific/dir/name
            ("/a/specific/other/dir", true),
            // Exact match with /b/c
            ("/b/c", true),
            // Sub path within /b/c
            ("/b/c/sub/path", true),
            // Sub path within /b/c, needs normalizing
            ("/b/c/sub/path/../path/.", true),
            // Inside of /b but outside of /b/c
            ("/b/e", false),
            // Inside of /a but outside of /a/specific
            ("/a/b", false),
        ];

        for (path, is_ok) in cases {
            assert_eq!(perms.check_read(path, "api").is_ok(), is_ok);
            assert_eq!(perms.check_write(path, "api").is_ok(), is_ok);
            assert_eq!(perms.check_ffi(path).is_ok(), is_ok);
        }
    }

    #[test]
    fn test_check_net_with_values() {
        let _locked = TESTMUTEX.lock();
        set_prompter(Box::new(TestPrompter));
        let parser = TestPermissionDescriptorParser;
        let mut perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_net: Some(svec![
                    "localhost",
                    "deno.land",
                    "github.com:3000",
                    "127.0.0.1",
                    "172.16.0.2:8000",
                    "www.github.com:443",
                    "80.example.com:80",
                    "443.example.com:443"
                ]),
                ..Default::default()
            },
        )
        .unwrap();

        let domain_tests = vec![
            ("localhost", 1234, true),
            ("deno.land", 0, true),
            ("deno.land", 3000, true),
            ("deno.lands", 0, false),
            ("deno.lands", 3000, false),
            ("github.com", 3000, true),
            ("github.com", 0, false),
            ("github.com", 2000, false),
            ("github.net", 3000, false),
            ("127.0.0.1", 0, true),
            ("127.0.0.1", 3000, true),
            ("127.0.0.2", 0, false),
            ("127.0.0.2", 3000, false),
            ("172.16.0.2", 8000, true),
            ("172.16.0.2", 0, false),
            ("172.16.0.2", 6000, false),
            ("172.16.0.1", 8000, false),
            ("443.example.com", 444, false),
            ("80.example.com", 81, false),
            ("80.example.com", 80, true),
            // Just some random hosts that should err
            ("somedomain", 0, false),
            ("192.168.0.1", 0, false),
        ];

        for (host, port, is_ok) in domain_tests {
            let host = Host::parse(host).unwrap();
            let descriptor = NetDescriptor(host, Some(port));
            assert_eq!(
                is_ok,
                perms.net.check(&descriptor, None).is_ok(),
                "{descriptor}",
            );
        }
    }

    #[test]
    fn test_check_net_only_flag() {
        let _locked = TESTMUTEX.lock();
        set_prompter(Box::new(TestPrompter));
        let parser = TestPermissionDescriptorParser;
        let mut perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_net: Some(svec![]), // this means `--allow-net` is present without values following `=` sign
                ..Default::default()
            },
        )
        .unwrap();

        let domain_tests = vec![
            ("localhost", 1234),
            ("deno.land", 0),
            ("deno.land", 3000),
            ("deno.lands", 0),
            ("deno.lands", 3000),
            ("github.com", 3000),
            ("github.com", 0),
            ("github.com", 2000),
            ("github.net", 3000),
            ("127.0.0.1", 0),
            ("127.0.0.1", 3000),
            ("127.0.0.2", 0),
            ("127.0.0.2", 3000),
            ("172.16.0.2", 8000),
            ("172.16.0.2", 0),
            ("172.16.0.2", 6000),
            ("172.16.0.1", 8000),
            ("somedomain", 0),
            ("192.168.0.1", 0),
        ];

        for (host_str, port) in domain_tests {
            let host = Host::parse(host_str).unwrap();
            let descriptor = NetDescriptor(host, Some(port));
            assert!(
                perms.net.check(&descriptor, None).is_ok(),
                "expected {host_str}:{port} to pass"
            );
        }
    }

    #[test]
    fn test_check_net_no_flag() {
        let _locked = TESTMUTEX.lock();
        set_prompter(Box::new(TestPrompter));
        let parser = TestPermissionDescriptorParser;
        let mut perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_net: None,
                ..Default::default()
            },
        )
        .unwrap();

        let domain_tests = vec![
            ("localhost", 1234),
            ("deno.land", 0),
            ("deno.land", 3000),
            ("deno.lands", 0),
            ("deno.lands", 3000),
            ("github.com", 3000),
            ("github.com", 0),
            ("github.com", 2000),
            ("github.net", 3000),
            ("127.0.0.1", 0),
            ("127.0.0.1", 3000),
            ("127.0.0.2", 0),
            ("127.0.0.2", 3000),
            ("172.16.0.2", 8000),
            ("172.16.0.2", 0),
            ("172.16.0.2", 6000),
            ("172.16.0.1", 8000),
            ("somedomain", 0),
            ("192.168.0.1", 0),
        ];

        for (host_str, port) in domain_tests {
            let host = Host::parse(host_str).unwrap();
            let descriptor = NetDescriptor(host, Some(port));
            assert!(
                perms.net.check(&descriptor, None).is_err(),
                "expected {host_str}:{port} to fail"
            );
        }
    }

    #[test]
    fn test_check_net_url() {
        let _locked = TESTMUTEX.lock();
        let parser = TestPermissionDescriptorParser;
        let perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_net: Some(svec![
                    "localhost",
                    "deno.land",
                    "github.com:3000",
                    "127.0.0.1",
                    "172.16.0.2:8000",
                    "www.github.com:443"
                ]),
                ..Default::default()
            },
        )
        .unwrap();
        let mut perms = PermissionsContainer::new(Arc::new(parser), perms);

        let url_tests = vec![
            // Any protocol + port for localhost should be ok, since we don't specify
            ("http://localhost", true),
            ("https://localhost", true),
            ("https://localhost:4443", true),
            ("tcp://localhost:5000", true),
            ("udp://localhost:6000", true),
            // Correct domain + any port and protocol should be ok incorrect shouldn't
            ("https://deno.land/std/example/welcome.ts", true),
            ("https://deno.land:3000/std/example/welcome.ts", true),
            ("https://deno.lands/std/example/welcome.ts", false),
            ("https://deno.lands:3000/std/example/welcome.ts", false),
            // Correct domain + port should be ok all other combinations should err
            ("https://github.com:3000/denoland/deno", true),
            ("https://github.com/denoland/deno", false),
            ("https://github.com:2000/denoland/deno", false),
            ("https://github.net:3000/denoland/deno", false),
            // Correct ipv4 address + any port should be ok others should err
            ("tcp://127.0.0.1", true),
            ("https://127.0.0.1", true),
            ("tcp://127.0.0.1:3000", true),
            ("https://127.0.0.1:3000", true),
            ("tcp://127.0.0.2", false),
            ("https://127.0.0.2", false),
            ("tcp://127.0.0.2:3000", false),
            ("https://127.0.0.2:3000", false),
            // Correct address + port should be ok all other combinations should err
            ("tcp://172.16.0.2:8000", true),
            ("https://172.16.0.2:8000", true),
            ("tcp://172.16.0.2", false),
            ("https://172.16.0.2", false),
            ("tcp://172.16.0.2:6000", false),
            ("https://172.16.0.2:6000", false),
            ("tcp://172.16.0.1:8000", false),
            ("https://172.16.0.1:8000", false),
            // Testing issue #6531 (Network permissions check doesn't account for well-known default ports) so we dont regress
            ("https://www.github.com:443/robots.txt", true),
        ];

        for (url_str, is_ok) in url_tests {
            let u = Url::parse(url_str).unwrap();
            assert_eq!(is_ok, perms.check_net_url(&u, "api()").is_ok(), "{}", u);
        }
    }

    #[test]
    fn check_specifiers() {
        let _locked = TESTMUTEX.lock();
        let read_allowlist = if cfg!(target_os = "windows") {
            svec!["C:\\a"]
        } else {
            svec!["/a"]
        };
        let parser = TestPermissionDescriptorParser;
        let perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_read: Some(read_allowlist),
                allow_import: Some(svec!["localhost"]),
                ..Default::default()
            },
        )
        .unwrap();
        let perms = PermissionsContainer::new(Arc::new(parser), perms);
        set_prompter(Box::new(TestPrompter));
        let mut fixtures = vec![
            (
                ModuleSpecifier::parse("http://localhost:4545/mod.ts").unwrap(),
                CheckSpecifierKind::Static,
                true,
            ),
            (
                ModuleSpecifier::parse("http://localhost:4545/mod.ts").unwrap(),
                CheckSpecifierKind::Dynamic,
                true,
            ),
            (
                ModuleSpecifier::parse("http://deno.land/x/mod.ts").unwrap(),
                CheckSpecifierKind::Dynamic,
                false,
            ),
            (
                ModuleSpecifier::parse("data:text/plain,Hello%2C%20Deno!").unwrap(),
                CheckSpecifierKind::Dynamic,
                true,
            ),
        ];

        if cfg!(target_os = "windows") {
            fixtures.push((
                ModuleSpecifier::parse("file:///C:/a/mod.ts").unwrap(),
                CheckSpecifierKind::Dynamic,
                true,
            ));
            fixtures.push((
                ModuleSpecifier::parse("file:///C:/b/mod.ts").unwrap(),
                CheckSpecifierKind::Static,
                true,
            ));
            fixtures.push((
                ModuleSpecifier::parse("file:///C:/b/mod.ts").unwrap(),
                CheckSpecifierKind::Dynamic,
                false,
            ));
        } else {
            fixtures.push((
                ModuleSpecifier::parse("file:///a/mod.ts").unwrap(),
                CheckSpecifierKind::Dynamic,
                true,
            ));
            fixtures.push((
                ModuleSpecifier::parse("file:///b/mod.ts").unwrap(),
                CheckSpecifierKind::Static,
                true,
            ));
            fixtures.push((
                ModuleSpecifier::parse("file:///b/mod.ts").unwrap(),
                CheckSpecifierKind::Dynamic,
                false,
            ));
        }

        for (specifier, kind, expected) in fixtures {
            assert_eq!(
                perms.check_specifier(&specifier, kind).is_ok(),
                expected,
                "{}",
                specifier,
            );
        }
    }

    #[test]
    fn test_query() {
        set_prompter(Box::new(TestPrompter));
        let parser = TestPermissionDescriptorParser;
        let perms1 = Permissions::allow_all();
        let perms2 = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_read: Some(svec!["/foo"]),
                allow_write: Some(svec!["/foo"]),
                allow_ffi: Some(svec!["/foo"]),
                allow_net: Some(svec!["127.0.0.1:8000"]),
                allow_env: Some(svec!["HOME"]),
                allow_sys: Some(svec!["hostname"]),
                allow_run: Some(svec!["/deno"]),
                allow_all: false,
                ..Default::default()
            },
        )
        .unwrap();
        let perms3 = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                deny_read: Some(svec!["/foo"]),
                deny_write: Some(svec!["/foo"]),
                deny_ffi: Some(svec!["/foo"]),
                deny_net: Some(svec!["127.0.0.1:8000"]),
                deny_env: Some(svec!["HOME"]),
                deny_sys: Some(svec!["hostname"]),
                deny_run: Some(svec!["deno"]),
                ..Default::default()
            },
        )
        .unwrap();
        let perms4 = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_read: Some(vec![]),
                deny_read: Some(svec!["/foo"]),
                allow_write: Some(vec![]),
                deny_write: Some(svec!["/foo"]),
                allow_ffi: Some(vec![]),
                deny_ffi: Some(svec!["/foo"]),
                allow_net: Some(vec![]),
                deny_net: Some(svec!["127.0.0.1:8000"]),
                allow_env: Some(vec![]),
                deny_env: Some(svec!["HOME"]),
                allow_sys: Some(vec![]),
                deny_sys: Some(svec!["hostname"]),
                allow_run: Some(vec![]),
                deny_run: Some(svec!["deno"]),
                ..Default::default()
            },
        )
        .unwrap();
        #[rustfmt::skip]
        {
            let read_query = |path: &str| parser.parse_path_query(path).unwrap().into_read();
            let write_query = |path: &str| parser.parse_path_query(path).unwrap().into_write();
            let ffi_query = |path: &str| parser.parse_path_query(path).unwrap().into_ffi();
            assert_eq!(perms1.read.query(None), PermissionState::Granted);
            assert_eq!(perms1.read.query(Some(&read_query("/foo"))), PermissionState::Granted);
            assert_eq!(perms2.read.query(None), PermissionState::Prompt);
            assert_eq!(perms2.read.query(Some(&read_query("/foo"))), PermissionState::Granted);
            assert_eq!(perms2.read.query(Some(&read_query("/foo/bar"))), PermissionState::Granted);
            assert_eq!(perms3.read.query(None), PermissionState::Prompt);
            assert_eq!(perms3.read.query(Some(&read_query("/foo"))), PermissionState::Denied);
            assert_eq!(perms3.read.query(Some(&read_query("/foo/bar"))), PermissionState::Denied);
            assert_eq!(perms4.read.query(None), PermissionState::GrantedPartial);
            assert_eq!(perms4.read.query(Some(&read_query("/foo"))), PermissionState::Denied);
            assert_eq!(perms4.read.query(Some(&read_query("/foo/bar"))), PermissionState::Denied);
            assert_eq!(perms4.read.query(Some(&read_query("/bar"))), PermissionState::Granted);
            assert_eq!(perms1.write.query(None), PermissionState::Granted);
            assert_eq!(perms1.write.query(Some(&write_query("/foo"))), PermissionState::Granted);
            assert_eq!(perms2.write.query(None), PermissionState::Prompt);
            assert_eq!(perms2.write.query(Some(&write_query("/foo"))), PermissionState::Granted);
            assert_eq!(perms2.write.query(Some(&write_query("/foo/bar"))), PermissionState::Granted);
            assert_eq!(perms3.write.query(None), PermissionState::Prompt);
            assert_eq!(perms3.write.query(Some(&write_query("/foo"))), PermissionState::Denied);
            assert_eq!(perms3.write.query(Some(&write_query("/foo/bar"))), PermissionState::Denied);
            assert_eq!(perms4.write.query(None), PermissionState::GrantedPartial);
            assert_eq!(perms4.write.query(Some(&write_query("/foo"))), PermissionState::Denied);
            assert_eq!(perms4.write.query(Some(&write_query("/foo/bar"))), PermissionState::Denied);
            assert_eq!(perms4.write.query(Some(&write_query("/bar"))), PermissionState::Granted);
            assert_eq!(perms1.ffi.query(None), PermissionState::Granted);
            assert_eq!(perms1.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Granted);
            assert_eq!(perms2.ffi.query(None), PermissionState::Prompt);
            assert_eq!(perms2.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Granted);
            assert_eq!(perms2.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Granted);
            assert_eq!(perms3.ffi.query(None), PermissionState::Prompt);
            assert_eq!(perms3.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Denied);
            assert_eq!(perms3.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Denied);
            assert_eq!(perms4.ffi.query(None), PermissionState::GrantedPartial);
            assert_eq!(perms4.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Denied);
            assert_eq!(perms4.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Denied);
            assert_eq!(perms4.ffi.query(Some(&ffi_query("/bar"))), PermissionState::Granted);
            assert_eq!(perms1.net.query(None), PermissionState::Granted);
            assert_eq!(perms1.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), None))), PermissionState::Granted);
            assert_eq!(perms2.net.query(None), PermissionState::Prompt);
            assert_eq!(perms2.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Granted);
            assert_eq!(perms3.net.query(None), PermissionState::Prompt);
            assert_eq!(perms3.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Denied);
            assert_eq!(perms4.net.query(None), PermissionState::GrantedPartial);
            assert_eq!(perms4.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Denied);
            assert_eq!(perms4.net.query(Some(&NetDescriptor(Host::must_parse("192.168.0.1"), Some(8000)))), PermissionState::Granted);
            assert_eq!(perms1.env.query(None), PermissionState::Granted);
            assert_eq!(perms1.env.query(Some("HOME")), PermissionState::Granted);
            assert_eq!(perms2.env.query(None), PermissionState::Prompt);
            assert_eq!(perms2.env.query(Some("HOME")), PermissionState::Granted);
            assert_eq!(perms3.env.query(None), PermissionState::Prompt);
            assert_eq!(perms3.env.query(Some("HOME")), PermissionState::Denied);
            assert_eq!(perms4.env.query(None), PermissionState::GrantedPartial);
            assert_eq!(perms4.env.query(Some("HOME")), PermissionState::Denied);
            assert_eq!(perms4.env.query(Some("AWAY")), PermissionState::Granted);
            let sys_desc = |name: &str| SysDescriptor::parse(name.to_string()).unwrap();
            assert_eq!(perms1.sys.query(None), PermissionState::Granted);
            assert_eq!(perms1.sys.query(Some(&sys_desc("osRelease"))), PermissionState::Granted);
            assert_eq!(perms2.sys.query(None), PermissionState::Prompt);
            assert_eq!(perms2.sys.query(Some(&sys_desc("hostname"))), PermissionState::Granted);
            assert_eq!(perms3.sys.query(None), PermissionState::Prompt);
            assert_eq!(perms3.sys.query(Some(&sys_desc("hostname"))), PermissionState::Denied);
            assert_eq!(perms4.sys.query(None), PermissionState::GrantedPartial);
            assert_eq!(perms4.sys.query(Some(&sys_desc("hostname"))), PermissionState::Denied);
            assert_eq!(perms4.sys.query(Some(&sys_desc("uid"))), PermissionState::Granted);
            assert_eq!(perms1.run.query(None), PermissionState::Granted);
            let deno_run_query = RunQueryDescriptor::Path {
                requested: "deno".to_string(),
                resolved: PathBuf::from("/deno"),
            };
            let node_run_query = RunQueryDescriptor::Path {
                requested: "node".to_string(),
                resolved: PathBuf::from("/node"),
            };
            assert_eq!(perms1.run.query(Some(&deno_run_query)), PermissionState::Granted);
            assert_eq!(perms1.write.query(Some(&write_query("/deno"))), PermissionState::Granted);
            assert_eq!(perms2.run.query(None), PermissionState::Prompt);
            assert_eq!(perms2.run.query(Some(&deno_run_query)), PermissionState::Granted);
            assert_eq!(perms2.write.query(Some(&write_query("/deno"))), PermissionState::Denied);
            assert_eq!(perms3.run.query(None), PermissionState::Prompt);
            assert_eq!(perms3.run.query(Some(&deno_run_query)), PermissionState::Denied);
            assert_eq!(perms4.run.query(None), PermissionState::GrantedPartial);
            assert_eq!(perms4.run.query(Some(&deno_run_query)), PermissionState::Denied);
            assert_eq!(perms4.run.query(Some(&node_run_query)), PermissionState::Granted);
        };
    }

    #[test]
    fn test_request() {
        set_prompter(Box::new(TestPrompter));
        let parser = TestPermissionDescriptorParser;
        let mut perms: Permissions = Permissions::none_with_prompt();
        let mut perms_no_prompt: Permissions = Permissions::none_without_prompt();
        let read_query = |path: &str| parser.parse_path_query(path).unwrap().into_read();
        let write_query = |path: &str| parser.parse_path_query(path).unwrap().into_write();
        let ffi_query = |path: &str| parser.parse_path_query(path).unwrap().into_ffi();
        #[rustfmt::skip]
        {
            let _locked = TESTMUTEX.lock();
            let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
            prompt_value.set(true);
            assert_eq!(perms.read.request(Some(&read_query("/foo"))), PermissionState::Granted);
            assert_eq!(perms.read.query(None), PermissionState::Prompt);
            prompt_value.set(false);
            assert_eq!(perms.read.request(Some(&read_query("/foo/bar"))), PermissionState::Granted);
            prompt_value.set(false);
            assert_eq!(perms.write.request(Some(&write_query("/foo"))), PermissionState::Denied);
            assert_eq!(perms.write.query(Some(&write_query("/foo/bar"))), PermissionState::Prompt);
            prompt_value.set(true);
            assert_eq!(perms.write.request(None), PermissionState::Denied);
            prompt_value.set(false);
            assert_eq!(perms.ffi.request(Some(&ffi_query("/foo"))), PermissionState::Denied);
            assert_eq!(perms.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Prompt);
            prompt_value.set(true);
            assert_eq!(perms.ffi.request(None), PermissionState::Denied);
            prompt_value.set(true);
            assert_eq!(perms.net.request(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), None))), PermissionState::Granted);
            prompt_value.set(false);
            assert_eq!(perms.net.request(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Granted);
            prompt_value.set(true);
            assert_eq!(perms.env.request(Some("HOME")), PermissionState::Granted);
            assert_eq!(perms.env.query(None), PermissionState::Prompt);
            prompt_value.set(false);
            assert_eq!(perms.env.request(Some("HOME")), PermissionState::Granted);
            prompt_value.set(true);
            let sys_desc = |name: &str| SysDescriptor::parse(name.to_string()).unwrap();
            assert_eq!(perms.sys.request(Some(&sys_desc("hostname"))), PermissionState::Granted);
            assert_eq!(perms.sys.query(None), PermissionState::Prompt);
            prompt_value.set(false);
            assert_eq!(perms.sys.request(Some(&sys_desc("hostname"))), PermissionState::Granted);
            prompt_value.set(true);
            let run_query = RunQueryDescriptor::Path {
                requested: "deno".to_string(),
                resolved: PathBuf::from("/deno"),
            };
            assert_eq!(perms.run.request(Some(&run_query)), PermissionState::Granted);
            assert_eq!(perms.run.query(None), PermissionState::Prompt);
            prompt_value.set(false);
            assert_eq!(perms.run.request(Some(&run_query)), PermissionState::Granted);
            assert_eq!(perms_no_prompt.read.request(Some(&read_query("/foo"))), PermissionState::Denied);
        };
    }

    #[test]
    fn test_revoke() {
        let _locked = TESTMUTEX.lock();
        set_prompter(Box::new(TestPrompter));
        let parser = TestPermissionDescriptorParser;
        let mut perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_read: Some(svec!["/foo", "/foo/baz"]),
                allow_write: Some(svec!["/foo", "/foo/baz"]),
                allow_ffi: Some(svec!["/foo", "/foo/baz"]),
                allow_net: Some(svec!["127.0.0.1", "127.0.0.1:8000"]),
                allow_env: Some(svec!["HOME"]),
                allow_sys: Some(svec!["hostname"]),
                allow_run: Some(svec!["/deno"]),
                ..Default::default()
            },
        )
        .unwrap();
        let read_query = |path: &str| parser.parse_path_query(path).unwrap().into_read();
        let write_query = |path: &str| parser.parse_path_query(path).unwrap().into_write();
        let ffi_query = |path: &str| parser.parse_path_query(path).unwrap().into_ffi();
        #[rustfmt::skip]
    {
        assert_eq!(perms.read.revoke(Some(&read_query("/foo/bar"))), PermissionState::Prompt);
        assert_eq!(perms.read.query(Some(&read_query("/foo"))), PermissionState::Prompt);
        assert_eq!(perms.read.query(Some(&read_query("/foo/baz"))), PermissionState::Granted);
        assert_eq!(perms.write.revoke(Some(&write_query("/foo/bar"))), PermissionState::Prompt);
        assert_eq!(perms.write.query(Some(&write_query("/foo"))), PermissionState::Prompt);
        assert_eq!(perms.write.query(Some(&write_query("/foo/baz"))), PermissionState::Granted);
        assert_eq!(perms.ffi.revoke(Some(&ffi_query("/foo/bar"))), PermissionState::Prompt);
        assert_eq!(perms.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Prompt);
        assert_eq!(perms.ffi.query(Some(&ffi_query("/foo/baz"))), PermissionState::Granted);
        assert_eq!(perms.net.revoke(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(9000)))), PermissionState::Prompt);
        assert_eq!(perms.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), None))), PermissionState::Prompt);
        assert_eq!(perms.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Granted);
        assert_eq!(perms.env.revoke(Some("HOME")), PermissionState::Prompt);
        assert_eq!(perms.env.revoke(Some("hostname")), PermissionState::Prompt);
        let run_query = RunQueryDescriptor::Path {
            requested: "deno".to_string(),
            resolved: PathBuf::from("/deno"),
        };
        assert_eq!(perms.run.revoke(Some(&run_query)), PermissionState::Prompt);
    };
    }

    #[test]
    fn test_check() {
        let _locked = TESTMUTEX.lock();
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions::none_with_prompt();
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        let parser = TestPermissionDescriptorParser;
        let read_query = |path: &str| parser.parse_path_query(path).unwrap().into_read();
        let write_query = |path: &str| parser.parse_path_query(path).unwrap().into_write();
        let ffi_query = |path: &str| parser.parse_path_query(path).unwrap().into_ffi();
        prompt_value.set(true);
        assert!(perms.read.check(&read_query("/foo"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.read.check(&read_query("/foo"), None).is_ok());
        assert!(perms.read.check(&read_query("/bar"), None).is_err());

        prompt_value.set(true);
        assert!(perms.write.check(&write_query("/foo"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.write.check(&write_query("/foo"), None).is_ok());
        assert!(perms.write.check(&write_query("/bar"), None).is_err());

        prompt_value.set(true);
        assert!(perms.ffi.check(&ffi_query("/foo"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.ffi.check(&ffi_query("/foo"), None).is_ok());
        assert!(perms.ffi.check(&ffi_query("/bar"), None).is_err());

        prompt_value.set(true);
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)),
                None
            )
            .is_ok());
        prompt_value.set(false);
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)),
                None
            )
            .is_ok());
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8001)),
                None
            )
            .is_err());
        assert!(perms
            .net
            .check(&NetDescriptor(Host::must_parse("127.0.0.1"), None), None)
            .is_err());
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("deno.land"), Some(8000)),
                None
            )
            .is_err());
        assert!(perms
            .net
            .check(&NetDescriptor(Host::must_parse("deno.land"), None), None)
            .is_err());

        #[allow(clippy::disallowed_methods)]
        let cwd = std::env::current_dir().unwrap();
        prompt_value.set(true);
        assert!(perms
            .run
            .check(
                &RunQueryDescriptor::Path {
                    requested: "cat".to_string(),
                    resolved: cwd.join("cat")
                },
                None
            )
            .is_ok());
        prompt_value.set(false);
        assert!(perms
            .run
            .check(
                &RunQueryDescriptor::Path {
                    requested: "cat".to_string(),
                    resolved: cwd.join("cat")
                },
                None
            )
            .is_ok());
        assert!(perms
            .run
            .check(
                &RunQueryDescriptor::Path {
                    requested: "ls".to_string(),
                    resolved: cwd.join("ls")
                },
                None
            )
            .is_err());

        prompt_value.set(true);
        assert!(perms.env.check("HOME", None).is_ok());
        prompt_value.set(false);
        assert!(perms.env.check("HOME", None).is_ok());
        assert!(perms.env.check("PATH", None).is_err());

        prompt_value.set(true);
        assert!(perms.env.check("hostname", None).is_ok());
        prompt_value.set(false);
        assert!(perms.env.check("hostname", None).is_ok());
        assert!(perms.env.check("osRelease", None).is_err());
    }

    #[test]
    fn test_check_fail() {
        let _locked = TESTMUTEX.lock();
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions::none_with_prompt();
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        let parser = TestPermissionDescriptorParser;
        let read_query = |path: &str| parser.parse_path_query(path).unwrap().into_read();
        let write_query = |path: &str| parser.parse_path_query(path).unwrap().into_write();
        let ffi_query = |path: &str| parser.parse_path_query(path).unwrap().into_ffi();

        prompt_value.set(false);
        assert!(perms.read.check(&read_query("/foo"), None).is_err());
        prompt_value.set(true);
        assert!(perms.read.check(&read_query("/foo"), None).is_err());
        assert!(perms.read.check(&read_query("/bar"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.read.check(&read_query("/bar"), None).is_ok());

        prompt_value.set(false);
        assert!(perms.write.check(&write_query("/foo"), None).is_err());
        prompt_value.set(true);
        assert!(perms.write.check(&write_query("/foo"), None).is_err());
        assert!(perms.write.check(&write_query("/bar"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.write.check(&write_query("/bar"), None).is_ok());

        prompt_value.set(false);
        assert!(perms.ffi.check(&ffi_query("/foo"), None).is_err());
        prompt_value.set(true);
        assert!(perms.ffi.check(&ffi_query("/foo"), None).is_err());
        assert!(perms.ffi.check(&ffi_query("/bar"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.ffi.check(&ffi_query("/bar"), None).is_ok());

        prompt_value.set(false);
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)),
                None
            )
            .is_err());
        prompt_value.set(true);
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)),
                None
            )
            .is_err());
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8001)),
                None
            )
            .is_ok());
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("deno.land"), Some(8000)),
                None
            )
            .is_ok());
        prompt_value.set(false);
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8001)),
                None
            )
            .is_ok());
        assert!(perms
            .net
            .check(
                &NetDescriptor(Host::must_parse("deno.land"), Some(8000)),
                None
            )
            .is_ok());

        prompt_value.set(false);
        #[allow(clippy::disallowed_methods)]
        let cwd = std::env::current_dir().unwrap();
        assert!(perms
            .run
            .check(
                &RunQueryDescriptor::Path {
                    requested: "cat".to_string(),
                    resolved: cwd.join("cat")
                },
                None
            )
            .is_err());
        prompt_value.set(true);
        assert!(perms
            .run
            .check(
                &RunQueryDescriptor::Path {
                    requested: "cat".to_string(),
                    resolved: cwd.join("cat")
                },
                None
            )
            .is_err());
        assert!(perms
            .run
            .check(
                &RunQueryDescriptor::Path {
                    requested: "ls".to_string(),
                    resolved: cwd.join("ls")
                },
                None
            )
            .is_ok());
        prompt_value.set(false);
        assert!(perms
            .run
            .check(
                &RunQueryDescriptor::Path {
                    requested: "ls".to_string(),
                    resolved: cwd.join("ls")
                },
                None
            )
            .is_ok());

        prompt_value.set(false);
        assert!(perms.env.check("HOME", None).is_err());
        prompt_value.set(true);
        assert!(perms.env.check("HOME", None).is_err());
        assert!(perms.env.check("PATH", None).is_ok());
        prompt_value.set(false);
        assert!(perms.env.check("PATH", None).is_ok());

        prompt_value.set(false);
        let sys_desc = |name: &str| SysDescriptor::parse(name.to_string()).unwrap();
        assert!(perms.sys.check(&sys_desc("hostname"), None).is_err());
        prompt_value.set(true);
        assert!(perms.sys.check(&sys_desc("hostname"), None).is_err());
        assert!(perms.sys.check(&sys_desc("osRelease"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.sys.check(&sys_desc("osRelease"), None).is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn test_env_windows() {
        let _locked = TESTMUTEX.lock();
        set_prompter(Box::new(TestPrompter));
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        let mut perms = Permissions::allow_all();
        perms.env = UnaryPermission {
            granted_global: false,
            ..Permissions::new_unary(
                Some(HashSet::from([EnvDescriptor::new("HOME")])),
                None,
                false,
            )
            .unwrap()
        };

        prompt_value.set(true);
        assert!(perms.env.check("HOME", None).is_ok());
        prompt_value.set(false);
        assert!(perms.env.check("HOME", None).is_ok());
        assert!(perms.env.check("hOmE", None).is_ok());

        assert_eq!(perms.env.revoke(Some("HomE")), PermissionState::Prompt);
    }

    #[test]
    fn test_check_partial_denied() {
        let _locked = TESTMUTEX.lock();
        let parser = TestPermissionDescriptorParser;
        let mut perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_read: Some(vec![]),
                deny_read: Some(svec!["/foo/bar"]),
                allow_write: Some(vec![]),
                deny_write: Some(svec!["/foo/bar"]),
                ..Default::default()
            },
        )
        .unwrap();

        let read_query = parser.parse_path_query("/foo").unwrap().into_read();
        perms.read.check_partial(&read_query, None).unwrap();
        assert!(perms.read.check(&read_query, None).is_err());

        let write_query = parser.parse_path_query("/foo").unwrap().into_write();
        perms.write.check_partial(&write_query, None).unwrap();
        assert!(perms.write.check(&write_query, None).is_err());
    }

    #[test]
    fn test_net_fully_qualified_domain_name() {
        let _locked = TESTMUTEX.lock();
        let parser = TestPermissionDescriptorParser;
        let perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_net: Some(svec!["allowed.domain", "1.1.1.1"]),
                deny_net: Some(svec!["denied.domain", "2.2.2.2"]),
                ..Default::default()
            },
        )
        .unwrap();
        let mut perms = PermissionsContainer::new(Arc::new(parser), perms);
        set_prompter(Box::new(TestPrompter));
        let cases = [
            ("allowed.domain.", true),
            ("1.1.1.1", true),
            ("denied.domain.", false),
            ("2.2.2.2", false),
        ];

        for (host, is_ok) in cases {
            assert_eq!(perms.check_net(&(host, None), "api").is_ok(), is_ok);
        }
    }

    #[test]
    fn test_deserialize_child_permissions_arg() {
        let _locked = TESTMUTEX.lock();
        set_prompter(Box::new(TestPrompter));
        assert_eq!(
            ChildPermissionsArg::inherit(),
            ChildPermissionsArg {
                env: ChildUnaryPermissionArg::Inherit,
                net: ChildUnaryPermissionArg::Inherit,
                ffi: ChildUnaryPermissionArg::Inherit,
                import: ChildUnaryPermissionArg::Inherit,
                read: ChildUnaryPermissionArg::Inherit,
                run: ChildUnaryPermissionArg::Inherit,
                sys: ChildUnaryPermissionArg::Inherit,
                write: ChildUnaryPermissionArg::Inherit,
            }
        );
        assert_eq!(
            ChildPermissionsArg::none(),
            ChildPermissionsArg {
                env: ChildUnaryPermissionArg::NotGranted,
                net: ChildUnaryPermissionArg::NotGranted,
                ffi: ChildUnaryPermissionArg::NotGranted,
                import: ChildUnaryPermissionArg::NotGranted,
                read: ChildUnaryPermissionArg::NotGranted,
                run: ChildUnaryPermissionArg::NotGranted,
                sys: ChildUnaryPermissionArg::NotGranted,
                write: ChildUnaryPermissionArg::NotGranted,
            }
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!("inherit")).unwrap(),
            ChildPermissionsArg::inherit()
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!("none")).unwrap(),
            ChildPermissionsArg::none()
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({})).unwrap(),
            ChildPermissionsArg::none()
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({
              "env": ["foo", "bar"],
            }))
            .unwrap(),
            ChildPermissionsArg {
                env: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar"]),
                ..ChildPermissionsArg::none()
            }
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({
              "env": true,
              "net": true,
              "ffi": true,
              "import": true,
              "read": true,
              "run": true,
              "sys": true,
              "write": true,
            }))
            .unwrap(),
            ChildPermissionsArg {
                env: ChildUnaryPermissionArg::Granted,
                net: ChildUnaryPermissionArg::Granted,
                ffi: ChildUnaryPermissionArg::Granted,
                import: ChildUnaryPermissionArg::Granted,
                read: ChildUnaryPermissionArg::Granted,
                run: ChildUnaryPermissionArg::Granted,
                sys: ChildUnaryPermissionArg::Granted,
                write: ChildUnaryPermissionArg::Granted,
            }
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({
              "env": false,
              "net": false,
              "ffi": false,
              "import": false,
              "read": false,
              "run": false,
              "sys": false,
              "write": false,
            }))
            .unwrap(),
            ChildPermissionsArg {
                env: ChildUnaryPermissionArg::NotGranted,
                net: ChildUnaryPermissionArg::NotGranted,
                ffi: ChildUnaryPermissionArg::NotGranted,
                import: ChildUnaryPermissionArg::NotGranted,
                read: ChildUnaryPermissionArg::NotGranted,
                run: ChildUnaryPermissionArg::NotGranted,
                sys: ChildUnaryPermissionArg::NotGranted,
                write: ChildUnaryPermissionArg::NotGranted,
            }
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({
              "env": ["foo", "bar"],
              "net": ["foo", "bar:8000"],
              "ffi": ["foo", "file:///bar/baz"],
              "import": ["example.com"],
              "read": ["foo", "file:///bar/baz"],
              "run": ["foo", "file:///bar/baz", "./qux"],
              "sys": ["hostname", "osRelease"],
              "write": ["foo", "file:///bar/baz"],
            }))
            .unwrap(),
            ChildPermissionsArg {
                env: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar"]),
                net: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar:8000"]),
                ffi: ChildUnaryPermissionArg::GrantedList(svec!["foo", "file:///bar/baz"]),
                import: ChildUnaryPermissionArg::GrantedList(svec!["example.com"]),
                read: ChildUnaryPermissionArg::GrantedList(svec!["foo", "file:///bar/baz"]),
                run: ChildUnaryPermissionArg::GrantedList(svec!["foo", "file:///bar/baz", "./qux"]),
                sys: ChildUnaryPermissionArg::GrantedList(svec!["hostname", "osRelease"]),
                write: ChildUnaryPermissionArg::GrantedList(svec!["foo", "file:///bar/baz"]),
            }
        );
    }

    #[test]
    fn test_create_child_permissions() {
        let _locked = TESTMUTEX.lock();
        let parser = TestPermissionDescriptorParser;
        let main_perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                allow_env: Some(vec![]),
                allow_net: Some(svec!["foo", "bar"]),
                ..Default::default()
            },
        )
        .unwrap();
        let main_perms = PermissionsContainer::new(Arc::new(parser), main_perms);
        set_prompter(Box::new(TestPrompter));
        assert_eq!(
            main_perms
                .create_child_permissions(ChildPermissionsArg {
                    env: ChildUnaryPermissionArg::Inherit,
                    net: ChildUnaryPermissionArg::GrantedList(svec!["foo"]),
                    ffi: ChildUnaryPermissionArg::NotGranted,
                    ..ChildPermissionsArg::none()
                })
                .unwrap()
                .inner
                .lock()
                .clone(),
            Permissions {
                env: Permissions::new_unary(Some(HashSet::new()), None, false).unwrap(),
                net: Permissions::new_unary(
                    Some(HashSet::from([NetDescriptor::parse("foo").unwrap()])),
                    None,
                    false
                )
                .unwrap(),
                ..Permissions::none_without_prompt()
            }
        );
        assert!(main_perms
            .create_child_permissions(ChildPermissionsArg {
                net: ChildUnaryPermissionArg::Granted,
                ..ChildPermissionsArg::none()
            })
            .is_err());
        assert!(main_perms
            .create_child_permissions(ChildPermissionsArg {
                net: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar", "baz"]),
                ..ChildPermissionsArg::none()
            })
            .is_err());
        assert!(main_perms
            .create_child_permissions(ChildPermissionsArg {
                ffi: ChildUnaryPermissionArg::GrantedList(svec!["foo"]),
                ..ChildPermissionsArg::none()
            })
            .is_err());
    }

    #[test]
    fn test_create_child_permissions_with_prompt() {
        let _locked = TESTMUTEX.lock();
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        let main_perms = Permissions::from_options(
            &TestPermissionDescriptorParser,
            &PermissionsOptions {
                prompt: true,
                ..Default::default()
            },
        )
        .unwrap();
        let main_perms =
            PermissionsContainer::new(Arc::new(TestPermissionDescriptorParser), main_perms);
        set_prompter(Box::new(TestPrompter));
        prompt_value.set(true);
        let worker_perms = main_perms
            .create_child_permissions(ChildPermissionsArg {
                read: ChildUnaryPermissionArg::Granted,
                run: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar"]),
                ..ChildPermissionsArg::none()
            })
            .unwrap();
        assert_eq!(
            main_perms.0.inner.lock().clone(),
            worker_perms.inner.lock().clone()
        );
        assert_eq!(
            main_perms.0.inner.lock().run.granted_list,
            HashSet::from([
                AllowRunDescriptor(PathBuf::from("/bar")),
                AllowRunDescriptor(PathBuf::from("/foo")),
            ])
        );
    }

    #[test]
    fn test_create_child_permissions_with_inherited_denied_list() {
        let _locked = TESTMUTEX.lock();
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        let parser = TestPermissionDescriptorParser;
        let main_perms = Permissions::from_options(
            &parser,
            &PermissionsOptions {
                prompt: true,
                ..Default::default()
            },
        )
        .unwrap();
        let main_perms = PermissionsContainer::new(Arc::new(parser.clone()), main_perms);
        set_prompter(Box::new(TestPrompter));
        prompt_value.set(false);
        assert!(main_perms
            .0
            .inner
            .lock()
            .write
            .check(&parser.parse_path_query("foo").unwrap().into_write(), None)
            .is_err());
        let worker_perms = main_perms
            .create_child_permissions(ChildPermissionsArg::none())
            .unwrap();
        assert_eq!(
            worker_perms.inner.lock().write.flag_denied_list.clone(),
            main_perms.0.inner.lock().write.flag_denied_list
        );
    }

    #[test]
    fn test_host_parse() {
        let hosts = &[
            ("deno.land", Some(Host::Fqdn(fqdn!("deno.land")))),
            ("DENO.land", Some(Host::Fqdn(fqdn!("deno.land")))),
            ("deno.land.", Some(Host::Fqdn(fqdn!("deno.land")))),
            (
                "1.1.1.1",
                Some(Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))),
            ),
            (
                "::1",
                Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))),
            ),
            (
                "[::1]",
                Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))),
            ),
            ("[::1", None),
            ("::1]", None),
            ("deno. land", None),
            ("1. 1.1.1", None),
            ("1.1.1.1.", None),
            ("1::1.", None),
            ("deno.land.", Some(Host::Fqdn(fqdn!("deno.land")))),
            (".deno.land", None),
            (
                "::ffff:1.1.1.1",
                Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
                    0, 0, 0, 0, 0, 0xffff, 0x0101, 0x0101,
                )))),
            ),
        ];

        for (host_str, expected) in hosts {
            assert_eq!(Host::parse(host_str).ok(), *expected, "{host_str}");
        }
    }

    #[test]
    fn test_net_descriptor_parse() {
        let cases = &[
            (
                "deno.land",
                Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), None)),
            ),
            (
                "DENO.land",
                Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), None)),
            ),
            (
                "deno.land:8000",
                Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), Some(8000))),
            ),
            ("deno.land:", None),
            ("deno.land:a", None),
            ("deno. land:a", None),
            ("deno.land.: a", None),
            (
                "1.1.1.1",
                Some(NetDescriptor(
                    Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                    None,
                )),
            ),
            ("1.1.1.1.", None),
            ("1.1.1.1..", None),
            (
                "1.1.1.1:8000",
                Some(NetDescriptor(
                    Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                    Some(8000),
                )),
            ),
            ("::", None),
            (":::80", None),
            ("::80", None),
            (
                "[::]",
                Some(NetDescriptor(
                    Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))),
                    None,
                )),
            ),
            ("[::1", None),
            ("::1]", None),
            ("::1]", None),
            ("[::1]:", None),
            ("[::1]:a", None),
            (
                "[::1]:443",
                Some(NetDescriptor(
                    Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
                    Some(443),
                )),
            ),
            ("", None),
            ("deno.land..", None),
        ];

        for (input, expected) in cases {
            assert_eq!(NetDescriptor::parse(input).ok(), *expected, "'{input}'");
        }
    }

    #[test]
    fn test_denies_run_name() {
        let cases = [
            #[cfg(windows)]
            ("deno", "C:\\deno.exe", true),
            #[cfg(windows)]
            ("deno", "C:\\sub\\deno.cmd", true),
            #[cfg(windows)]
            ("deno", "C:\\sub\\DeNO.cmd", true),
            #[cfg(windows)]
            ("DEno", "C:\\sub\\deno.cmd", true),
            #[cfg(windows)]
            ("deno", "C:\\other\\sub\\deno.batch", true),
            #[cfg(windows)]
            ("deno", "C:\\other\\sub\\deno", true),
            #[cfg(windows)]
            ("denort", "C:\\other\\sub\\deno.exe", false),
            ("deno", "/home/test/deno", true),
            ("deno", "/home/test/denot", false),
        ];
        for (name, cmd_path, denies) in cases {
            assert_eq!(
                denies_run_name(name, &PathBuf::from(cmd_path)),
                denies,
                "{} {}",
                name,
                cmd_path
            );
        }
    }
}
