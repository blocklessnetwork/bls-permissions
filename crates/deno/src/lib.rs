// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.

use deno_core::serde::de;
use deno_core::serde::Deserialize;
use deno_core::serde::Deserializer;
use deno_core::serde_json;
use deno_core::unsync::sync::AtomicFlag;
use deno_terminal::colors;

use std::fmt;
use std::fmt::Debug;
use std::path::Path;

pub mod prompter;
pub use prompter::set_prompt_callbacks;
pub use prompter::PromptCallback;

pub use bls_permissions::*;


#[derive(Clone, Debug)]
pub struct PermissionsContainer(bls_permissions::BlsPermissionsContainer);

impl PermissionsContainer {
    pub fn new(perms: Permissions) -> Self {
        init_debug_log_msg_func(|msg: &str| format!("{}", colors::bold(msg)));
        Self(BlsPermissionsContainer::new(perms))
    }

    #[inline(always)]
    pub fn allow_hrtime(&mut self) -> bool {
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
    pub fn check_read(&mut self, path: &Path, api_name: &str) -> Result<(), AnyError> {
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
        &mut self,
        path: &Path,
        display: &str,
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_read_blind(path, display, api_name)
    }

    #[inline(always)]
    pub fn check_read_all(&mut self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_read_all(api_name)
    }

    #[inline(always)]
    pub fn check_write(&mut self, path: &Path, api_name: &str) -> Result<(), AnyError> {
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
    pub fn check_write_all(&mut self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_write_all(api_name)
    }

    #[inline(always)]
    pub fn check_write_blind(
        &mut self,
        path: &Path,
        display: &str,
        api_name: &str,
    ) -> Result<(), AnyError> {
        self.0.check_write_blind(path, display, api_name)
    }

    #[inline(always)]
    pub fn check_write_partial(&mut self, path: &Path, api_name: &str) -> Result<(), AnyError> {
        self.0.check_write_partial(path, api_name)
    }

    #[inline(always)]
    pub fn check_run(&mut self, cmd: &str, api_name: &str) -> Result<(), AnyError> {
        self.0.check_run(cmd, api_name)
    }

    #[inline(always)]
    pub fn check_run_all(&mut self, api_name: &str) -> Result<(), AnyError> {
        self.0.check_run_all(api_name)
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
    pub fn check_ffi(&mut self, path: Option<&Path>) -> Result<(), AnyError> {
        self.0.check_ffi(path)
    }

    #[inline(always)]
    pub fn check_ffi_partial(&mut self, path: Option<&Path>) -> Result<(), AnyError> {
        self.0.check_ffi_partial(path)
    }
}


/// Directly deserializable from JS worker and test permission options.
#[derive(Debug, Eq, PartialEq)]
pub struct ChildPermissionsArg {
    env: ChildUnaryPermissionArg,
    hrtime: ChildUnitPermissionArg,
    net: ChildUnaryPermissionArg,
    ffi: ChildUnaryPermissionArg,
    read: ChildUnaryPermissionArg,
    run: ChildUnaryPermissionArg,
    sys: ChildUnaryPermissionArg,
    write: ChildUnaryPermissionArg,
}

impl ChildPermissionsArg {
    pub fn inherit() -> Self {
        ChildPermissionsArg {
            env: ChildUnaryPermissionArg::Inherit,
            hrtime: ChildUnitPermissionArg::Inherit,
            net: ChildUnaryPermissionArg::Inherit,
            ffi: ChildUnaryPermissionArg::Inherit,
            read: ChildUnaryPermissionArg::Inherit,
            run: ChildUnaryPermissionArg::Inherit,
            sys: ChildUnaryPermissionArg::Inherit,
            write: ChildUnaryPermissionArg::Inherit,
        }
    }

    pub fn none() -> Self {
        ChildPermissionsArg {
            env: ChildUnaryPermissionArg::NotGranted,
            hrtime: ChildUnitPermissionArg::NotGranted,
            net: ChildUnaryPermissionArg::NotGranted,
            ffi: ChildUnaryPermissionArg::NotGranted,
            read: ChildUnaryPermissionArg::NotGranted,
            run: ChildUnaryPermissionArg::NotGranted,
            sys: ChildUnaryPermissionArg::NotGranted,
            write: ChildUnaryPermissionArg::NotGranted,
        }
    }
}

impl<'de> Deserialize<'de> for ChildPermissionsArg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ChildPermissionsArgVisitor;
        impl<'de> de::Visitor<'de> for ChildPermissionsArgVisitor {
            type Value = ChildPermissionsArg;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("\"inherit\" or \"none\" or object")
            }

            fn visit_unit<E>(self) -> Result<ChildPermissionsArg, E>
            where
                E: de::Error,
            {
                Ok(ChildPermissionsArg::inherit())
            }

            fn visit_str<E>(self, v: &str) -> Result<ChildPermissionsArg, E>
            where
                E: de::Error,
            {
                if v == "inherit" {
                    Ok(ChildPermissionsArg::inherit())
                } else if v == "none" {
                    Ok(ChildPermissionsArg::none())
                } else {
                    Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
                }
            }

            fn visit_map<V>(self, mut v: V) -> Result<ChildPermissionsArg, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut child_permissions_arg = ChildPermissionsArg::none();
                while let Some((key, value)) = v.next_entry::<String, serde_json::Value>()? {
                    if key == "env" {
                        let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
                        child_permissions_arg.env = arg.map_err(|e| {
                            de::Error::custom(format!("(deno.permissions.env) {e}"))
                        })?;
                    } else if key == "hrtime" {
                        let arg = serde_json::from_value::<ChildUnitPermissionArg>(value);
                        child_permissions_arg.hrtime = arg.map_err(|e| {
                            de::Error::custom(format!("(deno.permissions.hrtime) {e}"))
                        })?;
                    } else if key == "net" {
                        let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
                        child_permissions_arg.net = arg.map_err(|e| {
                            de::Error::custom(format!("(deno.permissions.net) {e}"))
                        })?;
                    } else if key == "ffi" {
                        let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
                        child_permissions_arg.ffi = arg.map_err(|e| {
                            de::Error::custom(format!("(deno.permissions.ffi) {e}"))
                        })?;
                    } else if key == "read" {
                        let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
                        child_permissions_arg.read = arg.map_err(|e| {
                            de::Error::custom(format!("(deno.permissions.read) {e}"))
                        })?;
                    } else if key == "run" {
                        let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
                        child_permissions_arg.run = arg.map_err(|e| {
                            de::Error::custom(format!("(deno.permissions.run) {e}"))
                        })?;
                    } else if key == "sys" {
                        let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
                        child_permissions_arg.sys = arg.map_err(|e| {
                            de::Error::custom(format!("(deno.permissions.sys) {e}"))
                        })?;
                    } else if key == "write" {
                        let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
                        child_permissions_arg.write = arg.map_err(|e| {
                            de::Error::custom(format!("(deno.permissions.write) {e}"))
                        })?;
                    } else {
                        return Err(de::Error::custom("unknown permission name"));
                    }
                }
                Ok(child_permissions_arg)
            }
        }
        deserializer.deserialize_any(ChildPermissionsArgVisitor)
    }
}

pub fn create_child_permissions(
    main_perms: &mut Permissions,
    child_permissions_arg: ChildPermissionsArg,
) -> Result<Permissions, AnyError> {
    fn is_granted_unary(arg: &ChildUnaryPermissionArg) -> bool {
        match arg {
            ChildUnaryPermissionArg::Inherit | ChildUnaryPermissionArg::Granted => true,
            ChildUnaryPermissionArg::NotGranted | ChildUnaryPermissionArg::GrantedList(_) => false,
        }
    }

    fn is_granted_unit(arg: &ChildUnitPermissionArg) -> bool {
        match arg {
            ChildUnitPermissionArg::Inherit | ChildUnitPermissionArg::Granted => true,
            ChildUnitPermissionArg::NotGranted => false,
        }
    }

    let mut worker_perms = Permissions::none_without_prompt();

    worker_perms.all = main_perms
        .all
        .create_child_permissions(ChildUnitPermissionArg::Inherit)?;

    // downgrade the `worker_perms.all` based on the other values
    if worker_perms.all.query() == PermissionState::Granted {
        let unary_perms = [
            &child_permissions_arg.read,
            &child_permissions_arg.write,
            &child_permissions_arg.net,
            &child_permissions_arg.env,
            &child_permissions_arg.sys,
            &child_permissions_arg.run,
            &child_permissions_arg.ffi,
        ];
        let unit_perms = [&child_permissions_arg.hrtime];
        let allow_all = unary_perms.into_iter().all(is_granted_unary)
            && unit_perms.into_iter().all(is_granted_unit);
        if !allow_all {
            worker_perms.all.revoke();
        }
    }

    // WARNING: When adding a permission here, ensure it is handled
    // in the worker_perms.all block above
    worker_perms.read = main_perms
        .read
        .create_child_permissions(child_permissions_arg.read)?;
    worker_perms.write = main_perms
        .write
        .create_child_permissions(child_permissions_arg.write)?;
    worker_perms.net = main_perms
        .net
        .create_child_permissions(child_permissions_arg.net)?;
    worker_perms.env = main_perms
        .env
        .create_child_permissions(child_permissions_arg.env)?;
    worker_perms.sys = main_perms
        .sys
        .create_child_permissions(child_permissions_arg.sys)?;
    worker_perms.run = main_perms
        .run
        .create_child_permissions(child_permissions_arg.run)?;
    worker_perms.ffi = main_perms
        .ffi
        .create_child_permissions(child_permissions_arg.ffi)?;
    worker_perms.hrtime = main_perms
        .hrtime
        .create_child_permissions(child_permissions_arg.hrtime)?;

    Ok(worker_perms)
}

static IS_STANDALONE: AtomicFlag = AtomicFlag::lowered();

pub fn mark_standalone() {
    IS_STANDALONE.raise();
}

pub fn is_standalone() -> bool {
    IS_STANDALONE.is_raised()
}

#[cfg(test)]
mod tests {
    use super::*;
    use deno_core::serde_json::json;
    use fqdn::fqdn;
    use prompter::tests::*;
    use std::net::Ipv4Addr;
    use deno_core::url;
    use std::net::IpAddr;
    use std::net::Ipv6Addr;
    use std::path::PathBuf;
    use std::collections::HashSet;
    use std::string::ToString;

    // Creates vector of strings, Vec<String>
    macro_rules! svec {
      ($($x:expr),*) => (vec![$($x.to_string()),*]);
  }

    #[test]
    fn check_paths() {
        set_prompter(Box::new(TestPrompter));
        let allowlist = vec![
            PathBuf::from("/a/specific/dir/name"),
            PathBuf::from("/a/specific"),
            PathBuf::from("/b/c"),
        ];

        let mut perms = Permissions::from_options(&PermissionsOptions {
            allow_read: Some(allowlist.clone()),
            allow_write: Some(allowlist.clone()),
            allow_ffi: Some(allowlist),
            ..Default::default()
        })
        .unwrap();

        // Inside of /a/specific and /a/specific/dir/name
        assert!(perms
            .read
            .check(Path::new("/a/specific/dir/name"), None)
            .is_ok());
        assert!(perms
            .write
            .check(Path::new("/a/specific/dir/name"), None)
            .is_ok());
        assert!(perms
            .ffi
            .check(Path::new("/a/specific/dir/name"), None)
            .is_ok());

        // Inside of /a/specific but outside of /a/specific/dir/name
        assert!(perms.read.check(Path::new("/a/specific/dir"), None).is_ok());
        assert!(perms
            .write
            .check(Path::new("/a/specific/dir"), None)
            .is_ok());
        assert!(perms.ffi.check(Path::new("/a/specific/dir"), None).is_ok());

        // Inside of /a/specific and /a/specific/dir/name
        assert!(perms
            .read
            .check(Path::new("/a/specific/dir/name/inner"), None)
            .is_ok());
        assert!(perms
            .write
            .check(Path::new("/a/specific/dir/name/inner"), None)
            .is_ok());
        assert!(perms
            .ffi
            .check(Path::new("/a/specific/dir/name/inner"), None)
            .is_ok());

        // Inside of /a/specific but outside of /a/specific/dir/name
        assert!(perms
            .read
            .check(Path::new("/a/specific/other/dir"), None)
            .is_ok());
        assert!(perms
            .write
            .check(Path::new("/a/specific/other/dir"), None)
            .is_ok());
        assert!(perms
            .ffi
            .check(Path::new("/a/specific/other/dir"), None)
            .is_ok());

        // Exact match with /b/c
        assert!(perms.read.check(Path::new("/b/c"), None).is_ok());
        assert!(perms.write.check(Path::new("/b/c"), None).is_ok());
        assert!(perms.ffi.check(Path::new("/b/c"), None).is_ok());

        // Sub path within /b/c
        assert!(perms.read.check(Path::new("/b/c/sub/path"), None).is_ok());
        assert!(perms.write.check(Path::new("/b/c/sub/path"), None).is_ok());
        assert!(perms.ffi.check(Path::new("/b/c/sub/path"), None).is_ok());

        // Sub path within /b/c, needs normalizing
        assert!(perms
            .read
            .check(Path::new("/b/c/sub/path/../path/."), None)
            .is_ok());
        assert!(perms
            .write
            .check(Path::new("/b/c/sub/path/../path/."), None)
            .is_ok());
        assert!(perms
            .ffi
            .check(Path::new("/b/c/sub/path/../path/."), None)
            .is_ok());

        // Inside of /b but outside of /b/c
        assert!(perms.read.check(Path::new("/b/e"), None).is_err());
        assert!(perms.write.check(Path::new("/b/e"), None).is_err());
        assert!(perms.ffi.check(Path::new("/b/e"), None).is_err());

        // Inside of /a but outside of /a/specific
        assert!(perms.read.check(Path::new("/a/b"), None).is_err());
        assert!(perms.write.check(Path::new("/a/b"), None).is_err());
        assert!(perms.ffi.check(Path::new("/a/b"), None).is_err());
    }

    #[test]
    fn test_check_net_with_values() {
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions::from_options(&PermissionsOptions {
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
        })
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
            let host = host.parse().unwrap();
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
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions::from_options(&PermissionsOptions {
            allow_net: Some(svec![]), // this means `--allow-net` is present without values following `=` sign
            ..Default::default()
        })
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
            let host = host_str.parse().unwrap();
            let descriptor = NetDescriptor(host, Some(port));
            assert!(
                perms.net.check(&descriptor, None).is_ok(),
                "expected {host_str}:{port} to pass"
            );
        }
    }

    #[test]
    fn test_check_net_no_flag() {
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions::from_options(&PermissionsOptions {
            allow_net: None,
            ..Default::default()
        })
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
            let host = host_str.parse().unwrap();
            let descriptor = NetDescriptor(host, Some(port));
            assert!(
                perms.net.check(&descriptor, None).is_err(),
                "expected {host_str}:{port} to fail"
            );
        }
    }

    #[test]
    fn test_check_net_url() {
        let mut perms = Permissions::from_options(&PermissionsOptions {
            allow_net: Some(svec![
                "localhost",
                "deno.land",
                "github.com:3000",
                "127.0.0.1",
                "172.16.0.2:8000",
                "www.github.com:443"
            ]),
            ..Default::default()
        })
        .unwrap();

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
            let u = url::Url::parse(url_str).unwrap();
            assert_eq!(is_ok, perms.net.check_url(&u, None).is_ok(), "{}", u);
        }
    }

    #[test]
    fn check_specifiers() {
        set_prompter(Box::new(TestPrompter));
        let read_allowlist = if cfg!(target_os = "windows") {
            vec![PathBuf::from("C:\\a")]
        } else {
            vec![PathBuf::from("/a")]
        };
        let mut perms = Permissions::from_options(&PermissionsOptions {
            allow_read: Some(read_allowlist),
            allow_net: Some(svec!["localhost"]),
            ..Default::default()
        })
        .unwrap();

        let mut fixtures = vec![
            (
                ModuleSpecifier::parse("http://localhost:4545/mod.ts").unwrap(),
                true,
            ),
            (
                ModuleSpecifier::parse("http://deno.land/x/mod.ts").unwrap(),
                false,
            ),
            (
                ModuleSpecifier::parse("data:text/plain,Hello%2C%20Deno!").unwrap(),
                true,
            ),
        ];

        if cfg!(target_os = "windows") {
            fixtures.push((ModuleSpecifier::parse("file:///C:/a/mod.ts").unwrap(), true));
            fixtures.push((
                ModuleSpecifier::parse("file:///C:/b/mod.ts").unwrap(),
                false,
            ));
        } else {
            fixtures.push((ModuleSpecifier::parse("file:///a/mod.ts").unwrap(), true));
            fixtures.push((ModuleSpecifier::parse("file:///b/mod.ts").unwrap(), false));
        }

        for (specifier, expected) in fixtures {
            assert_eq!(
                perms.check_specifier(&specifier).is_ok(),
                expected,
                "{}",
                specifier,
            );
        }
    }

    #[test]
    fn check_invalid_specifiers() {
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions::allow_all();

        let mut test_cases = vec![];

        if cfg!(target_os = "windows") {
            test_cases.push("file://");
            test_cases.push("file:///");
        } else {
            test_cases.push("file://remotehost/");
        }

        for url in test_cases {
            assert!(perms
                .check_specifier(&ModuleSpecifier::parse(url).unwrap())
                .is_err());
        }
    }

    #[test]
    fn test_query() {
        set_prompter(Box::new(TestPrompter));
        let perms1 = Permissions::allow_all();
        let perms2 = Permissions {
            read: Permissions::new_unary(&Some(vec![PathBuf::from("/foo")]), &None, false).unwrap(),
            write: Permissions::new_unary(&Some(vec![PathBuf::from("/foo")]), &None, false)
                .unwrap(),
            ffi: Permissions::new_unary(&Some(vec![PathBuf::from("/foo")]), &None, false).unwrap(),
            net: Permissions::new_unary(&Some(svec!["127.0.0.1:8000"]), &None, false).unwrap(),
            env: Permissions::new_unary(&Some(svec!["HOME"]), &None, false).unwrap(),
            sys: Permissions::new_unary(&Some(svec!["hostname"]), &None, false).unwrap(),
            run: Permissions::new_unary(&Some(svec!["deno"]), &None, false).unwrap(),
            all: Permissions::new_all(false),
            hrtime: Permissions::new_hrtime(false, false),
        };
        let perms3 = Permissions {
            read: Permissions::new_unary(&None, &Some(vec![PathBuf::from("/foo")]), false).unwrap(),
            write: Permissions::new_unary(&None, &Some(vec![PathBuf::from("/foo")]), false)
                .unwrap(),
            ffi: Permissions::new_unary(&None, &Some(vec![PathBuf::from("/foo")]), false).unwrap(),
            net: Permissions::new_unary(&None, &Some(svec!["127.0.0.1:8000"]), false).unwrap(),
            env: Permissions::new_unary(&None, &Some(svec!["HOME"]), false).unwrap(),
            sys: Permissions::new_unary(&None, &Some(svec!["hostname"]), false).unwrap(),
            run: Permissions::new_unary(&None, &Some(svec!["deno"]), false).unwrap(),
            all: Permissions::new_all(false),
            hrtime: Permissions::new_hrtime(false, true),
        };
        let perms4 = Permissions {
            read: Permissions::new_unary(&Some(vec![]), &Some(vec![PathBuf::from("/foo")]), false)
                .unwrap(),
            write: Permissions::new_unary(&Some(vec![]), &Some(vec![PathBuf::from("/foo")]), false)
                .unwrap(),
            ffi: Permissions::new_unary(&Some(vec![]), &Some(vec![PathBuf::from("/foo")]), false)
                .unwrap(),
            net: Permissions::new_unary(&Some(vec![]), &Some(svec!["127.0.0.1:8000"]), false)
                .unwrap(),
            env: Permissions::new_unary(&Some(vec![]), &Some(svec!["HOME"]), false).unwrap(),
            sys: Permissions::new_unary(&Some(vec![]), &Some(svec!["hostname"]), false).unwrap(),
            run: Permissions::new_unary(&Some(vec![]), &Some(svec!["deno"]), false).unwrap(),
            all: Permissions::new_all(false),
            hrtime: Permissions::new_hrtime(true, true),
        };
        #[rustfmt::skip]
    {
      assert_eq!(perms1.read.query(None), PermissionState::Granted);
      assert_eq!(perms1.read.query(Some(Path::new("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.read.query(None), PermissionState::Prompt);
      assert_eq!(perms2.read.query(Some(Path::new("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.read.query(Some(Path::new("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms3.read.query(None), PermissionState::Prompt);
      assert_eq!(perms3.read.query(Some(Path::new("/foo"))), PermissionState::Denied);
      assert_eq!(perms3.read.query(Some(Path::new("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.read.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.read.query(Some(Path::new("/foo"))), PermissionState::Denied);
      assert_eq!(perms4.read.query(Some(Path::new("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.read.query(Some(Path::new("/bar"))), PermissionState::Granted);
      assert_eq!(perms1.write.query(None), PermissionState::Granted);
      assert_eq!(perms1.write.query(Some(Path::new("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.write.query(None), PermissionState::Prompt);
      assert_eq!(perms2.write.query(Some(Path::new("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.write.query(Some(Path::new("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms3.write.query(None), PermissionState::Prompt);
      assert_eq!(perms3.write.query(Some(Path::new("/foo"))), PermissionState::Denied);
      assert_eq!(perms3.write.query(Some(Path::new("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.write.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.write.query(Some(Path::new("/foo"))), PermissionState::Denied);
      assert_eq!(perms4.write.query(Some(Path::new("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.write.query(Some(Path::new("/bar"))), PermissionState::Granted);
      assert_eq!(perms1.ffi.query(None), PermissionState::Granted);
      assert_eq!(perms1.ffi.query(Some(Path::new("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.ffi.query(None), PermissionState::Prompt);
      assert_eq!(perms2.ffi.query(Some(Path::new("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.ffi.query(Some(Path::new("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms3.ffi.query(None), PermissionState::Prompt);
      assert_eq!(perms3.ffi.query(Some(Path::new("/foo"))), PermissionState::Denied);
      assert_eq!(perms3.ffi.query(Some(Path::new("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.ffi.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.ffi.query(Some(Path::new("/foo"))), PermissionState::Denied);
      assert_eq!(perms4.ffi.query(Some(Path::new("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.ffi.query(Some(Path::new("/bar"))), PermissionState::Granted);
      assert_eq!(perms1.net.query(None), PermissionState::Granted);
      assert_eq!(perms1.net.query(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), None))), PermissionState::Granted);
      assert_eq!(perms2.net.query(None), PermissionState::Prompt);
      assert_eq!(perms2.net.query(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)))), PermissionState::Granted);
      assert_eq!(perms3.net.query(None), PermissionState::Prompt);
      assert_eq!(perms3.net.query(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)))), PermissionState::Denied);
      assert_eq!(perms4.net.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.net.query(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)))), PermissionState::Denied);
      assert_eq!(perms4.net.query(Some(&NetDescriptor("192.168.0.1".parse().unwrap(), Some(8000)))), PermissionState::Granted);
      assert_eq!(perms1.env.query(None), PermissionState::Granted);
      assert_eq!(perms1.env.query(Some("HOME")), PermissionState::Granted);
      assert_eq!(perms2.env.query(None), PermissionState::Prompt);
      assert_eq!(perms2.env.query(Some("HOME")), PermissionState::Granted);
      assert_eq!(perms3.env.query(None), PermissionState::Prompt);
      assert_eq!(perms3.env.query(Some("HOME")), PermissionState::Denied);
      assert_eq!(perms4.env.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.env.query(Some("HOME")), PermissionState::Denied);
      assert_eq!(perms4.env.query(Some("AWAY")), PermissionState::Granted);
      assert_eq!(perms1.sys.query(None), PermissionState::Granted);
      assert_eq!(perms1.sys.query(Some("HOME")), PermissionState::Granted);
      assert_eq!(perms2.sys.query(None), PermissionState::Prompt);
      assert_eq!(perms2.sys.query(Some("hostname")), PermissionState::Granted);
      assert_eq!(perms3.sys.query(None), PermissionState::Prompt);
      assert_eq!(perms3.sys.query(Some("hostname")), PermissionState::Denied);
      assert_eq!(perms4.sys.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.sys.query(Some("hostname")), PermissionState::Denied);
      assert_eq!(perms4.sys.query(Some("uid")), PermissionState::Granted);
      assert_eq!(perms1.run.query(None), PermissionState::Granted);
      assert_eq!(perms1.run.query(Some("deno")), PermissionState::Granted);
      assert_eq!(perms2.run.query(None), PermissionState::Prompt);
      assert_eq!(perms2.run.query(Some("deno")), PermissionState::Granted);
      assert_eq!(perms3.run.query(None), PermissionState::Prompt);
      assert_eq!(perms3.run.query(Some("deno")), PermissionState::Denied);
      assert_eq!(perms4.run.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.run.query(Some("deno")), PermissionState::Denied);
      assert_eq!(perms4.run.query(Some("node")), PermissionState::Granted);
      assert_eq!(perms1.hrtime.query(), PermissionState::Granted);
      assert_eq!(perms2.hrtime.query(), PermissionState::Prompt);
      assert_eq!(perms3.hrtime.query(), PermissionState::Denied);
      assert_eq!(perms4.hrtime.query(), PermissionState::Denied);
    };
    }

    #[test]
    fn test_request() {
        set_prompter(Box::new(TestPrompter));
        let mut perms: Permissions = Permissions::none_without_prompt();
        #[rustfmt::skip]
    {
      let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
      prompt_value.set(true);
      assert_eq!(perms.read.request(Some(Path::new("/foo"))), PermissionState::Granted);
      assert_eq!(perms.read.query(None), PermissionState::Prompt);
      prompt_value.set(false);
      assert_eq!(perms.read.request(Some(Path::new("/foo/bar"))), PermissionState::Granted);
      prompt_value.set(false);
      assert_eq!(perms.write.request(Some(Path::new("/foo"))), PermissionState::Denied);
      assert_eq!(perms.write.query(Some(Path::new("/foo/bar"))), PermissionState::Prompt);
      prompt_value.set(true);
      assert_eq!(perms.write.request(None), PermissionState::Denied);
      prompt_value.set(false);
      assert_eq!(perms.ffi.request(Some(Path::new("/foo"))), PermissionState::Denied);
      assert_eq!(perms.ffi.query(Some(Path::new("/foo/bar"))), PermissionState::Prompt);
      prompt_value.set(true);
      assert_eq!(perms.ffi.request(None), PermissionState::Denied);
      prompt_value.set(true);
      assert_eq!(perms.net.request(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), None))), PermissionState::Granted);
      prompt_value.set(false);
      assert_eq!(perms.net.request(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)))), PermissionState::Granted);
      prompt_value.set(true);
      assert_eq!(perms.env.request(Some("HOME")), PermissionState::Granted);
      assert_eq!(perms.env.query(None), PermissionState::Prompt);
      prompt_value.set(false);
      assert_eq!(perms.env.request(Some("HOME")), PermissionState::Granted);
      prompt_value.set(true);
      assert_eq!(perms.sys.request(Some("hostname")), PermissionState::Granted);
      assert_eq!(perms.sys.query(None), PermissionState::Prompt);
      prompt_value.set(false);
      assert_eq!(perms.sys.request(Some("hostname")), PermissionState::Granted);
      prompt_value.set(true);
      assert_eq!(perms.run.request(Some("deno")), PermissionState::Granted);
      assert_eq!(perms.run.query(None), PermissionState::Prompt);
      prompt_value.set(false);
      assert_eq!(perms.run.request(Some("deno")), PermissionState::Granted);
      prompt_value.set(false);
      assert_eq!(perms.hrtime.request(), PermissionState::Denied);
      prompt_value.set(true);
      assert_eq!(perms.hrtime.request(), PermissionState::Denied);
    };
    }

    #[test]
    fn test_revoke() {
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions {
            read: Permissions::new_unary(
                &Some(vec![PathBuf::from("/foo"), PathBuf::from("/foo/baz")]),
                &None,
                false,
            )
            .unwrap(),
            write: Permissions::new_unary(
                &Some(vec![PathBuf::from("/foo"), PathBuf::from("/foo/baz")]),
                &None,
                false,
            )
            .unwrap(),
            ffi: Permissions::new_unary(
                &Some(vec![PathBuf::from("/foo"), PathBuf::from("/foo/baz")]),
                &None,
                false,
            )
            .unwrap(),
            net: Permissions::new_unary(&Some(svec!["127.0.0.1", "127.0.0.1:8000"]), &None, false)
                .unwrap(),
            env: Permissions::new_unary(&Some(svec!["HOME"]), &None, false).unwrap(),
            sys: Permissions::new_unary(&Some(svec!["hostname"]), &None, false).unwrap(),
            run: Permissions::new_unary(&Some(svec!["deno"]), &None, false).unwrap(),
            all: Permissions::new_all(false),
            hrtime: Permissions::new_hrtime(false, true),
        };
        #[rustfmt::skip]
    {
      assert_eq!(perms.read.revoke(Some(Path::new("/foo/bar"))), PermissionState::Prompt);
      assert_eq!(perms.read.query(Some(Path::new("/foo"))), PermissionState::Prompt);
      assert_eq!(perms.read.query(Some(Path::new("/foo/baz"))), PermissionState::Granted);
      assert_eq!(perms.write.revoke(Some(Path::new("/foo/bar"))), PermissionState::Prompt);
      assert_eq!(perms.write.query(Some(Path::new("/foo"))), PermissionState::Prompt);
      assert_eq!(perms.write.query(Some(Path::new("/foo/baz"))), PermissionState::Granted);
      assert_eq!(perms.ffi.revoke(Some(Path::new("/foo/bar"))), PermissionState::Prompt);
      assert_eq!(perms.ffi.query(Some(Path::new("/foo"))), PermissionState::Prompt);
      assert_eq!(perms.ffi.query(Some(Path::new("/foo/baz"))), PermissionState::Granted);
      assert_eq!(perms.net.revoke(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), Some(9000)))), PermissionState::Prompt);
      assert_eq!(perms.net.query(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), None))), PermissionState::Prompt);
      assert_eq!(perms.net.query(Some(&NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)))), PermissionState::Granted);
      assert_eq!(perms.env.revoke(Some("HOME")), PermissionState::Prompt);
      assert_eq!(perms.env.revoke(Some("hostname")), PermissionState::Prompt);
      assert_eq!(perms.run.revoke(Some("deno")), PermissionState::Prompt);
      assert_eq!(perms.hrtime.revoke(), PermissionState::Denied);
    };
    }

    #[test]
    fn test_check() {
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions::none_with_prompt();
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();

        prompt_value.set(true);
        assert!(perms.read.check(Path::new("/foo"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.read.check(Path::new("/foo"), None).is_ok());
        assert!(perms.read.check(Path::new("/bar"), None).is_err());

        prompt_value.set(true);
        assert!(perms.write.check(Path::new("/foo"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.write.check(Path::new("/foo"), None).is_ok());
        assert!(perms.write.check(Path::new("/bar"), None).is_err());

        prompt_value.set(true);
        assert!(perms.ffi.check(Path::new("/foo"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.ffi.check(Path::new("/foo"), None).is_ok());
        assert!(perms.ffi.check(Path::new("/bar"), None).is_err());

        prompt_value.set(true);
        assert!(perms
            .net
            .check(
                &NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)),
                None
            )
            .is_ok());
        prompt_value.set(false);
        assert!(perms
            .net
            .check(
                &NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)),
                None
            )
            .is_ok());
        assert!(perms
            .net
            .check(
                &NetDescriptor("127.0.0.1".parse().unwrap(), Some(8001)),
                None
            )
            .is_err());
        assert!(perms
            .net
            .check(&NetDescriptor("127.0.0.1".parse().unwrap(), None), None)
            .is_err());
        assert!(perms
            .net
            .check(
                &NetDescriptor("deno.land".parse().unwrap(), Some(8000)),
                None
            )
            .is_err());
        assert!(perms
            .net
            .check(&NetDescriptor("deno.land".parse().unwrap(), None), None)
            .is_err());

        prompt_value.set(true);
        assert!(perms.run.check("cat", None).is_ok());
        prompt_value.set(false);
        assert!(perms.run.check("cat", None).is_ok());
        assert!(perms.run.check("ls", None).is_err());

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

        assert!(perms.hrtime.check().is_err());
    }

    #[test]
    fn test_check_fail() {
        set_prompter(Box::new(TestPrompter));
        let mut perms = Permissions::none_with_prompt();
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();

        prompt_value.set(false);
        assert!(perms.read.check(Path::new("/foo"), None).is_err());
        prompt_value.set(true);
        assert!(perms.read.check(Path::new("/foo"), None).is_err());
        assert!(perms.read.check(Path::new("/bar"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.read.check(Path::new("/bar"), None).is_ok());

        prompt_value.set(false);
        assert!(perms.write.check(Path::new("/foo"), None).is_err());
        prompt_value.set(true);
        assert!(perms.write.check(Path::new("/foo"), None).is_err());
        assert!(perms.write.check(Path::new("/bar"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.write.check(Path::new("/bar"), None).is_ok());

        prompt_value.set(false);
        assert!(perms.ffi.check(Path::new("/foo"), None).is_err());
        prompt_value.set(true);
        assert!(perms.ffi.check(Path::new("/foo"), None).is_err());
        assert!(perms.ffi.check(Path::new("/bar"), None).is_ok());
        prompt_value.set(false);
        assert!(perms.ffi.check(Path::new("/bar"), None).is_ok());

        prompt_value.set(false);
        assert!(perms
            .net
            .check(
                &NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)),
                None
            )
            .is_err());
        prompt_value.set(true);
        assert!(perms
            .net
            .check(
                &NetDescriptor("127.0.0.1".parse().unwrap(), Some(8000)),
                None
            )
            .is_err());
        assert!(perms
            .net
            .check(
                &NetDescriptor("127.0.0.1".parse().unwrap(), Some(8001)),
                None
            )
            .is_ok());
        assert!(perms
            .net
            .check(
                &NetDescriptor("deno.land".parse().unwrap(), Some(8000)),
                None
            )
            .is_ok());
        prompt_value.set(false);
        assert!(perms
            .net
            .check(
                &NetDescriptor("127.0.0.1".parse().unwrap(), Some(8001)),
                None
            )
            .is_ok());
        assert!(perms
            .net
            .check(
                &NetDescriptor("deno.land".parse().unwrap(), Some(8000)),
                None
            )
            .is_ok());

        prompt_value.set(false);
        assert!(perms.run.check("cat", None).is_err());
        prompt_value.set(true);
        assert!(perms.run.check("cat", None).is_err());
        assert!(perms.run.check("ls", None).is_ok());
        prompt_value.set(false);
        assert!(perms.run.check("ls", None).is_ok());

        prompt_value.set(false);
        assert!(perms.env.check("HOME", None).is_err());
        prompt_value.set(true);
        assert!(perms.env.check("HOME", None).is_err());
        assert!(perms.env.check("PATH", None).is_ok());
        prompt_value.set(false);
        assert!(perms.env.check("PATH", None).is_ok());

        prompt_value.set(false);
        assert!(perms.sys.check("hostname", None).is_err());
        prompt_value.set(true);
        assert!(perms.sys.check("hostname", None).is_err());
        assert!(perms.sys.check("osRelease", None).is_ok());
        prompt_value.set(false);
        assert!(perms.sys.check("osRelease", None).is_ok());

        prompt_value.set(false);
        assert!(perms.hrtime.check().is_err());
        prompt_value.set(true);
        assert!(perms.hrtime.check().is_err());
    }

    #[test]
    #[cfg(windows)]
    fn test_env_windows() {
        set_prompter(Box::new(TestPrompter));
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        let mut perms = Permissions::allow_all();
        perms.env = UnaryPermission {
            granted_global: false,
            ..Permissions::new_unary(&Some(svec!["HOME"]), &None, false).unwrap()
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
        let mut perms = Permissions {
            read: Permissions::new_unary(
                &Some(vec![]),
                &Some(vec![PathBuf::from("/foo/bar")]),
                false,
            )
            .unwrap(),
            write: Permissions::new_unary(
                &Some(vec![]),
                &Some(vec![PathBuf::from("/foo/bar")]),
                false,
            )
            .unwrap(),
            ..Permissions::none_without_prompt()
        };

        perms.read.check_partial(Path::new("/foo"), None).unwrap();
        assert!(perms.read.check(Path::new("/foo"), None).is_err());

        perms.write.check_partial(Path::new("/foo"), None).unwrap();
        assert!(perms.write.check(Path::new("/foo"), None).is_err());
    }

    #[test]
    fn test_net_fully_qualified_domain_name() {
        let mut perms = Permissions {
            net: Permissions::new_unary(
                &Some(vec!["allowed.domain".to_string(), "1.1.1.1".to_string()]),
                &Some(vec!["denied.domain".to_string(), "2.2.2.2".to_string()]),
                false,
            )
            .unwrap(),
            ..Permissions::none_without_prompt()
        };

        perms
            .net
            .check(
                &NetDescriptor("allowed.domain.".parse().unwrap(), None),
                None,
            )
            .unwrap();
        perms
            .net
            .check(&NetDescriptor("1.1.1.1".parse().unwrap(), None), None)
            .unwrap();
        assert!(perms
            .net
            .check(
                &NetDescriptor("denied.domain.".parse().unwrap(), None),
                None
            )
            .is_err());
        assert!(perms
            .net
            .check(&NetDescriptor("2.2.2.2".parse().unwrap(), None), None)
            .is_err());
    }

    #[test]
    fn test_deserialize_child_permissions_arg() {
        set_prompter(Box::new(TestPrompter));
        assert_eq!(
            ChildPermissionsArg::inherit(),
            ChildPermissionsArg {
                env: ChildUnaryPermissionArg::Inherit,
                hrtime: ChildUnitPermissionArg::Inherit,
                net: ChildUnaryPermissionArg::Inherit,
                ffi: ChildUnaryPermissionArg::Inherit,
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
                hrtime: ChildUnitPermissionArg::NotGranted,
                net: ChildUnaryPermissionArg::NotGranted,
                ffi: ChildUnaryPermissionArg::NotGranted,
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
              "hrtime": true,
            }))
            .unwrap(),
            ChildPermissionsArg {
                hrtime: ChildUnitPermissionArg::Granted,
                ..ChildPermissionsArg::none()
            }
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({
              "hrtime": false,
            }))
            .unwrap(),
            ChildPermissionsArg {
                hrtime: ChildUnitPermissionArg::NotGranted,
                ..ChildPermissionsArg::none()
            }
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({
              "env": true,
              "net": true,
              "ffi": true,
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
                read: ChildUnaryPermissionArg::Granted,
                run: ChildUnaryPermissionArg::Granted,
                sys: ChildUnaryPermissionArg::Granted,
                write: ChildUnaryPermissionArg::Granted,
                ..ChildPermissionsArg::none()
            }
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({
              "env": false,
              "net": false,
              "ffi": false,
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
                read: ChildUnaryPermissionArg::NotGranted,
                run: ChildUnaryPermissionArg::NotGranted,
                sys: ChildUnaryPermissionArg::NotGranted,
                write: ChildUnaryPermissionArg::NotGranted,
                ..ChildPermissionsArg::none()
            }
        );
        assert_eq!(
            serde_json::from_value::<ChildPermissionsArg>(json!({
              "env": ["foo", "bar"],
              "net": ["foo", "bar:8000"],
              "ffi": ["foo", "file:///bar/baz"],
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
                read: ChildUnaryPermissionArg::GrantedList(svec!["foo", "file:///bar/baz"]),
                run: ChildUnaryPermissionArg::GrantedList(svec!["foo", "file:///bar/baz", "./qux"]),
                sys: ChildUnaryPermissionArg::GrantedList(svec!["hostname", "osRelease"]),
                write: ChildUnaryPermissionArg::GrantedList(svec!["foo", "file:///bar/baz"]),
                ..ChildPermissionsArg::none()
            }
        );
    }

    #[test]
    fn test_create_child_permissions() {
        set_prompter(Box::new(TestPrompter));
        let mut main_perms = Permissions {
            env: Permissions::new_unary(&Some(vec![]), &None, false).unwrap(),
            hrtime: Permissions::new_hrtime(true, false),
            net: Permissions::new_unary(&Some(svec!["foo", "bar"]), &None, false).unwrap(),
            ..Permissions::none_without_prompt()
        };
        assert_eq!(
            create_child_permissions(
                &mut main_perms.clone(),
                ChildPermissionsArg {
                    env: ChildUnaryPermissionArg::Inherit,
                    hrtime: ChildUnitPermissionArg::NotGranted,
                    net: ChildUnaryPermissionArg::GrantedList(svec!["foo"]),
                    ffi: ChildUnaryPermissionArg::NotGranted,
                    ..ChildPermissionsArg::none()
                }
            )
            .unwrap(),
            Permissions {
                env: Permissions::new_unary(&Some(vec![]), &None, false).unwrap(),
                net: Permissions::new_unary(&Some(svec!["foo"]), &None, false).unwrap(),
                ..Permissions::none_without_prompt()
            }
        );
        assert!(create_child_permissions(
            &mut main_perms.clone(),
            ChildPermissionsArg {
                net: ChildUnaryPermissionArg::Granted,
                ..ChildPermissionsArg::none()
            }
        )
        .is_err());
        assert!(create_child_permissions(
            &mut main_perms.clone(),
            ChildPermissionsArg {
                net: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar", "baz"]),
                ..ChildPermissionsArg::none()
            }
        )
        .is_err());
        assert!(create_child_permissions(
            &mut main_perms,
            ChildPermissionsArg {
                ffi: ChildUnaryPermissionArg::GrantedList(svec!["foo"]),
                ..ChildPermissionsArg::none()
            }
        )
        .is_err());
    }

    #[test]
    fn test_create_child_permissions_with_prompt() {
        set_prompter(Box::new(TestPrompter));
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        let mut main_perms = Permissions::from_options(&PermissionsOptions {
            prompt: true,
            ..Default::default()
        })
        .unwrap();
        prompt_value.set(true);
        let worker_perms = create_child_permissions(
            &mut main_perms,
            ChildPermissionsArg {
                read: ChildUnaryPermissionArg::Granted,
                run: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar"]),
                ..ChildPermissionsArg::none()
            },
        )
        .unwrap();
        assert_eq!(main_perms, worker_perms);
        assert_eq!(
            main_perms.run.granted_list,
            HashSet::from([
                RunDescriptor::Name("bar".to_owned()),
                RunDescriptor::Name("foo".to_owned())
            ])
        );
    }

    #[test]
    fn test_create_child_permissions_with_inherited_denied_list() {
        set_prompter(Box::new(TestPrompter));
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        let mut main_perms = Permissions::from_options(&PermissionsOptions {
            prompt: true,
            ..Default::default()
        })
        .unwrap();
        prompt_value.set(false);
        assert!(main_perms.write.check(&PathBuf::from("foo"), None).is_err());
        let worker_perms =
            create_child_permissions(&mut main_perms.clone(), ChildPermissionsArg::none()).unwrap();
        assert_eq!(
            worker_perms.write.flag_denied_list,
            main_perms.write.flag_denied_list
        );
    }

    #[test]
    fn test_handle_empty_value() {
        set_prompter(Box::new(TestPrompter));

        assert!(Permissions::new_unary::<ReadDescriptor>(
            &Some(vec![Default::default()]),
            &None,
            false
        )
        .is_err());
        assert!(Permissions::new_unary::<EnvDescriptor>(
            &Some(vec![Default::default()]),
            &None,
            false
        )
        .is_err());
        assert!(Permissions::new_unary::<NetDescriptor>(
            &Some(vec![Default::default()]),
            &None,
            false
        )
        .is_err());
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
            assert_eq!(host_str.parse::<Host>().ok(), *expected, "{host_str}");
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
            assert_eq!(input.parse::<NetDescriptor>().ok(), *expected, "'{input}'");
        }
    }
}
