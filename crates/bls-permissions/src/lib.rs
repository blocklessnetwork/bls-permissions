use serde::de;
use std::fmt;
use std::sync::Once;
use url::Url;
use fqdn::FQDN;
use anyhow::Context;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use which::which;

mod error;
use error::custom_error;
use error::type_error;
use error::uri_error;

mod prompter;
pub use prompter::*;
pub use prompter::bls_permission_prompt as permission_prompt;

pub type AnyError = anyhow::Error;

pub type ModuleSpecifier = Url;

/// Quadri-state value for storing permission state
#[derive(Eq, PartialEq, Default, Debug, Clone, Copy, Deserialize, PartialOrd)]
pub enum PermissionState {
    Granted = 0,
    GrantedPartial = 1,
    #[default]
    Prompt = 2,
    Denied = 3,
}

static DEBUG_LOG_ENABLED: Lazy<bool> = Lazy::new(|| log::log_enabled!(log::Level::Debug));

static DEBUG_LOG_MSG_FUNC: Mutex<Option<Box<dyn Fn(&str) -> String + 'static + Send + Sync>>> = Mutex::new(None);

/// ensure init only once.
pub fn init_debug_log_msg_func(fun: impl Fn(&str) -> String + 'static + Send + Sync) {
    static INIT_ONCE: Once = Once::new();
    INIT_ONCE.call_once(|| {
        *DEBUG_LOG_MSG_FUNC.lock() = Some(Box::new(fun));
    });
}

static IS_STANDALONE: AtomicBool = AtomicBool::new(false);

pub fn mark_standalone() {
    IS_STANDALONE.swap(true, Ordering::SeqCst);
}

pub fn is_standalone() -> bool {
    IS_STANDALONE.load(Ordering::SeqCst)
}

impl fmt::Display for PermissionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermissionState::Granted => f.pad("granted"),
            PermissionState::GrantedPartial => f.pad("granted-partial"),
            PermissionState::Prompt => f.pad("prompt"),
            PermissionState::Denied => f.pad("denied"),
        }
    }
}

impl PermissionState {
    fn error(name: &str, info: impl FnOnce() -> Option<String>) -> AnyError {
        let msg = if is_standalone() {
            format!(
            "Requires {}, specify the required permissions during compilation using `deno compile --allow-{}`",
            Self::fmt_access(name, info),
            name
          )
        } else {
            format!(
                "Requires {}, run again with the --allow-{} flag",
                Self::fmt_access(name, info),
                name
            )
        };
        custom_error("PermissionDenied", msg)
    }

    fn fmt_access(name: &str, info: impl FnOnce() -> Option<String>) -> String {
        format!(
            "{} access{}",
            name,
            info()
                .map(|info| { format!(" to {info}") })
                .unwrap_or_default(),
        )
    }

    #[inline(always)]
    fn log_perm_access(name: &str, info: impl FnOnce() -> Option<String>) {
        if *DEBUG_LOG_ENABLED {
            let msg = Self::fmt_access(name, info);
            let msg = if let Some(f) = DEBUG_LOG_MSG_FUNC.lock().as_ref() {
                (f)(&msg)
            } else {
                msg
            };
            log::debug!("{} Granted {msg}", PERMISSION_EMOJI);
        }
    }

    /// Check the permission state. bool is whether a prompt was issued.
    #[inline]
    pub fn check(
        self,
        name: &str,
        api_name: Option<&str>,
        info: Option<&str>,
        prompt: bool,
    ) -> (Result<(), AnyError>, bool, bool) {
        self.check2(name, api_name, || info.map(|s| s.to_string()), prompt)
    }

    #[inline]
    pub fn check2(
        self,
        name: &str,
        api_name: Option<&str>,
        info: impl Fn() -> Option<String>,
        prompt: bool,
    ) -> (Result<(), AnyError>, bool, bool) {
        match self {
            PermissionState::Granted => {
                Self::log_perm_access(name, info);
                (Ok(()), false, false)
            }
            PermissionState::Prompt if prompt => {
                let msg = format!(
                    "{} access{}",
                    name,
                    info()
                        .map(|info| { format!(" to {info}") })
                        .unwrap_or_default(),
                );
                match permission_prompt(&msg, name, api_name, true) {
                    PromptResponse::Allow => {
                        Self::log_perm_access(name, info);
                        (Ok(()), true, false)
                    }
                    PromptResponse::AllowAll => {
                        Self::log_perm_access(name, info);
                        (Ok(()), true, true)
                    }
                    PromptResponse::Deny => (Err(Self::error(name, info)), true, false),
                }
            }
            _ => (Err(Self::error(name, info)), false, false),
        }
    }
}

/// A normalized environment variable name. On Windows this will
/// be uppercase and on other platforms it will stay as-is.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
struct EnvVarName {
    inner: String,
}

impl EnvVarName {
    pub fn new(env: impl AsRef<str>) -> Self {
        Self {
            inner: if cfg!(windows) {
                env.as_ref().to_uppercase()
            } else {
                env.as_ref().to_string()
            },
        }
    }
}

impl AsRef<str> for EnvVarName {
    fn as_ref(&self) -> &str {
        self.inner.as_str()
    }
}

/// Fast exit from permission check routines if this permission
/// is in the "fully-granted" state.
macro_rules! skip_check_if_is_permission_fully_granted {
    ($this:ident) => {
        if $this.is_allow_all() {
            return Ok(());
        }
    };
}

fn parse_run_list(list: &Option<Vec<String>>) -> Result<HashSet<RunDescriptor>, AnyError> {
    let mut result = HashSet::new();
    if let Some(v) = list {
        for s in v {
            if s.is_empty() {
                return Err(AnyError::msg("Empty path is not allowed"));
            } else {
                let desc = RunDescriptor::from(s.to_string());
                let aliases = desc.aliases();
                result.insert(desc);
                result.extend(aliases);
            }
        }
    }
    Ok(result)
}

fn parse_net_list(list: &Option<Vec<String>>) -> Result<HashSet<NetDescriptor>, AnyError> {
    if let Some(v) = list {
        v.iter()
            .map(|x| NetDescriptor::from_str(x))
            .collect::<Result<HashSet<NetDescriptor>, AnyError>>()
    } else {
        Ok(HashSet::new())
    }
}

fn parse_env_list(list: &Option<Vec<String>>) -> Result<HashSet<EnvDescriptor>, AnyError> {
    if let Some(v) = list {
        v.iter()
            .map(|x| {
                if x.is_empty() {
                    Err(AnyError::msg("Empty path is not allowed"))
                } else {
                    Ok(EnvDescriptor::new(x))
                }
            })
            .collect()
    } else {
        Ok(HashSet::new())
    }
}

#[inline]
pub fn normalize_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let mut components = path.as_ref().components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}

fn parse_path_list<T: Descriptor + Hash>(
    list: &Option<Vec<PathBuf>>,
    f: fn(PathBuf) -> T,
) -> Result<HashSet<T>, AnyError> {
    if let Some(v) = list {
        v.iter()
            .map(|raw_path| {
                if raw_path.as_os_str().is_empty() {
                    Err(AnyError::msg("Empty path is not allowed"))
                } else {
                    resolve_from_cwd(Path::new(&raw_path)).map(f)
                }
            })
            .collect()
    } else {
        Ok(HashSet::new())
    }
}

#[inline]
pub fn resolve_from_cwd(path: &Path) -> Result<PathBuf, AnyError> {
    if path.is_absolute() {
        Ok(normalize_path(path))
    } else {
        #[allow(clippy::disallowed_methods)]
        let cwd = std::env::current_dir().context("Failed to get current working directory")?;
        Ok(normalize_path(cwd.join(path)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnaryPermission<T: Descriptor + Hash> {
    pub granted_global: bool,
    pub granted_list: HashSet<T>,
    pub flag_denied_global: bool,
    pub flag_denied_list: HashSet<T>,
    pub prompt_denied_global: bool,
    pub prompt_denied_list: HashSet<T>,
    pub prompt: bool,
}

pub trait Descriptor: Eq + Clone + Hash {
    type Arg: From<String>;

    /// Parse this descriptor from a list of Self::Arg, which may have been converted from
    /// command-line strings.
    fn parse(list: &Option<Vec<Self::Arg>>) -> Result<HashSet<Self>, AnyError>;

    /// Generic check function to check this descriptor against a `UnaryPermission`.
    fn check_in_permission(
        &self,
        perm: &mut UnaryPermission<Self>,
        api_name: Option<&str>,
    ) -> Result<(), AnyError>;

    fn flag_name() -> &'static str;
    fn name(&self) -> Cow<str>;
    // By default, specifies no-stronger-than relationship.
    // As this is not strict, it's only true when descriptors are the same.
    fn stronger_than(&self, other: &Self) -> bool {
        self == other
    }
    fn aliases(&self) -> Vec<Self> {
        vec![]
    }
}

impl<T: Descriptor + Hash> UnaryPermission<T> {
    pub fn allow_all() -> Self {
        Self {
            granted_global: true,
            ..Default::default()
        }
    }

    pub fn is_allow_all(&self) -> bool {
        self.granted_global
            && self.flag_denied_list.is_empty()
            && self.prompt_denied_list.is_empty()
    }

    pub fn check_all_api(&mut self, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(None, false, api_name, || None)
    }

    fn check_desc(
        &mut self,
        desc: Option<&T>,
        assert_non_partial: bool,
        api_name: Option<&str>,
        get_display_name: impl Fn() -> Option<String>,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        let (result, prompted, is_allow_all) = self
            .query_desc(desc, AllowPartial::from(!assert_non_partial))
            .check2(
                T::flag_name(),
                api_name,
                || match get_display_name() {
                    Some(display_name) => Some(display_name),
                    None => desc.map(|d| format!("\"{}\"", d.name())),
                },
                self.prompt,
            );
        if prompted {
            if result.is_ok() {
                if is_allow_all {
                    self.insert_granted(None);
                } else {
                    self.insert_granted(desc.cloned());
                }
            } else {
                self.insert_prompt_denied(desc.cloned());
            }
        }
        result
    }

    fn query_desc(&self, desc: Option<&T>, allow_partial: AllowPartial) -> PermissionState {
        let aliases = desc.map_or(vec![], T::aliases);
        for desc in [desc]
            .into_iter()
            .chain(aliases.iter().map(Some).collect::<Vec<_>>())
        {
            let state = if self.is_flag_denied(desc) || self.is_prompt_denied(desc) {
                PermissionState::Denied
            } else if self.is_granted(desc) {
                match allow_partial {
                    AllowPartial::TreatAsGranted => PermissionState::Granted,
                    AllowPartial::TreatAsDenied => {
                        if self.is_partial_flag_denied(desc) {
                            PermissionState::Denied
                        } else {
                            PermissionState::Granted
                        }
                    }
                    AllowPartial::TreatAsPartialGranted => {
                        if self.is_partial_flag_denied(desc) {
                            PermissionState::GrantedPartial
                        } else {
                            PermissionState::Granted
                        }
                    }
                }
            } else if matches!(allow_partial, AllowPartial::TreatAsDenied)
                && self.is_partial_flag_denied(desc)
            {
                PermissionState::Denied
            } else {
                PermissionState::Prompt
            };
            if state != PermissionState::Prompt {
                return state;
            }
        }
        PermissionState::Prompt
    }

    fn request_desc(
        &mut self,
        desc: Option<&T>,
        get_display_name: impl Fn() -> Option<String>,
    ) -> PermissionState {
        let state = self.query_desc(desc, AllowPartial::TreatAsPartialGranted);
        if state == PermissionState::Granted {
            self.insert_granted(desc.cloned());
            return state;
        }
        if state != PermissionState::Prompt {
            return state;
        }
        let mut message = String::with_capacity(40);
        message.push_str(&format!("{} access", T::flag_name()));
        match get_display_name() {
            Some(display_name) => message.push_str(&format!(" to \"{}\"", display_name)),
            None => {
                if let Some(desc) = desc {
                    message.push_str(&format!(" to \"{}\"", desc.name()));
                }
            }
        }
        match permission_prompt(
            &message,
            T::flag_name(),
            Some("Deno.permissions.request()"),
            true,
        ) {
            PromptResponse::Allow => {
                self.insert_granted(desc.cloned());
                PermissionState::Granted
            }
            PromptResponse::Deny => {
                self.insert_prompt_denied(desc.cloned());
                PermissionState::Denied
            }
            PromptResponse::AllowAll => {
                self.insert_granted(None);
                PermissionState::Granted
            }
        }
    }

    fn revoke_desc(&mut self, desc: Option<&T>) -> PermissionState {
        match desc {
            Some(desc) => {
                self.granted_list.retain(|v| !v.stronger_than(desc));
                for alias in desc.aliases() {
                    self.granted_list.retain(|v| !v.stronger_than(&alias));
                }
            }
            None => {
                self.granted_global = false;
                // Revoke global is a special case where the entire granted list is
                // cleared. It's inconsistent with the granular case where only
                // descriptors stronger than the revoked one are purged.
                self.granted_list.clear();
            }
        }
        self.query_desc(desc, AllowPartial::TreatAsPartialGranted)
    }

    fn is_granted(&self, desc: Option<&T>) -> bool {
        Self::list_contains(desc, self.granted_global, &self.granted_list)
    }

    fn is_flag_denied(&self, desc: Option<&T>) -> bool {
        Self::list_contains(desc, self.flag_denied_global, &self.flag_denied_list)
    }

    fn is_prompt_denied(&self, desc: Option<&T>) -> bool {
        match desc {
            Some(desc) => self
                .prompt_denied_list
                .iter()
                .any(|v| desc.stronger_than(v)),
            None => self.prompt_denied_global || !self.prompt_denied_list.is_empty(),
        }
    }

    fn is_partial_flag_denied(&self, desc: Option<&T>) -> bool {
        match desc {
            None => !self.flag_denied_list.is_empty(),
            Some(desc) => self.flag_denied_list.iter().any(|v| desc.stronger_than(v)),
        }
    }

    fn list_contains(desc: Option<&T>, list_global: bool, list: &HashSet<T>) -> bool {
        match desc {
            Some(desc) => list_global || list.iter().any(|v| v.stronger_than(desc)),
            None => list_global,
        }
    }

    fn insert_granted(&mut self, desc: Option<T>) {
        Self::list_insert(desc, &mut self.granted_global, &mut self.granted_list);
    }

    fn insert_prompt_denied(&mut self, desc: Option<T>) {
        Self::list_insert(
            desc,
            &mut self.prompt_denied_global,
            &mut self.prompt_denied_list,
        );
    }

    fn list_insert(desc: Option<T>, list_global: &mut bool, list: &mut HashSet<T>) {
        match desc {
            Some(desc) => {
                let aliases = desc.aliases();
                list.insert(desc);
                for alias in aliases {
                    list.insert(alias);
                }
            }
            None => *list_global = true,
        }
    }

    pub fn create_child_permissions(
        &mut self,
        flag: ChildUnaryPermissionArg,
    ) -> Result<UnaryPermission<T>, AnyError> {
        let mut perms = Self::default();

        match flag {
            ChildUnaryPermissionArg::Inherit => {
                perms.clone_from(self);
            }
            ChildUnaryPermissionArg::Granted => {
                if self.check_all_api(None).is_err() {
                    return Err(escalation_error());
                }
                perms.granted_global = true;
            }
            ChildUnaryPermissionArg::NotGranted => {}
            ChildUnaryPermissionArg::GrantedList(granted_list) => {
                let granted: Vec<T::Arg> = granted_list.into_iter().map(From::from).collect();
                perms.granted_list = T::parse(&Some(granted))?;
                if !perms
                    .granted_list
                    .iter()
                    .all(|desc| desc.check_in_permission(self, None).is_ok())
                {
                    return Err(escalation_error());
                }
            }
        }
        perms.flag_denied_global = self.flag_denied_global;
        perms.prompt_denied_global = self.prompt_denied_global;
        perms.prompt = self.prompt;
        perms.flag_denied_list.clone_from(&self.flag_denied_list);
        perms
            .prompt_denied_list
            .clone_from(&self.prompt_denied_list);

        Ok(perms)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ChildUnaryPermissionArg {
    Inherit,
    Granted,
    NotGranted,
    GrantedList(Vec<String>),
}

impl<'de> Deserialize<'de> for ChildUnaryPermissionArg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ChildUnaryPermissionArgVisitor;
        impl<'de> de::Visitor<'de> for ChildUnaryPermissionArgVisitor {
            type Value = ChildUnaryPermissionArg;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("\"inherit\" or boolean or string[]")
            }

            fn visit_unit<E>(self) -> Result<ChildUnaryPermissionArg, E>
            where
                E: de::Error,
            {
                Ok(ChildUnaryPermissionArg::NotGranted)
            }

            fn visit_str<E>(self, v: &str) -> Result<ChildUnaryPermissionArg, E>
            where
                E: de::Error,
            {
                if v == "inherit" {
                    Ok(ChildUnaryPermissionArg::Inherit)
                } else {
                    Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
                }
            }

            fn visit_bool<E>(self, v: bool) -> Result<ChildUnaryPermissionArg, E>
            where
                E: de::Error,
            {
                match v {
                    true => Ok(ChildUnaryPermissionArg::Granted),
                    false => Ok(ChildUnaryPermissionArg::NotGranted),
                }
            }

            fn visit_seq<V>(self, mut v: V) -> Result<ChildUnaryPermissionArg, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let mut granted_list = vec![];
                while let Some(value) = v.next_element::<String>()? {
                    granted_list.push(value);
                }
                Ok(ChildUnaryPermissionArg::GrantedList(granted_list))
            }
        }
        deserializer.deserialize_any(ChildUnaryPermissionArgVisitor)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct ReadDescriptor(pub PathBuf);

impl Descriptor for ReadDescriptor {
    type Arg = PathBuf;

    fn check_in_permission(
        &self,
        perm: &mut UnaryPermission<Self>,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(perm);
        perm.check_desc(Some(self), true, api_name, || None)
    }

    fn parse(args: &Option<Vec<Self::Arg>>) -> Result<HashSet<Self>, AnyError> {
        parse_path_list(args, ReadDescriptor)
    }

    fn flag_name() -> &'static str {
        "read"
    }

    fn name(&self) -> Cow<str> {
        Cow::from(self.0.display().to_string())
    }

    fn stronger_than(&self, other: &Self) -> bool {
        other.0.starts_with(&self.0)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct WriteDescriptor(pub PathBuf);

impl Descriptor for WriteDescriptor {
    type Arg = PathBuf;

    fn check_in_permission(
        &self,
        perm: &mut UnaryPermission<Self>,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(perm);
        perm.check_desc(Some(self), true, api_name, || None)
    }

    fn parse(args: &Option<Vec<Self::Arg>>) -> Result<HashSet<Self>, AnyError> {
        parse_path_list(args, WriteDescriptor)
    }

    fn flag_name() -> &'static str {
        "write"
    }

    fn name(&self) -> Cow<str> {
        Cow::from(self.0.display().to_string())
    }

    fn stronger_than(&self, other: &Self) -> bool {
        other.0.starts_with(&self.0)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum Host {
    Fqdn(FQDN),
    Ip(IpAddr),
}

impl FromStr for Host {
    type Err = AnyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with('[') && s.ends_with(']') {
            let ip = s[1..s.len() - 1]
                .parse::<Ipv6Addr>()
                .map_err(|_| uri_error(format!("invalid IPv6 address: '{s}'")))?;
            return Ok(Host::Ip(IpAddr::V6(ip)));
        }
        let (without_trailing_dot, has_trailing_dot) =
            s.strip_suffix('.').map_or((s, false), |s| (s, true));
        if let Ok(ip) = without_trailing_dot.parse::<IpAddr>() {
            if has_trailing_dot {
                return Err(uri_error(format!("invalid host: '{without_trailing_dot}'")));
            }
            Ok(Host::Ip(ip))
        } else {
            let lower = if s.chars().all(|c| c.is_ascii_lowercase()) {
                Cow::Borrowed(s)
            } else {
                Cow::Owned(s.to_ascii_lowercase())
            };
            let fqdn = FQDN::from_str(&lower).with_context(|| format!("invalid host: '{s}'"))?;
            if fqdn.is_root() {
                return Err(uri_error(format!("invalid empty host: '{s}'")));
            }
            Ok(Host::Fqdn(fqdn))
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct NetDescriptor(pub Host, pub Option<u16>);

impl Descriptor for NetDescriptor {
    type Arg = String;

    fn check_in_permission(
        &self,
        perm: &mut UnaryPermission<Self>,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(perm);
        perm.check_desc(Some(self), false, api_name, || None)
    }

    fn parse(args: &Option<Vec<Self::Arg>>) -> Result<HashSet<Self>, AnyError> {
        parse_net_list(args)
    }

    fn flag_name() -> &'static str {
        "net"
    }

    fn name(&self) -> Cow<str> {
        Cow::from(format!("{}", self))
    }

    fn stronger_than(&self, other: &Self) -> bool {
        self.0 == other.0 && (self.1.is_none() || self.1 == other.1)
    }
}

impl FromStr for NetDescriptor {
    type Err = AnyError;

    fn from_str(hostname: &str) -> Result<Self, Self::Err> {
        // If this is a IPv6 address enclosed in square brackets, parse it as such.
        if hostname.starts_with('[') {
            if let Some((ip, after)) = hostname.split_once(']') {
                let ip = ip[1..].parse::<Ipv6Addr>().map_err(|_| {
                    uri_error(format!("invalid IPv6 address in '{hostname}': '{ip}'"))
                })?;
                let port = if let Some(port) = after.strip_prefix(':') {
                    let port = port.parse::<u16>().map_err(|_| {
                        uri_error(format!("invalid port in '{hostname}': '{port}'"))
                    })?;
                    Some(port)
                } else if after.is_empty() {
                    None
                } else {
                    return Err(uri_error(format!("invalid host: '{hostname}'")));
                };
                return Ok(NetDescriptor(Host::Ip(IpAddr::V6(ip)), port));
            } else {
                return Err(uri_error(format!("invalid host: '{hostname}'")));
            }
        }

        // Otherwise it is an IPv4 address or a FQDN with an optional port.
        let (host, port) = match hostname.split_once(':') {
            Some((_, "")) => {
                return Err(uri_error(format!("invalid empty port in '{hostname}'")));
            }
            Some((host, port)) => (host, port),
            None => (hostname, ""),
        };
        let host = host.parse::<Host>()?;

        let port = if port.is_empty() {
            None
        } else {
            let port = port.parse::<u16>().map_err(|_| {
                // If the user forgot to enclose an IPv6 address in square brackets, we
                // should give them a hint. There are always at least two colons in an
                // IPv6 address, so this heuristic finds likely a bare IPv6 address.
                if port.contains(':') {
                    uri_error(format!(
                        "ipv6 addresses must be enclosed in square brackets: '{hostname}'"
                    ))
                } else {
                    uri_error(format!("invalid port in '{hostname}': '{port}'"))
                }
            })?;
            Some(port)
        };

        Ok(NetDescriptor(host, port))
    }
}

impl fmt::Display for NetDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Host::Fqdn(fqdn) => write!(f, "{fqdn}"),
            Host::Ip(IpAddr::V4(ip)) => write!(f, "{ip}"),
            Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
        }?;
        if let Some(port) = self.1 {
            write!(f, ":{}", port)?;
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct EnvDescriptor(EnvVarName);

impl EnvDescriptor {
    pub fn new(env: impl AsRef<str>) -> Self {
        Self(EnvVarName::new(env))
    }
}

impl Descriptor for EnvDescriptor {
    type Arg = String;

    fn check_in_permission(
        &self,
        perm: &mut UnaryPermission<Self>,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(perm);
        perm.check_desc(Some(self), false, api_name, || None)
    }

    fn parse(list: &Option<Vec<Self::Arg>>) -> Result<HashSet<Self>, AnyError> {
        parse_env_list(list)
    }

    fn flag_name() -> &'static str {
        "env"
    }

    fn name(&self) -> Cow<str> {
        Cow::from(self.0.as_ref())
    }
}

impl AsRef<str> for EnvDescriptor {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum RunDescriptor {
    /// Warning: You may want to construct with `RunDescriptor::from()` for case
    /// handling.
    Name(String),
    /// Warning: You may want to construct with `RunDescriptor::from()` for case
    /// handling.
    Path(PathBuf),
}

impl Descriptor for RunDescriptor {
    type Arg = String;

    fn check_in_permission(
        &self,
        perm: &mut UnaryPermission<Self>,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(perm);
        perm.check_desc(Some(self), false, api_name, || None)
    }

    fn parse(args: &Option<Vec<Self::Arg>>) -> Result<HashSet<Self>, AnyError> {
        parse_run_list(args)
    }

    fn flag_name() -> &'static str {
        "run"
    }

    fn name(&self) -> Cow<str> {
        Cow::from(self.to_string())
    }

    fn aliases(&self) -> Vec<Self> {
        match self {
            RunDescriptor::Name(name) => match which(name) {
                Ok(path) => vec![RunDescriptor::Path(path)],
                Err(_) => vec![],
            },
            RunDescriptor::Path(_) => vec![],
        }
    }
}

impl From<String> for RunDescriptor {
    fn from(s: String) -> Self {
        #[cfg(windows)]
        let s = s.to_lowercase();
        let is_path = s.contains('/');
        #[cfg(windows)]
        let is_path = is_path || s.contains('\\') || Path::new(&s).is_absolute();
        if is_path {
            Self::Path(resolve_from_cwd(Path::new(&s)).unwrap())
        } else {
            Self::Name(s)
        }
    }
}

impl From<PathBuf> for RunDescriptor {
    fn from(p: PathBuf) -> Self {
        #[cfg(windows)]
        let p = PathBuf::from(p.to_string_lossy().to_string().to_lowercase());
        if p.is_absolute() {
            Self::Path(p)
        } else {
            Self::Path(resolve_from_cwd(&p).unwrap())
        }
    }
}

impl std::fmt::Display for RunDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunDescriptor::Name(s) => f.write_str(s),
            RunDescriptor::Path(p) => f.write_str(&p.display().to_string()),
        }
    }
}

impl AsRef<Path> for RunDescriptor {
    fn as_ref(&self) -> &Path {
        match self {
            RunDescriptor::Name(s) => s.as_ref(),
            RunDescriptor::Path(s) => s.as_ref(),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct SysDescriptor(pub String);

impl Descriptor for SysDescriptor {
    type Arg = String;

    fn check_in_permission(
        &self,
        perm: &mut UnaryPermission<Self>,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(perm);
        perm.check_desc(Some(self), false, api_name, || None)
    }

    fn parse(list: &Option<Vec<Self::Arg>>) -> Result<HashSet<Self>, AnyError> {
        parse_sys_list(list)
    }

    fn flag_name() -> &'static str {
        "sys"
    }

    fn name(&self) -> Cow<str> {
        Cow::from(self.0.to_string())
    }
}

pub fn parse_sys_kind(kind: &str) -> Result<&str, AnyError> {
    match kind {
        "hostname" | "osRelease" | "osUptime" | "loadavg" | "networkInterfaces"
        | "systemMemoryInfo" | "uid" | "gid" | "cpus" | "homedir" | "getegid" | "username"
        | "statfs" | "getPriority" | "setPriority" => Ok(kind),
        _ => Err(type_error(format!("unknown system info kind \"{kind}\""))),
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct FfiDescriptor(pub PathBuf);

impl Descriptor for FfiDescriptor {
    type Arg = PathBuf;

    fn check_in_permission(
        &self,
        perm: &mut UnaryPermission<Self>,
        api_name: Option<&str>,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(perm);
        perm.check_desc(Some(self), true, api_name, || None)
    }

    fn parse(list: &Option<Vec<Self::Arg>>) -> Result<HashSet<Self>, AnyError> {
        parse_path_list(list, FfiDescriptor)
    }

    fn flag_name() -> &'static str {
        "ffi"
    }

    fn name(&self) -> Cow<str> {
        Cow::from(self.0.display().to_string())
    }

    fn stronger_than(&self, other: &Self) -> bool {
        other.0.starts_with(&self.0)
    }
}

impl UnaryPermission<ReadDescriptor> {
    pub fn query(&self, path: Option<&Path>) -> PermissionState {
        self.query_desc(
            path.map(|p| ReadDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
            AllowPartial::TreatAsPartialGranted,
        )
    }

    pub fn request(&mut self, path: Option<&Path>) -> PermissionState {
        self.request_desc(
            path.map(|p| ReadDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
            || Some(path?.display().to_string()),
        )
    }

    pub fn revoke(&mut self, path: Option<&Path>) -> PermissionState {
        self.revoke_desc(
            path.map(|p| ReadDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
        )
    }

    pub fn check(&mut self, path: &Path, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(
            Some(&ReadDescriptor(resolve_from_cwd(path)?)),
            true,
            api_name,
            || Some(format!("\"{}\"", path.display())),
        )
    }

    #[inline]
    pub fn check_partial(&mut self, path: &Path, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        let desc = ReadDescriptor(resolve_from_cwd(path)?);
        self.check_desc(Some(&desc), false, api_name, || {
            Some(format!("\"{}\"", path.display()))
        })
    }

    /// As `check()`, but permission error messages will anonymize the path
    /// by replacing it with the given `display`.
    pub fn check_blind(
        &mut self,
        path: &Path,
        display: &str,
        api_name: &str,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        let desc = ReadDescriptor(resolve_from_cwd(path)?);
        self.check_desc(Some(&desc), false, Some(api_name), || {
            Some(format!("<{display}>"))
        })
    }

    pub fn check_all(&mut self, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(None, false, api_name, || None)
    }
}

impl UnaryPermission<WriteDescriptor> {
    pub fn query(&self, path: Option<&Path>) -> PermissionState {
        self.query_desc(
            path.map(|p| WriteDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
            AllowPartial::TreatAsPartialGranted,
        )
    }

    pub fn request(&mut self, path: Option<&Path>) -> PermissionState {
        self.request_desc(
            path.map(|p| WriteDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
            || Some(path?.display().to_string()),
        )
    }

    pub fn revoke(&mut self, path: Option<&Path>) -> PermissionState {
        self.revoke_desc(
            path.map(|p| WriteDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
        )
    }

    pub fn check(&mut self, path: &Path, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(
            Some(&WriteDescriptor(resolve_from_cwd(path)?)),
            true,
            api_name,
            || Some(format!("\"{}\"", path.display())),
        )
    }

    #[inline]
    pub fn check_partial(&mut self, path: &Path, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(
            Some(&WriteDescriptor(resolve_from_cwd(path)?)),
            false,
            api_name,
            || Some(format!("\"{}\"", path.display())),
        )
    }

    /// As `check()`, but permission error messages will anonymize the path
    /// by replacing it with the given `display`.
    pub fn check_blind(
        &mut self,
        path: &Path,
        display: &str,
        api_name: &str,
    ) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        let desc = WriteDescriptor(resolve_from_cwd(path)?);
        self.check_desc(Some(&desc), false, Some(api_name), || {
            Some(format!("<{display}>"))
        })
    }

    pub fn check_all(&mut self, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(None, false, api_name, || None)
    }
}

impl UnaryPermission<NetDescriptor> {
    pub fn query(&self, host: Option<&NetDescriptor>) -> PermissionState {
        self.query_desc(host, AllowPartial::TreatAsPartialGranted)
    }

    pub fn request(&mut self, host: Option<&NetDescriptor>) -> PermissionState {
        self.request_desc(host, || None)
    }

    pub fn revoke(&mut self, host: Option<&NetDescriptor>) -> PermissionState {
        self.revoke_desc(host)
    }

    pub fn check(&mut self, host: &NetDescriptor, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(Some(host), false, api_name, || None)
    }

    pub fn check_url(&mut self, url: &url::Url, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        let host = url
            .host_str()
            .ok_or_else(|| type_error(format!("Missing host in url: '{}'", url)))?;
        let host = host.parse::<Host>()?;
        let port = url.port_or_known_default();
        let descriptor = NetDescriptor(host, port);
        self.check_desc(Some(&descriptor), false, api_name, || {
            Some(format!("\"{descriptor}\""))
        })
    }

    pub fn check_all(&mut self) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(None, false, None, || None)
    }
}

impl UnaryPermission<EnvDescriptor> {
    pub fn query(&self, env: Option<&str>) -> PermissionState {
        self.query_desc(
            env.map(EnvDescriptor::new).as_ref(),
            AllowPartial::TreatAsPartialGranted,
        )
    }

    pub fn request(&mut self, env: Option<&str>) -> PermissionState {
        self.request_desc(env.map(EnvDescriptor::new).as_ref(), || None)
    }

    pub fn revoke(&mut self, env: Option<&str>) -> PermissionState {
        self.revoke_desc(env.map(EnvDescriptor::new).as_ref())
    }

    pub fn check(&mut self, env: &str, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(Some(&EnvDescriptor::new(env)), false, api_name, || None)
    }

    pub fn check_all(&mut self) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(None, false, None, || None)
    }
}

impl UnaryPermission<SysDescriptor> {
    pub fn query(&self, kind: Option<&str>) -> PermissionState {
        self.query_desc(
            kind.map(|k| SysDescriptor(k.to_string())).as_ref(),
            AllowPartial::TreatAsPartialGranted,
        )
    }

    pub fn request(&mut self, kind: Option<&str>) -> PermissionState {
        self.request_desc(kind.map(|k| SysDescriptor(k.to_string())).as_ref(), || None)
    }

    pub fn revoke(&mut self, kind: Option<&str>) -> PermissionState {
        self.revoke_desc(kind.map(|k| SysDescriptor(k.to_string())).as_ref())
    }

    pub fn check(&mut self, kind: &str, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(
            Some(&SysDescriptor(kind.to_string())),
            false,
            api_name,
            || None,
        )
    }

    pub fn check_all(&mut self) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(None, false, None, || None)
    }
}

impl UnaryPermission<RunDescriptor> {
    pub fn query(&self, cmd: Option<&str>) -> PermissionState {
        self.query_desc(
            cmd.map(|c| RunDescriptor::from(c.to_string())).as_ref(),
            AllowPartial::TreatAsPartialGranted,
        )
    }

    pub fn request(&mut self, cmd: Option<&str>) -> PermissionState {
        self.request_desc(
            cmd.map(|c| RunDescriptor::from(c.to_string())).as_ref(),
            || Some(cmd?.to_string()),
        )
    }

    pub fn revoke(&mut self, cmd: Option<&str>) -> PermissionState {
        self.revoke_desc(cmd.map(|c| RunDescriptor::from(c.to_string())).as_ref())
    }

    pub fn check(&mut self, cmd: &str, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(
            Some(&RunDescriptor::from(cmd.to_string())),
            false,
            api_name,
            || Some(format!("\"{}\"", cmd)),
        )
    }

    pub fn check_all(&mut self, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(None, false, api_name, || None)
    }
}

impl UnaryPermission<FfiDescriptor> {
    pub fn query(&self, path: Option<&Path>) -> PermissionState {
        self.query_desc(
            path.map(|p| FfiDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
            AllowPartial::TreatAsPartialGranted,
        )
    }

    pub fn request(&mut self, path: Option<&Path>) -> PermissionState {
        self.request_desc(
            path.map(|p| FfiDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
            || Some(path?.display().to_string()),
        )
    }

    pub fn revoke(&mut self, path: Option<&Path>) -> PermissionState {
        self.revoke_desc(
            path.map(|p| FfiDescriptor(resolve_from_cwd(p).unwrap()))
                .as_ref(),
        )
    }

    pub fn check(&mut self, path: &Path, api_name: Option<&str>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(
            Some(&FfiDescriptor(resolve_from_cwd(path)?)),
            true,
            api_name,
            || Some(format!("\"{}\"", path.display())),
        )
    }

    pub fn check_partial(&mut self, path: Option<&Path>) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        let desc = match path {
            Some(path) => Some(FfiDescriptor(resolve_from_cwd(path)?)),
            None => None,
        };
        self.check_desc(desc.as_ref(), false, None, || {
            Some(format!("\"{}\"", path?.display()))
        })
    }

    pub fn check_all(&mut self) -> Result<(), AnyError> {
        skip_check_if_is_permission_fully_granted!(self);
        self.check_desc(None, false, Some("all"), || None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Permissions {
    pub read: UnaryPermission<ReadDescriptor>,
    pub write: UnaryPermission<WriteDescriptor>,
    pub net: UnaryPermission<NetDescriptor>,
    pub env: UnaryPermission<EnvDescriptor>,
    pub sys: UnaryPermission<SysDescriptor>,
    pub run: UnaryPermission<RunDescriptor>,
    pub ffi: UnaryPermission<FfiDescriptor>,
    pub all: UnitPermission,
    pub hrtime: UnitPermission,
}

#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct PermissionsOptions {
    pub allow_all: bool,
    pub allow_env: Option<Vec<String>>,
    pub deny_env: Option<Vec<String>>,
    pub allow_hrtime: bool,
    pub deny_hrtime: bool,
    pub allow_net: Option<Vec<String>>,
    pub deny_net: Option<Vec<String>>,
    pub allow_ffi: Option<Vec<PathBuf>>,
    pub deny_ffi: Option<Vec<PathBuf>>,
    pub allow_read: Option<Vec<PathBuf>>,
    pub deny_read: Option<Vec<PathBuf>>,
    pub allow_run: Option<Vec<String>>,
    pub deny_run: Option<Vec<String>>,
    pub allow_sys: Option<Vec<String>>,
    pub deny_sys: Option<Vec<String>>,
    pub allow_write: Option<Vec<PathBuf>>,
    pub deny_write: Option<Vec<PathBuf>>,
    pub prompt: bool,
}

impl<T: Descriptor + Hash> Default for UnaryPermission<T> {
    fn default() -> Self {
        UnaryPermission {
            granted_global: Default::default(),
            granted_list: Default::default(),
            flag_denied_global: Default::default(),
            flag_denied_list: Default::default(),
            prompt_denied_global: Default::default(),
            prompt_denied_list: Default::default(),
            prompt: Default::default(),
        }
    }
}

impl Permissions {
    pub fn new_unary<T>(
        allow_list: &Option<Vec<T::Arg>>,
        deny_list: &Option<Vec<T::Arg>>,
        prompt: bool,
    ) -> Result<UnaryPermission<T>, AnyError>
    where
        T: Descriptor + Hash,
    {
        Ok(UnaryPermission::<T> {
            granted_global: global_from_option(allow_list),
            granted_list: T::parse(allow_list)?,
            flag_denied_global: global_from_option(deny_list),
            flag_denied_list: T::parse(deny_list)?,
            prompt,
            ..Default::default()
        })
    }

    pub const fn new_hrtime(allow_state: bool, deny_state: bool) -> UnitPermission {
        unit_permission_from_flag_bools(
            allow_state,
            deny_state,
            "hrtime",
            "high precision time",
            false, // never prompt for hrtime
        )
    }

    pub const fn new_all(allow_state: bool) -> UnitPermission {
        unit_permission_from_flag_bools(
            allow_state,
            false,
            "all",
            "all",
            false, // never prompt for all
        )
    }

    pub fn from_options(opts: &PermissionsOptions) -> Result<Self, AnyError> {
        Ok(Self {
            read: Permissions::new_unary(&opts.allow_read, &opts.deny_read, opts.prompt)?,
            write: Permissions::new_unary(&opts.allow_write, &opts.deny_write, opts.prompt)?,
            net: Permissions::new_unary(&opts.allow_net, &opts.deny_net, opts.prompt)?,
            env: Permissions::new_unary(&opts.allow_env, &opts.deny_env, opts.prompt)?,
            sys: Permissions::new_unary(&opts.allow_sys, &opts.deny_sys, opts.prompt)?,
            run: Permissions::new_unary(&opts.allow_run, &opts.deny_run, opts.prompt)?,
            ffi: Permissions::new_unary(&opts.allow_ffi, &opts.deny_ffi, opts.prompt)?,
            all: Permissions::new_all(opts.allow_all),
            hrtime: Permissions::new_hrtime(opts.allow_hrtime, opts.deny_hrtime),
        })
    }

    /// Create a set of permissions that explicitly allow everything.
    pub fn allow_all() -> Self {
        Self {
            read: UnaryPermission::allow_all(),
            write: UnaryPermission::allow_all(),
            net: UnaryPermission::allow_all(),
            env: UnaryPermission::allow_all(),
            sys: UnaryPermission::allow_all(),
            run: UnaryPermission::allow_all(),
            ffi: UnaryPermission::allow_all(),
            all: Permissions::new_all(true),
            hrtime: Permissions::new_hrtime(true, false),
        }
    }

    /// Create a set of permissions that enable nothing, but will allow prompting.
    pub fn none_with_prompt() -> Self {
        Self::none(true)
    }

    /// Create a set of permissions that enable nothing, and will not allow prompting.
    pub fn none_without_prompt() -> Self {
        Self::none(false)
    }

    fn none(prompt: bool) -> Self {
        Self {
            read: Permissions::new_unary(&None, &None, prompt).unwrap(),
            write: Permissions::new_unary(&None, &None, prompt).unwrap(),
            net: Permissions::new_unary(&None, &None, prompt).unwrap(),
            env: Permissions::new_unary(&None, &None, prompt).unwrap(),
            sys: Permissions::new_unary(&None, &None, prompt).unwrap(),
            run: Permissions::new_unary(&None, &None, prompt).unwrap(),
            ffi: Permissions::new_unary(&None, &None, prompt).unwrap(),
            all: Permissions::new_all(false),
            hrtime: Permissions::new_hrtime(false, false),
        }
    }

    /// A helper function that determines if the module specifier is a local or
    /// remote, and performs a read or net check for the specifier.
    pub fn check_specifier(&mut self, specifier: &ModuleSpecifier) -> Result<(), AnyError> {
        match specifier.scheme() {
            "file" => match specifier.to_file_path() {
                Ok(path) => self.read.check(&path, Some("import()")),
                Err(_) => Err(uri_error(format!(
                    "Invalid file path.\n  Specifier: {specifier}"
                ))),
            },
            "data" => Ok(()),
            "blob" => Ok(()),
            _ => self.net.check_url(specifier, Some("import()")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitPermission {
    pub name: &'static str,
    pub description: &'static str,
    pub state: PermissionState,
    pub prompt: bool,
}

impl UnitPermission {
    pub fn query(&self) -> PermissionState {
        self.state
    }

    pub fn request(&mut self) -> PermissionState {
        if self.state == PermissionState::Prompt {
            if PromptResponse::Allow
                == permission_prompt(
                    &format!("access to {}", self.description),
                    self.name,
                    Some("Deno.permissions.query()"),
                    false,
                )
            {
                self.state = PermissionState::Granted;
            } else {
                self.state = PermissionState::Denied;
            }
        }
        self.state
    }

    pub fn revoke(&mut self) -> PermissionState {
        if self.state == PermissionState::Granted {
            self.state = PermissionState::Prompt;
        }
        self.state
    }

    pub fn check(&mut self) -> Result<(), AnyError> {
        let (result, prompted, _is_allow_all) =
            self.state.check(self.name, None, None, self.prompt);
        if prompted {
            if result.is_ok() {
                self.state = PermissionState::Granted;
            } else {
                self.state = PermissionState::Denied;
            }
        }
        result
    }

    pub fn create_child_permissions(&mut self, flag: ChildUnitPermissionArg) -> Result<Self, AnyError> {
        let mut perm = self.clone();
        match flag {
            ChildUnitPermissionArg::Inherit => {
                // copy
            }
            ChildUnitPermissionArg::Granted => {
                if self.check().is_err() {
                    return Err(escalation_error());
                }
                perm.state = PermissionState::Granted;
            }
            ChildUnitPermissionArg::NotGranted => {
                perm.state = PermissionState::Prompt;
            }
        }
        if self.state == PermissionState::Denied {
            perm.state = PermissionState::Denied;
        }
        Ok(perm)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ChildUnitPermissionArg {
    Inherit,
    Granted,
    NotGranted,
}

impl<'de> Deserialize<'de> for ChildUnitPermissionArg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ChildUnitPermissionArgVisitor;
        impl<'de> de::Visitor<'de> for ChildUnitPermissionArgVisitor {
            type Value = ChildUnitPermissionArg;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("\"inherit\" or boolean")
            }

            fn visit_unit<E>(self) -> Result<ChildUnitPermissionArg, E>
            where
                E: de::Error,
            {
                Ok(ChildUnitPermissionArg::NotGranted)
            }

            fn visit_str<E>(self, v: &str) -> Result<ChildUnitPermissionArg, E>
            where
                E: de::Error,
            {
                if v == "inherit" {
                    Ok(ChildUnitPermissionArg::Inherit)
                } else {
                    Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
                }
            }

            fn visit_bool<E>(self, v: bool) -> Result<ChildUnitPermissionArg, E>
            where
                E: de::Error,
            {
                match v {
                    true => Ok(ChildUnitPermissionArg::Granted),
                    false => Ok(ChildUnitPermissionArg::NotGranted),
                }
            }
        }
        deserializer.deserialize_any(ChildUnitPermissionArgVisitor)
    }
}

fn global_from_option<T>(flag: &Option<Vec<T>>) -> bool {
    matches!(flag, Some(v) if v.is_empty())
}

const fn unit_permission_from_flag_bools(
    allow_flag: bool,
    deny_flag: bool,
    name: &'static str,
    description: &'static str,
    prompt: bool,
) -> UnitPermission {
    UnitPermission {
        name,
        description,
        state: if deny_flag {
            PermissionState::Denied
        } else if allow_flag {
            PermissionState::Granted
        } else {
            PermissionState::Prompt
        },
        prompt,
    }
}

fn parse_sys_list(list: &Option<Vec<String>>) -> Result<HashSet<SysDescriptor>, AnyError> {
    if let Some(v) = list {
        v.iter()
            .map(|x| {
                if x.is_empty() {
                    Err(AnyError::msg("empty"))
                } else {
                    Ok(SysDescriptor(x.to_string()))
                }
            })
            .collect()
    } else {
        Ok(HashSet::new())
    }
}

fn escalation_error() -> AnyError {
    custom_error(
        "PermissionDenied",
        "Can't escalate parent thread permissions",
    )
}

/// `AllowPartial` prescribes how to treat a permission which is partially
/// denied due to a `--deny-*` flag affecting a subscope of the queried
/// permission.
///
/// `TreatAsGranted` is used in place of `TreatAsPartialGranted` when we don't
/// want to wastefully check for partial denials when, say, checking read
/// access for a file.
#[derive(Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum AllowPartial {
    TreatAsGranted,
    TreatAsDenied,
    TreatAsPartialGranted,
}

impl From<bool> for AllowPartial {
    fn from(value: bool) -> Self {
        if value {
            Self::TreatAsGranted
        } else {
            Self::TreatAsDenied
        }
    }
}
