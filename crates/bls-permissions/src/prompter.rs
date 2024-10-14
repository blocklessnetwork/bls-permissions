use once_cell::sync::Lazy;
use parking_lot::Mutex;

#[derive(Debug, Eq, PartialEq)]
pub enum PromptResponse {
    Allow,
    Deny,
    AllowAll,
}

pub type PromptCallback = Box<dyn FnMut() + Send + Sync>;

pub const PERMISSION_EMOJI: &str = "⚠️";

// 10kB of permission prompting should be enough for anyone
pub const MAX_PERMISSION_PROMPT_LENGTH: usize = 10 * 1024;

pub trait PermissionPrompter: Send + Sync {
    fn prompt(
        &mut self,
        message: &str,
        name: &str,
        api_name: Option<&str>,
        is_unary: bool,
    ) -> PromptResponse;
}

struct AllowPrompter;

impl PermissionPrompter for AllowPrompter {
    fn prompt(
        &mut self,
        _message: &str,
        _name: &str,
        _api_name: Option<&str>,
        _is_unary: bool,
    ) -> PromptResponse {
        PromptResponse::AllowAll
    }
}

static PERMISSION_PROMPTER: Lazy<Mutex<Box<dyn PermissionPrompter>>> =
    Lazy::new(|| Mutex::new(Box::new(AllowPrompter)));

static MAYBE_BEFORE_PROMPT_CALLBACK: Lazy<Mutex<Option<PromptCallback>>> =
    Lazy::new(|| Mutex::new(None));

static MAYBE_AFTER_PROMPT_CALLBACK: Lazy<Mutex<Option<PromptCallback>>> =
    Lazy::new(|| Mutex::new(None));

pub fn bls_permission_prompt(
    message: &str,
    flag: &str,
    api_name: Option<&str>,
    is_unary: bool,
) -> PromptResponse {
    if let Some(before_callback) = MAYBE_BEFORE_PROMPT_CALLBACK.lock().as_mut() {
        before_callback();
    }
    let r = PERMISSION_PROMPTER
        .lock()
        .prompt(message, flag, api_name, is_unary);
    if let Some(after_callback) = MAYBE_AFTER_PROMPT_CALLBACK.lock().as_mut() {
        after_callback();
    }
    r
}

pub fn bls_set_prompt_callbacks(before_callback: PromptCallback, after_callback: PromptCallback) {
    *MAYBE_BEFORE_PROMPT_CALLBACK.lock() = Some(before_callback);
    *MAYBE_AFTER_PROMPT_CALLBACK.lock() = Some(after_callback);
}

pub fn bls_set_prompter(prompter: Box<dyn PermissionPrompter>) {
    *PERMISSION_PROMPTER.lock() = prompter;
}
