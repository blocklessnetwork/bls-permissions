use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::Once;
use std::time::Duration;

use bls_permissions::bls_set_prompter;
use bls_permissions::PermissionPrompter;
use bls_permissions::PromptResponse;
use bls_permissions::MAX_PERMISSION_PROMPT_LENGTH;
use once_cell::sync::Lazy;
use wasm_bindgen::prelude::wasm_bindgen;
use crate::bls_runtime_input as rt_input;

const BLOCKED: &str = "cmd:blocked";

pub fn init_browser_prompter() {
    static BROWSERPROMPTER: Once = Once::new();
    info!("install browser prompter");
    BROWSERPROMPTER.call_once(|| {
        bls_set_prompter(Box::new(BrowserPrompter));
    });
}

static COND_VAR: Lazy<Arc<(Mutex<bool>, Condvar)>> = Lazy::new(|| {
    Arc::new((Mutex::new(false), Condvar::new()))
}) ;

#[wasm_bindgen]
pub fn notify_input() {
    let (lock, cvar) = &(**COND_VAR);
    *lock.lock().unwrap() = false;
    cvar.notify_all();
}

/// get input from browser. the js function will return value immediately
/// so use condvar block the call.
fn bls_runtime_input() -> String {
    let mut input = rt_input();
    input = input.to_lowercase();
    if input == BLOCKED {
        let (lock, cvar) = &(**COND_VAR);
        let mut guard = lock.lock().unwrap();
        *guard = false;
        // keep the input get y or n.
        while !*guard {
            let sec = Duration::from_millis(50);
            let result = cvar.wait_timeout(guard, sec).unwrap();
            guard = result.0;
            if result.1.timed_out() {
                continue;
            } else {
                input = rt_input();
                input = input.to_lowercase();
                if input == BLOCKED {
                    continue;
                }
                break;
            }
        }
    }
    input
}

pub struct BrowserPrompter;

impl PermissionPrompter for BrowserPrompter {
    fn prompt(
        &mut self,
        message: &str,
        name: &str,
        _api_name: Option<&str>,
        is_unary: bool,
    ) -> PromptResponse {
        if message.len() > MAX_PERMISSION_PROMPT_LENGTH {
            info!("❌ Permission prompt length ({} bytes) was larger than the configured maximum length ({} bytes): denying request.", message.len(), MAX_PERMISSION_PROMPT_LENGTH);
            info!("❌ WARNING: This may indicate that code is trying to bypass or hide permission check requests.");
            info!("❌ Run again with --allow-{name} to bypass this check if this is really what you want to do.");
            return PromptResponse::Deny;
        }

        let opts: String = if is_unary {
            format!("[y/n/A] (y = yes, allow; n = no, deny; A = allow all {name} permissions)")
        } else {
            "[y/n] (y = yes, allow; n = no, deny)".to_string()
        };
        let resp = loop {
            let input = bls_runtime_input();
            let bytes = input.as_bytes();
            match bytes[0] as char {
                'y' | 'Y' => {
                    let msg = format!("Granted {message} access.");
                    bls_info!("✅ {msg}");
                    break PromptResponse::Allow;
                }
                'n' | 'N' | '\x1b' => {
                    let msg = format!("Denied {message}.");
                    bls_info!("❌ {msg}");
                    break PromptResponse::Deny;
                }
                'A' if is_unary => {
                    let msg = format!("Granted all {name} access.");
                    bls_info!("✅ {msg}");
                    break PromptResponse::AllowAll;
                }
                _ => {
                    bls_info!("┗ Unrecognized option. Allow? {opts} > ");
                }
            }
        };
        return resp;
    }
}