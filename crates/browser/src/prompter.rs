use std::sync::Once;

use bls_permissions::bls_set_prompter;
use bls_permissions::PermissionPrompter;
use bls_permissions::PromptResponse;
use bls_permissions::MAX_PERMISSION_PROMPT_LENGTH;
use serde::Serialize;
use crate::bls_runtime_input as rt_input;

const YIELD: &str = "cmd:yield";

pub fn init_browser_prompter() {
    static BROWSERPROMPTER: Once = Once::new();
    info!("install browser prompter");
    BROWSERPROMPTER.call_once(|| {
        bls_set_prompter(Box::new(BrowserPrompter));
    });
}

/// get input from browser. the js function will return value immediately
/// so use condvar block the call.
fn bls_runtime_input() -> String {
    let mut input = rt_input();
    input = input.to_lowercase();
    input
}

#[derive(Serialize)]
struct PromptMsg<'a> {
    api_name: Option<&'a str>,
    is_unary: bool,
    name: &'a str,
    message: &'a str,
    opts: &'a str,
}

pub struct BrowserPrompter;

impl PermissionPrompter for BrowserPrompter {
    fn prompt(
        &mut self,
        message: &str,
        name: &str,
        api_name: Option<&str>,
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
        {
            let prompt_msg = serde_json::to_string(&PromptMsg{
                api_name: api_name,
                message,
                name,
                opts: &opts,
                is_unary,
            }).unwrap();
            bls_prompt_dlg_info!("{prompt_msg}");
        }
        let resp = loop {
            let input = bls_runtime_input();
            #[cfg(target_arch = "wasm32")]
            if input == YIELD {
                return PromptResponse::Yield;
            }
            let bytes = input.as_bytes();
            match bytes[0] as char {
                'y' | 'Y' => {
                    let msg = format!("Granted {message} access.");
                    info!("✅ {msg}");
                    break PromptResponse::Allow;
                }
                'n' | 'N' | '\x1b' => {
                    let msg = format!("Denied {message}.");
                    info!("❌ {msg}");
                    break PromptResponse::Deny;
                }
                'A' if is_unary => {
                    let msg = format!("Granted all {name} access.");
                    info!("✅ {msg}");
                    break PromptResponse::AllowAll;
                }
                _ => {
                    info!("┗ Unrecognized option. Allow? {opts} > ");
                }
            }
        };
        return resp;
    }
}