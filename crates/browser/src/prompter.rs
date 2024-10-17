use bls_permissions::PermissionPrompter;
use bls_permissions::PromptResponse;
use bls_permissions::MAX_PERMISSION_PROMPT_LENGTH;
use crate::bls_runtime_prompter;

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
            log!("❌ Permission prompt length ({} bytes) was larger than the configured maximum length ({} bytes): denying request.", message.len(), MAX_PERMISSION_PROMPT_LENGTH);
            log!("❌ WARNING: This may indicate that code is trying to bypass or hide permission check requests.");
            log!("❌ Run again with --allow-{name} to bypass this check if this is really what you want to do.");
            return PromptResponse::Deny;
        }

        let opts: String = if is_unary {
            format!("[y/n/A] (y = yes, allow; n = no, deny; A = allow all {name} permissions)")
        } else {
            "[y/n] (y = yes, allow; n = no, deny)".to_string()
        };
        let resp = loop {
            let input = bls_runtime_prompter();
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