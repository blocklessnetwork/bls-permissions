use bls_permissions::PermissionPrompter;
use bls_permissions::PromptResponse;
use bls_permissions::MAX_PERMISSION_PROMPT_LENGTH;
use wasm_bindgen::prelude::wasm_bindgen;


#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    fn console_log(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = debug)]
    fn console_debug(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(s: &str);

    
}

macro_rules! console_log {
    ($($arg:tt)*) => {
        let s = format!($($arg)*);
        console_log(&s);
    };
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
        #[allow(clippy::print_stderr)]
        if message.len() > MAX_PERMISSION_PROMPT_LENGTH {
            console_log!("❌ Permission prompt length ({} bytes) was larger than the configured maximum length ({} bytes): denying request.", message.len(), MAX_PERMISSION_PROMPT_LENGTH);
            console_log!("❌ WARNING: This may indicate that code is trying to bypass or hide permission check requests.");
            console_log!("❌ Run again with --allow-{name} to bypass this check if this is really what you want to do.");
            return PromptResponse::Deny;
        }
        return PromptResponse::Deny;
    }
}