use std::fmt::Write;
use std::sync::Once;

use super::html::Html;
use crate::blsrt_get_input as get_input;
use bls_permissions::bls_set_prompter;
use bls_permissions::is_standalone;
use bls_permissions::PermissionPrompter;
use bls_permissions::PromptResponse;
use bls_permissions::MAX_PERMISSION_PROMPT_LENGTH;
use bls_permissions::PERMISSION_EMOJI;
use serde::Serialize;

#[cfg(target_family = "wasm")]
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
fn blsrt_get_input() -> String {
    let mut input = get_input();
    input = input.to_lowercase();
    input
}

#[derive(Serialize)]
struct PromptMsg<'a> {
    api_name: Option<&'a str>,
    is_unary: bool,
    name: &'a str,
    message: &'a str,
    dlg_html: &'a str,
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
            let mut output = String::new();
            write!(
                &mut output,
                "<div style='text-align: left;line-height:100%;'>"
            )
            .unwrap();
            write!(
                &mut output,
                "┏ {} ",
                Html::span_color("yellow", PERMISSION_EMOJI)
            )
            .unwrap();
            write!(&mut output, "{}", Html::bold("bls-runtime requests ")).unwrap();
            write!(&mut output, "{}", Html::bold(message)).unwrap();
            writeln!(&mut output, "{}", ".").unwrap();
            if let Some(api_name) = api_name.clone() {
                writeln!(&mut output, "<br/>┠─ Requested by `{}` API.", api_name).unwrap();
            }
            let msg = format!(
                "Learn more at: {}",
                Html::color_with_underline(
                    "cyan",
                    &format!("https://blockless.network/docs/go--allow-{}", name)
                )
            );
            writeln!(&mut output, "<br/>┠─ {}", Html::italic(&msg)).unwrap();
            let msg = if is_standalone() {
                format!("Specify the required permissions during compile time using `deno compile --allow-{name}`.")
            } else {
                format!("Run again with --allow-{name} to bypass this prompt.")
            };
            writeln!(&mut output, "<br/>┠─ {}", Html::italic(&msg)).unwrap();
            write!(&mut output, "<br/>┗ {}", Html::bold("Allow?")).unwrap();
            write!(&mut output, " {opts}  ").unwrap();
            write!(&mut output, "</div>").unwrap();
            let prompt_msg = serde_json::to_string(&PromptMsg {
                api_name: api_name,
                message,
                dlg_html: &output,
                name,
                opts: &opts,
                is_unary,
            })
            .unwrap();
            bls_prompt_dlg_info!("{prompt_msg}");
        }
        let resp = loop {
            let input = blsrt_get_input();
            #[cfg(target_family = "wasm")]
            if input == YIELD {
                return PromptResponse::Yield;
            }
            let bytes = input.as_bytes();
            match bytes[0] as char {
                'y' | 'Y' => {
                    let msg = format!("Granted {message} access.");
                    blsrt_show_tips!(success: "✅ {msg}");
                    break PromptResponse::Allow;
                }
                'n' | 'N' | '\x1b' => {
                    let msg = format!("Denied {message}.");
                    blsrt_show_tips!(fail: "❌ {msg}");
                    break PromptResponse::Deny;
                }
                'A' | 'a' if is_unary => {
                    let msg = format!("Granted all {name} access.");
                    blsrt_show_tips!(success: "✅ {msg}");
                    break PromptResponse::AllowAll;
                }
                _ => {
                    blsrt_show_tips!(fail:"┗ Unrecognized option. Allow? {opts} > ");
                    #[cfg(target_family = "wasm")]
                    break PromptResponse::Yield;
                }
            }
        };
        return resp;
    }
}
