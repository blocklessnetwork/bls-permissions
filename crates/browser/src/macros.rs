use wasm_bindgen::prelude::wasm_bindgen;


#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn console_log(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = debug)]
    pub fn console_debug(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(s: &str);
}

#[wasm_bindgen(module = "/module.js")]
extern "C" {
    #[wasm_bindgen(js_name = "blsRuntimeGetInput")]
    pub fn blsrt_get_input() -> String;
    #[wasm_bindgen(js_name = "blsRuntimeSetPromptDlgInfo")]
    pub fn blsrt_set_prompt_dlg_info(info: &str);
}

macro_rules! bls_prompt_dlg_info {
    ($($arg:tt)*) => {
        crate::blsrt_set_prompt_dlg_info(&format!($($arg)*));
    };
}

macro_rules! info {
    ($($arg:tt)*) => {
        crate::console_log(&format!($($arg)*));
    };
}

#[allow(unused_macros)]
macro_rules! error {
    ($($arg:tt)*) => {
        crate::console_error(&format!($($arg)*));
    };
}

macro_rules! error2jscode {
    ($e: expr, $msg: expr) => {
        if is_yield_error_class($e) {
            JsCode::jscode_yield()
        } else {
            info!("Error: {}", $msg);
            JsCode::error(Code::Failed, $msg)
        }
    };
    ($e: expr) => {
        {
            let msg = format!("{}", $e);
            error2jscode!($e, msg)
        }
    }
}

macro_rules! permission_check {
    ($e: expr) => {
        if let Err(e) = $e {
            error2jscode!(&e)
        } else {
            JsCode::success()
        }
    };
}