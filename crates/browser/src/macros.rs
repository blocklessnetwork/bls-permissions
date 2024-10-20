use wasm_bindgen::prelude::wasm_bindgen;


#[wasm_bindgen]
extern "C" {
    type Class;

    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn console_log(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = debug)]
    pub fn console_debug(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(s: &str);
}

#[wasm_bindgen(module = "/module.js")]
extern "C" {
    pub fn bls_runtime_input() -> String;
    pub fn bls_runtime_prompt_dlg_info(info: &str);
}

macro_rules! bls_prompt_dlg_info {
    ($($arg:tt)*) => {
        crate::bls_runtime_prompt_dlg_info(&format!($($arg)*));
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
