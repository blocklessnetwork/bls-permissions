use wasm_bindgen::prelude::wasm_bindgen;


#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = debug)]
    pub fn console_debug(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    pub fn console_error(s: &str);
    
    #[wasm_bindgen(js_namespace = bls_runtime, js_name = error)]
    pub fn bls_runtime_err(s: &str);

    #[wasm_bindgen(js_namespace = bls_runtime, js_name = prompter)]
    pub fn bls_runtime_prompter() -> String;
}

macro_rules! log {
    ($($arg:tt)*) => {
        crate::log(&format!($($arg)*));
    };
}

macro_rules! info {
    ($($arg:tt)*) => {
        crate::log(&format!($($arg)*));
    }
}