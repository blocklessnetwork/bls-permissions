class BlsRuntime {
    constructor() {
        this.info_cache = [];
        this.prompt = null;
    }
    show_prompter() {
        
    }
}

let instance = new BlsRuntime();

export function bls_runtime_input() {
    if (instance.prompt == null) {
        instance.show_prompter();
        return "cmd:yield";
    }
    return instance.prompt;
}

export function bls_runtime_info(s) {
    console.log(s)
}