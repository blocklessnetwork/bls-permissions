class BlsRuntime {
    constructor() {
        this.info_cache = [];
        this.input = null;
        this.yield = null;
        this.promptDlg = null;
    }
    defaultDlg() {
        let promptDlg = document.createElement("dialog");
        let msg = document.createElement("p");
        promptDlg.appendChild(msg);
        let y = document.createElement("button");
        y.innerText = "yes";
        promptDlg.appendChild(y);
        let n = document.createElement("button");
        n.innerText = "no";
        promptDlg.appendChild(n);
        let a = document.createElement("button");
        a.innerText = "all";
        promptDlg.appendChild(a);
        return promptDlg;
    }
    show_prompter() {
        if (this.promptDlg == null) {
            this.promptDlg = this.defaultDlg();
            document.body.appendChild(this.promptDlg);
        }
        this.promptDlg.open = true;
    }
}

let instance = new BlsRuntime();

export function bls_runtime_input() {
    if (instance.input == null) {
        instance.show_prompter();
        return "cmd:yield";
    }
    return instance.input;
}

export function bls_runtime_info(s) {
    console.log(s)
}