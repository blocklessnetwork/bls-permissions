class BlsRuntime {
    constructor() {
        this.info_cache = [];
        this.input = null;
        this.yield = null;
        this.promptDlg = null;
        this.is_yielding = false;
    }
    defaultDlg() {
        let promptDlg = document.createElement("dialog");
        let msg = document.createElement("p");
        promptDlg.appendChild(msg);
        let y = document.createElement("button");
        y.innerText = "yes";
        promptDlg.appendChild(y);
        let that = this;
        y.onclick = function() {
            that.input = "y";
            promptDlg.open = false;
        };
        let n = document.createElement("button");
        n.innerText = "no";
        n.onclick = function() {
            that.input = "n";
            promptDlg.open = false;
        };
        promptDlg.appendChild(n);
        let a = document.createElement("button");
        a.innerText = "all";
        a.onclick = function() {
            that.input = "a";
            promptDlg.open = false;
        };
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
        instance.is_yielding = true;
        instance.show_prompter();
        return "cmd:yield";
    }
    instance.is_yielding = false;
    return instance.input;
}

export function bls_runtime_prompt_dlg_info(s) {
    if (!instance.is_yielding) {
        console.log(s);
    }
}