class DefaultDlg {
    constructor(blsRuntime) {
        this.blsRuntime = blsRuntime;
        let promptDlg = document.createElement("dialog");
        let msg = document.createElement("div");
        if (this.blsRuntime.dialog_msg) {
            msg.innerHTML = this.blsRuntime.dialog_msg;
        }
        promptDlg.appendChild(msg);
        let y = document.createElement("button");
        y.innerText = "y";
        promptDlg.appendChild(y);
        let that = this;
        y.onclick = function() {
            blsRuntime.input = "y";
            that.open(false);
        };
        let n = document.createElement("button");
        n.innerText = "n";
        n.onclick = function() {
            blsRuntime.input = "n";
            that.open(false);
        };
        promptDlg.appendChild(n);
        let a = document.createElement("button");
        a.innerText = "A";
        a.onclick = function() {
            blsRuntime.input = "a";
            that.open(false);
        };
        promptDlg.appendChild(a);
        this.msgElm = msg;
        this.promptDlgElm = promptDlg;
        document.body.appendChild(promptDlg);
    }
    open(b) {
        this.promptDlgElm.open = b;
    }
    set_msg(b) {
        this.msgElm.innerHTML = b
    }
}

class BlsRuntime {
    constructor() {
        this.info_cache = [];
        this.input = null;
        this.yield = null;
        this.prompt_dlg = null;
        this.is_yielding = false;
    }
    set_dialog_msg(msg) {
        this.dialog_msg = msg;
        if (this.prompt_dlg) {
            this.prompt_dlg.set_msg(msg);
        }
    }
    show_prompter() {
        if (this.prompt_dlg == null) {
            this.prompt_dlg = new DefaultDlg(this);
        }
        this.prompt_dlg.open(true);
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
        let obj = JSON.parse(s);
        instance.set_dialog_msg(obj.dlg_html);
    }
}