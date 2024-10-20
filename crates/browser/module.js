class DefaultDlg {
    constructor(blsRuntime) {
        this.blsRuntime = blsRuntime;
        let promptDlg = document.createElement("dialog");
        let msg = document.createElement("div");
        
        promptDlg.appendChild(msg);
        let y = document.createElement("button");
        y.innerText = "y";
        let buttons = document.createElement("div");
        promptDlg.appendChild(buttons);
        buttons.style.textAlign = "center";
        buttons.appendChild(y);
        let that = this;
        y.onclick = function() {
            blsRuntime.set_input("y");
            that.open(false);
        };
        let n = document.createElement("button");
        n.innerText = "n";
        n.onclick = function() {
            blsRuntime.set_input("n");
            that.open(false);
        };
        buttons.appendChild(n);
        let a = document.createElement("button");
        a.innerText = "A";
        a.onclick = function() {
            blsRuntime.set_input("A");
            that.open(false);
        };
        buttons.appendChild(a);
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
    set_input(b) {
        if (b != 'y' && b != 'Y' && b != 'n' && b != 'N' && b != 'A') {
            throw new "input must be y,n,A";
        }
        this.input = b;
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
            if (this.dialog_msg) {
                this.prompt_dlg.set_msg(this.dialog_msg);
            }
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