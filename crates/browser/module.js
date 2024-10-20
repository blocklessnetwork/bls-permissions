class DefaultDialog {
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
            blsRuntime.setInput("y");
            that.open(false);
        };
        let n = document.createElement("button");
        n.innerText = "n";
        n.onclick = function() {
            blsRuntime.setInput("n");
            that.open(false);
        };
        buttons.appendChild(n);
        let a = document.createElement("button");
        a.innerText = "A";
        a.onclick = function() {
            blsRuntime.setInput("A");
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
    setMsg(msg) {
        this.msgElm.innerHTML = msg;
    }
}

class BlsRuntime {
    constructor() {
        this.input = null;
        this.yield = null;
        this.promptDlg = null;
        this.dialogMsg = "";
        this.isYield = false;
    }
    setInput(b) {
        if (b != 'y' && b != 'Y' && b != 'n' && b != 'N' && b != 'A') {
            throw new "input must be y,n,A";
        }
        this.input = b;
    }
    setDialogMsg(msg) {
        this.dialogMsg = msg;
        if (this.promptDlg) {
            this.promptDlg.setMsg(msg);
        }
    }
    showDialog() {
        if (this.promptDlg == null) {
            let DialogClass = window.BlsPrompterDialogClass||DefaultDialog;
            this.promptDlg = new DialogClass(this);
            if (this.dialogMsg) {
                this.promptDlg.setMsg(this.dialogMsg);
            }
        }
        this.promptDlg.open(true);
    }
}

let instance = new BlsRuntime();

export function blsrtGetInput() {
    if (instance.input == null) {
        instance.isYield = true;
        instance.showDialog();
        return "cmd:yield";
    }
    instance.isYield = false;
    return instance.input;
}

export function blsrtSetPromptDlgInfo(s) {
    if (!instance.isYield) {
        let obj = JSON.parse(s);
        instance.setDialogMsg(obj['dlg_html']);
    }
}