class DefaultDialog {
    constructor(blsRuntime) {
        this.blsRuntime = blsRuntime;
        let promptDlg = document.createElement("dialog");
        let msg = document.createElement("div");
        promptDlg.className = "promptDlg";
        promptDlg.appendChild(msg);
        let y = document.createElement("button");
        y.innerText = "y";
        let buttons = document.createElement("div");
        promptDlg.appendChild(buttons);
        buttons.className = "buttons";
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
        this.css();
    }
    css() {
        let style = document.querySelector('style.promptDlg')
        if (style == null) {
            style = document.createElement('style');
            style.innerHTML = `
            dialog.promptDlg {
                font-size:15px;
                color:red;
            }
            dialog.promptDlg .buttons button {
                margin-left: 3px;
                padding-left: 10px;
                padding-right: 10px;
            }
            dialog.promptDlg .buttons {
                margin-top: 5px;
            }    
            `;
            document.head.appendChild(style);
        }

    }
    open(b) {
        this.promptDlgElm.open = b;
    }
    setMsg(msg) {
        this.msgElm.innerHTML = msg;
    }
}

class DefaultTips {
    css() {
        let style = document.head.querySelector("style.blsTips");
        if (style == null) {
            let style = document.createElement("style");
            style.className = "blsTips";
            style.innerHTML = `
            div.blsTips {
                position:absolute;
                width: 300px;
                min-height: 35px;
                right: 10px;
                top: 10px;
                padding-left:10px;
                animation: hidetip 2.5s 1;
                padding-top: 5px;
                border-radius: 8px;
                font-size: 13px;
            }
            .successTips {
                background-color:darkgreen;
                color: white;
            }
            .failTips {
                background-color:darkred;
                color: white;
            }
            @keyframes hidetip {
                0% {
                    opacity: 1;
                    top: 10px;
                    display: block;
                }
                100% {
                    top: 100px;
                    opacity: 0.5;
                    display: none;
                }
            }
            `;
            document.head.appendChild(style);
        }
    }
    show(text, flag) {
        this.css();
        let div = document.createElement("div");
        flag = flag||false;
        div.className = "blsTips " + (flag?"successTips":"failTips") ;
        console.log(div.className);
        div.innerHTML = text;
        document.body.append(div);
        div.addEventListener("animationend", () => {
            document.body.removeChild(div);
        },false);
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
    showTips(text, flag) {
        let TipsClass = window.BlsTipsClass||DefaultTips;
        let tips = new TipsClass();
        tips.show(text, flag);
    }
}

let instance = new BlsRuntime();

export function blsRuntimeGetInput() {
    if (instance.input == null) {
        instance.isYield = true;
        instance.showDialog();
        return "cmd:yield";
    }
    instance.isYield = false;
    return instance.input;
}

export function blsRuntimeSetPromptDlgInfo(s) {
    if (!instance.isYield) {
        let obj = JSON.parse(s);
        instance.setDialogMsg(obj['dlg_html']);
    }
}
export function blsRuntimeShowTips(text, flag) {
    instance.showTips(text, flag);
}