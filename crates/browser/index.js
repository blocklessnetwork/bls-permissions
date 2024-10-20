import {bls_check_read, set_prompter_dialog_class} from "./permissions.js"

class MyDialog {
    constructor(blsRuntime) {
        this.blsRuntime = blsRuntime;
        let promptDlg = document.createElement("dialog");
        promptDlg.style.color = "red";
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

set_prompter_dialog_class(MyDialog);

bls_check_read("/test.o", "permission").then((rs) =>{
    console.log(rs);
    let {code, msg} = rs;
    console.log(`code:${code} msg:${msg}` );
});