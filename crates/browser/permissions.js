import { init_permissions_prompt, check_read } from './pkg';

init_permissions_prompt(true);

const SUCCESS = 0;
const YIELD = 255;
const YIELD_DELAY = 200;

function yieldCallback(callback) {
    return new Promise((resolve) => {
        let ret = callback();
        let {code, msg} = ret;
        ret.free();
        if (code == YIELD) {
            setTimeout(
                () => {
                    resolve(yieldCallback(callback));
                },
                YIELD_DELAY
            )
        } else {
            if (msg == null) {
                msg = "success";
            }
            resolve({code, msg});
        }
    });
}

/// replace the default prometer dialog.
export function setPromptDialogClass(clz) {
    if (clz == null) {
        throw "invalid prompter dialog class."
    }
    window.BlsPrompterDialogClass = clz;
}

export async function blsCheckRead(path, urlName) {
    return await yieldCallback(() => {
        return check_read(path, urlName);
    });
}
