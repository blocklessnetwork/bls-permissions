import { init_permissions_prompt, check_read } from './pkg';

init_permissions_prompt(true);

const YIELD = 255;
const YIELD_DELAY = 200;

function yield_callback(callback) {
    console.log("yield_callback.");
    return new Promise((resolve) => {
        let ret = callback();
        if (ret.code == YIELD) {
            setTimeout(
                () => {
                    resolve(yield_callback(callback));
                },
                YIELD_DELAY
            )
        } else {
            resolve(ret)
        }
    });
}

/// replace the default prometer dialog.
export function set_prompter_dialog_class(clz) {
    if (clz == null) {
        throw "invalid prompter dialog class."
    }
    window.BlsPrompterDialogClass = clz;
}

export async function bls_check_read(path, urlName) {
    let ret = await yield_callback(() => {
        return check_read(path, urlName);
    });
    let {code, msg} = ret;
    ret.free();
    return {code, msg};
}
