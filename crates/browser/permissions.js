import { 
    init_permissions_prompt, check_read, check_env, check_write,check_net, check_net_url 
} from './pkg';

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

/// replace the default prometer dialog.
export function setTipsClass(clz) {
    if (clz == null) {
        throw "invalid tips class."
    }
    window.BlsTipsClass = clz;
}

export function setTipClass(clz) {
    if (clz == null) {
        throw "invalid tip class."
    }
    window.BlsTipClass = clz;
}

export async function blsCheckRead(path, apiName) {
    return await yieldCallback(() => {
        return check_read(path, apiName);
    });
}

export async function blsCheckWrite(path, apiName) {
    return await yieldCallback(() => {
        return check_write(path, apiName);
    });
}

export async function blsCheckNet(net, apiName) {
    return await yieldCallback(() => {
        return check_net(net, apiName);
    });
}

export async function blsCheckNetUrl(url, apiName) {
    return await yieldCallback(() => {
        return check_net_url(url, apiName);
    });
}

export async function blsEnv(env, apiName) {
    return await yieldCallback(() => {
        return check_env(env, apiName);
    });
}