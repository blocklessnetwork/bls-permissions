import { init_permissions_prompt, check_read } from './pkg';

init_permissions_prompt(true);

const YIELD = 255;
const YIELD_DELAY = 200;

function yield_call(cb) {
    return new Promise((resolve) => {
        let ret = cb();
        if (ret.code == YIELD) {
            setTimeout(
                () => {
                    resolve(yield_call(cb));
                },
                YIELD_DELAY
            )
        } else {
            resolve(ret)
        }
    });
}

export async function bls_check_read(path, urlName) {
    let ret = await yield_call(() => {
        return check_read(path, urlName);
    });
    let {code, msg} = ret;
    ret.free();
    return {code, msg};
}
