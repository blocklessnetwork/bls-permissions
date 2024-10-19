import { init_permissions_prompt, check_read } from './pkg';

init_permissions_prompt(true);

const YIELD = 255;

function yield_call(cb) {
    return new Promise((resolve) => {
        let ret = cb();
        if (ret.code == YIELD) {
            setTimeout(
                () => {
                    resolve(yield_call(cb));
                },
                500
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
    if (ret.code != 0) {
        console.log(ret.msg);
    } else {
        console.log(ret.code);
    }
    ret.free();
}
