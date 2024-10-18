import { init_permissions_prompt, check_read } from './pkg';

init_permissions_prompt(true);

let ret = check_read("/test.o","Permision");
if (ret.code != 0) {
    console.log(ret.msg);
} else {
    console.log(ret.code);
}
ret.free();


