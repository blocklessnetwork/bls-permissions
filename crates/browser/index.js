import {bls_check_read} from "./permissions.js"

bls_check_read("/test.o", "permission").then((rs) =>{
    console.log(rs);
    let {code, msg} = rs;
    console.log(`code:${code} msg:${msg}` );
});