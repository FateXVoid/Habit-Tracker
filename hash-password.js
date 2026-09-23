const crypto=require('crypto');
const password=process.argv[2];
if(!password){console.error('Usage: node tools/hash-password.js "your-password"');process.exit(1)}
const salt=crypto.randomBytes(16);
const hash=crypto.scryptSync(password,salt,32,{N:16384,r:8,p:1});
console.log('DEV_PASSWORD_SALT_B64='+salt.toString('base64'));
console.log('DEV_PASSWORD_HASH_B64='+hash.toString('base64'));
