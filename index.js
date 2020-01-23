const config = {
  encoding: 'base64',
  salt: "89p7awp98zwagp9zgzp9n8ag4st83743rs8bzj73ut7879s8e3ef71fd3gfh7j1s3e7r1f3d8gft71a3s87d1fga38e7asr8ga3d8f7gs8dfgsd8gf7sdf8g7sd78g",
  iv: "a7sf5daf751",
}

const $config = document.querySelector('#config');
const $togglEncoding = document.querySelector('#toggle-encoding');
const $password = document.querySelector('#password');
const $plain = document.querySelector('#plain-in');
const $encrypted = document.querySelector('#encrypted');
const $decrypted = document.querySelector('#decrypted');
const $doEncrypt = document.querySelector('#do-encrypt');
const $doDecrypt = document.querySelector('#do-decrypt');

// for debuging
showConfig();

// register click handler
$togglEncoding.onclick = function encrypt(e) {
  e.preventDefault();
  config.encoding = config.encoding === 'base64' ? '' : 'base64';
  showConfig();
}
$doEncrypt.onclick = function encrypt(e) {
  e.preventDefault();
  let plain = str2ab($plain.value);
  encryptAlgo(plain, str2ab(config.salt), str2ab(config.iv))
    .then(cypher => {
      console.log({ cypher });
      $encrypted.value = encode(cypher)
    })
    .catch(err => {
      console.error(err)
      $encrypted.value = err;
    })
}
$doDecrypt.onclick = function decrypt(e) {
  e.preventDefault();
  let cypher = decode($encrypted.value);
  console.log({ cypher });
  decryptAlgo(cypher, str2ab(config.salt), str2ab(config.iv))
    .then(plaintext => {
      $decrypted.value = ab2str(plaintext)
    })
    .catch(err => {
      console.error(err)
      $decrypted.value = err;
    })
}


/**
 * Get some key material to use as input to the deriveKey method.
 * The key material is a password supplied by the user.
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
 */
function getKeyMaterial() {
  let password = $password.value;
  let enc = new TextEncoder();
  console.log({ encoded: enc.encode(password) })
  return window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
}

/**
 * encrypts plaintext with key derived from password
 * from https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey
 * @param {ArrayBuffer} plaintext 
 * @param {ArrayBuffer} salt 
 * @param {ArrayBuffer} iv 
 */
async function encryptAlgo(plaintext, salt, iv) {
  let keyMaterial = await getKeyMaterial();
  let key = await window.crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt: salt,
      "iterations": 100000,
      "hash": "SHA-256"
    },
    keyMaterial,
    { "name": "AES-GCM", "length": 256 },
    true,
    ["encrypt", "decrypt"]
  );

  return window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    plaintext
  );
}

/**
 * decrypts cypher with key derived from password
 * @param {ArrayBuffer} cypher 
 * @param {ArrayBuffer} salt 
 * @param {ArrayBuffer} iv 
 */
async function decryptAlgo(cypher, salt, iv) {
  let keyMaterial = await getKeyMaterial();
  let key = await window.crypto.subtle.deriveKey(
    {
      "name": "PBKDF2",
      salt: salt,
      "iterations": 100000,
      "hash": "SHA-256"
    },
    keyMaterial,
    { "name": "AES-GCM", "length": 256 },
    true,
    ["encrypt", "decrypt"]
  );

  return window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    cypher
  );
}

/**
 * helper for encoding ArrayBuffer by config.encoding
 * @param {String} a 
 */
function encode(a) {
  const formatter = config.encoding === 'base64' ? ab2b : ab2str;
  return formatter(a)
}

/**
 * helper for decoding String by config.encoding
 * @param {String} str 
 */
function decode(str) {
  const formatter = config.encoding === 'base64' ? b2ab : str2ab;
  return formatter(str)
}

/**
 * converts ArrayBuffer to String
 * @param {ArrayBuffer} buf 
 */
function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint16Array(buf));
}

/**
 * converts String to ArrayBuffer
 * @param {String} str 
 */
function str2ab(str) {
  const buf = new ArrayBuffer(str.length * 2); // 2 bytes for each char
  const bufView = new Uint16Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

/**
 * converts ArrayBuffer to base64 encoded String
 * @param {ArrayBuffer} buf 
 */
function ab2b(buf) {
  let binary = '';
  const bytes = new Uint8Array(buf);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

/**
 * converts base64 encoded String to ArrayBuffer
 * @param {String} str
 */
function b2ab(str) {
  const binary = window.atob(str);
  const buf = new ArrayBuffer(binary.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = binary.length; i < strLen; i++) {
    bufView[i] = binary.charCodeAt(i);
  }
  return buf;
}

function showConfig() {
  $config.innerHTML = JSON.stringify(config, null, 2)
  console.log({ config })
}