import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const keyPair=await webcrypto.subtle.generateKey({
    name:"RSA-OAEP",
    modulusLength:2048,
    publicExponent:new Uint8Array([0x01,0x00,0x01]),
    hash:"SHA-256",
  },
  true,
  ["encrypt","decrypt"]);
  return { publicKey:keyPair.publicKey, privateKey:keyPair.privateKey};
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exports=await webcrypto.subtle.exportKey("spki",key);
  return arrayBufferToBase64(exports);
}
// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key:webcrypto.CryptoKey|null
):Promise<string|null>{
  if (!key) return null;
  const exports=await webcrypto.subtle.exportKey("pkcs8",key);
  return arrayBufferToBase64(exports);
  }

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey:string
):Promise<webcrypto.CryptoKey>{
  const keyBuffer=base64ToArrayBuffer(strKey);
  const importedKey=await webcrypto.subtle.importKey(
    "spki",
    keyBuffer,
    {
      name:"RSA-OAEP",
      hash:"SHA-256"
    },
    true,
    ["encrypt"]
  );
  return importedKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey:string
):Promise<webcrypto.CryptoKey>{
  const keyBuffer=base64ToArrayBuffer(strKey);
  const importedKey=await webcrypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    true,
    ["decrypt"]
  );
  return importedKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data:string,
  strPublicKey:string
):Promise<string>{
  const publicKey=await importPubKey(strPublicKey);
  const dataBuffer=base64ToArrayBuffer(b64Data);
  const encryptedData=await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    publicKey,
    dataBuffer
  );
  const encryptedDataBuffer=new Uint8Array(encryptedData);
  const base64EncryptedData=arrayBufferToBase64(encryptedDataBuffer);
  return base64EncryptedData;

}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data:string,
  privateKey:webcrypto.CryptoKey
):Promise<string>{
  const dataBuffer=base64ToArrayBuffer(data);
  const decryptedData=await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    privateKey,
    dataBuffer
  );
  const decryptedDataBuffer=new Uint8Array(decryptedData);
  const base64DecryptedData=arrayBufferToBase64(decryptedDataBuffer);
  return base64DecryptedData;
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  const key=await webcrypto.subtle.generateKey(
    {
      name:"AES-CBC",
      length:256
    },
    true,
    ["encrypt","decrypt"]
  );
  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey=await webcrypto.subtle.exportKey("raw",key);
  const exportedKeyBuffer=new Uint8Array(exportedKey);
  const base64Key=arrayBufferToBase64(exportedKeyBuffer);
  return base64Key;
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey:string
):Promise<webcrypto.CryptoKey>{
  const keyBuffer=base64ToArrayBuffer(strKey);
  const importedKey=await webcrypto.subtle.importKey(
    "raw",
    keyBuffer,
    {
      name:"AES-CBC"
    },
    true,
    ["encrypt","decrypt"]
  );
  return importedKey;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  const iv=webcrypto.getRandomValues(new Uint8Array(16));
  const dataBuffer=new TextEncoder().encode(data);
  const encryptedData=await webcrypto.subtle.encrypt(
    {
      name:"AES-CBC",
      iv
    },
    key,
    dataBuffer
  );
  const encryptedDataBuffer=new Uint8Array(encryptedData);
  const base64EncryptedData=arrayBufferToBase64(encryptedDataBuffer);
  return base64EncryptedData;
  }

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  const iv=webcrypto.getRandomValues(new Uint8Array(16));
  const key=await importSymKey(strKey);
  const dataBuffer=base64ToArrayBuffer(encryptedData);
  const decryptedData=await webcrypto.subtle.decrypt(
    {
      name:"AES-CBC",
      iv
    },
    key,
    dataBuffer
  );
  const decryptedDataBuffer=new Uint8Array(decryptedData);
  const decryptedDataString=new TextDecoder().decode(decryptedDataBuffer)
  return "decryptedDataString";
}
