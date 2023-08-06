const crypto = require("crypto");

// Generate ECC key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "secp256k1", // Use secp256k1 curve, commonly used in Bitcoin and Ethereum
});

// Function to generate a random symmetric encryption key
function generateSymmetricKey() {
  return crypto.randomBytes(32); // 32 bytes for AES-256
}

// Function to encrypt data using symmetric key (AES)
function encryptWithSymmetricKey(symmetricKey, plaintext) {
  const iv = crypto.randomBytes(16); // Initialization vector for AES
  const cipher = crypto.createCipheriv("aes-256-cbc", symmetricKey, iv);
  let encrypted = cipher.update(plaintext, "utf-8", "base64");
  encrypted += cipher.final("base64");
  return `${iv.toString("base64")}:${encrypted}`;
}

// Function to decrypt data using symmetric key (AES)
function decryptWithSymmetricKey(symmetricKey, encryptedData) {
  const [iv, data] = encryptedData
    .split(":")
    .map((part) => Buffer.from(part, "base64"));
  const decipher = crypto.createDecipheriv("aes-256-cbc", symmetricKey, iv);
  let decrypted = decipher.update(data, "base64", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}

// Encrypt "hello world" using hybrid encryption
const plaintext = "hello world";
const symmetricKey = generateSymmetricKey();
const encryptedData = encryptWithSymmetricKey(symmetricKey, plaintext);
console.log("Encrypted:", encryptedData);

// Decrypt the encrypted data using the symmetric key
const decryptedData = decryptWithSymmetricKey(symmetricKey, encryptedData);
console.log("Decrypted:", decryptedData);
