const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Load master key
const masterKey = JSON.parse(fs.readFileSync("masterKey.json", "utf-8"));
const sk = BigInt(masterKey.sk);
const g2 = BigInt(masterKey.g2);
const p = BigInt(masterKey.p);

// Ensure decryptedfile folder exists
if (!fs.existsSync("decryptedfile")) {
    fs.mkdirSync("decryptedfile");
}

function modPow(base, exp, mod) {
    let result = BigInt(1);
    base = base % mod;
    while (exp > 0) {
        if (exp % BigInt(2) === BigInt(1)) {
            result = (result * base) % mod;
        }
        exp = exp / BigInt(2);
        base = (base * base) % mod;
    }
    return result;
}

function modInverse(a, p) {
    let [m0, x0, x1] = [p, BigInt(0), BigInt(1)];
    if (p === BigInt(1)) return BigInt(0);

    while (a > 1) {
        let q = a / p;
        [p, a] = [a % p, p];
        [x0, x1] = [x1 - q * x0, x0];
    }

    if (x1 < 0) x1 += m0;
    return x1;
}

function hashAttribute(attribute, p) {
    const hash = crypto.createHash("sha256").update(attribute).digest("hex");
    return BigInt("0x" + hash) % p;
}

function generateUserKey(user) {
    const H_attr = hashAttribute(user, p);
    const sk_plus_H = sk + H_attr;
    const sk_attr_inv = modInverse(sk_plus_H, p);
    const userKey = modPow(g2, sk_attr_inv, p);
    console.log(`🔑 Generated User Key for ${user}: ${userKey}`);
    return userKey;
}

function decryptAESKey(user, encryptedData) {
    if (!encryptedData[user]) {
        console.error("❌ User not authorized!");
        return null;
    }

    const userKey = generateUserKey(user);
    const userKeyHash = crypto.createHash("sha256").update(userKey.toString(), "utf-8").digest();
    console.log("🔑 User Key Hash (Decryption):", userKeyHash.toString("hex"));

    const iv = Buffer.from(encryptedData[user].iv, "hex");
    const authTag = Buffer.from(encryptedData[user].authTag, "hex");
    const encryptedKey = Buffer.from(encryptedData[user].encryptedKey, "hex");

    try {
        const decipher = crypto.createDecipheriv("aes-256-gcm", userKeyHash, iv);
        decipher.setAuthTag(authTag);
        let decryptedAESKey = decipher.update(encryptedKey);
        decryptedAESKey = Buffer.concat([decryptedAESKey, decipher.final()]);

        console.log("🔓 Successfully decrypted AES key:", decryptedAESKey.toString("hex"));
        return decryptedAESKey;
    } catch (error) {
        console.log("❌ Decryption failed.");
        return null;
    }
}

function decryptFile(user, encryptedFile) {
    const encryptedAESData = JSON.parse(fs.readFileSync("encryptedfile/encryptedAES.json", "utf-8"));
    const decryptedAESKey = decryptAESKey(user, encryptedAESData);

    if (!decryptedAESKey) return;

    const metadata = JSON.parse(fs.readFileSync(encryptedFile + ".meta.json", "utf-8"));
    const ivFile = Buffer.from(metadata.iv, "hex");
    const authTag = Buffer.from(metadata.authTag, "hex");
    const encryptedData = fs.readFileSync(encryptedFile);

    const decipher = crypto.createDecipheriv("aes-256-gcm", decryptedAESKey, ivFile);
    decipher.setAuthTag(authTag);
    let decryptedFile = decipher.update(encryptedData);
    decryptedFile = Buffer.concat([decryptedFile, decipher.final()]);

    const outputFile = path.join("decryptedfile", path.basename(encryptedFile, ".enc"));
    fs.writeFileSync(outputFile, decryptedFile);
    console.log(`✅ File decrypted and saved as ${outputFile}`);
}

// Decrypt file
decryptFile("User2", "encryptedfile/input.png.enc");

