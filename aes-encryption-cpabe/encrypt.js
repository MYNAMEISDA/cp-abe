const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// Load master key
const masterKey = JSON.parse(fs.readFileSync("masterKey.json", "utf-8"));
const sk = BigInt(masterKey.sk);
const g2 = BigInt(masterKey.g2);
const p = BigInt(masterKey.p);

// Users with access
const access_permission_users = ["User1", "User2", "User3"];

// Ensure encryptedfile folder exists
if (!fs.existsSync("encryptedfile")) {
    fs.mkdirSync("encryptedfile");
}

function hashAttribute(attribute, p) {
    const hash = crypto.createHash("sha256").update(attribute).digest("hex");
    return BigInt("0x" + hash) % p;
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

function generateUserKeys(users) {
    return users.map(user => {
        const H_attr = hashAttribute(user, p);
        const sk_plus_H = sk + H_attr;
        const sk_attr_inv = modInverse(sk_plus_H, p);
        const userKey = modPow(g2, sk_attr_inv, p);
        console.log(`🔑 Generated User Key for ${user}: ${userKey}`);
        return { user, key: userKey };
    });
}

function encryptAESKey(aesKey, users) {
    const userKeys = generateUserKeys(users);
    const ivKey = crypto.randomBytes(12);
    console.log("🌀 IV for AES Key Encryption:", ivKey.toString("hex"));

    let encryptedData = {};

    userKeys.forEach(({ user, key }) => {
        const userKeyHash = crypto.createHash("sha256").update(key.toString(), "utf-8").digest();
        console.log(`🔑 User Key Hash (Encryption) for ${user}:`, userKeyHash.toString("hex"));

        const cipher = crypto.createCipheriv("aes-256-gcm", userKeyHash, ivKey);
        let encryptedAESKey = cipher.update(aesKey);
        encryptedAESKey = Buffer.concat([encryptedAESKey, cipher.final()]);

        encryptedData[user] = {
            encryptedKey: encryptedAESKey.toString("hex"),
            iv: ivKey.toString("hex"),
            authTag: cipher.getAuthTag().toString("hex")
        };
    });

    fs.writeFileSync("encryptedfile/encryptedAES.json", JSON.stringify(encryptedData, null, 2), "utf-8");
    console.log("🔒 AES Key encrypted and stored.");
}

function encryptFile(inputFile) {
    try {
        const aesKey = crypto.randomBytes(32);
        console.log("🗝 AES Key (Plaintext):", aesKey.toString("hex"));

        encryptAESKey(aesKey, access_permission_users);

        const fileData = fs.readFileSync(inputFile);
        const ivFile = crypto.randomBytes(12);
        console.log("🌀 IV for File Encryption:", ivFile.toString("hex"));

        const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, ivFile);
        let encryptedFile = cipher.update(fileData);
        encryptedFile = Buffer.concat([encryptedFile, cipher.final()]);
        const authTag = cipher.getAuthTag();

        const outputFile = path.join("encryptedfile", path.basename(inputFile) + ".enc");
        fs.writeFileSync(outputFile, encryptedFile);
        fs.writeFileSync(outputFile + ".meta.json", JSON.stringify({
            iv: ivFile.toString("hex"),
            authTag: authTag.toString("hex")
        }, null, 2));

        console.log(`✅ File encrypted and saved as ${outputFile}`);
    } catch (error) {
        console.error("❌ Error during file encryption:", error);
    }
}

// Encrypt input.png
encryptFile("input.png");

