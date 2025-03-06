const crypto = require('crypto');
const fs = require('fs');

// Define a large prime number `p` (BLS12-381 prime order)
const p = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

// Function for modular exponentiation: (base^exp) % mod
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

// Function to generate a random BigInt in the range [1, max)
function randomBigInt(max) {
    let bytes = Math.ceil(max.toString(2).length / 8); // Bytes needed
    let randomValue;
    do {
        randomValue = BigInt('0x' + crypto.randomBytes(bytes).toString('hex'));
    } while (randomValue >= max || randomValue === BigInt(0)); // Ensure within range
    return randomValue;
}

// Generate master secret key (MSK)
const sk = randomBigInt(p); // sk ∈ Zp

// Generate public parameters
const g = randomBigInt(p); // Random generator in the group
const pk = modPow(g, sk, p); // pk = g^sk mod p

// Define generators g1 and g2
const g1 = modPow(g, BigInt(2), p);  // g1 = g^2 mod p
const g2 = modPow(g, sk, p);         // g2 = g^sk mod p

// Save the keys to a file
const masterKey = { 
    sk: sk.toString(), 
    pk: pk.toString(), 
    g1: g1.toString(), 
    g2: g2.toString(), 
    p: p.toString() 
};

fs.writeFileSync('masterKey.json', JSON.stringify(masterKey, null, 2), 'utf-8');

console.log("Master Key saved to masterKey.json:", masterKey);

