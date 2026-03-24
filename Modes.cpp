#include "Modes.h"
#include <stdexcept>

// ─── Helpers PKCS#7 ─────────────────────────────────────────────────────────

std::vector<uint8_t> Modes::pkcs7Pad(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> padded = data;
    uint8_t padValue = 16 - (data.size() % 16);
    for (int i = 0; i < padValue; i++) {
        padded.push_back(padValue);
    }
    return padded;
}

std::vector<uint8_t> Modes::pkcs7Unpad(const std::vector<uint8_t>& data) {
    if (data.empty() || data.size() % 16 != 0) {
        throw std::runtime_error("Erreur PKCS#7 : taille invalide.");
    }
    uint8_t padValue = data.back();
    if (padValue == 0 || padValue > 16) {
        throw std::runtime_error("Erreur PKCS#7 : valeur de padding invalide.");
    }
    for (size_t i = data.size() - padValue; i < data.size(); i++) {
        if (data[i] != padValue) {
            throw std::runtime_error("Erreur PKCS#7 : padding incohérent.");
        }
    }
    return std::vector<uint8_t>(data.begin(), data.end() - padValue);
}

// ─── ECB ─────────────────────────────────────────────────────────────────────

std::vector<uint8_t> Modes::encryptECB(const std::vector<uint8_t>& plaintext, const AES128& aes) {
    std::vector<uint8_t> padded = pkcs7Pad(plaintext);
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(padded.size());

    for (size_t i = 0; i < padded.size(); i += 16) {
        std::array<uint8_t, 16> block;
        for (int j = 0; j < 16; j++) block[j] = padded[i + j];
        aes.encryptBlock(block);
        for (int j = 0; j < 16; j++) ciphertext.push_back(block[j]);
    }
    return ciphertext;
}

std::vector<uint8_t> Modes::decryptECB(const std::vector<uint8_t>& ciphertext, const AES128& aes) {
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
        throw std::runtime_error("Erreur ECB : taille du chiffré invalide.");
    }
    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        std::array<uint8_t, 16> block;
        for (int j = 0; j < 16; j++) block[j] = ciphertext[i + j];
        aes.decryptBlock(block);
        for (int j = 0; j < 16; j++) plaintext.push_back(block[j]);
    }
    return pkcs7Unpad(plaintext);
}

// ─── MAC naïf ECB ────────────────────────────────────────────────────────────
//
// Principe : on chiffre le message bloc par bloc en ECB (avec padding PKCS#7),
// puis on retourne le DERNIER bloc chiffré comme tag d'authentification.
// C'est le "MAC naïf" : simple mais vulnérable (pas de chaînage entre blocs).

std::vector<uint8_t> Modes::computeECBMAC(const std::vector<uint8_t>& message, const AES128& aes) {
    std::vector<uint8_t> padded = pkcs7Pad(message);

    std::array<uint8_t, 16> lastBlock = {0};

    for (size_t i = 0; i < padded.size(); i += 16) {
        for (int j = 0; j < 16; j++) lastBlock[j] = padded[i + j];
        aes.encryptBlock(lastBlock);
    }

    // Le tag = dernier bloc chiffré
    return std::vector<uint8_t>(lastBlock.begin(), lastBlock.end());
}

// ─── CBC ─────────────────────────────────────────────────────────────────────

std::vector<uint8_t> Modes::encryptCBC(const std::vector<uint8_t>& plaintext, const AES128& aes, const std::array<uint8_t, 16>& iv) {
    std::vector<uint8_t> padded = pkcs7Pad(plaintext);
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(padded.size());

    std::array<uint8_t, 16> prev = iv;

    for (size_t i = 0; i < padded.size(); i += 16) {
        std::array<uint8_t, 16> block;
        for (int j = 0; j < 16; j++) block[j] = padded[i + j] ^ prev[j];
        aes.encryptBlock(block);
        for (int j = 0; j < 16; j++) ciphertext.push_back(block[j]);
        prev = block;
    }
    return ciphertext;
}

std::vector<uint8_t> Modes::decryptCBC(const std::vector<uint8_t>& ciphertext, const AES128& aes, const std::array<uint8_t, 16>& iv) {
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
        throw std::runtime_error("Erreur CBC : taille du chiffré invalide.");
    }
    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());

    std::array<uint8_t, 16> prev = iv;

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        std::array<uint8_t, 16> block;
        for (int j = 0; j < 16; j++) block[j] = ciphertext[i + j];
        std::array<uint8_t, 16> cipherBlock = block;
        aes.decryptBlock(block);
        for (int j = 0; j < 16; j++) plaintext.push_back(block[j] ^ prev[j]);
        prev = cipherBlock;
    }
    return pkcs7Unpad(plaintext);
}

// ─── CBC-MAC ─────────────────────────────────────────────────────────────────

std::vector<uint8_t> Modes::computeCBCMAC(const std::vector<uint8_t>& message, const AES128& aes, const std::array<uint8_t, 16>& iv) {
    std::vector<uint8_t> padded = pkcs7Pad(message);

    std::array<uint8_t, 16> currentBlock = iv;

    for (size_t i = 0; i < padded.size(); i += 16) {
        for (int j = 0; j < 16; j++) currentBlock[j] ^= padded[i + j];
        aes.encryptBlock(currentBlock);
    }

    return std::vector<uint8_t>(currentBlock.begin(), currentBlock.end());
}