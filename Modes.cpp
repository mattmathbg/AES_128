#include "Modes.h"

std::vector<uint8_t> Modes::encryptECB(const std::vector<uint8_t>& plaintext, const AES128& aes) {
    std::vector<uint8_t> padded = plaintext;

    // Padding PKCS#7
    uint8_t padValue = 16 - (plaintext.size() % 16);
    for (int i = 0; i < padValue; i++) {
        padded.push_back(padValue);
    }

    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(padded.size());

    // Chiffrement bloc par bloc
    for (size_t i = 0; i < padded.size(); i += 16) {
        std::array<uint8_t, 16> block;
        for (int j = 0; j < 16; j++) block[j] = padded[i + j];

        aes.encryptBlock(block);

        for (int j = 0; j < 16; j++) ciphertext.push_back(block[j]);
    }
    return ciphertext;
}

std::vector<uint8_t> Modes::decryptECB(const std::vector<uint8_t>& ciphertext, const AES128& aes) {
    std::vector<uint8_t> plaintext;
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) return plaintext;

    plaintext.reserve(ciphertext.size());

    // Déchiffrement bloc par bloc
    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        std::array<uint8_t, 16> block;
        for (int j = 0; j < 16; j++) block[j] = ciphertext[i + j];

        aes.decryptBlock(block);

        for (int j = 0; j < 16; j++) plaintext.push_back(block[j]);
    }

    // Retrait du Padding PKCS#7
    if (!plaintext.empty()) {
        uint8_t padValue = plaintext.back();
        if (padValue > 0 && padValue <= 16) {
            plaintext.erase(plaintext.end() - padValue, plaintext.end());
        }
    }
    return plaintext;
}

std::vector<uint8_t> Modes::computeCBCMAC(const std::vector<uint8_t>& message, const AES128& aes, const std::array<uint8_t, 16>& iv) {
    std::vector<uint8_t> padded = message;

    // Padding PKCS#7
    uint8_t padValue = 16 - (message.size() % 16);
    for (int i = 0; i < padValue; i++) {
        padded.push_back(padValue);
    }

    std::array<uint8_t, 16> currentBlock = iv; // On commence par l'IV

    for (size_t i = 0; i < padded.size(); i += 16) {
        // XOR avec le bloc précédent (ou l'IV)
        for (int j = 0; j < 16; j++) {
            currentBlock[j] ^= padded[i + j];
        }

        // Chiffrement du bloc
        aes.encryptBlock(currentBlock);
    }

    // Le MAC est le tout dernier bloc chiffré
    std::vector<uint8_t> mac(currentBlock.begin(), currentBlock.end());
    return mac;
}