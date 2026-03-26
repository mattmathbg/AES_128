#include "Modes.h"
#include <stdexcept>


//fait en sorte que la taille du message soit un multiple de 16 octets pour pouvoir le chiffrer avec AES-128 (bloc de 16 octets)
std::vector<uint8_t> Modes::pkcs7Pad(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> padded = data;
    uint8_t padValue = 16 - (data.size() % 16);
    for (int i = 0; i < padValue; i++) {
        padded.push_back(padValue);
    }
    return padded;
}

std::vector<uint8_t> Modes::pkcs7Unpad(const std::vector<uint8_t>& data) {
    //Verfie que la taille du message est un multiple de 16 et que le padding est valide
    if (data.empty() || data.size() % 16 != 0) {
        throw std::runtime_error("Erreur PKCS#7 : taille invalide.");
    }
    // padValue doit être entre 1 et 16 (jamais 0 et jamais plus de 16)
    uint8_t padValue = data.back();
    if (padValue == 0 || padValue > 16) {
        throw std::runtime_error("Erreur PKCS#7 : valeur de padding invalide.");
    }

    //verifie si tout les octets de padding ont la même valeur que padValue (faut que ce soit cohérent)
    for (size_t i = data.size() - padValue; i < data.size(); i++) {
        if (data[i] != padValue) {
            throw std::runtime_error("Erreur PKCS#7 : padding incohérent.");
        }
    }
    //on supprime le padding pour retourner le message original
    return std::vector<uint8_t>(data.begin(), data.end() - padValue);
}

// ─── ECB ─────────────────────────────────────────────────────────────────────

std::vector<uint8_t> Modes::encryptECB(const std::vector<uint8_t>& plaintext, const AES128& aes) {
    //on pad le message pour que sa taille soit un multiple de 16 octets
    std::vector<uint8_t> padded = pkcs7Pad(plaintext);

    std::vector<uint8_t> ciphertext;
    //on reserve de la place pour le messagechiffré (optimisation pour éviter les reallocations)
    ciphertext.reserve(padded.size());

    //on traite un bloc de 16 octets à la fois
    for (size_t i = 0; i < padded.size(); i += 16) {
        //on crée un tableau fixe de 16 octets pour le bloc courant
        std::array<uint8_t, 16> block;
        // Copie des 16 octets depuis padded vers block
        for (int j = 0; j < 16; j++) block[j] = padded[i + j];
        //on chiffre le bloc avec AES-128
        aes.encryptBlock(block);
        //on ajoute le bloc chiffré au résultat final
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

bool Modes::verifyECBMAC(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& tag,
                          const AES128& aes) {
    return Modes::computeECBMAC(message, aes) == tag;
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

bool Modes::verifyCBCMAC(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& tag,
                          const AES128& aes,
                          const std::array<uint8_t, 16>& iv) {
    return Modes::computeCBCMAC(message, aes, iv) == tag;
}