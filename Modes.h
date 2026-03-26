#ifndef MODES_H
#define MODES_H

#include <vector>
#include <cstdint>
#include <stdexcept>
#include "AES128.h"

class Modes {
public:
    // Mode ECB - Chiffrement
    static std::vector<uint8_t> encryptECB(const std::vector<uint8_t>& plaintext, const AES128& aes);

    // Mode ECB - Déchiffrement
    static std::vector<uint8_t> decryptECB(const std::vector<uint8_t>& ciphertext, const AES128& aes);

    // Mode CBC - Chiffrement
    static std::vector<uint8_t> encryptCBC(const std::vector<uint8_t>& plaintext, const AES128& aes, const std::array<uint8_t, 16>& iv);

    // Mode CBC - Déchiffrement
    static std::vector<uint8_t> decryptCBC(const std::vector<uint8_t>& ciphertext, const AES128& aes, const std::array<uint8_t, 16>& iv);

    // MAC naïf ECB : chiffrement ECB du message, le dernier bloc chiffré est le tag
    static std::vector<uint8_t> computeECBMAC(const std::vector<uint8_t>& message, const AES128& aes);

    static bool verifyECBMAC(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& tag,
                          const AES128& aes);

    // Mode CBC-MAC - Génération du tag d'authentification
    static std::vector<uint8_t> computeCBCMAC(const std::vector<uint8_t>& message, const AES128& aes, const std::array<uint8_t, 16>& iv);

    static bool verifyCBCMAC(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& tag,
                          const AES128& aes,
                          const std::array<uint8_t, 16>& iv);
private:
    // Helpers PKCS#7
    static std::vector<uint8_t> pkcs7Pad(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> pkcs7Unpad(const std::vector<uint8_t>& data);
};

#endif // MODES_H