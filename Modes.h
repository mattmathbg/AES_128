#ifndef MODES_H
#define MODES_H

#include <vector>
#include <cstdint>
#include "AES128.h"

class Modes {
public:
    // Mode ECB - Chiffrement
    static std::vector<uint8_t> encryptECB(const std::vector<uint8_t>& plaintext, const AES128& aes);

    // Mode ECB - Déchiffrement
    static std::vector<uint8_t> decryptECB(const std::vector<uint8_t>& ciphertext, const AES128& aes);

    // Mode CBC-MAC - Génération du tag d'authentification
    static std::vector<uint8_t> computeCBCMAC(const std::vector<uint8_t>& message, const AES128& aes, const std::array<uint8_t, 16>& iv);
};

#endif // MODES_H