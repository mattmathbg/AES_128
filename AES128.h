#ifndef AES128_H
#define AES128_H

#include <cstdint>
#include <vector>
#include <array>

class AES128 {
public:
    // Initialise l'AES avec la clé maître de 128 bits (16 octets)
    AES128(const std::vector<uint8_t>& key);

    // Chiffre un bloc de 16 octets
    void encryptBlock(std::array<uint8_t, 16>& block) const;

    // Déchiffre un bloc de 16 octets
    void decryptBlock(std::array<uint8_t, 16>& block) const;

private:
    std::array<uint8_t, 176> roundKeys; // 11 clés de ronde de 16 octets (176 octets)

    // TODO: Déclarer les tables constantes ici (S-Box, InvS-Box, Rcon)

    // Fonctions internes d'expansion de clé
    void keyExpansion(const std::vector<uint8_t>& key);
    uint32_t subWord(uint32_t word) const;
    uint32_t rotWord(uint32_t word) const;

    // Transformations d'une ronde
    void subBytes(std::array<uint8_t, 16>& state) const;
    void shiftRows(std::array<uint8_t, 16>& state) const;
    void mixColumns(std::array<uint8_t, 16>& state) const;
    void addRoundKey(std::array<uint8_t, 16>& state, int round) const;

    // Transformations inverses
    void invSubBytes(std::array<uint8_t, 16>& state) const;
    void invShiftRows(std::array<uint8_t, 16>& state) const;
    void invMixColumns(std::array<uint8_t, 16>& state) const;
};

#endif // AES128_H