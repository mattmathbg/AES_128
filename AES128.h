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


    // Fonctions internes d'expansion de clé
    void keyExpansion(const std::vector<uint8_t>& key);

    // Transformations d'une ronde

    //Substitution octet par octet via la S-Box
    void subBytes(std::array<uint8_t, 16>& state) const;
    //décalage cyclique des lignes de la matrice état
    void shiftRows(std::array<uint8_t, 16>& state) const;
    //Mélange les colonnes (multiplication dans GF(2⁸))
    void mixColumns(std::array<uint8_t, 16>& state) const;
    //XOR de l'état avec la clé de ronde courante
    void addRoundKey(std::array<uint8_t, 16>& state, int round) const;

    // Transformations inverses
    void invSubBytes(std::array<uint8_t, 16>& state) const;
    void invShiftRows(std::array<uint8_t, 16>& state) const;
    void invMixColumns(std::array<uint8_t, 16>& state) const;
};

#endif // AES128_H