#include "AES128.h"
#include "MathGF256.h"

// Table de substitution (S-Box) de l'AES
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Constantes de ronde (Rcon)
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


void AES128::encryptBlock(std::array<uint8_t, 16>& state) const {
    // 1. Initialisation : XOR avec la clé de base (ronde 0)
    addRoundKey(state, 0);

    // 2. Les 9 rondes principales
    for (int round = 1; round <= 9; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, round);
    }

    // 3. La 10ème et dernière ronde (ATTENTION : pas de mixColumns !)
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, 10);
}

void AES128::keyExpansion(const std::vector<uint8_t>& key) {
    // 1. On copie la clé secrète dans les 16 premiers octets
    for (int i = 0; i < 16; i++) {
        roundKeys[i] = key[i];
    }

    int bytesGenerated = 16;
    int rconIndex = 1;
    uint8_t temp[4];

    while (bytesGenerated < 176) {
        // A. Prendre les 4 derniers octets générés
        temp[0] = roundKeys[bytesGenerated - 4];
        temp[1] = roundKeys[bytesGenerated - 3];
        temp[2] = roundKeys[bytesGenerated - 2];
        temp[3] = roundKeys[bytesGenerated - 1];

        // B. Tous les 16 octets, on fait le brassage spécial !
        if (bytesGenerated % 16 == 0) {
            // Étape RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // Étape SubWord
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            // Étape Rcon
            temp[0] ^= rcon[rconIndex];
            rconIndex++;
        }

        // C. On XOR avec l'octet qui se trouve 16 positions en arrière
        roundKeys[bytesGenerated]     = roundKeys[bytesGenerated - 16] ^ temp[0];
        roundKeys[bytesGenerated + 1] = roundKeys[bytesGenerated - 15] ^ temp[1];
        roundKeys[bytesGenerated + 2] = roundKeys[bytesGenerated - 14] ^ temp[2];
        roundKeys[bytesGenerated + 3] = roundKeys[bytesGenerated - 13] ^ temp[3];

        bytesGenerated += 4;
    }
}

void AES128::encryptBlock(std::array<uint8_t, 16>& state) const {
    // TODO: Implémenter l'algorithme de chiffrement (Cipher) FIPS 197
    // 1. addRoundKey(state, 0)
    // 2. Boucle de la ronde 1 à 9 : subBytes, shiftRows, mixColumns, addRoundKey
    // 3. Ronde 10 (finale) : subBytes, shiftRows, addRoundKey (pas de mixColumns !)
}

void AES128::decryptBlock(std::array<uint8_t, 16>& state) const {
    // TODO: Implémenter l'algorithme de déchiffrement (InvCipher)
    // Attention à l'ordre inversé des opérations et à l'utilisation des clés de la dernière à la première.
}

void AES128::subBytes(std::array<uint8_t, 16>& state) const {
    //pour chaque bytes on prend son equivalent dans la table sbox
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

void AES128::addRoundKey(std::array<uint8_t, 16>& state, int round) const {
    // Le décalage (offset) permet de trouver la bonne clé dans notre grand tableau de 176 octets
    int offset = round * 16;

    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKeys[offset + i]; // XOR entre l'état et la clé de ronde
    }
}

void AES128::shiftRows(std::array<uint8_t, 16>& state) const {
    uint8_t temp;

    // Ligne 0 : Inchangée (indices 0, 4, 8, 12)

    // Ligne 1 : Décalage de 1 vers la gauche (indices 1, 5, 9, 13)
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Ligne 2 : Décalage de 2 vers la gauche (indices 2, 6, 10, 14)
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Ligne 3 : Décalage de 3 vers la gauche (indices 3, 7, 11, 15)
    // Astuce : Décaler de 3 à gauche = décaler de 1 à droite !
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

void AES128::mixColumns(std::array<uint8_t, 16>& state) const {
    // On boucle sur les 4 colonnes
    for (int i = 0; i < 4; i++) {
        int c = i * 4; // Indice de départ de la colonne (0, 4, 8 ou 12)

        // On sauvegarde la colonne d'origine avant de l'écraser
        uint8_t s0 = state[c];
        uint8_t s1 = state[c + 1];
        uint8_t s2 = state[c + 2];
        uint8_t s3 = state[c + 3];

        // On applique les formules en utilisant la fonction multiply !
        state[c]     = multiply(s0, 0x02) ^ multiply(s1, 0x03) ^ s2 ^ s3;
        state[c + 1] = s0 ^ multiply(s1, 0x02) ^ multiply(s2, 0x03) ^ s3;
        state[c + 2] = s0 ^ s1 ^ multiply(s2, 0x02) ^ multiply(s3, 0x03);
        state[c + 3] = multiply(s0, 0x03) ^ s1 ^ s2 ^ multiply(s3, 0x02);
    }
}