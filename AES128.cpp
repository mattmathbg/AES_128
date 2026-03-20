#include "AES128.h"
#include "MathGF256.h"

// TODO: Initialiser les tableaux S_BOX, INV_S_BOX et RCON d'après la FIPS 197.

AES128::AES128(const std::vector<uint8_t>& key) {
    // TODO: Vérifier que la clé fait bien 16 octets
    keyExpansion(key);
}

void AES128::keyExpansion(const std::vector<uint8_t>& key) {
    // TODO: Copier la clé d'origine dans les 16 premiers octets de 'roundKeys'
    // TODO: Générer les 10 autres clés de ronde en utilisant rotWord, subWord et Rcon
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

// TODO: Implémenter toutes les fonctions privées (subBytes, shiftRows, mixColumns, etc.)
// Astuce pour mixColumns : Utilise la fonction multiply() du module MathGF256.