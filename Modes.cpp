#include "Modes.h"

std::vector<uint8_t> Modes::encryptECB(const std::vector<uint8_t>& plaintext, const AES128& aes) {
    std::vector<uint8_t> ciphertext;
    // TODO: Gérer le padding (ex: PKCS#7) si le texte clair n'est pas un multiple de 16 octets.
    // TODO: Boucler sur le plaintext par blocs de 16 octets.
    // TODO: Pour chaque bloc, appeler aes.encryptBlock() et ajouter le résultat à 'ciphertext'.
    return ciphertext;
}

std::vector<uint8_t> Modes::decryptECB(const std::vector<uint8_t>& ciphertext, const AES128& aes) {
    std::vector<uint8_t> plaintext;
    // TODO: Vérifier que la taille du ciphertext est un multiple de 16.
    // TODO: Boucler sur les blocs, appeler aes.decryptBlock().
    // TODO: Retirer le padding à la fin.
    return plaintext;
}

std::vector<uint8_t> Modes::computeCBCMAC(const std::vector<uint8_t>& message, const AES128& aes, const std::array<uint8_t, 16>& iv) {
    std::vector<uint8_t> mac(16);
    // TODO: Gérer le padding du message.
    // TODO: XORer le premier bloc de 16 octets avec l'IV.
    // TODO: Chiffrer ce bloc avec AES.
    // TODO: Pour les blocs suivants, XORer avec le bloc chiffré précédent, puis chiffrer.
    // TODO: Retourner UNIQUEMENT le dernier bloc chiffré (c'est ça le MAC).
    return mac;
}