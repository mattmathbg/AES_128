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

// Principe :ECB est le mode le plus simple : chaque bloc de 16 octets
// est chiffré indépendamment avec la même clé, sans aucun lien avec les autres blocs.
// Le déchiffrement fonctionne de la même façon, bloc par bloc dans n'importe quel ordre.
//

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
    //Verifie que la taille du message chiffré est un multiple de 16 octets 
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
        throw std::runtime_error("Erreur ECB : taille du chiffré invalide.");
    }

    std::vector<uint8_t> plaintext;
    //Comme avant on reserve de la place pour le message déchiffré 
    plaintext.reserve(ciphertext.size());

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        // Copie de 16 octets chiffrés dans block
        std::array<uint8_t, 16> block;
        for (int j = 0; j < 16; j++) block[j] = ciphertext[i + j];
        // Déchiffrement AES du bloc
        aes.decryptBlock(block);
        // Copie des 16 octets déchiffrés dans plaintext
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
    // On s'assure que le message est un multiple de 16 octets
    std::vector<uint8_t> padded = pkcs7Pad(message);


    // lastBlock démarre à zéro, il va être écrasé à chaque itération
    // À la fin de la boucle il contiendra uniquement le DERNIER bloc chiffré
    std::array<uint8_t, 16> lastBlock = {0};

    //Chiffrement bloc par bloc 
    for (size_t i = 0; i < padded.size(); i += 16) {
          // On copie le bloc courant dans lastBlock (écrase le précédent)
        for (int j = 0; j < 16; j++) lastBlock[j] = padded[i + j];
        // On chiffre le bloc courant, le résultat écrase lastBlock
        aes.encryptBlock(lastBlock);
    }

    // Le tag = dernier bloc chiffré
    return std::vector<uint8_t>(lastBlock.begin(), lastBlock.end());
}


// Vérification du MAC : on recalcule le tag à partir du message et on compare avec le tag fourni
bool Modes::verifyECBMAC(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& tag,
                          const AES128& aes) {
    return Modes::computeECBMAC(message, aes) == tag;
}

// ─── CBC ─────────────────────────────────────────────────────────────────────
// CBC corrige le principal défaut d'ECB en introduisant
// un chaînage entre les blocs : avant d'être chiffré, chaque bloc est XORé avec
// le bloc chiffré précédent. Le premier bloc n'ayant pas de précédent, on utilise
// un vecteur d'initialisation (IV) aléatoire à la place. Ainsi, deux blocs
// identiques en clair produiront toujours deux blocs chiffrés différents, car
// ils n'ont pas le même historique de chaînage. Le déchiffrement fonctionne en
// sens inverse : on déchiffre chaque bloc AES puis on XOR avec le bloc chiffré
// précédent pour retrouver le plaintext. L'IV doit être le même au chiffrement
// et au déchiffrement, mais n'a pas besoin d'être secret.

std::vector<uint8_t> Modes::encryptCBC(const std::vector<uint8_t>& plaintext, const AES128& aes, const std::array<uint8_t, 16>& iv) {
    std::vector<uint8_t> padded = pkcs7Pad(plaintext);
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(padded.size());

    //bloc précédent utilisé pour le XOR avant chiffrement du bloc courant
    std::array<uint8_t, 16> prev = iv;

    for (size_t i = 0; i < padded.size(); i += 16) {
        std::array<uint8_t, 16> block;
        //on fait le XOR du bloc courant avec le bloc précédent 
        for (int j = 0; j < 16; j++) block[j] = padded[i + j] ^ prev[j];
        aes.encryptBlock(block);
        //ajout du bloc chiffré au résultat final
        for (int j = 0; j < 16; j++) ciphertext.push_back(block[j]);
        // Le bloc chiffré devient le précédent pour le prochain tour
        // C'est le chaînage : chaque bloc dépend du précédent
        prev = block;
    }
    return ciphertext;
}

std::vector<uint8_t> Modes::decryptCBC(const std::vector<uint8_t>& ciphertext, const AES128& aes, const std::array<uint8_t, 16>& iv) {
    // Le message chiffré doit obligatoirement être un multiple de 16
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
        throw std::runtime_error("Erreur CBC : taille du chiffré invalide.");
    }
    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());
    // Même IV que lors du chiffrement, obligatoire pour retrouver le premier bloc
    std::array<uint8_t, 16> prev = iv;

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        std::array<uint8_t, 16> block;
        for (int j = 0; j < 16; j++) block[j] = ciphertext[i + j];

        //On sauvegarde le bloc chiffré AVANT de le déchiffrer
        // car on en aura besoin comme précédent au prochain tour
        // Si on ne le sauvegarde pas, aes.decryptBlock(block) va l'écraser
        std::array<uint8_t, 16> cipherBlock = block;
        aes.decryptBlock(block);
        for (int j = 0; j < 16; j++) plaintext.push_back(block[j] ^ prev[j]);
        // Le bloc chiffré (sauvegardé) devient le nouveau précédent
        // On utilise le bloc CHIFFRÉ et non déchiffré, comme en encryptCBC
        prev = cipherBlock;
    }
    return pkcs7Unpad(plaintext);
}


// ─── CBC-MAC ─────────────────────────────────────────────────────────────────

std::vector<uint8_t> Modes::computeCBCMAC(const std::vector<uint8_t>& message, const AES128& aes, const std::array<uint8_t, 16>& iv) {
    std::vector<uint8_t> padded = pkcs7Pad(message);

    //currentBlock vaut au premier tour IV, ensuite il vaut le bloc chiffré précédent
    std::array<uint8_t, 16> currentBlock = iv;

    for (size_t i = 0; i < padded.size(); i += 16) {
        // XOR du bloc courant avec currentBlock (IV au premier tour,
        // bloc chiffré précédent aux tours suivants)
        // C'est le chaînage : chaque bloc dépend de tous les précédents
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