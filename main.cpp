#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include "AES128.h"
#include "Modes.h"
#include <cstdlib>

void printUsage() {
    std::cout << "Usage: aes_app [action] [mode] [key_hex] [input_file] [output_file] (iv_hex)" << std::endl;
    std::cout << "Actions: -e (encrypt), -d (decrypt), -m (mac)" << std::endl;
    std::cout << "Modes: -ecb, -cbc" << std::endl;
}

// Fonction utilitaire pour convertir une string Hex en vecteur d'octets
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

int main(int argc, char* argv[]) {
    if (argc < 6) {
        printUsage();
        return 1;
    }

    // ✅ CORRIGÉ : indices argv[1] à argv[5] étaient tous vides
    std::string action     = argv[1];
    std::string mode       = argv[2];
    std::string keyHex     = argv[3];
    std::string inputFile  = argv[4];
    std::string outputFile = argv[5];

    // Conversion de la clé
    std::vector<uint8_t> keyBytes = hexToBytes(keyHex);
    if (keyBytes.size() != 16) {
        std::cerr << "Erreur : La cle doit faire exactement 16 octets (32 caracteres hexa)." << std::endl;
        return 1;
    }

    // Lecture du fichier d'entrée en binaire
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Erreur: Impossible de lire le fichier " << inputFile << std::endl;
        return 1;
    }
    std::vector<uint8_t> inputData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    // Initialisation de l'AES
    AES128 aes(keyBytes);
    std::vector<uint8_t> resultData;

    // Exécution du mode choisi
    if (action == "-e" && mode == "-ecb") {
        resultData = Modes::encryptECB(inputData, aes);
        std::cout << "Chiffrement ECB termine." << std::endl;
    }
    else if (action == "-d" && mode == "-ecb") {
        resultData = Modes::decryptECB(inputData, aes);
        std::cout << "Dechiffrement ECB termine." << std::endl;
    }
    else if (action == "-m" && mode == "-cbc") {
        std::array<uint8_t, 16> iv = {0}; // IV par défaut (zéros)
        if (argc >= 7) {
            // ✅ CORRIGÉ : argv[6] était vide
            std::vector<uint8_t> ivBytes = hexToBytes(argv[6]);
            for (int i = 0; i < 16 && i < (int)ivBytes.size(); i++) iv[i] = ivBytes[i];
        }

        resultData = Modes::computeCBCMAC(inputData, aes, iv);

        std::cout << "Calcul du CBC-MAC termine. MAC : ";
        for (uint8_t b : resultData) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        std::cout << std::dec << std::endl;
    }
    else {
        std::cerr << "Action ou mode non supporte." << std::endl;
        printUsage();
        return 1;
    }

    // Écriture du fichier de sortie
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Erreur: Impossible d'ecrire dans le fichier " << outputFile << std::endl;
        return 1;
    }
    outFile.write(reinterpret_cast<const char*>(resultData.data()), resultData.size());
    outFile.close();

    return 0;
}