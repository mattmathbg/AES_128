#include <iostream>
#include <string>
#include <vector>
#include "AES128.h"
#include "Modes.h"

// TODO: Ajouter les bibliothèques pour lire/écrire des fichiers (fstream)

void printUsage() {
    std::cout << "Usage: aes_app [action] [mode] [key_hex] [input_file] [output_file] (iv_hex)" << std::endl;
    std::cout << "Actions: -e (encrypt), -d (decrypt), -m (mac)" << std::endl;
    std::cout << "Modes: -ecb, -cbc" << std::endl;
    // Exemple: ./aes_app -e -ecb 2b7e151628aed2a6abf7158809cf4f3c input.txt output.bin
}

int main(int argc, char* argv[]) {
    if (argc < 6) {
        printUsage();
        return 1;
    }

    std::string action = argv[1];
    std::string mode = argv[2];
    std::string keyHex = argv[3];
    std::string inputFile = argv[4];
    std::string outputFile = argv[5];

    // TODO: Convertir la clé hexadécimale (string) en std::vector<uint8_t>.

    // TODO: Lire le contenu du fichier d'entrée en binaire.

    // std::vector<uint8_t> keyBytes = ...;
    // AES128 aes(keyBytes);

    if (action == "-e" && mode == "-ecb") {
        // TODO: Appeler Modes::encryptECB
        // TODO: Écrire le résultat dans le fichier de sortie
        std::cout << "Chiffrement ECB termine." << std::endl;
    }
    else if (action == "-d" && mode == "-ecb") {
        // TODO: Appeler Modes::decryptECB
        // TODO: Écrire le résultat dans le fichier de sortie
        std::cout << "Dechiffrement ECB termine." << std::endl;
    }
    else if (action == "-m" && mode == "-cbc") {
        // TODO: Récupérer l'IV s'il est fourni (argv[6]), sinon utiliser un IV rempli de zéros.
        // TODO: Appeler Modes::computeCBCMAC
        // TODO: Afficher le MAC dans la console (en hexadécimal) et/ou l'écrire dans le fichier.
        std::cout << "Calcul du CBC-MAC termine." << std::endl;
    }
    else {
        std::cerr << "Action ou mode non supporte." << std::endl;
        printUsage();
    }

    return 0;
}