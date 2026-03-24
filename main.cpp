#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include "AES128.h"
#include "Modes.h"
#include <cstdlib>

void printUsage() {
    std::cout << "Usage: aes_app [action] [mode] [key_hex] [input_file] [output_file] [iv_hex]" << std::endl;
    std::cout << std::endl;
    std::cout << "Actions :" << std::endl;
    std::cout << "  -e   Chiffrement" << std::endl;
    std::cout << "  -d   Dechiffrement" << std::endl;
    std::cout << "  -m   Calcul du MAC" << std::endl;
    std::cout << std::endl;
    std::cout << "Modes :" << std::endl;
    std::cout << "  -ecb   Electronic Code Book" << std::endl;
    std::cout << "  -cbc   Cipher Block Chaining (iv_hex requis pour -e et -d)" << std::endl;
    std::cout << std::endl;
    std::cout << "Exemples :" << std::endl;
    std::cout << "  aes_app -e -ecb 2b7e151628aed2a6abf7158809cf4f3c message.txt cipher.bin" << std::endl;
    std::cout << "  aes_app -d -ecb 2b7e151628aed2a6abf7158809cf4f3c cipher.bin output.txt" << std::endl;
    std::cout << "  aes_app -m -ecb 2b7e151628aed2a6abf7158809cf4f3c message.txt mac.bin" << std::endl;
    std::cout << "  aes_app -e -cbc 2b7e151628aed2a6abf7158809cf4f3c message.txt cipher.bin 000102030405060708090a0b0c0d0e0f" << std::endl;
    std::cout << "  aes_app -d -cbc 2b7e151628aed2a6abf7158809cf4f3c cipher.bin output.txt 000102030405060708090a0b0c0d0e0f" << std::endl;
    std::cout << "  aes_app -m -cbc 2b7e151628aed2a6abf7158809cf4f3c message.txt mac.bin" << std::endl;
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i + 1 < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::array<uint8_t, 16> parseIV(int argc, char* argv[]) {
    std::array<uint8_t, 16> iv = {0};
    if (argc >= 7) {
        std::vector<uint8_t> ivBytes = hexToBytes(argv[6]);
        if (ivBytes.size() != 16) {
            throw std::runtime_error("L'IV doit faire exactement 16 octets (32 caracteres hexa).");
        }
        for (int i = 0; i < 16; i++) iv[i] = ivBytes[i];
    }
    return iv;
}

// Affiche un MAC en hex et l'écrit dans le fichier de sortie
void printMAC(const std::string& label, const std::vector<uint8_t>& mac) {
    std::cout << label << " : ";
    for (uint8_t b : mac) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::dec << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 6) {
        printUsage();
        return 1;
    }

    std::string action     = argv[1];
    std::string mode       = argv[2];
    std::string keyHex     = argv[3];
    std::string inputFile  = argv[4];
    std::string outputFile = argv[5];

    std::vector<uint8_t> keyBytes = hexToBytes(keyHex);
    if (keyBytes.size() != 16) {
        std::cerr << "Erreur : La cle doit faire exactement 16 octets (32 caracteres hexa)." << std::endl;
        return 1;
    }

    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Erreur : Impossible de lire le fichier " << inputFile << std::endl;
        return 1;
    }
    std::vector<uint8_t> inputData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();

    AES128 aes(keyBytes);
    std::vector<uint8_t> resultData;

    try {
        if (action == "-e" && mode == "-ecb") {
            resultData = Modes::encryptECB(inputData, aes);
            std::cout << "Chiffrement ECB termine." << std::endl;
        }
        else if (action == "-d" && mode == "-ecb") {
            resultData = Modes::decryptECB(inputData, aes);
            std::cout << "Dechiffrement ECB termine." << std::endl;
        }
        else if (action == "-m" && mode == "-ecb") {
            // MAC naïf ECB : dernier bloc chiffré du message paddé
            resultData = Modes::computeECBMAC(inputData, aes);
            printMAC("MAC naif ECB", resultData);
        }
        else if (action == "-e" && mode == "-cbc") {
            std::array<uint8_t, 16> iv = parseIV(argc, argv);
            resultData = Modes::encryptCBC(inputData, aes, iv);
            std::cout << "Chiffrement CBC termine." << std::endl;
        }
        else if (action == "-d" && mode == "-cbc") {
            std::array<uint8_t, 16> iv = parseIV(argc, argv);
            resultData = Modes::decryptCBC(inputData, aes, iv);
            std::cout << "Dechiffrement CBC termine." << std::endl;
        }
        else if (action == "-m" && mode == "-cbc") {
            std::array<uint8_t, 16> iv = parseIV(argc, argv);
            resultData = Modes::computeCBCMAC(inputData, aes, iv);
            printMAC("CBC-MAC", resultData);
        }
        else {
            std::cerr << "Action ou mode non supporte." << std::endl;
            printUsage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Erreur : " << e.what() << std::endl;
        return 1;
    }

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Erreur : Impossible d'ecrire dans le fichier " << outputFile << std::endl;
        return 1;
    }
    outFile.write(reinterpret_cast<const char*>(resultData.data()), resultData.size());
    outFile.close();

    return 0;
}