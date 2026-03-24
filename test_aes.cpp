#include <iostream>
#include <vector>
#include <array>
#include <iomanip>
#include <cassert>
#include "AES128.h"
#include "Modes.h"

// ─── Utilitaires ─────────────────────────────────────────────────────────────

std::vector<uint8_t> fromHex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        bytes.push_back((uint8_t) strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    }
    return bytes;
}

std::string toHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

std::string toHex(const std::array<uint8_t, 16>& block) {
    return toHex(std::vector<uint8_t>(block.begin(), block.end()));
}

bool testEqual(const std::string& label,
               const std::string& got,
               const std::string& expected) {
    bool ok = (got == expected);
    std::cout << (ok ? "[PASS] " : "[FAIL] ") << label << std::endl;
    if (!ok) {
        std::cout << "       Attendu : " << expected << std::endl;
        std::cout << "       Obtenu  : " << got       << std::endl;
    }
    return ok;
}

// ─── Tests FIPS 197 (Appendix B) ─────────────────────────────────────────────

/*
 * Source : FIPS 197, Appendix B
 * Clé     : 2b7e151628aed2a6abf7158809cf4f3c
 * Plaintext : 3243f6a8885a308d313198a2e0370734
 * Ciphertext : 3925841d02dc09fbdc118597196a0b32
 */
bool testFIPS197_AppendixB() {
    std::cout << "\n=== FIPS 197 Appendix B ===" << std::endl;
    bool pass = true;

    auto key   = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    auto plain = fromHex("3243f6a8885a308d313198a2e0370734");
    AES128 aes(key);

    // Chiffrement d'un bloc brut
    std::array<uint8_t, 16> block;
    for (int i = 0; i < 16; i++) block[i] = plain[i];
    aes.encryptBlock(block);
    pass &= testEqual("encryptBlock (FIPS B)", toHex(block), "3925841d02dc09fbdc118597196a0b32");

    // Déchiffrement : on repart du chiffré et on doit retrouver le plaintext
    aes.decryptBlock(block);
    pass &= testEqual("decryptBlock (FIPS B)", toHex(block), "3243f6a8885a308d313198a2e0370734");

    return pass;
}

/*
 * Source : FIPS 197, Appendix C.1
 * Clé     : 000102030405060708090a0b0c0d0e0f
 * Plaintext : 00112233445566778899aabbccddeeff
 * Ciphertext : 69c4e0d86a7b0430d8cdb78070b4c55a
 */
bool testFIPS197_AppendixC1() {
    std::cout << "\n=== FIPS 197 Appendix C.1 ===" << std::endl;
    bool pass = true;

    auto key   = fromHex("000102030405060708090a0b0c0d0e0f");
    auto plain = fromHex("00112233445566778899aabbccddeeff");
    AES128 aes(key);

    std::array<uint8_t, 16> block;
    for (int i = 0; i < 16; i++) block[i] = plain[i];
    aes.encryptBlock(block);
    pass &= testEqual("encryptBlock (FIPS C.1)", toHex(block), "69c4e0d86a7b0430d8cdb78070b4c55a");

    aes.decryptBlock(block);
    pass &= testEqual("decryptBlock (FIPS C.1)", toHex(block), "00112233445566778899aabbccddeeff");

    return pass;
}

// ─── Tests mode ECB (NIST SP 800-38A) ────────────────────────────────────────

/*
 * Source : NIST SP 800-38A, F.1.1 ECB-AES128
 * Clé     : 2b7e151628aed2a6abf7158809cf4f3c
 * Bloc 1 plaintext : 6bc1bee22e409f96e93d7e117393172a
 * Bloc 1 ciphertext : 3ad77bb40d7a3660a89ecaf32466ef97
 */
bool testECB() {
    std::cout << "\n=== Mode ECB (NIST SP 800-38A F.1) ===" << std::endl;
    bool pass = true;

    auto key = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    AES128 aes(key);

    // Deux blocs de 32 octets pour tester le multi-bloc
    auto plaintext = fromHex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    );
    auto expected = fromHex(
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
    );

    auto ciphertext = Modes::encryptECB(plaintext, aes);

    // encryptECB ajoute le padding : le résultat fait 3 blocs (2 blocs + 1 bloc de padding)
    // On compare seulement les 2 premiers blocs (les données)
    std::vector<uint8_t> cipherFirst32(ciphertext.begin(), ciphertext.begin() + 32);
    pass &= testEqual("encryptECB blocs 1-2",
                      toHex(cipherFirst32),
                      toHex(expected));

    // Déchiffrement complet round-trip
    auto decrypted = Modes::decryptECB(ciphertext, aes);
    pass &= testEqual("decryptECB round-trip",
                      toHex(decrypted),
                      toHex(plaintext));

    return pass;
}

// ─── Tests mode CBC (NIST SP 800-38A) ────────────────────────────────────────

/*
 * Source : NIST SP 800-38A, F.2.1 CBC-AES128
 * Clé     : 2b7e151628aed2a6abf7158809cf4f3c
 * IV      : 000102030405060708090a0b0c0d0e0f
 * Bloc 1 plaintext  : 6bc1bee22e409f96e93d7e117393172a
 * Bloc 1 ciphertext : 7649abac8119b246cee98e9b12e9197d
 */
bool testCBC() {
    std::cout << "\n=== Mode CBC (NIST SP 800-38A F.2) ===" << std::endl;
    bool pass = true;

    auto key = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    AES128 aes(key);

    std::array<uint8_t, 16> iv;
    auto ivBytes = fromHex("000102030405060708090a0b0c0d0e0f");
    for (int i = 0; i < 16; i++) iv[i] = ivBytes[i];

    auto plaintext = fromHex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
    );
    auto expected = fromHex(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
    );

    auto ciphertext = Modes::encryptCBC(plaintext, aes, iv);

    std::vector<uint8_t> cipherFirst32(ciphertext.begin(), ciphertext.begin() + 32);
    pass &= testEqual("encryptCBC blocs 1-2",
                      toHex(cipherFirst32),
                      toHex(expected));

    // Round-trip
    auto decrypted = Modes::decryptCBC(ciphertext, aes, iv);
    pass &= testEqual("decryptCBC round-trip",
                      toHex(decrypted),
                      toHex(plaintext));

    return pass;
}

// ─── Test padding PKCS#7 invalide ────────────────────────────────────────────

bool testBadPadding() {
    std::cout << "\n=== Validation padding PKCS#7 invalide ===" << std::endl;
    bool pass = true;

    auto key = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    AES128 aes(key);

    // Données corrompues (16 octets mais padding incohérent)
    std::vector<uint8_t> corrupted(16, 0xAA);
    bool threw = false;
    try {
        Modes::decryptECB(corrupted, aes);
    } catch (const std::exception&) {
        threw = true;
    }
    pass &= testEqual("decryptECB rejette padding invalide",
                      threw ? "true" : "false", "true");

    return pass;
}

// ─── Point d'entrée ──────────────────────────────────────────────────────────

int main() {
    int failures = 0;

    if (!testFIPS197_AppendixB()) failures++;
    if (!testFIPS197_AppendixC1()) failures++;
    if (!testECB()) failures++;
    if (!testCBC()) failures++;
    if (!testBadPadding()) failures++;

    std::cout << "\n==============================" << std::endl;
    if (failures == 0) {
        std::cout << "Tous les tests sont passes ✓" << std::endl;
    } else {
        std::cout << failures << " test(s) en echec ✗" << std::endl;
    }

    return failures == 0 ? 0 : 1;
}