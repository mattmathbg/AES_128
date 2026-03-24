//
// Created by mmath on 20/03/2026.
//

#include "MathGF256.h"


uint8_t xtime(uint8_t x) {
    //je verifie si le bit tout a gauche est 1 (0x80 => 10000000)
    bool depassement = (x & 0x80) != 0;

    //je decale tout de 1 vers la gauche
    uint8_t resultat = x << 1;

    //si le bit tout a gauche etait 1 on XOR avec 0x1B (regle AES)
    if (depassement) {
        resultat = resultat ^ 0x1B;
    }
    return resultat;
}

uint8_t multiply(uint8_t x, uint8_t y) {
    uint8_t res = 0;
    for (int i = 0; i < 8; i++) {
        // Si le bit de poids faible de y est à 1, on ajoute x au résultat
        if (y & 0x1) {
            res ^= x;
        }
        // On prépare x pour le prochain tour en le multipliant par X dans GF(2^8)
        x = xtime(x);
        // On décale y vers la droite pour traiter le bit suivant au prochain tour
        y >>= 1;
    }
    return res;
}