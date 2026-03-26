# 🔐 AES-128 : Implémentation en C++

> **Description** : Ce projet est une implémentation "from scratch" de l'algorithme de chiffrement symétrique AES-128 (Advanced Encryption Standard) réalisée en C++. Il permet de chiffrer et déchiffrer des blocs de données de 128 bits.

## ✨ Fonctionnalités implémentées

L'algorithme respecte le standard AES et inclut les étapes clés suivantes :
* **Key Expansion** : Génération des sous-clés à partir de la clé principale de 128 bits.
* **Chiffrement (Encryption)** : Implémentation des rondes (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`).
* **Déchiffrement (Decryption)** : Implémentation des rondes inverses (`InvShiftRows`, `InvSubBytes`, `InvMixColumns`, `AddRoundKey`).

## 🛠️ Technologies utilisées

* **Langage :** C++
* **Bibliothèques :** Bibliothèque standard C++ (aucune dépendance externe requise)

## ⚙️ Comment compiler et tester le projet ?

Pour tester cette implémentation sur ta machine, tu dois disposer d'un compilateur C++ (comme `g++` ou `clang`).

1. **Cloner ce dépôt :**
   ```bash
   git clone [https://github.com/mattmathbg/AES_128.git](https://github.com/mattmathbg/AES_128.git)
   cd AES_128
   ```

2. **Compiler le code source :**
   *(Commande standard avec g++ - à adapter selon la structure exacte de tes fichiers)*
   ```bash
   g++ main.cpp AES128.cpp Modes.cpp MathGF256.cpp -o aes_app      
   ```

3. **Exécuter le programme :**
   ```bash
   Usage: aes_app [action] [mode] [key_hex] [input_file] [output_file] [iv_hex]
   ```

## 👨‍💻 Auteur

**Mattéo** - Étudiant en Informatique à l'Université de Lorraine.

* [Mon Profil GitHub](https://github.com/mattmathbg)
