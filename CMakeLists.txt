cmake_minimum_required(VERSION 3.10)
project(AES_128)

set(CMAKE_CXX_STANDARD 20)

# Sources communes aux deux exécutables
set(COMMON_SRC
        MathGF256.cpp
        MathGF256.h
        AES128.cpp
        AES128.h
        Modes.cpp
        Modes.h
)

# Exécutable principal
add_executable(aes_app
        main.cpp
        ${COMMON_SRC}
)

set_target_properties(aes_app PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)

# Exécutable de tests (vecteurs FIPS 197 + NIST SP 800-38A)
add_executable(test_aes
        test_aes.cpp
        ${COMMON_SRC}
)