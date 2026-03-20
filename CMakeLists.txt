cmake_minimum_required(VERSION 4.1)
project(projet)

set(CMAKE_CXX_STANDARD 20)

add_executable(projet main.cpp
        MathGF256.cpp
        MathGF256.h
        AES128.cpp
        AES128.h
        Modes.cpp
        Modes.h)
