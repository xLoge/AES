#include <stdint.h>
#include <iostream>
#include "AES.hpp"

void print_block(const uint8_t* data, size_t size)
{
    std::cout << "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F\n" << "------------------------------------------------\n";
	for (size_t i = 0; i != size; ++i) {
        const int curr = static_cast<int>(data[i]);
        if (i && i % 8 == 0) {
            std::cout << ' ';
        }
        if (i && i % 16 == 0) {
            std::cout << '\n';
        }
        if (curr <= 0xF) {
            std::cout << '0';
        }
        std::cout << std::uppercase << std::hex << curr << ' ';
	}
    std::cout << "\n\n";
};

// Verify: https://emn178.github.io/online-tools/aes/encrypt/?input=6BC1BEE22E409F96E93D7E117393172A6BC1BEE22E409F96E93D7E117393172A6BC1BEE22E409F96E93D7E117393172A&source=text&input_type=hex&output_type=hex&key_size=128&mode=CBC&padding=NoPadding&key_type=custom&passphrase=2B7E151628AED2A6ABF7158809CF4F3C&hash=SHA384&salt_type=random&salt_input_type=utf-8&custom_iteration_enabled=1&iteration=0&key_input_type=hex&key=2B7E151628AED2A6ABF7158809CF4F3C&iv_input_type=hex&iv=000102030405060708090A0B0C0D0E0F

int main()
{
    uint8_t data[] = { 
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
        0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A
    };
    uint8_t key[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
    uint8_t iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    AES::AES128 aes;
    aes.encrypt_cbc(data, data, sizeof(data), key, iv);

    print_block(data, sizeof(data));
}
