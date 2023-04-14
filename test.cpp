#include <stdint.h>
#include <iostream>
#include "AES.hpp"

template <size_t N>
auto to_array(const char (&str)[N]) 
{
    static_assert(N % 16 != 0, "String size not divisible by 16");
    AES::detail::array<uint8_t, N> data;
    for (size_t i = 0; i != N; ++i) {
        data[i] = str[i];
    }
    return data;
};

auto print_aes(const uint8_t* data, size_t size)
{
    std::cout << "00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F\n" << "------------------------------------------------\n";
	for (size_t i = 0; i != size; ++i) {
        const auto curr = (int)data[i];
        if (i % 8 == 0 && i != 0) {
            std::cout << ' ';
        }
        if (i % 16 == 0 && i != 0) {
            std::cout << '\n';
        }
        if (curr <= 0xF) {
            std::cout << '0';
        }
        std::cout << std::hex << curr << ' ';
	}
    std::cout << "\n\n";
};

int main()
{
    const auto DATASIZE = 16;

	auto data = to_array("SUPER SECURE ..."); // LEN 16
	auto key  = to_array("SUPER SECURE KEY"); // LEN 16
	auto iv   = to_array("SUPER SECURE IV "); // LEN 16

	AES::AES aes(AES::AES128);

    std::cout << "Plain:\n";
	print_aes(&data[0], DATASIZE);

	aes.encrypt_cbc(&data[0], DATASIZE, &key[0], &iv[0]);

	std::cout << "Encrypted:\n";
	print_aes(&data[0], DATASIZE);

	aes.decrypt_cbc(&data[0], DATASIZE, &key[0], &iv[0]);

	std::cout << "Decrypted:\n";
	print_aes(&data[0], DATASIZE);
}
