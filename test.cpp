#include <iostream>
#include "AES.hpp"

template <class Ty>
void print_vec(const std::vector<Ty>& _vec)
{
    for (auto& o : _vec)
        std::cout << o;
}

int main()
{
    std::vector<std::uint8_t> key = AES::str_to_vec("Super Secure Password! that has to be this long of AES256\0\0\0\0\0\0\0"); // LEN MOD 16 // ALSO HAS TO BE 64 Bytes long
    std::vector<std::uint8_t> iv = AES::str_to_vec("Super Secure IV!"); // LEN 16
    std::vector<std::uint8_t> text_to_enc = AES::str_to_vec("Super Secret Message!"); // LEN MOD 16

    // Makes text mod 16 by adding 0 to end
    AES::make_cbc_ready(key);
    AES::make_cbc_ready(iv);
    AES::make_cbc_ready(text_to_enc);

    {
        // TEMPLATE AES
        AES::AES_T<AES::AES_256> aes;

        aes.set_key(key);
        aes.set_iv(iv);
        
        const std::vector<std::uint8_t> cipher = aes.encrypt_cbc(text_to_enc);
        const std::vector<std::uint8_t> decrypted = aes.decrypt_cbc(cipher);

        std::cout << "Template AES: \n";
        std::cout << " Encrypted: ";
        print_vec(cipher);
        std::cout << "\n";
        std::cout << " Decrypted: ";
        print_vec(decrypted);
        std::cout << "\n\n";
    }

    {
        // NORMAL AES
        AES::AES aes(AES::AES_256);

        aes.set_key(key);
        aes.set_iv(iv);

        const std::vector<std::uint8_t> cipher = aes.encrypt_cbc(text_to_enc);
        const std::vector<std::uint8_t> decrypted = aes.decrypt_cbc(cipher);

        std::cout << "Normal AES: \n";
        std::cout << " Encrypted: ";
        print_vec(cipher);
        std::cout << "\n";
        std::cout << " Decrypted: ";
        print_vec(decrypted);
        std::cout << "\n\n";
    }
}
