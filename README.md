# AES

* Please note that this is a rewritten version of [SergeyBel AES](https://github.com/SergeyBel/AES)

## Usage

```
#include <iostream>
#include "AES.hpp"

int main()
{
    AES::AES_T<AES::AES_256> aes;

    aes.set_random_key();
    aes.set_random_iv();

    auto plain = AES::str_to_vec("Hello World!");
    AES::make_cbc_ready(plain);

    auto enc = aes.encrypt_cbc(plain);

    std::cout << "Key: " << aes.key().data() << " | Len: " << aes.key().size() << "\n";
    std::cout << "Iv: " << aes.iv().data() << " | Len: " << aes.iv().size() << "\n";
    std::cout << "\n";
    std::cout << "Encrypted: " << enc.data() << "\n";
    std::cout << "Decrypted: " << aes.decrypt_cbc(enc).data() << "\n";

    return 0;
}
```
