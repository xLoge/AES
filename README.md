# AES
 
* I made this class to learn how AES works
* The class should have no errors, but if you find one please open a issue :)
* C++11 and above

# Usage

```
int main()
{
    uint8_t data[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    uint8_t key[16] = { 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 14 };
    uint8_t iv[16] = { 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 13 };

    constexpr AES::AES aes(AES::AES128);
    aes.encrypt_cbc(data, 16, key, iv);
}
```
