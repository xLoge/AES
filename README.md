# AES
 
* I made this class to learn how AES works
* The class should have no errors, but if you find one please open a issue :)
* C++11 and above

# Usage

```
    uint8_t data[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x010, 0x011, 0x012, 0x013, 0x014, 0x015 };
    uint8_t key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x010, 0x011, 0x012, 0x013, 0x014, 0x015 };
    uint8_t iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x010, 0x011, 0x012, 0x013, 0x014, 0x015 };

    constexpr AES::AES aes(AES::AES128);
    aes.encrypt_cfb8(data, 16, key, iv);
```
