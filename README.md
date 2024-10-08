# AES
 
* I made this class to learn how AES works
* The class should have no errors, but if you find one please [open a issue](../../issues/new/choose) :smile:
* Lightweight
* **C++11**

# Usage Example

```C++
int main()
{
    uint8_t data[16] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };
    uint8_t key[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
    uint8_t iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    AES::AES128 aes;
    aes.encrypt_cbc(data, 16, key, iv);
}
```

**Output: {** ```76 49 AB AC 81 19 B2 46  CE E9 8E 9B 12 E9 19 7D``` **}**

# Size
Size with the [Usage](../../../AES#usage) example.

```
$ g++ -std=c++11 -Os -o AES main.cpp
$ size AES.o        
   text    data     bss     dec     hex   filename
   2069     616       8    2693     a85   AES
```

# Speed
Tested on Intel i5 12400F | AES128 | C++23 | 512MB | CBC-Mode:
```
$ g++  (12.2) -Ofast | around 220MBs
$ MSVC (2022) /O2    | around 172MBs
```
