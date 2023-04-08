# AES
 
* I made this class to learn how AES works
* The class should have no errors, but if you find one please open a issue :)
* C++14 or above

# Usage

Here is an example:

```
int main()
{
	auto print_matrix = [](const uint8_t* matrix, size_t x, size_t y) {
		for (size_t i = 0; i < x; ++i) {
			for (size_t j = 0; j < y; ++j) {
				if (matrix[i + j * 4] <= 0xF) { std::cout << '0'; }
				std::cout << std::hex << (int)matrix[i + j * 4] << ' ';
			}
			std::cout << '\n';
		}
	};

	uint8_t data[16] = { 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
	const uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	const uint8_t iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	AES::AES aes(AES::AES128);

	aes.encrypt_cbc(data, 16, key, iv);

	std::cout << "Encrypted: \n";
	print_matrix(data, 4, 4); // print 4 * 4 array
	std::cout << '\n';

	aes.decrypt_cbc(data, 16, key, iv);
	std::cout << "Decrypted: \n";
	print_matrix(data, 4, 4); // print 4 * 4 array
	std::cout << '\n';
}
```
