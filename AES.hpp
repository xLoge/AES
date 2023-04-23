#ifndef _LOGE_AES_
#define _LOGE_AES_

#define _AES_NAMESPACE_ AES
#define _AES_CLASS_ AES

#if __cpp_constexpr >= 201304L
#define _AES_CONSTEXPR_FUNC_ constexpr
#define _AES_CONSTEXPR_ constexpr
#else
#define _AES_CONSTEXPR_FUNC_
#define _AES_CONSTEXPR_ const
#endif // __cpp_constexpr

#ifdef _MSC_VER
#define _AES_FORCEINLINE_ __forceinline
#endif // _MSC_VER
#ifdef __GNUG__
#define _AES_FORCEINLINE_ __attribute__((always_inline))
#endif // __GNUG__

namespace _AES_NAMESPACE_
{
	typedef signed int int32_t;
	typedef unsigned char uint8_t;
	typedef unsigned short uint16_t;
	typedef unsigned int uint32_t;
	typedef unsigned long long size_t;
}

namespace _AES_NAMESPACE_
{
	namespace detail
	{
		template <class Ty, size_t SIZE>
		class array
		{
		public:
			Ty m_data[SIZE];

			_AES_CONSTEXPR_FUNC_ Ty& operator[](const size_t _at) noexcept {
				return m_data[_at];
			}

			_AES_CONSTEXPR_FUNC_ const Ty operator[](const size_t _at) const noexcept {
				return m_data[_at];
			}
		};

		_AES_CONSTEXPR_FUNC_ array<uint8_t, 256> sbox = {
			0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
			0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
			0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
			0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
			0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
			0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
			0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
			0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
			0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
			0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
			0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
			0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
			0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
			0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
			0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
			0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
		};

		_AES_CONSTEXPR_FUNC_ array<uint8_t, 256> inv_sbox = {
			0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
			0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
			0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
			0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
			0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
			0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
			0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
			0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
			0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
			0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
			0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
			0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
			0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
			0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
			0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
		};

		_AES_CONSTEXPR_FUNC_ array<uint8_t, 11> rcon = {
			0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
		};

		_AES_CONSTEXPR_FUNC_ uint8_t xtime(const uint8_t _byte)
		{
			return ((_byte << 0x01) ^ (((_byte >> 0x07) & 0x01) * 0x1B));
		}

		_AES_CONSTEXPR_FUNC_ array<uint8_t, 256> gmul_table(const uint8_t _byte)
		{
			array<uint8_t, 256> table{ };
			for (uint32_t input = 0; input != 256; ++input) {
				table[input] = (
					((_byte & 1) * input) ^
					((_byte >> 1 & 1) * xtime(input)) ^
					((_byte >> 2 & 1) * xtime(xtime(input))) ^
					((_byte >> 3 & 1) * xtime(xtime(xtime(input)))) ^
					((_byte >> 4 & 1) * xtime(xtime(xtime(xtime(input)))))
				);
			}
			return table;
		}

		_AES_CONSTEXPR_FUNC_ array<uint8_t, 256> gmul2 = gmul_table(0x02);
		_AES_CONSTEXPR_FUNC_ array<uint8_t, 256> gmul9 = gmul_table(0x09);
		_AES_CONSTEXPR_FUNC_ array<uint8_t, 256> gmul11 = gmul_table(0x0B);
		_AES_CONSTEXPR_FUNC_ array<uint8_t, 256> gmul13 = gmul_table(0x0D);
		_AES_CONSTEXPR_FUNC_ array<uint8_t, 256> gmul14 = gmul_table(0x0E);
	}
}

namespace _AES_NAMESPACE_
{
	enum AES_KEY_LEN
	{
		AES128 = 128,
		AES192 = 192,
		AES256 = 256
	};
}

namespace _AES_NAMESPACE_
{
	class _AES_CLASS_
	{
	protected:
		static _AES_CONSTEXPR_ AES_KEY_LEN DEFAULT_MODE = AES_KEY_LEN::AES128;
		static _AES_CONSTEXPR_ size_t BLOCK_SIZE = 16;
		static _AES_CONSTEXPR_ size_t MAX_EXPKEY_SIZE = 240;

		using state_t = uint8_t[4][4]; // Row, Column
		using block_t = uint8_t[BLOCK_SIZE];
		using exkey_t = uint8_t[MAX_EXPKEY_SIZE];

		const uint16_t KEY_SIZE = DEFAULT_MODE / 8;
	public:

		_AES_CONSTEXPR_FUNC_ _AES_CLASS_() = default;

		_AES_CONSTEXPR_FUNC_ _AES_CLASS_(const AES_KEY_LEN _keymode) noexcept
			: KEY_SIZE(_keymode / 8)
		{

		}

		_AES_CONSTEXPR_FUNC_ _AES_CLASS_(const uint16_t _keybits)
			: KEY_SIZE(_keybits / 8)
		{
			if (_keybits % 32 != 0 || _keybits < AES128) {
				throw("Provided keybits are invalid");
			}
		}

		// Cipher block chaining mode, encrypt
		_AES_CONSTEXPR_FUNC_ void encrypt_cbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			copy_block(block, _iv);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				xor_blocks(block, _data);
				encrypt_block(block, expkey, KEY_SIZE);
				copy_block(_data, block);
			}
		}

		// Cipher block chaining mode, decrypt
		_AES_CONSTEXPR_FUNC_ void decrypt_cbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			block_t cipher_block{ };
			copy_block(block, _iv);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				copy_block(cipher_block, _data);
				decrypt_block(_data, expkey, KEY_SIZE);
				xor_blocks(_data, block);
				copy_block(block, cipher_block);
			}
		}

		// Propagating cipher block chaining mode, encrypt
		_AES_CONSTEXPR_FUNC_ void encrypt_pcbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			block_t plain_block{ };
			copy_block(block, _iv);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				copy_block(plain_block, _data);
				xor_blocks(block, _data);
				encrypt_block(block, expkey, KEY_SIZE);
				copy_block(_data, block);
				xor_blocks(block, plain_block);
			}
		}

		// Propagating cipher block chaining mode, decrypt
		_AES_CONSTEXPR_FUNC_ void decrypt_pcbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			block_t cipher_block{ };
			copy_block(block, _iv);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				copy_block(cipher_block, _data);
				decrypt_block(_data, expkey, KEY_SIZE);
				xor_blocks(_data, block, _data);
				xor_blocks(cipher_block, _data);
				copy_block(block, cipher_block);
			}
		}

		// Cipher feedback mode 8 Bit, encrypt
		_AES_CONSTEXPR_FUNC_ void encrypt_cfb8(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const noexcept
		{
			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			block_t crypt_block{ };
			copy_block(block, _iv);

			const uint8_t* const end = _data + _datasize;
			for (; _data != end; _data += 1)
			{
				copy_block(crypt_block, block);
				encrypt_block(crypt_block, expkey, KEY_SIZE);
				copy_block(block, &block[1]);
				_data[0] ^= crypt_block[0];
				block[BLOCK_SIZE - 1] = _data[0];
			}
		}

		// Cipher feedback mode 8 Bit, decrypt
		_AES_CONSTEXPR_FUNC_ void decrypt_cfb8(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const noexcept
		{
			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			block_t crypt_block{ };
			copy_block(block, _iv);

			const uint8_t* const end = _data + _datasize;
			for (; _data != end; _data += 1)
			{
				copy_block(crypt_block, block);
				encrypt_block(crypt_block, expkey, KEY_SIZE);
				copy_block(block, &block[1]);
				block[BLOCK_SIZE - 1] = _data[0];
				_data[0] ^= crypt_block[0];
			}
		}

		// Cipher feedback mode 128 Bit, encrypt
		_AES_CONSTEXPR_FUNC_ void encrypt_cfb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			copy_block(block, _iv);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				encrypt_block(block, expkey, KEY_SIZE);
				xor_blocks(_data, block);
				copy_block(block, _data);
			}
		}

		// Cipher feedback mode 128 Bit, decrypt
		_AES_CONSTEXPR_FUNC_ void decrypt_cfb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			block_t cipher_block{ };
			copy_block(block, _iv);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				copy_block(cipher_block, block);
				encrypt_block(cipher_block, expkey, KEY_SIZE);
				copy_block(block, _data);
				xor_blocks(_data, cipher_block);
			}
		}

		// Counter mode, encrypt and decrypt
		_AES_CONSTEXPR_FUNC_ void encrypt_ctr(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _nonce, const size_t _counter_state = 0) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t counter{ };
			block_t counter_block{ };
			copy_block(counter, _nonce);

			for (size_t i = 0; i != _counter_state; ++i) 
			{
				increment_counter(counter);
			}

			const uint8_t* const end = _data + _datasize;
			for (; _data != end; _data += BLOCK_SIZE)
			{
				copy_block(counter_block, counter);
				encrypt_block(counter_block, expkey, KEY_SIZE);
				xor_blocks(_data, counter_block);
				increment_counter(counter);
			}
		}

		// Counter mode, decrypt and encrypt 
		_AES_CONSTEXPR_FUNC_ void decrypt_ctr(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _nonce, const size_t _block_pos = 0, const size_t _counter_state = 0) const
		{
			check_block(_block_pos, _datasize);
			encrypt_ctr(_data + (_block_pos * BLOCK_SIZE), _datasize - (_block_pos * BLOCK_SIZE), _key, _nonce, _counter_state + _block_pos);
		}

		// Output feedback mode, encrypt and decrypt
		_AES_CONSTEXPR_FUNC_ void encrypt_ofb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			block_t block{ };
			copy_block(block, _iv);

			const uint8_t* const end = _data + _datasize;
			for (; _data != end; _data += BLOCK_SIZE)
			{
				encrypt_block(block, expkey, KEY_SIZE);
				xor_blocks(_data, block);
			}
		}

		// Output feedback mode, decrypt and encrypt
		_AES_CONSTEXPR_FUNC_ void decrypt_ofb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			encrypt_ofb(_data, _datasize, _key, _iv);
		}

		// Electronic codebook mode, encrypt
		_AES_CONSTEXPR_FUNC_ void encrypt_ecb(uint8_t* _data, const size_t _datasize, const uint8_t* _key) const
		{
			check_data(_datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			const uint8_t* const end = _data + _datasize;
			for (; _data != end; _data += BLOCK_SIZE)
			{
				encrypt_block(_data, expkey, KEY_SIZE);
			}
		}

		// Electronic codebook mode, decrypt
		_AES_CONSTEXPR_FUNC_ void decrypt_ecb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const size_t _block_pos = 0) const
		{
			check_data(_datasize);
			check_block(_block_pos, _datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			const uint8_t* const end = _data + _datasize;
			_data += _block_pos * BLOCK_SIZE;
			for (; _data != end; _data += BLOCK_SIZE)
			{
				decrypt_block(_data, expkey, KEY_SIZE);
			}
		}

		_AES_CONSTEXPR_FUNC_ uint16_t keysize() const noexcept
		{
			return KEY_SIZE;
		}

	private:
		static _AES_CONSTEXPR_FUNC_ void increment_counter(block_t& _counter) noexcept
		{
			for (size_t i = BLOCK_SIZE - 1, counter = 1; i != 0; --i)
			{
				counter += _counter[i];
				_counter[i] = counter;
				counter >>= 8;
			}
		}

		static void encrypt_block(uint8_t* _state, const uint8_t* _round_key, const uint16_t _keysize) noexcept
		{
			state_t& state = *reinterpret_cast<state_t*>(_state);
			const uint16_t rounds = (_keysize / 4) + 6;

			add_round_key(state, _round_key);

			for (size_t round = 1; round != rounds; ++round)
			{
				sub_bytes(state);
				shift_rows(state);
				mix_columns(state);
				add_round_key(state, &_round_key[round * 16]);
			}

			sub_bytes(state);
			shift_rows(state);
			add_round_key(state, &_round_key[rounds * 16]);
		}

		static _AES_CONSTEXPR_ _AES_FORCEINLINE_ void mix_columns(state_t& _state) noexcept
		{
			using namespace detail;
			uint8_t a{ }, b{ }, c{ }, d{ }, tmp{ };

			for (int32_t i = 0; i != 4; ++i)
			{
				a = _state[i][0];
				b = _state[i][1];
				c = _state[i][2];
				d = _state[i][3];

				tmp = a ^ b ^ c ^ d;
				_state[i][0] ^= gmul2[a ^ b] ^ tmp;
				_state[i][1] ^= gmul2[b ^ c] ^ tmp;
				_state[i][2] ^= gmul2[c ^ d] ^ tmp;
				_state[i][3] ^= gmul2[d ^ a] ^ tmp;
			}
		}

		static _AES_CONSTEXPR_FUNC_ _AES_FORCEINLINE_ void shift_rows(state_t& _state) noexcept
		{
			uint8_t tmp = _state[0][1];
			_state[0][1] = _state[1][1];
			_state[1][1] = _state[2][1];
			_state[2][1] = _state[3][1];
			_state[3][1] = tmp;
			tmp = _state[0][2];
			_state[0][2] = _state[2][2];
			_state[2][2] = tmp;
			tmp = _state[1][2];
			_state[1][2] = _state[3][2];
			_state[3][2] = tmp;
			tmp = _state[3][3];
			_state[3][3] = _state[2][3];
			_state[2][3] = _state[1][3];
			_state[1][3] = _state[0][3];
			_state[0][3] = tmp;
		}

		static _AES_FORCEINLINE_ void sub_bytes(state_t& _state) noexcept
		{
			uint8_t* const state = reinterpret_cast<uint8_t* const>(_state);
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				state[i] = detail::sbox[state[i]];
			}
		}

		static void decrypt_block(uint8_t* _state, const uint8_t* _round_key, const uint16_t _keysize) noexcept
		{
			state_t& state = *reinterpret_cast<state_t*>(_state);
			const uint16_t rounds = (_keysize / 4) + 6;

			add_round_key(state, &_round_key[rounds * 16]);

			for (size_t round = rounds - 1; round != 0; --round)
			{
				inv_shift_rows(state);
				inv_sub_bytes(state);
				add_round_key(state, &_round_key[round * 16]);
				inv_mix_columns(state);
			}

			inv_shift_rows(state);
			inv_sub_bytes(state);
			add_round_key(state, _round_key);
		}

		static _AES_CONSTEXPR_FUNC_ _AES_FORCEINLINE_ void inv_mix_columns(state_t& _state) noexcept
		{
			using namespace detail;
			uint8_t a{ }, b{ }, c{ }, d{ };

			for (int32_t i = 0; i != 4; ++i)
			{
				a = _state[i][0];
				b = _state[i][1];
				c = _state[i][2];
				d = _state[i][3];

				_state[i][0] = gmul14[a] ^ gmul11[b] ^ gmul13[c] ^ gmul9[d];
				_state[i][1] = gmul9[a] ^ gmul14[b] ^ gmul11[c] ^ gmul13[d];
				_state[i][2] = gmul13[a] ^ gmul9[b] ^ gmul14[c] ^ gmul11[d];
				_state[i][3] = gmul11[a] ^ gmul13[b] ^ gmul9[c] ^ gmul14[d];
			}
		}

		static _AES_CONSTEXPR_FUNC_ _AES_FORCEINLINE_ void inv_shift_rows(state_t& _state) noexcept
		{
			uint8_t tmp = _state[3][1];
			_state[3][1] = _state[2][1];
			_state[2][1] = _state[1][1];
			_state[1][1] = _state[0][1];
			_state[0][1] = tmp;
			tmp = _state[0][2];
			_state[0][2] = _state[2][2];
			_state[2][2] = tmp;
			tmp = _state[1][2];
			_state[1][2] = _state[3][2];
			_state[3][2] = tmp;		
			tmp = _state[0][3];	
			_state[0][3] = _state[1][3];
			_state[1][3] = _state[2][3];
			_state[2][3] = _state[3][3];
			_state[3][3] = tmp;
		}

		static _AES_FORCEINLINE_ void inv_sub_bytes(state_t& _state) noexcept
		{
			uint8_t* const state = reinterpret_cast<uint8_t* const>(_state);
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				state[i] = detail::inv_sbox[state[i]];
			}
		}

		static _AES_CONSTEXPR_FUNC_ void key_expansion(const uint8_t* _key, uint8_t* _out_round_key, const uint16_t _keysize) noexcept
		{
			using namespace detail;

			const size_t columns = _keysize / 4;
			const size_t rounds = columns + 6;
			const size_t end = 4 * (rounds + 1);

			for (size_t i = 0; i != _keysize; ++i) {
				_out_round_key[i] = _key[i];
			}

			uint8_t tmp[4]{ };
			for (size_t i = columns; i != end; ++i)
			{
				tmp[0] = _out_round_key[(i - 1) * 4 + 0];
				tmp[1] = _out_round_key[(i - 1) * 4 + 1];
				tmp[2] = _out_round_key[(i - 1) * 4 + 2];
				tmp[3] = _out_round_key[(i - 1) * 4 + 3];

				if (i % columns == 0) {
					const uint8_t tmp2 = tmp[0];
					tmp[0] = tmp[1];
					tmp[1] = tmp[2];
					tmp[2] = tmp[3];
					tmp[3] = tmp2;

					tmp[0] = sbox[tmp[0]];
					tmp[1] = sbox[tmp[1]];
					tmp[2] = sbox[tmp[2]];
					tmp[3] = sbox[tmp[3]];

					tmp[0] = tmp[0] ^ rcon[i / columns];
				}
				else if (columns > 6 && i % columns == 4) {
					tmp[0] = sbox[tmp[0]];
					tmp[1] = sbox[tmp[1]];
					tmp[2] = sbox[tmp[2]];
					tmp[3] = sbox[tmp[3]];
				}

				_out_round_key[i * 4 + 0] = _out_round_key[(i - columns) * 4 + 0] ^ tmp[0];
				_out_round_key[i * 4 + 1] = _out_round_key[(i - columns) * 4 + 1] ^ tmp[1];
				_out_round_key[i * 4 + 2] = _out_round_key[(i - columns) * 4 + 2] ^ tmp[2];
				_out_round_key[i * 4 + 3] = _out_round_key[(i - columns) * 4 + 3] ^ tmp[3];
			}
		}

		static void add_round_key(state_t& _state, const uint8_t* _round_key) noexcept
		{
			uint8_t* const state = reinterpret_cast<uint8_t* const>(_state);
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				state[i] ^= _round_key[i];
			}
		}

		static _AES_CONSTEXPR_FUNC_ void xor_blocks(const uint8_t* _block1, const uint8_t* _block2, uint8_t* _dest) noexcept
		{
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				_dest[i] = _block1[i] ^ _block2[i];
			}
		}

		static _AES_CONSTEXPR_FUNC_ void xor_blocks(uint8_t* _block1, const uint8_t* _block2) noexcept
		{
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				_block1[i] ^= _block2[i];
			}
		}

		static _AES_CONSTEXPR_FUNC_ void copy_block(uint8_t* _dst, const uint8_t* _src) noexcept
		{
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				_dst[i] = _src[i];
			}
		}

		static _AES_CONSTEXPR_FUNC_ void check_data(const size_t _size)
		{
			if (_size == 0 || _size % BLOCK_SIZE != 0) {
				throw("Inavlid _datasize specified.");
			}
		}

		static _AES_CONSTEXPR_FUNC_ void check_block(const size_t _pos, const size_t _max)
		{
			if (_pos * BLOCK_SIZE > _max - BLOCK_SIZE) {
				throw("Inavlid _block_pos specified.");
			}
		}
	};
}

#undef _AES_CONSTEXPR_FUNC_
#undef _AES_CONSTEXPR_
#undef _AES_FORCEINLINE_
#undef _AES_CLASS_
#undef _AES_NAMESPACE_

#endif // _LOGE_AES_
