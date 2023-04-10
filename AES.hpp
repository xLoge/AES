#pragma once

#ifndef _LOGE_AES_
#define _LOGE_AES_

#define _NAMESPACE_ AES
#define _FORCEINLINE_ __forceinline

#ifndef _HAS_CXX17
#define _HAS_CXX17 (__cplusplus >= 201703L)
#endif

#ifndef _HAS_CXX20
#define _HAS_CXX20 (__cplusplus >= 202002L)
#endif

namespace _NAMESPACE_
{
	typedef signed char int8_t;
	typedef signed short int16_t;
	typedef signed int int32_t;
	typedef signed long long int64_t;

	typedef unsigned char uint8_t;
	typedef unsigned short uint16_t;
	typedef unsigned int uint32_t;
	typedef unsigned long long uint64_t;
	typedef unsigned long long size_t;
}

namespace _NAMESPACE_
{
	namespace detail
	{
		template <class Ty, size_t SIZE>
		struct array
		{
			Ty m_data[SIZE];
			
			constexpr Ty& operator[](const size_t idx) noexcept {
				return m_data[idx];
			}

			constexpr const Ty operator[](const size_t idx) const noexcept {

				return m_data[idx];
			}
		};

		constexpr array<uint8_t, 256> sbox = {
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

		constexpr array<uint8_t, 256> inv_sbox = {
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

		constexpr array<uint8_t, 11> rcon = {
			0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
		};

		constexpr uint8_t xtime(const uint8_t _byte)
		{
			return ((_byte << 0x01) ^ (((_byte >> 0x07) & 0x01) * 0x1B));
		}

#if _HAS_CXX20
	consteval
#else 
	constexpr
#endif
		array<uint8_t, 256> gmul_table(const uint8_t byte)
		{
			array<uint8_t, 256> table{ };
			for (uint32_t input = 0; input != 256; ++input) {
				table[input] = (
					((byte & 1) * input) ^
					((byte >> 1 & 1) * xtime(input)) ^
					((byte >> 2 & 1) * xtime(xtime(input))) ^
					((byte >> 3 & 1) * xtime(xtime(xtime(input)))) ^
					((byte >> 4 & 1) * xtime(xtime(xtime(xtime(input)))))
				);
			}
			return table;
		}

		constexpr array<uint8_t, 256> gmul2 = gmul_table(2);
		constexpr array<uint8_t, 256> gmul9 = gmul_table(9);
		constexpr array<uint8_t, 256> gmul11 = gmul_table(11);
		constexpr array<uint8_t, 256> gmul13 = gmul_table(13);
		constexpr array<uint8_t, 256> gmul14 = gmul_table(14);

		constexpr void* memcpy(void* _dst, const void* const _src, const size_t _size)
		{
			const uint8_t* const end = static_cast<uint8_t*>(_dst) + _size;
			const uint8_t* src = static_cast<const uint8_t*>(_src);
			uint8_t* dst = static_cast<uint8_t*>(_dst);
			while (dst != end) {
				*dst++ = *src++;
			}
			return _dst;
		}
	}
}

namespace _NAMESPACE_
{
	enum AES_KEY_LEN
	{
		AES128 = 128,
		AES192 = 192,
		AES256 = 256
	};
}

namespace _NAMESPACE_
{
	class AES
	{
	private:
		static constexpr size_t Nb = 4;
		static constexpr size_t BLOCK_SIZE = 16;
		static constexpr size_t MAX_EXPKEY_SIZE = 4 * (Nb * (14 + 1));

		using state_t = uint8_t[4][Nb]; // Row, Column
		using block_t = uint8_t[BLOCK_SIZE];
		using expkey_t = uint8_t[MAX_EXPKEY_SIZE];

		AES_KEY_LEN m_mode = AES128;
		uint32_t m_keysize = m_mode / 8;

	public:

		constexpr AES() = default;

		constexpr AES(const AES_KEY_LEN keylen) noexcept
			: m_mode(keylen)
		{

		}

		// Cipher block chaining mode, encrypt
		constexpr void encrypt_cbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);
			state_t block{ };
			detail::memcpy(block, _iv, BLOCK_SIZE);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				xor_blocks(block, _data);
				encrypt_block(block, expkey, m_keysize);
				detail::memcpy(_data, block, BLOCK_SIZE);
			}
		}
		
		// Cipher block chaining mode, decrypt
		constexpr void decrypt_cbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);

			block_t enc_data{ };
			block_t block{ };
			detail::memcpy(block, _iv, BLOCK_SIZE);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				detail::memcpy(enc_data, _data, BLOCK_SIZE);
				decrypt_block(*reinterpret_cast<state_t*>(_data), expkey, m_keysize);
				xor_blocks(*reinterpret_cast<state_t*>(_data), block);
				detail::memcpy(block, enc_data, BLOCK_SIZE);
			}
		}

		// Propagating cipher block chaining mode, encrypt
		constexpr void encrypt_pcbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);

			state_t block{ };
			block_t last_plain{ };
			detail::memcpy(block, _iv, BLOCK_SIZE);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				detail::memcpy(last_plain, _data, BLOCK_SIZE);
				xor_blocks(block, _data);
				encrypt_block(block, expkey, m_keysize);
				detail::memcpy(_data, block, BLOCK_SIZE);
				xor_blocks(block, last_plain);
			}
		}

		// Propagating cipher block chaining mode, decrypt
		constexpr void decrypt_pcbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);
			
			block_t block{ };
			block_t last_enc{ };
			detail::memcpy(block, _iv, BLOCK_SIZE);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				detail::memcpy(last_enc, _data, BLOCK_SIZE);
				decrypt_block(*reinterpret_cast<state_t*>(_data), expkey, m_keysize);
				xor_blocks(_data, block, _data);
				xor_blocks(last_enc, _data, last_enc);
				detail::memcpy(block, last_enc, BLOCK_SIZE);
			}
		}

		// Electronic codebook mode, encrypt
		constexpr void encrypt_ecb(uint8_t* _data, const size_t _datasize, const uint8_t* _key) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				encrypt_block(*reinterpret_cast<state_t*>(_data), expkey, m_keysize);
			}
		}

		// Electronic codebook mode, decrypt
		constexpr void decrypt_ecb(uint8_t* _data, const size_t _datasize, const uint8_t* _key) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				decrypt_block(*reinterpret_cast<state_t*>(_data), expkey, m_keysize);
			}
		}

		// Cipher feedback mode, encrypt
		constexpr void encrypt_cfb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);

			block_t block { };
			detail::memcpy(block, _iv, BLOCK_SIZE);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				encrypt_block(*reinterpret_cast<state_t*>(block), expkey, m_keysize);
				xor_blocks(_data, block, _data);
				detail::memcpy(block, _data, BLOCK_SIZE);
			}
		}

		// Cipher feedback mode, decrypt
		constexpr void decrypt_cfb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);

			block_t block{ };
			block_t enc_block{ };
			detail::memcpy(block, _iv, BLOCK_SIZE);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				detail::memcpy(enc_block, block, BLOCK_SIZE);
				encrypt_block(*reinterpret_cast<state_t*>(enc_block), expkey, m_keysize);
				detail::memcpy(block, _data, BLOCK_SIZE);
				xor_blocks(_data, enc_block, _data);
			}
		}

		// Counter mode, encrypt and decrypt
		constexpr void encrypt_ctr(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _nonce) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);

			block_t counter_block{ };
			size_t counter = 0;

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				combine_nonce_counter(counter_block, _nonce, counter);
				counter += 1;
				encrypt_block(*reinterpret_cast<state_t*>(counter_block), expkey, m_keysize);
				xor_blocks(_data, counter_block, _data);
			}
		}

		// Counter mode, decrypt and encrypt 
		constexpr void decrypt_ctr(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _nonce) const 
		{
			encrypt_ctr(_data, _datasize, _key, _nonce);
		}

		// Output feedback mode, encrypt and decrypt
		constexpr void encrypt_ofb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			check_data(_datasize);

			expkey_t expkey{ };
			key_expansion(_key, expkey, m_keysize);

			block_t block{ };
			detail::memcpy(block, _iv, BLOCK_SIZE);

			const size_t end = _datasize / BLOCK_SIZE;
			for (size_t i = 0; i != end; ++i, _data += BLOCK_SIZE)
			{
				encrypt_block(*reinterpret_cast<state_t*>(block), expkey, m_keysize);
				xor_blocks(_data, block, _data);
			}
		}

		// Output feedback mode, decrypt and encrypt
		constexpr void decrypt_ofb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			encrypt_ofb(_data, _datasize, _key, _iv);
		}

	private:
		static constexpr void combine_nonce_counter(block_t& _combined, const uint8_t* _nonce, size_t _counter) noexcept
		{
			block_t counter_block{ };
			for (uint32_t i = 0; i != BLOCK_SIZE; ++i) {
				counter_block[(BLOCK_SIZE - 1) - i] = static_cast<uint8_t>(_counter & 0xFF);
				_counter >>= 8;
			}
			xor_blocks(_nonce, counter_block, _combined);
		}

		static constexpr void encrypt_block(state_t& _state, const uint8_t* _round_key, const uint32_t _keysize) noexcept
		{
			add_round_key(_state, _round_key);

			const uint32_t rounds = _keysize / 4 + 6;
			for (uint32_t round = 1; round != rounds; ++round)
			{
				sub_bytes(_state);
				shift_rows(_state);
				mix_columns(_state);
				add_round_key(_state, &_round_key[round * (Nb * 4)]);
			}

			sub_bytes(_state);
			shift_rows(_state);
			add_round_key(_state, &_round_key[rounds * (Nb * 4)]);
		}

		_FORCEINLINE_ static constexpr void mix_columns(state_t& _state) noexcept
		{
			uint8_t a{ }, b{ }, c{ }, d{ }, tmp{ };

			for (uint32_t i = 0; i != 4; ++i)
			{
				a = _state[i][0];
				b = _state[i][1];
				c = _state[i][2];
				d = _state[i][3];

				tmp = a ^ b ^ c ^ d;
				_state[i][0] ^= detail::gmul2[a ^ b] ^ tmp;
				_state[i][1] ^= detail::gmul2[b ^ c] ^ tmp;
				_state[i][2] ^= detail::gmul2[c ^ d] ^ tmp;
				_state[i][3] ^= detail::gmul2[d ^ a] ^ tmp;
			}
		}

		_FORCEINLINE_ static constexpr void shift_rows(state_t& _state) noexcept
		{
			/*
			* shift rows

				---------------      ---------------
	  Column -> | 35 36 37 38 |	 ->  | 35 36 37 38 |  nothing
				| 45 46 47 48 |	 ->  | 46 47 48 45 |  1 Left or 3 Right
				| 55 56 57 58 |	 ->  | 57 58 55 56 |  2 Left or 2 Right
				| 65 66 67 68 |	 ->  | 68 65 66 67 |  3 Left or 1 Right
				---------------      ---------------
				  ^
				  |
				 Row

			state[ROW][COLUMN]
			*/

			// Column 2
			uint8_t tmp = _state[0][1];		// tmp -> 45
			_state[0][1] = _state[1][1];	// 45 -> 46
			_state[1][1] = _state[2][1];	// 46 -> 47
			_state[2][1] = _state[3][1];	// 47 -> 48
			_state[3][1] = tmp;				// 48 -> tmp (45)

			// Column 3
			tmp = _state[0][2];				// tmp -> 55
			_state[0][2] = _state[2][2];	// 55 -> 57
			_state[2][2] = tmp;				// 57 -> tmp (55)
			tmp = _state[1][2];				// tmp -> 56
			_state[1][2] = _state[3][2];	// 56 -> 58
			_state[3][2] = tmp;				// 58 -> tmp (56)

			// Column 4
			tmp = _state[3][3];				// tmp -> 68
			_state[3][3] = _state[2][3];	// 68 -> 67
			_state[2][3] = _state[1][3];	// 67 -> 66
			_state[1][3] = _state[0][3];	// 66 -> 65
			_state[0][3] = tmp;				// 65 -> tmp (68)
		}

		_FORCEINLINE_ static constexpr void sub_bytes(state_t& _state) noexcept
		{
			uint8_t* const state = (uint8_t*)_state;

			for (uint32_t i = 0; i != BLOCK_SIZE; ++i) {
				state[i] = detail::sbox[state[i]];
			}
		}

		static constexpr void decrypt_block(state_t& _state, const uint8_t* _round_key, const uint32_t _keysize) noexcept
		{
			const uint32_t rounds = _keysize / 4 + 6;

			add_round_key(_state, &_round_key[rounds * (Nb * 4)]);

			for (uint32_t round = rounds - 1; round != 0; --round)
			{
				inv_shift_rows(_state);
				inv_sub_bytes(_state);
				add_round_key(_state, &_round_key[round * (Nb * 4)]);
				inv_mix_columns(_state);
			}

			inv_shift_rows(_state);
			inv_sub_bytes(_state);
			add_round_key(_state, _round_key);
		}

		_FORCEINLINE_ static constexpr void inv_mix_columns(state_t& _state) noexcept
		{
			constexpr uint8_t x09 = 0;
			constexpr uint8_t x0B = 1;
			constexpr uint8_t x0D = 2;
			constexpr uint8_t x0E = 3;

			uint8_t a{ }, b{ }, c{ }, d{ };

			for (uint32_t i = 0; i != 4; ++i)
			{
				a = _state[i][0];
				b = _state[i][1];
				c = _state[i][2];
				d = _state[i][3];

				using namespace detail;
				_state[i][0] = gmul14[a] ^ gmul11[b] ^ gmul13[c] ^ gmul9[d];
				_state[i][1] = gmul9[a] ^ gmul14[b] ^ gmul11[c] ^ gmul13[d];
				_state[i][2] = gmul13[a] ^ gmul9[b] ^ gmul14[c] ^ gmul11[d];
				_state[i][3] = gmul11[a] ^ gmul13[b] ^ gmul9[c] ^ gmul14[d];
			}
		}

		_FORCEINLINE_ static constexpr void inv_shift_rows(state_t& _state) noexcept
		{
			/*
			* reversed shift rows

					  ---------------        ---------------
			Column -> | 35 36 37 38 |	 ->  | 35 36 37 38 |  nothing
					  | 46 47 48 45 |	 ->  | 45 46 47 48 |  1 Right or 3 Left
					  | 57 58 55 56 |	 ->  | 55 56 57 58 |  2 Right or 2 Left
					  | 68 65 66 67 |	 ->  | 65 66 67 68 |  3 Right or 1 Left
					  ---------------        ---------------
						^
						|
					   Row

			state[ROW][COLUMN]
			*/

			// Column 2
			uint8_t tmp = _state[3][1];		// tmp -> 45
			_state[3][1] = _state[2][1];	// 45 -> 48
			_state[2][1] = _state[1][1];	// 48 -> 47
			_state[1][1] = _state[0][1];	// 47 -> 46
			_state[0][1] = tmp;				// 46 -> tmp (45)

			// Column 3
			tmp = _state[0][2];				// tmp -> 57
			_state[0][2] = _state[2][2];	// 57 -> 55
			_state[2][2] = tmp;				// 55 -> tmp (57)
			tmp = _state[1][2];				// tmp -> 58
			_state[1][2] = _state[3][2];	// 58 -> 56
			_state[3][2] = tmp;				// 56 -> tmp (58)

			// Column 4
			tmp = _state[0][3];				// tmp -> 68
			_state[0][3] = _state[1][3];	// 68 -> 65
			_state[1][3] = _state[2][3];	// 65 -> 66
			_state[2][3] = _state[3][3];	// 66 -> 67
			_state[3][3] = tmp;				// 67 -> tmp (68)
		}

		_FORCEINLINE_ static constexpr void inv_sub_bytes(state_t& _state) noexcept
		{
			uint8_t* const state = (uint8_t*)_state;

			for (uint32_t i = 0; i != BLOCK_SIZE; ++i) {
				state[i] = detail::inv_sbox[state[i]];
			}
		}

		static constexpr void key_expansion(const uint8_t* _key, uint8_t* _out_round_key, const uint32_t _keysize) noexcept
		{
			using namespace detail;

			const size_t columns = _keysize / 4;
			const size_t rounds = columns + 6;
			const size_t end = Nb * (rounds + 1);

			detail::memcpy(_out_round_key, _key, _keysize);

			uint8_t tmp[4]{ };
			for (uint32_t i = columns; i != end; ++i)
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
		
		static constexpr void add_round_key(state_t& _state, const uint8_t* _round_key) noexcept
		{
			uint8_t* const state = (uint8_t*)_state;
			for (uint32_t x = 0; x != BLOCK_SIZE; ++x) {
				state[x] ^= _round_key[x];
			}
		}

		static constexpr void xor_blocks(state_t& _state, const uint8_t* _block) noexcept
		{
			uint8_t* const state = (uint8_t*)_state;
			for (uint32_t x = 0; x != BLOCK_SIZE; ++x) {
				state[x] ^= _block[x];
			}
		}

		static constexpr void xor_blocks(const uint8_t* _block1, const uint8_t* _block2, uint8_t* _dest) noexcept
		{
			for (uint32_t x = 0; x != BLOCK_SIZE; ++x) {
				_dest[x] = _block1[x] ^ _block2[x];
			}
		}

		static constexpr void check_data(const size_t _size)
		{
			if (_size == 0 || _size % BLOCK_SIZE != 0) {
				throw("Inavlid _datasize specified.");
			}
		}
	};
}

#undef _NAMESPACE_
#undef _FORCEINLINE_

#endif
