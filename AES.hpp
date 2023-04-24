#ifndef _LOGE_AES_
#define _LOGE_AES_

#define _AES_NAMESPACE_ AES
#define _AES_CLASS_ AES

#if __cpp_constexpr >= 201304L
	#define _AES_CONSTEXPR_14_ constexpr
	#define _AES_CONSTEXPR_11_ constexpr
#else
	#define _AES_CONSTEXPR_14_ 
	#define _AES_CONSTEXPR_11_ constexpr
#endif // __cpp_constexpr >= 201304L

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
	typedef unsigned long long size_t;
}

namespace _AES_NAMESPACE_
{
	namespace detail
	{
		_AES_CONSTEXPR_11_ uint8_t rcon[10] = {
			0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
		};

		_AES_CONSTEXPR_11_ uint8_t sbox[256] = {
			0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
			0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
			0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
			0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
			0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
			0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
			0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
			0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
			0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
			0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
			0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
			0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
			0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
			0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
			0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
			0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
		};

		_AES_CONSTEXPR_11_ uint8_t inv_sbox[256] = {
			0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
			0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
			0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
			0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
			0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
			0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
			0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
			0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
			0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
			0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
			0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
			0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
			0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
			0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
			0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
		};

		_AES_CONSTEXPR_11_ uint8_t gmul02[256] = {
			0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
			0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
			0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
			0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
			0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
			0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
			0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
			0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
			0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
			0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25,
			0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45,
			0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
			0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85,
			0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5,
			0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
			0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5 
		};

		_AES_CONSTEXPR_11_ uint8_t gmul09[256] = {
			0x00, 0x09, 0x12, 0x1B, 0x24, 0x2D, 0x36, 0x3F, 0x48, 0x41, 0x5A, 0x53, 0x6C, 0x65, 0x7E, 0x77,
			0x90, 0x99, 0x82, 0x8B, 0xB4, 0xBD, 0xA6, 0xAF, 0xD8, 0xD1, 0xCA, 0xC3, 0xFC, 0xF5, 0xEE, 0xE7,
			0x3B, 0x32, 0x29, 0x20, 0x1F, 0x16, 0x0D, 0x04, 0x73, 0x7A, 0x61, 0x68, 0x57, 0x5E, 0x45, 0x4C,
			0xAB, 0xA2, 0xB9, 0xB0, 0x8F, 0x86, 0x9D, 0x94, 0xE3, 0xEA, 0xF1, 0xF8, 0xC7, 0xCE, 0xD5, 0xDC,
			0x76, 0x7F, 0x64, 0x6D, 0x52, 0x5B, 0x40, 0x49, 0x3E, 0x37, 0x2C, 0x25, 0x1A, 0x13, 0x08, 0x01,
			0xE6, 0xEF, 0xF4, 0xFD, 0xC2, 0xCB, 0xD0, 0xD9, 0xAE, 0xA7, 0xBC, 0xB5, 0x8A, 0x83, 0x98, 0x91,
			0x4D, 0x44, 0x5F, 0x56, 0x69, 0x60, 0x7B, 0x72, 0x05, 0x0C, 0x17, 0x1E, 0x21, 0x28, 0x33, 0x3A,
			0xDD, 0xD4, 0xCF, 0xC6, 0xF9, 0xF0, 0xEB, 0xE2, 0x95, 0x9C, 0x87, 0x8E, 0xB1, 0xB8, 0xA3, 0xAA,
			0xEC, 0xE5, 0xFE, 0xF7, 0xC8, 0xC1, 0xDA, 0xD3, 0xA4, 0xAD, 0xB6, 0xBF, 0x80, 0x89, 0x92, 0x9B,
			0x7C, 0x75, 0x6E, 0x67, 0x58, 0x51, 0x4A, 0x43, 0x34, 0x3D, 0x26, 0x2F, 0x10, 0x19, 0x02, 0x0B,
			0xD7, 0xDE, 0xC5, 0xCC, 0xF3, 0xFA, 0xE1, 0xE8, 0x9F, 0x96, 0x8D, 0x84, 0xBB, 0xB2, 0xA9, 0xA0,
			0x47, 0x4E, 0x55, 0x5C, 0x63, 0x6A, 0x71, 0x78, 0x0F, 0x06, 0x1D, 0x14, 0x2B, 0x22, 0x39, 0x30,
			0x9A, 0x93, 0x88, 0x81, 0xBE, 0xB7, 0xAC, 0xA5, 0xD2, 0xDB, 0xC0, 0xC9, 0xF6, 0xFF, 0xE4, 0xED,
			0x0A, 0x03, 0x18, 0x11, 0x2E, 0x27, 0x3C, 0x35, 0x42, 0x4B, 0x50, 0x59, 0x66, 0x6F, 0x74, 0x7D,
			0xA1, 0xA8, 0xB3, 0xBA, 0x85, 0x8C, 0x97, 0x9E, 0xE9, 0xE0, 0xFB, 0xF2, 0xCD, 0xC4, 0xDF, 0xD6,
			0x31, 0x38, 0x23, 0x2A, 0x15, 0x1C, 0x07, 0x0E, 0x79, 0x70, 0x6B, 0x62, 0x5D, 0x54, 0x4F, 0x46
		};

		_AES_CONSTEXPR_11_ uint8_t gmul11[256] = {
			0x00, 0x0B, 0x16, 0x1D, 0x2C, 0x27, 0x3A, 0x31, 0x58, 0x53, 0x4E, 0x45, 0x74, 0x7F, 0x62, 0x69,
			0xB0, 0xBB, 0xA6, 0xAD, 0x9C, 0x97, 0x8A, 0x81, 0xE8, 0xE3, 0xFE, 0xF5, 0xC4, 0xCF, 0xD2, 0xD9,
			0x7B, 0x70, 0x6D, 0x66, 0x57, 0x5C, 0x41, 0x4A, 0x23, 0x28, 0x35, 0x3E, 0x0F, 0x04, 0x19, 0x12,
			0xCB, 0xC0, 0xDD, 0xD6, 0xE7, 0xEC, 0xF1, 0xFA, 0x93, 0x98, 0x85, 0x8E, 0xBF, 0xB4, 0xA9, 0xA2,
			0xF6, 0xFD, 0xE0, 0xEB, 0xDA, 0xD1, 0xCC, 0xC7, 0xAE, 0xA5, 0xB8, 0xB3, 0x82, 0x89, 0x94, 0x9F,
			0x46, 0x4D, 0x50, 0x5B, 0x6A, 0x61, 0x7C, 0x77, 0x1E, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2F,
			0x8D, 0x86, 0x9B, 0x90, 0xA1, 0xAA, 0xB7, 0xBC, 0xD5, 0xDE, 0xC3, 0xC8, 0xF9, 0xF2, 0xEF, 0xE4,
			0x3D, 0x36, 0x2B, 0x20, 0x11, 0x1A, 0x07, 0x0C, 0x65, 0x6E, 0x73, 0x78, 0x49, 0x42, 0x5F, 0x54,
			0xF7, 0xFC, 0xE1, 0xEA, 0xDB, 0xD0, 0xCD, 0xC6, 0xAF, 0xA4, 0xB9, 0xB2, 0x83, 0x88, 0x95, 0x9E,
			0x47, 0x4C, 0x51, 0x5A, 0x6B, 0x60, 0x7D, 0x76, 0x1F, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2E,
			0x8C, 0x87, 0x9A, 0x91, 0xA0, 0xAB, 0xB6, 0xBD, 0xD4, 0xDF, 0xC2, 0xC9, 0xF8, 0xF3, 0xEE, 0xE5,
			0x3C, 0x37, 0x2A, 0x21, 0x10, 0x1B, 0x06, 0x0D, 0x64, 0x6F, 0x72, 0x79, 0x48, 0x43, 0x5E, 0x55,
			0x01, 0x0A, 0x17, 0x1C, 0x2D, 0x26, 0x3B, 0x30, 0x59, 0x52, 0x4F, 0x44, 0x75, 0x7E, 0x63, 0x68,
			0xB1, 0xBA, 0xA7, 0xAC, 0x9D, 0x96, 0x8B, 0x80, 0xE9, 0xE2, 0xFF, 0xF4, 0xC5, 0xCE, 0xD3, 0xD8,
			0x7A, 0x71, 0x6C, 0x67, 0x56, 0x5D, 0x40, 0x4B, 0x22, 0x29, 0x34, 0x3F, 0x0E, 0x05, 0x18, 0x13,
			0xCA, 0xC1, 0xDC, 0xD7, 0xE6, 0xED, 0xF0, 0xFB, 0x92, 0x99, 0x84, 0x8F, 0xBE, 0xB5, 0xA8, 0xA3 
		};

		_AES_CONSTEXPR_11_ uint8_t gmul13[256] = {
			0x00, 0x0D, 0x1A, 0x17, 0x34, 0x39, 0x2E, 0x23, 0x68, 0x65, 0x72, 0x7F, 0x5C, 0x51, 0x46, 0x4B,
			0xD0, 0xDD, 0xCA, 0xC7, 0xE4, 0xE9, 0xFE, 0xF3, 0xB8, 0xB5, 0xA2, 0xAF, 0x8C, 0x81, 0x96, 0x9B,
			0xBB, 0xB6, 0xA1, 0xAC, 0x8F, 0x82, 0x95, 0x98, 0xD3, 0xDE, 0xC9, 0xC4, 0xE7, 0xEA, 0xFD, 0xF0,
			0x6B, 0x66, 0x71, 0x7C, 0x5F, 0x52, 0x45, 0x48, 0x03, 0x0E, 0x19, 0x14, 0x37, 0x3A, 0x2D, 0x20,
			0x6D, 0x60, 0x77, 0x7A, 0x59, 0x54, 0x43, 0x4E, 0x05, 0x08, 0x1F, 0x12, 0x31, 0x3C, 0x2B, 0x26,
			0xBD, 0xB0, 0xA7, 0xAA, 0x89, 0x84, 0x93, 0x9E, 0xD5, 0xD8, 0xCF, 0xC2, 0xE1, 0xEC, 0xFB, 0xF6,
			0xD6, 0xDB, 0xCC, 0xC1, 0xE2, 0xEF, 0xF8, 0xF5, 0xBE, 0xB3, 0xA4, 0xA9, 0x8A, 0x87, 0x90, 0x9D,
			0x06, 0x0B, 0x1C, 0x11, 0x32, 0x3F, 0x28, 0x25, 0x6E, 0x63, 0x74, 0x79, 0x5A, 0x57, 0x40, 0x4D,
			0xDA, 0xD7, 0xC0, 0xCD, 0xEE, 0xE3, 0xF4, 0xF9, 0xB2, 0xBF, 0xA8, 0xA5, 0x86, 0x8B, 0x9C, 0x91,
			0x0A, 0x07, 0x10, 0x1D, 0x3E, 0x33, 0x24, 0x29, 0x62, 0x6F, 0x78, 0x75, 0x56, 0x5B, 0x4C, 0x41,
			0x61, 0x6C, 0x7B, 0x76, 0x55, 0x58, 0x4F, 0x42, 0x09, 0x04, 0x13, 0x1E, 0x3D, 0x30, 0x27, 0x2A,
			0xB1, 0xBC, 0xAB, 0xA6, 0x85, 0x88, 0x9F, 0x92, 0xD9, 0xD4, 0xC3, 0xCE, 0xED, 0xE0, 0xF7, 0xFA,
			0xB7, 0xBA, 0xAD, 0xA0, 0x83, 0x8E, 0x99, 0x94, 0xDF, 0xD2, 0xC5, 0xC8, 0xEB, 0xE6, 0xF1, 0xFC,
			0x67, 0x6A, 0x7D, 0x70, 0x53, 0x5E, 0x49, 0x44, 0x0F, 0x02, 0x15, 0x18, 0x3B, 0x36, 0x21, 0x2C,
			0x0C, 0x01, 0x16, 0x1B, 0x38, 0x35, 0x22, 0x2F, 0x64, 0x69, 0x7E, 0x73, 0x50, 0x5D, 0x4A, 0x47,
			0xDC, 0xD1, 0xC6, 0xCB, 0xE8, 0xE5, 0xF2, 0xFF, 0xB4, 0xB9, 0xAE, 0xA3, 0x80, 0x8D, 0x9A, 0x97
		};

		_AES_CONSTEXPR_11_ uint8_t gmul14[256] = {
			0x00, 0x0E, 0x1C, 0x12, 0x38, 0x36, 0x24, 0x2A, 0x70, 0x7E, 0x6C, 0x62, 0x48, 0x46, 0x54, 0x5A,
			0xE0, 0xEE, 0xFC, 0xF2, 0xD8, 0xD6, 0xC4, 0xCA, 0x90, 0x9E, 0x8C, 0x82, 0xA8, 0xA6, 0xB4, 0xBA,
			0xDB, 0xD5, 0xC7, 0xC9, 0xE3, 0xED, 0xFF, 0xF1, 0xAB, 0xA5, 0xB7, 0xB9, 0x93, 0x9D, 0x8F, 0x81,
			0x3B, 0x35, 0x27, 0x29, 0x03, 0x0D, 0x1F, 0x11, 0x4B, 0x45, 0x57, 0x59, 0x73, 0x7D, 0x6F, 0x61,
			0xAD, 0xA3, 0xB1, 0xBF, 0x95, 0x9B, 0x89, 0x87, 0xDD, 0xD3, 0xC1, 0xCF, 0xE5, 0xEB, 0xF9, 0xF7,
			0x4D, 0x43, 0x51, 0x5F, 0x75, 0x7B, 0x69, 0x67, 0x3D, 0x33, 0x21, 0x2F, 0x05, 0x0B, 0x19, 0x17,
			0x76, 0x78, 0x6A, 0x64, 0x4E, 0x40, 0x52, 0x5C, 0x06, 0x08, 0x1A, 0x14, 0x3E, 0x30, 0x22, 0x2C,
			0x96, 0x98, 0x8A, 0x84, 0xAE, 0xA0, 0xB2, 0xBC, 0xE6, 0xE8, 0xFA, 0xF4, 0xDE, 0xD0, 0xC2, 0xCC,
			0x41, 0x4F, 0x5D, 0x53, 0x79, 0x77, 0x65, 0x6B, 0x31, 0x3F, 0x2D, 0x23, 0x09, 0x07, 0x15, 0x1B,
			0xA1, 0xAF, 0xBD, 0xB3, 0x99, 0x97, 0x85, 0x8B, 0xD1, 0xDF, 0xCD, 0xC3, 0xE9, 0xE7, 0xF5, 0xFB,
			0x9A, 0x94, 0x86, 0x88, 0xA2, 0xAC, 0xBE, 0xB0, 0xEA, 0xE4, 0xF6, 0xF8, 0xD2, 0xDC, 0xCE, 0xC0,
			0x7A, 0x74, 0x66, 0x68, 0x42, 0x4C, 0x5E, 0x50, 0x0A, 0x04, 0x16, 0x18, 0x32, 0x3C, 0x2E, 0x20,
			0xEC, 0xE2, 0xF0, 0xFE, 0xD4, 0xDA, 0xC8, 0xC6, 0x9C, 0x92, 0x80, 0x8E, 0xA4, 0xAA, 0xB8, 0xB6,
			0x0C, 0x02, 0x10, 0x1E, 0x34, 0x3A, 0x28, 0x26, 0x7C, 0x72, 0x60, 0x6E, 0x44, 0x4A, 0x58, 0x56,
			0x37, 0x39, 0x2B, 0x25, 0x0F, 0x01, 0x13, 0x1D, 0x47, 0x49, 0x5B, 0x55, 0x7F, 0x71, 0x63, 0x6D,
			0xD7, 0xD9, 0xCB, 0xC5, 0xEF, 0xE1, 0xF3, 0xFD, 0xA7, 0xA9, 0xBB, 0xB5, 0x9F, 0x91, 0x83, 0x8D
		};
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
		static _AES_CONSTEXPR_11_ AES_KEY_LEN DEFAULT_MODE = AES_KEY_LEN::AES128;
		static _AES_CONSTEXPR_11_ size_t BLOCK_SIZE = 16;
		static _AES_CONSTEXPR_11_ size_t MAX_EXPKEY_SIZE = 240;

		using state_t = uint8_t[4][4];
		using block_t = uint8_t[BLOCK_SIZE];
		using exkey_t = uint8_t[MAX_EXPKEY_SIZE];

		const uint8_t KEY_SIZE = DEFAULT_MODE / 8;
	public:

		_AES_CONSTEXPR_11_ _AES_CLASS_() = default;

		_AES_CONSTEXPR_11_ _AES_CLASS_(const AES_KEY_LEN _keymode) noexcept
			: KEY_SIZE(_keymode / 8)
		{

		}

		_AES_CONSTEXPR_14_ _AES_CLASS_(const size_t _keybits)
			: KEY_SIZE(_keybits / 8)
		{
			if (_keybits % 32 != 0 || _keybits < AES_KEY_LEN::AES128 || _keybits > AES_KEY_LEN::AES256) {
				throw("Provided keybits are invalid");
			}
		}

		// Cipher feedback mode 8 Bit, encrypt
		_AES_CONSTEXPR_14_ void encrypt_cfb8(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const noexcept
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
		_AES_CONSTEXPR_14_ void decrypt_cfb8(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const noexcept
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
		_AES_CONSTEXPR_14_ void encrypt_cfb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
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
		_AES_CONSTEXPR_14_ void decrypt_cfb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
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

		// Propagating cipher block chaining mode, encrypt
		_AES_CONSTEXPR_14_ void encrypt_pcbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
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
		_AES_CONSTEXPR_14_ void decrypt_pcbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
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
				xor_blocks(cipher_block, _data);
				copy_block(block, cipher_block);
			}
		}

		// Cipher block chaining mode, encrypt
		_AES_CONSTEXPR_14_ void encrypt_cbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
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
		_AES_CONSTEXPR_14_ void decrypt_cbc(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
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

		// Counter mode, encrypt and decrypt
		_AES_CONSTEXPR_14_ void encrypt_ctr(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _nonce, const size_t _counter_state = 0) const
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
		_AES_CONSTEXPR_14_ void decrypt_ctr(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _nonce, const size_t _block_pos = 0, const size_t _counter_state = 0) const
		{
			check_block_pos(_block_pos, _datasize);
			encrypt_ctr(_data + (_block_pos * BLOCK_SIZE), _datasize - (_block_pos * BLOCK_SIZE), _key, _nonce, _counter_state + _block_pos);
		}

		// Output feedback mode, encrypt and decrypt
		_AES_CONSTEXPR_14_ void encrypt_ofb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
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
		_AES_CONSTEXPR_14_ void decrypt_ofb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const uint8_t* _iv) const
		{
			encrypt_ofb(_data, _datasize, _key, _iv);
		}

		// Electronic codebook mode, encrypt
		_AES_CONSTEXPR_14_ void encrypt_ecb(uint8_t* _data, const size_t _datasize, const uint8_t* _key) const
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
		_AES_CONSTEXPR_14_ void decrypt_ecb(uint8_t* _data, const size_t _datasize, const uint8_t* _key, const size_t _block_pos = 0) const
		{
			check_data(_datasize);
			check_block_pos(_block_pos, _datasize);

			exkey_t expkey{ };
			key_expansion(_key, expkey, KEY_SIZE);

			const uint8_t* const end = _data + _datasize;
			_data += _block_pos * BLOCK_SIZE;
			for (; _data != end; _data += BLOCK_SIZE)
			{
				decrypt_block(_data, expkey, KEY_SIZE);
			}
		}

		_AES_CONSTEXPR_14_ uint8_t keysize() const noexcept
		{
			return KEY_SIZE;
		}

	private:
		static void encrypt_block(uint8_t* const _state, const uint8_t* _round_key, const uint8_t _keysize) noexcept
		{
			state_t& state = *reinterpret_cast<state_t*>(_state);
			const size_t rounds = (_keysize / 4) + 6;

			xor_blocks(_state, _round_key);

			for (size_t round = 1; round != rounds; ++round)
			{
				sub_bytes(_state);
				shift_rows(state);
				mix_columns(state);
				xor_blocks(_state, &_round_key[round * 16]);
			}

			sub_bytes(_state);
			shift_rows(state);
			xor_blocks(_state, &_round_key[rounds * 16]);
		}

		static _AES_CONSTEXPR_14_ _AES_FORCEINLINE_ void mix_columns(state_t& _state) noexcept
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
				_state[i][0] ^= gmul02[a ^ b] ^ tmp;
				_state[i][1] ^= gmul02[b ^ c] ^ tmp;
				_state[i][2] ^= gmul02[c ^ d] ^ tmp;
				_state[i][3] ^= gmul02[d ^ a] ^ tmp;
			}
		}

		static _AES_CONSTEXPR_14_ _AES_FORCEINLINE_ void shift_rows(state_t& _state) noexcept
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

		static _AES_CONSTEXPR_14_ _AES_FORCEINLINE_ void sub_bytes(uint8_t* const _state) noexcept
		{
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				_state[i] = detail::sbox[_state[i]];
			}
		}

		static void decrypt_block(uint8_t* const _state, const uint8_t* _round_key, const uint8_t _keysize) noexcept
		{
			state_t& state = *reinterpret_cast<state_t* const>(_state);
			const size_t rounds = (_keysize / 4) + 6;

			xor_blocks(_state, &_round_key[rounds * 16]);

			for (size_t round = rounds - 1; round != 0; --round)
			{
				inv_shift_rows(state);
				inv_sub_bytes(_state);
				xor_blocks(_state, &_round_key[round * 16]);
				inv_mix_columns(state);
			}

			inv_shift_rows(state);
			inv_sub_bytes(_state);
			xor_blocks(_state, _round_key);
		}

		static _AES_CONSTEXPR_14_ _AES_FORCEINLINE_ void inv_mix_columns(state_t& _state) noexcept
		{
			using namespace detail;
			uint8_t a{ }, b{ }, c{ }, d{ };

			for (int32_t i = 0; i != 4; ++i)
			{
				a = _state[i][0];
				b = _state[i][1];
				c = _state[i][2];
				d = _state[i][3];

				_state[i][0] = gmul14[a] ^ gmul11[b] ^ gmul13[c] ^ gmul09[d];
				_state[i][1] = gmul09[a] ^ gmul14[b] ^ gmul11[c] ^ gmul13[d];
				_state[i][2] = gmul13[a] ^ gmul09[b] ^ gmul14[c] ^ gmul11[d];
				_state[i][3] = gmul11[a] ^ gmul13[b] ^ gmul09[c] ^ gmul14[d];
			}
		}

		static _AES_CONSTEXPR_14_ _AES_FORCEINLINE_ void inv_shift_rows(state_t& _state) noexcept
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

		static _AES_CONSTEXPR_14_ _AES_FORCEINLINE_ void inv_sub_bytes(uint8_t* const _state) noexcept
		{
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				_state[i] = detail::inv_sbox[_state[i]];
			}
		}

		static _AES_CONSTEXPR_14_ void key_expansion(const uint8_t* _key, exkey_t& _exkey_out, const uint8_t _keysize) noexcept
		{
			using namespace detail;

			const size_t columns = _keysize / 4;
			const size_t rounds = columns + 6;
			const size_t end = 4 * (rounds + 1);

			for (size_t i = 0; i != _keysize; ++i) {
				_exkey_out[i] = _key[i];
			}

			uint8_t tmp0{ };
			uint8_t tmp[4]{ };
			for (size_t i = columns; i != end; ++i)
			{
				tmp[0] = _exkey_out[(i - 1) * 4 + 0];
				tmp[1] = _exkey_out[(i - 1) * 4 + 1];
				tmp[2] = _exkey_out[(i - 1) * 4 + 2];
				tmp[3] = _exkey_out[(i - 1) * 4 + 3];

				if (i % columns == 0) {
					tmp0 = tmp[0];
					tmp[0] = tmp[1];
					tmp[1] = tmp[2];
					tmp[2] = tmp[3];
					tmp[3] = tmp0;

					tmp[0] = sbox[tmp[0]];
					tmp[1] = sbox[tmp[1]];
					tmp[2] = sbox[tmp[2]];
					tmp[3] = sbox[tmp[3]];

					tmp[0] = tmp[0] ^ rcon[(i / columns) - 1];
				}
				else if (columns > 6 && i % columns == 4) {
					tmp[0] = sbox[tmp[0]];
					tmp[1] = sbox[tmp[1]];
					tmp[2] = sbox[tmp[2]];
					tmp[3] = sbox[tmp[3]];
				}

				_exkey_out[i * 4 + 0] = _exkey_out[(i - columns) * 4 + 0] ^ tmp[0];
				_exkey_out[i * 4 + 1] = _exkey_out[(i - columns) * 4 + 1] ^ tmp[1];
				_exkey_out[i * 4 + 2] = _exkey_out[(i - columns) * 4 + 2] ^ tmp[2];
				_exkey_out[i * 4 + 3] = _exkey_out[(i - columns) * 4 + 3] ^ tmp[3];
			}
		}

		static _AES_CONSTEXPR_14_ void increment_counter(uint8_t* const _counter) noexcept
		{
			for (size_t i = BLOCK_SIZE - 1, counter = 1; i != 0; --i) {
				counter += _counter[i];
				_counter[i] = counter;
				counter >>= 8;
			}
		}

		static _AES_CONSTEXPR_14_ void xor_blocks(uint8_t* _dst, const uint8_t* _xor) noexcept
		{
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				_dst[i] ^= _xor[i];
			}
		}

		static _AES_CONSTEXPR_14_ void copy_block(uint8_t* _dst, const uint8_t* _src) noexcept
		{
			for (size_t i = 0; i != BLOCK_SIZE; ++i) {
				_dst[i] = _src[i];
			}
		}

		static _AES_CONSTEXPR_14_ void check_data(const size_t _size)
		{
			if (_size == 0 || _size % BLOCK_SIZE != 0) {
				throw("Inavlid _datasize specified.");
			}
		}

		static _AES_CONSTEXPR_14_ void check_block_pos(const size_t _pos, const size_t _max)
		{
			if (_pos * BLOCK_SIZE > _max - BLOCK_SIZE) {
				throw("Inavlid _block_pos specified.");
			}
		}
	};
}

#undef _AES_CLASS_
#undef _AES_NAMESPACE_
#undef _AES_FORCEINLINE_
#undef _AES_CONSTEXPR_11_
#undef _AES_CONSTEXPR_14_

#endif // _LOGE_AES_
