#pragma once

//MIT License
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files(the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions :
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

#ifndef _AES_HPP_
#define _AES_HPP_

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <random>
#include <memory>
#include <array>

namespace AES
{
    namespace detail
    {
        constexpr std::array<std::uint8_t, 16> sbox[16] = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
        };

        constexpr std::array<std::uint8_t, 16> inv_sbox[16] = {
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
        };

        constexpr std::array<std::uint8_t, 256> GF_MUL_TABLE[15] = {
            {},
            {},

            {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16,
             0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
             0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46,
             0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
             0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76,
             0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
             0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6,
             0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
             0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6,
             0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
             0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 0x1b, 0x19, 0x1f, 0x1d,
             0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
             0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d,
             0x23, 0x21, 0x27, 0x25, 0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
             0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, 0x7b, 0x79, 0x7f, 0x7d,
             0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
             0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d,
             0x83, 0x81, 0x87, 0x85, 0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
             0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5, 0xdb, 0xd9, 0xdf, 0xdd,
             0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
             0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed,
             0xe3, 0xe1, 0xe7, 0xe5},

             {0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d,
              0x14, 0x17, 0x12, 0x11, 0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39,
              0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21, 0x60, 0x63, 0x66, 0x65,
              0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
              0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d,
              0x44, 0x47, 0x42, 0x41, 0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9,
              0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1, 0xf0, 0xf3, 0xf6, 0xf5,
              0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
              0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd,
              0xb4, 0xb7, 0xb2, 0xb1, 0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99,
              0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81, 0x9b, 0x98, 0x9d, 0x9e,
              0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
              0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6,
              0xbf, 0xbc, 0xb9, 0xba, 0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2,
              0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea, 0xcb, 0xc8, 0xcd, 0xce,
              0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
              0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46,
              0x4f, 0x4c, 0x49, 0x4a, 0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62,
              0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a, 0x3b, 0x38, 0x3d, 0x3e,
              0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
              0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16,
              0x1f, 0x1c, 0x19, 0x1a},

             {},
             {},
             {},
             {},
             {},

             {0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53,
              0x6c, 0x65, 0x7e, 0x77, 0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf,
              0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7, 0x3b, 0x32, 0x29, 0x20,
              0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
              0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8,
              0xc7, 0xce, 0xd5, 0xdc, 0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49,
              0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01, 0xe6, 0xef, 0xf4, 0xfd,
              0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
              0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e,
              0x21, 0x28, 0x33, 0x3a, 0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2,
              0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa, 0xec, 0xe5, 0xfe, 0xf7,
              0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
              0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f,
              0x10, 0x19, 0x02, 0x0b, 0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8,
              0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0, 0x47, 0x4e, 0x55, 0x5c,
              0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
              0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9,
              0xf6, 0xff, 0xe4, 0xed, 0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35,
              0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d, 0xa1, 0xa8, 0xb3, 0xba,
              0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
              0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62,
              0x5d, 0x54, 0x4f, 0x46},

             {},

             {0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45,
              0x74, 0x7f, 0x62, 0x69, 0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81,
              0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9, 0x7b, 0x70, 0x6d, 0x66,
              0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
              0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e,
              0xbf, 0xb4, 0xa9, 0xa2, 0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7,
              0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f, 0x46, 0x4d, 0x50, 0x5b,
              0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
              0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8,
              0xf9, 0xf2, 0xef, 0xe4, 0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c,
              0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54, 0xf7, 0xfc, 0xe1, 0xea,
              0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
              0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02,
              0x33, 0x38, 0x25, 0x2e, 0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd,
              0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5, 0x3c, 0x37, 0x2a, 0x21,
              0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
              0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44,
              0x75, 0x7e, 0x63, 0x68, 0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80,
              0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8, 0x7a, 0x71, 0x6c, 0x67,
              0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
              0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f,
              0xbe, 0xb5, 0xa8, 0xa3},

             {},

             {0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f,
              0x5c, 0x51, 0x46, 0x4b, 0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3,
              0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b, 0xbb, 0xb6, 0xa1, 0xac,
              0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
              0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14,
              0x37, 0x3a, 0x2d, 0x20, 0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e,
              0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26, 0xbd, 0xb0, 0xa7, 0xaa,
              0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
              0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9,
              0x8a, 0x87, 0x90, 0x9d, 0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25,
              0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d, 0xda, 0xd7, 0xc0, 0xcd,
              0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
              0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75,
              0x56, 0x5b, 0x4c, 0x41, 0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42,
              0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a, 0xb1, 0xbc, 0xab, 0xa6,
              0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
              0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8,
              0xeb, 0xe6, 0xf1, 0xfc, 0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44,
              0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c, 0x0c, 0x01, 0x16, 0x1b,
              0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
              0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3,
              0x80, 0x8d, 0x9a, 0x97},

              {0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62,
               0x48, 0x46, 0x54, 0x5a, 0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca,
               0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba, 0xdb, 0xd5, 0xc7, 0xc9,
               0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
               0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59,
               0x73, 0x7d, 0x6f, 0x61, 0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87,
               0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7, 0x4d, 0x43, 0x51, 0x5f,
               0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
               0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14,
               0x3e, 0x30, 0x22, 0x2c, 0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc,
               0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc, 0x41, 0x4f, 0x5d, 0x53,
               0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
               0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3,
               0xe9, 0xe7, 0xf5, 0xfb, 0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0,
               0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0, 0x7a, 0x74, 0x66, 0x68,
               0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
               0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e,
               0xa4, 0xaa, 0xb8, 0xb6, 0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26,
               0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56, 0x37, 0x39, 0x2b, 0x25,
               0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
               0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5,
               0x9f, 0x91, 0x83, 0x8d}
        };

        constexpr std::array<std::uint8_t, 4> CMDS[4] = {
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}
        };

        constexpr std::array<std::uint8_t, 4> INV_CMDS[4] = {
            {14, 11, 13, 9},
            {9, 14, 11, 13},
            {13, 9, 14, 11},
            {11, 13, 9, 14}
        };
    }
}

namespace AES
{
    using string = std::string;
    using vector = std::vector<std::uint8_t>;
    using unique_ptr = std::unique_ptr<std::uint8_t[]>;

    enum AES_KEY
    {
        AES_128 = 128,
        AES_160 = 160,
        AES_192 = 192,
        AES_224 = 224,
        AES_256 = 256
    };
}

namespace AES
{
    _NODISCARD std::vector<std::uint8_t> random_key(const AES_KEY _len) noexcept
    {
        std::uniform_int_distribution<int32_t> dist(0, 255);
        std::vector<std::uint8_t> key(_len / 4, 0);

        for (auto& pos : key) {
            std::random_device rd;
            pos = static_cast<std::uint8_t>(dist(rd));
        }

        return key;
    }

    _NODISCARD std::vector<std::uint8_t> random_iv() noexcept
    {
        std::uniform_int_distribution<int32_t> dist(0, 255);
        std::vector<std::uint8_t> key(16, 0);

        for (auto& pos : key) {
            std::random_device rd;
            pos = static_cast<std::uint8_t>(dist(rd));
        }

        return key;
    }

    _NODISCARD static std::vector<std::uint8_t> str_to_vec(const std::string& _str) noexcept
    {
        std::vector<std::uint8_t> vec(_str.size(), 0);

        for (std::size_t i = 0; i != _str.size(); ++i) {
            vec[i] = _str[i];
        }

        return vec;
    }

    _NODISCARD static std::string vec_to_str(const std::vector<std::uint8_t>& _vec) noexcept
    {
        std::string str(_vec.size(), 0);

        for (std::size_t i = 0; i != _vec.size(); ++i) {
            str[i] = _vec[i];
        }

        return str;
    }

    void make_ready(std::vector<std::uint8_t>& _vec) noexcept
    {
        if (_vec.size() % 16 != 0) {
            _vec.resize(_vec.size() + (16 - (_vec.size() % 16)), 0);
        }
    }

    void make_ready(std::string& _str) noexcept
    {
        if (_str.size() % 16 != 0) {
            _str.resize(_str.size() + (16 - (_str.size() % 16)), 0);
        }
    }
}

namespace AES
{
    class AES
    {
    protected:
        static constexpr std::size_t BYTES = 4;
        static constexpr std::size_t BLOCK_BYTES = 4 * BYTES;
        static constexpr std::size_t IV_SIZE = BLOCK_BYTES;
        static constexpr std::size_t MAX_EXP_KEY_SIZE = 4 * BYTES * (14 + 1); // 4 * bytes * (max columns + 1)

        AES_KEY m_mode = AES_256;
        std::uint8_t m_keysize = m_mode / 4;
        std::uint8_t m_columns = m_mode / 32;
        std::uint8_t m_rounds = m_columns + 6;

        unique_ptr m_expkey = std::make_unique<std::uint8_t[]>(MAX_EXP_KEY_SIZE);
        unique_ptr m_iv = std::make_unique<std::uint8_t[]>(IV_SIZE);

    public:
        AES() = default;

        AES(const AES_KEY _key_len)
            : m_mode(_key_len)
        {

        }

        void set_key(const vector& _key)
        {
            if (_key.size() != m_keysize) {
                key_length_error();
            }
            expand_key(_key.data(), m_expkey.get());
        }

        void set_iv(const vector& _iv)
        {
            if (_iv.size() != IV_SIZE) {
                key_length_error();
            }
            std::memcpy(m_iv.get(), _iv.data(), IV_SIZE);
        }

        void set_mode(const AES_KEY _key_len)
        {
            m_mode = m_mode;
            m_keysize = m_mode / 4;
            m_columns = m_mode / 32;
            m_rounds = m_columns + 6;
            std::memset(m_expkey.get(), 0, MAX_EXP_KEY_SIZE);
        }

        void set_random_key()
        {
            set_key(random_key(m_mode));
        }

        void set_random_iv()
        {
            set_iv(random_iv());
        }

        _NODISCARD std::uint8_t* expanded_key() noexcept
        {
            return m_expkey.get();
        }

        _NODISCARD const std::uint8_t* expanded_key() const noexcept
        {
            return m_expkey.get();
        }

        _NODISCARD bool has_key() const noexcept
        {
            return (*m_expkey.get() != '\0');
        }

        _NODISCARD std::uint8_t* iv() noexcept
        {
            return m_iv.get();
        }

        _NODISCARD const std::uint8_t* iv() const noexcept
        {
            return m_iv.get();
        }

        _NODISCARD bool has_iv() const noexcept
        {
            return (*m_iv.get() != '\0');
        }

        _NODISCARD operator bool() const noexcept
        {
            return (has_key() && has_iv());
        }

        _NODISCARD AES& operator=(const AES& _aes) noexcept
        {
            if (_aes) {
                m_mode = _aes.m_mode;
                m_columns = _aes.m_columns;
                m_keysize = _aes.m_keysize;
                m_rounds = _aes.m_rounds;
                std::memcpy(m_iv.get(), _aes.m_iv.get(), IV_SIZE);
                std::memcpy(m_expkey.get(), _aes.m_expkey.get(), MAX_EXP_KEY_SIZE);
            }
            return *this;
        }

    public:
        // --- ECB ---

        // Raw
        _NODISCARD unique_ptr encrypt_ecb(const std::uint8_t* _plain, const std::uint8_t* _key, const std::size_t _plain_size)
        {
            check_data(_plain_size);

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, MAX_EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(&_plain[i], &output[i], expkey.data());
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_ecb(const std::uint8_t* _cipher, const std::uint8_t* _key, const std::size_t _cipher_size)
        {
            check_data(_cipher_size);

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, MAX_EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                decrypt_block(&_cipher[i], &output[i], expkey.data());
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_ecb(const vector& _plain, const vector& _key)
        {
            const unique_ptr output = encrypt_ecb(
                _plain.data(),
                _key.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_ecb(const vector& _cipher, const vector& _key)
        {
            const unique_ptr output = decrypt_ecb(
                _cipher.data(),
                _key.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_ecb(const string& _plain, const string& _key)
        {
            const unique_ptr output = encrypt_ecb(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                _plain.size());
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_ecb(const string& _cipher, const string& _key)
        {
            const unique_ptr output = decrypt_ecb(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // -- Internal --

        // Raw
        _NODISCARD unique_ptr encrypt_ecb(const std::uint8_t* _plain, const std::size_t _plain_size) const
        {
            check_data(_plain_size);
            check_key();

            unique_ptr output = std::make_unique<uint8_t[]>(_plain_size);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(&_plain[i], &output[i], m_expkey.get());
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_ecb(const std::uint8_t* _cipher, const std::size_t _cipher_size) const
        {
            check_data(_cipher_size);
            check_key();

            unique_ptr output = std::make_unique<uint8_t[]>(_cipher_size);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                decrypt_block(&_cipher[i], &output[i], m_expkey.get());
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_ecb(const vector& _plain) const
        {
            const unique_ptr output = encrypt_ecb(
                _plain.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_ecb(const vector& _cipher) const
        {
            const unique_ptr output = decrypt_ecb(
                _cipher.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_ecb(const string& _plain) const
        {
            const unique_ptr output = encrypt_ecb(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_ecb(const string& _cipher) const
        {
            const unique_ptr output = decrypt_ecb(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // --- CBC ---

        // Raw
        _NODISCARD unique_ptr encrypt_cbc(const std::uint8_t* _plain, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _plain_size)
        {
            check_data(_plain_size);

            std::array<std::uint8_t, BLOCK_BYTES> block;

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, MAX_EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(block.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                xor_blocks(block.data(), &_plain[i], block.data());
                encrypt_block(block.data(), &output[i], expkey.data());
                std::memcpy(block.data(), &output[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_cbc(const std::uint8_t* _cipher, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _cipher_size)
        {
            check_data(_cipher_size);

            std::array<std::uint8_t, BLOCK_BYTES> block;

            unique_ptr output = std::make_unique<uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, MAX_EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(block.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                decrypt_block(&_cipher[i], &output[i], expkey.data());
                xor_blocks(block.data(), &output[i], &output[i]);
                std::memcpy(block.data(), &_cipher[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_cbc(const vector& _plain, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = encrypt_cbc(
                _plain.data(),
                _key.data(),
                _iv.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_cbc(const vector& _cipher, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = decrypt_cbc(
                _cipher.data(),
                _key.data(),
                _iv.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_cbc(const string& _plain, const string& _key, const string& _iv)
        {
            const unique_ptr output = encrypt_cbc(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_cbc(const string& _cipher, const string& _key, const string& _iv)
        {
            const unique_ptr output = decrypt_cbc(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // -- Internal --

        // Raw
        _NODISCARD unique_ptr encrypt_cbc(const std::uint8_t* _plain, const std::size_t _plain_size) const
        {
            check_data(_plain_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, BLOCK_BYTES> block;

            std::memcpy(block.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                xor_blocks(block.data(), &_plain[i], block.data());
                encrypt_block(block.data(), &output[i], m_expkey.get());
                std::memcpy(block.data(), &output[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_cbc(const std::uint8_t* _cipher, const std::size_t _cipher_size) const
        {
            check_data(_cipher_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, BLOCK_BYTES> block;

            std::memcpy(block.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                decrypt_block(&_cipher[i], &output[i], m_expkey.get());
                xor_blocks(block.data(), &output[i], &output[i]);
                std::memcpy(block.data(), &_cipher[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_cbc(const vector& _plain)
        {
            const unique_ptr output = encrypt_cbc(
                _plain.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_cbc(const vector& _cipher)
        {
            const unique_ptr output = decrypt_cbc(
                _cipher.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_cbc(const string& _plain)
        {
            const unique_ptr output = encrypt_cbc(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_cbc(const string& _cipher)
        {
            const unique_ptr output = decrypt_cbc(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // --- CTR ---

        // Raw
        _NODISCARD unique_ptr encrypt_ctr(const std::uint8_t* _plain, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _plain_size)
        {
            check_data(_plain_size);

            std::array<std::uint8_t, BLOCK_BYTES> counter;
            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, BLOCK_BYTES> block;
            std::array<std::uint8_t, MAX_EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(counter.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(counter.data(), block.data(), expkey.data());
                xor_blocks(block.data(), &_plain[i], &output[i]);
                increment_counter(counter.data());
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_ctr(const std::uint8_t* _cipher, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _cipher_size)
        {
            check_data(_cipher_size);

            std::array<std::uint8_t, BLOCK_BYTES> counter;
            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, BLOCK_BYTES> block;
            std::array<std::uint8_t, MAX_EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(counter.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                encrypt_block(counter.data(), block.data(), expkey.data());
                xor_blocks(&_cipher[i], block.data(), &output[i]);
                increment_counter(counter.data());
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_ctr(const vector& _plain, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = encrypt_ctr(
                _plain.data(),
                _key.data(),
                _iv.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_ctr(const vector& _cipher, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = decrypt_ctr(
                _cipher.data(),
                _key.data(),
                _iv.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_ctr(const string& _plain, const string& _key, const string& _iv)
        {
            const unique_ptr output = encrypt_ctr(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_ctr(const string& _cipher, const string& _key, const string& _iv)
        {
            const unique_ptr output = decrypt_ctr(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // -- Internal --

        // Raw
        _NODISCARD unique_ptr encrypt_ctr(const std::uint8_t* _plain, const std::size_t _plain_size) const
        {
            check_data(_plain_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, BLOCK_BYTES> counter;
            std::array<std::uint8_t, BLOCK_BYTES> block;

            std::memcpy(counter.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(counter.data(), block.data(), m_expkey.get());
                xor_blocks(block.data(), &_plain[i], &output[i]);
                increment_counter(counter.data());
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_ctr(const std::uint8_t* _cipher, const std::size_t _cipher_size) const
        {
            check_data(_cipher_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, BLOCK_BYTES> counter;
            std::array<std::uint8_t, BLOCK_BYTES> block;

            std::memcpy(counter.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                encrypt_block(counter.data(), block.data(), m_expkey.get());
                xor_blocks(&_cipher[i], block.data(), &output[i]);
                increment_counter(counter.data());
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_ctr(const vector& _plain)
        {
            const unique_ptr output = encrypt_ctr(
                _plain.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_ctr(const vector& _cipher)
        {
            const unique_ptr output = decrypt_ctr(
                _cipher.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_ctr(const string& _plain)
        {
            const unique_ptr output = encrypt_ctr(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_ctr(const string& _cipher)
        {
            const unique_ptr output = decrypt_ctr(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // --- CFB ---

        // Raw
        _NODISCARD unique_ptr encrypt_cfb(const std::uint8_t* _plain, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _plain_size)
        {
            check_data(_plain_size);

            std::array<std::uint8_t, BLOCK_BYTES> block, encrypted_block;

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, MAX_EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(block.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(block.data(), encrypted_block.data(), expkey.data());
                xor_blocks(&_plain[i], encrypted_block.data(), &output[i]);
                std::memcpy(block.data(), &output[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_cfb(const std::uint8_t* _cipher, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _cipher_size)
        {
            check_data(_cipher_size);

            std::array<std::uint8_t, BLOCK_BYTES> block, encrypted_block;

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, MAX_EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(block.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                encrypt_block(block.data(), encrypted_block.data(), expkey.data());
                xor_blocks(&_cipher[i], encrypted_block.data(), &output[i]);
                std::memcpy(block.data(), &_cipher[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_cfb(const vector& _plain, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = encrypt_cfb(
                _plain.data(),
                _key.data(),
                _iv.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_cfb(const vector& _cipher, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = decrypt_cfb(
                _cipher.data(),
                _key.data(),
                _iv.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_cfb(const string& _plain, const string& _key, const string& _iv)
        {
            const unique_ptr output = encrypt_cfb(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_cfb(const string& _cipher, const string& _key, const string& _iv)
        {
            const unique_ptr output = decrypt_cfb(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // -- Internal --

        // Raw
        _NODISCARD unique_ptr encrypt_cfb(const std::uint8_t* _plain, const std::size_t _plain_size) const
        {
            check_data(_plain_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, BLOCK_BYTES> block, encrypted_block;

            std::memcpy(block.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(block.data(), encrypted_block.data(), m_expkey.get());
                xor_blocks(&_plain[i], encrypted_block.data(), &output[i]);
                std::memcpy(block.data(), &output[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_cfb(const std::uint8_t* _cipher, const std::size_t _cipher_size) const
        {
            check_data(_cipher_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, BLOCK_BYTES> block, encrypted_block;

            std::memcpy(block.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                encrypt_block(block.data(), encrypted_block.data(), m_expkey.get());
                xor_blocks(&_cipher[i], encrypted_block.data(), &output[i]);
                std::memcpy(block.data(), &_cipher[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_cfb(const vector& _plain)
        {
            const unique_ptr output = encrypt_cfb(
                _plain.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_cfb(const vector& _cipher)
        {
            const unique_ptr output = decrypt_cfb(
                _cipher.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_cfb(const string& _plain)
        {
            const unique_ptr output = encrypt_cfb(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_cfb(const string& _cipher)
        {
            const unique_ptr output = decrypt_cfb(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

    private:
        void check_key() const
        {
            if (!has_key())
            {
                throw std::bad_exception();
            }
        }

        void check_iv() const
        {
            if (!has_iv())
            {
                throw std::bad_exception();
            }
        }

        void encrypt_block(const std::uint8_t* _plain, std::uint8_t* _output, const std::uint8_t* _expkey) const noexcept
        {
            std::array<std::array<std::uint8_t, BYTES>, 4> state;

            auto sub_bytes = [&state]() noexcept -> void
            {
                for (std::uint32_t i = 0; i < 4; ++i) {
                    for (std::uint32_t j = 0, t; j < BYTES; ++j) {
                        t = state[i][j];
                        state[i][j] = detail::sbox[t / 16][t % 16];
                    }
                }
            };

            auto mix_columns = [&state]() noexcept -> void
            {
                std::array<std::array<std::uint8_t, BYTES>, 4> temp_state{ };

                for (std::uint32_t i = 0; i < 4; ++i) {
                    for (std::uint32_t k = 0; k < 4; ++k) {
                        for (std::uint32_t j = 0; j < 4; ++j)
                        {
                            if (detail::CMDS[i][k] == 1) {
                                temp_state[i][j] ^= state[k][j];
                            }
                            else {
                                temp_state[i][j] ^= detail::GF_MUL_TABLE[detail::CMDS[i][k]][state[k][j]];
                            }
                        }
                    }
                }

                std::memcpy(state.data(), temp_state.data(), 4 * BYTES);
            };

            auto shift_rows = [this, &state]() noexcept -> void
            {
                shift_row(state, 1, 1);
                shift_row(state, 2, 2);
                shift_row(state, 3, 3);
            };

            for (std::size_t i = 0; i < 4; ++i) {
                for (std::uint32_t j = 0; j < BYTES; ++j)
                {
                    state[i][j] = _plain[i + 4 * j];
                }
            }

            add_round_key(state, _expkey);

            for (std::size_t round = 1; round <= m_rounds - 1; ++round)
            {
                sub_bytes();
                shift_rows();
                mix_columns();
                add_round_key(state, _expkey + round * 4 * BYTES);
            }

            sub_bytes();
            shift_rows();
            add_round_key(state, _expkey + m_rounds * 4 * BYTES);

            for (std::size_t i = 0; i < 4; ++i) {
                for (std::uint32_t j = 0; j < BYTES; ++j)
                {
                    _output[i + 4 * j] = state[i][j];
                }
            }
        }

        void decrypt_block(const std::uint8_t* _cipher, std::uint8_t* _output, const std::uint8_t* _expkey) const noexcept
        {
            std::array<std::array<std::uint8_t, BYTES>, 4> state;

            auto inv_sub_bytes = [&state]() noexcept -> void
            {
                for (std::uint32_t i = 0; i < 4; ++i) {
                    for (std::uint32_t j = 0, t; j < BYTES; ++j)
                    {
                        t = state[i][j];
                        state[i][j] = detail::inv_sbox[t / 16][t % 16];
                    }
                }
            };

            auto inv_mix_columns = [&state]() noexcept -> void
            {
                std::array<std::array<std::uint8_t, BYTES>, 4> temp_state{ };

                for (std::uint32_t i = 0; i < 4; ++i) {
                    for (std::uint32_t k = 0; k < 4; ++k) {
                        for (std::uint32_t j = 0; j < 4; ++j)
                        {
                            temp_state[i][j] ^= detail::GF_MUL_TABLE[detail::INV_CMDS[i][k]][state[k][j]];
                        }
                    }
                }

                std::memcpy(state.data(), temp_state.data(), 4 * BYTES);
            };

            auto inv_shift_rows = [this, &state]() noexcept -> void
            {
                shift_row(state, 1, BYTES - 1);
                shift_row(state, 2, BYTES - 2);
                shift_row(state, 3, BYTES - 3);
            };

            for (std::size_t i = 0; i < 4; ++i) {
                for (std::size_t j = 0; j < BYTES; ++j)
                {
                    state[i][j] = _cipher[i + 4 * j];
                }
            }

            add_round_key(state, _expkey + m_rounds * 4 * BYTES);

            for (std::size_t round = m_rounds - 1; round >= 1; --round)
            {
                inv_sub_bytes();
                inv_shift_rows();
                add_round_key(state, _expkey + round * 4 * BYTES);
                inv_mix_columns();
            }

            inv_sub_bytes();
            inv_shift_rows();
            add_round_key(state, _expkey);

            for (std::size_t i = 0; i < 4; ++i) {
                for (std::size_t j = 0; j < BYTES; ++j)
                {
                    _output[i + 4 * j] = state[i][j];
                }
            }
        }

        void expand_key(const std::uint8_t* _key, std::uint8_t* _dst) const noexcept
        {
            std::array<std::uint8_t, 4> rcon{ };
            std::array<std::uint8_t, 4> temp;

            auto rot_word = [&temp]() noexcept -> void
            {
                const std::uint8_t c = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = c;
            };

            auto sub_word = [&temp]() noexcept -> void
            {
                for (std::uint32_t i = 0; i < 4; ++i)
                {
                    temp[i] = detail::sbox[temp[i] / 16][temp[i] % 16];
                }
            };

            auto xor_words = [&temp, rcon]() noexcept -> void
            {
                for (std::uint32_t i = 0; i < 4; ++i)
                {
                    temp[i] = temp[i] ^ rcon[i];
                }
            };

            auto r_con = [&rcon](const std::uint32_t _n) noexcept -> void
            {
                std::uint8_t c = 1;

                for (std::uint32_t i = 0; i < _n - 1; ++i)
                {
                    c = (c << 1) ^ (((c >> 7) & 1) * 0x1B);
                }

                rcon[0] = c;
                rcon[1] = rcon[2] = rcon[3] = 0;
            };

            std::memcpy(_dst, _key, 4 * m_columns);

            for (std::size_t i = 4 * m_columns; i < 4 * BYTES * (m_rounds + 1); i += 4)
            {
                temp[0] = _dst[i - 4 + 0];
                temp[1] = _dst[i - 4 + 1];
                temp[2] = _dst[i - 4 + 2];
                temp[3] = _dst[i - 4 + 3];

                if (i / 4 % m_columns == 0)
                {
                    rot_word();
                    sub_word();
                    r_con(i / (m_columns * 4));
                    xor_words();
                }
                else if (m_columns > 6 && i / 4 % m_columns == 4)
                {
                    sub_word();
                }

                _dst[i + 0] = _dst[i - 4 * m_columns] ^ temp[0];
                _dst[i + 1] = _dst[i + 1 - 4 * m_columns] ^ temp[1];
                _dst[i + 2] = _dst[i + 2 - 4 * m_columns] ^ temp[2];
                _dst[i + 3] = _dst[i + 3 - 4 * m_columns] ^ temp[3];
            }
        }

        static void check_data(const std::size_t _size)
        {
            if (!_size || _size % BLOCK_BYTES != 0)
            {
                data_length_error();
            }
        }

        static void increment_counter(std::uint8_t* _counter) noexcept
        {
            std::uint32_t* p = reinterpret_cast<std::uint32_t*>(_counter);
            std::uint32_t carry = 1;
            for (std::int64_t i = BLOCK_BYTES / 4 - 1; i >= 0; --i)
            {
                const std::size_t sum = static_cast<std::size_t>(p[i]) + carry;
                p[i] = static_cast<std::uint32_t>(sum);
                carry = static_cast<std::uint32_t>(sum >> 32);
            }
        }

        static void add_round_key(std::array<std::array<std::uint8_t, BYTES>, 4>& _state, const std::uint8_t* _key) noexcept
        {
            for (std::uint32_t i = 0; i < 4; ++i) {
                for (std::uint32_t j = 0; j < BYTES; ++j)
                {
                    _state[i][j] = _state[i][j] ^ _key[i + 4 * j];
                }
            }
        };

        static void shift_row(std::array<std::array<std::uint8_t, BYTES>, 4>& _state, const std::uint32_t _i, const std::uint32_t _n) noexcept
        {
            std::array<std::uint8_t, BYTES> tmp;

            for (std::size_t i = 0; i < BYTES; ++i)
            {
                tmp[i] = _state[_i][(i + _n) % BYTES];
            }

            std::memcpy(_state[_i].data(), tmp.data(), BYTES);
        }

        static constexpr void xor_blocks(const std::uint8_t* _block1, const std::uint8_t* _block2, std::uint8_t* _dest_block) noexcept
        {
            for (std::uint32_t i = 0; i < BLOCK_BYTES; ++i)
            {
                _dest_block[i] = _block1[i] ^ _block2[i];
            }
        }

        static __declspec(noreturn) void key_length_error()
        {
            throw std::length_error("key length must be KEY_SIZE");
        }

        static __declspec(noreturn) void iv_length_error()
        {
            throw std::length_error("IV size is not IV_SIZE or not set");
        }

        static __declspec(noreturn) void data_length_error()
        {
            throw std::length_error("length of data must be divisible by BLOCK_BYTES and should`t be 0");
        }
    };
}

namespace AES
{
    template <AES_KEY MODE = AES_256>
    class AES_T
    {
    protected:
        static constexpr std::size_t BYTES = 4;
        static constexpr std::size_t BLOCK_BYTES = 4 * BYTES;
        static constexpr std::size_t IV_SIZE = BLOCK_BYTES;
        static constexpr std::size_t KEY_SIZE = MODE / 4;
        static constexpr std::size_t COLUMNS = MODE / 32;
        static constexpr std::size_t ROUNDS = COLUMNS + 6;
        static constexpr std::size_t EXP_KEY_SIZE = 4 * BYTES * (ROUNDS + 1);

        unique_ptr m_expkey = std::make_unique<std::uint8_t[]>(EXP_KEY_SIZE);
        unique_ptr m_iv = std::make_unique<std::uint8_t[]>(IV_SIZE);

    public:
        constexpr AES_T() = default;

        constexpr void set_key(const vector& _key)
        {
            if (_key.size() != KEY_SIZE) {
                key_length_error();
            }
            expand_key(_key.data(), m_expkey.get());
        }

        constexpr void set_iv(const vector& _iv)
        {
            if (_iv.size() != IV_SIZE) {
                key_length_error();
            }
            std::memcpy(m_iv.get(), _iv.data(), IV_SIZE);
        }

        void set_random_key()
        {
            set_key(random_key(MODE));
        }

        void set_random_iv()
        {
            set_iv(random_iv());
        }

        _NODISCARD constexpr std::uint8_t* expanded_key() noexcept
        {
            return m_expkey.get();
        }

        _NODISCARD constexpr const std::uint8_t* expanded_key() const noexcept
        {
            return m_expkey.get();
        }

        _NODISCARD constexpr bool has_key() const noexcept
        {
            return (*m_expkey.get() != '\0');
        }

        _NODISCARD constexpr std::uint8_t* iv() noexcept
        {
            return m_iv.get();
        }

        _NODISCARD constexpr const std::uint8_t* iv() const noexcept
        {
            return m_iv.get();
        }

        _NODISCARD constexpr bool has_iv() const noexcept
        {
            return (*m_iv.get() != '\0');
        }

        _NODISCARD constexpr operator bool() const noexcept
        {
            return (has_key() && has_iv());
        }

        _NODISCARD constexpr AES_T& operator=(const AES_T& _aes) noexcept
        {
            if (_aes) {
                std::memcpy(m_expkey.get(), _aes.m_expkey.get(), EXP_KEY_SIZE);
                std::memcpy(m_iv.get(), _aes.m_iv.get(), IV_SIZE);
            }
            return *this;
        }

    public:
        // --- ECB ---

        // Raw
        _NODISCARD static unique_ptr encrypt_ecb(const std::uint8_t* _plain, const std::uint8_t* _key, const std::size_t _plain_size)
        {
            check_data(_plain_size);

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(&_plain[i], &output[i], expkey.data());
            }

            return std::move(output);
        }

        _NODISCARD static unique_ptr decrypt_ecb(const std::uint8_t* _cipher, const std::uint8_t* _key, const std::size_t _cipher_size)
        {
            check_data(_cipher_size);

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                decrypt_block(&_cipher[i], &output[i], expkey.data());
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD static vector encrypt_ecb(const vector& _plain, const vector& _key)
        {
            const unique_ptr output = encrypt_ecb(
                _plain.data(),
                _key.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static vector decrypt_ecb(const vector& _cipher, const vector& _key)
        {
            const unique_ptr output = decrypt_ecb(
                _cipher.data(), 
                _key.data(), 
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD static string encrypt_ecb(const string& _plain, const string& _key)
        {
            const unique_ptr output = encrypt_ecb(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                _plain.size());
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static string decrypt_ecb(const string& _cipher, const string& _key)
        {
            const unique_ptr output = decrypt_ecb(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // -- Internal --

        // Raw
        _NODISCARD unique_ptr encrypt_ecb(const std::uint8_t* _plain, const std::size_t _plain_size) const
        {
            check_data(_plain_size);
            check_key();

            unique_ptr output = std::make_unique<uint8_t[]>(_plain_size);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(&_plain[i], &output[i], m_expkey.get());
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_ecb(const std::uint8_t* _cipher, const std::size_t _cipher_size) const
        {
            check_data(_cipher_size);
            check_key();

            unique_ptr output = std::make_unique<uint8_t[]>(_cipher_size);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                decrypt_block(&_cipher[i], &output[i], m_expkey.get());
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_ecb(const vector& _plain) const
        {
            const unique_ptr output = encrypt_ecb(
                _plain.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_ecb(const vector& _cipher) const
        {
            const unique_ptr output = decrypt_ecb(
                _cipher.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_ecb(const string& _plain) const
        {
            const unique_ptr output = encrypt_ecb(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_ecb(const string& _cipher) const
        {
            const unique_ptr output = decrypt_ecb(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // --- CBC ---

        // Raw
        _NODISCARD static unique_ptr encrypt_cbc(const std::uint8_t* _plain, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _plain_size)
        {
            check_data(_plain_size);

            std::array<std::uint8_t, BLOCK_BYTES> block;

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(block.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                xor_blocks(block.data(), &_plain[i], block.data());
                encrypt_block(block.data(), &output[i], expkey.data());
                std::memcpy(block.data(), &output[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        _NODISCARD static unique_ptr decrypt_cbc(const std::uint8_t* _cipher, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _cipher_size)
        {
            check_data(_cipher_size);

            std::array<std::uint8_t, BLOCK_BYTES> block;

            unique_ptr output = std::make_unique<uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(block.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                decrypt_block(&_cipher[i], &output[i], expkey.data());
                xor_blocks(block.data(), &output[i], &output[i]);
                std::memcpy(block.data(), &_cipher[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD static vector encrypt_cbc(const vector& _plain, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = encrypt_cbc(
                _plain.data(),
                _key.data(),
                _iv.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static vector decrypt_cbc(const vector& _cipher, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = decrypt_cbc(
                _cipher.data(),
                _key.data(),
                _iv.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD static string encrypt_cbc(const string& _plain, const string& _key, const string& _iv)
        {
            const unique_ptr output = encrypt_cbc(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static vector decrypt_cbc(const string& _cipher, const string& _key, const string& _iv)
        {
            const unique_ptr output = decrypt_cbc(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // -- Internal --

        // Raw
        _NODISCARD unique_ptr encrypt_cbc(const std::uint8_t* _plain, const std::size_t _plain_size) const
        {
            check_data(_plain_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, BLOCK_BYTES> block;

            std::memcpy(block.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                xor_blocks(block.data(), &_plain[i], block.data());
                encrypt_block(block.data(), &output[i], m_expkey.get());
                std::memcpy(block.data(), &output[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_cbc(const std::uint8_t* _cipher, const std::size_t _cipher_size) const
        {
            check_data(_cipher_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, BLOCK_BYTES> block;

            std::memcpy(block.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                decrypt_block(&_cipher[i], &output[i], m_expkey.get());
                xor_blocks(block.data(), &output[i], &output[i]);
                std::memcpy(block.data(), &_cipher[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_cbc(const vector& _plain)
        {
            const unique_ptr output = encrypt_cbc(
                _plain.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_cbc(const vector& _cipher)
        {
            const unique_ptr output = decrypt_cbc(
                _cipher.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_cbc(const string& _plain)
        {
            const unique_ptr output = encrypt_cbc(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_cbc(const string& _cipher)
        {
            const unique_ptr output = decrypt_cbc(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // --- CTR ---

        // Raw
        _NODISCARD static unique_ptr encrypt_ctr(const std::uint8_t* _plain, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _plain_size)
        {
            check_data(_plain_size);

            std::array<std::uint8_t, BLOCK_BYTES> counter;
            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, BLOCK_BYTES> block;
            std::array<std::uint8_t, EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(counter.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(counter.data(), block.data(), expkey.data());
                xor_blocks(block.data(), &_plain[i], &output[i]);
                increment_counter(counter.data());
            }

            return std::move(output);
        }

        _NODISCARD static unique_ptr decrypt_ctr(const std::uint8_t* _cipher, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _cipher_size)
        {
            check_data(_cipher_size);

            std::array<std::uint8_t, BLOCK_BYTES> counter;
            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, BLOCK_BYTES> block;
            std::array<std::uint8_t, EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(counter.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                encrypt_block(counter.data(), block.data(), expkey.data());
                xor_blocks(&_cipher[i], block.data(), &output[i]);
                increment_counter(counter.data());
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD static vector encrypt_ctr(const vector& _plain, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = encrypt_ctr(
                _plain.data(),
                _key.data(),
                _iv.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static vector decrypt_ctr(const vector& _cipher, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = decrypt_ctr(
                _cipher.data(),
                _key.data(),
                _iv.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD static string encrypt_ctr(const string& _plain, const string& _key, const string& _iv)
        {
            const unique_ptr output = encrypt_ctr(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static vector decrypt_ctr(const string& _cipher, const string& _key, const string& _iv)
        {
            const unique_ptr output = decrypt_ctr(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // -- Internal --

        // Raw
        _NODISCARD unique_ptr encrypt_ctr(const std::uint8_t* _plain, const std::size_t _plain_size) const
        {
            check_data(_plain_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, BLOCK_BYTES> counter;
            std::array<std::uint8_t, BLOCK_BYTES> block;

            std::memcpy(counter.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(counter.data(), block.data(), m_expkey.get());
                xor_blocks(block.data(), &_plain[i], &output[i]);
                increment_counter(counter.data());
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_ctr(const std::uint8_t* _cipher, const std::size_t _cipher_size) const
        {
            check_data(_cipher_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, BLOCK_BYTES> counter;
            std::array<std::uint8_t, BLOCK_BYTES> block;

            std::memcpy(counter.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                encrypt_block(counter.data(), block.data(), m_expkey.get());
                xor_blocks(&_cipher[i], block.data(), &output[i]);
                increment_counter(counter.data());
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_ctr(const vector& _plain)
        {
            const unique_ptr output = encrypt_ctr(
                _plain.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_ctr(const vector& _cipher)
        {
            const unique_ptr output = decrypt_ctr(
                _cipher.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_ctr(const string& _plain)
        {
            const unique_ptr output = encrypt_ctr(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_ctr(const string& _cipher)
        {
            const unique_ptr output = decrypt_ctr(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // --- CFB ---

        // Raw
        _NODISCARD static unique_ptr encrypt_cfb(const std::uint8_t* _plain, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _plain_size)
        {
            check_data(_plain_size);

            std::array<std::uint8_t, BLOCK_BYTES> block, encrypted_block;

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(block.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(block.data(), encrypted_block.data(), expkey.data());
                xor_blocks(&_plain[i], encrypted_block.data(), &output[i]);
                std::memcpy(block.data(), &output[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        _NODISCARD static unique_ptr decrypt_cfb(const std::uint8_t* _cipher, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _cipher_size)
        {
            check_data(_cipher_size);

            std::array<std::uint8_t, BLOCK_BYTES> block, encrypted_block;

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, EXP_KEY_SIZE> expkey;

            expand_key(_key, expkey.data());
            std::memcpy(block.data(), _iv, BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                encrypt_block(block.data(), encrypted_block.data(), expkey.data());
                xor_blocks(&_cipher[i], encrypted_block.data(), &output[i]);
                std::memcpy(block.data(), &_cipher[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD static vector encrypt_cfb(const vector& _plain, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = encrypt_cfb(
                _plain.data(),
                _key.data(),
                _iv.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static vector decrypt_cfb(const vector& _cipher, const vector& _key, const vector& _iv)
        {
            const unique_ptr output = decrypt_cfb(
                _cipher.data(),
                _key.data(),
                _iv.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD static string encrypt_cfb(const string& _plain, const string& _key, const string& _iv)
        {
            const unique_ptr output = encrypt_cfb(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static string decrypt_cfb(const string& _cipher, const string& _key, const string& _iv)
        {
            const unique_ptr output = decrypt_cfb(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                reinterpret_cast<const std::uint8_t*>(_key.data()),
                reinterpret_cast<const std::uint8_t*>(_iv.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

        // -- Internal --

        // Raw
        _NODISCARD unique_ptr encrypt_cfb(const std::uint8_t* _plain, const std::size_t _plain_size) const
        {
            check_data(_plain_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_plain_size);
            std::array<std::uint8_t, BLOCK_BYTES> block, encrypted_block;

            std::memcpy(block.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _plain_size; i += BLOCK_BYTES)
            {
                encrypt_block(block.data(), encrypted_block.data(), m_expkey.get());
                xor_blocks(&_plain[i], encrypted_block.data(), &output[i]);
                std::memcpy(block.data(), &output[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        _NODISCARD unique_ptr decrypt_cfb(const std::uint8_t* _cipher, const std::size_t _cipher_size) const
        {
            check_data(_cipher_size);
            check_key();
            check_iv();

            unique_ptr output = std::make_unique<std::uint8_t[]>(_cipher_size);
            std::array<std::uint8_t, BLOCK_BYTES> block, encrypted_block;

            std::memcpy(block.data(), m_iv.get(), BLOCK_BYTES);

            for (std::size_t i = 0; i < _cipher_size; i += BLOCK_BYTES)
            {
                encrypt_block(block.data(), encrypted_block.data(), m_expkey.get());
                xor_blocks(&_cipher[i], encrypted_block.data(), &output[i]);
                std::memcpy(block.data(), &_cipher[i], BLOCK_BYTES);
            }

            return std::move(output);
        }

        // Vector
        _NODISCARD vector encrypt_cfb(const vector& _plain)
        {
            const unique_ptr output = encrypt_cfb(
                _plain.data(),
                _plain.size()
            );
            return vector(output.get(), output.get() + _plain.size());
        }

        _NODISCARD vector decrypt_cfb(const vector& _cipher)
        {
            const unique_ptr output = decrypt_cfb(
                _cipher.data(),
                _cipher.size()
            );
            return vector(output.get(), output.get() + _cipher.size());
        }

        // String
        _NODISCARD string encrypt_cfb(const string& _plain)
        {
            const unique_ptr output = encrypt_cfb(
                reinterpret_cast<const std::uint8_t*>(_plain.data()),
                _plain.size()
            );
            return string(output.get(), output.get() + _plain.size());
        }

        _NODISCARD string decrypt_cfb(const string& _cipher)
        {
            const unique_ptr output = decrypt_cfb(
                reinterpret_cast<const std::uint8_t*>(_cipher.data()),
                _cipher.size()
            );
            return string(output.get(), output.get() + _cipher.size());
        }

    private:
        constexpr void check_key() const
        {
            if (!has_key())
            {
                throw std::bad_exception();
            }
        }

        constexpr void check_iv() const
        {
            if (!has_iv())
            {
                throw std::bad_exception();
            }
        }

        static constexpr void check_data(const std::size_t _size)
        {
            if (!_size || _size % BLOCK_BYTES != 0)
            {
                data_length_error();
            }
        }

        static constexpr void increment_counter(std::uint8_t* _counter)
        {
            std::uint32_t* p = reinterpret_cast<std::uint32_t*>(_counter);
            std::uint32_t carry = 1;
            for (std::int64_t i = BLOCK_BYTES / 4 - 1; i >= 0; --i)
            {
                const std::size_t sum = static_cast<std::size_t>(p[i]) + carry;
                p[i] = static_cast<std::uint32_t>(sum);
                carry = static_cast<std::uint32_t>(sum >> 32);
            }
        }

        static constexpr void encrypt_block(const std::uint8_t* _plain, std::uint8_t* _output, const std::uint8_t* _expkey) noexcept
        {
            std::array<std::array<std::uint8_t, BYTES>, 4> state;

            auto sub_bytes = [&state]() noexcept -> void
            {
                for (std::uint32_t i = 0; i < 4; ++i) {
                    for (std::uint32_t j = 0, t; j < BYTES; ++j) {
                        t = state[i][j];
                        state[i][j] = detail::sbox[t / 16][t % 16];
                    }
                }
            };

            auto mix_columns = [&state]() noexcept -> void
            {
                std::array<std::array<std::uint8_t, BYTES>, 4> temp_state{ };

                for (std::uint32_t i = 0; i < 4; ++i) {
                    for (std::uint32_t k = 0; k < 4; ++k) {
                        for (std::uint32_t j = 0; j < 4; ++j)
                        {
                            if (detail::CMDS[i][k] == 1) {
                                temp_state[i][j] ^= state[k][j];
                            }
                            else {
                                temp_state[i][j] ^= detail::GF_MUL_TABLE[detail::CMDS[i][k]][state[k][j]];
                            }
                        }
                    }
                }

                std::memcpy(state.data(), temp_state.data(), 4 * BYTES);
            };

            auto shift_rows = [&state]() noexcept -> void
            {
                shift_row(state, 1, 1);
                shift_row(state, 2, 2);
                shift_row(state, 3, 3);
            };

            for (std::size_t i = 0; i < 4; ++i) {
                for (std::uint32_t j = 0; j < BYTES; ++j)
                {
                    state[i][j] = _plain[i + 4 * j];
                }
            }

            add_round_key(state, _expkey);

            for (std::size_t round = 1; round <= ROUNDS - 1; ++round)
            {
                sub_bytes();
                shift_rows();
                mix_columns();
                add_round_key(state, _expkey + round * 4 * BYTES);
            }

            sub_bytes();
            shift_rows();
            add_round_key(state, _expkey + ROUNDS * 4 * BYTES);

            for (std::size_t i = 0; i < 4; ++i) {
                for (std::uint32_t j = 0; j < BYTES; ++j)
                {
                    _output[i + 4 * j] = state[i][j];
                }
            }
        }

        static constexpr void decrypt_block(const std::uint8_t* _cipher, std::uint8_t* _output, const std::uint8_t* _expkey) noexcept
        {
            std::array<std::array<std::uint8_t, BYTES>, 4> state;

            auto inv_sub_bytes = [&state]() noexcept -> void
            {
                for (std::uint32_t i = 0; i < 4; ++i) {
                    for (std::uint32_t j = 0, t; j < BYTES; ++j)
                    {
                        t = state[i][j];
                        state[i][j] = detail::inv_sbox[t / 16][t % 16];
                    }
                }
            };

            auto inv_mix_columns = [&state]() noexcept -> void
            {
                std::array<std::array<std::uint8_t, BYTES>, 4> temp_state{ };

                for (std::uint32_t i = 0; i < 4; ++i) {
                    for (std::uint32_t k = 0; k < 4; ++k) {
                        for (std::uint32_t j = 0; j < 4; ++j)
                        {
                            temp_state[i][j] ^= detail::GF_MUL_TABLE[detail::INV_CMDS[i][k]][state[k][j]];
                        }
                    }
                }

                std::memcpy(state.data(), temp_state.data(), 4 * BYTES);
            };

            auto inv_shift_rows = [&state]() noexcept -> void
            {
                shift_row(state, 1, BYTES - 1);
                shift_row(state, 2, BYTES - 2);
                shift_row(state, 3, BYTES - 3);
            };

            for (std::size_t i = 0; i < 4; ++i) {
                for (std::size_t j = 0; j < BYTES; ++j)
                {
                    state[i][j] = _cipher[i + 4 * j];
                }
            }

            add_round_key(state, _expkey + ROUNDS * 4 * BYTES);

            for (std::size_t round = ROUNDS - 1; round >= 1; --round)
            {
                inv_sub_bytes();
                inv_shift_rows();
                add_round_key(state, _expkey + round * 4 * BYTES);
                inv_mix_columns();
            }

            inv_sub_bytes();
            inv_shift_rows();
            add_round_key(state, _expkey);

            for (std::size_t i = 0; i < 4; ++i) {
                for (std::size_t j = 0; j < BYTES; ++j)
                {
                    _output[i + 4 * j] = state[i][j];
                }
            }
        }

        static constexpr void add_round_key(std::array<std::array<std::uint8_t, BYTES>, 4>& _state, const std::uint8_t* _key) noexcept
        {
            for (std::uint32_t i = 0; i < 4; ++i) {
                for (std::uint32_t j = 0; j < BYTES; ++j)
                {
                    _state[i][j] = _state[i][j] ^ _key[i + 4 * j];
                }
            }
        };

        static constexpr void shift_row(std::array<std::array<std::uint8_t, BYTES>, 4>& _state, const std::uint32_t _i, const std::uint32_t _n) noexcept
        {
            std::array<std::uint8_t, BYTES> tmp;

            for (std::size_t i = 0; i < BYTES; ++i)
            {
                tmp[i] = _state[_i][(i + _n) % BYTES];
            }

            std::memcpy(_state[_i].data(), tmp.data(), BYTES);
        }

        static constexpr void expand_key(const std::uint8_t* _key, std::uint8_t* _dst) noexcept
        {
            std::array<std::uint8_t, 4> rcon{ };
            std::array<std::uint8_t, 4> temp;

            auto rot_word = [&temp]() noexcept -> void
            {
                const std::uint8_t c = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = c;
            };

            auto sub_word = [&temp]() noexcept -> void
            {
                for (std::uint32_t i = 0; i < 4; ++i)
                {
                    temp[i] = detail::sbox[temp[i] / 16][temp[i] % 16];
                }
            };

            auto xor_words = [&temp, rcon]() noexcept -> void
            {
                for (std::uint32_t i = 0; i < 4; ++i)
                {
                    temp[i] = temp[i] ^ rcon[i];
                }
            };

            auto r_con = [&rcon](const std::uint32_t _n) noexcept -> void
            {
                std::uint8_t c = 1;

                for (std::uint32_t i = 0; i < _n - 1; ++i)
                {
                    c = (c << 1) ^ (((c >> 7) & 1) * 0x1B);
                }

                rcon[0] = c;
                rcon[1] = rcon[2] = rcon[3] = 0;
            };

            std::memcpy(_dst, _key, 4 * COLUMNS);

            for (std::size_t i = 4 * COLUMNS; i < EXP_KEY_SIZE; i += 4)
            {
                temp[0] = _dst[i - 4 + 0];
                temp[1] = _dst[i - 4 + 1];
                temp[2] = _dst[i - 4 + 2];
                temp[3] = _dst[i - 4 + 3];

                if (i / 4 % COLUMNS == 0)
                {
                    rot_word();
                    sub_word();
                    r_con(i / (COLUMNS * 4));
                    xor_words();
                }
                else if (COLUMNS > 6 && i / 4 % COLUMNS == 4)
                {
                    sub_word();
                }

                _dst[i + 0] = _dst[i - 4 * COLUMNS] ^ temp[0];
                _dst[i + 1] = _dst[i + 1 - 4 * COLUMNS] ^ temp[1];
                _dst[i + 2] = _dst[i + 2 - 4 * COLUMNS] ^ temp[2];
                _dst[i + 3] = _dst[i + 3 - 4 * COLUMNS] ^ temp[3];
            }
        }

        static constexpr void xor_blocks(const std::uint8_t* _block1, const std::uint8_t* _block2, std::uint8_t* _dest_block) noexcept
        {
            for (std::uint32_t i = 0; i < BLOCK_BYTES; ++i)
            {
                _dest_block[i] = _block1[i] ^ _block2[i];
            }
        }

        static constexpr __declspec(noreturn) void key_length_error()
        {
            throw std::length_error("key length must be KEY_SIZE");
        }

        static constexpr __declspec(noreturn) void iv_length_error()
        {
            throw std::length_error("IV size is not IV_SIZE or not set");
        }

        static constexpr __declspec(noreturn) void data_length_error()
        {
            throw std::length_error("length of data must be divisible by BLOCK_BYTES and should`t be 0");
        }
    };
}

#endif
