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
    enum AES_KEY
    {
        AES_128 = 128,
        AES_160 = 160,
        AES_192 = 192,
        AES_224 = 224,
        AES_256 = 256
    };

    template <AES_KEY KEY_LEN = AES_KEY::AES_192>
    class AES
    {
    protected:
        static constexpr std::uint32_t m_bytes = 4;
        static constexpr std::uint32_t m_block_bytes_len = 4 * m_bytes;
        static constexpr std::uint32_t m_columns = KEY_LEN / 32;
        static constexpr std::uint32_t m_rounds = KEY_LEN / 32 + 6;
        static constexpr std::uint32_t m_keysize = KEY_LEN / 4;
        static constexpr std::uint32_t m_ivsize = m_block_bytes_len;

    private:
        std::vector<std::uint8_t> m_key{ };
        std::vector<std::uint8_t> m_iv{ };

    public:
        constexpr AES() = default;

        constexpr AES(const std::vector<std::uint8_t>& _key)
            : m_key(_key)
        {
            check_key(std::move(m_key));
        }

        constexpr AES(std::vector<std::uint8_t>&& _key)
            : m_key(std::move(_key))
        {
            check_key(std::move(m_key));
        }

        constexpr AES(const std::vector<std::uint8_t>& _key, const std::vector<std::uint8_t>& _iv)
            : m_key(_key), m_iv(_iv)
        {
            check_key(std::move(m_key));
            check_iv(std::move(m_iv));
        }

        constexpr AES(std::vector<std::uint8_t>&& _key, std::vector<std::uint8_t>&& _iv)
            : m_key(std::move(_key)), m_iv(std::move(_iv))
        {
            check_key(std::move(m_key));
            check_iv(std::move(m_iv));
        }

    public:
        void set_random_key()
        {
            m_key = random_key();
        }

        constexpr void set_key(const std::vector<std::uint8_t>& _key)
        {
            m_key = _key;
            check_key(std::move(m_key));
        }

        constexpr void set_key(std::vector<std::uint8_t>&& _key)
        {
            check_key(std::move(_key));
            m_key = _key;
        }

        _NODISCARD constexpr const std::vector<std::uint8_t>& key() const noexcept
        {
            return m_key;
        }

        _NODISCARD constexpr bool has_key() const noexcept
        {
            return (m_key.size() == m_keysize);
        }

        void set_random_iv()
        {
            m_iv = random_iv();
        }

        constexpr void set_iv(const std::vector<std::uint8_t>& _iv)
        {
            m_iv = _iv;
            check_iv(std::move(m_iv));
        }

        constexpr void set_iv(std::vector<std::uint8_t>&& _iv)
        {
            check_iv(std::move(_iv));
            m_iv = _iv;
        }

        _NODISCARD constexpr const std::vector<std::uint8_t>& iv() const noexcept
        {
            return m_iv;
        }

        _NODISCARD constexpr bool has_iv() const noexcept
        {
            return (m_iv.size() == m_ivsize);
        }

        _NODISCARD static std::vector<std::uint8_t> random_key() noexcept
        {
            std::uniform_int_distribution<int32_t> dist(0, 255);
            std::vector<std::uint8_t> key(m_keysize, 0);

            for (auto& pos : key) {
                std::random_device rd;
                pos = static_cast<std::uint8_t>(dist(rd));
            }

            return key;
        }

        _NODISCARD static std::vector<std::uint8_t> random_iv() noexcept
        {
            std::uniform_int_distribution<int32_t> dist(0, 255);
            std::vector<std::uint8_t> key(m_ivsize, 0);

            for (auto& pos : key) {
                std::random_device rd;
                pos = static_cast<std::uint8_t>(dist(rd));
            }

            return key;
        }

    public:
        // ----- ECB -----
        _NODISCARD static constexpr std::unique_ptr<uint8_t[]> encrypt_ecb(const std::uint8_t* _plain, const std::uint8_t* _key, const std::size_t _in_length) noexcept
        {
            check_length(_in_length);

            auto output = std::make_unique<uint8_t[]>(_in_length);
            auto round_keys = std::make_unique<uint8_t[]>(4 * m_bytes * (m_rounds + 1));

            key_expansion(_key, round_keys.get());

            for (std::size_t i = 0; i < _in_length; i += m_block_bytes_len) {
                encrypt_block(_plain + i, &output[i], round_keys.get());
            }

            return std::move(output);
        }

        _NODISCARD static constexpr std::unique_ptr<uint8_t[]> decrypt_ecb(const std::uint8_t* _enc, const std::uint8_t* _key, const std::size_t _in_length) noexcept
        {
            check_length(_in_length);

            auto output = std::make_unique<uint8_t[]>(_in_length);
            auto round_keys = std::make_unique<uint8_t[]>(4 * m_bytes * (m_rounds + 1));

            key_expansion(_key, round_keys.get());

            for (std::size_t i = 0; i < _in_length; i += m_block_bytes_len)
            {
                decrypt_block(_enc + i, &output[i], round_keys.get());
            }

            return std::move(output);
        }

        _NODISCARD static constexpr std::vector<std::uint8_t> encrypt_ecb(const std::vector<std::uint8_t>& _plain, const std::vector<std::uint8_t>& _key) noexcept
        {
            const auto output = encrypt_ecb(_plain.data(), _key.data(), _plain.size());
            return std::vector<std::uint8_t>(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static constexpr std::vector<std::uint8_t> decrypt_ecb(const std::vector<std::uint8_t>& _enc, const std::vector<std::uint8_t>& _key) noexcept
        {
            const auto output = decrypt_ecb(_enc.data(), _key.data(), _enc.size());
            return std::vector<std::uint8_t>(output.get(), output.get() + _enc.size());;
        }

        _NODISCARD constexpr std::vector<std::uint8_t> encrypt_ecb(const std::vector<std::uint8_t>& _plain)
        {
            check_key(std::move(m_key));
            return encrypt_ecb(_plain, m_key);
        }

        _NODISCARD constexpr std::vector<std::uint8_t> decrypt_ecb(const std::vector<std::uint8_t>& _enc)
        {
            check_key(std::move(m_key));
            return decrypt_ecb(_enc, m_key);
        }

        // ----- CBC -----
        _NODISCARD static constexpr std::unique_ptr<uint8_t[]> encrypt_cbc(const std::uint8_t* _plain, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _in_length) noexcept
        {
            check_length(_in_length);

            std::uint8_t block[m_block_bytes_len];
            auto output = std::make_unique<uint8_t[]>(_in_length);
            auto round_keys = std::make_unique<uint8_t[]>(4 * m_bytes * (m_rounds + 1));

            key_expansion(_key, round_keys.get());
            std::memcpy(block, _iv, m_block_bytes_len);

            for (std::size_t i = 0; i < _in_length; i += m_block_bytes_len) {
                xor_blocks(block, &_plain[i], block);
                encrypt_block(block, &output[i], round_keys.get());
                std::memcpy(block, &output[i], m_block_bytes_len);
            }

            return std::move(output);
        }

        _NODISCARD static constexpr std::unique_ptr<uint8_t[]> decrypt_cbc(const std::uint8_t* _enc, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _in_length) noexcept
        {
            check_length(_in_length);

            std::uint8_t block[m_block_bytes_len];
            auto output = std::make_unique<uint8_t[]>(_in_length);
            auto round_keys = std::make_unique<uint8_t[]>(4 * m_bytes * (m_rounds + 1));

            key_expansion(_key, round_keys.get());
            std::memcpy(block, _iv, m_block_bytes_len);

            for (std::size_t i = 0; i < _in_length; i += m_block_bytes_len) {
                decrypt_block(_enc + i, &output[i], round_keys.get());
                xor_blocks(block, &output[i], &output[i]);
                std::memcpy(block, &_enc[i], m_block_bytes_len);
            }

            return std::move(output);
        }

        _NODISCARD static constexpr std::vector<std::uint8_t> encrypt_cbc(const std::vector<std::uint8_t>& _plain, const std::vector<std::uint8_t>& _key, const std::vector<std::uint8_t>& _iv) noexcept
        {
            const auto output = encrypt_cbc(_plain.data(), _key.data(), _iv.data(), _plain.size());
            return std::vector<std::uint8_t>(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static constexpr std::vector<std::uint8_t> decrypt_cbc(const std::vector<std::uint8_t>& _enc, const std::vector<std::uint8_t>& _key, const std::vector<std::uint8_t>& _iv) noexcept
        {
            const auto output = decrypt_cbc(_enc.data(), _key.data(), _iv.data(), _enc.size());
            return std::vector<std::uint8_t>(output.get(), output.get() + _enc.size());
        }

        _NODISCARD constexpr std::vector<std::uint8_t> encrypt_cbc(const std::vector<std::uint8_t>& _plain)
        {
            check_key(std::move(m_key));
            check_iv(std::move(m_iv));
            return encrypt_cbc(_plain, m_key, m_iv);
        }

        _NODISCARD constexpr std::vector<std::uint8_t> decrypt_cbc(const std::vector<std::uint8_t>& _enc)
        {
            check_key(std::move(m_key));
            check_iv(std::move(m_iv));
            return decrypt_cbc(_enc, m_key, m_iv);
        }

        // ----- CFB -----
        _NODISCARD static constexpr std::unique_ptr<uint8_t[]> encrypt_cfb(const std::uint8_t* _plain, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _in_length) noexcept
        {
            check_length(_in_length);

            std::uint8_t block[m_block_bytes_len];
            std::uint8_t encrypted_block[m_block_bytes_len];
            auto output = std::make_unique<uint8_t[]>(_in_length);
            auto round_keys = std::make_unique<uint8_t[]>(4 * m_bytes * (m_rounds + 1));

            key_expansion(_key, round_keys.get());
            std::memcpy(block, _iv, m_block_bytes_len);

            for (std::size_t i = 0; i < _in_length; i += m_block_bytes_len) {
                encrypt_block(block, encrypted_block, round_keys.get());
                xor_blocks(&_plain[i], encrypted_block, &output[i]);
                std::memcpy(block, &output[i], m_block_bytes_len);
            }

            return std::move(output);
        }

        _NODISCARD static constexpr std::unique_ptr<uint8_t[]> decrypt_cfb(const std::uint8_t* _enc, const std::uint8_t* _key, const std::uint8_t* _iv, const std::size_t _in_length) noexcept
        {
            check_length(_in_length);

            std::uint8_t block[m_block_bytes_len];
            std::uint8_t encrypted_block[m_block_bytes_len];
            auto output = std::make_unique<uint8_t[]>(_in_length);
            auto round_keys = std::make_unique<uint8_t[]>(4 * m_bytes * (m_rounds + 1));

            key_expansion(_key, round_keys.get());
            std::memcpy(block, _iv, m_block_bytes_len);

            for (std::size_t i = 0; i < _in_length; i += m_block_bytes_len) {
                encrypt_block(block, encrypted_block, round_keys.get());
                xor_blocks(&_enc[i], encrypted_block, &output[i]);
                memcpy(block, &_enc[i], m_block_bytes_len);
            }

            return std::move(output);
        }

        _NODISCARD static constexpr std::vector<std::uint8_t> encrypt_cfb(const std::vector<std::uint8_t>& _plain, const std::vector<std::uint8_t>& _key, const std::vector<std::uint8_t>& _iv) noexcept
        {
            const auto output = encrypt_cfb(_plain.data(), _key.data(), _iv.data(), _plain.size());
            return std::vector<std::uint8_t>(output.get(), output.get() + _plain.size());
        }

        _NODISCARD static constexpr std::vector<std::uint8_t> decrypt_cfb(const std::vector<std::uint8_t>& _enc, const std::vector<std::uint8_t>& _key, const std::vector<std::uint8_t>& _iv) noexcept
        {
            const auto output = decrypt_cfb(_enc.data(), _key.data(), _iv.data(), _enc.size());
            return std::vector<std::uint8_t>(output.get(), output.get() + _enc.size());
        }

        _NODISCARD constexpr std::vector<std::uint8_t> encrypt_cfb(const std::vector<std::uint8_t>& _plain)
        {
            check_key(std::move(m_key));
            check_iv(std::move(m_iv));
            return encrypt_cfb(_plain, m_key, m_iv);
        }

        _NODISCARD constexpr std::vector<std::uint8_t> decrypt_cfb(const std::vector<std::uint8_t>& _enc)
        {
            check_key(std::move(m_key));
            check_iv(std::move(m_iv));
            return decrypt_cfb(_enc, m_key, m_iv);
        }

    public:
        _NODISCARD constexpr operator bool()
        {
            return (has_key() && has_iv());
        }

        _NODISCARD constexpr AES<KEY_LEN>& operator=(const AES<KEY_LEN> _aes)
        {
            if (_aes) {
                m_key = _aes.m_key;
                m_iv = _aes.m_iv;
            }
            return *this;
        }

        friend std::ostream& operator<<(std::ostream& _out, const AES<KEY_LEN>& _aes)
        {
            _out << "AES " << KEY_LEN << ":\n";
            _out << "KEYLEN: " << KEY_LEN / 4 << '\n';
            _out << "IV LEN: " << 16 << "\n\n";
            if (_aes.has_key())
            {
                _out << "----KEY----\n{ ";
                for (std::size_t i = 0; i != _aes.key().size() - 1; ++i) {
                    _out << static_cast<std::int32_t>(_aes.key()[i]) << ", ";
                }
                _out << static_cast<std::int32_t>(_aes.key().back()) << " }\n\n";
            }
            else {
                _out << "NO KEY SET\n\n";
            }
            if (_aes.has_iv())
            {
                _out << "----IV----\n{ ";
                for (std::size_t i = 0; i != _aes.iv().size() - 1; ++i) {
                    _out << static_cast<std::int32_t>(_aes.iv()[i]) << ", ";
                }
                _out << static_cast<std::int32_t>(_aes.iv().back()) << " }\n\n";
            }
            else {
                _out << "NO IV SET\n\n";
            }
            return _out;
        }

    private:
        static constexpr void check_key(std::vector<std::uint8_t>&& _key) {
            if (_key.size() != m_keysize) {
                throw("keysize is invalid");
            }
        }

        static constexpr void check_iv(std::vector<std::uint8_t>&& _iv) {
            if (_iv.size() != m_ivsize) {
                throw("ivsize is invalid");
            }
        }

        static constexpr void check_length(const std::size_t _length)
        {
            if (_length % m_block_bytes_len != 0) {
                throw std::length_error("Plaintext length must be divisible by m_block_bytes_len");
            }
        }

        static constexpr void sub_bytes(std::uint8_t state[4][m_bytes]) noexcept
        {
            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t j = 0, t; j < m_bytes; ++j)
                {
                    t = state[i][j];
                    state[i][j] = detail::sbox[t / 16][t % 16];
                }
            }
        }

        static constexpr void encrypt_block(const std::uint8_t* _in, std::uint8_t* _output, std::uint8_t* _round_keys) noexcept
        {
            std::uint8_t state[4][m_bytes];

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t j = 0; j < m_bytes; ++j)
                {
                    state[i][j] = _in[i + 4 * j];
                }
            }

            add_round_key(state, _round_keys);

            for (std::uint32_t round = 1; round <= m_rounds - 1; ++round)
            {
                sub_bytes(state);
                shift_rows(state);
                mix_columns(state);
                add_round_key(state, _round_keys + round * 4 * m_bytes);
            }

            sub_bytes(state);
            shift_rows(state);
            add_round_key(state, _round_keys + m_rounds * 4 * m_bytes);

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t j = 0; j < m_bytes; ++j)
                {
                    _output[i + 4 * j] = state[i][j];
                }
            }
        }

        static constexpr void decrypt_block(const std::uint8_t* _in, std::uint8_t* _output, std::uint8_t* _round_keys) noexcept
        {
            std::uint8_t state[4][m_bytes];

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t j = 0; j < m_bytes; ++j)
                {
                    state[i][j] = _in[i + 4 * j];
                }
            }

            add_round_key(state, _round_keys + m_rounds * 4 * m_bytes);

            for (std::uint32_t round = m_rounds - 1; round >= 1; --round) {
                inv_sub_bytes(state);
                inv_shift_rows(state);
                add_round_key(state, _round_keys + round * 4 * m_bytes);
                inv_mix_columns(state);
            }

            inv_sub_bytes(state);
            inv_shift_rows(state);
            add_round_key(state, _round_keys);

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t j = 0; j < m_bytes; ++j)
                {
                    _output[i + 4 * j] = state[i][j];
                }
            }
        }

        static constexpr void shift_row(std::uint8_t _state[4][m_bytes], const std::uint32_t _i, const std::uint32_t _n) noexcept
        {
            std::uint8_t tmp[m_bytes];

            for (std::uint32_t i = 0; i < m_bytes; ++i)
            {
                tmp[i] = _state[_i][(i + _n) % m_bytes];
            }

            std::memcpy(_state[_i], tmp, m_bytes);
        }

        static constexpr void shift_rows(std::uint8_t _state[4][m_bytes]) noexcept
        {
            shift_row(_state, 1, 1);
            shift_row(_state, 2, 2);
            shift_row(_state, 3, 3);
        }

        static constexpr void mix_columns(std::uint8_t _state[4][m_bytes]) noexcept
        {
            std::uint8_t temp_state[4][m_bytes];

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                std::memset(temp_state[i], 0, 4);
            }

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t k = 0; k < 4; ++k)
                {
                    for (std::uint32_t j = 0; j < 4; ++j)
                    {
                        if (detail::CMDS[i][k] == 1) {
                            temp_state[i][j] ^= _state[k][j];
                        }
                        else {
                            temp_state[i][j] ^= detail::GF_MUL_TABLE[detail::CMDS[i][k]][_state[k][j]];
                        }
                    }
                }
            }

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                std::memcpy(_state[i], temp_state[i], 4);
            }
        }

        static constexpr void add_round_key(std::uint8_t _state[4][m_bytes], const std::uint8_t* _key) noexcept
        {
            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t j = 0; j < m_bytes; ++j)
                {
                    _state[i][j] = _state[i][j] ^ _key[i + 4 * j];
                }
            }
        }

        static constexpr void sub_word(std::uint8_t* _a) noexcept
        {
            for (std::uint32_t i = 0; i < 4; ++i)
            {
                _a[i] = detail::sbox[_a[i] / 16][_a[i] % 16];
            }
        }

        static constexpr void rot_word(std::uint8_t* _a) noexcept
        {
            const std::uint8_t c = _a[0];
            _a[0] = _a[1];
            _a[1] = _a[2];
            _a[2] = _a[3];
            _a[3] = c;
        }

        static constexpr void xor_words(const std::uint8_t* _a, const std::uint8_t* _b, std::uint8_t* _c) noexcept
        {
            for (std::uint32_t i = 0; i < 4; ++i)
            {
                _c[i] = _a[i] ^ _b[i];
            }
        }

        static constexpr void r_con(std::uint8_t* _a, const std::uint32_t _n) noexcept
        {
            auto xtime = [](std::uint8_t _b) -> std::uint8_t
            {
                return (_b << 1) ^ (((_b >> 7) & 1) * 0x1B);
            };

            std::uint8_t c = 1;

            for (std::uint32_t i = 0; i < _n - 1; ++i)
            {
                c = xtime(c);
            }

            _a[0] = c;
            _a[1] = _a[2] = _a[3] = 0;
        }

        static constexpr void key_expansion(const std::uint8_t* _key, std::uint8_t* _w) noexcept
        {
            std::uint8_t temp[4];
            std::uint8_t rcon[4];

            for (std::uint32_t i = 0; i < 4 * m_columns; ++i)
            {
                _w[i] = _key[i];
                ++i;
            }

            for (std::uint32_t i = 4 * m_columns; i < 4 * m_bytes * (m_rounds + 1); i += 4)
            {
                temp[0] = _w[i - 4 + 0];
                temp[1] = _w[i - 4 + 1];
                temp[2] = _w[i - 4 + 2];
                temp[3] = _w[i - 4 + 3];

                if (i / 4 % m_columns == 0) {
                    rot_word(temp);
                    sub_word(temp);
                    r_con(rcon, i / (m_columns * 4));
                    xor_words(temp, rcon, temp);
                }
                else if (m_columns > 6 && i / 4 % m_columns == 4) {
                    sub_word(temp);
                }

                _w[i + 0] = _w[i - 4 * m_columns] ^ temp[0];
                _w[i + 1] = _w[i + 1 - 4 * m_columns] ^ temp[1];
                _w[i + 2] = _w[i + 2 - 4 * m_columns] ^ temp[2];
                _w[i + 3] = _w[i + 3 - 4 * m_columns] ^ temp[3];
            }
        }

        static constexpr void inv_sub_bytes(std::uint8_t _state[4][m_bytes]) noexcept
        {
            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t j = 0, t; j < m_bytes; ++j)
                {
                    t = _state[i][j];
                    _state[i][j] = detail::inv_sbox[t / 16][t % 16];
                }
            }
        }

        static constexpr void inv_mix_columns(std::uint8_t _state[4][m_bytes]) noexcept
        {
            std::uint8_t temp_state[4][m_bytes];

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                std::memset(temp_state[i], 0, 4);
            }

            for (std::uint32_t i = 0; i < 4; ++i)
            {
                for (std::uint32_t k = 0; k < 4; ++k)
                {
                    for (std::uint32_t j = 0; j < 4; ++j)
                    {
                        temp_state[i][j] ^= detail::GF_MUL_TABLE[detail::INV_CMDS[i][k]][_state[k][j]];
                    }
                }
            }

            for (std::uint32_t i = 0; i < 4; ++i) {
                std::memcpy(_state[i], temp_state[i], 4);
            }
        }

        static constexpr void inv_shift_rows(std::uint8_t _state[4][m_bytes]) noexcept
        {
            shift_row(_state, 1, m_bytes - 1);
            shift_row(_state, 2, m_bytes - 2);
            shift_row(_state, 3, m_bytes - 3);
        }

        static constexpr void xor_blocks(const std::uint8_t* a, const std::uint8_t* b, std::uint8_t* c) noexcept
        {
            for (std::uint32_t i = 0; i < m_block_bytes_len; ++i)
            {
                c[i] = a[i] ^ b[i];
            }
        }
    };

    _NODISCARD static constexpr std::vector<std::uint8_t> str_to_vec(const std::string_view& _str) noexcept
    {
        std::vector<std::uint8_t> vec(_str.size(), 0);

        for (std::size_t i = 0; i != _str.size(); ++i) {
            vec[i] = _str[i];
        }

        return vec;
    }

    _NODISCARD static constexpr std::string vec_to_str(const std::vector<std::uint8_t>& _vec) noexcept
    {
        std::string str(_vec.size(), 0);

        for (std::size_t i = 0; i != _vec.size(); ++i) {
            str[i] = _vec[i];
        }

        return str;
    }

    static void make_cbc_ready(std::vector<std::uint8_t>& v) noexcept
    {
        if (v.size() % 16 == 0) {
            return;
        }

        v.push_back(0); // add null byte

        if (v.size() % 16 == 0) {
            return;
        }

        std::size_t new_size = v.size() + (16 - (v.size() % 16)); // fill rest with random bytes
        std::mt19937 mt(std::random_device{ }());
        std::uniform_int_distribution<> dist(static_cast<std::uint8_t>(0), static_cast<std::uint8_t>(255));

        while (v.size() < new_size) {
            v.push_back(dist(mt));
        }
    }
}

#endif
