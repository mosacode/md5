#pragma once
#include <bits/stdc++.h>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <iostream>
#include <inttypes.h>

#define ll long long
#define ull unsigned long long
#define uc unsigned char
#define MD5_u32 unsigned int

#define F(b, c, d) ( d ^ (b & (c ^ d) ) )
#define G(b, c, d) ( c ^ (d & (b ^ c) ) )
#define H(b, c, d) ( b ^ c ^ d )
#define I(b, c, d) ( c ^ (b | (~d) ) )

#define RR(x, n) (((x & 0xffffffff) >> n) | (x << 32-n))
#define RL(x, n) ((x << n) | ((x & 0xffffffff) >> 32-n))

#define STEP(func, a, b, c, d, sbind, cind)\
(a) += func((b), (c), (d)) + sb[sbind] + md5_ac[cind];\
(a) = RL(a, md5_rc[cind]);\
(a) += (b);

static const char hexdigit[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

static const uint32_t md5_ac[] =
{ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821
, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x2441453 , 0xd8a1e681, 0xe7d3fbc8
, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a
, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70
, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05 , 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665
, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1
, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

static const uint32_t md5_rc[] =
{ 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22
, 5, 9 , 14, 20, 5, 9 , 14, 20, 5, 9 , 14, 20, 5, 9 , 14, 20
, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23
, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

class md5 {
public:
	uint32_t  A = 0x67452301,
			  B = 0xefcdab89,
			  C = 0x98badcfe,
			  D = 0x10325476;
	std::ifstream file;
	std::vector<unsigned char> data;
	std::string path;
	size_t filesize;
	void init(std::string pat="\0") {
		if (pat == "\0") file.open(path, std::ios_base::ate | std::ios_base::binary);
		else file.open(pat, std::ios_base::ate | std::ios_base::binary);
		if (!file.is_open()) { std::cout << "unable to open file!\n";return; }
		filesize = file.tellg();
		data.resize(filesize);
		file.seekg(0);
		file.read((char*)data.data(), filesize);
		file.close();
		data.push_back((char)(0b10000000));
		while (data.size() % 64 != 56) data.push_back((char)(0b00000000));
		filesize *= 8;
		for (int i = 0; i < 8; i++)
			data.push_back(((uint8_t*)(&filesize))[i]);
		A = 0x67452301,
		B = 0xefcdab89,
		C = 0x98badcfe,
		D = 0x10325476;
		CalculateMD5();
	}
	
	void CalculateMD5() {
		for (int i = 0; i < data.size(); i += 64) {
			uint32_t sb[16], OA, OB, OC, OD, j = 0;
			for (int p = 0; p < 16; p++) sb[p] = 0;
			for (int p = 0; p < 64; p += 4)sb[p / 4] = (MD5_u32)data[i + p] | ((MD5_u32)data[i + p + 1] << 8) | ((MD5_u32)data[i + p + 2] << 16) | ((MD5_u32)data[i + p + 3] << 24);
			OA = A, OB = B, OC = C, OD = D;
			
			STEP(F, A, B, C, D, 0 , j);j++;
			STEP(F, D, A, B, C, 1 , j);j++;
			STEP(F, C, D, A, B, 2 , j);j++;
			STEP(F, B, C, D, A, 3 , j);j++;
			STEP(F, A, B, C, D, 4 , j);j++;
			STEP(F, D, A, B, C, 5 , j);j++;
			STEP(F, C, D, A, B, 6 , j);j++;
			STEP(F, B, C, D, A, 7 , j);j++;
			STEP(F, A, B, C, D, 8 , j);j++;
			STEP(F, D, A, B, C, 9 , j);j++;
			STEP(F, C, D, A, B, 10, j);j++;
			STEP(F, B, C, D, A, 11, j);j++;
			STEP(F, A, B, C, D, 12, j);j++;
			STEP(F, D, A, B, C, 13, j);j++;
			STEP(F, C, D, A, B, 14, j);j++;
			STEP(F, B, C, D, A, 15, j);j++;
			STEP(G, A, B, C, D, 1 , j);j++;
			STEP(G, D, A, B, C, 6 , j);j++;
			STEP(G, C, D, A, B, 11, j);j++;
			STEP(G, B, C, D, A, 0 , j);j++;
			STEP(G, A, B, C, D, 5 , j);j++;
			STEP(G, D, A, B, C, 10, j);j++;
			STEP(G, C, D, A, B, 15, j);j++;
			STEP(G, B, C, D, A, 4 , j);j++;
			STEP(G, A, B, C, D, 9 , j);j++;
			STEP(G, D, A, B, C, 14, j);j++;
			STEP(G, C, D, A, B, 3 , j);j++;
			STEP(G, B, C, D, A, 8 , j);j++;
			STEP(G, A, B, C, D, 13, j);j++;
			STEP(G, D, A, B, C, 2 , j);j++;
			STEP(G, C, D, A, B, 7 , j);j++;
			STEP(G, B, C, D, A, 12, j);j++;
			STEP(H, A, B, C, D, 5 , j);j++;
			STEP(H, D, A, B, C, 8 , j);j++;
			STEP(H, C, D, A, B, 11, j);j++;
			STEP(H, B, C, D, A, 14, j);j++;
			STEP(H, A, B, C, D, 1 , j);j++;
			STEP(H, D, A, B, C, 4 , j);j++;
			STEP(H, C, D, A, B, 7 , j);j++;
			STEP(H, B, C, D, A, 10, j);j++;
			STEP(H, A, B, C, D, 13, j);j++;
			STEP(H, D, A, B, C, 0 , j);j++;
			STEP(H, C, D, A, B, 3 , j);j++;
			STEP(H, B, C, D, A, 6 , j);j++;
			STEP(H, A, B, C, D, 9 , j);j++;
			STEP(H, D, A, B, C, 12, j);j++;
			STEP(H, C, D, A, B, 15, j);j++;
			STEP(H, B, C, D, A, 2 , j);j++;
			STEP(I, A, B, C, D, 0 , j);j++;
			STEP(I, D, A, B, C, 7 , j);j++;
			STEP(I, C, D, A, B, 14, j);j++;
			STEP(I, B, C, D, A, 5 , j);j++;
			STEP(I, A, B, C, D, 12, j);j++;
			STEP(I, D, A, B, C, 3 , j);j++;
			STEP(I, C, D, A, B, 10, j);j++;
			STEP(I, B, C, D, A, 1 , j);j++;
			STEP(I, A, B, C, D, 8 , j);j++;
			STEP(I, D, A, B, C, 15, j);j++;
			STEP(I, C, D, A, B, 6 , j);j++;
			STEP(I, B, C, D, A, 13, j);j++;
			STEP(I, A, B, C, D, 4 , j);j++;
			STEP(I, D, A, B, C, 11, j);j++;
			STEP(I, C, D, A, B, 2 , j);j++;
			STEP(I, B, C, D, A, 9 , j);j++;

			A += OA, B += OB, C += OC, D += OD;
		}
		output();
	}

	void output() {
		for (int i = 0; i < 4;i++) std::cout << hexdigit[((A >> (8 * i + 4)) & 0b1111)] << hexdigit[((A >> (8 * i)) & 0b1111)];
		for (int i = 0; i < 4;i++) std::cout << hexdigit[((B >> (8 * i + 4)) & 0b1111)] << hexdigit[((B >> (8 * i)) & 0b1111)];
		for (int i = 0; i < 4;i++) std::cout << hexdigit[((C >> (8 * i + 4)) & 0b1111)] << hexdigit[((C >> (8 * i)) & 0b1111)];
		for (int i = 0; i < 4;i++) std::cout << hexdigit[((D >> (8 * i + 4)) & 0b1111)] << hexdigit[((D >> (8 * i)) & 0b1111)];
	}
};