/*
Copyright 2016 Tomohiro Matsumoto

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <vector>
#include "gcryptMD.hpp"
#include "hmacSha1Cuda.hpp"
#include "xorshift1024star.hpp"
#include "util.hpp"
#include <gcrypt.h>

using namespace std;

#define LUKS_SALTSIZE 32

int pbkdf2(const char* pass, size_t passLen, const char* salt, size_t saltLen, unsigned long iterations, char* key, size_t keyLen)
{
	const int hash_id = gcry_md_map_name("sha1");
	if
	(
		gcry_kdf_derive
		(
			pass,				passLen,
			GCRY_KDF_PBKDF2,	hash_id,
			salt,				saltLen,
			iterations,
			keyLen,				key
		)
	)
		 return -EINVAL;

	return 0;
}

int batchSha1Test()
{
	const static size_t numTest = 5000;
	const static size_t batchSize = 100000;
	sha1Cuda hmsc;
	hmsc.resize(batchSize);
	xorshift1024star rnd;

	gcryptMD md(false);
	if(md.getErrorCode())
	{
		return md.getErrorCode();
	}

	const unsigned int hashLen = md.getHashLen();

	for(size_t h=0; h<numTest; ++h)
	{
		for(size_t i=0; i<batchSize; ++i)
		{
			hmsc.clear(i);
			char* in = hmsc.input(i);
			const size_t len = (rnd.get()&31) + 1;
			for(size_t j=0; j<len; ++j)
			{
				in[j] = rnd.get();
			}

			hmsc.setInputLength(i, len);
		}
		hmsc.transform();

		for(size_t i=0; i<batchSize; ++i)
		{
			const unsigned char* const hash =
				md.getHash(0, 0, hmsc.input(i), hmsc.getLength(i));
			if (!hash)
			{
				return md.getErrorCode();
			}
			if(memcmp(hash, hmsc.output(i), hashLen)!=0)
			{
				cout << "Test failed!:" << i << "\n";
				return 1;
			}
		}
		cout << "Progress: " << (h+1) << '/' << numTest << endl;
	}

	cout << "Test success!\n";

	return 0;
}

int batchHmacSha1Test()
{
	const static size_t numTest = 50;
	const static size_t batchSize = 100000;
	hmacSha1Cuda hmsc;
	hmsc.resize(batchSize);
	xorshift1024star rnd;

	gcryptMD md(true);
	if(md.getErrorCode())
	{
		return md.getErrorCode();
	}

	const unsigned int hashLen = md.getHashLen();

	std::vector<size_t> keyLens(batchSize);
	for(size_t h=0; h<numTest; ++h)
	{
		hmsc.clearInput();
		char* in = hmsc.input();
		const size_t len = (rnd.get()&31) + 1;
		for(size_t j=0; j<len; ++j)
		{
			in[j] = rnd.get();
		}

		hmsc.setInputLength(len);

		for(size_t i=0; i<batchSize; ++i)
		{
			char* key = hmsc.key(i);
			const size_t keyLen = keyLens[i] = (rnd.get()&31) + 1;
			for(size_t j=0; j<keyLen; ++j)
			{
				key[j] = rnd.get();
			}
		}
		hmsc.transform();

		for(size_t i=0; i<batchSize; ++i)
		{
			const unsigned char* const hash =
				md.getHash(hmsc.key(i), keyLens[i], hmsc.input(), hmsc.getLength());
			if(!hash)
			{
				return md.getErrorCode();
			}
			if(memcmp(hash, hmsc.output(i), hashLen)!=0)
			{
				cout << "Test failed!:" << i << "\n";
				return 1;
			}
		}
		cout << "Progress: " << (h+1) << '/' << numTest << endl;
	}

	cout << "Test success!\n";

	return 0;
}

int batchPbkdf2Test()
{
#if 1
	const unsigned int	numIteration	= 1000;
	const static size_t numTest = 40;
#else
	const unsigned int	numIteration	= 155000;
	const static size_t numTest = 4;
#endif
	const static size_t batchSize = 1000;
	hmacSha1Cuda hmsc;
	hmsc.resize(batchSize);
	xorshift1024star rnd;

	std::vector<size_t> keyLens(batchSize);
	for(size_t h=0; h<numTest; ++h)
	{
		hmsc.clearInput();
		char* in = hmsc.input();
		const size_t len = ((rnd.get()&31) + 4)&(255-3);
		for(size_t j=0; j<len; ++j)
		{
			in[j] = rnd.get();
		}

		hmsc.setInputLength(len);

		for(size_t i=0; i<batchSize; ++i)
		{
			hmsc.clearKey(i);
			char* key = hmsc.key(i);
			const size_t keyLen = keyLens[i] = (rnd.get()&31) + 1;
			for(size_t j=0; j<keyLen; ++j)
			{
				key[j] = rnd.get();
			}
		}
		hmsc.transformPbkdf2(numIteration);

#if 1
		int ret;
		char keybuff[32];
		for(size_t i=0; i<batchSize; ++i)
		{
			ret=
				pbkdf2
				(
					hmsc.key(i),	keyLens[i],
					hmsc.input(),	hmsc.getLength(),
					numIteration,
					keybuff,		sizeof(keybuff)
				);
			if(ret)
				return ret;
			if(memcmp(keybuff, hmsc.outputPbkdf2(i), sizeof(keybuff))!=0)
			{
				cout << "Test failed!:" << i << "\n";
				return 1;
			}
		}
#else
		char keybuff[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
		for(size_t i=0; i<batchSize; ++i)
		{
			if(memcmp(keybuff, hmsc.outputPbkdf2(i), sizeof(keybuff))==0)
			{
				cout << "Miracle!\n";
			}
		}
#endif
		cout << "Progress: " << (h+1) << '/' << numTest << endl;
	}

	cout << "Test success!\n";

	return 0;
}

int main(int /*argc*/, char** /*argv*/)
{
	const static char passphrase[] = "abcdef12AgZ1i";
	const static char passSalt[LUKS_SALTSIZE] =
	{0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
	0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

	int ret;
	if((ret = gcryptMD::init()) != 0)
	{
		return ret;
	}

	gcryptMD md(true);
	if(md.getErrorCode())
	{
		return md.getErrorCode();
	}

	const unsigned int hashLen = md.getHashLen();
	const unsigned char* const hash =
		md.getHash(passphrase, sizeof(passphrase), passSalt, sizeof(passSalt));
	if (!hash)
	{
		return md.getErrorCode();
	}else
	{
		cout << hex;
		printHex(hash, hashLen);
	}

	hmacSha1Cuda hmsc;
	const unsigned char* const hashCuda =
		hmsc.getHash(passphrase, sizeof(passphrase), passSalt, sizeof(passSalt));
	printHex(hashCuda, hashLen);

	const static unsigned int numIteration = 1250;
	char keybuff[32];
	ret=pbkdf2(passphrase, sizeof(passphrase), passSalt, sizeof(passSalt), numIteration, keybuff, sizeof(keybuff));
	if(ret)
		return ret;
	printHex(keybuff);

	const unsigned char* pbkdf2Cuda =
		hmsc.getPbkdf2(passphrase, sizeof(passphrase), passSalt, sizeof(passSalt), numIteration);
	printHex(pbkdf2Cuda, 32);

#if 0
	if((ret = batchSha1Test()) != 0)
	{
		return ret;
	}
#elif 0
	if((ret = batchHmacSha1Test()) != 0)
	{
		return ret;
	}
#else
	if((ret = batchPbkdf2Test()) != 0)
	{
		return ret;
	}
#endif

	return 0;
}
