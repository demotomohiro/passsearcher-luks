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

#include "passGen.hpp"
#include "progOptions.hpp"
#include "util.hpp"
#include "hmacSha1Cuda.hpp"
extern "C"
{
#include "libcryptsetup/luks.h"
#include "libcrypt.h"
}

#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <fstream>
#include <memory>

using namespace std;

bool readHeader(const char* filename, luks_phdr& hdr, bool isPrintSaltAndDigest = false)
{
	ifstream ifs(filename, std::ifstream::binary);
	if(!ifs.good())
	{
		cerr << "Failed to open " << filename << " for read\n";
		return false;
	}

	ifs.read((char*)&hdr, sizeof(hdr));
	if(ifs.fail() || ifs.bad())
	{
		cerr << "Failed to read header\n";
		return false;
	}

	const char luksMagic[] = LUKS_MAGIC;
	if(memcmp(hdr.magic, luksMagic, LUKS_MAGIC_L) != 0)
	{
		cerr << "Magic mismatch!(O_o)\n";
	}

	hdr.version				= ntohs(hdr.version);
	hdr.payloadOffset		= ntohl(hdr.payloadOffset);
	hdr.keyBytes			= ntohl(hdr.keyBytes);
	hdr.mkDigestIterations	= ntohl(hdr.mkDigestIterations);
	for(int i=0; i<LUKS_NUMKEYS; ++i)
	{
		hdr.keyblock[i].active				= ntohl(hdr.keyblock[i].active);
		hdr.keyblock[i].passwordIterations	= ntohl(hdr.keyblock[i].passwordIterations);
		hdr.keyblock[i].keyMaterialOffset	= ntohl(hdr.keyblock[i].keyMaterialOffset);
		hdr.keyblock[i].stripes				= ntohl(hdr.keyblock[i].stripes);
	}

	cout << "magic: "				<< staticStr(hdr.magic)			<< '\n';
	cout << "version: "				<< dec << hdr.version			<< '\n';
	cout << "cipherName: "			<< staticStr(hdr.cipherName)	<< '\n';
	cout << "cipherMode: "			<< staticStr(hdr.cipherMode)	<< '\n';
	cout << "hashSpec: "			<< staticStr(hdr.hashSpec)		<< '\n';
	cout << "payloadOffset: "		<< dec << hdr.payloadOffset		<< '\n';
	cout << "keyBytes: "			<< dec << hdr.keyBytes			<< '\n';
	if(isPrintSaltAndDigest)
	{
		cout << "mkDigest: "										<< '\n';
		printHex(hdr.mkDigest);
		cout << "mkDigestSalt: "									<< '\n';
		printHex(hdr.mkDigestSalt);
	}
	cout << "mkDigestIterations: "	<< dec << hdr.mkDigestIterations<< '\n';
	cout << "uuid: "				<< staticStr(hdr.uuid)			<< '\n';

	bool hasDisabledSlot = false;
	for(int i=0; i<LUKS_NUMKEYS; ++i)
	{
		if(hdr.keyblock[i].active == LUKS_KEY_ENABLED)
		{
			cout << "Keyslot " << i << " is active.\n";
		}else
		{
			hasDisabledSlot = true;
			continue;
		}

		cout << "passwordIterations: "	<< dec << hdr.keyblock[i].passwordIterations	<< '\n';
		if(isPrintSaltAndDigest)
		{
			cout << "passwordSalt: "													<< '\n';
			printHex(hdr.keyblock[i].passwordSalt);
		}
		cout << "keyMaterialOffset: "	<< dec << hdr.keyblock[i].keyMaterialOffset		<< '\n';
		cout << "stripes: "				<< dec << hdr.keyblock[i].stripes				<< '\n';
	}

	if(hasDisabledSlot)
	{
		cout << "Keyslot ";
		for(int i=0; i<LUKS_NUMKEYS; ++i)
		{
			if(hdr.keyblock[i].active != LUKS_KEY_ENABLED)
			{ 
				cout << i << ", ";
			}
		}
		cout << "are disabled.\n";
	}else
	{
		cout << "All keyslots are active.\n";
	}

	if(hdr.payloadOffset < 8)
	{
		cerr << "invalid payloadOffset\n";
	}

	return true;
}

int main(int argc, char** argv)
{
	const progOptions options(argc, argv);

	if(options.device.empty())
	{
		return 1;
	}

	luks_phdr hdr;
	const char* filename = options.device.c_str();
	if(!readHeader(filename, hdr))
	{
		return 1;
	}

	if(options.expression.empty())
	{
		return 0;
	}

	const passGen pg(options.expression.c_str());
	if(pg.getHasError())
	{
		cerr << "Password generating expression error\n";
		return 1;
	}
	if(pg.getPasswordLength() > hmacSha1Cuda::getMaxKeyLength())
	{
		cerr << "Password length must be less than or equal to " << hmacSha1Cuda::getMaxKeyLength() << endl;
		return 1;
	}

	const passGenInt numCandidates = pg.getNumCandidates();
	cout << "Number of password candidates: " << numCandidates << endl;

	const size_t keyIndex	= 0;
	//This value is a multiple of SECTOR_SIZE.
	const size_t AFEKSize = roundUpDiv(hdr.keyBytes * hdr.keyblock[keyIndex].stripes, SECTOR_SIZE) * SECTOR_SIZE;
	cout << "AFEKSize: " << AFEKSize << endl;
	std::unique_ptr<char[]> AfKey(new char[AFEKSize]);

	crypt_device* cd;
	initCryptDevice(&cd, filename);

	const size_t batchSize = hmacSha1Cuda::getBatchSize();
	if(batchSize == 0)
	{
		cerr << "Failed to hmacSha1Cuda::getBatchSize()" << endl;
		return 1;
	}
	cout << "batchSize: " << batchSize << endl;

	hmacSha1Cuda hmsc;
	hmacSha1Cuda hmsc2(hdr.keyBytes, hdr.keyblock[keyIndex].stripes, batchSize);
	hmsc.resize(batchSize);
	hmsc2.resize(batchSize);
	hmsc.clearInput();
	hmsc2.clearInput();

	memcpy(hmsc.input(), hdr.keyblock[keyIndex].passwordSalt, LUKS_SALTSIZE);
	hmsc.setInputLength(LUKS_SALTSIZE);
	memcpy(hmsc2.input(), hdr.mkDigestSalt, LUKS_SALTSIZE);
	hmsc2.setInputLength(LUKS_SALTSIZE);
	if(!hmsc.checkInput() || !hmsc2.checkInput())
	{
		cerr << "Invalid input\n";
		return 1;
	}

	cout << "begin loop\n";
	const size_t numLoop = roundUpDiv(numCandidates, batchSize);
	passGenInt passGenCount = 0;
	auto beforeLoopTime = chrono::system_clock::now();
	for(size_t i=0; i<numLoop; ++i)
	{
		for(size_t j=0; j<batchSize; ++j)
		{
			hmsc.clearKey(j);
			pg.generate(hmsc.key(j), passGenCount++);
		}
		hmsc.transformPbkdf2(hdr.keyblock[keyIndex].passwordIterations);

		for(size_t j=0; j<batchSize; ++j)
		{
			int r =
				decryptFromStorage
				(
					AfKey.get(), AFEKSize,
					hdr.cipherName, hdr.cipherMode,
					reinterpret_cast<const char*>(hmsc.outputPbkdf2(j)), hdr.keyBytes,
					hdr.keyblock[keyIndex].keyMaterialOffset,
					cd
				);
			if (r < 0)
			{
				cerr << "Failed to LUKS_decrypt_from_storage\n";
				cerr << "Try again as root\n";
				return r;
			}

			hmsc2.setAfKey(j, AfKey.get());
		}
		hmsc2.AFMerge();
		hmsc2.transformPbkdf2(hdr.mkDigestIterations);
		for(size_t j=0; j<batchSize; ++j)
		{
			if(memcmp(hmsc2.outputPbkdf2(j), hdr.mkDigest, LUKS_DIGESTSIZE) == 0)
			{
				cout << "found: " << hmsc.key(j) << endl;
				cout << "passGenCount: " << passGenCount << endl;
				return 0;
			}
		}

		const float progRate = float(i+1)/numLoop;
		cout << "progress: " << (i+1) << '/' << numLoop << "(" << progRate << "%)" << ", passGenCount=" << passGenCount << endl;
	}
	const auto afterLoopTime = chrono::system_clock::now();
	const float time = chrono::duration_cast<chrono::duration<float>>(afterLoopTime - beforeLoopTime).count();

	cout << "passGenCount: " << passGenCount << endl;
	cout << "time: " << time << "sec" << endl;
	cout << "time/pass: " << time/passGenCount << "sec/pass" << endl;
	cout << "pass/time: " << passGenCount/time << "pass/sec" << endl;
	freeCryptDevice(cd);
	return 0;
}

