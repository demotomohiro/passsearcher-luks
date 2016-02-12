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
#include <cassert>
#include <gcrypt.h>

#include "gcryptMD.hpp"
#include "hmac.hpp"

using namespace std;

namespace
{
	const static char	hashName[] = "sha1";
}

int gcryptMD::init()
{
	if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
	{
		if (!gcry_check_version (GCRYPT_REQ_VERSION))
		{
			return 1;
		}
	}

	const int	hash_id = gcry_md_map_name(hashName);
	cout << "hash_id:\t" << hash_id << endl;

	const unsigned int hashLen = crypt_hmac_size(hashName);
	cout << "hmac size:\t" << hashLen << endl;
	if(hashLen == 0)
	{
		return -EINVAL;
	}

	return 0;
}

gcryptMD::gcryptMD(bool isHmac):hmac(0), isHmac(isHmac)
{
	errorCode = crypt_hmac_init(&hmac, hashName, isHmac);
}

gcryptMD::~gcryptMD()
{
	crypt_hmac_destroy(hmac);
}

const unsigned char* gcryptMD::getHash
(
	const char* pass, size_t passLen,
	const char* salt, size_t saltLen
)
{
	if(isHmac)
	{
		if((errorCode = gcry_md_setkey(hmac->hd, pass, passLen))!=0)
		{
			return 0;
		}
	}else
	{
		gcry_md_reset(hmac->hd);
	}

	gcry_md_write(hmac->hd, salt, saltLen);
	const unsigned char* ret = gcry_md_read(hmac->hd, hmac->hash_id);
	if(!ret)
	{
		errorCode = -EINVAL;
		return 0;
	}else
		return ret;
}

int gcryptMD::getHashLen() const
{
	assert(hmac);
	return hmac->hash_len;
}
