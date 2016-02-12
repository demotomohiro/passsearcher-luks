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

#pragma once

#include <gcrypt.h>
#define GCRYPT_REQ_VERSION "1.1.42"

struct crypt_hash
{
	gcry_md_hd_t hd;
	int hash_id;
	int hash_len;
};

typedef crypt_hash crypt_hmac;

int crypt_hmac_size(const char *name);
int crypt_hmac_init(crypt_hmac **ctx, const char *name, bool isHmac);
int crypt_hmac_destroy(crypt_hmac *ctx);
