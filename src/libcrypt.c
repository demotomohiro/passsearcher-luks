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

#include "libcrypt.h"
#include "libcryptsetup/libcryptsetup.h"
#include "libcryptsetup/luks.h"
#include "libcryptsetup/internal.h"

#include <stdlib.h>
#include <errno.h>

int initCryptDevice(struct crypt_device** cd, const char* filename)
{
	int r;
	if ((r = crypt_init(cd, filename)))
		goto out;

	return r;

out:
	crypt_free(*cd);
	return r;
}

void freeCryptDevice(struct crypt_device* cd)
{
	crypt_free(cd);
}

int decryptFromStorage(
	char *dst, size_t dstLength,
	const char *cipher,
	const char *cipher_mode,
	const char *vkey, size_t vkLength,
	unsigned int sector,
	struct crypt_device *ctx)
{
	struct volume_key* vk = malloc(sizeof(struct volume_key) + vkLength);
	vk->keylength = vkLength;
	memcpy(&vk->key, vkey, vkLength);

	const int r = LUKS_decrypt_from_storage
	(
		dst,		dstLength,
		cipher,		cipher_mode,
		vk,
		sector,
		ctx
	);
	free(vk);

	return r;
}

