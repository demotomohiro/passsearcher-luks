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

#include <cerrno>
#include <cstdlib>
#include "hmac.hpp"

int crypt_hash_size(const char *name)
{
	const int hash_id = gcry_md_map_name(name);
	if (!hash_id)
		return -EINVAL;

	return gcry_md_get_algo_dlen(hash_id);
}

int crypt_hmac_size(const char *name)
{
	return crypt_hash_size(name);
}

int crypt_hmac_init(crypt_hmac **ctx, const char *name, bool isHmac)
{
	unsigned int flags = isHmac ? GCRY_MD_FLAG_HMAC : 0;
	crypt_hmac *h = reinterpret_cast<crypt_hmac*>(malloc(sizeof(*h)));
	if (!h)
		return -ENOMEM;

	h->hash_id = gcry_md_map_name(name);
	if (!h->hash_id) {
		free(h);
		return -EINVAL;
	}

	if (gcry_md_open(&h->hd, h->hash_id, flags)) {
		free(h);
		return -EINVAL;
	}

	h->hash_len = gcry_md_get_algo_dlen(h->hash_id);
	*ctx = h;
	return 0;
}

int crypt_hmac_destroy(crypt_hmac *ctx)
{
	gcry_md_close(ctx->hd);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
	return 0;
}

