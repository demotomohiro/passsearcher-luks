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

#include <stddef.h>

#define SECTOR_SHIFT            9
#define SECTOR_SIZE             (1 << SECTOR_SHIFT)

struct crypt_device;
int initCryptDevice(struct crypt_device** cd, const char* filename);
void freeCryptDevice(struct crypt_device* cd);
int decryptFromStorage(
	char *dst, size_t dstLength,
	const char *cipher,
	const char *cipher_mode,
	const char *vk, size_t vkLength,
	unsigned int sector,
	struct crypt_device *ctx);
