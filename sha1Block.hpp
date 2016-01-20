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

#include <cstddef>

#define GET_BGEN(u) \
	(				\
		(((u)<<24)&0xff000000) | (((u)<< 8)&0x00ff0000) |	\
		(((u)>> 8)&0x0000ff00) | (((u)>>24)&0x000000ff))

typedef unsigned int ui32;

struct sha1InputBlock
{
	void setInputLength(size_t len);
	void setInputLengthHmac(size_t len);
	void set(const char* src, size_t srcLen);
	void setKey(const char* src, size_t srcLen);
	void clear();
	size_t getLength() const;
	size_t getLengthHmac() const;
	bool checkInputHmac() const;

	char* data()
	{
		return reinterpret_cast<char*>(block);
	}
	void print() const;

	const static size_t blockSize	= 16;
	const static size_t blockBytes	= blockSize * sizeof(ui32);
	const static size_t blockBits	= blockBytes * 8;
	ui32 block[blockSize];

	const static size_t maxInputLength = sizeof(block) - sizeof(ui32)*2 - 1;
};

struct sha1Output
{
	const static size_t hashSize	= 5;
	const static size_t hashLen		= sizeof(ui32)*hashSize;

	union
	{
		struct
		{
			ui32	h0,h1,h2,h3,h4;
		};
		ui32	h[hashSize];
	};

	const unsigned char* data() const
	{
		return reinterpret_cast<const unsigned char*>(this);
	}
};

struct derivedKey
{
	const static size_t keySize	= 8;

	ui32 block[keySize];

	const unsigned char* data() const
	{
		return reinterpret_cast<const unsigned char*>(this);
	}
};

