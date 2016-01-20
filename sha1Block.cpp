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

#include "sha1Block.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

void sha1InputBlock::setInputLength(size_t len)
{
	assert(len <= maxInputLength);

	reinterpret_cast<unsigned char*>(block)[len] = 0x80;
	block[blockSize-1] = GET_BGEN(len*8);
}

void sha1InputBlock::setInputLengthHmac(size_t len)
{
	assert(len <= maxInputLength);

	reinterpret_cast<unsigned char*>(block)[len] = 0x80;
	block[blockSize-1] = GET_BGEN(len*8+blockBits);
}

void sha1InputBlock::set(const char* src, size_t srcLen)
{
	if(srcLen >= maxInputLength)
		return;
	setKey(src, srcLen);
	setInputLength(srcLen);
}

void sha1InputBlock::setKey(const char* src, size_t srcLen)
{
	if(srcLen >= maxInputLength)
		return;
	clear();
	for(size_t i=0; i<sha1InputBlock::blockSize; ++i)
	{
		const size_t idx = i*4;
		if(idx >= srcLen)
			break;
		block[i] = src[idx];
		if(idx+1 >= srcLen)
			break;
		block[i] |= src[idx+1] << 8;
		if(idx+2 >= srcLen)
			break;
		block[i] |= src[idx+2] << 16;
		if(idx+3 >= srcLen)
			break;
		block[i] |= src[idx+3] << 24;
	}
}

void sha1InputBlock::clear()
{
	memset(block, 0, sizeof(block));
}

size_t sha1InputBlock::getLength() const
{
	return GET_BGEN(block[blockSize-1])>>3;
}

size_t sha1InputBlock::getLengthHmac() const
{
	return getLength() - blockBytes;
}

bool sha1InputBlock::checkInputHmac() const
{
	const size_t len = getLengthHmac();
	if(len > maxInputLength)
		return false;

	if(reinterpret_cast<const unsigned char*>(block)[len] != 0x80)
		return false;

	return true;
}

void sha1InputBlock::print() const
{
	using namespace std;
	cout << hex;
	for(ui32 i=0; i<blockSize*4; ++i)
		cout << (unsigned int)(reinterpret_cast<const char*>(block)[i]) << " ";
	cout << endl;
}

