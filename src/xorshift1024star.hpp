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

class xorshift1024star
{
public:
	xorshift1024star():c(0), p(0)
	{
		for(int i=0; i<16; ++i)
		{
			s[i] = (i*271415) ^ (i*21467937);
		}

		val = generate();
	}

	char get()
	{
		++c;
		if(c==sizeof(uint64_t))
		{
			val = generate();
			c = 0;
		}

		return (char)(val >> (c*8));
	}

private:
	uint64_t generate(void) {
		uint64_t s0 = s[ p ];
		uint64_t s1 = s[ p = (p+1) & 15 ];
		s1 ^= s1 << 31; // a
		s1 ^= s1 >> 11; // b
		s0 ^= s0 >> 30; // c
		return ( s[p] = s0 ^ s1 ) * 1181783497276652981ULL;
	}

	int c;
	uint64_t val;

	uint64_t s[16];
	int p;
};
