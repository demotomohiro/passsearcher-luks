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

#include <cassert>
#include <algorithm>
#include <iostream>

passGen::passGen(const char* pattern)
{
	//Current implementation suppose passwords don't include '[', ']' and '-' characters.
	hasError = true;
	size_t s = 0;
	for(const char* p = pattern; *p; ++p, ++s)
	{
		if(*p == '[')
		{
			++p;
			if(*p == ']')
			{
				std::cerr << "Empty character list." << std::endl;
				return;
			}
			for(; *p != ']'; ++p)
			{
				if(*p == 0 || *p == '[')
				{
					std::cerr << "'[' is not closed." << std::endl;
					return;
				}
			}
		}
	}
	userMask.resize(s);
	size_t i = 0;
	for(const char* p = pattern; *p; ++p, ++i)
	{
		if(*p == '[')
		{
			size_t cs = 0;
			++p;
			for(;*p != ']'; ++p)
			{
				const char prev = *(p-1), next = *(p+1);
				if(*p == '-')
				{
					if(prev == '[' || next == ']' || prev == '-' || next == '-')
					{
						std::cerr << "Invalid range expression." << std::endl;
						return;
					}
					char begin = prev, end = next;
					if(begin > end)
					{
						std::swap(begin, end);
					}
					cs += end - begin + 1;
				}else if(prev != '-' && next != '-')
				{
					++cs;
				}
			}
			userMask[i].resize(cs);
		}else
		{
			userMask[i].resize(1);
		}
	}

	i = 0;
	for(const char* p = pattern; *p; ++p, ++i)
	{
		if(*p == '[')
		{
			++p;
			for(size_t j = 0; *p != ']'; ++p)
			{
				const char prev = *(p-1), next = *(p+1);
				if(*p == '-')
				{
					char begin = prev, end = next;
					if(begin > end)
					{
						std::swap(begin, end);
					}
					const size_t s = end - begin + 1;
					for(char k = 0; k < s; ++k, ++j)
					{
						userMask[i][j] = begin + k;
					}
				}else if(prev != '-' && next != '-')
				{
					userMask[i][j] = *p;
					++j;
				}
			}
		}else
		{
			userMask[i][0] = *p;
		}
	}

	hasError = false;
}

std::size_t passGen::getPasswordLength() const
{
	assert(!getHasError());

	return userMask.size();
}

passGenInt passGen::getNumCandidates() const
{
	assert(!getHasError());

	passGenInt ret = 1;
	for(const charset& i : userMask)
	{
		ret *= i.size();
	}

	return ret;
}

void passGen::generate(char* dst, passGenInt count) const
{
	//count can be larger than getNumCandidates().
	assert(!getHasError());

	passGenInt j = count;
	char* d = dst;
	for(const charset& i : userMask)
	{
		const size_t s = i.size();
		const size_t k = j % s;
		*d = i[k];
		++d;
		j /= s;
	}
	*d = 0;
}

void passGen::printMask() const
{
	assert(!getHasError());

	for(const charset& i : userMask)
	{
		for(const char c : i)
		{
			std::cout << c << ',';
		}
		std::cout << std::endl;
	}
}

#if 0
//Test passGen
int main(int argc, const char** argv)
{
	using namespace std;

	if(argc < 2)
		return 1;

	const passGen pg(argv[1]);
	if(pg.getHasError())
	{
		return 1;
	}

	const static size_t maxPassLen = 63;
	if(pg.getPasswordLength() > maxPassLen)
	{
		cerr << "Password length must be less than or equal to " << maxPassLen << endl;
		return 1;
	}

	const passGenInt numCandidates = pg.getNumCandidates();
	cout << "Number of candidates: " << numCandidates << endl;

	pg.printMask();

	char key[maxPassLen+1];
	for(passGenInt i=0; i<numCandidates; ++i)
	{
		pg.generate(key, i);
		cout << key << endl;
	}

	return 0;
}
#endif
