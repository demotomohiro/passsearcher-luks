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

#include <iostream>
#include <iomanip>

inline void printHex(const void* data, size_t size)
{
	using namespace std;

	const static size_t columns	= 16;
	const size_t	remainder	= size % columns;
	const size_t	lines		= size / columns + (remainder!=0 ? 1: 0);
	const unsigned char*	cdata	= reinterpret_cast<const unsigned char*>(data);

	const streamsize prevw = cout.width();

	cout << hex;
	for(size_t i=0; i<lines; ++i)
	{
		const size_t c = (i==lines-1 && remainder!=0 ? remainder : columns);
		for(size_t j=0; j<c; ++j)
		{
			cout << setw(2) << (unsigned int)(*cdata++);
			if(j%4 == 3)
				cout << '|';
			else
				cout << " ";
		}
		if(i!=lines-1)
			cout << '<';
		cout << '\n';
	}

	cout.width(prevw);
}

template<typename T>
inline void printHex(const T& data)
{
	printHex(&data, sizeof(data));
}

template<size_t N>
class staticStrRef
{
	staticStrRef(const char (&str)[N]):str(str)
	{
	}

	staticStrRef(const staticStrRef& str):str(str.str)
	{
	}

	const char (&str)[N];

	template<size_t NN>
	friend staticStrRef<NN> staticStr(const char (&str)[NN]);
	template<size_t NN>
	friend std::ostream& operator<< (std::ostream& os, const staticStrRef<NN>& str);
};

template<size_t NN>
inline staticStrRef<NN> staticStr(const char (&str)[NN])
{
	return staticStrRef<NN>(str);
}

template<size_t NN>
inline std::ostream& operator<< (std::ostream& os, const staticStrRef<NN>& str)
{
	using namespace std;

	const char* p = str.str;
	size_t i=0;
	for(; i<NN; ++i)
	{
		if(*p == 0)
			break;
		os << *p++;
	}

	os << '[' << i << '/' <<  NN << ']';
	return os;
}

//T must be integer type.
template<typename T0, typename T1>
inline decltype(T0()+T1()) roundUpDiv(const T0 a, const T1 b)
{
	return (a + (b - 1)) / b;
}

