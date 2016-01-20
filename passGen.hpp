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

#include <vector>

typedef unsigned int passGenInt;

//This class's constractor takes a password generating expression from program parameter.
//And 'generate' member function takes counter(0, 1, 2, ...) and returns corresponding password candidate.
class passGen
{
	typedef std::vector<char>		charset;
	typedef std::vector<charset>	mask;

public:

	passGen(const char* pattern);

	bool getHasError() const
	{
		return hasError;
	}

	std::size_t	getPasswordLength()	const;
	passGenInt	getNumCandidates() const;
	//Write password candidate to dst.
	void		generate(char* dst, passGenInt count) const;
	//Print content of userMask for debug.
	void		printMask() const;

private:

	mask	userMask;
	bool	hasError;
};

