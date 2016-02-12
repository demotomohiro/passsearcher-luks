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

#include "sha1Block.hpp"
#include <thrust/host_vector.h>

namespace cuda
{
void sha1(const thrust::host_vector<sha1InputBlock>& input, thrust::host_vector<sha1Output>& output);
void hmacSha1
(
	const thrust::host_vector<sha1InputBlock>&	key,
	const sha1InputBlock&						input,
	thrust::host_vector<sha1Output>&			output
);
void pbkdf2
(
	const thrust::host_vector<sha1InputBlock>&	key,
	const sha1InputBlock&						input,
	unsigned int								numIteration,
	thrust::host_vector<derivedKey>&			output
);
void AFMerge
(
	const ui32*								src,
	const ui32								blockSize,
	const ui32								numBlocks,
	const ui32								numKeys,
	thrust::host_vector<sha1InputBlock>&	output
);
}
