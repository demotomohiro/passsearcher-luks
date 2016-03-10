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

#define IS_NV
#define _PBKDF2_SHA1_
#include "oclHashcat/include/constants.h"
#include "oclHashcat/include/kernel_functions.c"

typedef unsigned char uchar;
typedef unsigned int u32x;
#include "oclHashcat/OpenCL/types_ocl.c"

#include "sha1Block.hpp"
#include <cassert>
#include <thrust/host_vector.h>
#include <thrust/device_vector.h>
#include <thrust/transform.h>
#include <thrust/iterator/counting_iterator.h>

__device__ void sha1Init(sha1Output& output)
{
	output.h0 = 0x67452301;
	output.h1 = 0xefcdab89;
	output.h2 = 0x98badcfe;
	output.h3 = 0x10325476;
	output.h4 = 0xc3d2e1f0;
}

__device__ void sha1Transform(const sha1InputBlock& input, sha1Output& output)
{
/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */
//Following code was copied from "sha1_transform" in oclHashcat/OpenCL/m12000.cl in https://github.com/hashcat/oclHashcat

	typedef ui32 u32;

	u32 A = output.h0;
	u32 B = output.h1;
	u32 C = output.h2;
	u32 D = output.h3;
	u32 E = output.h4;

	u32 w0_t = GET_BGEN(input.block[0]);
	u32 w1_t = GET_BGEN(input.block[1]);
	u32 w2_t = GET_BGEN(input.block[2]);
	u32 w3_t = GET_BGEN(input.block[3]);
	u32 w4_t = GET_BGEN(input.block[4]);
	u32 w5_t = GET_BGEN(input.block[5]);
	u32 w6_t = GET_BGEN(input.block[6]);
	u32 w7_t = GET_BGEN(input.block[7]);
	u32 w8_t = GET_BGEN(input.block[8]);
	u32 w9_t = GET_BGEN(input.block[9]);
	u32 wa_t = GET_BGEN(input.block[10]);
	u32 wb_t = GET_BGEN(input.block[11]);
	u32 wc_t = GET_BGEN(input.block[12]);
	u32 wd_t = GET_BGEN(input.block[13]);
	u32 we_t = GET_BGEN(input.block[14]);
	u32 wf_t = GET_BGEN(input.block[15]);

	#undef K
	#define K SHA1C00

	SHA1_STEP (SHA1_F0o, A, B, C, D, E, w0_t);
	SHA1_STEP (SHA1_F0o, E, A, B, C, D, w1_t);
	SHA1_STEP (SHA1_F0o, D, E, A, B, C, w2_t);
	SHA1_STEP (SHA1_F0o, C, D, E, A, B, w3_t);
	SHA1_STEP (SHA1_F0o, B, C, D, E, A, w4_t);
	SHA1_STEP (SHA1_F0o, A, B, C, D, E, w5_t);
	SHA1_STEP (SHA1_F0o, E, A, B, C, D, w6_t);
	SHA1_STEP (SHA1_F0o, D, E, A, B, C, w7_t);
	SHA1_STEP (SHA1_F0o, C, D, E, A, B, w8_t);
	SHA1_STEP (SHA1_F0o, B, C, D, E, A, w9_t);
	SHA1_STEP (SHA1_F0o, A, B, C, D, E, wa_t);
	SHA1_STEP (SHA1_F0o, E, A, B, C, D, wb_t);
	SHA1_STEP (SHA1_F0o, D, E, A, B, C, wc_t);
	SHA1_STEP (SHA1_F0o, C, D, E, A, B, wd_t);
	SHA1_STEP (SHA1_F0o, B, C, D, E, A, we_t);
	SHA1_STEP (SHA1_F0o, A, B, C, D, E, wf_t);
	w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, E, A, B, C, D, w0_t);
	w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, D, E, A, B, C, w1_t);
	w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, C, D, E, A, B, w2_t);
	w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, B, C, D, E, A, w3_t);

	#undef K
	#define K SHA1C01

	w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w4_t);
	w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w5_t);
	w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w6_t);
	w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w7_t);
	w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w8_t);
	w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w9_t);
	wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wa_t);
	wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wb_t);
	wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wc_t);
	wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wd_t);
	we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, we_t);
	wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wf_t);
	w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w0_t);
	w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w1_t);
	w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w2_t);
	w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w3_t);
	w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w4_t);
	w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w5_t);
	w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w6_t);
	w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w7_t);

	#undef K
	#define K SHA1C02

	w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w8_t);
	w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w9_t);
	wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wa_t);
	wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wb_t);
	wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wc_t);
	wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, wd_t);
	we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, we_t);
	wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wf_t);
	w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w0_t);
	w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w1_t);
	w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w2_t);
	w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w3_t);
	w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w4_t);
	w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w5_t);
	w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w6_t);
	w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w7_t);
	w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w8_t);
	w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w9_t);
	wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wa_t);
	wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wb_t);

	#undef K
	#define K SHA1C03

	wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wc_t);
	wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wd_t);
	we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, we_t);
	wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wf_t);
	w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w0_t);
	w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w1_t);
	w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w2_t);
	w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w3_t);
	w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w4_t);
	w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w5_t);
	w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w6_t);
	w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w7_t);
	w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w8_t);
	w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w9_t);
	wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wa_t);
	wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wb_t);
	wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wc_t);
	wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wd_t);
	we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, we_t);
	wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wf_t);

	output.h0 += A;
	output.h1 += B;
	output.h2 += C;
	output.h3 += D;
	output.h4 += E;
}

__device__ void sha1Final(sha1Output& output)
{
	output.h0 = GET_BGEN(output.h0);
	output.h1 = GET_BGEN(output.h1);
	output.h2 = GET_BGEN(output.h2);
	output.h3 = GET_BGEN(output.h3);
	output.h4 = GET_BGEN(output.h4);
}

__device__ sha1InputBlock outputToInputHmac(const sha1Output& src)
{
	sha1InputBlock ret;
	ret.block[0] = src.h0;
	ret.block[1] = src.h1;
	ret.block[2] = src.h2;
	ret.block[3] = src.h3;
	ret.block[4] = src.h4;
	ret.block[5] = 0x80;

	for(int i=6; i<sha1InputBlock::blockSize-1; ++i)
	{
		ret.block[i] = 0;
	}
	ret.block[sha1InputBlock::blockSize-1] = GET_BGEN((ui32)(512+160));

	return ret;
}
__device__ sha1Output hmacSha1(const sha1InputBlock& key, const sha1InputBlock& input)
{
	sha1Output	tmp;
	sha1Init(tmp);

	sha1InputBlock ipadKey;
	for(int i=0; i<sha1InputBlock::blockSize; ++i)
	{
		ipadKey.block[i] = key.block[i] ^ 0x36363636;
	}

	sha1Transform(ipadKey, tmp);
	sha1Transform(input, tmp);
	sha1Final(tmp);

	sha1Output	ret;
	sha1Init(ret);
	sha1InputBlock opadKey;
	for(int i=0; i<sha1InputBlock::blockSize; ++i)
	{
		opadKey.block[i] = key.block[i] ^ 0x5c5c5c5c;
	}
	sha1Transform(opadKey, ret);

	sha1InputBlock hashed = outputToInputHmac(tmp);

	sha1Transform(hashed, ret);
	sha1Final(ret);

	return ret;
}

__device__ void hashBuf(ui32* buf, ui32 size, ui32 iv)
{
	sha1InputBlock input;
	input.block[0] = GET_BGEN(iv);
	ui32 j = 1;
	for(; j<size+1; ++j)
	{
		input.block[j] = buf[j - 1];
	}
	input.block[j++] = 0x80;
	for(; j<sha1InputBlock::blockSize-1; ++j)
	{
		input.block[j] = 0;
	}
	const ui32 ml = (size+1)*sizeof(ui32)*8;
	input.block[sha1InputBlock::blockSize-1] = GET_BGEN(ml);

	sha1Output	tmp;
	sha1Init(tmp);
	sha1Transform(input, tmp);
	sha1Final(tmp);

	for(j=0; j<size; ++j)
	{
		buf[j] = tmp.h[j];
	}
}

class sha1Op
{
public:
	__device__ sha1Output operator()(const sha1InputBlock& in) const
	{
		sha1Output	ret;

		sha1Init(ret);
		sha1Transform(in, ret);
		sha1Final(ret);

		return ret;
	}
};

class hmacSha1Op
{
	const sha1InputBlock input;

public:
	hmacSha1Op(const sha1InputBlock& input):input(input)
	{
	}

	__device__ sha1Output operator()(const sha1InputBlock& key) const
	{
		return hmacSha1(key, input);
	}
};

class pbkdf2Op
{
	const unsigned int		numIteration;
	const sha1InputBlock	input;

public:
	pbkdf2Op(unsigned int numIteration, const sha1InputBlock& input):
		numIteration(numIteration),
		input(input)
	{
	}

	__device__ derivedKey operator()(const sha1InputBlock& key) const
	{
		derivedKey DK;
		for(int i=1; i<=2; ++i)
		{
			sha1InputBlock tmp = input;
			const ui32 sz = GET_BGEN(input.block[sha1InputBlock::blockSize-1]);
			tmp.block[sha1InputBlock::blockSize-1] = GET_BGEN(sz+32);
			const ui32 end		= (sz-512)>>5;
			tmp.block[end]		= GET_BGEN(i);
			tmp.block[end+1]	= 0x80;
			sha1Output 	T = hmacSha1(key, tmp);
			sha1Output	U = T;
			for(int j=2; j<=numIteration; ++j)
			{
				U = hmacSha1(key, outputToInputHmac(U));
				T.h0 ^= U.h0;
				T.h1 ^= U.h1;
				T.h2 ^= U.h2;
				T.h3 ^= U.h3;
				T.h4 ^= U.h4;
			}
			if(i == 1)
			{
				DK.block[0] = T.h0;
				DK.block[1] = T.h1;
				DK.block[2] = T.h2;
				DK.block[3] = T.h3;
				DK.block[4] = T.h4;
			}else
			{
				DK.block[5] = T.h0;
				DK.block[6] = T.h1;
				DK.block[7] = T.h2;
			}
		}
		return DK;
	}
};

class AFMergeOp
{
	const ui32* src;
	const ui32	blockSize;
	const ui32	numBlocks;

public:

	//blockSize == keyBytes / sizeof(ui32)
	//keyBytes % 4 must be 0 && keyBytes <= 32
	AFMergeOp(const ui32* src, const ui32 blockSize, const ui32 numBlocks):
		src(src), blockSize(blockSize), numBlocks(numBlocks)
	{
	}

	__device__ sha1InputBlock operator()(const ui32 id) const
	{
		ui32 bufblock[32/sizeof(ui32)];

		for(ui32 i=0; i<blockSize; ++i)
		{
			bufblock[i] = 0;
		}

		ui32 i=0;
		for(; i<numBlocks-1; ++i)
		{
			for(ui32 j=0; j<blockSize; ++j)
			{
				bufblock[j] = src[id*blockSize*numBlocks + i*blockSize + j] ^ bufblock[j];
			}

			diffuse(bufblock);
		}

		sha1InputBlock ret;
		ui32 j=0;
		for(; j<blockSize; ++j)
		{
			ret.block[j] = src[id*blockSize*numBlocks + i*blockSize + j] ^ bufblock[j];
		}
		for(; j<sha1InputBlock::blockSize; ++j)
		{
			ret.block[j] = 0;
		}

		return ret;
	}

private:

	__device__ void diffuse(ui32* bufblock) const
	{
		const ui32 numMDBlks 	= blockSize / sha1Output::hashSize;
		const ui32 padding		= blockSize % sha1Output::hashSize;

		ui32 i=0;
		for(; i<numMDBlks; ++i)
		{
			hashBuf(bufblock + i*sha1Output::hashSize, sha1Output::hashSize, i);
		}
		if(padding)
			hashBuf(bufblock + i*sha1Output::hashSize, padding, i);
	}
};

namespace cuda
{
void sha1(const thrust::host_vector<sha1InputBlock>& input, thrust::host_vector<sha1Output>& output)
{
	thrust::device_vector<sha1InputBlock>	deviceIn(input);
	thrust::device_vector<sha1Output>		deviceOut(input.size());
	thrust::transform(deviceIn.begin(), deviceIn.end(), deviceOut.begin(), sha1Op());
	output = deviceOut;
}

void hmacSha1
(
	const thrust::host_vector<sha1InputBlock>&	key,
	const sha1InputBlock&						input,
	thrust::host_vector<sha1Output>&			output
)
{
	thrust::device_vector<sha1InputBlock>	deviceKey(key);
	thrust::device_vector<sha1Output>		deviceOut(key.size());
	thrust::transform(deviceKey.begin(), deviceKey.end(), deviceOut.begin(), hmacSha1Op(input));
	output = deviceOut;
}

void pbkdf2
(
	const thrust::host_vector<sha1InputBlock>&	key,
	const sha1InputBlock&						input,
	unsigned int								numIteration,
	thrust::host_vector<derivedKey>&			output
)
{
	static thread_local thrust::device_vector<sha1InputBlock>	deviceKey;
	deviceKey = key;
	static thread_local thrust::device_vector<derivedKey>		deviceOut;
	deviceOut.resize(key.size());
	thrust::transform
	(
		deviceKey.begin(), deviceKey.end(), deviceOut.begin(), pbkdf2Op(numIteration, input)
	);
	output = deviceOut;
}

void AFMerge
(
	const ui32*								src,
	const ui32								blockSize,
	const ui32								numBlocks,
	const ui32								numKeys,
	thrust::host_vector<sha1InputBlock>&	output
)
{
	assert(blockSize <= 32/sizeof(ui32));
	thrust::counting_iterator<ui32> citer(0);
	thrust::device_vector<sha1InputBlock> deviceOut(numKeys);
	thrust::transform
	(
		citer, citer + numKeys, deviceOut.begin(), AFMergeOp(src, blockSize, numBlocks)
	);
	output = deviceOut;
}
}
