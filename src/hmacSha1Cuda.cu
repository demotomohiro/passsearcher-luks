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

#include "hmacSha1Cuda.hpp"
#include "sha1Block.hpp"
#include "mdCuda.hpp"
#include <cassert>
#include <thrust/host_vector.h>
#include <thrust/device_vector.h>

struct myCudaDeletor
{
	void operator()(void* ptr)
	{
		cudaFree(ptr);
	}
};

template<typename T>
using myCudaUniquePtr = std::unique_ptr<T, myCudaDeletor>;

template<typename T>
__host__ myCudaUniquePtr<T[]> makeCudaUniquePtr(const size_t size)
{
	T* ptr;
	cudaMalloc(&ptr, sizeof(T) * size);
	return myCudaUniquePtr<T[]>(ptr, myCudaDeletor());
}

class AF
{
public:

	AF(size_t blockBytes, size_t numBlocks, size_t numKeys):
		blockSize(blockBytes/sizeof(ui32)), numBlocks(numBlocks), numKeys(numKeys),
		AfKeys(new ui32[blockBytes/sizeof(ui32) * numBlocks * numKeys]),
		deviceAfKeys(makeCudaUniquePtr<ui32>(blockBytes/sizeof(ui32) * numBlocks * numKeys))
	{
		assert(blockBytes%sizeof(ui32) == 0);
	}

	void setAfKey(size_t idx, const char* src)
	{
		char* dst = reinterpret_cast<char*>(&AfKeys[blockSize * numBlocks * idx]);
		memcpy(dst, src, sizeof(ui32) * blockSize * numBlocks);
	}

	void AFMerge(thrust::host_vector<sha1InputBlock>&	output)
	{
		cudaMemcpy(deviceAfKeys.get(), AfKeys.get(), sizeof(ui32) * blockSize * numBlocks * numKeys, cudaMemcpyHostToDevice);
		cuda::AFMerge(deviceAfKeys.get(), blockSize, numBlocks, numKeys, output);
	}

	AF& operator=(const AF&);

	const size_t blockSize;
	const size_t numBlocks;
	const size_t numKeys;

	std::unique_ptr<ui32[]>	AfKeys;
	myCudaUniquePtr<ui32[]>	deviceAfKeys;
};

struct hmacSha1CudaPrivate
{
	hmacSha1CudaPrivate()
	{
	}

	hmacSha1CudaPrivate(size_t blockBytes, size_t numBlocks, size_t numKeys):
		pAF(new AF(blockBytes, numBlocks, numKeys))
	{
	}

	thrust::host_vector<sha1InputBlock>		hostKey;
	sha1InputBlock							hostIn;
	thrust::host_vector<sha1Output>			hostOut;
	thrust::host_vector<derivedKey>			hostPbkdf2Out;

	std::unique_ptr<AF>						pAF;
};

hmacSha1Cuda::hmacSha1Cuda():priv(new hmacSha1CudaPrivate)
{
}

hmacSha1Cuda::hmacSha1Cuda(size_t blockBytes, size_t numBlocks, size_t numKeys):
	priv(new hmacSha1CudaPrivate(blockBytes, numBlocks, numKeys))
{
}

hmacSha1Cuda::~hmacSha1Cuda()
{
}

size_t hmacSha1Cuda::getMaxKeyLength()
{
	return sha1InputBlock::blockBytes - 1;
}

size_t hmacSha1Cuda::getBatchSize()
{
	int val;
	cudaError_t e = cudaDeviceGetAttribute(&val, cudaDevAttrMultiProcessorCount, 0);
	if(e != cudaSuccess)
	{
		return 0;
	}

	return val*256;
}

const unsigned char* hmacSha1Cuda::getHash
(
	const char* pass, size_t passLen,
	const char* salt, size_t saltLen
)
{
	thrust::host_vector<sha1InputBlock>		hostKey(1);
	sha1InputBlock							hostIn;
	hostKey[0].setKey(pass, passLen);
	hostIn.set(salt, saltLen);
	hostIn.setInputLengthHmac(saltLen);
	assert(hostIn.getLengthHmac() == saltLen);
//	hostIn[0].print();
	cuda::hmacSha1(hostKey, hostIn, priv->hostOut);

	return priv->hostOut[0].data();
}

const unsigned char* hmacSha1Cuda::getPbkdf2
(
	const char* pass, size_t passLen,
	const char* salt, size_t saltLen,
	unsigned int numIteration
)
{
	resize(1);
	clearInput();
	clearKey(0);
	memcpy(key(0), pass, passLen);
	memcpy(input(), salt, saltLen);
	setInputLength(saltLen);
	assert(checkInput());
	assert(getLength() == saltLen);
	transformPbkdf2(numIteration);
	return outputPbkdf2(0);
}

void hmacSha1Cuda::resize(size_t n)
{
	priv->hostKey.resize(n);
}

void hmacSha1Cuda::clearInput()
{
	priv->hostIn.clear();
}

void hmacSha1Cuda::clearKey(size_t idx)
{
	priv->hostKey[idx].clear();
}

char* hmacSha1Cuda::key(size_t idx)
{
	return priv->hostKey[idx].data();
}

char* hmacSha1Cuda::input()
{
	return priv->hostIn.data();
}

void hmacSha1Cuda::setInputLength(size_t length)
{
	priv->hostIn.setInputLengthHmac(length);
}

bool hmacSha1Cuda::checkInput()
{
	return priv->hostIn.checkInputHmac();
}

void hmacSha1Cuda::setAfKey(size_t idx, const char* src)
{
	assert(priv->pAF);
	priv->pAF->setAfKey(idx, src);
}

void hmacSha1Cuda::transform()
{
	cuda::hmacSha1(priv->hostKey, priv->hostIn, priv->hostOut);
}

void hmacSha1Cuda::AFMerge()
{
	assert(priv->pAF);

	priv->pAF->AFMerge(priv->hostKey);
}

void hmacSha1Cuda::transformPbkdf2(unsigned int numIteration)
{
	cuda::pbkdf2(priv->hostKey, priv->hostIn, numIteration, priv->hostPbkdf2Out);
}

size_t hmacSha1Cuda::getLength()
{
	return priv->hostIn.getLengthHmac();
}

const unsigned char* hmacSha1Cuda::output(size_t idx) const
{
	return priv->hostOut[idx].data();
}

const unsigned char* hmacSha1Cuda::outputPbkdf2(size_t idx) const
{
	return priv->hostPbkdf2Out[idx].data();
}

struct sha1CudaPrivate
{
	thrust::host_vector<sha1InputBlock>		hostIn;
	thrust::host_vector<sha1Output>			hostOut;
};

sha1Cuda::sha1Cuda():priv(new sha1CudaPrivate)
{
}

sha1Cuda::~sha1Cuda()
{
}

const unsigned char* sha1Cuda::getHash
(
	const char* pass, size_t passLen,
	const char* salt, size_t saltLen
)
{
	thrust::host_vector<sha1InputBlock>		hostIn(1);
	hostIn[0].set(salt, saltLen);
	assert(hostIn[0].getLength() == saltLen);
//	hostIn[0].print();
	cuda::sha1(hostIn, priv->hostOut);

	return priv->hostOut[0].data();
}

void sha1Cuda::resize(size_t n)
{
	priv->hostIn.resize(n);
}

void sha1Cuda::clear(size_t idx)
{
	priv->hostIn[idx].clear();
}

char* sha1Cuda::input(size_t idx)
{
	return priv->hostIn[idx].data();
}

void sha1Cuda::setInputLength(size_t idx, size_t length)
{
	priv->hostIn[idx].setInputLength(length);
}

void sha1Cuda::transform()
{
	cuda::sha1(priv->hostIn, priv->hostOut);
}

size_t sha1Cuda::getLength(size_t idx)
{
	return priv->hostIn[idx].getLength();
}

const unsigned char* sha1Cuda::output(size_t idx) const
{
	return priv->hostOut[idx].data();
}

