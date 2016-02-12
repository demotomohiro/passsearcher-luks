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

#include <memory>

struct hmacSha1CudaPrivate;

class hmacSha1Cuda
{
public:
	hmacSha1Cuda();
	hmacSha1Cuda(size_t blockBytes, size_t numBlocks, size_t numKeys);
	~hmacSha1Cuda();

	static size_t getMaxKeyLength();
	static size_t getBatchSize();

	const unsigned char* getHash
	(
		const char* pass, size_t passLen,
		const char* salt, size_t saltLen
	);
	const unsigned char* getPbkdf2
	(
		const char* pass, size_t passLen,
		const char* salt, size_t saltLen,
		unsigned int numIteration
	);

	void resize(size_t n);
	void clearInput();
	void clearKey(size_t idx);
	char* key(size_t idx);
	char* input();
	void setInputLength(size_t length);
	bool checkInput();
	void setAfKey(size_t idx, const char* src);
	void transform();
	void AFMerge();
	void transformPbkdf2(unsigned int numIteration);
	size_t getLength();
	const unsigned char* output(size_t idx) const;
	const unsigned char* outputPbkdf2(size_t idx) const;

private:
	std::unique_ptr<hmacSha1CudaPrivate> priv;
};

struct sha1CudaPrivate;

class sha1Cuda
{
public:
	sha1Cuda();
	~sha1Cuda();

	const unsigned char* getHash
	(
		const char* pass, size_t passLen,
		const char* salt, size_t saltLen
	);

	void resize(size_t n);
	void clear(size_t idx);
	char* input(size_t idx);
	void setInputLength(size_t idx, size_t length);
	void transform();
	size_t getLength(size_t idx);
	const unsigned char* output(size_t idx) const;

private:
	std::unique_ptr<sha1CudaPrivate> priv;
};

