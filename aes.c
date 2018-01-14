#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <x86intrin.h>

#include "hodl.h"
#include "miner.h"
#include "wolf-aes.h"

void GenerateGarbageCore(CacheEntry *Garbage, int ThreadID, int ThreadCount, void *MidHash)
{
	uint32_t TempBuf[8];
	memcpy(TempBuf, MidHash, 32);

	uint32_t StartChunk = ThreadID * (TOTAL_CHUNKS / ThreadCount);
	for(uint32_t i = StartChunk; i < StartChunk + (TOTAL_CHUNKS / ThreadCount); ++i)
	{
		TempBuf[0] = i;
		SHA512((uint8_t *)TempBuf, 32, ((uint8_t *)Garbage) + (i * GARBAGE_CHUNK_SIZE));
	}
}

void Rev256(uint32_t *Dest, const uint32_t *Src)
{
	for(int i = 0; i < 8; ++i) Dest[i] = swab32(Src[i]);
}

int scanhash_hodl(int threadNumber, int totalThreads, uint32_t *pdata, CacheEntry *Garbage, const uint32_t *ptarget, unsigned long *hashes_done)
{
	uint32_t CollisionCount = 0;
	CacheEntry Cache;

	// Search for pattern in psuedorandom data
	int searchNumber = COMPARE_SIZE / totalThreads;
	int startLoc = threadNumber * searchNumber;

	for(int32_t k = startLoc; k < startLoc + searchNumber && !work_restart[threadNumber].restart; k++)
	{
		// copy data to first l2 cache
		memcpy(Cache.dwords, Garbage + k, GARBAGE_SLICE_SIZE);

		for(int j = 0; j < AES_ITERATIONS; j++)
		{
			CacheEntry TmpXOR;

			// use last 4 bytes of first cache as next location
			uint32_t nextLocation = Cache.dwords[(GARBAGE_SLICE_SIZE >> 2) - 1] & (COMPARE_SIZE - 1); //% COMPARE_SIZE;

			// Copy data from indicated location to second l2 cache -
			memcpy(&TmpXOR, Garbage + nextLocation, GARBAGE_SLICE_SIZE);

			//XOR location data into second cache
			for(int i = 0; i < (GARBAGE_SLICE_SIZE >> 4); ++i) TmpXOR.dqwords[i] = _mm_xor_si128(Cache.dqwords[i], TmpXOR.dqwords[i]);

			// Key is last 32b of TmpXOR
			// IV is last 16b of TmpXOR

#if defined(__AES__)
			if (aes_ni_supported) {
				__m128i ExpKey[16];
				ExpandAESKey256(ExpKey, TmpXOR.dqwords + (GARBAGE_SLICE_SIZE / sizeof(__m128i)) - 2);
				AES256CBC(Cache.dqwords, TmpXOR.dqwords, ExpKey, TmpXOR.dqwords[(GARBAGE_SLICE_SIZE / sizeof(__m128i)) - 1], 256);
			} else
#endif
			{
				EVP_CIPHER_CTX ctx;
				int outlen1;
				EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), (const unsigned char *)(TmpXOR.dqwords + (GARBAGE_SLICE_SIZE / sizeof(__m128i)) - 2), (const unsigned char *)(TmpXOR.dqwords + ((GARBAGE_SLICE_SIZE / sizeof(__m128i)) - 1)));
				EVP_EncryptUpdate(&ctx, (unsigned char *)Cache.dqwords, &outlen1,  (const unsigned char *)TmpXOR.dqwords, GARBAGE_SLICE_SIZE);
				//EVP_EncryptFinal(&ctx, &Cache.dqwords + outlen1, &outlen2);
				EVP_CIPHER_CTX_cleanup(&ctx);
			}
		}

		// use last X bits as solution
		if((Cache.dwords[(GARBAGE_SLICE_SIZE >> 2) - 1] & (COMPARE_SIZE - 1)) < 1000)
		{
			uint32_t BlockHdr[22], FinalPoW[8];

			BlockHdr[0] = swab32(pdata[0]);

			Rev256(BlockHdr + 1, pdata + 1);
			Rev256(BlockHdr + 9, pdata + 9);

			BlockHdr[17] = swab32(pdata[17]);
			BlockHdr[18] = swab32(pdata[18]);
			BlockHdr[19] = swab32(pdata[19]);
			BlockHdr[20] = k;
			BlockHdr[21] = Cache.dwords[(GARBAGE_SLICE_SIZE >> 2) - 2];

			sha256d((uint8_t *)FinalPoW, (uint8_t *)BlockHdr, 88);
			CollisionCount++;

			if(FinalPoW[7] <= ptarget[7])
			{
				pdata[20] = swab32(BlockHdr[20]);
				pdata[21] = swab32(BlockHdr[21]);
				*hashes_done = CollisionCount;
				return(1);
			}
		}
	}

    *hashes_done = CollisionCount;
    return(0);
}

void GenRandomGarbage(CacheEntry *Garbage, int totalThreads, uint32_t *pdata, int thr_id)
{
	uint32_t BlockHdr[20], MidHash[8];

	BlockHdr[0] = swab32(pdata[0]);

	Rev256(BlockHdr + 1, pdata + 1);
	Rev256(BlockHdr + 9, pdata + 9);

	BlockHdr[17] = swab32(pdata[17]);
	BlockHdr[18] = swab32(pdata[18]);
	BlockHdr[19] = swab32(pdata[19]);

	sha256d((uint8_t *)MidHash, (uint8_t *)BlockHdr, 80);

	GenerateGarbageCore(Garbage, thr_id, totalThreads, MidHash);
}