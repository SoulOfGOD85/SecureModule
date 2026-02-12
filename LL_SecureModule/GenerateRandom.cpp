#include "stdafx.h"

#include "Session.h"
#include "Utils.h"

#include <ctfext.h>

namespace LL_SecureModule
{
	/// <summary>
	/// Generates random or pseudo-random data.
	/// <para>This function can mix additional seed material into the token's random number generator.</para>
	/// </summary>
	void SMSession::GenerateRandom(array<Byte>^ seed, UInt32 randomLength, array<Byte>^% randomData)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR seed_data = NULL;
		CK_ULONG seed_len = 0;

		CK_BYTE_PTR random_data = NULL;
		CK_ULONG random_data_length = 0;

		try
		{
			// Input data validation check.
			if (randomLength == 0) throw gcnew SecureModuleException("'randomLength' should be grater than zero.");

			if (seed != nullptr)
			{
				// Convert seed from array of byte to CK_BYTE_PTR.
				Utils::ConvertByteArrayToCKBytePtr(seed, &seed_data, &seed_len);

				rv = C_SeedRandom(this->hSession, seed_data, seed_len);

				delete[] seed_data;

				// Check if resulting an exception.
				if (rv != CKR_OK)
					throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
			}

			random_data_length = randomLength;
			random_data = new CK_BYTE[random_data_length];

			rv = C_GenerateRandom(this->hSession, random_data, random_data_length);

			// Convert random_data from CK_BYTE_PTR to array of byte.
			Utils::ConvertCKBytePtrToByteArray(random_data, random_data_length, randomData);

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (SecureModuleException^)
		{
			throw;
		}
		catch (Exception^)
		{
			throw;
		}
	}
}