#include "stdafx.h"

#include "Mechanisms.h"
#include "Object.h"
#include "Utils.h"

#include <ctutil.h>

namespace LL_SecureModule
{
	/// <summary>
	/// Digest data in a single part.
	/// </summary>
	void SMSession::Digest(DigestMechanism mechanism, array<Byte>^ plainData, array<Byte>^% digestData)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR plain_data = NULL;
		CK_ULONG plain_data_length = 0;

		CK_BYTE_PTR digest_data = NULL;
		CK_ULONG digest_data_length = 0;

		CK_MECHANISM digest_mechanism;

		try
		{
			// Input data validation check.
			if (plainData == nullptr) throw gcnew SecureModuleException("plainData is null.");

			// Set the Digest mechanism.
			digest_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			digest_mechanism.pParameter = NULL;
			digest_mechanism.parameterLen = 0;

			// Convert plain data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(plainData, &plain_data, &plain_data_length);

			// Initialize digesting operation with specific mechanism.
			rv = C_DigestInit(this->hSession, &digest_mechanism);

			if (rv == CKR_OK)
			{
				// Digest input data (plain_data) and get the output length (digest_data_length) to allocate the memory (This is a request for the digest length).
				rv = C_Digest(this->hSession, plain_data, plain_data_length, NULL, &digest_data_length);

				if (rv == CKR_OK)
				{
					// Allocate the output memory.
					digest_data = new CK_BYTE[digest_data_length];

					// Digest data and get the output.
					rv = C_Digest(this->hSession, plain_data, plain_data_length, digest_data, &digest_data_length);
				}
			}

			// Convert random_data from CK_BYTE_PTR to array<Byte>.
			Utils::ConvertCKBytePtrToByteArray(digest_data, digest_data_length, digestData);

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
		finally
		{
			// Deallocate memory of 'digest_data' and 'plain_data'.
			if (plain_data != NULL) delete[] plain_data;
			plain_data = NULL;
			plain_data_length = 0;

			if (digest_data != NULL) delete[] digest_data;
			digest_data = NULL;
			digest_data_length = 0;
		}
	}
}