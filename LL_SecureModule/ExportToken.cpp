#include "stdafx.h"

#include "Object.h"
#include "Utils.h"

#include <kmlib.h>

namespace LL_SecureModule
{
	/// <summary>
	/// This Function exports slot/token.
	/// </summary>
	void Cryptoki::ExportToken(SMSession^ session, array<Byte>^% tokenData)
	{
		CK_RV rv = CKR_OK;
		int i = 0;

		CK_BYTE_PTR token_data = 0;
		CK_ULONG token_data_len = NULL;

		CK_CHAR serialNumber[CK_SERIAL_NUMBER_SIZE] = { 0 };

		TokenInfo^ tokenInfo = nullptr;

		try
		{
			Cryptoki::GetTokenInfo(session->SlotID, tokenInfo);

			// Convert tokenInfo->serialNumber from String to char[CK_SERIAL_NUMBER_SIZE]
			for (i = 0; i < tokenInfo->serialNumber->Length; i++)
			{
				serialNumber[i] = (CK_CHAR)tokenInfo->serialNumber[i];
			}
			for (; i < CK_SERIAL_NUMBER_SIZE; i++)
			{
				serialNumber[i] = (CK_CHAR)' ';
			}

			// Import objects from file (output length prediction).
			rv = KM_ExportToken(session->SessionID, serialNumber, NULL, &token_data_len);
			if (rv == CKR_OK)
			{
				// memory allocation.
				token_data = new CK_BYTE[token_data_len];

				// Import objects from file.
				rv = KM_ExportToken(session->SessionID, serialNumber, token_data, &token_data_len);

				if (rv == CKR_OK)
				{
					// Convert token_data from CK_BYTE* to array of bytes.
					Utils::ConvertCKBytePtrToByteArray(token_data, token_data_len, tokenData);
				}
			}

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
			// Deallocate memory of 'token_data'.
			if (token_data != NULL) delete[] token_data;
			token_data = NULL;
			token_data_len = 0;
		}
	}

	/// <summary>
	/// This Function import slot/token.
	/// </summary>
	void Cryptoki::ImportToken(SMSession^ session, array<Byte>^ tokenData)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR token_data = 0;
		CK_ULONG token_data_len = NULL;

		try
		{
			// Input data validation check.
			if (tokenData == nullptr) throw gcnew SecureModuleException("tokenData is null.");

			// Convert tokenData from array of bytes to CK_BYTE*.
			Utils::ConvertByteArrayToCKBytePtr(tokenData, &token_data, &token_data_len);

			// Import objects from file.
			rv = KM_ImportToken(session->SessionID, token_data, token_data_len);

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
			// Deallocate memory of 'pszFileName'.
			if (token_data != NULL) delete[] token_data;
			token_data = NULL;
			token_data_len = 0;
		}
	}
}