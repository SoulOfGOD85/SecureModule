#include "stdafx.h"

#include "Object.h"
#include "Utils.h"

#include <ctutil.h>

namespace LL_SecureModule
{
	/// <summary>
	/// Calculate and return an AS2805 KCV (Key Check Value) for a key.
	/// <para>The key must be capable of doing an encryption operation using the supplied mechanism for this to succeed.</para>
	/// <para>Note that The CKA_CHECK_VALUE attribute can be used to get the KVC of a key that does not support the encryption operation.</para>
	/// </summary>
	void SMObject::CalculateKCV(array<Byte>^% kcv)
	{
		CK_RV rv = CKR_OK;

		const CK_SIZE kcv_data_length = 8;
		CK_BYTE kcv_data[kcv_data_length] = { 0 };

		CK_SIZE kcvlen = 0;

		try
		{
			rv = calcKvc(this->object_session->SessionID, this->hObject, kcv_data, kcv_data_length, &kcvlen);

			if (rv == CKR_OK)
			{
				// Convert kcv_data from CK_BYTE_PTR to array of byte.
				Utils::ConvertCKBytePtrToByteArray(kcv_data, kcvlen, kcv);
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
	}
}