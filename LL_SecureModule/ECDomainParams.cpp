#include "stdafx.h"

#include "LL_SecureModule.h"
#include "Utils.h"

#include <ctutil.h>

namespace LL_SecureModule
{
	/// <summary>
	/// This Function Encode elliptic curve domain parameters over Fp.
	/// </summary>
	void Cryptoki::EncodeECParamsP(array<Byte>^ prime, array<Byte>^ curveA, array<Byte>^ curveB, array<Byte>^ curveSeed, array<Byte>^ baseX, array<Byte>^ baseY, array<Byte>^ bpOrder, array<Byte>^ cofactor, array<Byte>^% result)
	{
		CK_RV rv = CKR_OK;

		// ECC Domain Params
		CK_BYTE_PTR prime_data = NULL;
		CK_ULONG prime_data_len = 0;
		CK_BYTE_PTR curveA_data = NULL;
		CK_ULONG curveA_data_len = 0;
		CK_BYTE_PTR curveB_data = NULL;
		CK_ULONG curveB_data_len = 0;
		CK_BYTE_PTR curveSeed_data = NULL;
		CK_ULONG curveSeed_data_len = 0;
		CK_BYTE_PTR baseX_data = NULL;
		CK_ULONG baseX_data_len = 0;
		CK_BYTE_PTR baseY_data = NULL;
		CK_ULONG baseY_data_len = 0;
		CK_BYTE_PTR bpOrder_data = NULL;
		CK_ULONG bpOrder_data_len = 0;
		CK_BYTE_PTR cofactor_data = NULL;
		CK_ULONG cofactor_data_len = 0;

		CK_BYTE_PTR result_data = NULL;
		CK_ULONG result_data_len = 0;
		//

		try
		{
			// Input data validation check.
			if (prime == nullptr) throw gcnew SecureModuleException("prime is null.");
			if (curveA == nullptr) throw gcnew SecureModuleException("curveA is null.");
			if (curveB == nullptr) throw gcnew SecureModuleException("curveB is null.");
			if (baseX == nullptr) throw gcnew SecureModuleException("baseX is null.");
			if (baseY == nullptr) throw gcnew SecureModuleException("baseY is null.");
			if (bpOrder == nullptr) throw gcnew SecureModuleException("bpOrder is null.");
			if (cofactor == nullptr) throw gcnew SecureModuleException("cofactor is null.");

			// Convert prime from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(prime, &prime_data, &prime_data_len);

			// Convert curveA from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(curveA, &curveA_data, &curveA_data_len);

			// Convert curveB from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(curveB, &curveB_data, &curveB_data_len);

			if (curveSeed != nullptr)
			{
				// Convert curveB from array of byte to CK_BYTE_PTR.
				Utils::ConvertByteArrayToCKBytePtr(curveSeed, &curveSeed_data, &curveSeed_data_len);
			}

			// Convert baseX from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(baseX, &baseX_data, &baseX_data_len);

			// Convert baseY from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(baseY, &baseY_data, &baseY_data_len);

			// Convert bpOrder from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(bpOrder, &bpOrder_data, &bpOrder_data_len);

			// Convert cofactor from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(cofactor, &cofactor_data, &cofactor_data_len);

			// Elliptic Curve Domain Parameter over Fp
			rv = KM_EncodeECParamsP(prime_data, prime_data_len, curveA_data, curveA_data_len, curveB_data, curveB_data_len, curveSeed_data, curveSeed_data_len, baseX_data, baseX_data_len, baseY_data, baseY_data_len, bpOrder_data, bpOrder_data_len, cofactor_data, cofactor_data_len, NULL, &result_data_len);

			if (rv == CKR_OK)
			{
				result_data = new CK_BYTE[result_data_len];

				// Elliptic Curve Domain Parameter over Fp
				rv = KM_EncodeECParamsP(prime_data, prime_data_len, curveA_data, curveA_data_len, curveB_data, curveB_data_len, curveSeed_data, curveSeed_data_len, baseX_data, baseX_data_len, baseY_data, baseY_data_len, bpOrder_data, bpOrder_data_len, cofactor_data, cofactor_data_len, result_data, &result_data_len);
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
			{
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
			}

			// Convert result_data from CK_BYTE_PTR to array of byte.
			Utils::ConvertCKBytePtrToByteArray(result_data, result_data_len, result);
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
			// Deallocate memory for 'prime_data', 'curveA_data', 'curveB_data', 'curveSeed_data', 'baseX_data', 'baseY_data', 'bpOrder_data', 'cofactor_data' and 'result_data'.
			if (prime_data != NULL) delete[] prime_data;
			prime_data = NULL;
			prime_data_len = 0;

			if (curveA_data != NULL) delete[] curveA_data;
			curveA_data = NULL;
			curveA_data_len = 0;

			if (curveB_data != NULL) delete[] curveB_data;
			curveB_data = NULL;
			curveB_data_len = 0;

			if (curveSeed_data != NULL) delete[] curveSeed_data;
			curveSeed_data = NULL;
			curveSeed_data_len = 0;

			if (baseX_data != NULL) delete[] baseX_data;
			baseX_data = NULL;
			baseX_data_len = 0;

			if (baseY_data != NULL) delete[] baseY_data;
			baseY_data = NULL;
			baseY_data_len = 0;

			if (bpOrder_data != NULL) delete[] bpOrder_data;
			bpOrder_data = NULL;
			bpOrder_data_len = 0;

			if (cofactor_data != NULL) delete[] cofactor_data;
			cofactor_data = NULL;
			cofactor_data_len = 0;

			if (result_data != NULL) delete[] result_data;
			result_data = NULL;
			result_data_len = 0;
		}
	}

	/// <summary>
	/// This Function Encode elliptic curve domain parameters over F2^m.
	/// <para>Do DER enc of ECC Domain Parameters 2^M</para>
	/// <para>All long integer values are variable length big endian numbers with optional leading zeros, lengths are all in bytes.</para>
	/// </summary>
	void Cryptoki::EncodeECParams2M(UInt32 m, ECBasis basis, array<UInt32>^ parameters, array<Byte>^ curveA, array<Byte>^ curveB, array<Byte>^ curveSeed, array<Byte>^ baseX, array<Byte>^ baseY, array<Byte>^ bpOrder, array<Byte>^ cofactor, array<Byte>^% result)
	{
		CK_RV rv = CKR_OK;

		// ECC Domain Params
		CK_SIZE parameters_data[3] = { 0 };
		ECBasisType ECBasis = (ECBasisType)basis;
		CK_BYTE_PTR curveA_data = NULL;
		CK_ULONG curveA_data_len = 0;
		CK_BYTE_PTR curveB_data = NULL;
		CK_ULONG curveB_data_len = 0;
		CK_BYTE_PTR curveSeed_data = NULL;
		CK_ULONG curveSeed_data_len = 0;
		CK_BYTE_PTR baseX_data = NULL;
		CK_ULONG baseX_data_len = 0;
		CK_BYTE_PTR baseY_data = NULL;
		CK_ULONG baseY_data_len = 0;
		CK_BYTE_PTR bpOrder_data = NULL;
		CK_ULONG bpOrder_data_len = 0;
		CK_BYTE_PTR cofactor_data = NULL;
		CK_ULONG cofactor_data_len = 0;

		CK_BYTE_PTR result_data = NULL;
		CK_ULONG result_data_len = 0;
		//

		try
		{
			// Input data validation check.
			if (parameters == nullptr) throw gcnew SecureModuleException("curveA is null.");
			if (parameters->Length != 3) throw gcnew SecureModuleException("parameters length is != 3.");
			if (curveA == nullptr) throw gcnew SecureModuleException("curveA is null.");
			if (curveB == nullptr) throw gcnew SecureModuleException("curveB is null.");
			if (baseX == nullptr) throw gcnew SecureModuleException("baseX is null.");
			if (baseY == nullptr) throw gcnew SecureModuleException("baseY is null.");
			if (bpOrder == nullptr) throw gcnew SecureModuleException("bpOrder is null.");
			if (cofactor == nullptr) throw gcnew SecureModuleException("cofactor is null.");

			// Convert parameters array of CK_SIZE.
			parameters_data[0] = (CK_SIZE)parameters[0];
			parameters_data[1] = (CK_SIZE)parameters[1];
			parameters_data[2] = (CK_SIZE)parameters[2];

			// Convert curveA from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(curveA, &curveA_data, &curveA_data_len);

			// Convert curveB from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(curveB, &curveB_data, &curveB_data_len);

			if (curveSeed != nullptr)
			{
				// Convert curveB from array of byte to CK_BYTE_PTR.
				Utils::ConvertByteArrayToCKBytePtr(curveSeed, &curveSeed_data, &curveSeed_data_len);
			}

			// Convert baseX from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(baseX, &baseX_data, &baseX_data_len);

			// Convert baseY from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(baseY, &baseY_data, &baseY_data_len);

			// Convert bpOrder from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(bpOrder, &bpOrder_data, &bpOrder_data_len);

			// Convert cofactor from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(cofactor, &cofactor_data, &cofactor_data_len);

			// Elliptic Curve Domain Parameter over F2^m
			rv = KM_EncodeECParams2M((CK_SIZE)m, ECBasis, parameters_data, curveA_data, curveA_data_len, curveB_data, curveB_data_len, curveSeed_data, curveSeed_data_len, baseX_data, baseX_data_len, baseY_data, baseY_data_len, bpOrder_data, bpOrder_data_len, cofactor_data, cofactor_data_len, NULL, &result_data_len);

			if (rv == CKR_OK)
			{
				result_data = new CK_BYTE[result_data_len];

				// Elliptic Curve Domain Parameter over F2^m
				rv = KM_EncodeECParams2M((CK_SIZE)m, ECBasis, parameters_data, curveA_data, curveA_data_len, curveB_data, curveB_data_len, curveSeed_data, curveSeed_data_len, baseX_data, baseX_data_len, baseY_data, baseY_data_len, bpOrder_data, bpOrder_data_len, cofactor_data, cofactor_data_len, result_data, &result_data_len);
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
			{
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
			}

			// Convert result_data from CK_BYTE_PTR to array of byte.
			Utils::ConvertCKBytePtrToByteArray(result_data, result_data_len, result);
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
			// Deallocate memory for 'curveA_data', 'curveB_data', 'curveSeed_data', 'baseX_data', 'baseY_data', 'bpOrder_data', 'cofactor_data' and 'result_data'
			if (curveA_data != NULL) delete[] curveA_data;
			curveA_data = NULL;
			curveA_data_len = 0;

			if (curveB_data != NULL) delete[] curveB_data;
			curveB_data = NULL;
			curveB_data_len = 0;

			if (curveSeed_data != NULL) delete[] curveSeed_data;
			curveSeed_data = NULL;
			curveSeed_data_len = 0;

			if (baseX_data != NULL) delete[] baseX_data;
			baseX_data = NULL;
			baseX_data_len = 0;

			if (baseY_data != NULL) delete[] baseY_data;
			baseY_data = NULL;
			baseY_data_len = 0;

			if (bpOrder_data != NULL) delete[] bpOrder_data;
			bpOrder_data = NULL;
			bpOrder_data_len = 0;

			if (cofactor_data != NULL) delete[] cofactor_data;
			cofactor_data = NULL;
			cofactor_data_len = 0;

			if (result_data != NULL) delete[] result_data;
			result_data = NULL;
			result_data_len = 0;
		}
	}

	/// <summary>
	/// This function provides the DER encoding of a supported named curve.
	/// <para>This function is typically used to populate the CKA_EC_PARAMS attribute of the template used during EC key pair generation.</para>
	/// </summary>
	void Cryptoki::DerEncodeNamedCurve(CurveName curve, array<Byte>^% dp)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR dp_data = NULL;
		CK_ULONG dp_data_len = 0;

		char* name = NULL;
		unsigned int name_len = 0;
		//

		try
		{
			// Convert curve type from String to char*.
			Utils::ConvertStringToCharPtr(curve.ToString(), &name, &name_len);

			// Der Encoding Elliptic Curve Domain Parameter
			rv = CT_DerEncodeNamedCurve(NULL, &dp_data_len, name);

			if (rv == CKR_OK)
			{
				dp_data = new CK_BYTE[dp_data_len];

				// Der Encoding Elliptic Curve Domain Parameter
				rv = CT_DerEncodeNamedCurve(dp_data, &dp_data_len, name);
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
			{
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
			}

			// Convert dp_data from CK_BYTE_PTR to array of byte.
			Utils::ConvertCKBytePtrToByteArray(dp_data, dp_data_len, dp);
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
			// Deallocate memory for 'dp_data'.
			if (dp_data != NULL) delete[] dp_data;
			dp_data = NULL;
			dp_data_len = 0;
		}
	}
};