#include "stdafx.h"

#include "LL_SecureModule.h"
#include "Mechanisms.h"
#include "Object.h"
#include "Utils.h"

namespace LL_SecureModule
{
	/// <summary>
	/// Signs data in a single part, where the signature is an appendix to the data.
	/// </summary>
	void SMObject::Sign(SignMechanism mechanism, Object^ parameter, array<Byte>^ data, array<Byte>^% signature)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR plain_data = NULL;
		CK_ULONG plain_data_length = 0;

		CK_BYTE_PTR signature_data = NULL;
		CK_ULONG signature_data_length = 0;

		CK_MECHANISM signing_mechanism;

		CK_MAC_GENERAL_PARAMS ck_mac_general_params;
		CK_RC2_MAC_GENERAL_PARAMS ck_rc2_mac_general_params;
		CK_RC2_PARAMS ck_rc2_params;
		CK_TIMESTAMP_PARAMS ck_timestamp_params;

		try
		{
			// Input data validation check.
			if (data == nullptr) throw gcnew SecureModuleException("data is null.");

			signing_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			signing_mechanism.pParameter = NULL;
			signing_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == SignMechanism::ARIA_MAC_GENERAL ||
					mechanism == SignMechanism::AES_MAC_GENERAL ||
					mechanism == SignMechanism::CAST128_MAC_GENERAL ||
					mechanism == SignMechanism::DES_MAC_GENERAL ||
					mechanism == SignMechanism::DES3_MAC_GENERAL ||
					mechanism == SignMechanism::IDEA_MAC_GENERAL ||
					mechanism == SignMechanism::MD2_HMAC_GENERAL ||
					mechanism == SignMechanism::MD5_HMAC_GENERAL ||
					mechanism == SignMechanism::SSL3_MD5_MAC ||
					mechanism == SignMechanism::SSL3_SHA1_MAC ||
					mechanism == SignMechanism::SHA_1_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA_224_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA_256_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA384_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA512_HMAC_GENERAL ||
					mechanism == SignMechanism::RIPEMD128_HMAC_GENERAL ||
					mechanism == SignMechanism::RIPEMD160_HMAC_GENERAL ||
					mechanism == SignMechanism::SEED_MAC_GENERAL ||
					mechanism == SignMechanism::DES3_X919_MAC_GENERAL)
				{
					MAC_GENERAL_PARAMS^ mac_general_params = gcnew MAC_GENERAL_PARAMS((MAC_GENERAL_PARAMS^)parameter);

					ck_mac_general_params = (CK_MAC_GENERAL_PARAMS)mac_general_params->lengthOfMAC;

					signing_mechanism.pParameter = &ck_mac_general_params;
					signing_mechanism.parameterLen = sizeof(ck_mac_general_params);
				}
				else if (mechanism == SignMechanism::RC2_MAC)
				{
					RC2_PARAMS^ rc2_params = gcnew RC2_PARAMS((RC2_PARAMS^)parameter);

					ck_rc2_params = (CK_RC2_PARAMS)rc2_params->effectiveBits;

					signing_mechanism.pParameter = &ck_rc2_params;
					signing_mechanism.parameterLen = sizeof(ck_rc2_params);
				}
				else if (mechanism == SignMechanism::RC2_MAC_GENERAL)
				{
					RC2_MAC_GENERAL_PARAMS^ rc2_mac_general_params = gcnew RC2_MAC_GENERAL_PARAMS((RC2_MAC_GENERAL_PARAMS^)parameter);

					ck_rc2_mac_general_params.effectiveBits = (CK_ULONG)rc2_mac_general_params->effectiveBits;
					ck_rc2_mac_general_params.macLength = (CK_ULONG)rc2_mac_general_params->macLength;

					signing_mechanism.pParameter = &ck_rc2_mac_general_params;
					signing_mechanism.parameterLen = sizeof(ck_rc2_mac_general_params);
				}
				else if (mechanism == SignMechanism::SHA1_RSA_PKCS_TIMESTAMP)
				{
					TIMESTAMP_PARAMS^ timestamp_params = gcnew TIMESTAMP_PARAMS((TIMESTAMP_PARAMS^)parameter);

					ck_timestamp_params.useMilliseconds = (CK_BBOOL)timestamp_params->useMilliseconds;
					ck_timestamp_params.timestampFormat = (CK_TIMESTAMP_FORMAT)timestamp_params->timestampFormat;

					signing_mechanism.pParameter = &ck_timestamp_params;
					signing_mechanism.parameterLen = sizeof(ck_timestamp_params);
				}
			}

			// Convert plain data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(data, &plain_data, &plain_data_length);

			rv = C_SignInit(this->object_session->SessionID, &signing_mechanism, this->hObject);

			if (rv == CKR_OK)
			{
				rv = C_Sign(this->object_session->SessionID, plain_data, plain_data_length, NULL, &signature_data_length);

				if (rv == CKR_OK)
				{
					signature_data = new CK_BYTE[signature_data_length];
					rv = C_Sign(this->object_session->SessionID, plain_data, plain_data_length, signature_data, &signature_data_length);

					if (rv == CKR_OK)
					{
						// Convert cipher_data from CK_BYTE_PTR to array of byte.
						Utils::ConvertCKBytePtrToByteArray(signature_data, signature_data_length, signature);
					}
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
			// Deallocate memory of 'plain_data', 'signature_data'.
			if (plain_data != NULL) delete[] plain_data;
			plain_data = NULL;
			plain_data_length = 0;

			if (signature_data != NULL) delete[] signature_data;
			signature_data = NULL;
			signature_data_length = 0;
		}
	}

	/// <summary>
	/// High Performance Sign data in a single part, where the signature is an appendix to the data.
	/// </summary>
	void SMObject::HighPerformanceSign(SignMechanism mechanism, Object^ parameter, array<Byte>^ data, array<Byte>^% signature)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR plain_data = NULL;
		CK_ULONG plain_data_length = 0;

		CK_BYTE signature_data[1024] = { NULL };
		CK_ULONG signature_data_length = 1024;

		CK_MECHANISM signing_mechanism;

		CK_MAC_GENERAL_PARAMS ck_mac_general_params;
		CK_RC2_MAC_GENERAL_PARAMS ck_rc2_mac_general_params;
		CK_RC2_PARAMS ck_rc2_params;
		CK_TIMESTAMP_PARAMS ck_timestamp_params;

		try
		{
			// Input data validation check.
			if (data == nullptr) throw gcnew SecureModuleException("data is null.");

			signing_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			signing_mechanism.pParameter = NULL;
			signing_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == SignMechanism::ARIA_MAC_GENERAL ||
					mechanism == SignMechanism::AES_MAC_GENERAL ||
					mechanism == SignMechanism::CAST128_MAC_GENERAL ||
					mechanism == SignMechanism::DES_MAC_GENERAL ||
					mechanism == SignMechanism::DES3_MAC_GENERAL ||
					mechanism == SignMechanism::IDEA_MAC_GENERAL ||
					mechanism == SignMechanism::MD2_HMAC_GENERAL ||
					mechanism == SignMechanism::MD5_HMAC_GENERAL ||
					mechanism == SignMechanism::SSL3_MD5_MAC ||
					mechanism == SignMechanism::SSL3_SHA1_MAC ||
					mechanism == SignMechanism::SHA_1_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA_224_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA_256_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA384_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA512_HMAC_GENERAL ||
					mechanism == SignMechanism::RIPEMD128_HMAC_GENERAL ||
					mechanism == SignMechanism::RIPEMD160_HMAC_GENERAL ||
					mechanism == SignMechanism::SEED_MAC_GENERAL ||
					mechanism == SignMechanism::DES3_X919_MAC_GENERAL)
				{
					MAC_GENERAL_PARAMS^ mac_general_params = gcnew MAC_GENERAL_PARAMS((MAC_GENERAL_PARAMS^)parameter);

					ck_mac_general_params = (CK_MAC_GENERAL_PARAMS)mac_general_params->lengthOfMAC;

					signing_mechanism.pParameter = &ck_mac_general_params;
					signing_mechanism.parameterLen = sizeof(ck_mac_general_params);
				}
				else if (mechanism == SignMechanism::RC2_MAC)
				{
					RC2_PARAMS^ rc2_params = gcnew RC2_PARAMS((RC2_PARAMS^)parameter);

					ck_rc2_params = (CK_RC2_PARAMS)rc2_params->effectiveBits;

					signing_mechanism.pParameter = &ck_rc2_params;
					signing_mechanism.parameterLen = sizeof(ck_rc2_params);
				}
				else if (mechanism == SignMechanism::RC2_MAC_GENERAL)
				{
					RC2_MAC_GENERAL_PARAMS^ rc2_mac_general_params = gcnew RC2_MAC_GENERAL_PARAMS((RC2_MAC_GENERAL_PARAMS^)parameter);

					ck_rc2_mac_general_params.effectiveBits = (CK_ULONG)rc2_mac_general_params->effectiveBits;
					ck_rc2_mac_general_params.macLength = (CK_ULONG)rc2_mac_general_params->macLength;

					signing_mechanism.pParameter = &ck_rc2_mac_general_params;
					signing_mechanism.parameterLen = sizeof(ck_rc2_mac_general_params);
				}
				else if (mechanism == SignMechanism::SHA1_RSA_PKCS_TIMESTAMP)
				{
					TIMESTAMP_PARAMS^ timestamp_params = gcnew TIMESTAMP_PARAMS((TIMESTAMP_PARAMS^)parameter);

					ck_timestamp_params.useMilliseconds = (CK_BBOOL)timestamp_params->useMilliseconds;
					ck_timestamp_params.timestampFormat = (CK_TIMESTAMP_FORMAT)timestamp_params->timestampFormat;

					signing_mechanism.pParameter = &ck_timestamp_params;
					signing_mechanism.parameterLen = sizeof(ck_timestamp_params);
				}
			}

			// Convert plain data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(data, &plain_data, &plain_data_length);

			rv = C_SignInit(this->object_session->SessionID, &signing_mechanism, this->hObject);

			if (rv == CKR_OK)
			{
				rv = C_Sign(this->object_session->SessionID, plain_data, plain_data_length, signature_data, &signature_data_length);

				if (rv == CKR_OK)
				{
					// Convert cipher_data from CK_BYTE_PTR to array of byte.
					Utils::ConvertCKBytePtrToByteArray(signature_data, signature_data_length, signature);
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
			// Deallocate memory of 'plain_data', 'signature_data'.
			if (plain_data != NULL) delete[] plain_data;
			plain_data = NULL;
			plain_data_length = 0;

			signature_data_length = 0;
		}
	}

	/// <summary>
	/// Signs data in a single operation, where the data can be recovered from the signature.
	/// </summary>
	void SMObject::SignRecover(SignRecoverMechanism mechanism, Object^ parameter, array<Byte>^ data, array<Byte>^% signature)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR plain_data = NULL;
		CK_ULONG plain_data_length = 0;

		CK_BYTE_PTR signature_data = NULL;
		CK_ULONG signature_data_length = 0;

		CK_MECHANISM signing_mechanism;

		CK_TIMESTAMP_PARAMS ck_timestamp_params;

		try
		{
			// Input data validation check.
			if (data == nullptr) throw gcnew SecureModuleException("data is null.");

			signing_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			signing_mechanism.pParameter = NULL;
			signing_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == SignRecoverMechanism::SHA1_RSA_PKCS_TIMESTAMP)
				{
					TIMESTAMP_PARAMS^ timestamp_params = gcnew TIMESTAMP_PARAMS((TIMESTAMP_PARAMS^)parameter);

					ck_timestamp_params.useMilliseconds = (CK_BBOOL)timestamp_params->useMilliseconds;
					ck_timestamp_params.timestampFormat = (CK_TIMESTAMP_FORMAT)timestamp_params->timestampFormat;

					signing_mechanism.pParameter = &ck_timestamp_params;
					signing_mechanism.parameterLen = sizeof(ck_timestamp_params);
				}
			}

			// Convert plain data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(data, &plain_data, &plain_data_length);

			rv = C_SignRecoverInit(this->object_session->SessionID, &signing_mechanism, this->hObject);

			if (rv == CKR_OK)
			{
				rv = C_SignRecover(this->object_session->SessionID, plain_data, plain_data_length, NULL, &signature_data_length);

				if (rv == CKR_OK)
				{
					signature_data = new CK_BYTE[signature_data_length];
					rv = C_SignRecover(this->object_session->SessionID, plain_data, plain_data_length, signature_data, &signature_data_length);

					if (rv == CKR_OK)
					{
						// Convert cipher_data from CK_BYTE_PTR to array of byte.
						Utils::ConvertCKBytePtrToByteArray(signature_data, signature_data_length, signature);
					}
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
			// Deallocate memory of 'plain_data', 'signature_data'.
			if (plain_data != NULL) delete[] plain_data;
			plain_data = NULL;
			plain_data_length = 0;

			if (signature_data != NULL) delete[] signature_data;
			signature_data = NULL;
			signature_data_length = 0;
		}
	}

	/// <summary>
	/// Verifies a signature in a single-part operation, where the signature is an appendix to the data.
	/// </summary>
	Boolean SMObject::Verify(SignMechanism mechanism, Object^ parameter, array<Byte>^ data, array<Byte>^ signature)
	{
		CK_RV rv = CKR_OK;
		Boolean result = false;

		CK_BYTE_PTR plain_data = NULL;
		CK_ULONG plain_data_length = 0;

		CK_BYTE_PTR signature_data = NULL;
		CK_ULONG signature_data_length = 0;

		CK_MECHANISM verification_mechanism;

		CK_MAC_GENERAL_PARAMS ck_mac_general_params;
		CK_RC2_MAC_GENERAL_PARAMS ck_rc2_mac_general_params;
		CK_RC2_PARAMS ck_rc2_params;
		CK_TIMESTAMP_PARAMS ck_timestamp_params;

		try
		{
			// Input data validation check.
			if (data == nullptr) throw gcnew SecureModuleException("data is null.");
			if (signature == nullptr) throw gcnew SecureModuleException("signature is null.");

			verification_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			verification_mechanism.pParameter = NULL;
			verification_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == SignMechanism::ARIA_MAC_GENERAL ||
					mechanism == SignMechanism::AES_MAC_GENERAL ||
					mechanism == SignMechanism::CAST128_MAC_GENERAL ||
					mechanism == SignMechanism::DES_MAC_GENERAL ||
					mechanism == SignMechanism::DES3_MAC_GENERAL ||
					mechanism == SignMechanism::IDEA_MAC_GENERAL ||
					mechanism == SignMechanism::MD2_HMAC_GENERAL ||
					mechanism == SignMechanism::MD5_HMAC_GENERAL ||
					mechanism == SignMechanism::SSL3_MD5_MAC ||
					mechanism == SignMechanism::SSL3_SHA1_MAC ||
					mechanism == SignMechanism::SHA_1_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA_224_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA_256_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA384_HMAC_GENERAL ||
					mechanism == SignMechanism::SHA512_HMAC_GENERAL ||
					mechanism == SignMechanism::RIPEMD128_HMAC_GENERAL ||
					mechanism == SignMechanism::RIPEMD160_HMAC_GENERAL ||
					mechanism == SignMechanism::SEED_MAC_GENERAL ||
					mechanism == SignMechanism::DES3_X919_MAC_GENERAL)
				{
					MAC_GENERAL_PARAMS^ mac_general_params = gcnew MAC_GENERAL_PARAMS((MAC_GENERAL_PARAMS^)parameter);

					ck_mac_general_params = (CK_MAC_GENERAL_PARAMS)mac_general_params->lengthOfMAC;

					verification_mechanism.pParameter = &ck_mac_general_params;
					verification_mechanism.parameterLen = sizeof(ck_mac_general_params);
				}
				else if (mechanism == SignMechanism::RC2_MAC)
				{
					RC2_PARAMS^ rc2_params = gcnew RC2_PARAMS((RC2_PARAMS^)parameter);

					ck_rc2_params = (CK_RC2_PARAMS)rc2_params->effectiveBits;

					verification_mechanism.pParameter = &ck_rc2_params;
					verification_mechanism.parameterLen = sizeof(ck_rc2_params);
				}
				else if (mechanism == SignMechanism::RC2_MAC_GENERAL)
				{
					RC2_MAC_GENERAL_PARAMS^ rc2_mac_general_params = gcnew RC2_MAC_GENERAL_PARAMS((RC2_MAC_GENERAL_PARAMS^)parameter);

					ck_rc2_mac_general_params.effectiveBits = (CK_ULONG)rc2_mac_general_params->effectiveBits;
					ck_rc2_mac_general_params.macLength = (CK_ULONG)rc2_mac_general_params->macLength;

					verification_mechanism.pParameter = &ck_rc2_mac_general_params;
					verification_mechanism.parameterLen = sizeof(ck_rc2_mac_general_params);
				}
				else if (mechanism == SignMechanism::SHA1_RSA_PKCS_TIMESTAMP)
				{
					TIMESTAMP_PARAMS^ timestamp_params = gcnew TIMESTAMP_PARAMS((TIMESTAMP_PARAMS^)parameter);

					ck_timestamp_params.useMilliseconds = (CK_BBOOL)timestamp_params->useMilliseconds;
					ck_timestamp_params.timestampFormat = (CK_TIMESTAMP_FORMAT)timestamp_params->timestampFormat;

					verification_mechanism.pParameter = &ck_timestamp_params;
					verification_mechanism.parameterLen = sizeof(ck_timestamp_params);
				}
			}

			// Convert plain data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(data, &plain_data, &plain_data_length);

			// Convert signature from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(signature, &signature_data, &signature_data_length);

			rv = C_VerifyInit(this->object_session->SessionID, &verification_mechanism, this->hObject);

			if (rv == CKR_OK)
			{
				rv = C_Verify(this->object_session->SessionID, plain_data, plain_data_length, signature_data, signature_data_length);

				// Check the verification result.
				if (rv == CKR_OK)
				{
					result = true;
				}
				else if (rv == CKR_SIGNATURE_INVALID)
				{
					result = false;
				}
				else
				{
					throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
				}
			}
			else
			{
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
			}

			return result;
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
			// Deallocate memory of 'plain_data', 'signature_data'.
			if (plain_data != NULL) delete[] plain_data;
			plain_data = NULL;
			plain_data_length = 0;

			if (signature_data != NULL) delete[] signature_data;
			signature_data = NULL;
			signature_data_length = 0;
		}
	}

	/// <summary>
	/// Verifies a signature in a single-part operation, where the data is recovered from the signature.
	/// </summary>
	void SMObject::VerifyRecover(SignRecoverMechanism mechanism, Object^ parameter, array<Byte>^ signature, array<Byte>^% data)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR plain_data = NULL;
		CK_ULONG plain_data_length = 0;

		CK_BYTE_PTR signature_data = NULL;
		CK_ULONG signature_data_length = 0;

		CK_TIMESTAMP_PARAMS ck_timestamp_params;

		CK_MECHANISM verification_mechanism;

		try
		{
			// Input data validation check.
			if (signature == nullptr) throw gcnew SecureModuleException("signature is null.");

			verification_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			verification_mechanism.pParameter = NULL;
			verification_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == SignRecoverMechanism::SHA1_RSA_PKCS_TIMESTAMP)
				{
					TIMESTAMP_PARAMS^ timestamp_params = gcnew TIMESTAMP_PARAMS((TIMESTAMP_PARAMS^)parameter);

					ck_timestamp_params.useMilliseconds = (CK_BBOOL)timestamp_params->useMilliseconds;
					ck_timestamp_params.timestampFormat = (CK_TIMESTAMP_FORMAT)timestamp_params->timestampFormat;

					verification_mechanism.pParameter = &ck_timestamp_params;
					verification_mechanism.parameterLen = sizeof(ck_timestamp_params);
				}
			}

			// Convert signature from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(signature, &signature_data, &signature_data_length);

			rv = C_VerifyRecoverInit(this->object_session->SessionID, &verification_mechanism, this->hObject);
			if (rv == CKR_OK)
			{
				rv = C_VerifyRecover(this->object_session->SessionID, signature_data, signature_data_length, NULL, &plain_data_length);

				// Check the verification result.
				if (rv == CKR_OK)
				{
					plain_data = new CK_BYTE[plain_data_length];
					rv = C_VerifyRecover(this->object_session->SessionID, signature_data, signature_data_length, plain_data, &plain_data_length);

					if (rv == CKR_OK)
					{
						// Convert cipher_data from CK_BYTE_PTR to array of byte.
						Utils::ConvertCKBytePtrToByteArray(plain_data, plain_data_length, data);
					}
				}
			}

			if (rv != CKR_OK)
			{
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
			}
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
			// Deallocate memory of 'plain_data', 'signature_data'.
			if (plain_data != NULL) delete[] plain_data;
			plain_data = NULL;
			plain_data_length = 0;

			if (signature_data != NULL) delete[] signature_data;
			signature_data = NULL;
			signature_data_length = 0;
		}
	}
}