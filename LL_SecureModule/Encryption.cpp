#include "stdafx.h"

#include "Mechanisms.h"
#include "Object.h"
#include "Utils.h"

namespace LL_SecureModule
{
	/// <summary>
	/// Encrypts single-part data.
	/// </summary>
	void SMObject::Encrypt(EncryptionMechanism mechanism, Object^ parameter, array<Byte>^ plainData, array<Byte>^% cipherData)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR plain_data = NULL;
		CK_ULONG plain_data_length = 0;

		CK_BYTE_PTR cipher_data = NULL;
		CK_ULONG cipher_data_length = 0;

		CK_BYTE_PTR source_data = NULL;
		CK_ULONG source_data_length = 0;

		CK_BYTE_PTR shared_data_1 = NULL;
		CK_ULONG shared_data_1_length = 0;

		CK_BYTE_PTR shared_data_2 = NULL;
		CK_ULONG shared_data_2_length = 0;

		CK_BYTE_PTR iv_data = NULL;
		CK_ULONG iv_data_length = 0;

		CK_MECHANISM encryption_mechanism;

		CK_RSA_PKCS_OAEP_PARAMS ck_oaep_param;

		CK_RC2_PARAMS ck_rc2_param;

		CK_RC2_CBC_PARAMS ck_rc2_cbc_param;

		CK_ECIES_PARAMS ck_ecies_param;

		array<Byte>^ iv = nullptr;

		try
		{
			// Input data validation check.
			if (plainData == nullptr) throw gcnew SecureModuleException("plainData is null.");

			encryption_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			encryption_mechanism.pParameter = NULL;
			encryption_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == EncryptionMechanism::RSA_PKCS_OAEP)
				{
					RSA_PKCS_OAEP_PARAMS^ oaep_params = gcnew RSA_PKCS_OAEP_PARAMS((RSA_PKCS_OAEP_PARAMS^)parameter);

					// Convert source data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(oaep_params->sourceData, &source_data, &source_data_length);

					ck_oaep_param.hashAlg = (CK_MECHANISM_TYPE)oaep_params->hashAlg;
					ck_oaep_param.mgf = oaep_params->MGF;
					ck_oaep_param.source = 0;
					ck_oaep_param.pSourceData = NULL;
					ck_oaep_param.sourceDataLen = 0;
					if (oaep_params->sourceType)
					{
						ck_oaep_param.source = CKZ_DATA_SPECIFIED;
						ck_oaep_param.pSourceData = source_data;
						ck_oaep_param.sourceDataLen = source_data_length;
					}

					encryption_mechanism.pParameter = &ck_oaep_param;
					encryption_mechanism.parameterLen = sizeof(ck_oaep_param);
				}
				else if (mechanism == EncryptionMechanism::RC2_ECB || mechanism == EncryptionMechanism::RC2_ECB_PAD)
				{
					RC2_PARAMS^ rc2_params = gcnew RC2_PARAMS((RC2_PARAMS^)parameter);
					ck_rc2_param = (CK_RC2_PARAMS)rc2_params->effectiveBits;

					encryption_mechanism.pParameter = &ck_rc2_param;
					encryption_mechanism.parameterLen = sizeof(ck_rc2_param);
				}
				else if (mechanism == EncryptionMechanism::RC2_CBC || mechanism == EncryptionMechanism::RC2_CBC_PAD)
				{
					RC2_CBC_PARAMS^ rc2_cbc_params = gcnew RC2_CBC_PARAMS((RC2_CBC_PARAMS^)parameter);
					ck_rc2_cbc_param.effectiveBits = (CK_ULONG)rc2_cbc_params->effectiveBits;

					// Convert iv from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(rc2_cbc_params->iv, &iv_data, &iv_data_length);

					for (unsigned int i = 0; i < iv_data_length; i++)
					{
						ck_rc2_cbc_param.iv[i] = iv_data[i];
					}

					encryption_mechanism.pParameter = &ck_rc2_cbc_param;
					encryption_mechanism.parameterLen = sizeof(ck_rc2_cbc_param);
				}
				else if (mechanism == EncryptionMechanism::ECIES)
				{
					ECIES_PARAMS^ ecies_params = gcnew ECIES_PARAMS((ECIES_PARAMS^)parameter);
					ck_ecies_param.ulEncKeyLenInBits = (CK_ULONG)ecies_params->encKeyLenInBits;
					ck_ecies_param.ulMacKeyLenInBits = (CK_ULONG)ecies_params->macKeyLenInBits;
					ck_ecies_param.ulMacLenInBits = (CK_ULONG)ecies_params->macLenInBits;
					ck_ecies_param.dhPrimitive = (CK_EC_DH_PRIMITIVE)ecies_params->dhPrimitive;
					ck_ecies_param.kdf = (CK_EC_KDF_TYPE)ecies_params->kdf;
					ck_ecies_param.encScheme = (CK_EC_ENC_SCHEME)ecies_params->encScheme;
					ck_ecies_param.macScheme = (CK_EC_MAC_SCHEME)ecies_params->macScheme;

					// Convert shared data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(ecies_params->sharedData1, &shared_data_1, &shared_data_1_length);
					Utils::ConvertByteArrayToCKBytePtr(ecies_params->sharedData2, &shared_data_2, &shared_data_2_length);

					ck_ecies_param.pSharedData1 = shared_data_1;
					ck_ecies_param.ulSharedDataLen1 = shared_data_1_length;

					ck_ecies_param.pSharedData2 = shared_data_2;
					ck_ecies_param.ulSharedDataLen2 = shared_data_2_length;

					encryption_mechanism.pParameter = &ck_ecies_param;
					encryption_mechanism.parameterLen = sizeof(ck_ecies_param);
				}
				else
				{
					iv = gcnew array<Byte>(((array<Byte>^)parameter)->Length);
					for (int i = 0; i < iv->Length; i++)
					{
						iv[i] = ((array<Byte>^)parameter)[i];
					}

					// Convert iv data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(iv, &iv_data, &iv_data_length);

					encryption_mechanism.pParameter = iv_data;
					encryption_mechanism.parameterLen = iv_data_length;
				}
			}

			// Convert plain data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(plainData, &plain_data, &plain_data_length);

			rv = C_EncryptInit(this->object_session->SessionID, &encryption_mechanism, this->hObject);

			if (rv == CKR_OK)
			{
				rv = C_Encrypt(this->object_session->SessionID, plain_data, plain_data_length, NULL, &cipher_data_length);

				if (rv == CKR_OK)
				{
					cipher_data = new CK_BYTE[cipher_data_length];
					rv = C_Encrypt(this->object_session->SessionID, plain_data, plain_data_length, cipher_data, &cipher_data_length);

					if (rv == CKR_OK)
					{
						// Convert cipher_data from CK_BYTE_PTR to array of byte.
						Utils::ConvertCKBytePtrToByteArray(cipher_data, cipher_data_length, cipherData);
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
			// Deallocate memory of 'plain_data', 'source_data', 'shared_data_1', 'shared_data_2', 'iv_data'  and 'cipher_data'.
			if (plain_data != NULL) delete[] plain_data;
			plain_data = NULL;
			plain_data_length = 0;

			if (source_data != NULL) delete[] source_data;
			source_data = NULL;
			source_data_length = 0;

			if (shared_data_1 != NULL) delete[] shared_data_1;
			shared_data_1 = NULL;
			shared_data_1_length = 0;

			if (shared_data_2 != NULL) delete[] shared_data_2;
			shared_data_2 = NULL;
			shared_data_2_length = 0;

			if (iv_data != NULL) delete[] iv_data;
			iv_data = NULL;
			iv_data_length = 0;

			if (cipher_data != NULL) delete[] cipher_data;
			cipher_data = NULL;
			cipher_data_length = 0;
		}
	}

	/// <summary>
	/// Decrypts single-part data.
	/// </summary>
	void SMObject::Decrypt(EncryptionMechanism mechanism, Object^ parameter, array<Byte>^ cipherData, array<Byte>^% plainData)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR plain_data = NULL;
		CK_ULONG plain_data_length = 0;

		CK_BYTE_PTR cipher_data = NULL;
		CK_ULONG cipher_data_length = 0;

		CK_BYTE_PTR source_data = NULL;
		CK_ULONG source_data_length = 0;

		CK_BYTE_PTR shared_data_1 = NULL;
		CK_ULONG shared_data_1_length = 0;

		CK_BYTE_PTR shared_data_2 = NULL;
		CK_ULONG shared_data_2_length = 0;

		CK_BYTE_PTR iv_data = NULL;
		CK_ULONG iv_data_length = 0;

		CK_MECHANISM decryption_mechanism;

		CK_RSA_PKCS_OAEP_PARAMS ck_oaep_param;

		CK_RC2_PARAMS ck_rc2_param;

		CK_RC2_CBC_PARAMS ck_rc2_cbc_param;

		CK_ECIES_PARAMS ck_ecies_param;

		array<Byte>^ iv = nullptr;

		try
		{
			// Input data validation check.
			if (cipherData == nullptr) throw gcnew SecureModuleException("cipherData is null.");

			decryption_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			decryption_mechanism.pParameter = NULL;
			decryption_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == EncryptionMechanism::RSA_PKCS_OAEP)
				{
					RSA_PKCS_OAEP_PARAMS^ oaep_params = gcnew RSA_PKCS_OAEP_PARAMS((RSA_PKCS_OAEP_PARAMS^)parameter);

					// Convert source data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(oaep_params->sourceData, &source_data, &source_data_length);

					ck_oaep_param.hashAlg = (CK_MECHANISM_TYPE)oaep_params->hashAlg;
					ck_oaep_param.mgf = oaep_params->MGF;
					ck_oaep_param.source = 0;
					ck_oaep_param.pSourceData = NULL;
					ck_oaep_param.sourceDataLen = 0;
					if (oaep_params->sourceType)
					{
						ck_oaep_param.source = CKZ_DATA_SPECIFIED;
						ck_oaep_param.pSourceData = source_data;
						ck_oaep_param.sourceDataLen = source_data_length;
					}

					decryption_mechanism.pParameter = &ck_oaep_param;
					decryption_mechanism.parameterLen = sizeof(ck_oaep_param);
				}
				else if (mechanism == EncryptionMechanism::RC2_ECB || mechanism == EncryptionMechanism::RC2_ECB_PAD)
				{
					RC2_PARAMS^ rc2_params = gcnew RC2_PARAMS((RC2_PARAMS^)parameter);
					ck_rc2_param = (CK_RC2_PARAMS)rc2_params->effectiveBits;

					decryption_mechanism.pParameter = &ck_rc2_param;
					decryption_mechanism.parameterLen = sizeof(ck_rc2_param);
				}
				else if (mechanism == EncryptionMechanism::RC2_CBC || mechanism == EncryptionMechanism::RC2_CBC_PAD)
				{
					RC2_CBC_PARAMS^ rc2_cbc_params = gcnew RC2_CBC_PARAMS((RC2_CBC_PARAMS^)parameter);
					ck_rc2_cbc_param.effectiveBits = (CK_ULONG)rc2_cbc_params->effectiveBits;

					// Convert iv from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(rc2_cbc_params->iv, &iv_data, &iv_data_length);

					for (unsigned int i = 0; i < iv_data_length; i++)
					{
						ck_rc2_cbc_param.iv[i] = iv_data[i];
					}

					decryption_mechanism.pParameter = &ck_rc2_cbc_param;
					decryption_mechanism.parameterLen = sizeof(ck_rc2_cbc_param);
				}
				else if (mechanism == EncryptionMechanism::ECIES)
				{
					ECIES_PARAMS^ ecies_params = gcnew ECIES_PARAMS((ECIES_PARAMS^)parameter);
					ck_ecies_param.ulEncKeyLenInBits = (CK_ULONG)ecies_params->encKeyLenInBits;
					ck_ecies_param.ulMacKeyLenInBits = (CK_ULONG)ecies_params->macKeyLenInBits;
					ck_ecies_param.ulMacLenInBits = (CK_ULONG)ecies_params->macLenInBits;
					ck_ecies_param.dhPrimitive = (CK_EC_DH_PRIMITIVE)ecies_params->dhPrimitive;
					ck_ecies_param.kdf = (CK_EC_KDF_TYPE)ecies_params->kdf;
					ck_ecies_param.encScheme = (CK_EC_ENC_SCHEME)ecies_params->encScheme;
					ck_ecies_param.macScheme = (CK_EC_MAC_SCHEME)ecies_params->macScheme;

					// Convert shared data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(ecies_params->sharedData1, &shared_data_1, &shared_data_1_length);
					Utils::ConvertByteArrayToCKBytePtr(ecies_params->sharedData2, &shared_data_2, &shared_data_2_length);

					ck_ecies_param.pSharedData1 = shared_data_1;
					ck_ecies_param.ulSharedDataLen1 = shared_data_1_length;

					ck_ecies_param.pSharedData2 = shared_data_2;
					ck_ecies_param.ulSharedDataLen2 = shared_data_2_length;

					decryption_mechanism.pParameter = &ck_ecies_param;
					decryption_mechanism.parameterLen = sizeof(ck_ecies_param);
				}
				else
				{
					iv = gcnew array<Byte>(((array<Byte>^)parameter)->Length);
					for (int i = 0; i < iv->Length; i++)
					{
						iv[i] = ((array<Byte>^)parameter)[i];
					}

					// Convert iv data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(iv, &iv_data, &iv_data_length);

					decryption_mechanism.pParameter = iv_data;
					decryption_mechanism.parameterLen = iv_data_length;
				}
			}

			// Convert cipher data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(cipherData, &cipher_data, &cipher_data_length);

			rv = C_DecryptInit(this->object_session->SessionID, &decryption_mechanism, this->hObject);

			if (rv == CKR_OK)
			{
				rv = C_Decrypt(this->object_session->SessionID, cipher_data, cipher_data_length, NULL, &plain_data_length);

				if (rv == CKR_OK)
				{
					plain_data = new CK_BYTE[plain_data_length];
					rv = C_Decrypt(this->object_session->SessionID, cipher_data, cipher_data_length, plain_data, &plain_data_length);

					if (rv == CKR_OK)
					{
						// Convert plain_data from CK_BYTE_PTR to array of byte.
						Utils::ConvertCKBytePtrToByteArray(plain_data, plain_data_length, plainData);
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
			// Deallocate memory of 'plain_data', 'source_data', 'shared_data_1', 'shared_data_2', 'iv_data'  and 'cipher_data'.
			if (plain_data != NULL) delete[] plain_data;
			plain_data = NULL;
			plain_data_length = 0;

			if (source_data != NULL) delete[] source_data;
			source_data = NULL;
			source_data_length = 0;

			if (shared_data_1 != NULL) delete[] shared_data_1;
			shared_data_1 = NULL;
			shared_data_1_length = 0;

			if (shared_data_2 != NULL) delete[] shared_data_2;
			shared_data_2 = NULL;
			shared_data_2_length = 0;

			if (iv_data != NULL) delete[] iv_data;
			iv_data = NULL;
			iv_data_length = 0;

			if (cipher_data != NULL) delete[] cipher_data;
			cipher_data = NULL;
			cipher_data_length = 0;
		}
	}

	//
	// Dual-function cryptographic functions (C_DigestEncryptUpdate & C_DigestDecryptUpdate)
}