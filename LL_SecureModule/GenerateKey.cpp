#include "stdafx.h"

#include "LL_SecureModule.h"
#include "Mechanisms.h"
#include "Object.h"
#include "Utils.h"

namespace LL_SecureModule
{
	/// <summary>
	/// Generates a secret key or set of domain parameters, creating a new object.
	/// <para>Since the type of key or domain parameters to be generated is implicit in the generation mechanism, the template does not need to supply a key type.</para>
	/// <para>If it does supply a key type which is inconsistent with the generation mechanism, GenerateKey fails and returns the error code TEMPLATE_INCONSISTENT.The CLASS attribute is treated similarly.</para>
	/// <para>The object created by a successful call to GenerateKey will have its LOCAL attribute set to TRUE</para>
	/// </summary>
	void SMObject::GenerateKey(KeyGenerationMechanism mechanism, Object^ parameter, array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;

		CK_SESSION_HANDLE hSession = (CK_SESSION_HANDLE) this->object_session->SessionID;
		CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

		CK_MECHANISM generation_mechanism;

		CK_VERSION ck_version;
		CK_PBE_PARAMS ck_pbe_params;
		CK_PP_LOAD_SECRET_PARAMS ck_pp_load_secret_params;

		CK_BYTE_PTR iv_data = NULL;
		CK_ULONG iv_data_length = 0;

		CK_CHAR_PTR password_data = NULL;
		CK_ULONG password_data_length = 0;

		CK_BYTE_PTR salt_data = NULL;
		CK_ULONG salt_data_length = 0;

		CK_CHAR_PTR prompt_data = NULL;
		CK_ULONG prompt_data_length = 0;

		int i = 0;

		// These variables are used to create a CK_ATTRIBUTE[] from the input 'attribute'.
		CK_ATTRIBUTE_PTR CKA_Template = NULL;
		CK_ULONG Template_length = 0;

		CK_BBOOL boolean_value[Utils::MaxArrayLength] = { (CK_BBOOL)0 };
		int boolean_indx = 0;

		CK_ULONG uint_value[Utils::MaxArrayLength] = { 0 };
		int uint_indx = 0;

		CK_DATE dateTime_value[Utils::MaxArrayLength];
		int dateTime_indx = 0;

		CK_BYTE_PTR byte_array_value[Utils::MaxArrayLength] = { NULL };
		CK_ULONG byte_array_value_length[Utils::MaxArrayLength] = { 0 };
		int byte_array_indx = 0;

		CK_CHAR_PTR char_array_value[Utils::MaxArrayLength] = { NULL };
		CK_ULONG char_array_value_length[Utils::MaxArrayLength] = { 0 };
		int char_array_indx = 0;
		//

		try
		{
			generation_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			generation_mechanism.pParameter = NULL;
			generation_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == KeyGenerationMechanism::SSL3_PRE_MASTER_KEY_GEN)
				{
					CVersion^ version = gcnew CVersion((CVersion^)parameter);
					ck_version.major = (CK_BYTE)version->Major;
					ck_version.minor = (CK_BYTE)version->Minor;

					generation_mechanism.pParameter = &ck_version;
					generation_mechanism.parameterLen = sizeof(ck_version);
				}
				else if (mechanism == KeyGenerationMechanism::PP_LOAD_SECRET)
				{
					PP_LOAD_SECRET_PARAMS^ pp_load_secret = gcnew PP_LOAD_SECRET_PARAMS((PP_LOAD_SECRET_PARAMS^)parameter);

					ck_pp_load_secret_params.bMaskInput = (CK_BBOOL)pp_load_secret->maskInput;
					ck_pp_load_secret_params.cConvert = (CK_PP_CONVERT_TYPE)pp_load_secret->convert;
					ck_pp_load_secret_params.cTimeout = (CK_CHAR)pp_load_secret->timeout;

					// Convert prompt from string to CK_CHAR_PTR.
					Utils::ConvertStringToCKCharPtr(pp_load_secret->prompt, &prompt_data, &prompt_data_length);

					ck_pp_load_secret_params.prompt = prompt_data;

					generation_mechanism.pParameter = &ck_pp_load_secret_params;
					generation_mechanism.parameterLen = sizeof(ck_pp_load_secret_params);
				}
				else if (mechanism == KeyGenerationMechanism::PBE_MD2_DES_CBC ||
					mechanism == KeyGenerationMechanism::PBE_MD5_DES_CBC ||
					mechanism == KeyGenerationMechanism::PBE_MD5_CAST128_CBC ||
					mechanism == KeyGenerationMechanism::PBE_MD5_CAST5_CBC ||
					mechanism == KeyGenerationMechanism::PBE_SHA1_CAST128_CBC ||
					mechanism == KeyGenerationMechanism::PBE_SHA1_CAST5_CBC ||
					mechanism == KeyGenerationMechanism::PBE_SHA1_DES2_EDE_CBC ||
					mechanism == KeyGenerationMechanism::PBE_SHA1_DES3_EDE_CBC ||
					mechanism == KeyGenerationMechanism::PBE_SHA1_RC2_128_CBC ||
					mechanism == KeyGenerationMechanism::PBE_SHA1_RC2_40_CBC ||
					mechanism == KeyGenerationMechanism::PBE_SHA1_RC4_128 ||
					mechanism == KeyGenerationMechanism::PBE_SHA1_RC4_40)
				{
					PBE_PARAMS^ pbe_params = gcnew PBE_PARAMS((PBE_PARAMS^)parameter);

					// Convert initial vector from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(pbe_params->initVector, &iv_data, &iv_data_length);

					// Convert salt from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(pbe_params->salt, &salt_data, &salt_data_length);

					// Convert password from string to CK_CHAR_PTR.
					Utils::ConvertStringToCKCharPtr(pbe_params->password, &password_data, &password_data_length);

					ck_pbe_params.iteration = (CK_ULONG)pbe_params->iteration;

					ck_pbe_params.pInitVector = iv_data;

					ck_pbe_params.pPassword = password_data;
					ck_pbe_params.passwordLen = password_data_length;

					ck_pbe_params.pSalt = salt_data;
					ck_pbe_params.saltLen = salt_data_length;

					generation_mechanism.pParameter = &ck_pbe_params;
					generation_mechanism.parameterLen = sizeof(ck_pbe_params);
				}
			}

			if (attribute == nullptr || attribute->Length == 0)
			{
				CKA_Template = NULL;
				Template_length = 0;
			}
			else
			{
				// Create a CK_ATTRIBUTE[] from the input 'attribute'.
				Utils::ConvertToCKTemplate(&CKA_Template, &Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, attribute);
			}

			//  Generate a Secret Key.
			rv = C_GenerateKey(hSession, &generation_mechanism, CKA_Template, Template_length, &hKey);

			if (rv == CKR_OK)
			{
				this->hObject = hKey;
			}

			// Check if resulting an exception.
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
			// Deallocate memory for all of 'byte_array_value[]' and 'char_array_value[]'.
			for (i = 0; i < byte_array_indx; i++)
			{
				if (byte_array_value[i] != NULL) delete[] byte_array_value[i];
				byte_array_value[i] = NULL;
				byte_array_value_length[i] = 0;
			}

			for (i = 0; i < char_array_indx; i++)
			{
				if (char_array_value[i] != NULL) delete[] char_array_value[i];
				char_array_value[i] = NULL;
				char_array_value_length[i] = 0;
			}

			// Deallocate memory of 'iv_data', 'password_data', 'salt_data'.
			if (iv_data != NULL) delete[] iv_data;
			iv_data = NULL;
			iv_data_length = 0;

			if (password_data != NULL) delete[] password_data;
			password_data = NULL;
			password_data_length = 0;

			if (salt_data != NULL) delete[] salt_data;
			salt_data = NULL;
			salt_data_length = 0;

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	/// <summary>
	/// Generates a public/private key pair, creating new key objects.
	/// <para>Since the types of keys to be generated are implicit in the key pair generation mechanism, the templates do not need to supply key types.</para>
	/// <para>The key objects created by a successful call to GenerateKeyPair will have their LOCAL attributes set to TRUE.</para>
	/// </summary>
	void SMObject::GenerateKeyPair(KeyGenerationMechanism mechanism, Object^ parameter, array<SMAttribute^>^ publicKey_attribute, array<SMAttribute^>^ privateKey_attribute, SMObject^% privateKey)
	{
		CK_RV rv = CKR_OK;

		CK_SESSION_HANDLE hSession = (CK_SESSION_HANDLE) this->object_session->SessionID;
		CK_OBJECT_HANDLE hPublicKey = CK_INVALID_HANDLE, hPrivateKey = CK_INVALID_HANDLE;

		CK_MECHANISM generation_mechanism;

		int i = 0;

		// These variables are used to create a CK_ATTRIBUTE[] from the input 'publicKey_attribute' and privateKey_attribute.
		CK_ATTRIBUTE_PTR CKA_Private_Template = NULL;
		CK_ATTRIBUTE_PTR CKA_Public_Template = NULL;
		CK_ULONG Public_Template_length = 0;
		CK_ULONG Private_Template_length = 0;

		CK_BBOOL boolean_value[Utils::MaxArrayLength] = { (CK_BBOOL)0 };
		int boolean_indx = 0;

		CK_ULONG uint_value[Utils::MaxArrayLength] = { 0 };
		int uint_indx = 0;

		CK_DATE dateTime_value[Utils::MaxArrayLength];
		int dateTime_indx = 0;

		CK_BYTE_PTR byte_array_value[Utils::MaxArrayLength] = { NULL };
		CK_ULONG byte_array_value_length[Utils::MaxArrayLength] = { 0 };
		int byte_array_indx = 0;

		CK_CHAR_PTR char_array_value[Utils::MaxArrayLength] = { NULL };
		CK_ULONG char_array_value_length[Utils::MaxArrayLength] = { 0 };
		int char_array_indx = 0;
		//

		try
		{
			generation_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			generation_mechanism.pParameter = NULL;
			generation_mechanism.parameterLen = 0;

			if (publicKey_attribute == nullptr || publicKey_attribute->Length == 0)
			{
				CKA_Public_Template = NULL;
				Public_Template_length = 0;
			}
			else
			{
				// Create a CK_ATTRIBUTE[] from the input 'publicKey_attribute'.
				Utils::ConvertToCKTemplate(&CKA_Public_Template, &Public_Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, publicKey_attribute);
			}

			if (privateKey_attribute == nullptr || privateKey_attribute->Length == 0)
			{
				CKA_Private_Template = NULL;
				Private_Template_length = 0;
			}
			else
			{
				// Create a CK_ATTRIBUTE[] from the input 'privateKey_attribute'.
				Utils::ConvertToCKTemplate(&CKA_Private_Template, &Private_Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, privateKey_attribute);
			}

			//  Generate a Key Pair.
			rv = C_GenerateKeyPair(hSession, &generation_mechanism, CKA_Public_Template, Public_Template_length, CKA_Private_Template, Private_Template_length, &hPublicKey, &hPrivateKey);

			if (rv == CKR_OK)
			{
				this->hObject = hPublicKey;
				privateKey = gcnew SMObject(this->object_session, hPrivateKey);
			}

			// Check if resulting an exception.
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
			// Deallocate memory for all of 'byte_array_value[]' and 'char_array_value[]'.
			for (i = 0; i < byte_array_indx; i++)
			{
				if (byte_array_value[i] != NULL) delete[] byte_array_value[i];
				byte_array_value[i] = NULL;
				byte_array_value_length[i] = 0;
			}

			for (i = 0; i < char_array_indx; i++)
			{
				if (char_array_value[i] != NULL) delete[] char_array_value[i];
				char_array_value[i] = NULL;
				char_array_value_length[i] = 0;
			}
		}
	}
}