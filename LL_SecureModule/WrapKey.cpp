#include "stdafx.h"

#include "Mechanisms.h"
#include "Object.h"
#include "Utils.h"

#define MAX_PKCS12_CERTS	10

namespace LL_SecureModule
{
	/// <summary>
	/// Wraps (i.e., encrypts) a private or secret key.
	/// </summary>
	void SMObject::WrapKey(WrappingMechanism mechanism, Object^ parameter, SMObject^ key, array<Byte>^% wrappedKey)
	{
		CK_RV rv = CKR_OK;

		CK_OBJECT_HANDLE hWrappingKey = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

		CK_BYTE_PTR wrapped_data = NULL;
		CK_ULONG wrapped_data_length = 0;

		CK_BYTE_PTR source_data = NULL;
		CK_ULONG source_data_length = 0;

		CK_BYTE_PTR x_data = NULL;
		CK_ULONG x_data_length = 0;

		CK_BYTE_PTR iv_data = NULL;
		CK_ULONG iv_data_length = 0;

		CK_CHAR_PTR authPass = NULL;
		CK_ULONG authPass_length = 0;

		CK_CHAR_PTR hmacPass = NULL;
		CK_ULONG hmacPass_length = 0;

		CK_MECHANISM wrap_mechanism;

		CK_RSA_PKCS_OAEP_PARAMS ck_oaep_param;

		CK_RC2_PARAMS ck_rc2_param;

		CK_RC2_CBC_PARAMS ck_rc2_cbc_param;

		CK_KEY_WRAP_SET_OAEP_PARAMS ck_key_wrap_set_oaep_params;

		CK_PKCS12_PBE_EXPORT_PARAMS ck_pkcs12_pbe_export_params;

		array<Byte>^ iv = nullptr;
		array<Byte>^ pkcs12_pass_bytes = nullptr;

		try
		{
			// Input data validation check.
			if (key == nullptr) throw gcnew SecureModuleException("key is null.");

			wrap_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			wrap_mechanism.pParameter = NULL;
			wrap_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == WrappingMechanism::RSA_PKCS_OAEP)
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

					wrap_mechanism.pParameter = &ck_oaep_param;
					wrap_mechanism.parameterLen = sizeof(ck_oaep_param);
				}
				else if (mechanism == WrappingMechanism::RC2_ECB || mechanism == WrappingMechanism::RC2_ECB_PAD)
				{
					RC2_PARAMS^ rc2_params = gcnew RC2_PARAMS((RC2_PARAMS^)parameter);
					ck_rc2_param = (CK_RC2_PARAMS)rc2_params->effectiveBits;

					wrap_mechanism.pParameter = &ck_rc2_param;
					wrap_mechanism.parameterLen = sizeof(ck_rc2_param);
				}
				else if (mechanism == WrappingMechanism::RC2_CBC || mechanism == WrappingMechanism::RC2_CBC_PAD)
				{
					RC2_CBC_PARAMS^ rc2_cbc_params = gcnew RC2_CBC_PARAMS((RC2_CBC_PARAMS^)parameter);
					ck_rc2_cbc_param.effectiveBits = (CK_ULONG)rc2_cbc_params->effectiveBits;

					// Convert iv from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(rc2_cbc_params->iv, &iv_data, &iv_data_length);

					for (unsigned int i = 0; i < iv_data_length; i++)
					{
						ck_rc2_cbc_param.iv[i] = iv_data[i];
					}

					wrap_mechanism.pParameter = &ck_rc2_cbc_param;
					wrap_mechanism.parameterLen = sizeof(ck_rc2_cbc_param);
				}
				else if (mechanism == WrappingMechanism::KEY_WRAP_SET_OAEP)
				{
					KEY_WRAP_SET_OAEP_PARAMS^ key_wrap_set_oaep_params = gcnew KEY_WRAP_SET_OAEP_PARAMS((KEY_WRAP_SET_OAEP_PARAMS^)parameter);

					ck_key_wrap_set_oaep_params.bBC = (CK_BYTE)key_wrap_set_oaep_params->BC;

					// Convert X from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(key_wrap_set_oaep_params->X, &x_data, &x_data_length);

					ck_key_wrap_set_oaep_params.pX = x_data;
					ck_key_wrap_set_oaep_params.XLen = x_data_length;

					wrap_mechanism.pParameter = &ck_key_wrap_set_oaep_params;
					wrap_mechanism.parameterLen = sizeof(ck_key_wrap_set_oaep_params);
				}
				else if (mechanism == WrappingMechanism::PKCS12_PBE_EXPORT)
				{
					PKCS12_PBE_EXPORT_PARAMS^ pkcs12_pbe_export_params = gcnew PKCS12_PBE_EXPORT_PARAMS((PKCS12_PBE_EXPORT_PARAMS^)parameter);

					ck_pkcs12_pbe_export_params.hmacKgMech = (CK_MECHANISM_TYPE)pkcs12_pbe_export_params->hmacKgMech;
					ck_pkcs12_pbe_export_params.safeBagKgMech = (CK_MECHANISM_TYPE)pkcs12_pbe_export_params->safeBagKgMech;
					ck_pkcs12_pbe_export_params.safeContentKgMech = (CK_MECHANISM_TYPE)pkcs12_pbe_export_params->safeContentKgMech;

					Utils::ConvertStringToUnicodeArray(pkcs12_pbe_export_params->passwordAuthSafe, pkcs12_pass_bytes);
					// Convert pkcs12_pass_bytes(passwordAuthSafe) from array of bytes to CK_CHAR_PTR.
					Utils::ConvertByteArrayToCKCharPtr(pkcs12_pass_bytes, &authPass, &authPass_length);

					ck_pkcs12_pbe_export_params.passwordAuthSafe = authPass;
					ck_pkcs12_pbe_export_params.passwordAuthSafeLen = authPass_length;

					Utils::ConvertStringToUnicodeArray(pkcs12_pbe_export_params->passwordHMAC, pkcs12_pass_bytes);
					// Convert pkcs12_pass_bytes(passwordHMAC) from array of bytes to CK_CHAR_PTR.
					Utils::ConvertByteArrayToCKCharPtr(pkcs12_pass_bytes, &hmacPass, &hmacPass_length);

					ck_pkcs12_pbe_export_params.passwordHMAC = hmacPass;
					ck_pkcs12_pbe_export_params.passwordHMACLen = hmacPass_length;

					if (pkcs12_pbe_export_params->keyCert == nullptr)
					{
						ck_pkcs12_pbe_export_params.keyCert = CK_INVALID_HANDLE;
					}
					else
					{
						ck_pkcs12_pbe_export_params.keyCert = pkcs12_pbe_export_params->keyCert->hObject;
					}

					wrap_mechanism.pParameter = &ck_pkcs12_pbe_export_params;
					wrap_mechanism.parameterLen = sizeof(ck_pkcs12_pbe_export_params);
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

					wrap_mechanism.pParameter = iv_data;
					wrap_mechanism.parameterLen = iv_data_length;
				}
			}

			hWrappingKey = this->hObject;
			hKey = key->hObject;

			rv = C_WrapKey(this->object_session->SessionID, &wrap_mechanism, hWrappingKey, hKey, NULL, &wrapped_data_length);

			if (rv == CKR_OK)
			{
				wrapped_data = new CK_BYTE[wrapped_data_length];
				rv = C_WrapKey(this->object_session->SessionID, &wrap_mechanism, hWrappingKey, hKey, wrapped_data, &wrapped_data_length);

				if (rv == CKR_OK)
				{
					// Convert wrapped_data from CK_BYTE_PTR to array of byte.
					Utils::ConvertCKBytePtrToByteArray(wrapped_data, wrapped_data_length, wrappedKey);
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
			// Deallocate memory of 'wrapped_data', 'source_data', 'x_data', 'iv_data', authPass and hmacPass.
			if (wrapped_data != NULL) delete[] wrapped_data;
			wrapped_data = NULL;
			wrapped_data_length = 0;

			if (source_data != NULL) delete[] source_data;
			source_data = NULL;
			source_data_length = 0;

			if (iv_data != NULL) delete[] iv_data;
			iv_data = NULL;
			iv_data_length = 0;

			if (x_data != NULL) delete[] x_data;
			x_data = NULL;
			x_data_length = 0;

			if (authPass != NULL) delete[] authPass;
			authPass = NULL;
			authPass_length = 0;

			if (hmacPass != NULL) delete[] hmacPass;
			hmacPass = NULL;
			hmacPass_length = 0;
		}
	}

	/// <summary>
	/// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object.
	/// </summary>
	void SMObject::UnwrapKey(WrappingMechanism mechanism, Object^ parameter, array<Byte>^ wrappedKey, array<SMAttribute^>^ attribute, SMObject^% key)
	{
		CK_RV rv = CKR_OK;

		CK_OBJECT_HANDLE hWrappingKey = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

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

		CK_BYTE_PTR wrapped_data = NULL;
		CK_ULONG wrapped_data_length = 0;

		CK_BYTE_PTR source_data = NULL;
		CK_ULONG source_data_length = 0;

		CK_BYTE_PTR x_data = NULL;
		CK_ULONG x_data_length = 0;

		CK_BYTE_PTR iv_data = NULL;
		CK_ULONG iv_data_length = 0;

		CK_MECHANISM unwrap_mechanism;

		CK_RSA_PKCS_OAEP_PARAMS ck_oaep_param;

		CK_RC2_PARAMS ck_rc2_param;

		CK_RC2_CBC_PARAMS ck_rc2_cbc_param;

		CK_KEY_WRAP_SET_OAEP_PARAMS ck_key_wrap_set_oaep_params;

		array<Byte>^ iv = nullptr;

		try
		{
			// Input data validation check.
			if (wrappedKey == nullptr) throw gcnew SecureModuleException("wrappedKey is null.");

			unwrap_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			unwrap_mechanism.pParameter = NULL;
			unwrap_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == WrappingMechanism::RSA_PKCS_OAEP)
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

					unwrap_mechanism.pParameter = &ck_oaep_param;
					unwrap_mechanism.parameterLen = sizeof(ck_oaep_param);
				}
				else if (mechanism == WrappingMechanism::RC2_ECB || mechanism == WrappingMechanism::RC2_ECB_PAD)
				{
					RC2_PARAMS^ rc2_params = gcnew RC2_PARAMS((RC2_PARAMS^)parameter);
					ck_rc2_param = (CK_RC2_PARAMS)rc2_params->effectiveBits;

					unwrap_mechanism.pParameter = &ck_rc2_param;
					unwrap_mechanism.parameterLen = sizeof(ck_rc2_param);
				}
				else if (mechanism == WrappingMechanism::RC2_CBC || mechanism == WrappingMechanism::RC2_CBC_PAD)
				{
					RC2_CBC_PARAMS^ rc2_cbc_params = gcnew RC2_CBC_PARAMS((RC2_CBC_PARAMS^)parameter);
					ck_rc2_cbc_param.effectiveBits = (CK_ULONG)rc2_cbc_params->effectiveBits;

					// Convert iv from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(rc2_cbc_params->iv, &iv_data, &iv_data_length);

					for (unsigned int i = 0; i < iv_data_length; i++)
					{
						ck_rc2_cbc_param.iv[i] = iv_data[i];
					}

					unwrap_mechanism.pParameter = &ck_rc2_cbc_param;
					unwrap_mechanism.parameterLen = sizeof(ck_rc2_cbc_param);
				}
				else if (mechanism == WrappingMechanism::KEY_WRAP_SET_OAEP)
				{
					KEY_WRAP_SET_OAEP_PARAMS^ key_wrap_set_oaep_params = gcnew KEY_WRAP_SET_OAEP_PARAMS((KEY_WRAP_SET_OAEP_PARAMS^)parameter);

					ck_key_wrap_set_oaep_params.bBC = (CK_BYTE)key_wrap_set_oaep_params->BC;

					// Convert X from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(key_wrap_set_oaep_params->X, &x_data, &x_data_length);

					ck_key_wrap_set_oaep_params.pX = x_data;
					ck_key_wrap_set_oaep_params.XLen = x_data_length;

					unwrap_mechanism.pParameter = &ck_key_wrap_set_oaep_params;
					unwrap_mechanism.parameterLen = sizeof(ck_key_wrap_set_oaep_params);
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

					unwrap_mechanism.pParameter = iv_data;
					unwrap_mechanism.parameterLen = iv_data_length;
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

			// Convert wrappedKey data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(wrappedKey, &wrapped_data, &wrapped_data_length);

			hWrappingKey = this->hObject;

			rv = C_UnwrapKey(this->object_session->SessionID, &unwrap_mechanism, hWrappingKey, wrapped_data, wrapped_data_length, CKA_Template, Template_length, &hKey);

			if (rv == CKR_OK)
			{
				key = gcnew SMObject(this->object_session, hKey);
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
			// Deallocate memory of 'wrapped_data', 'source_data', 'x_data' and 'iv_data'.
			if (wrapped_data != NULL) delete[] wrapped_data;
			wrapped_data = NULL;
			wrapped_data_length = 0;

			if (source_data != NULL) delete[] source_data;
			source_data = NULL;
			source_data_length = 0;

			if (iv_data != NULL) delete[] iv_data;
			iv_data = NULL;
			iv_data_length = 0;

			if (x_data != NULL) delete[] x_data;
			x_data = NULL;
			x_data_length = 0;

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	/// <summary>
	/// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object.
	/// </summary>
	void SMObject::UnwrapKey(WrappingMechanism mechanism, PKCS12_PBE_IMPORT_PARAMS^% parameter, array<Byte>^ wrappedKey, array<SMAttribute^>^ attribute, SMObject^% key)
	{
		CK_RV rv = CKR_OK;

		CK_OBJECT_HANDLE hWrappingKey = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;

		CK_OBJECT_HANDLE hCerts[MAX_PKCS12_CERTS] = { CK_INVALID_HANDLE };
		CK_ULONG hCertsCount = 1;

		// These variables are used to create a CK_ATTRIBUTE[] from the input 'attribute'.
		CK_ATTRIBUTE_PTR CKA_Template = NULL;
		CK_ULONG Template_length = 0;

		CK_ATTRIBUTE_PTR CKA_Cert_Template = NULL;
		CK_ULONG Cert_Template_length = 0;

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

		CK_BYTE_PTR wrapped_data = NULL;
		CK_ULONG wrapped_data_length = 0;

		CK_CHAR_PTR authPass = NULL;
		CK_ULONG authPass_length = 0;

		CK_CHAR_PTR hmacPass = NULL;
		CK_ULONG hmacPass_length = 0;

		CK_MECHANISM unwrap_mechanism;

		CK_PKCS12_PBE_IMPORT_PARAMS ck_pkcs12_pbe_import_params;

		PKCS12_PBE_IMPORT_PARAMS^ pkcs12_pbe_import_params = nullptr;

		array<Byte>^ pkcs12_pass_bytes = nullptr;

		try
		{
			// Input data validation check.
			if (wrappedKey == nullptr) throw gcnew SecureModuleException("wrappedKey is null.");

			unwrap_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			unwrap_mechanism.pParameter = NULL;
			unwrap_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				pkcs12_pbe_import_params = gcnew PKCS12_PBE_IMPORT_PARAMS(parameter);

				if (mechanism == WrappingMechanism::PKCS12_PBE_IMPORT)
				{
					Utils::ConvertStringToUnicodeArray(pkcs12_pbe_import_params->passwordAuthSafe, pkcs12_pass_bytes);
					// Convert pkcs12_pass_bytes(passwordAuthSafe) from array of bytes to CK_CHAR_PTR.
					Utils::ConvertByteArrayToCKCharPtr(pkcs12_pass_bytes, &authPass, &authPass_length);

					ck_pkcs12_pbe_import_params.passwordAuthSafe = authPass;
					ck_pkcs12_pbe_import_params.passwordAuthSafeLen = authPass_length;

					Utils::ConvertStringToUnicodeArray(pkcs12_pbe_import_params->passwordHMAC, pkcs12_pass_bytes);
					// Convert pkcs12_pass_bytes(passwordHMAC) from array of bytes to CK_CHAR_PTR.
					Utils::ConvertByteArrayToCKCharPtr(pkcs12_pass_bytes, &hmacPass, &hmacPass_length);

					ck_pkcs12_pbe_import_params.passwordHMAC = hmacPass;
					ck_pkcs12_pbe_import_params.passwordHMACLen = hmacPass_length;

					if (pkcs12_pbe_import_params->certAttr == nullptr || pkcs12_pbe_import_params->certAttr->Length == 0)
					{
						CKA_Cert_Template = NULL;
						Cert_Template_length = 0;
					}
					else
					{
						// Create a CK_ATTRIBUTE[] from the input parameter.
						Utils::ConvertToCKTemplate(&CKA_Cert_Template, &Cert_Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, pkcs12_pbe_import_params->certAttr);
					}

					ck_pkcs12_pbe_import_params.certAttr = CKA_Cert_Template;
					ck_pkcs12_pbe_import_params.certAttrCount = Cert_Template_length;

					ck_pkcs12_pbe_import_params.hCert = hCerts;
					ck_pkcs12_pbe_import_params.hCertCount = &hCertsCount;

					unwrap_mechanism.pParameter = &ck_pkcs12_pbe_import_params;
					unwrap_mechanism.parameterLen = sizeof(ck_pkcs12_pbe_import_params);
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

			// Convert wrappedKey data from array of byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(wrappedKey, &wrapped_data, &wrapped_data_length);

			hWrappingKey = this->hObject;

			rv = C_UnwrapKey(this->object_session->SessionID, &unwrap_mechanism, hWrappingKey, wrapped_data, wrapped_data_length, CKA_Template, Template_length, &hKey);

			if (rv == CKR_OK)
			{
				if (hCertsCount == 0)
				{
					pkcs12_pbe_import_params->cert = nullptr;
				}
				else
				{
					pkcs12_pbe_import_params->cert = gcnew array<SMObject^>(hCertsCount);
					for (int i = 0; i < pkcs12_pbe_import_params->cert->Length; i++)
						pkcs12_pbe_import_params->cert[i] = gcnew SMObject(this->object_session, hCerts[i]);
				}

				parameter = gcnew PKCS12_PBE_IMPORT_PARAMS(pkcs12_pbe_import_params);

				key = gcnew SMObject(this->object_session, hKey);
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
			// Deallocate memory of 'wrapped_data', 'authPass' and 'hmacPass'.
			if (wrapped_data != NULL) delete[] wrapped_data;
			wrapped_data = NULL;
			wrapped_data_length = 0;

			if (authPass != NULL) delete[] authPass;
			authPass = NULL;
			authPass_length = 0;

			if (hmacPass != NULL) delete[] hmacPass;
			hmacPass = NULL;
			hmacPass_length = 0;

			// Deallocate memory of 'CKA_Template' and 'CKA_Cert_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;

			if (CKA_Cert_Template != NULL) delete[] CKA_Cert_Template;
			CKA_Cert_Template = NULL;
		}
	}
}