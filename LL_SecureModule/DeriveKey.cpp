#include "stdafx.h"

#include "Mechanisms.h"
#include "Object.h"
#include "Utils.h"

namespace LL_SecureModule
{
	/// <summary>
	/// Derives a key from a base key, creating a new key object
	/// </summary>
	void SMObject::DeriveKey(DeriveMechanism mechanism, Object^ parameter, array<SMAttribute^>^ attribute, SMObject^% key)
	{
		CK_RV rv = CKR_OK;

		CK_OBJECT_HANDLE hBaseKey = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
		CK_OBJECT_HANDLE object_handle = CK_INVALID_HANDLE;

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

		CK_BYTE_PTR data = NULL;
		CK_ULONG data_length = 0;

		CK_BYTE_PTR shared_data = NULL;
		CK_ULONG shared_data_length = 0;

		CK_BYTE_PTR client_random_data = NULL;
		CK_ULONG client_random_data_length = 0;

		CK_BYTE_PTR server_random_data = NULL;
		CK_ULONG server_random_data_length = 0;

		CK_BYTE_PTR iv_data = NULL;
		CK_ULONG iv_data_length = 0;

		CK_MECHANISM derive_mechanism;
		CK_MECHANISM mech_type;

		CK_KEY_DERIVATION_STRING_DATA ck_key_derivation_string_data;
		CK_EXTRACT_PARAMS ck_extract_params;
		CK_SSL3_MASTER_KEY_DERIVE_PARAMS ck_ssl3_master_key_derive_params;
		CK_VERSION ck_version;
		CK_DES_CBC_PARAMS ck_des_cbc_params;
		CK_DES3_CBC_PARAMS ck_des3_cbc_params;
		CK_ECDH1_DERIVE_PARAMS ck_ecdh1_derive_params;
		CK_MECH_TYPE_AND_OBJECT ck_mech_type_and_object;
		CK_SECRET_SHARE_PARAMS ck_secret_share_params;

		array<Byte>^ iv = nullptr;

		try
		{
			derive_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			derive_mechanism.pParameter = NULL;
			derive_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == DeriveMechanism::CONCATENATE_BASE_AND_DATA || mechanism == DeriveMechanism::XOR_BASE_AND_DATA)
				{
					KEY_DERIVATION_STRING_DATA^ key_derivation_string_data = gcnew KEY_DERIVATION_STRING_DATA((KEY_DERIVATION_STRING_DATA^)parameter);

					// Convert data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(key_derivation_string_data->data, &data, &data_length);

					ck_key_derivation_string_data.pData = data;
					ck_key_derivation_string_data.len = data_length;

					derive_mechanism.pParameter = &ck_key_derivation_string_data;
					derive_mechanism.parameterLen = sizeof(ck_key_derivation_string_data);
				}
				else if (mechanism == DeriveMechanism::CONCATENATE_BASE_AND_KEY || mechanism == DeriveMechanism::XOR_BASE_AND_KEY)
				{
					SMObject^ key_object = gcnew SMObject((SMObject^)parameter);
					CK_OBJECT_HANDLE hkey_object = key_object->hObject;

					derive_mechanism.pParameter = &hkey_object;
					derive_mechanism.parameterLen = sizeof(hkey_object);
				}
				else if (mechanism == DeriveMechanism::EXTRACT_KEY_FROM_KEY)
				{
					EXTRACT_PARAMS^ extract_params = gcnew EXTRACT_PARAMS((EXTRACT_PARAMS^)parameter);

					ck_extract_params = (CK_EXTRACT_PARAMS)extract_params->bits;

					derive_mechanism.pParameter = &ck_extract_params;
					derive_mechanism.parameterLen = sizeof(ck_extract_params);
				}
				else if (mechanism == DeriveMechanism::SSL3_MASTER_KEY_DERIVE)
				{
					SSL3_MASTER_KEY_DERIVE_PARAMS^ ssl3_master_key_derive_params = gcnew SSL3_MASTER_KEY_DERIVE_PARAMS((SSL3_MASTER_KEY_DERIVE_PARAMS^)parameter);

					// Convert client random data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(ssl3_master_key_derive_params->randomInfo->clientRandom, &client_random_data, &client_random_data_length);

					// Convert server random data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(ssl3_master_key_derive_params->randomInfo->serverRandom, &server_random_data, &server_random_data_length);

					ck_ssl3_master_key_derive_params.RandomInfo.pClientRandom = client_random_data;
					ck_ssl3_master_key_derive_params.RandomInfo.clientRandomLen = client_random_data_length;

					ck_ssl3_master_key_derive_params.RandomInfo.pServerRandom = server_random_data;
					ck_ssl3_master_key_derive_params.RandomInfo.serverRandomLen = server_random_data_length;

					ck_version.major = (CK_BYTE)ssl3_master_key_derive_params->version->Major;
					ck_version.minor = (CK_BYTE)ssl3_master_key_derive_params->version->Minor;
					ck_ssl3_master_key_derive_params.pVersion = &ck_version;

					derive_mechanism.pParameter = &ck_ssl3_master_key_derive_params;
					derive_mechanism.parameterLen = sizeof(ck_ssl3_master_key_derive_params);
				}
				else if (mechanism == DeriveMechanism::DES_DERIVE_ECB || mechanism == DeriveMechanism::DES3_DERIVE_ECB || mechanism == DeriveMechanism::DH_PKCS_DERIVE || mechanism == DeriveMechanism::ZKA_MDC_2_KEY_DERIVATION)
				{
					// Convert data parameter from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr((array<Byte>^)parameter, &data, &data_length);

					derive_mechanism.pParameter = data;
					derive_mechanism.parameterLen = data_length;
				}
				else if (mechanism == DeriveMechanism::DES_DERIVE_CBC)
				{
					DES_DERIVE_CBC_PARAMS^ des_derive_cbc_params = gcnew DES_DERIVE_CBC_PARAMS((DES_DERIVE_CBC_PARAMS^)parameter);

					// Convert iv from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(des_derive_cbc_params->iv, &iv_data, &iv_data_length);

					// Convert data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(des_derive_cbc_params->data, &data, &data_length);

					for (unsigned int i = 0; i < DIM(ck_des_cbc_params.iv) && i < iv_data_length; i++)
					{
						ck_des_cbc_params.iv[i] = iv_data[i];
					}

					for (unsigned int i = 0; i < DIM(ck_des_cbc_params.data) && i < data_length; i++)
					{
						ck_des_cbc_params.data[i] = data[i];
					}

					derive_mechanism.pParameter = &ck_des_cbc_params;
					derive_mechanism.parameterLen = sizeof(ck_des_cbc_params);
				}
				else if (mechanism == DeriveMechanism::DES3_DERIVE_CBC)
				{
					DES3_DERIVE_CBC_PARAMS^ des3_derive_cbc_params = gcnew DES3_DERIVE_CBC_PARAMS((DES3_DERIVE_CBC_PARAMS^)parameter);

					// Convert iv from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(des3_derive_cbc_params->iv, &iv_data, &iv_data_length);

					// Convert data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(des3_derive_cbc_params->data, &data, &data_length);

					for (unsigned int i = 0; i < DIM(ck_des3_cbc_params.iv) && i < iv_data_length; i++)
					{
						ck_des3_cbc_params.iv[i] = iv_data[i];
					}

					for (unsigned int i = 0; i < DIM(ck_des3_cbc_params.data) && i < data_length; i++)
					{
						ck_des3_cbc_params.data[i] = data[i];
					}

					derive_mechanism.pParameter = &ck_des3_cbc_params;
					derive_mechanism.parameterLen = sizeof(ck_des3_cbc_params);
				}
				else if (mechanism == DeriveMechanism::ECDH1_DERIVE)
				{
					ECDH1_DERIVE_PARAMS^ ecdh1_derive_params = gcnew ECDH1_DERIVE_PARAMS((ECDH1_DERIVE_PARAMS^)parameter);

					ck_ecdh1_derive_params.kdf = (CK_EC_KDF_TYPE)ecdh1_derive_params->kdf;

					// Convert public data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(ecdh1_derive_params->publicData, &data, &data_length);

					// Convert shared data from array of byte to CK_BYTE_PTR.
					if (ecdh1_derive_params->sharedData != nullptr)
					{
						Utils::ConvertByteArrayToCKBytePtr(ecdh1_derive_params->sharedData, &shared_data, &shared_data_length);
					}

					ck_ecdh1_derive_params.pPublicData = data;
					ck_ecdh1_derive_params.ulPublicDataLen = data_length;

					ck_ecdh1_derive_params.pSharedData = shared_data;
					ck_ecdh1_derive_params.ulSharedDataLen = shared_data_length;

					derive_mechanism.pParameter = &ck_ecdh1_derive_params;
					derive_mechanism.parameterLen = sizeof(ck_ecdh1_derive_params);
				}
				else if (mechanism == DeriveMechanism::ENCODE_X_509_LOCAL_CERT)
				{
					MECH_TYPE_AND_OBJECT^ mech_type_and_object = gcnew MECH_TYPE_AND_OBJECT((MECH_TYPE_AND_OBJECT^)parameter);

					object_handle = mech_type_and_object->obj->hObject;

					mech_type.mechanism = (CK_MECHANISM_TYPE)mech_type_and_object->mechanism;
					mech_type.pParameter = NULL;
					mech_type.parameterLen = 0;

					ck_mech_type_and_object.mechanism = mech_type.mechanism;
					ck_mech_type_and_object.obj = object_handle;

					derive_mechanism.pParameter = &ck_mech_type_and_object;
					derive_mechanism.parameterLen = sizeof(ck_mech_type_and_object);
				}
				else if (mechanism == DeriveMechanism::ENCODE_PKCS_10 || mechanism == DeriveMechanism::ENCODE_X_509)
				{
					MECH_TYPE_AND_OBJECT^ mech_type_and_object = gcnew MECH_TYPE_AND_OBJECT((MECH_TYPE_AND_OBJECT^)parameter);

					object_handle = mech_type_and_object->obj->hObject;

					mech_type.mechanism = (CK_MECHANISM_TYPE)mech_type_and_object->mechanism;
					mech_type.pParameter = NULL;
					mech_type.parameterLen = 0;

					if (mechanism == DeriveMechanism::ENCODE_PKCS_10)
					{
						ck_mech_type_and_object.mechanism = mech_type.mechanism;
						ck_mech_type_and_object.obj = object_handle;

						derive_mechanism.pParameter = &ck_mech_type_and_object;
						derive_mechanism.parameterLen = sizeof(ck_mech_type_and_object);
					}

					rv = C_SignInit(this->object_session->SessionID, &mech_type, object_handle);

					// Check if resulting an exception.
					if (rv != CKR_OK)
						throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
				}
				else if (mechanism == DeriveMechanism::SECRET_SHARE_WITH_ATTRIBUTES)
				{
					SECRET_SHARE_PARAMS^ secret_share_params = gcnew SECRET_SHARE_PARAMS((SECRET_SHARE_PARAMS^)parameter);

					ck_secret_share_params.m = secret_share_params->m;
					ck_secret_share_params.n = secret_share_params->n;

					derive_mechanism.pParameter = &ck_secret_share_params;
					derive_mechanism.parameterLen = sizeof(ck_secret_share_params);
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

			hBaseKey = this->hObject;

			rv = C_DeriveKey(this->object_session->SessionID, &derive_mechanism, hBaseKey, CKA_Template, Template_length, &hKey);

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
			// Deallocate memory of 'data', 'iv_data', 'client_random_data' and 'server_random_data'.
			if (data != NULL) delete[] data;
			data = NULL;
			data_length = 0;

			if (iv_data != NULL) delete[] iv_data;
			iv_data = NULL;
			iv_data_length = 0;

			if (client_random_data != NULL) delete[] client_random_data;
			client_random_data = NULL;
			client_random_data_length = 0;

			if (server_random_data != NULL) delete[] server_random_data;
			server_random_data = NULL;
			server_random_data_length = 0;

			if (shared_data != NULL) delete[] shared_data;
			shared_data = NULL;
			shared_data_length = 0;

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	/// <summary>
	/// Derives a key from a base key, creating a new key object
	/// </summary>
	void SMObject::DeriveKey(DeriveMechanism mechanism, SSL3_KEY_MAT_PARAMS^% parameter, array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;

		CK_OBJECT_HANDLE hBaseKey = CK_INVALID_HANDLE;

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

		CK_BYTE_PTR client_random_data = NULL;
		CK_ULONG client_random_data_length = 0;

		CK_BYTE_PTR server_random_data = NULL;
		CK_ULONG server_random_data_length = 0;

		CK_BYTE_PTR IVClient_data = NULL;
		CK_ULONG IVClient_data_length = 0;

		CK_BYTE_PTR IVServer_data = NULL;
		CK_ULONG IVServer_data_length = 0;

		CK_MECHANISM derive_mechanism;

		CK_SSL3_KEY_MAT_PARAMS ck_ssl3_key_mat_params;
		CK_SSL3_KEY_MAT_OUT ck_ssl3_key_mat_out;

		SSL3_KEY_MAT_PARAMS^ ssl3_key_mat_params = nullptr;
		SSL3_KEY_MAT_OUT^ ssl3_key_mat_out = nullptr;

		try
		{
			derive_mechanism.mechanism = (CK_MECHANISM_TYPE)mechanism;
			derive_mechanism.pParameter = NULL;
			derive_mechanism.parameterLen = 0;

			if (parameter != nullptr)
			{
				if (mechanism == DeriveMechanism::SSL3_KEY_AND_MAC_DERIVE)
				{
					ssl3_key_mat_params = gcnew SSL3_KEY_MAT_PARAMS((SSL3_KEY_MAT_PARAMS^)parameter);

					ck_ssl3_key_mat_params.bIsExport = (CK_BBOOL)ssl3_key_mat_params->isExport;
					ck_ssl3_key_mat_params.IVSizeInBits = (CK_ULONG)ssl3_key_mat_params->IVSizeInBits;
					ck_ssl3_key_mat_params.keySizeInBits = (CK_ULONG)ssl3_key_mat_params->keySizeInBits;
					ck_ssl3_key_mat_params.macSizeInBits = (CK_ULONG)ssl3_key_mat_params->macSizeInBits;

					// Convert client random data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(ssl3_key_mat_params->randomInfo->clientRandom, &client_random_data, &client_random_data_length);

					// Convert server random data from array of byte to CK_BYTE_PTR.
					Utils::ConvertByteArrayToCKBytePtr(ssl3_key_mat_params->randomInfo->serverRandom, &server_random_data, &server_random_data_length);

					ck_ssl3_key_mat_params.RandomInfo.pClientRandom = client_random_data;
					ck_ssl3_key_mat_params.RandomInfo.clientRandomLen = client_random_data_length;

					ck_ssl3_key_mat_params.RandomInfo.pServerRandom = server_random_data;
					ck_ssl3_key_mat_params.RandomInfo.serverRandomLen = server_random_data_length;

					IVClient_data_length = IVServer_data_length = ck_ssl3_key_mat_params.IVSizeInBits / 8;
					IVClient_data = new CK_BYTE[IVClient_data_length];
					IVServer_data = new CK_BYTE[IVServer_data_length];
					ck_ssl3_key_mat_out.pIVClient = IVClient_data;
					ck_ssl3_key_mat_out.pIVServer = IVServer_data;

					ck_ssl3_key_mat_params.pReturnedKeyMaterial = &ck_ssl3_key_mat_out;

					derive_mechanism.pParameter = &ck_ssl3_key_mat_params;
					derive_mechanism.parameterLen = sizeof(ck_ssl3_key_mat_params);
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

			hBaseKey = this->hObject;

			rv = C_DeriveKey(this->object_session->SessionID, &derive_mechanism, hBaseKey, CKA_Template, Template_length, NULL);

			if (rv == CKR_OK)
			{
				if (mechanism == DeriveMechanism::SSL3_KEY_AND_MAC_DERIVE)
				{
					ssl3_key_mat_out = gcnew SSL3_KEY_MAT_OUT();

					ssl3_key_mat_out->clientMacSecret = gcnew SMObject(this->object_session, ck_ssl3_key_mat_out.hClientMacSecret);
					ssl3_key_mat_out->serverMacSecret = gcnew SMObject(this->object_session, ck_ssl3_key_mat_out.hServerMacSecret);
					ssl3_key_mat_out->clientKey = gcnew SMObject(this->object_session, ck_ssl3_key_mat_out.hClientKey);
					ssl3_key_mat_out->serverKey = gcnew SMObject(this->object_session, ck_ssl3_key_mat_out.hServerKey);

					if (ck_ssl3_key_mat_params.IVSizeInBits > 0)
					{
						// Convert client IV data from CK_BYTE_PTR to array of byte.
						Utils::ConvertCKBytePtrToByteArray(ck_ssl3_key_mat_out.pIVClient, ck_ssl3_key_mat_params.IVSizeInBits / 8, ssl3_key_mat_out->IVClient);

						// Convert server IV data from CK_BYTE_PTR to array of byte.
						Utils::ConvertCKBytePtrToByteArray(ck_ssl3_key_mat_out.pIVServer, ck_ssl3_key_mat_params.IVSizeInBits / 8, ssl3_key_mat_out->IVServer);
					}

					parameter = gcnew SSL3_KEY_MAT_PARAMS(ssl3_key_mat_params->macSizeInBits, ssl3_key_mat_params->keySizeInBits, ssl3_key_mat_params->IVSizeInBits, ssl3_key_mat_params->isExport, ssl3_key_mat_params->randomInfo, ssl3_key_mat_out);
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
			// Deallocate memory of 'client_random_data', 'server_random_data', 'IVClient_data' and 'IVServer_data'.
			if (client_random_data != NULL) delete[] client_random_data;
			client_random_data = NULL;
			client_random_data_length = 0;

			if (server_random_data != NULL) delete[] server_random_data;
			server_random_data = NULL;
			server_random_data_length = 0;

			if (IVClient_data != NULL) delete[] IVClient_data;
			IVClient_data = NULL;
			IVClient_data_length = 0;

			if (IVServer_data != NULL) delete[] IVServer_data;
			IVServer_data = NULL;
			IVServer_data_length = 0;

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}
}