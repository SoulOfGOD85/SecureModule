#include "stdafx.h"

#include "Object.h"
#include "Utils.h"

#include <ctfext.h>
#include <ctutil.h>

namespace LL_SecureModule
{
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	SSL3_KEY_MAT_OUT::SSL3_KEY_MAT_OUT(SMObject^ clientMacSecret, SMObject^ serverMacSecret, SMObject^ clientKey, SMObject^ serverKey, array<Byte>^ IVClient, array<Byte>^ IVServer)
	{
		if (clientMacSecret == nullptr)
		{
			this->clientMacSecret = nullptr;
		}
		else
		{
			this->clientMacSecret = gcnew SMObject(clientMacSecret);
		}

		if (serverMacSecret == nullptr)
		{
			this->serverMacSecret = nullptr;
		}
		else
		{
			this->serverMacSecret = gcnew SMObject(serverMacSecret);
		}

		if (clientKey == nullptr)
		{
			this->clientKey = nullptr;
		}
		else
		{
			this->clientKey = gcnew SMObject(clientKey);
		}

		if (serverKey == nullptr)
		{
			this->serverKey = nullptr;
		}
		else
		{
			this->serverKey = gcnew SMObject(serverKey);
		}

		if (IVClient == nullptr)
		{
			this->IVClient = nullptr;
		}
		else
		{
			this->IVClient = gcnew array<Byte>(IVClient->Length);
			for (int i = 0; i < this->IVClient->Length; i++)
				this->IVClient[i] = IVClient[i];
		}

		if (IVServer == nullptr)
		{
			this->IVServer = nullptr;
		}
		else
		{
			this->IVServer = gcnew array<Byte>(IVServer->Length);
			for (int i = 0; i < this->IVServer->Length; i++)
				this->IVServer[i] = IVServer[i];
		}
	}

	SSL3_KEY_MAT_OUT::SSL3_KEY_MAT_OUT(SSL3_KEY_MAT_OUT^ ssl3_key_mat_out)
	{
		if (ssl3_key_mat_out->clientMacSecret == nullptr)
		{
			this->clientMacSecret = nullptr;
		}
		else
		{
			this->clientMacSecret = gcnew SMObject(ssl3_key_mat_out->clientMacSecret);
		}

		if (ssl3_key_mat_out->serverMacSecret == nullptr)
		{
			this->serverMacSecret = nullptr;
		}
		else
		{
			this->serverMacSecret = gcnew SMObject(ssl3_key_mat_out->serverMacSecret);
		}

		if (ssl3_key_mat_out->clientKey == nullptr)
		{
			this->clientKey = nullptr;
		}
		else
		{
			this->clientKey = gcnew SMObject(ssl3_key_mat_out->clientKey);
		}

		if (ssl3_key_mat_out->serverKey == nullptr)
		{
			this->serverKey = nullptr;
		}
		else
		{
			this->serverKey = gcnew SMObject(ssl3_key_mat_out->serverKey);
		}

		if (ssl3_key_mat_out->IVClient == nullptr)
		{
			this->IVClient = nullptr;
		}
		else
		{
			this->IVClient = gcnew array<Byte>(ssl3_key_mat_out->IVClient->Length);
			for (int i = 0; i < this->IVClient->Length; i++)
				this->IVClient[i] = ssl3_key_mat_out->IVClient[i];
		}

		if (ssl3_key_mat_out->IVServer == nullptr)
		{
			this->IVServer = nullptr;
		}
		else
		{
			this->IVServer = gcnew array<Byte>(ssl3_key_mat_out->IVServer->Length);
			for (int i = 0; i < this->IVServer->Length; i++)
				this->IVServer[i] = ssl3_key_mat_out->IVServer[i];
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	SSL3_KEY_MAT_PARAMS::SSL3_KEY_MAT_PARAMS(UInt32 macSizeInBits, UInt32 keySizeInBits, UInt32 IVSizeInBits, Boolean isExport, SSL3_RANDOM_DATA^ randomInfo, SSL3_KEY_MAT_OUT^ key_mat_out)
	{
		this->macSizeInBits = macSizeInBits;
		this->keySizeInBits = keySizeInBits;
		this->IVSizeInBits = IVSizeInBits;
		this->isExport = isExport;

		if (randomInfo == nullptr)
		{
			this->randomInfo = nullptr;
		}
		else
		{
			this->randomInfo = gcnew SSL3_RANDOM_DATA(randomInfo);
		}

		if (key_mat_out == nullptr)
		{
			this->key_mat_out = nullptr;
		}
		else
		{
			this->key_mat_out = gcnew SSL3_KEY_MAT_OUT(key_mat_out);
		}
	}

	SSL3_KEY_MAT_PARAMS::SSL3_KEY_MAT_PARAMS(SSL3_KEY_MAT_PARAMS^ ssl3_key_mat_params)
	{
		this->macSizeInBits = ssl3_key_mat_params->macSizeInBits;
		this->keySizeInBits = ssl3_key_mat_params->keySizeInBits;
		this->IVSizeInBits = ssl3_key_mat_params->IVSizeInBits;
		this->isExport = ssl3_key_mat_params->isExport;

		if (ssl3_key_mat_params->randomInfo == nullptr)
		{
			this->randomInfo = nullptr;
		}
		else
		{
			this->randomInfo = gcnew SSL3_RANDOM_DATA(ssl3_key_mat_params->randomInfo);
		}

		if (ssl3_key_mat_params->key_mat_out == nullptr)
		{
			this->key_mat_out = nullptr;
		}
		else
		{
			this->key_mat_out = gcnew SSL3_KEY_MAT_OUT(ssl3_key_mat_params->key_mat_out);
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	MECH_TYPE_AND_OBJECT::MECH_TYPE_AND_OBJECT(SignMechanism mechanism, SMObject^ obj)
	{
		this->mechanism = mechanism;

		if (obj == nullptr)
			this->obj = nullptr;
		else
			this->obj = gcnew SMObject(obj);
	}

	MECH_TYPE_AND_OBJECT::MECH_TYPE_AND_OBJECT(MECH_TYPE_AND_OBJECT^ mech_type_and_object)
	{
		this->mechanism = mech_type_and_object->mechanism;

		if (mech_type_and_object->obj == nullptr)
			this->obj = nullptr;
		else
			this->obj = gcnew SMObject(mech_type_and_object->obj);
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	PKCS12_PBE_EXPORT_PARAMS::PKCS12_PBE_EXPORT_PARAMS(SMObject^ keyCert, String^ passwordAuthSafe, String^ passwordHMAC, SafeBagEncryption safeBagKgMech, SafeContentEncryption safeContentKgMech)
	{
		this->passwordAuthSafe = passwordAuthSafe;
		this->passwordHMAC = passwordHMAC;
		this->safeBagKgMech = safeBagKgMech;
		this->safeContentKgMech = safeContentKgMech;

		if (keyCert == nullptr)
			this->keyCert = nullptr;
		else
			this->keyCert = gcnew SMObject(keyCert);
	}

	PKCS12_PBE_EXPORT_PARAMS::PKCS12_PBE_EXPORT_PARAMS(PKCS12_PBE_EXPORT_PARAMS^ pkcs12_pbe_export_params)
	{
		this->passwordAuthSafe = pkcs12_pbe_export_params->passwordAuthSafe;
		this->passwordHMAC = pkcs12_pbe_export_params->passwordHMAC;
		this->safeBagKgMech = pkcs12_pbe_export_params->safeBagKgMech;
		this->safeContentKgMech = pkcs12_pbe_export_params->safeContentKgMech;

		if (pkcs12_pbe_export_params->keyCert == nullptr)
			this->keyCert = nullptr;
		else
			this->keyCert = gcnew SMObject(pkcs12_pbe_export_params->keyCert);
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	PKCS12_PBE_IMPORT_PARAMS::PKCS12_PBE_IMPORT_PARAMS(String^ passwordAuthSafe, String^ passwordHMAC, array<SMAttribute^>^ certAttr, array<SMObject^>^ cert)
	{
		this->passwordAuthSafe = passwordAuthSafe;
		this->passwordHMAC = passwordHMAC;

		if (certAttr == nullptr || certAttr->Length == 0)
			this->certAttr = nullptr;
		else
		{
			this->certAttr = gcnew array<SMAttribute^>(certAttr->Length);
			for (int i = 0; i < this->certAttr->Length; i++)
				this->certAttr[i] = gcnew SMAttribute(certAttr[i]);
		}

		if (cert == nullptr || cert->Length == 0)
			this->cert = nullptr;
		else
		{
			this->cert = gcnew array<SMObject^>(cert->Length);
			for (int i = 0; i < this->cert->Length; i++)
				this->cert[i] = gcnew SMObject(cert[i]);
		}
	}

	PKCS12_PBE_IMPORT_PARAMS::PKCS12_PBE_IMPORT_PARAMS(PKCS12_PBE_IMPORT_PARAMS^ pkcs12_pbe_import_params)
	{
		this->passwordAuthSafe = pkcs12_pbe_import_params->passwordAuthSafe;
		this->passwordHMAC = pkcs12_pbe_import_params->passwordHMAC;

		if (pkcs12_pbe_import_params->certAttr == nullptr || pkcs12_pbe_import_params->certAttr->Length == 0)
			this->certAttr = nullptr;
		else
		{
			this->certAttr = gcnew array<SMAttribute^>(pkcs12_pbe_import_params->certAttr->Length);
			for (int i = 0; i < this->certAttr->Length; i++)
				this->certAttr[i] = gcnew SMAttribute(pkcs12_pbe_import_params->certAttr[i]);
		}

		if (pkcs12_pbe_import_params->cert == nullptr || pkcs12_pbe_import_params->cert->Length == 0)
			this->cert = nullptr;
		else
		{
			this->cert = gcnew array<SMObject^>(pkcs12_pbe_import_params->cert->Length);
			for (int i = 0; i < this->cert->Length; i++)
				this->cert[i] = gcnew SMObject(pkcs12_pbe_import_params->cert[i]);
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	/// <summary>
	/// Creates a new object.
	/// <para>Only session objects can be created during a read-only session. Only public objects can be created unless the normal user is logged in.</para>
	/// <para>If CreateObject cannot support the precise attribute(s) template supplied to it, it will fail and return without creating any object.</para>
	/// <para>If CreateObject is used to create a key object, the key object will have its LOCAL attribute set to 'False'. If that key object is a secret or private key then the new key will have the ALWAYS_SENSITIVE attribute set to 'False', and the NEVER_EXTRACTABLE attribute set to 'False'.</para>
	/// </summary>
	void SMObject::CreateObject(array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;
		int i = 0;

		CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;

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

		try
		{
			if (attribute == nullptr || attribute->Length == 0)
			{
				CKA_Template = NULL;
				Template_length = 0;
			}
			else
			{
				// Convert the input attribute(s) to CK_ATTRIBUTE[].
				Utils::ConvertToCKTemplate(&CKA_Template, &Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, attribute);
			}

			// Create new object related to CK_ATTRIBUTE[].
			rv = C_CreateObject(this->object_session->SessionID, CKA_Template, Template_length, &hObj);

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));

			this->hObject = hObj;
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
			//

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	/// <summary>
	/// Destroys object.
	/// <para>Only session objects can be destroyed during a read-only session. Only public objects can be destroyed unless the normal user is logged in.</para>
	/// <para>In addition to standard object deletion rules there is support for the DELETABLE attribute. This is an optional attribute that may be specified for token objects.</para>
	/// <para>For token objects with DELETABLE attribute set to 'False' the DestroyObject function will not delete the object and will instead return the error OBJECT_READ_ONLY.</para>
	/// <para>Unmodifiable objects can be deleted. Objects may however specify DELETABLE to 'False', for token objects only, in which case the object may not be deleted using the DestroyObject function. Only by re-initializing the token can the object be destroyed.</para>
	/// </summary>
	void SMObject::DestroyObject()
	{
		CK_RV rv = CKR_OK;

		try
		{
			// Attempting destroy the object.
			rv = C_DestroyObject(this->object_session->SessionID, this->hObject);

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));

			// Clear the current object's handle.
			this->hObject = CK_INVALID_HANDLE;
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

	/// <summary>
	/// Gets the size of the object in bytes.
	/// <para>This function interprets the object size to be the amount of memory guaranteed to be sufficient to encode the object‘s attributes.</para>
	/// </summary>
	void SMObject::GetObjectSize(UInt32% objectSize)
	{
		CK_RV rv = CKR_OK;

		try
		{
			CK_ULONG object_size = 0;

			// Get the size of this object.
			rv = C_GetObjectSize(this->object_session->SessionID, this->hObject, &object_size);

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));

			// Set the output 'objectSize'.
			objectSize = (UInt32)object_size;
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

	/// <summary>
	/// Obtains the value of one or more attributes of the object.
	/// <para>Sensitive attributes are returned with the type and length information but an empty value, and also return an error result value of ATTRIBUTE_SENSITIVE.</para>
	/// </summary>
	void SMObject::GetAttributeValue(array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;

		int i = 0;

		// this variable is used to the CK_ATTRIBYUTE with dynamic length (like BYTE[] or CHAR[]).
		Boolean needSecondTimeGet = false;

		const CK_ULONG Template_length = 1;
		CK_ATTRIBUTE CKA_Template[Template_length] = { 0 };

		CK_BBOOL boolean_value = (CK_BBOOL)0;
		CK_ULONG uint_value = 0;
		CK_DATE dateTime_value;
		CK_BYTE_PTR byte_array_value = NULL;
		CK_ULONG byte_array_value_length = 0;
		CK_CHAR_PTR char_array_value = NULL;
		CK_ULONG char_array_value_length = 0;

		DateTime dateTime_attribute;
		String^ string_attribute = String::Empty;
		array<Byte>^ byteArray_attribute = nullptr;

		for (i = 0; i < attribute->Length; i++)
		{
			CKA_Template[0].type = (CK_ATTRIBUTE_TYPE)attribute[i]->Attribute_Type;
			CKA_Template[0].pValue = NULL_PTR;
			CKA_Template[0].valueLen = 0;

			// Get the attribute's system data type (Boolean, String, Byte[], DateTime, UInt32).
			System::TypeCode attributeTypeCode = attribute[i]->GetAttributeSystemTypeCode();

			// Fill the template[] with the 'attribute' data.
			// For each (type, pValue, ulValueLen) triple in the template[], performs the following:
			switch (attributeTypeCode)
			{
			case System::TypeCode::Boolean:
				CKA_Template[0].pValue = &boolean_value;
				CKA_Template[0].valueLen = sizeof(boolean_value);
				break;
			case System::TypeCode::UInt32:
				CKA_Template[0].pValue = &uint_value;
				CKA_Template[0].valueLen = sizeof(uint_value);
				break;
			case System::TypeCode::DateTime:
				if (attribute[i]->Attribute_Type == AttributeType::START_DATE || attribute[i]->Attribute_Type == AttributeType::END_DATE)
				{
					CKA_Template[0].pValue = &dateTime_value;
					CKA_Template[0].valueLen = sizeof(dateTime_value);
				}
				else
				{
					needSecondTimeGet = true;
				}
				break;
			case System::TypeCode::Byte:
			case System::TypeCode::String:
				needSecondTimeGet = true;
				break;
			default:
				break;
			}

			// Get the attribute value.
			rv = C_GetAttributeValue(this->object_session->SessionID, this->hObject, CKA_Template, Template_length);

			try
			{
				if (rv == CKR_OK)
				{
					switch (attributeTypeCode)
					{
					case System::TypeCode::Boolean:
						attribute[i]->Value = Convert::ToBoolean(boolean_value);///???(Boolean)boolean_value;
						break;
					case System::TypeCode::UInt32:
						attribute[i]->Value = (UInt32)uint_value;
						break;
					case System::TypeCode::DateTime:
						if (attribute[i]->Attribute_Type == AttributeType::START_DATE || attribute[i]->Attribute_Type == AttributeType::END_DATE)
						{
							Utils::ConvertCKDateToDateTime(&dateTime_value, dateTime_attribute);
							attribute[i]->Value = dateTime_attribute;
						}
						else
						{
							char_array_value_length = CKA_Template[0].valueLen;
							char_array_value = new CK_CHAR[char_array_value_length];

							CKA_Template[0].pValue = char_array_value;
							CKA_Template[0].valueLen = char_array_value_length;
						}
						break;
					case System::TypeCode::Byte:
						byte_array_value_length = CKA_Template[0].valueLen;
						byte_array_value = new CK_BYTE[byte_array_value_length];

						CKA_Template[0].pValue = byte_array_value;
						CKA_Template[0].valueLen = byte_array_value_length;
						break;
					case System::TypeCode::String:
						char_array_value_length = CKA_Template[0].valueLen;
						char_array_value = new CK_CHAR[char_array_value_length];

						CKA_Template[0].pValue = char_array_value;
						CKA_Template[0].valueLen = char_array_value_length;
						break;
					default:
						break;
					}

					if (needSecondTimeGet)
					{
						rv = C_GetAttributeValue(this->object_session->SessionID, this->hObject, CKA_Template, Template_length);
						if (rv == CKR_OK)
						{
							switch (attributeTypeCode)
							{
							case System::TypeCode::DateTime:
								if (attribute[i]->Attribute_Type == AttributeType::TIME_STAMP || attribute[i]->Attribute_Type == AttributeType::CERTIFICATE_START_TIME || attribute[i]->Attribute_Type == AttributeType::CERTIFICATE_END_TIME)
								{
									Utils::ConvertCKCharPtrToString(char_array_value, char_array_value_length, string_attribute);
									Utils::ConvertCertificateTimeToDateTime(string_attribute, dateTime_attribute);
									attribute[i]->Value = dateTime_attribute;
								}
								break;
							case System::TypeCode::Byte:
								Utils::ConvertCKBytePtrToByteArray(byte_array_value, byte_array_value_length, byteArray_attribute);
								attribute[i]->Value = byteArray_attribute;
								break;
							case System::TypeCode::String:
								Utils::ConvertCKCharPtrToString(char_array_value, char_array_value_length, string_attribute);
								attribute[i]->Value = string_attribute;
								break;
							default:
								break;
							}
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
				// Deallocate memory for 'byte_array_value[]' and 'char_array_value[]'.
				if (byte_array_value != NULL) delete[] byte_array_value;
				byte_array_value = NULL;
				byte_array_value_length = 0;

				if (char_array_value != NULL) delete[] char_array_value;
				char_array_value = NULL;
				char_array_value_length = 0;
			}
		}
	}

	/// <summary>
	/// Modifies the value of one or more attributes of the object.
	/// <para>Only session objects can be modified during a read-only session.</para>
	/// <para>The input attribute(s) may specify new values for any attributes of the object that can be modified.</para>
	/// <para>If the attribute(s) specify a value of an attribute which is incompatible with other existing attributes of the object, the call fails with the return code TEMPLATE_INCONSISTENT.</para>
	/// <para>Not all attributes can be modified.</para>
	/// </summary>
	void SMObject::SetAttributeValue(array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;
		int i = 0;

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

		try
		{
			if (attribute == nullptr || attribute->Length == 0)
			{
				CKA_Template = NULL;
				Template_length = 0;
			}
			else
			{
				// Convert the input attribute(s) to CK_ATTRIBUTE[].
				Utils::ConvertToCKTemplate(&CKA_Template, &Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, attribute);
			}

			// Get the value of attributes of this object.
			rv = C_SetAttributeValue(this->object_session->SessionID, this->hObject, CKA_Template, Template_length);

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
			//

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	/// <summary>
	/// Copies an object, creating a new object for the copy.
	/// <para>The template may specify new values for any attributes of the object that can ordinarily be modified (e.g., in the course of copying a secret key, a key's EXTRACTABLE attribute may be changed from CK_TRUE to CK_FALSE, but not the other way around. If this change is made, the new key's NEVER_EXTRACTABLE attribute will have the value CK_FALSE. Similarly, the template may specify that the new key's SENSITIVE attribute be CK_TRUE; the new key will have the same value for its ALWAYS_SENSITIVE attribute as the original key).</para>
	/// <para>It may also specify new values of the TOKEN and PRIVATE attributes (e.g., to copy a session object to a token object). If the template specifies a value of an attribute which is incompatible with other existing attributes of the object, the call fails with the return code TEMPLATE_INCONSISTENT.</para>
	/// <para>If a call to C_CopyObject cannot support the precise template supplied to it, it will fail and return without creating any object.</para>
	/// <para>Only session objects can be created during a read-only session. Only public objects can be created unless the normal user is logged in.</para>
	/// </summary>
	void SMObject::CopyObject(SMObject^% newObject, array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;
		int i = 0;

		CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;

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

		try
		{
			if (attribute == nullptr || attribute->Length == 0)
			{
				CKA_Template = NULL;
				Template_length = 0;
			}
			else
			{
				// Convert the input attribute(s) to CK_ATTRIBUTE[].
				Utils::ConvertToCKTemplate(&CKA_Template, &Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, attribute);
			}

			// Make a copy of this object with specific attribute(s).
			rv = C_CopyObject(this->object_session->SessionID, this->hObject, CKA_Template, Template_length, &hObj);

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));

			// Set the new SMObject.
			newObject = gcnew SMObject(this->object_session, (UInt32)hObj);
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
			//

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	void SMObject::CopyObject(SMSession^ destinationSession, SMObject^% newObject, array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;
		int i = 0;

		CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;

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

		try
		{
			// Input data validation check.
			if (destinationSession == nullptr || destinationSession->SessionID == CK_INVALID_HANDLE) throw gcnew SecureModuleException("destinationSession is null or invalid.");

			if (attribute == nullptr || attribute->Length == 0)
			{
				CKA_Template = NULL;
				Template_length = 0;
			}
			else
			{
				// Convert the input attribute(s) to CK_ATTRIBUTE[].
				Utils::ConvertToCKTemplate(&CKA_Template, &Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, attribute);
			}

			// Make a copy an object from one session to another session.
			rv = CT_CopyObject(destinationSession->SessionID, this->object_session->SessionID, this->hObject, CKA_Template, Template_length, &hObj);

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));

			// Set the new SMObject.
			newObject = gcnew SMObject(destinationSession, (UInt32)hObj);
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
			//

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	void SMObject::Transfer(SMSession^ destinationSession, SMObject^% newObject, array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;
		int i = 0;

		CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;

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

		try
		{
			// Input data validation check.
			if (destinationSession == nullptr || destinationSession->SessionID == CK_INVALID_HANDLE) throw gcnew SecureModuleException("destinationSession is null or invalid.");

			if (attribute == nullptr || attribute->Length == 0)
			{
				CKA_Template = NULL;
				Template_length = 0;
			}
			else
			{
				// Convert the input attribute(s) to CK_ATTRIBUTE[].
				Utils::ConvertToCKTemplate(&CKA_Template, &Template_length, boolean_value, boolean_indx, uint_value, uint_indx, dateTime_value, dateTime_indx, byte_array_value, byte_array_value_length, byte_array_indx, char_array_value, char_array_value_length, char_array_indx, attribute);
			}

			// Make a copy an object from one session to another session.
			rv = TransferObject(destinationSession->SessionID, this->object_session->SessionID, this->hObject, &hObj, CKA_Template, Template_length);

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));

			// Set the new SMObject.
			newObject = gcnew SMObject(destinationSession, (UInt32)hObj);
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
			//

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	void SMObject::SelectObject(array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int i = 0;

		CK_ULONG object_count = 0;

		CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;

		// These variables are used to creation a CK_ATTRIBUTE[] from 'attribute'.
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

			//  Initialize a search for objects that match the CKA_Template.
			rv = C_FindObjectsInit(this->object_session->SessionID, CKA_Template, Template_length);

			if (rv == CKR_OK)
			{
				// Continue a search for token and session objects that match a template, obtaining additional object handles.
				rv = C_FindObjects(this->object_session->SessionID, &hObj, 1, &object_count);

				// Terminates a search for token and session objects.
				_rv = C_FindObjectsFinal(this->object_session->SessionID);
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
			{
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
			}
			else
			{
				// If there is no object matching the template, then the location that 'object_count' points to receives the value 0.
				if (object_count <= 0)
				{
					rv = CKR_FUNCTION_FAILED;
					throw gcnew SecureModuleException(rv, "No object were found.");
				}
			}

			// Set this object with the handle of founded object.
			this->hObject = hObj;
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
			//

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}

	void SMObject::FindObjects(SMSession^ session, System::Collections::Generic::List<SMObject^>^% objects, array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int i = 0;

		CK_ULONG object_count = 0;

		CK_OBJECT_HANDLE hObj = CK_INVALID_HANDLE;

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

			//  Initialize a search for objects that match a template.
			rv = C_FindObjectsInit(session->SessionID, CKA_Template, Template_length);

			if (rv == CKR_OK)
			{
				objects = gcnew System::Collections::Generic::List<SMObject^>();

				// Loop over all objects.
				while (true)
				{
					// Continue a search for token and session objects that match a template, obtaining additional object handles.
					// If there are no more objects matching the template, then the location that 'object_count' points to receives the value 0.
					rv = C_FindObjects(session->SessionID, &hObj, 1, &object_count);
					if (rv != CKR_OK || object_count == 0)
						break;

					// Add founded object to the output objects list.
					objects->Add(gcnew SMObject(session, (UInt32)hObj));
				}

				// Terminates a search for token and session objects.
				_rv = C_FindObjectsFinal(session->SessionID);
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

			// Deallocate memory of 'CKA_Template'.
			if (CKA_Template != NULL) delete[] CKA_Template;
			CKA_Template = NULL;
		}
	}
}