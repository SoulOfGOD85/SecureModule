#include "stdafx.h"

#include "LL_SecureModule.h"
#include "Utils.h"

#include <cmlib.h>
#include <ctfext.h>

namespace LL_SecureModule
{

	void Cryptoki::CloseAllSessions(UInt32 slotID)
	{
		CK_RV rv = CKR_OK;

		// Closes all sessions.
		rv = C_CloseAllSessions((CK_SLOT_ID)slotID);

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Obtains a list of slots in the system
	/// </summary>
	void Cryptoki::GetSlotList(Boolean tokenPresent, List<String^>^% tokensName)
	{
		CK_RV rv = CKR_OK;

		CK_ULONG indx = 0;

		CK_ULONG pulCount = 0;
		CK_SLOT_ID_PTR pSlotList = NULL;

		CK_TOKEN_INFO tokenInfo;

		String^ tokenLable = "";

		// // Get list of slots.
		// If 'pSlotList' is NULL_PTR, then all that "C_GetSlotList" does is return (in *pulCount) the number of slots, without actually returning a list of slots.
		rv = C_GetSlotList((CK_BBOOL)tokenPresent, NULL, &pulCount);

		// Check the C_GetSlotList result and be sure about 'tokensName' not be null.
		if (rv == CKR_OK && pulCount > 0)
		{
			// check for Token List memory for allocation.
			if (tokensName == nullptr)
				tokensName = gcnew List<String^>();

			// Allocates memory for 'pSlotList'.
			pSlotList = new CK_SLOT_ID[pulCount];

			// If memory allocation was unsuccessful.
			if (pSlotList == NULL)
				throw gcnew SecureModuleException(CKR_HOST_MEMORY, "Memory allocation was unsuccessful.");

			// Get list of slots.
			// If 'pSlotList' is not NULL_PTR, then *pulCount must contain the size (in terms of CK_SLOT_ID elements) of the buffer pointed to by 'pSlotList'.
			// If that buffer is large enough to hold the list of slots, then the list is returned in it, and CKR_OK is returned.
			rv = C_GetSlotList((CK_BBOOL)tokenPresent, pSlotList, &pulCount);

			// Check the C_GetSlotList result.
			if (rv == CKR_OK)
			{
				// Get token information for each slot.
				for (indx = 0; indx < pulCount; indx++)
				{
					// Get information the token
					rv = C_GetTokenInfo(pSlotList[indx], &tokenInfo);

					// Check the C_GetTokenInfo result.
					if (rv == CKR_OK)
					{
						try
						{
							// Convert token's name from CK_CHAR_PTR to System::String.
							Utils::ConvertCKCharPtrToString(tokenInfo.label, CK_TOKEN_LABEL_SIZE, tokenLable);

							// Removes all trailing occurrences of space character and then add the token's name to output list.
							tokensName->Add(tokenLable->TrimEnd());
						}
						catch (Exception^)
						{
							throw;
						}
					}
					else if (rv == CKR_TOKEN_NOT_PRESENT)
					{
						try
						{
							// Set Default label for no label tokens (like smart card token).
							tokenLable = "<no token>";

							// Add the token's name to output list; if it's not NULL.
							if (tokensName != nullptr)
								tokensName->Add(tokenLable);
						}
						catch (Exception^)
						{
							throw;
						}
					}
				}
			}

			// Deallocate memory for 'pSlotList'.
			delete[] pSlotList;
			pSlotList = NULL;
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Find a token with the specified label and return the corresponding slot id.
	/// <para>This function is not supported in the current version of 'LL_SecureModule'.</para>
	/// </summary>
	void Cryptoki::FindTokenByName(String^ label, UInt32% slotID)
	{
		CK_RV rv = CKR_OK;

		CK_SLOT_ID slot_id = 0;

		unsigned int cbLabel = 0;
		char* pbLabel = NULL;

		try
		{
			// Convert Admin PIN from System::String to char*.
			Utils::ConvertStringToCharPtr(label, &pbLabel, &cbLabel);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'pbLabel'.
			if (pbLabel != NULL)
			{
				delete[] pbLabel;
				pbLabel = NULL;
			}

			throw;
		}

		// Find Slot ID
		//rv = FindTokenFromName(pbLabel,&slot_id);
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		if (rv == CKR_OK)
			slotID = (UInt32)slot_id;

		// Deallocate memory for 'pbLabel'.
		delete[] pbLabel;
		pbLabel = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Returns the HSM id for the specified user Slot ID.
	/// </summary>
	void Cryptoki::GetDeviceIDFromSlotID(UInt32 slotID, UInt32% deviceID)
	{
		CK_RV rv = CKR_OK;
		unsigned int hsm_id = 0;

		//
		rv = CT_HsmIdFromSlotId(slotID, &hsm_id);
		if (rv != CKR_OK)
			deviceID = (UInt32)hsm_id;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Obtains information about a particular slot in the device
	/// </summary>
	void Cryptoki::GetSlotInfo(UInt32 slotID, SlotInfo^% slotInfo)
	{
		CK_RV rv = CKR_OK;
		String^ str = "";

		CK_SLOT_INFO ck_slot_info;

		// Get slot information.
		rv = C_GetSlotInfo((CK_SLOT_ID)slotID, &ck_slot_info);

		// Check the C_GetSlotInfo result and be sure about 'slotInfo' not be null.
		if (rv == CKR_OK && slotInfo != nullptr)
		{
			try
			{
				// Convert slot description from CK_CHAR_PTR to System::String.
				Utils::ConvertCKCharPtrToString(ck_slot_info.slotDescription, CK_SLOT_DESCRIPTION_SIZE, str);

				slotInfo->SlotDescription = str->TrimEnd();

				// Convert manufacturer's ID from CK_CHAR_PTR to System::String.
				Utils::ConvertCKCharPtrToString(ck_slot_info.manufacturerID, CK_SLOT_MANUFACTURER_SIZE, str);

				slotInfo->ManufacturerID = str->TrimEnd();

				// Sets Flags.
				slotInfo->Flags = (UInt32)ck_slot_info.flags;

				// Sets the version of firmware.
				slotInfo->FirmwareVersion->Major = (Byte)ck_slot_info.firmwareVersion.major;
				slotInfo->FirmwareVersion->Minor = (Byte)ck_slot_info.firmwareVersion.minor;

				// Sets the version of hardware.
				slotInfo->HardwareVersion->Major = (Byte)ck_slot_info.hardwareVersion.major;
				slotInfo->HardwareVersion->Minor = (Byte)ck_slot_info.hardwareVersion.minor;
			}
			catch (Exception^)
			{
				throw;
			}
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Obtains information about a particular token in the device.
	/// </summary>
	void Cryptoki::GetTokenInfo(UInt32 slotID, TokenInfo^% tokenInfo)
	{
		CK_RV rv = CKR_OK;

		String^ str = "";

		CK_TOKEN_INFO ck_token_info;

		// Get token information.
		rv = C_GetTokenInfo((CK_SLOT_ID)slotID, &ck_token_info);

		// Check the C_GetTokenInfo result.
		if (rv == CKR_OK)
		{
			tokenInfo = gcnew TokenInfo();

			try
			{
				// Convert token label from CK_CHAR_PTR to System::String.
				Utils::ConvertCKCharPtrToString(ck_token_info.label, CK_TOKEN_LABEL_SIZE, str);

				tokenInfo->label = str->TrimEnd();

				// Convert manufacturerID from CK_CHAR_PTR to System::String.
				Utils::ConvertCKCharPtrToString(ck_token_info.manufacturerID, CK_TOKEN_MANUFACTURER_SIZE, str);

				tokenInfo->manufacturerID = str->TrimEnd();

				// Convert model from CK_CHAR_PTR to System::String.
				Utils::ConvertCKCharPtrToString(ck_token_info.model, CK_TOKEN_MODEL_SIZE, str);

				tokenInfo->model = str->TrimEnd();

				// Convert token serial number from CK_CHAR_PTR to System::String.
				Utils::ConvertCKCharPtrToString(ck_token_info.serialNumber, CK_TOKEN_SERIAL_NUMBER_SIZE, str);

				tokenInfo->serialNumber = str->TrimEnd();

				// Convert token utcTime from CK_CHAR_PTR to System::String.
				Utils::ConvertCKCharPtrToString(ck_token_info.utcTime, CK_TOKEN_TIME_SIZE, str);

				tokenInfo->utcTime = str->TrimEnd();

				// Sets Flags.
				tokenInfo->flags = (UInt32)ck_token_info.flags;

				tokenInfo->maxSessionCount = (UInt32)ck_token_info.maxSessionCount;
				tokenInfo->sessionCount = (UInt32)ck_token_info.sessionCount;
				tokenInfo->maxRwSessionCount = (UInt32)ck_token_info.maxRwSessionCount;
				tokenInfo->rwSessionCount = (UInt32)ck_token_info.rwSessionCount;
				tokenInfo->maxPinLen = (UInt32)ck_token_info.maxPinLen;
				tokenInfo->minPinLen = (UInt32)ck_token_info.minPinLen;
				tokenInfo->totalPublicMemory = (UInt32)ck_token_info.totalPublicMemory;
				tokenInfo->freePublicMemory = (UInt32)ck_token_info.freePublicMemory;
				tokenInfo->totalPrivateMemory = (UInt32)ck_token_info.totalPrivateMemory;
				tokenInfo->freePrivateMemory = (UInt32)ck_token_info.freePrivateMemory;

				// Sets the version of firmware.
				tokenInfo->firmwareVersion->Major = (Byte)ck_token_info.firmwareVersion.major;
				tokenInfo->firmwareVersion->Minor = (Byte)ck_token_info.firmwareVersion.minor;

				// Sets the version of hardware.
				tokenInfo->hardwareVersion->Major = (Byte)ck_token_info.hardwareVersion.major;
				tokenInfo->hardwareVersion->Minor = (Byte)ck_token_info.hardwareVersion.minor;
			}
			catch (Exception^)
			{
				throw;
			}
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Determine the total number of sessions open on the specified token.
	/// </summary>
	void Cryptoki::GetSlotSessionCount(UInt32 deviceNumber, UInt32 slotID, UInt32% sessionCount)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;
		int deviceID = deviceNumber;
		int itemNumber = slotID;
		CM_eInfo eInfo = CM_TOKEN_SESSION_COUNT;
		CK_ULONG info = 0;

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Retrieve specific information.
			rv = CM_GetInfoLong(deviceID, itemNumber, eInfo, &info);
			if (rv == CKR_OK)
				sessionCount = (UInt32)info;

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Create the specified number of slots on the specified device.
	/// <para>This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
	/// </summary>
	void Cryptoki::CreateSlots(UInt32 deviceNumber, String^ adminPIN, UInt32 numSlots)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CK_ULONG cbAdminPin = 0;
		CK_CHAR_PTR pbAdminPin = NULL;

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pbAdminPin, &cbAdminPin);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'pbAdminPin'.
			if (pbAdminPin != NULL)
			{
				delete[] pbAdminPin;
				pbAdminPin = NULL;
			}

			throw;
		}

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Create new slot(s).
			rv = CM_CreateSlots(deviceNumber, (const unsigned char *)pbAdminPin, (int)numSlots);

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Deallocate memory for 'pbAdminPin'
		delete[] pbAdminPin;
		pbAdminPin = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Delete the specified slot on the specified device.
	/// <para>This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
	/// </summary>
	void Cryptoki::DeleteSlot(UInt32 slotID, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;
		CM_SlotRef SlotRef;

		CK_ULONG cbAdminPin = 0;
		CK_CHAR_PTR pbAdminPin = NULL;

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pbAdminPin, &cbAdminPin);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'pbAdminPin'.
			if (pbAdminPin != NULL)
			{
				delete[] pbAdminPin;
				pbAdminPin = NULL;
			}

			throw;
		}

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Get SlotRef from slodID
			rv = CM_SlotIdToSlotRef((int)slotID, &SlotRef);
			if (rv == CKR_OK)
			{
				// Delete slot.
				rv = CM_DeleteSlot(&SlotRef, (const unsigned char *)pbAdminPin);
			}

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Deallocate memory for 'pbAdminPin'.
		delete[] pbAdminPin;
		pbAdminPin = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Change the Admin SO/User PIN of a device.
	/// </summary>
	void Cryptoki::ChangeAdminPIN(UInt32 deviceNumber, UserType userType, String^ oldPIN, String^ newPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CK_ULONG cbOldPin = 0;
		CK_CHAR_PTR pbOldPin = NULL;
		CK_ULONG cbNewPin = 0;
		CK_CHAR_PTR pbNewPin = NULL;

		try
		{
			// Convert current PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(oldPIN, &pbOldPin, &cbOldPin);

			// Convert new PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(newPIN, &pbNewPin, &cbNewPin);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'pbOldPin', 'pbNewPin'.
			if (pbOldPin != NULL)
			{
				delete[] pbOldPin;
				pbOldPin = NULL;
			}

			if (pbNewPin != NULL)
			{
				delete[] pbNewPin;
				pbNewPin = NULL;
			}

			throw;
		}

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Change device admin PIN
			if (userType == UserType::USER) // User
				rv = CM_ChangeAdminPIN((int)deviceNumber, (const unsigned char *)pbOldPin, (const unsigned char *)pbNewPin);
			else if (userType == UserType::SO) // SO
				rv = CM_ChangeAdminSOPIN((int)deviceNumber, (const unsigned char *)pbOldPin, (const unsigned char *)pbNewPin);

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Deallocate memory for 'pbOldPin', 'pbNewPin'.
		delete[] pbOldPin;
		pbOldPin = NULL;

		delete[] pbNewPin;
		pbNewPin = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Initialise the Admin user PIN of a device.
	/// </summary>
	void Cryptoki::InitAdminPIN(UInt32 deviceNumber, String^ SOPIN, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CK_ULONG cbSOPin = 0;
		CK_CHAR_PTR pbSOPin = NULL;
		CK_ULONG cbAdminPin = 0;
		CK_CHAR_PTR pbAdminPin = NULL;

		try
		{
			// Convert AdminToken SO PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(SOPIN, &pbSOPin, &cbSOPin);

			// Convert AdminToken User PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pbAdminPin, &cbAdminPin);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'pbSOPin', 'pbAdminPin'.
			if (pbSOPin != NULL)
			{
				delete[] pbSOPin;
				pbSOPin = NULL;
			}

			if (pbAdminPin != NULL)
			{
				delete[] pbAdminPin;
				pbAdminPin = NULL;
			}

			throw;
		}

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Init device admin PIN
			rv = CM_InitAdminPIN((int)deviceNumber, (const unsigned char *)pbSOPin, (const unsigned char *)pbAdminPin);

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Deallocate memory for 'pbSOPin', 'pbAdminPin'.
		delete[] pbSOPin;
		pbSOPin = NULL;

		delete[] pbAdminPin;
		pbAdminPin = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Initializes a token.
	/// <para>If the token has not been initialized (i.e. new from the factory), then the 'SOPIN' parameter becomes the initial value of the SO PIN.</para>
	/// <para>If the token is being reinitialized, the 'SOPIN' parameter is checked against the existing SO PIN to authorize the initialization operation.</para>
	/// <para>In both cases, the SO PIN is the value 'SOPIN' after the function completes successfully.</para>
	/// <para>A token cannot be initialized if Cryptoki detects that any application has an open session with it.</para>
	/// <para>When a token is initialized, all objects that can be destroyed are destroyed. (i.e., all except for "indestructible" objects such as keys built into the token).</para>
	/// <para>Also, access by the normal user is disabled until the SO sets the normal user's PIN.</para>
	/// <para>Depending on the token, some default objects may be created, and attributes of some objects may be set to default values.</para>
	/// </summary>
	void Cryptoki::InitToken(UInt32 slotID, String^ SOPIN, String^ tokenLabel)
	{
		CK_RV rv = CKR_OK;

		CK_CHAR_PTR so_pin = NULL;
		CK_ULONG so_pin_len = 0;
		CK_CHAR_PTR label = NULL;
		CK_ULONG label_len = 0;

		CK_CHAR token_label[CK_TOKEN_LABEL_SIZE];

		// Data Validation check.
		if (String::IsNullOrEmpty(SOPIN)) throw gcnew SecureModuleException("SO PIN is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(tokenLabel)) throw gcnew SecureModuleException("Token label is nullptr or an Empty string.");
		if (SOPIN->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of SO PIN is more than maximum pin length.");
		if (tokenLabel->Length > CK_TOKEN_LABEL_SIZE) throw gcnew SecureModuleException("Length of token label is more than maximum token label size.");

		try
		{
			// Convert SO PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(SOPIN, &so_pin, &so_pin_len);

			// Convert token label from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(tokenLabel, &label, &label_len);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'so_pin' and 'label'.
			if (so_pin != NULL)
			{
				delete[] so_pin;
				so_pin = NULL;
			}

			if (label != NULL)
			{
				delete[] label;
				label = NULL;
			}

			throw;
		}

		// The PKCS#11 standard states that token labels must be 32 bytes padded with spaces.
		memset(token_label, ' ', DIM(token_label));

		// Copy 'label' to 'token_label' which is padded with spaces.
		memcpy_s(token_label, DIM(token_label), label, label_len);

		// Initializes the token.
		rv = C_InitToken((CK_SLOT_ID)slotID, so_pin, so_pin_len, token_label);

		// Deallocate memory for 'so_pin' and 'label'.
		delete[] so_pin;
		so_pin = NULL;

		delete[] label;
		label = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Initializes a token and set its user PIN.
	/// <para>If the token has not been initialized (i.e. new from the factory), then the 'SOPIN' parameter becomes the initial value of the SO PIN.</para>
	/// <para>If the token is being reinitialized, the 'SOPIN' parameter is checked against the existing SO PIN to authorize the initialization operation.</para>
	/// <para>In both cases, the SO PIN is the value 'SOPIN' after the function completes successfully.</para>
	/// <para>A token cannot be initialized if Cryptoki detects that any application has an open session with it.</para>
	/// <para>When a token is initialized, all objects that can be destroyed are destroyed. (i.e., all except for "indestructible" objects such as keys built into the token).</para>
	/// <para>Depending on the token, some default objects may be created, and attributes of some objects may be set to default values.</para>
	/// </summary>
	void Cryptoki::InitToken(UInt32 slotID, String^ SOPIN, String^ UserPIN, String^ tokenLabel)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CK_CHAR_PTR so_pin = NULL;
		CK_ULONG so_pin_len = 0;
		CK_CHAR_PTR user_pin = NULL;
		CK_ULONG user_pin_len = 0;
		CK_CHAR_PTR label = NULL;
		CK_ULONG label_len = 0;

		CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

		CK_CHAR token_label[CK_TOKEN_LABEL_SIZE];

		// input data validation check.
		if (String::IsNullOrEmpty(SOPIN)) throw gcnew SecureModuleException("SO PIN is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(UserPIN)) throw gcnew SecureModuleException("User PIN is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(tokenLabel)) throw gcnew SecureModuleException("Token label is nullptr or an Empty string.");
		if (SOPIN->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of SO PIN is more than maximum pin length.");
		if (UserPIN->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of User PIN is more than maximum pin length.");
		if (tokenLabel->Length > CK_TOKEN_LABEL_SIZE) throw gcnew SecureModuleException("Length of token label is more than maximum token label size.");

		try
		{
			// Convert SO PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(SOPIN, &so_pin, &so_pin_len);

			// Convert User PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(UserPIN, &user_pin, &user_pin_len);

			// Convert token label from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(tokenLabel, &label, &label_len);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'so_pin', 'user_pin' and 'label'.
			if (so_pin != NULL)
			{
				delete[] so_pin;
				so_pin = NULL;
			}

			if (user_pin != NULL)
			{
				delete[] user_pin;
				user_pin = NULL;
			}

			if (label != NULL)
			{
				delete[] label;
				label = NULL;
			}

			throw;
		}

		// The PKCS#11 standard states that token labels must be 32 bytes padded with spaces.
		memset(token_label, ' ', DIM(token_label));

		// Copy 'label' to 'token_label' which is padded with spaces.
		memcpy_s(token_label, DIM(token_label), label, label_len);

		// Initializes the token.
		rv = C_InitToken((CK_SLOT_ID)slotID, so_pin, so_pin_len, token_label);
		if (rv == CKR_OK)
		{
			// We now want to intialize the user pin. To do this we will use the "C_InitPIN(") function which can only be called in the "R/W SO Functions" state.
			// So, open a session and log in the SO.
			rv = C_OpenSession(slotID, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
			if (rv == CKR_OK)
			{
				// Login as security officer
				rv = C_Login(hSession, CKU_SO, so_pin, so_pin_len);
				if (rv == CKR_OK)
				{
					// Initialise the normal user's PIN
					rv = C_InitPIN(hSession, user_pin, user_pin_len);

					// Logout security officer
					_rv = C_Logout(hSession);
				}

				// Close the session
				_rv = C_CloseSession(hSession);
			}
		}

		// Deallocate memory for 'so_pin', 'user_pin' and 'label'.
		delete[] so_pin;
		so_pin = NULL;

		delete[] user_pin;
		user_pin = NULL;

		delete[] label;
		label = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Initialise the token.
	/// <para>There is an argument that says this function should not be useful, as it is for initializing a user Token, but the initialization may require the Admin Token USER PIN, so it belongs in this library.</para>
	/// <para>If the security mode of the slot is CKF_NO_CLEAR_PINS then the Admin Token USER PIN is required, otherwise it is ignored.</para>
	/// </summary>
	void Cryptoki::InitTokenByAdmin(UInt32 slotID, String^ adminPIN, String^ tokenLabel, String^ SOPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CM_SlotRef SlotRef;

		CK_ULONG cbAdminPin = 0;
		CK_CHAR_PTR pbAdminPin = NULL;
		CK_ULONG cbTokenLabel = 0;
		CK_CHAR_PTR pbTokenLabel = NULL;
		CK_ULONG cbSOPin = 0;
		CK_CHAR_PTR pbSOPin = NULL;

		try
		{
			// Convert AdminToken user PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pbAdminPin, &cbAdminPin);

			// Convert SO PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(SOPIN, &pbSOPin, &cbSOPin);

			// Convert token label from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(tokenLabel, &pbTokenLabel, &cbTokenLabel);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'pbAdminPin', 'pbSOPin', 'pbTokenLabel'.
			if (pbAdminPin != NULL)
			{
				delete[] pbAdminPin;
				pbAdminPin = NULL;
			}

			if (pbSOPin != NULL)
			{
				delete[] pbSOPin;
				pbSOPin = NULL;
			}

			if (pbTokenLabel != NULL)
			{
				delete[] pbTokenLabel;
				pbTokenLabel = NULL;
			}

			throw;
		}

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Get SlotRef from slodID
			rv = CM_SlotIdToSlotRef((int)slotID, &SlotRef);
			if (rv == CKR_OK)
			{
				// Initializes the token.
				rv = CM_InitToken(&SlotRef, (const unsigned char *)pbAdminPin, (const unsigned char *)pbTokenLabel, (const unsigned char *)pbSOPin);
			}
			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Deallocate memory for 'pbAdminPin', 'pbSOPin', 'pbTokenLabel'.
		delete[] pbAdminPin;
		pbAdminPin = NULL;

		delete[] pbSOPin;
		pbSOPin = NULL;

		delete[] pbTokenLabel;
		pbTokenLabel = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Reset the token.
	/// <para>This will clear the USER PIN and change the SO PIN and Token Label.</para>
	/// <para>There is an argument that says this function should not be in this library, as it is for resetting a user Token, but it complements the 'InitToken' method, so it belongs in this library.</para>
	/// </summary>
	void Cryptoki::ResetToken(UInt32 slotID, String^ SOPIN, String^ newSOPIN, String^ newLabel)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CM_SlotRef SlotRef;

		CK_ULONG cbSOPin = 0;
		CK_CHAR_PTR pbSOPin = NULL;
		CK_ULONG cbNewSOPin = 0;
		CK_CHAR_PTR pbNewSOPin = NULL;
		CK_ULONG cbNewLabel = 0;
		CK_CHAR_PTR pbNewLabel = NULL;

		try
		{
			// Convert current SO PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(SOPIN, &pbSOPin, &cbSOPin);

			// Convert new SO PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(newSOPIN, &pbNewSOPin, &cbNewSOPin);

			// Convert the label from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(newLabel, &pbNewLabel, &cbNewLabel);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'pbSOPin', 'pbNewSOPin', 'pbNewLabel'.
			if (pbSOPin != NULL)
			{
				delete[] pbSOPin;
				pbSOPin = NULL;
			}

			if (pbNewSOPin != NULL)
			{
				delete[] pbNewSOPin;
				pbNewSOPin = NULL;
			}

			if (pbNewLabel != NULL)
			{
				delete[] pbNewLabel;
				pbNewLabel = NULL;
			}

			throw;
		}

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Get SlotRef from slodID
			rv = CM_SlotIdToSlotRef((int)slotID, &SlotRef);
			if (rv == CKR_OK)
			{
				// reset the token.
				rv = CM_ResetToken(&SlotRef, (const unsigned char *)pbSOPin, (const unsigned char *)pbNewSOPin, (const unsigned char *)pbNewLabel);
			}
			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Deallocate memory for 'pbSOPin', 'pbNewSOPin', 'pbNewLabel'.
		delete[] pbSOPin;
		pbSOPin = NULL;

		delete[] pbNewSOPin;
		pbNewSOPin = NULL;

		delete[] pbNewLabel;
		pbNewLabel = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}
}