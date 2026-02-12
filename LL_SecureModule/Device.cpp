#include "stdafx.h"
#include "LL_SecureModule.h"
#include "Utils.h"
#include "DeviceInfoType.h"

#include <ctfext.h>

namespace LL_SecureModule
{
	/// <summary>
	/// Determine the total number of sessions open on all tokens on all adapters.
	/// </summary>
	void Cryptoki::GetTotalSessionCount(UInt32% sessionCount)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;
		int deviceID = 0;
		int itemNumber = (int)(CM_TOTAL_SESSION_COUNT);
		CM_eInfo eInfo = CM_TOTAL_SESSION_COUNT;
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
	/// Determine the number of applications currently using cryptoki.
	/// </summary>
	void Cryptoki::GetApplicationCount(UInt32% applicationCount)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;
		int deviceID = 0;
		int itemNumber = (int)(CM_APPLICATION_COUNT);
		CM_eInfo eInfo = CM_APPLICATION_COUNT;
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
			{
				if (info == CK_UNAVAILABLE_INFORMATION)
					rv = CKR_FUNCTION_FAILED;
				else
					applicationCount = (UInt32)info;
			}

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Synchronise the clock of the device with the host.
	/// </summary>
	void Cryptoki::SyncClock(int deviceNumber, String^ adminPIN)
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
			// Synchronise the device's clock.
			rv = CM_SyncClock((int)deviceNumber, (const unsigned char *)pbAdminPin);

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
	/// Set the clock of the device to the specified time.
	/// <para>The passed in time string must be GMT.</para>
	/// </summary>
	void Cryptoki::SetClock(int deviceNumber, String^ adminPIN, String^ dateTime)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CK_ULONG cbAdminPin = 0;
		CK_CHAR_PTR pbAdminPin = NULL;

		unsigned int cbDateTime = 0;
		char* pbDateTime = NULL;

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pbAdminPin, &cbAdminPin);

			// Convert input Date/Time from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCharPtr(dateTime, &pbDateTime, &cbDateTime);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'pbAdminPin', 'pbDateTime'.
			if (pbAdminPin != NULL)
			{
				delete[] pbAdminPin;
				pbAdminPin = NULL;
			}

			if (pbDateTime != NULL)
			{
				delete[] pbDateTime;
				pbDateTime = NULL;
			}

			throw;
		}

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Set the device's clock.
			rv = CM_SetClock((int)deviceNumber, (const unsigned char *)pbAdminPin, (const char *)pbDateTime);

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Deallocate memory for 'pbAdminPin', 'pbDateTime'.
		delete[] pbAdminPin;
		pbAdminPin = NULL;
		delete[] pbDateTime;
		pbDateTime = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Tamper the device.
	/// <para>This will erase all stored keys and data, returning the device to it's original out of the box state, i.e. uninitializes Admin Token and one user slot).</para>
	/// <para>This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
	/// </summary>
	void Cryptoki::TamperAdapter(UInt32 deviceNumber, String^ adminPIN)
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
			// Tamper the device.
			rv = CM_TamperAdapter((int)deviceNumber, (const unsigned char *)pbAdminPin);

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
	/// Halt the device.
	/// <para>The device will no longer be visible to Cryptoki applications until hsmreset.exe is executed.</para>
	/// </summary>
	void Cryptoki::HaltAdapter(UInt32 deviceNumber, String^ adminPIN)
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
			// Halt the device.
			rv = CM_HaltAdapter((int)deviceNumber, (const unsigned char *)pbAdminPin);

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
	/// Returns the real HSM id for the specified user Slot ID.
	/// </summary>
	void Cryptoki::GetDeviceNumberFromSlotID(UInt32 slotID, UInt32% deviceID)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CM_SlotRef slotRef;

		// Finalize the cryptoki library.
		_rv = C_Finalize(NULL);

		// Initialize Cprov Management library.
		rv = CM_Initialize();
		if (rv == CKR_OK)
		{
			// Convert slot ID to Slot Reference
			rv = CM_SlotIdToSlotRef((CK_SLOT_ID)slotID, &slotRef);
			if (rv == CKR_OK)
				deviceID = (UInt32)slotRef.deviceNumber;

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Retrieve information concerning a device or slot.
	/// </summary>
	void Cryptoki::GetDeviceInfo(UInt32 deviceNumber, Int32 itemNumber, DeviceInfoType eInfo, String^% info)
	{
		const int MAX_E_INFO = 4096;
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;
		int deviceID = deviceNumber;
		int ItemNumber;
		CM_eInfo cm_eInfo = (CM_eInfo)eInfo;
		CK_ULONG infoLong = 0;

		char strInfo[MAX_E_INFO] = { NULL };
		int strLength = MAX_E_INFO;

		try
		{
			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// set the ItemNumber if required
			if (eInfo == DeviceInfoType::TOKEN_NAME || eInfo == DeviceInfoType::TOTAL_SESSION_COUNT)
				ItemNumber = itemNumber;
			else
				ItemNumber = (int)((CM_eInfo)eInfo);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Retrieve numeric information
				if (eInfo == DeviceInfoType::SECURITY_MODE || eInfo == DeviceInfoType::BATTERY_STATUS || eInfo == DeviceInfoType::EXTERNAL_PINS
					|| eInfo == DeviceInfoType::FREE_MEMORY || eInfo == DeviceInfoType::TOTAL_PUBLIC_MEMORY || eInfo == DeviceInfoType::FREE_PUBLIC_MEMORY
					|| eInfo == DeviceInfoType::TOTAL_SESSION_COUNT || eInfo == DeviceInfoType::DEVICE_COUNT || eInfo == DeviceInfoType::SLOT_COUNT
					|| eInfo == DeviceInfoType::EVENT_LOG_COUNT || eInfo == DeviceInfoType::EVENT_LOG_FULL || eInfo == DeviceInfoType::DEVICE_INITIALISED
					|| eInfo == DeviceInfoType::APPLICATION_COUNT || eInfo == DeviceInfoType::TOKEN_SESSION_COUNT || eInfo == DeviceInfoType::FM_ROM_SIZE
					|| eInfo == DeviceInfoType::FM_RAM_SIZE || eInfo == DeviceInfoType::DEVICE_ALLOWS_FM || eInfo == DeviceInfoType::FM_STARTUP_STATUS
					|| eInfo == DeviceInfoType::RTC_AAC_ENABLED || eInfo == DeviceInfoType::RTC_AAC_GUARD_SECONDS || eInfo == DeviceInfoType::RTC_AAC_GUARD_COUNT
					|| eInfo == DeviceInfoType::RTC_AAC_GUARD_DURATION
#ifdef _PTKC_V500_
					|| eInfo == DeviceInfoType::TEMPERATURE
					|| eInfo == DeviceInfoType::HSM_SESSION_COUNT
#endif
					)
				{
					rv = CM_GetInfoLong(deviceID, itemNumber, cm_eInfo, &infoLong);
					if (rv == CKR_OK)
					{
						if (eInfo == DeviceInfoType::EVENT_LOG_FULL ||
							eInfo == DeviceInfoType::DEVICE_INITIALISED ||
							eInfo == DeviceInfoType::DEVICE_ALLOWS_FM ||
							eInfo == DeviceInfoType::RTC_AAC_ENABLED ||
							eInfo == DeviceInfoType::RTC_AAC_GUARD_SECONDS ||
							eInfo == DeviceInfoType::RTC_AAC_GUARD_COUNT ||
							eInfo == DeviceInfoType::RTC_AAC_GUARD_DURATION)
							info = ((Boolean)infoLong).ToString();
						else if (eInfo == DeviceInfoType::TRANSPORT_MODE)
							info = ((TransportMode)infoLong).ToString();
						else if (eInfo == DeviceInfoType::FM_STATUS)
							info = ((FMStatus)infoLong).ToString();
						else if (eInfo == DeviceInfoType::BATTERY_STATUS)
							info = ((BatteryStatus)infoLong).ToString();
						else
							info = ((UInt32)infoLong).ToString();
					}
				}
				if (eInfo == DeviceInfoType::MAX_INFO)
				{
					rv = CM_GetInfo(deviceID, 0, cm_eInfo, strInfo, &strLength);
					if (rv == CKR_OK)
						Utils::ConvertCharPtrToString(strInfo, info);
				}
				else // Retrieve string information
				{
					rv = CM_GetInfo(deviceID, itemNumber, cm_eInfo, strInfo, &strLength);
					if (rv == CKR_OK)
						Utils::ConvertCharPtrToString(strInfo, info);
				}

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
	}

	/// <summary>
	/// Retrieve an event log instance.
	/// <para>Use GetDeviceInfo with EVENT_LOG_COUNT to determine valid values for zero based index.</para>
	/// </summary>
	void Cryptoki::GetEventLogEntry(UInt32 deviceNumber, String^ adminPIN, UInt32 index, String^% entryLog)
	{
		const int MAX_LOG_LEN = 128;
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;
		int indx = index;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		char strEntry[MAX_LOG_LEN] = { NULL };
		int strEntryLen = MAX_LOG_LEN;

		// Input data validation check.
		if (String::IsNullOrEmpty(adminPIN)) throw gcnew SecureModuleException("adminPIN is nullptr or an Empty string.");

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pin, &pin_len);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Retrieve event log.
				rv = CM_GetEventLogEntry(deviceID, pin, indx, strEntry, &strEntryLen);
				if (rv == CKR_OK)
				{
					Utils::ConvertCharPtrToString(strEntry, strEntryLen, entryLog);
				}

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of 'pin'.
			if (pin != NULL) delete[] pin;
			pin = NULL;
		}
	}

	/// <summary>
	/// Purge the full event log of the device.
	/// <para>This function will only purge the event log if it is full. Use GetDeviceInfo with EVENT_LOG_FULL to check.</para>
	/// </summary>
	void Cryptoki::PurgeEventLog(UInt32 deviceNumber, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(adminPIN)) throw gcnew SecureModuleException("adminPIN is nullptr or an Empty string.");

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pin, &pin_len);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Purge event log.
				rv = CM_PurgeEventLog(deviceID, pin);

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of 'pin'.
			if (pin != NULL) delete[] pin;
			pin = NULL;
		}
	}

	/// <summary>
	/// Upgrade the firmware of the device.
	/// </summary>
	void Cryptoki::UpgradeFirmware(UInt32 deviceNumber, String^ adminPIN, String^ fileName, Boolean verifyOnly)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		int vrfyOnly = (int)verifyOnly;

		char* file_name = NULL;
		unsigned int file_name_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(adminPIN)) throw gcnew SecureModuleException("adminPIN is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(fileName)) throw gcnew SecureModuleException("fileName is nullptr or an Empty string.");

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pin, &pin_len);

			// Convert fileName from System::String to char*.
			Utils::ConvertStringToCharPtr(fileName, &file_name, &file_name_len);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Upgrade the firmware.
				rv = CM_UpgradeFirmware(deviceID, pin, file_name, vrfyOnly);

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of 'pin' and 'file_name'.
			if (pin != NULL) delete[] pin;
			pin = NULL;

			if (file_name != NULL) delete[] file_name;
			file_name = NULL;
		}
	}

	/// <summary>
	/// Download a Functionality Module to a device.
	/// <para>Note: If the firmware upgrade procedure is interrupted, the device may be left in an unusable state.Therefore, the caller must ensure that the operation cannot be terminated by the user, before this function returns.</para>
	/// <para>Note: This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
	/// </summary>
	void Cryptoki::UpgradeFirmware(UInt32 deviceNumber, String^ adminPIN, String^ fileName, String^ certName, Boolean verifyOnly)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		int vrfyOnly = (int)verifyOnly;

		char* file_name = NULL;
		unsigned int file_name_len = 0;

		char* cert_name = NULL;
		unsigned int cert_name_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(adminPIN)) throw gcnew SecureModuleException("adminPIN is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(fileName)) throw gcnew SecureModuleException("fileName is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(certName)) throw gcnew SecureModuleException("certName is nullptr or an Empty string.");

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pin, &pin_len);

			// Convert fileName from System::String to char*.
			Utils::ConvertStringToCharPtr(fileName, &file_name, &file_name_len);

			// Convert certName from System::String to char*.
			Utils::ConvertStringToCharPtr(certName, &cert_name, &cert_name_len);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Download FM to the device.
				rv = CM_DownloadFm(deviceID, pin, file_name, cert_name, vrfyOnly);

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of 'pin', 'cert_name' and 'file_name'.
			if (pin != NULL) delete[] pin;
			pin = NULL;

			if (cert_name != NULL) delete[] cert_name;
			cert_name = NULL;

			if (file_name != NULL) delete[] file_name;
			file_name = NULL;
		}
	}

	/// <summary>
	/// Disable the downloaded FM in the device.
	/// <para>Note: This function does not check whether the FM is already disabled or not.If a FM that is already disabled is disabled again, the function will report success.</para>
	/// </summary>
	void Cryptoki::DisableFm(UInt32 deviceNumber, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		char* pin = NULL;
		unsigned int pin_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(adminPIN)) throw gcnew SecureModuleException("adminPIN is nullptr or an Empty string.");

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCharPtr(adminPIN, &pin, &pin_len);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Disable the FM.
				rv = CM_DisableFm(deviceID, pin);

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of 'pin'.
			if (pin != NULL) delete[] pin;
			pin = NULL;
		}
	}

	/// <summary>
	/// Force a detection of the peripheral devices.
	/// <para>Note: This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
	/// </summary>
	void Cryptoki::RescanPeripherals(UInt32 deviceNumber, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(adminPIN)) throw gcnew SecureModuleException("adminPIN is nullptr or an Empty string.");

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pin, &pin_len);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Detection of the peripheral devices
				rv = CM_RescanPeripherals(deviceID, pin);

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of 'pin'.
			if (pin != NULL) delete[] pin;
			pin = NULL;
		}
	}

	/// <summary>
	/// Set a value within the secure config of a device for the specified domain. A domain is a collection of configuration items belonging, generally, to a specific application.
	/// </summary>
	void Cryptoki::SetHSMConfigItem(UInt32 deviceNumber, String^ adminPIN, String^ configDomain, String^ item, String^ value)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		char* configDomain_data = NULL;
		unsigned int configDomain_data_len = 0;

		char* item_data = NULL;
		unsigned int item_data_len = 0;

		char* value_data = NULL;
		unsigned int value_data_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(adminPIN)) throw gcnew SecureModuleException("adminPIN is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(configDomain)) throw gcnew SecureModuleException("configDomain is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(item)) throw gcnew SecureModuleException("item is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(value)) throw gcnew SecureModuleException("value is nullptr or an Empty string.");

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pin, &pin_len);

			// Convert configDomain from System::String to char*.
			Utils::ConvertStringToCharPtr(configDomain, &configDomain_data, &configDomain_data_len);

			// Convert item from System::String to char*.
			Utils::ConvertStringToCharPtr(item, &item_data, &item_data_len);

			// Convert value from System::String to char*.
			Utils::ConvertStringToCharPtr(value, &value_data, &value_data_len);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Set the secure config of device.
				rv = CM_SetConfigItem(deviceID, pin, configDomain_data, item_data, value_data);

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of 'pin', 'configDomain_data', 'item_data' and 'value_data'.
			if (pin != NULL) delete[] pin;
			pin = NULL;

			if (configDomain_data != NULL) delete[] configDomain_data;
			configDomain_data = NULL;

			if (item_data != NULL) delete[] item_data;
			item_data = NULL;

			if (value_data != NULL) delete[] value_data;
			value_data = NULL;
		}
	}

	/// <summary>
	/// Get a value from the secure config of a device for the specified domain. A domain is a collection of configuration items belonging, generally, to a specific application.
	/// </summary>
	void Cryptoki::GetConfigItem(UInt32 deviceNumber, String^ configDomain, String^ item, String^% value)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		char* configDomain_data = NULL;
		unsigned int configDomain_data_len = 0;

		char* item_data = NULL;
		unsigned int item_data_len = 0;

		char* value_data = NULL;
		int value_data_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(configDomain)) throw gcnew SecureModuleException("configDomain is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(item)) throw gcnew SecureModuleException("item is nullptr or an Empty string.");

		try
		{
			// Convert configDomain from System::String to char*.
			Utils::ConvertStringToCharPtr(configDomain, &configDomain_data, &configDomain_data_len);

			// Convert item from System::String to char*.
			Utils::ConvertStringToCharPtr(item, &item_data, &item_data_len);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Get value from the secure config of device.
				rv = CM_GetConfigItem(deviceID, configDomain_data, item_data, NULL, &value_data_len);

				// Convert value from char* to System::String.
				if (rv == CKR_OK)
				{
					// memory allocation.
					value_data = new char[value_data_len];

					// Get value from the secure config of device.
					rv = CM_GetConfigItem(deviceID, configDomain_data, item_data, value_data, &value_data_len);

					if (rv == CKR_OK)
					{
						Utils::ConvertCharPtrToString(value_data, value_data_len, value);
					}
				}

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Check if resulting an exception.
			if (rv != CKR_OK)
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of 'configDomain_data', 'item_data' and 'value_data'.
			if (configDomain_data != NULL) delete[] configDomain_data;
			configDomain_data = NULL;

			if (item_data != NULL) delete[] item_data;
			item_data = NULL;

			if (value_data != NULL) delete[] value_data;
			value_data = NULL;
		}
	}
}