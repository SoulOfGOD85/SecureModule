#include "stdafx.h"

#include "LL_SecureModule.h"
#include "Utils.h"

#include <cmlib.h>

namespace LL_SecureModule
{
	/// <summary>
	/// Set new parameters for the RTC Adjustment Access Control (AAC) for the specified device.
	/// <para>These parameters control how much of an adjustment can be made to the RTC within a specified duration using the unauthenticated HSMADM_AdjustTime() function.</para>
	/// </summary>
	void Cryptoki::SetRtcAacEnabled(UInt32 deviceNumber, Boolean aacEnabled, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		CK_BBOOL enabled = (CK_BBOOL)aacEnabled;

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
				// Set new parameters for the RTC Adjustment Access Control (AAC).
				rv = CM_SetRtcAacEnabled(deviceID, enabled, pin);

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
	/// Set new parameters for the RTC Adjustment Access Control (AAC) for the specified device.
	/// <para>These parameters control how much of an adjustment can be made to the RTC within a specified duration using the unauthenticated HSMADM_AdjustTime() function.</para>
	/// </summary>
	void Cryptoki::SetRtcAacSeconds(UInt32 deviceNumber, UInt32 guardSeconds, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		CK_NUMERIC seconds = (CK_NUMERIC)guardSeconds;

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
				// Set new parameters for the RTC Adjustment Access Control (AAC).
				rv = CM_SetRtcAacSeconds(deviceID, seconds, pin);

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
	/// Set new parameters for the RTC Adjustment Access Control (AAC) for the specified device.
	/// <para>These parameters control how much of an adjustment can be made to the RTC within a specified duration using the unauthenticated HSMADM_AdjustTime() function.</para>
	/// </summary>
	void Cryptoki::SetRtcAacCount(UInt32 deviceNumber, UInt32 guardCount, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		CK_NUMERIC count = (CK_NUMERIC)guardCount;

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
				// Set new parameters for the RTC Adjustment Access Control (AAC).
				rv = CM_SetRtcAacSeconds(deviceID, count, pin);

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
	/// Set new parameters for the RTC Adjustment Access Control (AAC) for the specified device.
	/// <para>These parameters control how much of an adjustment can be made to the RTC within a specified duration using the unauthenticated HSMADM_AdjustTime() function.</para>
	/// </summary>
	void Cryptoki::SetRtcAacDuration(UInt32 deviceNumber, UInt32 durationDays, String^ adminPIN)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		int deviceID = deviceNumber;

		CK_CHAR_PTR pin = NULL;
		CK_ULONG pin_len = 0;

		CK_NUMERIC days = (CK_NUMERIC)durationDays;

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
				// Set new parameters for the RTC Adjustment Access Control (AAC).
				rv = CM_SetRtcAacSeconds(deviceID, days, pin);

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
	/// Obtain the current time of day from the HSM RTC.
	/// </summary>
	void Cryptoki::HSMAdmin_GetTimeOfDay(UInt32 deviceNumber, HSMAdminTime^% adminTime)
	{
		HSMADM_RV rv = HSMADM_OK;

		unsigned int hsmIndex = deviceNumber;
		HSMADM_TimeVal_t tv;

		try
		{
			// Obtain the current time of day from the HSM RTC.
			rv = HSMADM_GetTimeOfDay(hsmIndex, &tv);

			// Check the error code.
			if (rv == HSMADM_OK)
			{
				adminTime = gcnew HSMAdminTime(tv.tv_sec, tv.tv_usec);
			}
			else // if resulting an exception
				throw gcnew SecureModuleException(rv, "HSM Admin Error: " + Utils::GetHSMAdminErrorString(rv) + "\tDescription message: " + Utils::GetHSMAdminErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
	}

	/// <summary>
	/// Either adjust the time, or obtain the current adjustment value.
	/// <para>The parameter, delta, indicates the adjustment factor to be applied to the HSM RTC.</para>
	/// <para>If there is an adjustment being performed when this function is called, the remaining adjustment factor is discarded, and the new adjustment value is used instead.</para>
	/// <para>This function can also be used to obtain the remaining adjustment amount.</para>
	/// <para>If the parameter delta is NULL, and oldDelta is a valid pointer, it will return the current delta value.</para>
	/// </summary>
	void Cryptoki::HSMAdmin_AdjustTime(UInt32 deviceNumber, HSMAdminTime^ delta, HSMAdminTime^% oldDelta)
	{
		HSMADM_RV rv = HSMADM_OK;

		unsigned int hsmIndex = deviceNumber;
		HSMADM_TimeVal_t *_delta = NULL;
		HSMADM_TimeVal_t *old_delta = NULL;

		try
		{
			if (delta != nullptr)
			{
				_delta = new HSMADM_TimeVal_t();
				_delta->tv_sec = delta->Second;
				_delta->tv_usec = delta->uSecond;
			}

			if (oldDelta != nullptr)
			{
				old_delta = new HSMADM_TimeVal_t();
				old_delta->tv_sec = oldDelta->Second;
				old_delta->tv_usec = oldDelta->uSecond;
			}

			// Adjust the time.
			rv = HSMADM_AdjustTime(hsmIndex, _delta, old_delta);

			// Check the error code.
			if (rv == HSMADM_OK)
			{
				oldDelta = gcnew HSMAdminTime(old_delta->tv_sec, old_delta->tv_usec);
			}
			else // if resulting an exception
				throw gcnew SecureModuleException(rv, "HSM Admin Error: " + Utils::GetHSMAdminErrorString(rv) + "\tDescription message: " + Utils::GetHSMAdminErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
		finally
		{
			// Deallocate memory of '_delta' and 'old_delta'.
			if (_delta != NULL) delete _delta;
			_delta = NULL;

			if (old_delta != NULL) delete old_delta;
			old_delta = NULL;
		}
	}

	/// <summary>
	/// Change the HSM RTC status. An external manager may use this function to change the status of the RTC.
	/// </summary>
	void Cryptoki::HSMAdmin_SetRtcStatus(UInt32 deviceNumber, RTCStatus status)
	{
		HSMADM_RV rv = HSMADM_OK;

		unsigned int hsmIndex = deviceNumber;
		HSMADM_RtcStatus_t _status = (HSMADM_RtcStatus_t)status;

		try
		{
			// Change the HSM RTC status.
			rv = HSMADM_SetRtcStatus(hsmIndex, _status);

			// Check if resulting an exception
			if (rv != HSMADM_OK)
				throw gcnew SecureModuleException(rv, "HSM Admin Error: " + Utils::GetHSMAdminErrorString(rv) + "\tDescription message: " + Utils::GetHSMAdminErrorDescription(rv));
		}
		catch (Exception^)
		{
			throw;
		}
	}

	/// <summary>
	/// Obtain the HSM RTC status. An application may use this function to determine the availability or reliability of the RTC.
	/// </summary>
	RTCStatus Cryptoki::HSMAdmin_GetRtcStatus(UInt32 deviceNumber)
	{
		HSMADM_RV rv = HSMADM_OK;

		unsigned int hsmIndex = deviceNumber;
		HSMADM_RtcStatus_t status;

		try
		{
			// Obtain the HSM RTC status.
			rv = HSMADM_GetRtcStatus(hsmIndex, &status);

			// Check if resulting an exception
			if (rv != HSMADM_OK)
				throw gcnew SecureModuleException(rv, "HSM Admin Error: " + Utils::GetHSMAdminErrorString(rv) + "\tDescription message: " + Utils::GetHSMAdminErrorDescription(rv));

			return (RTCStatus)status;
		}
		catch (Exception^)
		{
			throw;
		}
	}

	/// <summary>
	/// Get the effective total amount, in milliseconds, of adjustments made to the RTC using the HSMADM_AdjustTime() function.
	/// </summary>
	UInt32 Cryptoki::HSMAdmin_GetRtcAdjustAmount(UInt32 deviceNumber)
	{
		HSMADM_RV rv = HSMADM_OK;

		unsigned int hsmIndex = deviceNumber;
		long adjustment;

		try
		{
			// Get the effective total amount of adjustments.
			rv = HSMADM_GetRtcAdjustAmount(hsmIndex, &adjustment);

			// Check if resulting an exception
			if (rv != HSMADM_OK)
				throw gcnew SecureModuleException(rv, "HSM Admin Error: " + Utils::GetHSMAdminErrorString(rv) + "\tDescription message: " + Utils::GetHSMAdminErrorDescription(rv));

			return (UInt32)adjustment;
		}
		catch (Exception^)
		{
			throw;
		}
	}

	/// <summary>
	/// Get the effective count of adjustments made to the RTC using the HSMADM_AdjustTime() function.
	/// </summary>
	UInt32 Cryptoki::HSMAdmin_GetRtcAdjustCount(UInt32 deviceNumber)
	{
		HSMADM_RV rv = HSMADM_OK;

		unsigned int hsmIndex = deviceNumber;
		unsigned long count;

		try
		{
			// Get the effective count of adjustments.
			rv = HSMADM_GetRtcAdjustCount(hsmIndex, &count);

			// Check if resulting an exception
			if (rv != HSMADM_OK)
				throw gcnew SecureModuleException(rv, "HSM Admin Error: " + Utils::GetHSMAdminErrorString(rv) + "\tDescription message: " + Utils::GetHSMAdminErrorDescription(rv));

			return (UInt32)count;
		}
		catch (Exception^)
		{
			throw;
		}
	}
}