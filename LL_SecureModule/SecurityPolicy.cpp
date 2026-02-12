#include "stdafx.h"

#include "LL_SecureModule.h"
#include "Utils.h"

#include <cmlib.h>

namespace LL_SecureModule
{
	/// <summary>
	/// Set the security mode of the device.
	/// </summary>
	void Cryptoki::SetDeviceSecurityMode(int deviceNumber, String^ adminPIN, SecurityFlag securityMode)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;

		CK_ULONG cbAdminPin = 0;
		CK_CHAR_PTR pbAdminPin = NULL;

		try
		{
			// Convert Admin PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(adminPIN, &pbAdminPin, &cbAdminPin);

			// Finalize the cryptoki library.
			_rv = C_Finalize(NULL);

			// Initialize Cprov Management library.
			rv = CM_Initialize();
			if (rv == CKR_OK)
			{
				// Set Security Policy.
				rv = CM_SetSecurityMode(deviceNumber, pbAdminPin, (CK_FLAGS)securityMode);

				// Finalize Cprov Management library.
				_rv = CM_Finalize();
			}

			// Deallocate memory for 'pbAdminPin'
			if (pbAdminPin != NULL)
			{
				delete[] pbAdminPin;
				pbAdminPin = NULL;
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
	}

	/// <summary>
	/// Get the device current security mode.
	/// <para>The 32-bit value is going to be the logical OR of various security CKF_XXX flags.</para>
	/// </summary>
	void Cryptoki::GetDeviceSecurityMode(UInt32 deviceNumber, UInt32% securityMode)
	{
		CK_RV rv = CKR_OK;
		CK_RV _rv = CKR_OK;
		int deviceID = deviceNumber;
		int itemNumber = (int)(CM_SECURITY_MODE);
		CM_eInfo eInfo = CM_SECURITY_MODE;
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
				securityMode = (UInt32)info;

			// Finalize Cprov Management library.
			_rv = CM_Finalize();
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Get the device current security mode.
	/// </summary>
	void Cryptoki::GetDeviceSecurityMode(UInt32 deviceNumber, System::Collections::Generic::Dictionary<SecurityFlag, Boolean>^% securityMode)
	{
		CK_RV rv = CKR_OK;
		try
		{
			UInt32 secMode = 0;
			securityMode = gcnew System::Collections::Generic::Dictionary<SecurityFlag, Boolean>();
			GetDeviceSecurityMode(deviceNumber, secMode);
			securityMode->Add(SecurityFlag::ENTRUST_READY, Convert::ToBoolean((UInt32)SecurityFlag::ENTRUST_READY & secMode));///???(Boolean)((UInt32)SecurityFlag::ENTRUST_READY & secMode));
			securityMode->Add(SecurityFlag::NO_CLEAR_PINS, Convert::ToBoolean((UInt32)SecurityFlag::NO_CLEAR_PINS & secMode));
			securityMode->Add(SecurityFlag::AUTH_PROTECTION, Convert::ToBoolean((UInt32)SecurityFlag::AUTH_PROTECTION & secMode));
			securityMode->Add(SecurityFlag::NO_PUBLIC_CRYPTO, Convert::ToBoolean((UInt32)SecurityFlag::NO_PUBLIC_CRYPTO & secMode));
			securityMode->Add(SecurityFlag::TAMPER_BEFORE_UPGRADE, Convert::ToBoolean((UInt32)SecurityFlag::TAMPER_BEFORE_UPGRADE & secMode));
			securityMode->Add(SecurityFlag::INCREASED_SECURITY, Convert::ToBoolean((UInt32)SecurityFlag::INCREASED_SECURITY & secMode));
			securityMode->Add(SecurityFlag::FIPS_ALGORITHMS, Convert::ToBoolean((UInt32)SecurityFlag::FIPS_ALGORITHMS & secMode));
			securityMode->Add(SecurityFlag::FULL_SMS_ENC, Convert::ToBoolean((UInt32)SecurityFlag::FULL_SMS_ENC & secMode));
			securityMode->Add(SecurityFlag::FULL_SMS_SIGN, Convert::ToBoolean((UInt32)SecurityFlag::FULL_SMS_SIGN & secMode));
			securityMode->Add(SecurityFlag::PURE_P11, Convert::ToBoolean((UInt32)SecurityFlag::PURE_P11 & secMode));
			securityMode->Add(SecurityFlag::DES_EVEN_PARITY_ALLOWED, Convert::ToBoolean((UInt32)SecurityFlag::DES_EVEN_PARITY_ALLOWED & secMode));
			securityMode->Add(SecurityFlag::USER_ECC_DP_ALLOWED, Convert::ToBoolean((UInt32)SecurityFlag::USER_ECC_DP_ALLOWED & secMode));
			securityMode->Add(SecurityFlag::MODE_LOCKED, Convert::ToBoolean((UInt32)SecurityFlag::MODE_LOCKED & secMode));
		}
		catch (SecureModuleException^)
		{
			throw;
		}
		catch (Exception^ ex)
		{
			rv = CKR_FUNCTION_FAILED;
			throw gcnew SecureModuleException(rv, "Cryptoki::GetDeviceSecurityMode(...)", ex);
		}
	}

	/// <summary>
	/// Get the specific flag in current security mode.
	/// </summary>
	void Cryptoki::GetSecurityFlagStatus(UInt32 deviceNumber, SecurityFlag flag, Boolean% status)
	{
		CK_RV rv = CKR_OK;
		try
		{
			UInt32 securityMode = 0;
			GetDeviceSecurityMode(deviceNumber, securityMode);
			status = Convert::ToBoolean((UInt32)flag & securityMode);///???(Boolean)((UInt32)flag & securityMode);
		}
		catch (SecureModuleException^)
		{
			throw;
		}
		catch (Exception^ ex)
		{
			rv = CKR_FUNCTION_FAILED;
			throw gcnew SecureModuleException(rv, "Cryptoki::GetSecurityFlagStatus(...)", ex);
		}
	}

	/// <summary>
	/// Set the specific flag status in device security mode.
	/// </summary>
	void Cryptoki::SetSecurityFlagStatus(UInt32 deviceNumber, String^ adminPIN, SecurityFlag flag, Boolean status)
	{
		CK_RV rv = CKR_OK;
		try
		{
			UInt32 current_securityMode = 0;
			UInt32 new_securityMode = 0;
			Boolean current_status = false;
			GetSecurityFlagStatus(deviceNumber, flag, current_status);
			if (status != current_status)
			{
				GetDeviceSecurityMode(deviceNumber, current_securityMode);
				new_securityMode = (UInt32)flag ^ current_securityMode;
				SetDeviceSecurityMode(deviceNumber, adminPIN, (SecurityFlag)new_securityMode);
			}
		}
		catch (SecureModuleException^)
		{
			throw;
		}
		catch (Exception^ ex)
		{
			rv = CKR_FUNCTION_FAILED;
			throw gcnew SecureModuleException(rv, "Cryptoki::SetSecurityFlagStatus(...)", ex);
		}
	}
}