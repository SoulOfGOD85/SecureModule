// This is the main DLL file.

#include "stdafx.h"

#include "LL_SecureModule.h"
#include "Utils.h"

#include <cmlib.h>
#include <ctfext.h>
#include <hsmadmin.h>

using namespace System;

namespace LL_SecureModule {
	/// <summary>
	/// Obtains general information about Cryptoki library.
	/// </summary>

	void Cryptoki::GetInfo(CryptokiInfo^% cryptokiInfo)
	{
		CK_RV rv = CKR_OK;
		CK_INFO info;

		String^ str = "";

		// Get cryptoki information.
		rv = C_GetInfo(&info);

		//
		if (rv == CKR_OK && cryptokiInfo != nullptr)
		{
			try
			{
				// Convert library description from CK_CHAR_PTR to System::String
				Utils::ConvertCKCharPtrToString(info.libraryDescription, CK_LIB_DESC_SIZE, str);

				cryptokiInfo->LibraryDescription = str->TrimEnd();

				// Convert manufacturer's ID from CK_CHAR_PTR to System::String
				Utils::ConvertCKCharPtrToString(info.manufacturerID, CK_MANUFACTURER_SIZE, str);

				cryptokiInfo->ManufacturerID = str->TrimEnd();

				// Sets Flags
				cryptokiInfo->Flags = (UInt32)info.flags;

				// Sets the version of library
				cryptokiInfo->LibraryVersion->Major = (Byte)info.libraryVersion.major;
				cryptokiInfo->LibraryVersion->Minor = (Byte)info.libraryVersion.minor;

				// Sets the version of cryptoki
				cryptokiInfo->CryptokiVersion->Major = (Byte)info.cryptokiVersion.major;
				cryptokiInfo->CryptokiVersion->Minor = (Byte)info.cryptokiVersion.minor;
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
	/// Gets the usage level of the HSM as a percentage i.e. the load on the HSM.
	/// </summary>
	void Cryptoki::GetHSMUsageLevel(UInt32 deviceID, UInt32% value)
	{
		CK_RV rv = CKR_OK;
		unsigned long usage = 0;

		//
		rv = HSMADM_GetHsmUsageLevel((unsigned int)deviceID, &usage);

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));

		value = (UInt32)usage;
	}

#ifndef _PTKC_V400_
	/// <summary>
	/// This function can be used by an application to simulate the behavior of the WLD or HA system when an HSM fails.
	/// </summary>
	void Cryptoki::SetDeviceDead(UInt32 deviceID, Boolean disable)
	{
		CK_RV rv = CKR_OK;
		CK_BBOOL bDisable = (CK_BBOOL)disable;

		//
		rv = CT_SetHsmDead((CK_ULONG)deviceID, bDisable);

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}
#endif

	/// <summary>
	/// Initializes the Cryptoki library.
	/// </summary>
	void Cryptoki::CInitialize(Boolean useOSThreading)
	{
		CK_RV rv = CKR_OK;

		// This value points to a CK_C_INITIALIZE_ARGS structure containing information on how the library should deal with multi-threaded access.
		// If an application will not be accessing Cryptoki through multiple threads simultaneously, it can generally supply the value NULL_PTR to C_Initialize
		CK_C_INITIALIZE_ARGS_PTR initArgs = NULL;

		if (useOSThreading)
		{
			// Allocates memory for 'initArgs'.
			initArgs = new CK_C_INITIALIZE_ARGS();

			// If memory allocation was unsuccessful.
			if (initArgs == NULL)
				throw gcnew SecureModuleException(CKR_HOST_MEMORY, "Memory allocation was unsuccessful.");

			initArgs->CreateMutex = NULL;
			initArgs->DestroyMutex = NULL;
			initArgs->LockMutex = NULL;
			initArgs->UnlockMutex = NULL;
			initArgs->pReserved = NULL;

			// The library can use the native operation system threading model for locking.
			initArgs->flags = CKF_OS_LOCKING_OK;
		}

		// Initialize the library.
		rv = C_Initialize(initArgs);

		// Deallocate memory for 'initArgs'.
		delete initArgs;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Finalize the Cryptoki library.
	/// </summary>
	void Cryptoki::CFinalize()
	{
		CK_RV rv = CKR_OK;

		// Finalize the library.
		rv = C_Finalize(NULL);

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}
}
