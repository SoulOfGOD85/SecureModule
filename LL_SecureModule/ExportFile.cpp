#include "stdafx.h"

#include "Object.h"
#include "Utils.h"

#include <kmlib.h>

namespace LL_SecureModule
{
	/// <summary>
	/// Export(Wrap) object(s) to a file using wrap key with SafeNet format.
	/// </summary>
	void SMObject::ExportToFile(array<SMObject^>^ objects, String^ fileName)
	{
		CK_RV rv = CKR_OK;
		CK_ULONG i = 0;

		CK_OBJECT_HANDLE_PTR phWrapeeObjs = NULL;
		CK_ULONG numWrapeeObjs = 0;

		unsigned int pszFileNameLen = 0;
		char* pszFileName = NULL;

		try
		{
			// Input data validation check.
			if (String::IsNullOrEmpty(fileName)) throw gcnew SecureModuleException("fileName is null or empty.");
			if (objects == nullptr || objects->Length == 0) throw gcnew SecureModuleException("objects array is null or empty.");

			numWrapeeObjs = objects->Length;
			phWrapeeObjs = new CK_OBJECT_HANDLE[numWrapeeObjs];
			for (i = 0; i < numWrapeeObjs; i++)
				phWrapeeObjs[i] = objects[i]->hObject;

			// Convert fileName from String to char*.
			Utils::ConvertStringToCharPtr(fileName, &pszFileName, &pszFileNameLen);

			// Export to the destination file
			rv = KM_ExportToFile(this->object_session->SessionID, phWrapeeObjs, numWrapeeObjs, this->hObject, (const char *)pszFileName);

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
			// Deallocate memory of 'pszFileName' and 'phWrapeeObjs'.
			if (pszFileName != NULL) delete[] pszFileName;
			pszFileName = NULL;
			pszFileNameLen = 0;

			if (phWrapeeObjs != NULL) delete[] phWrapeeObjs;
			phWrapeeObjs = NULL;
			numWrapeeObjs = 0;
		}
	}

	/// <summary>
	/// import(Unwrap) objects from a file using wrap key with SafeNet format.
	/// </summary>
	void SMObject::ImportFromFile(String^ fileName, UInt32 importVersion)
	{
		CK_RV rv = CKR_OK;

		unsigned int pszFileNameLen = 0;
		char* pszFileName = NULL;

		try
		{
			// Input data validation check.
			if (String::IsNullOrEmpty(fileName)) throw gcnew SecureModuleException("fileName is null or empty.");

			// Convert fileName from String to char*.
			Utils::ConvertStringToCharPtr(fileName, &pszFileName, &pszFileNameLen);

			// Import objects from file.
			rv = KM_ImportFromFile(this->object_session->SessionID, (const char *)pszFileName, this->hObject, (CK_ULONG)importVersion);

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
			// Deallocate memory of 'pszFileName'.
			if (pszFileName != NULL) delete[] pszFileName;
			pszFileName = NULL;
			pszFileNameLen = 0;
		}
	}
}