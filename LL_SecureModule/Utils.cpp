#include "stdafx.h"

#include "Utils.h"
#include "Attribute.h"

namespace LL_SecureModule
{
	/// <summary>
	/// Default Class constructor.
	/// </summary>
	Utils::Utils(void)
	{
	}

	/// <summary>
	/// Convert bits to bytes.
	/// </summary>
	UInt32 Utils::ConvertBitsToBytes(UInt32 bits)
	{
		return ((bits + 7) / 8);
	}

	/// <summary>
	/// Convert hexadecimal String to Byte array.
	/// </summary>
	void Utils::ConvertHexStringToByteArray(String^ hexString, array<Byte>^% byteArray)
	{
		int i = 0, indx = 0;

		// Upper bound & Lower bound.
		int LB = 0, UB = 0;

		// temporary uppercase string.
		String^ str = String::Empty;

		try
		{
			// Input validation check.
			if (String::IsNullOrEmpty(hexString)) throw gcnew SecureModuleException("The specified string is nullptr or an Empty string.");
			if (hexString->Length % 2 != 0) throw gcnew SecureModuleException(CKR_DATA_LEN_RANGE, "The specified string's length is not even.");

			// Make uppercase string.
			str = hexString->ToUpper();

			// Allocates memory for 'byteArray'.
			byteArray = gcnew array<Byte>(str->Length / 2);

			// Get string hexadecimal values
			for (i = 0; i < str->Length - 1; i += 2)
			{
				switch (str[i])
				{
				case '0': UB = 0x00; break;
				case '1': UB = 0x01; break;
				case '2': UB = 0x02; break;
				case '3': UB = 0x03; break;
				case '4': UB = 0x04; break;
				case '5': UB = 0x05; break;
				case '6': UB = 0x06; break;
				case '7': UB = 0x07; break;
				case '8': UB = 0x08; break;
				case '9': UB = 0x09; break;
				case 'A': case 'a': UB = 0x0A; break;
				case 'B': case 'b': UB = 0x0B; break;
				case 'C': case 'c': UB = 0x0C; break;
				case 'D': case 'd': UB = 0x0D; break;
				case 'E': case 'e': UB = 0x0E; break;
				case 'F': case 'f': UB = 0x0F; break;
				default:
					throw gcnew SecureModuleException(CKR_DATA_INVALID, "The specified hexadecimal string is invalid.");
				}
				switch (str[i + 1])
				{
				case '0': LB = 0x00; break;
				case '1': LB = 0x01; break;
				case '2': LB = 0x02; break;
				case '3': LB = 0x03; break;
				case '4': LB = 0x04; break;
				case '5': LB = 0x05; break;
				case '6': LB = 0x06; break;
				case '7': LB = 0x07; break;
				case '8': LB = 0x08; break;
				case '9': LB = 0x09; break;
				case 'A': case 'a': LB = 0x0A; break;
				case 'B': case 'b': LB = 0x0B; break;
				case 'C': case 'c': LB = 0x0C; break;
				case 'D': case 'd': LB = 0x0D; break;
				case 'E': case 'e': LB = 0x0E; break;
				case 'F': case 'f': LB = 0x0F; break;
				default:
					throw gcnew SecureModuleException(CKR_DATA_INVALID, "The specified hexadecimal string is invalid.");
				}

				// Calculation of byte value from UB & LB
				byteArray[indx++] = (Byte)(UB * 0x10 + LB);
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
	}

	/// <summary>
	/// Convert String to CK_CHAR*.
	/// </summary>
	void Utils::ConvertStringToCKCharPtr(String^ string, CK_CHAR_PTR *CKCharPtr, CK_ULONG_PTR dataLength)
	{
		try
		{
			CK_ULONG i = 0;

			// Input validation check.
			if (String::IsNullOrEmpty(string)) throw gcnew SecureModuleException("The specified string is nullptr or an Empty string.");

			// Output validation check.
			if ((*CKCharPtr) != NULL) throw gcnew SecureModuleException("The CK_CHAR* is not a NULL pointer.");

			// Set output data length.
			(*dataLength) = string->Length;

			// Allocates memory for *CKCharPtr.
			(*CKCharPtr) = new CK_CHAR[(*dataLength) + 1];

			// If memory allocation was unsuccessful.
			if ((*CKCharPtr) == NULL)
				throw gcnew SecureModuleException(CKR_HOST_MEMORY, "Memory allocation was unsuccessful.");

			// Copy from 'string' to *CKCharPtr.
			for (i = 0; i < (*dataLength); i++)
				(*CKCharPtr)[i] = (CK_CHAR)string[i];

			// Add null-terminated.
			(*CKCharPtr)[i] = 0;
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
	/// Convert String to char*.
	/// </summary>
	void Utils::ConvertStringToCharPtr(String^ string, char* *charPtr, unsigned int *dataLength)
	{
		try
		{
			CK_ULONG i = 0;

			// Input validation check.
			if (String::IsNullOrEmpty(string)) throw gcnew SecureModuleException("The specified string is nullptr or an Empty string.");

			// Output validation check.
			if ((*charPtr) != NULL) throw gcnew SecureModuleException("The char* is not a NULL pointer.");

			// Set output data length.
			(*dataLength) = string->Length;

			// Allocates memory for *charPtr.
			(*charPtr) = new char[(*dataLength) + 1];

			// If memory allocation was unsuccessful.
			if ((*charPtr) == NULL)
				throw gcnew SecureModuleException(CKR_HOST_MEMORY, "Memory allocation was unsuccessful.");

			// Copy from 'string' to *charPtr.
			for (i = 0; i < (*dataLength); i++)
				(*charPtr)[i] = (char)string[i];

			// Add null-terminated.
			(*charPtr)[i] = 0;
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
	/// Convert CK_CHAR* to String.
	/// </summary>
	void Utils::ConvertCKCharPtrToString(CK_CHAR_PTR CKCharPtr, String^% string)
	{
		try
		{
			// Input validation check.
			if (CKCharPtr == NULL) throw gcnew SecureModuleException("The specified CK_CHAR* is a NULL pointer.");

			// Allocates memory for 'string'.
			string = gcnew String((const char *)CKCharPtr);
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
	/// Convert char* to String.
	/// </summary>
	void Utils::ConvertCharPtrToString(char* CharPtr, String^% string)
	{
		try
		{
			// Input validation check.
			if (CharPtr == NULL) throw gcnew SecureModuleException("The specified char* is a NULL pointer.");

			// Allocates memory for 'string'.
			string = gcnew String(CharPtr);
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
	/// Convert char* to String.
	/// </summary>
	void Utils::ConvertCharPtrToString(char* CharPtr, int dataLength, String^% string)
	{
		try
		{
			// Input validation check.
			if (CharPtr == NULL) throw gcnew SecureModuleException("The specified char* is a NULL pointer.");

			// Allocates memory for 'string'.
			string = gcnew String(CharPtr, 0, dataLength);
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
	/// Convert CK_CHAR* to String. This function can be used for CK_CHAR* with specific length or without null-terminated.
	/// </summary>
	void Utils::ConvertCKCharPtrToString(CK_CHAR_PTR CKCharPtr, CK_ULONG dataLength, String^% string)
	{
		try
		{
			// Input validation check.
			if (CKCharPtr == NULL) throw gcnew SecureModuleException("The specified CK_CHAR* is a NULL pointer.");
			if (dataLength == 0) throw gcnew SecureModuleException("The specified data length is zero.");

			// Allocates memory for 'charArray'.
			array<unsigned char>^ charArray = gcnew array<unsigned char>(dataLength);

			// Copy from 'CKCharPtr' to 'charArray'.
			for (CK_ULONG i = 0; i < dataLength; i++)
				charArray[i] = (unsigned char)CKCharPtr[i];

			// Convert sequence of bytes into a string.
			string = System::Text::Encoding::ASCII->GetString(charArray, 0, (int)dataLength);
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
	/// Convert Byte array to CK_BYTE*.
	/// </summary>
	void Utils::ConvertByteArrayToCKBytePtr(array<Byte>^ byteArray, CK_BYTE_PTR *CKBytePtr, CK_ULONG_PTR dataLength)
	{
		try
		{
			// Input validation check.
			if ((*CKBytePtr) != NULL) throw gcnew SecureModuleException("The CK_BYTE* is not a NULL pointer.");

			// Output validation check.
			if (byteArray == nullptr) throw gcnew SecureModuleException("The specified byte array is nullptr.");

			// Set output data length.
			(*dataLength) = byteArray->Length;

			// Allocates memory for *CKBytePtr.
			(*CKBytePtr) = new CK_BYTE[(*dataLength)];

			// If memory allocation was unsuccessful.
			if ((*CKBytePtr) == NULL)
				throw gcnew SecureModuleException(CKR_HOST_MEMORY, "Memory allocation was unsuccessful.");

			// Copy from 'byteArray' to *CKBytePtr.
			for (CK_ULONG i = 0; i < (*dataLength); i++)
				(*CKBytePtr)[i] = (CK_BYTE)byteArray[i];
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
	/// Convert Byte array to CK_CHAR*.
	/// </summary>
	void Utils::ConvertByteArrayToCKCharPtr(array<Byte>^ byteArray, CK_BYTE_PTR *CKCharPtr, CK_ULONG_PTR dataLength)
	{
		try
		{
			// Input validation check.
			if ((*CKCharPtr) != NULL) throw gcnew SecureModuleException("The CK_CHAR* is not a NULL pointer.");

			// Output validation check.
			if (byteArray == nullptr) throw gcnew SecureModuleException("The specified byte array is nullptr.");

			// Set output data length.
			(*dataLength) = byteArray->Length;

			// Allocates memory for *CKBytePtr.
			(*CKCharPtr) = new CK_CHAR[(*dataLength)];

			// If memory allocation was unsuccessful.
			if ((*CKCharPtr) == NULL)
				throw gcnew SecureModuleException(CKR_HOST_MEMORY, "Memory allocation was unsuccessful.");

			// Copy from 'byteArray' to *CKBytePtr.
			for (CK_ULONG i = 0; i < (*dataLength); i++)
				(*CKCharPtr)[i] = (CK_CHAR)byteArray[i];
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
	/// Convert CK_BYTE* to Byte array.
	/// </summary>
	void Utils::ConvertCKBytePtrToByteArray(CK_BYTE_PTR CKBytePtr, CK_ULONG dataLength, array<Byte>^% byteArray)
	{
		try
		{
			// Input validation check.
			if (CKBytePtr == NULL) throw gcnew SecureModuleException("The specified CK_BYTE* is a NULL pointer.");

			// Allocates memory for 'byteArray'.
			byteArray = gcnew array<Byte>(dataLength);

			// Copy from '*CKBytePtr' to byteArray.
			for (CK_ULONG i = 0; i < dataLength; i++)
				byteArray[i] = (Byte)CKBytePtr[i];
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
	/// Convert standard System::DateTime to certificate Date/Time.
	/// <para>The output format is "YYYYMMDDhhmmss00" which is used to specify a user defined validity period for X.509 certificates.</para>
	/// <para>The output can be set as "CERTIFICATE_START_TIME" and "CERTIFICATE_END_TIME" attributes for a X.509 certificate object.</para>
	/// </summary>
	void Utils::ConvertDateTimeToCertificateTime(DateTime^ dateTime, String^% CertificateTime)
	{
		try
		{
			// Input validation check.
			if (dateTime == nullptr) throw gcnew SecureModuleException("The specified DateTime is nullptr.");

			// Convert to Certificate time format.
			CertificateTime = dateTime->Year.ToString("D4") + dateTime->Month.ToString("D2") + dateTime->Day.ToString("D2") + dateTime->Hour.ToString("D2") + dateTime->Minute.ToString("D2") + dateTime->Second.ToString("D2");
		}
		catch (Exception^)
		{
			throw;
		}
	}

	/// <summary>
	/// Convert certificate Date/Time to standard System::DateTime.
	/// <para>The output format is "YYYYMMDDhhmmss00" which is used to specify a user defined validity period for X.509 certificates.</para>
	/// <para>The output can be set as "CERTIFICATE_START_TIME" and "CERTIFICATE_END_TIME" attributes for a X.509 certificate object.</para>
	/// </summary>
	void Utils::ConvertCertificateTimeToDateTime(String^ CertificateTime, DateTime% dateTime)
	{
		try
		{
			String^ str_year = CertificateTime->Substring(0, 4);
			String^ str_month = CertificateTime->Substring(4, 2);
			String^ str_day = CertificateTime->Substring(6, 2);
			String^ str_hour = CertificateTime->Substring(8, 2);
			String ^str_minute = CertificateTime->Substring(10, 2);
			String ^str_second = CertificateTime->Substring(12, 2);

			dateTime = DateTime(int::Parse(str_year), int::Parse(str_month), int::Parse(str_day), int::Parse(str_hour), int::Parse(str_minute), int::Parse(str_second));
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
	/// Convert standard System::DateTime to CK_DATE.
	/// <para>CK_DATE is a structure that defines a date. It is defined as : year('1900' - '9999'), month ('01' - '12'), day ('01' - '31').</para>
	/// <para>The CK_DATE fields hold numeric characters</para>
	/// </summary>
	void Utils::ConvertDateTimeToCKDate(DateTime^ dateTime, CK_DATE_PTR CKDate)
	{
		CK_CHAR_PTR year = NULL, month = NULL, day = NULL;

		try
		{
			CK_ULONG length = 0, i = 0;

			// Input validation check.
			if (dateTime == nullptr) throw gcnew SecureModuleException("The specified DateTime is nullptr.");

			// Set year.
			ConvertStringToCKCharPtr(dateTime->Year.ToString("D4"), &year, &length);
			for (i = 0; i < length; i++)
				CKDate->year[i] = year[i];

			// Set month.
			length = 0;
			ConvertStringToCKCharPtr(dateTime->Month.ToString("D2"), &month, &length);
			for (i = 0; i < length; i++)
				CKDate->month[i] = month[i];

			// Set day.
			length = 0;
			ConvertStringToCKCharPtr(dateTime->Day.ToString("D2"), &day, &length);
			for (i = 0; i < length; i++)
				CKDate->day[i] = day[i];
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
			delete[] year;
			year = NULL;

			delete[] month;
			month = NULL;

			delete[] day;
			day = NULL;
		}
	}

	/// <summary>
	/// Convert CK_DATE to standard System::DateTime.
	/// <para>CK_DATE is a structure that defines a date. It is defined as : year('1900' - '9999'), month ('01' - '12'), day ('01' - '31').</para>
	/// <para>The CK_DATE fields hold numeric characters</para>
	/// </summary>
	void Utils::ConvertCKDateToDateTime(CK_DATE_PTR CKDate, DateTime% dateTime)
	{
		try
		{
			String^ year = String::Empty;
			String^ month = String::Empty;
			String^ day = String::Empty;

			ConvertCharPtrToString((char *)(CKDate->year), 4, year);
			ConvertCharPtrToString((char *)(CKDate->month), 2, month);
			ConvertCharPtrToString((char *)(CKDate->day), 2, day);

			dateTime = DateTime(int::Parse(year), int::Parse(month), int::Parse(day), 0, 0, 0);
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
	/// Create TLV structure from tag and value which it calculates the length.
	/// </summary>
	void Utils::CreateTLV(Byte tag, array<Byte>^ value, array<Byte>^% TLV)
	{
		try
		{
			int ValueLen = 0, totalLen = 0, i = 0, indx = 0;
			array<Byte>^ vLen = nullptr;
			String^ strLen = "";

			// Input validation check.
			if (value == nullptr) throw gcnew SecureModuleException("The specified input byte array is nullptr.");

			// 'ValueLen' = value.Length
			ValueLen = value->Length;

			// 'totalLen' = 'ValueLen' + tag
			totalLen = ValueLen + 1;

			// Calculation of length format.
			if (ValueLen > 0xFF) // > 255 ? --> 82-XX-XX
				totalLen += 3;
			else if (ValueLen > 0x7F) // > 127 ? --> 81-XX
				totalLen += 2;
			else
				totalLen += 1; // < 127 ? --> XX

			// Allocates memory for output TLV.
			TLV = gcnew array<Byte>(totalLen);

			// Adds 'tag' to the output TLV.
			TLV[indx++] = tag;

			// Adds format of length to the output TLV.
			if (ValueLen > 0xFF) // > 255 ? --> 82-XX-XX
			{
				TLV[indx++] = 0x82;
				strLen = ValueLen.ToString("X4");
			}
			else if (ValueLen > 0x7F) // > 127 ? --> 81-XX
			{
				TLV[indx++] = 0x81;
				strLen = ValueLen.ToString("X2");
			}
			else // < 127 ? --> XX
				strLen = ValueLen.ToString("X2");

			// Convert 'strLen' from hex-string to byte array.
			ConvertHexStringToByteArray(strLen, vLen);

			// Adds data length to the output TLV.
			for (i = 0; i < vLen->Length; i++)
			{
				TLV[indx++] = vLen[i];
			}

			// Adds 'value' to the output TLV.
			for (i = 0; i < ValueLen; i++)
			{
				TLV[indx++] = value[i];
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
	}

	/// <summary>
	/// Get string format of a CK_RV error code.
	/// </summary>
	String^ Utils::GetCKRString(CK_RV rv)
	{
		String^ err_str = String::Empty;

		switch (rv)
		{
		case CKR_OK: return "CKR_OK";
		case CKR_CANCEL: return "CKR_CANCEL";
		case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
		case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
		case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
		case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
		case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
		case CKR_NO_EVENT: return "CKR_NO_EVENT";
		case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
		case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
		case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
		case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
		case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
		case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
		case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
		case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
		case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
		case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
		case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
		case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
		case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
		case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
		case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
		case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
		case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
		case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
		case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
		case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
		case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
		case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
		case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
		case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
		case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
		case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
		case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
		case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
		case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
		case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
		case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
		case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
		case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
		case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
		case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
		case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
		case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
		case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
		case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
		case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
		case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
		case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
		case CKR_WRAPPING_KEY_HANDLE_INVALID: return "CKR_WRAPPING_KEY_HANDLE_INVALID";
		case CKR_WRAPPING_KEY_SIZE_RANGE: return "CKR_WRAPPING_KEY_SIZE_RANGE";
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
		case CKR_RANDOM_SEED_NOT_SUPPORTED: return "CKR_RANDOM_SEED_NOT_SUPPORTED";
		case CKR_RANDOM_NO_RNG: return "CKR_RANDOM_NO_RNG";
		case CKR_DOMAIN_PARAMS_INVALID: return "CKR_DOMAIN_PARAMS_INVALID";
		case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
		case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
		case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
		case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
		case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
		case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
		case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";

			// List of error codes that may be returned from ProtectToolkit C which are Vendor extensions to the PKCS#11 standard.
		case CKR_TIME_STAMP: return "CKR_TIME_STAMP";
		case CKR_ACCESS_DENIED: return "CKR_ACCESS_DENIED";
		case CKR_CRYPTOKI_UNUSABLE: return "CKR_CRYPTOKI_UNUSABLE";
		case CKR_ENCODE_ERROR: return "CKR_ENCODE_ERROR";
		case CKR_V_CONFIG: return "CKR_V_CONFIG";
		case CKR_SO_NOT_LOGGED_IN: return "CKR_SO_NOT_LOGGED_IN";
		case CKR_CERT_NOT_VALIDATED: return "CKR_CERT_NOT_VALIDATED";
		case CKR_PIN_ALREADY_INITIALIZED: return "CKR_PIN_ALREADY_INITIALIZED";
		case CKR_REMOTE_SERVER_ERROR: return "CKR_REMOTE_SERVER_ERROR";
		case CKR_CSA_HW_ERROR: return "CKR_CSA_HW_ERROR";
		case CKR_NO_CHALLENGE: return "CKR_NO_CHALLENGE";
		case CKR_RESPONSE_INVALID: return "CKR_RESPONSE_INVALID";
		case CKR_EVENT_LOG_NOT_FULL: return "CKR_EVENT_LOG_NOT_FULL";
		case CKR_OBJECT_READ_ONLY: return "CKR_OBJECT_READ_ONLY";
		case CKR_TOKEN_READ_ONLY: return "CKR_TOKEN_READ_ONLY";
		case CKR_TOKEN_NOT_INITIALIZED: return "CKR_TOKEN_NOT_INITIALIZED";
		case CKR_NOT_ADMIN_TOKEN: return "CKR_NOT_ADMIN_TOKEN";
		case CKR_AUTHENTICATION_REQUIRED: return "CKR_AUTHENTICATION_REQUIRED";
		case CKR_OPERATION_NOT_PERMITTED: return "CKR_OPERATION_NOT_PERMITTED";
		case CKR_PKCS12_DECODE: return "CKR_PKCS12_DECODE";
		case CKR_PKCS12_UNSUPPORTED_SAFEBAG_TYPE: return "CKR_PKCS12_UNSUPPORTED_SAFEBAG_TYPE";
		case CKR_PKCS12_UNSUPPORTED_PRIVACY_MODE: return "CKR_PKCS12_UNSUPPORTED_PRIVACY_MODE";
		case CKR_PKCS12_UNSUPPORTED_INTEGRITY_MODE: return "CKR_PKCS12_UNSUPPORTED_INTEGRITY_MODE";
#ifndef _PTKC_V400_
		case CKR_KEY_NOT_ACTIVE: return "CKR_KEY_NOT_ACTIVE";
#endif
		case CKR_ET_NOT_ODD_PARITY: return "CKR_ET_NOT_ODD_PARITY";
		case CKR_BAD_REQUEST: return "CKR_BAD_REQUEST";
		case CKR_BAD_ATTRIBUTE_PACKING: return "CKR_BAD_ATTRIBUTE_PACKING";
		case CKR_BAD_ATTRIBUTE_COUNT: return "CKR_BAD_ATTRIBUTE_COUNT";
		case CKR_BAD_PARAM_PACKING: return "CKR_BAD_PARAM_PACKING";
		case CKR_EXTERN_DCP_ERROR: return "CKR_EXTERN_DCP_ERROR";
		case CKR_HIMK_NOT_FOUND: return "CKR_HIMK_NOT_FOUND";
		case CKR_CANNOT_DERIVE_KEYS: return "CKR_CANNOT_DERIVE_KEYS";
		case CKR_BAD_REQ_SIGNATURE: return "CKR_BAD_REQ_SIGNATURE";
		case CKR_BAD_REPLY_SIGNATURE: return "CKR_BAD_REPLY_SIGNATURE";
		case CKR_SMS_ERROR: return "CKR_SMS_ERROR";
		case CKR_BAD_PROTECTION: return "CKR_BAD_PROTECTION";
		case CKR_DEVICE_RESET: return "CKR_DEVICE_RESET";
		case CKR_NO_SESSION_KEYS: return "CKR_NO_SESSION_KEYS";
		case CKR_BAD_REPLY: return "CKR_BAD_REPLY";
		case CKR_KEY_ROLLOVER: return "CKR_KEY_ROLLOVER";
		case CKR_NEED_IV_UPDATE: return "CKR_NEED_IV_UPDATE";
		case CKR_DUPLICATE_IV_FOUND: return "CKR_DUPLICATE_IV_FOUND";
		case CKR_WLD_CONFIG_NOT_FOUND: return "CKR_WLD_CONFIG_NOT_FOUND";
		case CKR_WLD_CONFIG_ITEM_READ_FAILED: return "CKR_WLD_CONFIG_ITEM_READ_FAILED";
		case CKR_WLD_CONFIG_NO_TOKEN_LABEL: return "CKR_WLD_CONFIG_NO_TOKEN_LABEL";
		case CKR_WLD_CONFIG_TOKEN_LABEL_LEN: return "CKR_WLD_CONFIG_TOKEN_LABEL_LEN";
		case CKR_WLD_CONFIG_TOKEN_SERIAL_NUM_LEN: return "CKR_WLD_CONFIG_TOKEN_SERIAL_NUM_LEN";
		case CKR_WLD_CONFIG_SLOT_DESCRIPTION_LEN: return "CKR_WLD_CONFIG_SLOT_DESCRIPTION_LEN";
		case CKR_WLD_CONFIG_ITEM_FORMAT_INVALID: return "CKR_WLD_CONFIG_ITEM_FORMAT_INVALID";
		case CKR_WLD_LOGIN_CACHE_INCONSISTENT: return "CKR_WLD_LOGIN_CACHE_INCONSISTENT";
#ifndef _PTKC_V400_
		case CKR_HA_MAX_SLOTS_INVALID_LEN: return "CKR_HA_MAX_SLOTS_INVALID_LEN";
		case CKR_HA_SESSION_HANDLE_INVALID: return "CKR_HA_SESSION_HANDLE_INVALID";
		case CKR_HA_SESSION_INVALID: return "CKR_HA_SESSION_INVALID";
		case CKR_HA_OBJECT_INDEX_INVALID: return "CKR_HA_OBJECT_INDEX_INVALID";
		case CKR_HA_CANNOT_RECOVER_KEY: return "CKR_HA_CANNOT_RECOVER_KEY";
		case CKR_HA_NO_HSM: return "CKR_HA_NO_HSM";
		case CKR_HA_OUT_OF_OBJS: return "CKR_HA_OUT_OFOBJS";
#endif
		default:
			break;
		}
		return "_UNKNOWN_ERROR_";
	}

	/// <summary>
	/// Get string format of a Return codes of the HSM Administration module.
	/// </summary>
	String^ Utils::GetHSMAdminErrorString(HSMADM_RV_et rv)
	{
		String^ err_str = String::Empty;

		switch (rv)
		{
		case HSMADM_OK: return "HSMADM_OK";
		case HSMADM_BAD_PARAMETER: return "HSMADM_BAD_PARAMETER";
		case HSMADM_ADJ_TIME_LIMIT: return "HSMADM_ADJ_TIME_LIMIT";
		case HSMADM_ADJ_COUNT_LIMIT: return "HSMADM_ADJ_COUNT_LIMIT";
		case HSMADM_NO_MEMORY: return "HSMADM_NO_MEMORY";
		case HSMADM_SYSERR: return "HSMADM_SYSERR";
		default:
			break;
		}
		return "_UNKNOWN_HSMADMIN_ERROR_";
	}

	/// <summary>
	/// Get some description about a CK_RV error code.
	/// </summary>
	String^ Utils::GetErrorDescription(CK_RV rv)
	{
		String^ err_str = String::Empty;

		switch (rv)
		{
		case CKR_OK: return "The function executed successfully.";
		case CKR_CANCEL: return "The function was canceled in mid-execution. This happens to a cryptographic function if the function makes a \"CKN_SURRENDER\" application callback which returns CKR_CANCEL (see CKR_CANCEL). It also happens to a function that performs PIN entry through a protected path. The method used to cancel a protected path PIN entry operation is device dependent.";
		case CKR_HOST_MEMORY: return "The computer that the Cryptoki library is running on has insufficient memory to perform the requested function.";
		case CKR_SLOT_ID_INVALID: return "The specified slot ID is not valid.";
		case CKR_GENERAL_ERROR: return "Some horrible, unrecoverable error has occurred. In the worst case, it is possible that the function only partially succeeded, and that the computer and/or token is in an inconsistent state.";
		case CKR_FUNCTION_FAILED: return "The requested function could not be performed, but detailed information about why not is not available in this error return. If the failed function uses a session, it is possible that the \"CK_SESSION_INFO\" structure that can be obtained by calling \"C_GetSessionInfo\" will hold useful information about what happened in its ulDeviceError field. In any event, although the function call failed, the situation is not necessarily totally hopeless, as it is likely to be when CKR_GENERAL_ERROR is returned. Depending on what the root cause of the error actually was, it is possible that an attempt to make the exact same function call again would succeed.";
		case CKR_ARGUMENTS_BAD: return "This is a rather generic error code which indicates that the arguments supplied to the Cryptoki function were in some way not appropriate.";
		case CKR_NO_EVENT: return "This value can only be returned by \"C_GetSlotEvent\". It is returned when \"C_GetSlotEvent\" is called in non-blocking mode and there are no new slot events to return.";
		case CKR_NEED_TO_CREATE_THREADS: return "This value can only be returned by \"C_Initialize\". It is returned when two conditions hold: (1). The application called C_Initialize in a way which tells the Cryptoki library that application threads executing calls to the library cannot use native operating system methods to spawn new threads. (2). The library cannot function properly without being able to spawn new threads in the above fashion.";
		case CKR_CANT_LOCK: return "This value can only be returned by \"C_Initialize\". It means that the type of locking requested by the application for thread-safety is not available in this library, and so the application cannot make use of this library in the specified fashion.";
		case CKR_ATTRIBUTE_READ_ONLY: return "An attempt was made to set a value for an attribute which may not be set by the application, or which may not be modified by the application.";
		case CKR_ATTRIBUTE_SENSITIVE: return "An attempt was made to obtain the value of an attribute of an object which cannot be satisfied because the object is either sensitive or unextractable.";
		case CKR_ATTRIBUTE_TYPE_INVALID: return "An invalid attribute type was specified in a template.";
		case CKR_ATTRIBUTE_VALUE_INVALID: return "An invalid value was specified for a particular attribute in a template.";
		case CKR_DATA_INVALID: return "The plain-text input data to a cryptographic operation is invalid. This return value has lower priority than CKR_DATA_LEN_RANGE.";
		case CKR_DATA_LEN_RANGE: return "The plain-text input data to a cryptographic operation has a bad length. Depending on the operation's mechanism, this could mean that the plain-text data is too short, too long, or is not a multiple of some particular blocksize. This return value has higher priority than CKR_DATA_INVALID.";
		case CKR_DEVICE_ERROR: return "Some problem has occurred with the token and/or slot. This error code can be returned by more than just the functions mentioned above; in particular, it is possible for \"C_GetSlotInfo\" to return CKR_DEVICE_ERROR.";
		case CKR_DEVICE_MEMORY: return "The token does not have sufficient memory to perform the requested function.";
		case CKR_DEVICE_REMOVED: return "The token was removed from its slot during the execution of the function.";
		case CKR_ENCRYPTED_DATA_INVALID: return "The encrypted input to a decryption operation has been determined to be invalid cipher-text. This return value has lower priority than CKR_ENCRYPTED_DATA_LEN_RANGE.";
		case CKR_ENCRYPTED_DATA_LEN_RANGE: return "The cipher-text input to a decryption operation has been determined to be invalid cipher-text solely on the basis of its length. Depending on the operation's mechanism, this could mean that the cipher-text is too short, too long, or is not a multiple of some particular blocksize. This return value has higher priority than CKR_ENCRYPTED_DATA_INVALID.";
		case CKR_FUNCTION_CANCELED: return "When a function executing in serial with an application decides to give the application a chance to do some work, it calls an application-supplied function with a CKN_SURRENDER callback. If the callback returns the value CKR_CANCEL, then the function aborts and returns CKR_FUNCTION_CANCELED.";
		case CKR_FUNCTION_NOT_PARALLEL: return "There is currently no function executing in parallel in the specified session. This is a legacy error code which is only returned by the legacy functions \"C_GetFunctionStatus\" and \"C_CancelFunction\".";
		case CKR_FUNCTION_NOT_SUPPORTED: return "The requested function is not supported by this Cryptoki library. Even unsupported functions in the Cryptoki API should have a stub in the library; this stub should simply return the value CKR_FUNCTION_NOT_SUPPORTED.";
		case CKR_KEY_HANDLE_INVALID: return "The specified key handle is not valid. It may be the case that the specified handle is a valid handle for an object which is not a key. We reiterate here that 0 is never a valid key handle.";
		case CKR_KEY_SIZE_RANGE: return "Although the requested keyed cryptographic operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied key's size is outside the range of key sizes that it can handle.";
		case CKR_KEY_TYPE_INCONSISTENT: return "The specified key is not the correct type of key to use with the specified mechanism. This return value has a higher priority than CKR_KEY_FUNCTION_NOT_PERMITTED.";
		case CKR_KEY_NOT_NEEDED: return "An extraneous key was supplied to \"C_SetOperationState\". For example, an attempt was made to restore a session that had been performing a message digesting operation, and an encryption key was supplied.";
		case CKR_KEY_CHANGED: return "This value is only returned by \"C_SetOperationState\". It indicates that one of the keys specified is not the same key that was being used in the original saved session.";
		case CKR_KEY_NEEDED: return "This value is only returned by \"C_SetOperationState\". It indicates that the session state cannot be restored because \"C_SetOperationState\" needs to be supplied with one or more keys that were being used in the original saved session.";
		case CKR_KEY_FUNCTION_NOT_PERMITTED: return "An attempt has been made to use a key for a cryptographic purpose that the key's attributes are not set to allow it to do. For example, to use a key for performing encryption, that key must have its \"CKA_ENCRYPT\" attribute set to CK_TRUE (the fact that the key must have a \"CKA_ENCRYPT\" attribute implies that the key cannot be a private key). This return value has lower priority than CKR_KEY_TYPE_INCONSISTENT.";
		case CKR_KEY_NOT_WRAPPABLE: return "Although the specified private or secret key does not have its CKA_UNEXTRACTABLE attribute set to CK_TRUE, Cryptoki (or the token) is unable to wrap the key as requested (possibly the token can only wrap a given key with certain types of keys, and the wrapping key specified is not one of these types). Compare with CKR_KEY_UNEXTRACTABLE.";
		case CKR_KEY_UNEXTRACTABLE: return "The specified private or secret key can't be wrapped because its CKA_UNEXTRACTABLE attribute is set to CK_TRUE. Compare with CKR_KEY_NOT_WRAPPABLE.";
		case CKR_MECHANISM_INVALID: return "An invalid mechanism was specified to the cryptographic operation. This error code is an appropriate return value if an unknown mechanism was specified or if the mechanism specified cannot be used in the selected token with the selected function.";
		case CKR_MECHANISM_PARAM_INVALID: return "Invalid parameters were supplied to the mechanism specified to the cryptographic operation. Which parameter values are supported by a given mechanism can vary from token to token.";
		case CKR_OBJECT_HANDLE_INVALID: return "The specified object handle is not valid. We reiterate here that 0 is never a valid object handle.";
		case CKR_OPERATION_ACTIVE: return "There is already an active operation (or combination of active operations) which prevents Cryptoki from activating the specified operation. For example, an active object-searching operation would prevent Cryptoki from activating an encryption operation with \"C_EncryptInit\". Or, an active digesting operation and an active encryption operation would prevent Cryptoki from activating a signature operation. Or, on a token which doesn't support simultaneous dual cryptographic operations in a session (see the description of the \"CKF_DUAL_CRYPTO_OPERATIONS\" flag in the \"CK_TOKEN_INFO\" structure), an active signature operation would prevent Cryptoki from activating an encryption operation.";
		case CKR_OPERATION_NOT_INITIALIZED: return "There is no active operation of an appropriate type in the specified session. For example, an application cannot call \"C_Encrypt\" in a session without having called \"C_EncryptInit\" first to activate an encryption operation.";
		case CKR_PIN_INCORRECT: return "The specified PIN is incorrect, i.e., does not match the PIN stored on the token. More generally -- when authentication to the token involves something other than a PIN -- the attempt to authenticate the user has failed.";
		case CKR_PIN_INVALID: return "The specified PIN has invalid characters in it. This return code only applies to functions which attempt to set a PIN.";
		case CKR_PIN_LEN_RANGE: return "The specified PIN is too long or too short. This return code only applies to functions which attempt to set a PIN.";
		case CKR_PIN_EXPIRED: return "The specified PIN has expired, and the requested operation cannot be carried out unless C_SetPIN is called to change the PIN value. Whether or not the normal user's PIN on a token ever expires varies from token to token.";
		case CKR_PIN_LOCKED: return "The specified PIN is locked, and cannot be used. That is, because some particular number of failed authentication attempts has been reached, the token is unwilling to permit further attempts at authentication. Depending on the token, the specified PIN may or may not remain locked indefinitely.";
		case CKR_SESSION_CLOSED: return "The session was closed during the execution of the function. Note that, the behavior of Cryptoki is undefined if multiple threads of an application attempt to access a common Cryptoki session simultaneously. Therefore, there is actually no guarantee that a function invocation could ever return the value CKR_SESSION_CLOSED if one thread is using a session when another thread closes that session, that is an instance of multiple threads accessing a common session simultaneously.";
		case CKR_SESSION_COUNT: return "This value can only be returned by \"C_OpenSession\". It indicates that the attempt to open a session failed, either because the token has too many sessions already open, or because the token has too many read/write sessions already open.";
		case CKR_SESSION_HANDLE_INVALID: return "The specified session handle was invalid at the time that the function was invoked. Note that this can happen if the session's token is removed before the function invocation, since removing a token closes all sessions with it.";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "The specified token does not support parallel sessions. This is a legacy error code in Cryptoki Version 2.01 and up, no token supports parallel sessions. CKR_SESSION_PARALLEL_NOT_SUPPORTED can only be returned by \"C_OpenSession\", and it is only returned when \"C_OpenSession\" is called in a particular [deprecated] way.";
		case CKR_SESSION_READ_ONLY: return "The specified session was unable to accomplish the desired action because it is a read-only session. This return value has lower priority than CKR_TOKEN_WRITE_PROTECTED.";
		case CKR_SESSION_EXISTS: return "This value can only be returned by \"C_InitToken\". It indicates that a session with the token is already open, and so the token cannot be initialized.";
		case CKR_SESSION_READ_ONLY_EXISTS: return "A read-only session already exists, and so the SO cannot be logged in.";
		case CKR_SESSION_READ_WRITE_SO_EXISTS: return "A read/write SO session already exists, and so a read-only session cannot be opened.";
		case CKR_SIGNATURE_INVALID: return "The provided signature/MAC is invalid. This return value has lower priority than CKR_SIGNATURE_LEN_RANGE.";
		case CKR_SIGNATURE_LEN_RANGE: return "The provided signature/MAC can be seen to be invalid solely on the basis of its length. This return value has higher priority than CKR_SIGNATURE_INVALID.";
		case CKR_TEMPLATE_INCOMPLETE: return "The template specified for creating an object is incomplete, and lacks some necessary attributes.";
		case CKR_TEMPLATE_INCONSISTENT: return "The template specified for creating an object has conflicting attributes.";
		case CKR_TOKEN_NOT_PRESENT: return "The token was not present in its slot at the time that the function was invoked.";
		case CKR_TOKEN_NOT_RECOGNIZED: return "The Cryptoki library and/or slot does not recognize the token in the slot.";
		case CKR_TOKEN_WRITE_PROTECTED: return "The requested action could not be performed because the token is write-protected. This return value has higher priority than CKR_SESSION_READ_ONLY.";
		case CKR_UNWRAPPING_KEY_HANDLE_INVALID: return "This value can only be returned by \"C_UnwrapKey\". It indicates that the key handle specified to be used to unwrap another key is not valid.";
		case CKR_UNWRAPPING_KEY_SIZE_RANGE: return "This value can only be returned by \"C_UnwrapKey\". It indicates that although the requested unwrapping operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied key's size is outside the range of key sizes that it can handle.";
		case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: return "This value can only be returned by \"C_UnwrapKey\". It indicates that the type of the key specified to unwrap another key is not consistent with the mechanism specified for unwrapping.";
		case CKR_USER_ALREADY_LOGGED_IN: return "This value can only be returned by \"C_Login\". It indicates that the specified user cannot be logged into the session, because it is already logged into the session. For example, if an application has an open SO session, and it attempts to log the SO into it, it will receive this error code.";
		case CKR_USER_NOT_LOGGED_IN: return "The desired action cannot be performed because the appropriate user (or an appropriate user) is not logged in. One example is that a session cannot be logged out unless it is logged in. Another example is that a private object cannot be created on a token unless the session attempting to create it is logged in as the normal user. A final example is that cryptographic operations on certain tokens cannot be performed unless the normal user is logged in.";
		case CKR_USER_PIN_NOT_INITIALIZED: return "This value can only be returned by \"C_Login\". It indicates that the normal user's PIN has not yet been initialized with \"C_InitPIN\".";
		case CKR_USER_TYPE_INVALID: return "An invalid value was specified as a \"CK_USER_TYPE\". Valid types are \"CKU_SO\", \"CKU_USER\", and \"CKU_CONTEXT_SPECIFIC\".";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "This value can only be returned by \"C_Login\". It indicates that the specified user cannot be logged into the session, because another user is already logged into the session. For example, if an application has an open SO session, and it attempts to log the normal user into it, it will receive this error code.";
		case CKR_USER_TOO_MANY_TYPES: return "An attempt was made to have more distinct users simultaneously logged into the token than the token and/or library permits. For example, if some application has an open SO session, and another application attempts to log the normal user into a session, the attempt may return this error. It is not required to, however. Only if the simultaneous distinct users cannot be supported does \"C_Login\" have to return this value. Note that this error code generalizes to true multi-user tokens.";
		case CKR_WRAPPED_KEY_INVALID: return "This value can only be returned by \"C_UnwrapKey\". It indicates that the provided wrapped key is not valid. If a call is made to \"C_UnwrapKey\" to unwrap a particular type of key (i.e., some particular key type is specified in the template provided to \"C_UnwrapKey\"), and the wrapped key provided to \"C_UnwrapKey\" is recognizably not a wrapped key of the proper type, then \"C_UnwrapKey\" should return CKR_WRAPPED_KEY_INVALID. This return value has lower priority than CKR_WRAPPED_KEY_LEN_RANGE.";
		case CKR_WRAPPED_KEY_LEN_RANGE: return "This value can only be returned by \"C_UnwrapKey\". It indicates that the provided wrapped key can be seen to be invalid solely on the basis of its length. This return value has higher priority than CKR_WRAPPED_KEY_INVALID.";
		case CKR_WRAPPING_KEY_HANDLE_INVALID: return "This value can only be returned by \"C_WrapKey\". It indicates that the key handle specified to be used to wrap another key is not valid.";
		case CKR_WRAPPING_KEY_SIZE_RANGE: return "This value can only be returned by \"C_WrapKey\". It indicates that although the requested wrapping operation could in principle be carried out, this Cryptoki library (or the token) is unable to actually do it because the supplied wrapping key's size is outside the range of key sizes that it can handle.";
		case CKR_WRAPPING_KEY_TYPE_INCONSISTENT: return "This value can only be returned by \"C_WrapKey\". It indicates that the type of the key specified to wrap another key is not consistent with the mechanism specified for wrapping.";
		case CKR_RANDOM_SEED_NOT_SUPPORTED: return "This value can only be returned by \"C_SeedRandom\". It indicates that the token's random number generator does not accept seeding from an application. This return value has lower priority than CKR_RANDOM_NO_RNG.";
		case CKR_RANDOM_NO_RNG: return "This value can be returned by \"C_SeedRandom\" and \"C_GenerateRandom\". It indicates that the specified token doesn't have a random number generator. This return value has higher priority than CKR_RANDOM_SEED_NOT_SUPPORTED.";
		case CKR_DOMAIN_PARAMS_INVALID: return "Invalid or unsupported domain parameters were supplied to the function. Which representation methods of domain parameters are supported by a given mechanism can vary from token to token.";
		case CKR_BUFFER_TOO_SMALL: return "The output of the function is too large to fit in the supplied buffer.";
		case CKR_SAVED_STATE_INVALID: return "This value can only be returned by \"C_SetOperationState\". It indicates that the supplied saved cryptographic operations state is invalid, and so it cannot be restored to the specified session.";
		case CKR_INFORMATION_SENSITIVE: return "The information requested could not be obtained because the token considers it sensitive, and is not able or willing to reveal it.";
		case CKR_STATE_UNSAVEABLE: return "The cryptographic operations state of the specified session cannot be saved for some reason (possibly the token is simply unable to save the current state). This return value has lower priority than CKR_OPERATION_NOT_INITIALIZED.";
		case CKR_CRYPTOKI_NOT_INITIALIZED: return "This value can be returned by any function other than \"C_Initialize\" and \"C_GetFunctionList\". It indicates that the function cannot be executed because the Cryptoki library has not yet been initialized by a call to \"C_Initialize\".";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "This value can only be returned by \"C_Initialize\". It means that the Cryptoki library has already been initialized (by a previous call to \"C_Initialize\" which did not have a matching \"C_Finalize\" call).";
		case CKR_MUTEX_BAD: return "This error code can be returned by mutex-handling functions who are passed a bad mutex object as an argument. Unfortunately, it is possible for such a function not to recognize a bad mutex object. There is therefore no guarantee that such a function will successfully detect bad mutex objects and return this value.";
		case CKR_MUTEX_NOT_LOCKED: return "This error code can be returned by mutex-unlocking functions. It indicates that the mutex supplied to the mutex-unlocking function was not locked.";
		case CKR_VENDOR_DEFINED: return "Vendor-specific error";

			// List of error codes that may be returned from ProtectToolkit C which are Vendor extensions to the PKCS#11 standard.
		case CKR_TIME_STAMP: return "Not used";
		case CKR_ACCESS_DENIED: return "Attempting to call \"C_InitToken\" when HSM configured for No Clear Pins Use \"CT_InitToken\" instead.";
		case CKR_CRYPTOKI_UNUSABLE: return "Not used.";
		case CKR_ENCODE_ERROR: return "Template encode/decode error. Usually internal error but may be caused by badly formed function request parameters.";
		case CKR_V_CONFIG: return "Not used";
		case CKR_SO_NOT_LOGGED_IN: return "Operation requires session to be in SO RW mode.";
		case CKR_CERT_NOT_VALIDATED: return "Public key certificate chain not terminated by a TRUSTED certificate.";
		case CKR_PIN_ALREADY_INITIALIZED: return "Calling \"C_InitPIN\" when pin is already initialized. Use \"C_SetPIN\" instead.";
		case CKR_REMOTE_SERVER_ERROR: return "Not used";
		case CKR_CSA_HW_ERROR: return "Not used.";
		case CKR_NO_CHALLENGE: return "Not used.";
		case CKR_RESPONSE_INVALID: return "Failure to disable an FM.";
		case CKR_EVENT_LOG_NOT_FULL: return "Attempting to erase Event log when it is not full.";
		case CKR_OBJECT_READ_ONLY: return "Attempting to \"C_DestroyObject\" with CKA_DELETABLE = TRUE.";
		case CKR_TOKEN_READ_ONLY: return "Not used.";
		case CKR_TOKEN_NOT_INITIALIZED: return "Attempting to Reset a Token that is not initialized.";
		case CKR_NOT_ADMIN_TOKEN: return "Attempting to create an object or write an attribute of an object on a normal token that should only be on an Admin token.";
		case CKR_AUTHENTICATION_REQUIRED: return "Not used.";
		case CKR_OPERATION_NOT_PERMITTED: return "Attempting to generate a timestamp when the RTC is not working or trusted. PKCS#12 import package has more than one private key.";
		case CKR_PKCS12_DECODE: return "PKCS#12 package corrupt. This error code is returned when there is an error decoding the PKCS#12 file.";
		case CKR_PKCS12_UNSUPPORTED_SAFEBAG_TYPE: return "PKCS#12 package contains unrecognized SAFEBAG. This error code is returned when unsupported SafeBag is found. The import mechanism for this release only supports keyBag, pkcs8ShroudedKeyBag, and certBag.";
		case CKR_PKCS12_UNSUPPORTED_PRIVACY_MODE: return "PKCS#12 package contains unrecognized privacy (public key mode not supported). This error code is returned when a PKCS#12 file with unsupported privacy mode is encountered. The import mechanism for this release only supports password privacy mode.";
		case CKR_PKCS12_UNSUPPORTED_INTEGRITY_MODE: return "PKCS#12 package contains unrecognized integrity (should be MAC). This error code is returned when a PKCS#12 file with unsupported integrity mode is encountered. The import mechanism for this release only supports password integrity mode.";
#ifndef _PTKC_V400_
		case CKR_KEY_NOT_ACTIVE: return "Key has exceeded its usage limit or dates.";
#endif
		case CKR_ET_NOT_ODD_PARITY: return "DES key being loaded into HSM has bad parity (should be odd) - fix key or enable Des Keys Even Parity Allowed mode (ctconf -fd).";
		case CKR_BAD_REQUEST: return "Badly formed request message (network or device driver error).";
		case CKR_BAD_ATTRIBUTE_PACKING: return "Cryptoki client has failed to encode attribute list correctly.";
		case CKR_BAD_ATTRIBUTE_COUNT: return "Cryptoki client has failed to encode attribute list correctly.";
		case CKR_BAD_PARAM_PACKING: return "Cryptoki client has failed to encode function parameters correctly.";
		case CKR_EXTERN_DCP_ERROR: return "Not used.";
		case CKR_HIMK_NOT_FOUND: return "HIMK object not found on admin Token.";
		case CKR_CANNOT_DERIVE_KEYS: return "Internal error when establishing a secure messaging connection.";
		case CKR_BAD_REQ_SIGNATURE: return "Corrupt request to HSM when using secure messaging (network or device driver error).";
		case CKR_BAD_REPLY_SIGNATURE: return "Corrupt reply from HSM when using secure messaging (network or device driver error).";
		case CKR_SMS_ERROR: return "General error from secure messaging system - probably caused by HSM failure or network failure.";
		case CKR_BAD_PROTECTION: return "Cryptoki library has failed to apply proper secure message protection - internal error.";
		case CKR_DEVICE_RESET: return "HSM has unexpectantly shutdown. Check the event log for errors (ctconf -e)";
		case CKR_NO_SESSION_KEYS: return "Cryptoki library has failed to establish keys for secure message protection - internal error.";
		case CKR_BAD_REPLY: return "Reply message from HSM is badly formatted (network or device driver error).";
		case CKR_KEY_ROLLOVER: return "Secure messaging system has not implemented key rollover protocol properly.";
		case CKR_NEED_IV_UPDATE: return "Secure messaging system has not implemented key rollover protocol properly.";
		case CKR_DUPLICATE_IV_FOUND: return "Not used.";
		case CKR_WLD_CONFIG_NOT_FOUND: return "ET_PTKC_WLD configuration data not consistent.";
		case CKR_WLD_CONFIG_ITEM_READ_FAILED: return "ET_PTKC_WLD configuration data not available.";
		case CKR_WLD_CONFIG_NO_TOKEN_LABEL: return "ET_PTKC_WLD configuration data not formatted correctly.";
		case CKR_WLD_CONFIG_TOKEN_LABEL_LEN: return "ET_PTKC_WLD configuration data not formatted correctly.";
		case CKR_WLD_CONFIG_TOKEN_SERIAL_NUM_LEN: return "ET_PTKC_WLD configuration data not formatted correctly.";
		case CKR_WLD_CONFIG_SLOT_DESCRIPTION_LEN: return "ET_PTKC_WLD configuration data not formatted correctly.";
		case CKR_WLD_CONFIG_ITEM_FORMAT_INVALID: return "ET_PTKC_WLD configuration data not formatted correctly.";
		case CKR_WLD_LOGIN_CACHE_INCONSISTENT: return "Internal error in cryptoki library where WLD values are inconsistent.";
#ifndef _PTKC_V400_
		case CKR_HA_MAX_SLOTS_INVALID_LEN: return "Too many virtual WLD slots are defined.";
		case CKR_HA_SESSION_HANDLE_INVALID: return "Unknown session handle passed to Cryptoki library.";
		case CKR_HA_SESSION_INVALID: return "";
		case CKR_HA_OBJECT_INDEX_INVALID: return "";
		case CKR_HA_CANNOT_RECOVER_KEY: return "HA recovery process needs to create a key but is unable to.";
		case CKR_HA_NO_HSM: return "HA has tried to recover a lost session but no ore working HSMs are available.";
		case CKR_HA_OUT_OF_OBJS: return "The HA feature has reached its capacity to manage session objects - too many objects created.";
#endif
		default:
			break;
		}
		return "_NO_DESCRIPTION_";
	}

	/// <summary>
	/// Get some description about a Return codes of the HSM Administration module.
	/// </summary>
	String^ Utils::GetHSMAdminErrorDescription(HSMADM_RV_et rv)
	{
		String^ err_str = String::Empty;

		switch (rv)
		{
		case HSMADM_OK: return "Operation was successful.";
		case HSMADM_BAD_PARAMETER: return "One or more of the parameters have invalid value.";
		case HSMADM_ADJ_TIME_LIMIT: return "The delta value passed to the HSMADM_AdjustTime() is too large, and will not be used.";
		case HSMADM_ADJ_COUNT_LIMIT: return "The number of calls made to the HSMADM_AdjustTime() that change the time is too large. The adjustment will not be made.";
		case HSMADM_NO_MEMORY: return "Not enough memory to complete operation.";
		case HSMADM_SYSERR: return "There was a system error. The operation was not performed.";
		default:
			break;
		}
		return "_NO_ADMIN_ERROR_DESCRIPTION_";
	}

	/// <summary>
	/// It's an internal function to create a CK_ATTRIBUTE[] from the input 'attribute(s)'.
	/// </summary>
	void Utils::ConvertToCKTemplate(CK_ATTRIBUTE_PTR *CKA_Template, CK_ULONG_PTR Template_length,
		CK_BBOOL boolean_value[], int& boolean_indx,
		CK_ULONG uint_value[], int& uint_indx,
		CK_DATE dateTime_value[], int& dateTime_indx,
		CK_BYTE_PTR byte_array_value[], CK_ULONG byte_array_value_length[], int& byte_array_indx,
		CK_CHAR_PTR char_array_value[], CK_ULONG char_array_value_length[], int& char_array_indx,
		array<SMAttribute^>^ attribute)
	{
		CK_RV rv = CKR_OK;
		int i = 0;

		String^ string_attribute = String::Empty;
		array<Byte>^ byteArray_attribute = nullptr;

		// Set the length of output template[] with the number of input 'attribute'.
		(*Template_length) = attribute->Length;
		try
		{
			// Check the output template[] length is grater than zero.
			if ((*Template_length) <= 0)
			{
				rv = CKR_DATA_INVALID;
				throw gcnew SecureModuleException("attributes length is < 0.");
			}

			// Allocate memory for the output array.
			(*CKA_Template) = new CK_ATTRIBUTE[(*Template_length)];

			// Fill the output template[] with the 'attribute' data.
			// For each (type, pValue, ulValueLen) triple in the output template[], performs the following:
			for (int i = 0; i < attribute->Length; i++)
			{
				// Set the attribute type.
				(*CKA_Template)[i].type = (CK_ATTRIBUTE_TYPE)attribute[i]->Attribute_Type;
				(*CKA_Template)[i].pValue = NULL_PTR;
				(*CKA_Template)[i].valueLen = 0;

				// Ignore nullptr references
				if (attribute[i]->Value == nullptr)
					continue;

				// Get the attribute's system data type (Boolean, String, Byte[], DateTime, UInt32).
				System::TypeCode attributeTypeCode = attribute[i]->GetAttributeSystemTypeCode();

				// Set the template[].pValue and template[]ulValueLen with the attribute's value, according to it's data type.
				switch (attributeTypeCode)
				{
				case System::TypeCode::Boolean:
					boolean_value[boolean_indx] = (CK_BBOOL)((Boolean)(attribute[i]->Value));
					(*CKA_Template)[i].pValue = &(boolean_value[boolean_indx]);
					(*CKA_Template)[i].valueLen = sizeof(boolean_value[boolean_indx]);
					boolean_indx++;
					break;
				case System::TypeCode::UInt32:
					uint_value[uint_indx] = (CK_ULONG)((UInt32)(attribute[i]->Value));
					(*CKA_Template)[i].pValue = &(uint_value[uint_indx]);
					(*CKA_Template)[i].valueLen = sizeof(uint_value[uint_indx]);
					uint_indx++;
					break;
				case System::TypeCode::DateTime:
					if (attribute[i]->Attribute_Type == AttributeType::START_DATE || attribute[i]->Attribute_Type == AttributeType::END_DATE)
					{
						// Convert System::DateTime to CK_DATE.
						Utils::ConvertDateTimeToCKDate((DateTime)(attribute[i]->Value), &(dateTime_value[dateTime_indx]));
						(*CKA_Template)[i].pValue = &(dateTime_value[dateTime_indx]);
						(*CKA_Template)[i].valueLen = sizeof(dateTime_value[dateTime_indx]);
						dateTime_indx++;
					}
					else
					{
						// Convert System::DateTime to CK_CERTIFICATE_(START/END)_TIME.
						Utils::ConvertDateTimeToCertificateTime((DateTime)(attribute[i]->Value), string_attribute);

						// Convert System::String to CK_CHAR_PTR.
						Utils::ConvertStringToCKCharPtr(string_attribute, &(char_array_value[char_array_indx]), &(char_array_value_length[char_array_indx]));
						(*CKA_Template)[i].pValue = char_array_value[char_array_indx];
						(*CKA_Template)[i].valueLen = char_array_value_length[char_array_indx] * sizeof(char_array_value[char_array_indx][0]);
						char_array_indx++;
					}
					break;
				case System::TypeCode::Byte:
					Utils::ConvertByteArrayToCKBytePtr((array<Byte>^)(attribute[i]->Value), &(byte_array_value[byte_array_indx]), &(byte_array_value_length[byte_array_indx]));
					(*CKA_Template)[i].pValue = byte_array_value[byte_array_indx];
					(*CKA_Template)[i].valueLen = byte_array_value_length[byte_array_indx] * sizeof(byte_array_value[byte_array_indx][0]);
					byte_array_indx++;
					break;
				case System::TypeCode::String:
					string_attribute = (String^)(attribute[i]->Value);
					Utils::ConvertStringToCKCharPtr(string_attribute, &(char_array_value[char_array_indx]), &(char_array_value_length[char_array_indx]));
					(*CKA_Template)[i].pValue = char_array_value[char_array_indx];
					(*CKA_Template)[i].valueLen = char_array_value_length[char_array_indx] * sizeof(char_array_value[char_array_indx][0]);
					char_array_indx++;
					break;
				default:
					break;
				}
			}
		}
		catch (Exception^)
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

			// Deallocate memory of '*CKA_Template'.
			if ((*CKA_Template) != NULL) delete[](*CKA_Template);
			(*CKA_Template) = NULL;

			throw;
		}
	}

	/// <summary>
	/// Encodes all the characters in the specified string into a sequence of bytes for the UTF-16 format using the little endian byte order.
	/// </summary>
	void Utils::ConvertStringToUnicodeArray(String^ textString, array<Byte>^% bytes)
	{
		try
		{
			int i = 0;
			array<Byte>^ ucbytes = System::Text::Encoding::Unicode->GetBytes(textString);
			bytes = gcnew array<Byte>(ucbytes->Length + 2);
			for (i = 0; i < ucbytes->Length; i += 2)
			{
				bytes[i] = ucbytes[i + 1];
				bytes[i + 1] = ucbytes[i];
			}
			bytes[i] = bytes[i + 1] = (Byte)0;
		}
		catch (Exception^)
		{
			throw;
		}
	}
}