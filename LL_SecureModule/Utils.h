#pragma once

#include "SecureModuleException.h"
#include "Attribute.h"

#include <hsmadmin.h>

using namespace System;

namespace LL_SecureModule
{
	/// <summary>
	/// ...
	/// </summary>
	private ref class Utils
	{
	public:
		/// <summary>
		/// Default Class constructor.
		/// </summary>
		Utils(void);

		/// <summary>
		/// Default array length for Attributes.
		/// </summary>
		const static int MaxArrayLength = 50;

		/// <summary>
		/// Convert number of bits to number of bytes.
		/// </summary>
		/// <param name="bits">the input number of bits</param>
		/// <example>
		/// 14 bits = 2 bytes
		/// </example>
		/// <returns>returns number of bytes</returns>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/07/02	Created
		/// </history>
		static UInt32 ConvertBitsToBytes(UInt32 bits);

		/// <summary>
		/// Convert hexadecimal String to Byte array.
		/// </summary>
		/// <param name="hexString">the input hexadecimal System::String</param>
		/// <param name="ByteArray">the output System::Byte array</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void ConvertHexStringToByteArray(String^ hexString, array<Byte>^% ByteArray);

		/// <summary>
		/// Convert String to CK_CHAR*.
		/// </summary>
		/// <param name="string">the input System::String</param>
		/// <param name="CKCharPtr">the output CK_CHAR*. It must be a NULL pointer</param>
		/// <param name="dataLength">length of output data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void ConvertStringToCKCharPtr(String^ string, CK_CHAR_PTR *CKCharPtr, CK_ULONG_PTR dataLength);

		/// <summary>
		/// Convert String to char*.
		/// </summary>
		/// <param name="string">the input System::String</param>
		/// <param name="charPtr">the output char*. It must be a NULL pointer</param>
		/// <param name="dataLength">length of output data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/30	Created
		/// </history>
		static void ConvertStringToCharPtr(String^ string, char* *charPtr, unsigned int *dataLength);

		/// <summary>
		/// Convert CK_CHAR* to String. This function can be used for CK_CHAR* with specific length or without null-terminated.
		/// </summary>
		/// <param name="CKCharPtr">the input CK_CHAR*</param>
		/// <param name="dataLength">the input data length</param>
		/// <param name="string">the output System::String</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void ConvertCKCharPtrToString(CK_CHAR_PTR CKCharPtr, CK_ULONG dataLength, String^% string);

		/// <summary>
		/// Convert CK_CHAR* to String.
		/// </summary>
		/// <param name="CKCharPtr">the input CK_CHAR*</param>
		/// <param name="string">the output System::String</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void ConvertCKCharPtrToString(CK_CHAR_PTR CKCharPtr, String^% string);

		/// <summary>
		/// Convert char* to String.
		/// </summary>
		/// <param name="CharPtr">the input char*</param>
		/// <param name="string">the output System::String</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/15	Created
		/// </history>
		static void ConvertCharPtrToString(char* CharPtr, String^% string);

		/// <summary>
		/// Convert char* to String.
		/// </summary>
		/// <param name="CharPtr">the input char*</param>
		/// <param name="dataLength">input data length</param>
		/// <param name="string">the output System::String</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/15	Created
		/// </history>
		static void ConvertCharPtrToString(char* CharPtr, int dataLength, String^% string);

		/// <summary>
		/// Convert Byte array to CK_BYTE*.
		/// </summary>
		/// <param name="byteArray">the input System::Byte array</param>
		/// <param name="CKBytePtr">the output CK_BYTE*. It must be a NULL pointer</param>
		/// <param name="dataLength">length of output data</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void ConvertByteArrayToCKBytePtr(array<Byte>^ byteArray, CK_BYTE_PTR *CKBytePtr, CK_ULONG_PTR dataLength);

		/// <summary>
		/// Convert Byte array to CK_CHAR*.
		/// </summary>
		/// <param name="byteArray">the input System::Byte array</param>
		/// <param name="CKCharPtr">the output CK_CHAR*. It must be a NULL pointer</param>
		/// <param name="dataLength">length of output data</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/25	Created
		/// </history>
		static void ConvertByteArrayToCKCharPtr(array<Byte>^ byteArray, CK_BYTE_PTR *CKCharPtr, CK_ULONG_PTR dataLength);

		/// <summary>
		/// Convert CK_BYTE* to Byte array.
		/// </summary>
		/// <param name="CKBytePtr">the input CK_BYTE*</param>
		/// <param name="dataLength">input data length</param>
		/// <param name="byteArray">the output System::Byte array</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void	ConvertCKBytePtrToByteArray(CK_BYTE_PTR CKBytePtr, CK_ULONG dataLength, array<Byte>^% byteArray);

		/// <summary>
		/// Convert standard System::DateTime to certificate Date/Time.
		/// <para>The output format is "YYYYMMDDhhmmss00" which is used to specify a user defined validity period for X.509 certificates.</para>
		/// <para>The output can be set as "CERTIFICATE_START_TIME" and "CERTIFICATE_END_TIME" attributes for a X.509 certificate object.</para>
		/// </summary>
		/// <param name="dateTime">the input System::DateTime</param>
		/// <param name="CertificateTime">the output certificate Date/Time format</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void ConvertDateTimeToCertificateTime(DateTime^ dateTime, String^% CertificateTime);

		/// <summary>
		/// Convert certificate Date/Time to standard System::DateTime.
		/// <para>The output format is "YYYYMMDDhhmmss00" which is used to specify a user defined validity period for X.509 certificates.</para>
		/// <para>The output can be set as "CERTIFICATE_START_TIME" and "CERTIFICATE_END_TIME" attributes for a X.509 certificate object.</para>
		/// </summary>
		/// <param name="CertificateTime">the input certificate Date/Time format</param>
		/// <param name="dateTime">the output System::DateTime</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/28	Created
		/// </history>
		static void ConvertCertificateTimeToDateTime(String^ CertificateTime, DateTime% dateTime);

		/// <summary>
		/// Convert standard System::DateTime to CK_DATE.
		/// <para>CK_DATE is a structure that defines a date. It is defined as : year('1900' - '9999'), month ('01' - '12'), day ('01' - '31').</para>
		/// <para>The CK_DATE fields hold numeric characters</para>
		/// </summary>
		/// <param name="dateTime">the input System::DateTime</param>
		/// <param name="CKDate">the output CK_DATE</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void ConvertDateTimeToCKDate(DateTime^ dateTime, CK_DATE_PTR CKDate);

		/// <summary>
		/// Convert CK_DATE to standard System::DateTime.
		/// <para>CK_DATE is a structure that defines a date. It is defined as : year('1900' - '9999'), month ('01' - '12'), day ('01' - '31').</para>
		/// <para>The CK_DATE fields hold numeric characters</para>
		/// </summary>
		/// <param name="CKDate">the input CK_DATE</param>
		/// <param name="dateTime">the output System::DateTime</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/28	Created
		/// </history>
		static void ConvertCKDateToDateTime(CK_DATE_PTR CKDate, DateTime% dateTime);

		/// <summary>
		/// Create TLV structure from tag and value which it calculates the length.
		/// </summary>
		/// <param name="tag">the Tag value</param>
		/// <param name="value">the Value in byte array</param>
		/// <param name="TLV">the output TLV in byte array</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void CreateTLV(Byte tag, array<Byte>^ value, array<Byte>^% TLV);

		/// <summary>
		/// Get string format of a CK_RV error code.
		/// </summary>
		/// <param name="rv">is a value that identifies the return value of a Cryptoki function</param>
		/// <returns>Returns <paramref name="rv"/> in CK_RV string format</returns>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static String^ GetCKRString(CK_RV rv);

		/// <summary>
		/// Get string format of a Return codes of the HSM Administration module.
		/// </summary>
		/// <param name="rv">is a value that identifies the return value of a HSM Administration module function</param>
		/// <returns>Returns <paramref name="rv"/> in HSMADM_RV_et string format</returns>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static String^ GetHSMAdminErrorString(HSMADM_RV_et rv);

		/// <summary>
		/// Get some description about a CK_RV error code.
		/// </summary>
		/// <param name="rv">is a value that identifies the return value of a Cryptoki function</param>
		/// <returns>Returns description about <paramref name="rv"/></returns>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static String^ GetErrorDescription(CK_RV rv);

		/// <summary>
		/// Get some description about a Return codes of the HSM Administration module.
		/// </summary>
		/// <param name="rv">is a value that identifies the return value of a HSM Administration module function</param>
		/// <returns>Returns description about <paramref name="rv"/></returns>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/20	Created
		/// </history>
		static String^ GetHSMAdminErrorDescription(HSMADM_RV_et rv);

		/// <summary>
		/// It's a function to create a CK_ATTRIBUTE[] from the input 'attribute(s)'.
		/// </summary>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		static void ConvertToCKTemplate(CK_ATTRIBUTE_PTR *CKA_Template, CK_ULONG_PTR Template_length,
			CK_BBOOL boolean_value[], int& boolean_indx,
			CK_ULONG uint_value[], int& uint_indx,
			CK_DATE dateTime_value[], int& dateTime_indx,
			CK_BYTE_PTR byte_array_value[], CK_ULONG byte_array_value_length[], int& byte_array_indx,
			CK_CHAR_PTR char_array_value[], CK_ULONG char_array_value_length[], int& char_array_indx,
			array<SMAttribute^>^ attribute);

		/// <summary>
		/// Encodes all the characters in the specified string into a sequence of bytes for the UTF-16 format using the little endian byte order.
		/// </summary>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/25	Created
		/// </history>
		static void ConvertStringToUnicodeArray(String^ textString, array<Byte>^% bytes);
	};
}
