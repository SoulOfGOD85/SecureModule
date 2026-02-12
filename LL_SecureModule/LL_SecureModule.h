// LL_SecureModule.h

#pragma once

#include "SecureModuleException.h"
#include "SecurityPolicy.h"
#include "Session.h"
#include "DeviceInfoType.h"

#include <kmlib.h>
#include <hsmadmin.h>

using namespace System;
using namespace System::Collections::Generic;

#define DIM(a) (sizeof(a)/sizeof(a[0]))

/// <summary>
/// .Net Wrapper Library for SafeNet ProtectToolkit-C SDK.
/// </summary>
namespace LL_SecureModule {
	/// <summary>
	/// Describes the version of a Cryptoki interface, a Cryptoki library, or an SSL implementation, or the hardware or firmware version of a slot or token.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public ref class CVersion
	{
	public:
		/// <summary>
		/// major version number (the integer portion of the version).
		/// </summary>
		Byte Major;

		/// <summary>
		/// minor version number (the hundredths portion of the version).
		/// </summary>
		Byte Minor;

		/// <summary>
		/// Initializes a new instance of the <see cref="CVersion"/> class.
		/// </summary>
		CVersion(void) { this->Major = this->Minor = (Byte)0; };


		/// <summary>
		/// Initializes a new instance of the <see cref="CVersion"/> class.
		/// </summary>
		/// <param name="Major">the major version.</param>
		/// <param name="Minor">the minor version.</param>
		CVersion(Byte Major, Byte Minor) { this->Major = Major; this->Minor = Minor; };

		/// <summary>
		/// Initializes a new instance of the <see cref="CVersion"/> class.
		/// </summary>
		/// <param name="cversion">the source object.</param>
		CVersion(CVersion^ cversion) { this->Major = cversion->Major; this->Minor = cversion->Minor; };
	};

	/// <summary>
	/// This class is used to specify time values, or time amounts. When it is used to indicate absolute time, it must be interpreted as the time passed since midnight, 1 Jan 1970.
	/// <para>Note: SafeNet's HSM real-time clock only has millisecond resolution. As such, micro-second is always rounded - up to milliseconds.</para>
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public ref class HSMAdminTime
	{
	public:
		/// <summary>
		/// Number of seconds.
		/// </summary>
		UInt32 Second;

		/// <summary>
		/// Number of microseconds.
		/// </summary>
		UInt32 uSecond;

		/// <summary>
		/// Initializes a new instance of the <see cref="HSMAdminTime"/> class.
		/// </summary>
		HSMAdminTime(void) { this->Second = this->uSecond = 0; };

		/// <summary>
		/// Initializes a new instance of the <see cref="HSMAdminTime"/> class.
		/// </summary>
		/// <param name="Second">the second.</param>
		/// <param name="uSecond">the microseconds.</param>
		HSMAdminTime(UInt32 Second, UInt32 uSecond) { this->Second = Second; this->uSecond = uSecond; };

		/// <summary>
		/// Initializes a new instance of the <see cref="HSMAdminTime"/> class.
		/// </summary>
		/// <param name="adminTime">the source object.</param>
		HSMAdminTime(HSMAdminTime^ adminTime) { this->Second = adminTime->Second; this->uSecond = adminTime->uSecond; };
	};

	/// <summary>
	/// Flags indicating capabilities and status of the slot as defined.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public enum class SlotFlag
	{
		/// <summary>
		/// A token is present in the slot.
		/// </summary>
		TOKEN_PRESENT = CKF_TOKEN_PRESENT,

		/// <summary>
		/// The reader supports removable devices.
		/// </summary>
		REMOVABLE_DEVICE = CKF_REMOVABLE_DEVICE,

		/// <summary>
		/// The slot is a hardware slot, as opposed to a software slot implementing a "soft token".
		/// </summary>
		HW_SLOT = CKF_HW_SLOT,
	};

	/// <summary>
	/// Provides information about a particular slot in the device.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public ref class SlotInfo
	{
	public:
		/// <summary>
		/// Initializes a new instance of the <see cref="SlotInfo"/> class.
		/// </summary>
		SlotInfo(void)
		{
			this->SlotDescription = this->ManufacturerID = "";
			this->HardwareVersion = gcnew CVersion();
			this->FirmwareVersion = gcnew CVersion();
		};

		/// <summary>
		/// String description of the slot. Must be padded with the blank character (' '). Should not be null-terminated.
		/// </summary>
		String^ SlotDescription;

		/// <summary>
		/// ID of the slot manufacturer. Must be padded with the blank character (' '). Should not be null-terminated.
		/// </summary>
		String^ ManufacturerID;

		/// <summary>
		/// Bits flags that provide capabilities of the slot.
		/// </summary>
		UInt32 Flags;

		/// <summary>
		/// Version number of the slot's hardware
		/// </summary>
		CVersion^ HardwareVersion;

		/// <summary>
		/// Version number of the slot's firmware
		/// </summary>
		CVersion^ FirmwareVersion;
	};

	/// <summary>
	/// Flags indicating capabilities and status of the token as defined.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public enum class TokenFlag
	{
		/// <summary>
		/// Token has been initialized using InitializeToken or an equivalent mechanism outside the scope of this standard. Calling InitializeToken when this flag is set will cause the token to be reinitialized.
		/// </summary>
		TOKEN_INITIALIZED = CKF_TOKEN_INITIALIZED,

		/// <summary>
		/// Token has its own random number generator.
		/// </summary>
		RNG = CKF_RNG,

		/// <summary>
		/// Token is write-protected.
		/// </summary>
		WRITE_PROTECTED = CKF_WRITE_PROTECTED,

		/// <summary>
		/// There are some cryptographic functions that a user must be logged in to perform.
		/// </summary>
		LOGIN_REQUIRED = CKF_LOGIN_REQUIRED,

		/// <summary>
		/// The normal user's PIN has been initialized.
		/// </summary>
		USER_PIN_INITIALIZED = CKF_USER_PIN_INITIALIZED,

		/// <summary>
		/// A successful save of a session's cryptographic operations state ''always'' contains all keys needed to restore the state of the session.
		/// </summary>
		RESTORE_KEY_NOT_NEEDED = CKF_RESTORE_KEY_NOT_NEEDED,

		/// <summary>
		/// Token has its own hardware clock.
		/// </summary>
		CLOCK_ON_TOKEN = CKF_CLOCK_ON_TOKEN,

		/// <summary>
		/// Token has a "protected authentication path", whereby a user can log into the token without passing a PIN through the Cryptoki library.
		/// </summary>
		PROTECTED_AUTHENTICATION_PATH = CKF_PROTECTED_AUTHENTICATION_PATH,

		/// <summary>
		/// A single session with the token can perform dual cryptographic operations.
		/// </summary>
		DUAL_CRYPTO_OPERATIONS = CKF_DUAL_CRYPTO_OPERATIONS,

		/// <summary>
		/// An exclusive session exists.
		/// </summary>
		EXCLUSIVE_EXISTS = CKF_EXCLUSIVE_EXISTS,
	};

	/// <summary>
	/// Defines curves that named curve must be the DER OID-encoding of it.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public enum  class CurveName
	{
		/// <summary>
		/// { iso(1) member-body(2) US(840) x9-62(10045) curves(3) characteristicTwo(0) c2tnb191v1(5) }
		/// </summary>
		c2tnb191v1,

		/// <summary>
		/// { iso(1) member-body(2) US(840) x9-62(10045) curves(3) prime(1) prime192v1(1) }
		/// </summary>
		prime192v1,

		/// <summary>
		/// { iso(1) member-body(2) US(840) x9-62(10045) curves(3) prime(1) prime192v1(1) }
		/// </summary>
		secp192r1,

		/// <summary>
		/// { iso(1) identified-organization(3) Certicom(132) certicom_ellipticCurve(0) secp224r1(33) }
		/// </summary>
		secp224r1,

		/// <summary>
		/// { iso(1) member-body(2) US(840) x9-62(10045) curves(3) prime(1) prime256v1(7) }
		/// </summary>
		prime256v1,

		/// <summary>
		/// { iso(1) member-body(2) US(840) x9-62(10045) curves(3) prime(1) prime256v1(7) }
		/// </summary>
		secp256r1,

		/// <summary>
		/// { iso(1) identified-organization(3) Certicom(132) certicom_ellipticCurve(0) secp384r1(34) }
		/// </summary>
		secp384r1,

		/// <summary>
		/// { iso(1) identified-organization(3) Certicom(132) certicom_ellipticCurve(0) secp521r1(35) }
		/// </summary>
		secp521r1,

		/// <summary>
		/// (Non FIPS curve); { iso(1) member-body(2) US(840) x9-62(10045) curves(3) characteristicTwo(0) c2tnb191v1e (15) }
		/// </summary>
		c2tnb191v1e,
	};

	/// <summary>
	/// Possible values of the RTC status in the HSM.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public enum  class RTCStatus
	{
		/// <summary>
		/// The RTC is not initialized yet.
		/// </summary>
		RTC_UNINITIALIZED = HSMADM_RTC_UNINITIALIZED,

		/// <summary>
		/// The RTC is in the stand alone mode. This means that it is completely controlled by the crypto subsystem. In this mode, all cryptographic operations are allowed to use the value of the clock.
		/// </summary>
		RTC_STAND_ALONE = HSMADM_RTC_STAND_ALONE,

		/// <summary>
		/// The RTC is being controlled by an external program; but the value is not trusted yet. This means certain cryptographic operations will be refused because the value is(possibly) incorrect.
		/// </summary>
		RTC_MANAGED_UNTRUSTED = HSMADM_RTC_MANAGED_UNTRUSTED,

		/// <summary>
		/// The RTC is being controlled by an external program, and its value may be trusted. This means that all cryptographic operations are allowed to use the value of the clock.
		/// </summary>
		RTC_MANAGED_TRUSTED = HSMADM_RTC_MANAGED_TRUSTED,
	};

	/// <summary>
	/// Provides information about a token.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public ref class TokenInfo
	{
	public:
		/// <summary>
		/// Initializes a new instance of the <see cref="TokenInfo"/> class.
		/// </summary>
		TokenInfo(void)
		{
			label = manufacturerID = model = serialNumber = utcTime = String::Empty;
			maxSessionCount = sessionCount = maxRwSessionCount = rwSessionCount = maxPinLen = minPinLen = totalPublicMemory = freePublicMemory = totalPrivateMemory = freePrivateMemory = 0;
			hardwareVersion = gcnew CVersion();
			firmwareVersion = gcnew CVersion();
		};

		/// <summary>
		/// Application-defined label, assigned during token initialization.
		/// </summary>
		String^ label;

		/// <summary>
		/// ID of the device manufacturer.
		/// </summary>
		String^ manufacturerID;

		/// <summary>
		/// Model of the device.
		/// </summary>
		String^ model;

		/// <summary>
		/// Character-string serial number of the device.
		/// </summary>
		String^ serialNumber;

		/// <summary>
		/// Bits flags indicating capabilities and status of the device as defined below.
		/// </summary>
		UInt32 flags;

		/// <summary>
		/// Maximum number of sessions that can be opened with the token at one time by a single application.
		/// </summary>
		UInt32 maxSessionCount;

		/// <summary>
		/// Number of sessions that this application currently has open with the token.
		/// </summary>
		UInt32 sessionCount;

		/// <summary>
		/// Maximum number of read/write sessions that can be opened with the token at one time by a single application.
		/// </summary>
		UInt32 maxRwSessionCount;

		/// <summary>
		/// Number of read/write sessions that this application currently has open with the token.
		/// </summary>
		UInt32 rwSessionCount;

		/// <summary>
		/// Maximum length in bytes of the PIN.
		/// </summary>
		UInt32 maxPinLen;

		/// <summary>
		/// Minimum length in bytes of the PIN.
		/// </summary>
		UInt32 minPinLen;

		/// <summary>
		/// The total amount of memory on the token in bytes in which public objects may be stored.
		/// </summary>
		UInt32 totalPublicMemory;

		/// <summary>
		/// The amount of free (unused) memory on the token in bytes for public objects.
		/// </summary>
		UInt32 freePublicMemory;

		/// <summary>
		/// The total amount of memory on the token in bytes in which private objects may be stored.
		/// </summary>
		UInt32 totalPrivateMemory;

		/// <summary>
		/// The amount of free (unused) memory on the token in bytes for private objects.
		/// </summary>
		UInt32 freePrivateMemory;

		/// <summary>
		/// Version number of hardware.
		/// </summary>
		CVersion^ hardwareVersion;

		/// <summary>
		/// Version number of firmware.
		/// </summary>
		CVersion^ firmwareVersion;

		/// <summary>
		/// Current time as a character-string of length 16, represented in the format YYYYMMDDhhmmssxx (4 characters for the year; 2 characters each for the month, the day, the hour, the minute, and the second; and 2 additional reserved '0' characters).
		/// <para>The value of this field only makes sense for tokens equipped with a clock, as indicated in the token information flags</para>
		/// </summary>
		String^ utcTime;
	};

	/// <summary>
	/// Provides information about a particular slot in the system.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public ref class CryptokiInfo
	{
	public:

		/// <summary>
		/// Initializes a new instance of the <see cref="CryptokiInfo"/> class.
		/// </summary>
		CryptokiInfo(void)
		{
			this->LibraryDescription = this->ManufacturerID = "";
			Flags = 0;
			this->CryptokiVersion = gcnew CVersion();
			this->LibraryVersion = gcnew CVersion();
		};

		/// <summary>
		/// Description of the library. Must be padded with the blank character (' '). Should ''not'' be null-terminated.
		/// </summary>
		String^ LibraryDescription;

		/// <summary>
		/// ID of the Cryptoki library manufacturer. Must be padded with the blank character (' '). Should ''not'' be null-terminated.
		/// </summary>
		String^ ManufacturerID;

		/// <summary>
		/// Bit flags reserved for future versions. Must be zero for this version.
		/// </summary>
		UInt32 Flags;

		/// <summary>
		/// Cryptoki interface version number, for compatibility with future revisions of this interface.
		/// </summary>
		CVersion^ CryptokiVersion;

		/// <summary>
		/// Cryptoki library version number.
		/// </summary>
		CVersion^ LibraryVersion;
	};

	/// <summary>
	/// Cryptoki Class is implemented as a .Net compatible library supporting the HSM cryptographic functions in the device cryptoki DLL interface.
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public ref class Cryptoki
	{
	public:
		/// <summary>
		/// Type of EC Basis over F2^m.
		/// </summary>
		enum class ECBasis
		{
			/// <summary>
			/// Gaussian Normal Basis - parameters = 0, 0, 0
			/// </summary>
			GnBasis = ECBT_GnBasis,

			/// <summary>
			/// Trinomial Basis - parameters = k, 0, 0
			/// </summary>
			TpBasis = ECBT_TpBasis,

			/// <summary>
			/// Pentanomial Basis - parameters = k1, k2, k3
			/// </summary>
			PpBasis = ECBT_PpBasis,
		};

		/// <summary>
		/// Default subject for RSA Key-pair.
		/// </summary>
		static array<Byte>^ DefaultRSA_KeySubject = gcnew array<Byte>{ 0x30, 0x0B, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x00 };

		/// <summary>
		/// Gets the usage level of the HSM as a percentage i.e. the load on the HSM.
		/// <para>Before calling this function, the Cryptoki must be initialized (C_Initialize).</para>
		/// </summary>
		/// <param name="deviceID">the index number of HSM</param>
		/// <param name="value">the output HSM usage level (percentage)</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/04	Created
		/// </history>
		static void GetHSMUsageLevel(UInt32 deviceID, UInt32% value);

		/// <summary>
		/// Initializes the Cryptoki library.
		/// </summary>
		/// <param name="useOSThreading">This parameter indicating whether cryptoki library can use the native operation system threading model for locking. Should be set to 'True' in all multithreaded applications.</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void CInitialize(Boolean useOSThreading);

		/// <summary>
		/// Finalize the Cryptoki library. This Function is called to indicate that an application is finished with the Cryptoki library. It should be the last Cryptoki call made by an application.
		/// </summary>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void CFinalize();

		/// <summary>
		/// Set the security mode of the device.
		/// </summary>
		/// <param name="deviceNumber">the index number of device to update</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <param name="securityMode">new security mode to set in the device</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void SetDeviceSecurityMode(int deviceNumber, String^ adminPIN, SecurityFlag securityMode);

		/// <summary>
		/// Get the device current security mode.
		/// <para>The 32-bit value is going to be the logical OR of various security CKF_XXX flags.</para>
		/// </summary>
		/// <param name="deviceNumber">the index number of device</param>
		/// <param name="securityMode">output current status of the device security mode</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/15	Created
		/// </history>
		static void GetDeviceSecurityMode(UInt32 deviceNumber, UInt32% securityMode);

		/// <summary>
		/// Get the device current security mode.
		/// </summary>
		/// <param name="deviceNumber">the index number of device</param>
		/// <param name="securityMode">output the current status of each flag in the device security mode</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/27	Created
		/// </history>
		static void GetDeviceSecurityMode(UInt32 deviceNumber, System::Collections::Generic::Dictionary<SecurityFlag, Boolean>^% securityMode);

		/// <summary>
		/// Get the specific flag in current security mode.
		/// </summary>
		/// <param name="deviceNumber">the index number of device</param>
		/// <param name="flag">the input flag identifier</param>
		/// <param name="status">output the current status of the flag in device security mode</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/27	Created
		/// </history>
		static void GetSecurityFlagStatus(UInt32 deviceNumber, SecurityFlag flag, Boolean% status);

		/// <summary>
		/// Set the specific flag status in device security mode.
		/// </summary>
		/// <param name="deviceNumber">the index number of device</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <param name="flag">the input flag identifier</param>
		/// <param name="status">the input status of the flag</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/27	Created
		/// </history>
		static void SetSecurityFlagStatus(UInt32 deviceNumber, String^ adminPIN, SecurityFlag flag, Boolean status);

		/// <summary>
		/// Retrieve information concerning a device or slot.
		/// </summary>
		/// <param name="deviceNumber">the index number of device</param>
		/// <param name="itemNumber">the input item number, depends on the value of eInfo (e.g. slotID for 'TOKEN_SESSION_COUNT')</param>
		/// <param name="eInfo">the input type of information to retrieve</param>
		/// <param name="info">the output string information</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/04	Created
		/// </history>
		static void GetDeviceInfo(UInt32 deviceNumber, Int32 itemNumber, DeviceInfoType eInfo, String^% info);

		/// <summary>
		/// Determine the total number of sessions open on all tokens on all adapters.
		/// </summary>
		/// <param name="sessionCount">reference to int to hold the number of open session</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/30	Created
		/// </history>
		static void GetTotalSessionCount(UInt32% sessionCount);

		/// <summary>
		/// Determine the number of applications currently using cryptoki.
		/// </summary>
		/// <param name="applicationCount">the output number of applications currently using cryptoki</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/16	Created
		/// </history>
		static void GetApplicationCount(UInt32% applicationCount);
		
		/// <summary>
		/// closes all sessions an application has with a token.
		/// <para>After successful execution of this function, the login state of the token for the application returns to public sessions.</para>
		/// </summary>
		/// <param name="slotID">specifies the token's slot.</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/17	Created
		/// </history>
		static void CloseAllSessions(UInt32 slotID);

		/// <summary>
		/// Obtains a list of slots in the device.
		/// </summary>
		/// <param name="tokenPresent">it's indicating whether the list obtained includes only those slots with a token present ('True'), or all slots ('False')</param>
		/// <param name="tokensName">the output list of tokens name</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/18	Created
		/// </history>
		static void GetSlotList(Boolean tokenPresent, List<String^>^% tokensName);

		/// <summary>
		/// Find a token with the specified label and return the corresponding slot id.
		/// <para>This function is not supported in the current version of 'LL_SecureModule'.</para>
		/// </summary>
		/// <param name="label">string identifying Token to find</param>
		/// <param name="slotID">reference to slot id to hold located slot id which contains the Token</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/30	Created
		/// </history>
		static void FindTokenByName(String^ label, UInt32% slotID);

		/// <summary>
		/// Obtains general information about Cryptoki library.
		/// </summary>
		/// <param name="cryptokiInfo">the cryptoki library information</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/18	Created
		/// </history>
		static void GetInfo(CryptokiInfo^% cryptokiInfo);

		/// <summary>
		/// Obtains information about a particular slot in the device.
		/// </summary>
		/// <param name="slotID">is the ID of the slot</param>
		/// <param name="slotInfo">the slot information</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/18	Created
		/// </history>
		static void GetSlotInfo(UInt32 slotID, SlotInfo^% slotInfo);

		/// <summary>
		/// Returns the HSM id for the specified user Slot ID.
		/// <para>This functionality is not supported in WLD mode</para>
		/// </summary>
		/// <param name="slotID">the input ID of the slot</param>
		/// <param name="deviceID">the output ID of HSM</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/04	Created
		/// </history>
		static void GetDeviceIDFromSlotID(UInt32 slotID, UInt32% deviceID);

#ifndef _PTKC_V400_
		/// <summary>
		/// This function can be used by an application to simulate the behavior of the WLD or HA system when an HSM fails.
		/// </summary>
		/// <param name="deviceID">the input ID of HSM</param>
		/// <param name="disable">disable/enable</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/04	Created
		/// </history>
		static void SetDeviceDead(UInt32 deviceID, Boolean disable);
#endif

		/// <summary>
		/// Obtains information about a particular token in the device.
		/// </summary>
		/// <param name="slotID">is the ID of the slot</param>
		/// <param name="tokenInfo">the token information</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/18	Created
		/// </history>
		static void GetTokenInfo(UInt32 slotID, TokenInfo^% tokenInfo);

		/// <summary>
		/// Determine the total number of sessions open on the specified token.
		/// </summary>
		/// <param name="deviceNumber">device number</param>
		/// <param name="slotID">the index of the slot within the device</param>
		/// <param name="sessionCount">the output number of opened sessions on the token</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/15	Created
		/// </history>
		static void GetSlotSessionCount(UInt32 deviceNumber, UInt32 slotID, UInt32% sessionCount);

		/// <summary>
		/// Create the specified number of slots on the specified device.
		/// <para>This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
		/// </summary>
		/// <param name="deviceNumber">device index number to update</param>
		/// <param name="adminPIN">admin toke user PIN</param>
		/// <param name="numSlots">number of new slots to create</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/26	Created
		/// </history>
		static void CreateSlots(UInt32 deviceNumber, String^ adminPIN, UInt32 numSlots);

		/// <summary>
		/// Delete the specified slot on the specified device.
		/// <para>This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
		/// </summary>
		/// <param name="slotID">the slot number</param>
		/// <param name="adminPIN">admin toke user PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/26	Created
		/// </history>
		static void DeleteSlot(UInt32 slotID, String^ adminPIN);

		/// <summary>
		/// Change the Admin SO/User PIN of a device.
		/// </summary>
		/// <param name="deviceNumber">device index number</param>
		/// <param name="userType">user's type</param>
		/// <param name="oldPIN">current Admin Token SO/User PIN</param>
		/// <param name="newPIN">new Admin Token SO/User PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/29	Created
		/// </history>
		static void ChangeAdminPIN(UInt32 deviceNumber, UserType userType, String^ oldPIN, String^ newPIN);

		/// <summary>
		/// Initialise the Admin user PIN of a device.
		/// </summary>
		/// <param name="deviceNumber">device index number</param>
		/// <param name="SOPIN">current Admin Token SO PIN</param>
		/// <param name="adminPIN">value to set as the Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/29	Created
		/// </history>
		static void InitAdminPIN(UInt32 deviceNumber, String^ SOPIN, String^ adminPIN);

		/// <summary>
		/// Synchronise the clock of the device with the host.
		/// </summary>
		/// <param name="deviceNumber">device index number</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/29	Created
		/// </history>
		static void SyncClock(int deviceNumber, String^ adminPIN);

		/// <summary>
		/// Set the clock of the device to the specified time.
		/// <para>The passed in time string must be GMT.</para>
		/// </summary>
		/// <param name="deviceNumber">device number</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <param name="dateTime">Date/Time string of the format "yyyymmddhhnnss00".</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/29	Created
		/// </history>
		static void SetClock(int deviceNumber, String^ adminPIN, String^ dateTime);

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
		/// <param name="slotID">the slot number</param>
		/// <param name="SOPIN">SO's initial PIN</param>
		/// <param name="tokenLabel">label of the token</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/18	Created
		/// </history>
		static void InitToken(UInt32 slotID, String^ SOPIN, String^ tokenLabel);

		/// <summary>
		/// Initializes a token and set its user PIN.
		/// <para>If the token has not been initialized (i.e. new from the factory), then the 'SOPIN' parameter becomes the initial value of the SO PIN.</para>
		/// <para>If the token is being reinitialized, the 'SOPIN' parameter is checked against the existing SO PIN to authorize the initialization operation.</para>
		/// <para>In both cases, the SO PIN is the value 'SOPIN' after the function completes successfully.</para>
		/// <para>A token cannot be initialized if Cryptoki detects that any application has an open session with it.</para>
		/// <para>When a token is initialized, all objects that can be destroyed are destroyed. (i.e., all except for "indestructible" objects such as keys built into the token).</para>
		/// <para>Depending on the token, some default objects may be created, and attributes of some objects may be set to default values.</para>
		/// </summary>
		/// <param name="slotID">the slot number</param>
		/// <param name="SOPIN">Security Officer's initial PIN</param>
		/// <param name="UserPIN">normal User's initial PIN</param>
		/// <param name="tokenLabel">label of the token</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/26	Created
		/// </history>
		static void InitToken(UInt32 slotID, String^ SOPIN, String^ UserPIN, String^ tokenLabel);

		/// <summary>
		/// Initialise the token.
		/// <para>There is an argument that says this function should not be useful, as it is for initializing a user Token, but the initialization may require the Admin Token USER PIN, so it belongs in this library.</para>
		/// <para>If the security mode of the slot is CKF_NO_CLEAR_PINS then the Admin Token USER PIN is required, otherwise it is ignored.</para>
		/// </summary>
		/// <param name="slotID">the slot number</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <param name="tokenLabel">label of the token</param>
		/// <param name="SOPIN">Security Officer's initial PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/29	Created
		/// </history>
		static void InitTokenByAdmin(UInt32 slotID, String^ adminPIN, String^ tokenLabel, String^ SOPIN);

		/// <summary>
		/// Reset the token.
		/// <para>This will clear the USER PIN and change the SO PIN and Token Label.</para>
		/// <para>There is an argument that says this function should not be in this library, as it is for resetting a user Token, but it complements the 'InitToken' method, so it belongs in this library.</para>
		/// </summary>
		/// <param name="slotID">the ID of the slot to reset</param>
		/// <param name="SOPIN">current Token SO PIN</param>
		/// <param name="newSOPIN">new Token SO PIN to set</param>
		/// <param name="newLabel">new Token Label to set</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/30	Created
		/// </history>
		static void ResetToken(UInt32 slotID, String^ SOPIN, String^ newSOPIN, String^ newLabel);

		/// <summary>
		/// Tamper the device.
		/// <para>This will erase all stored keys and data, returning the device to it's original out of the box state, i.e. uninitializes Admin Token and one user slot).</para>
		/// <para>This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
		/// </summary>
		/// <param name="deviceNumber">device to tamper</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/30	Created
		/// </history>
		static void TamperAdapter(UInt32 deviceNumber, String^ adminPIN);

		/// <summary>
		/// Halt the device.
		/// <para>The device will no longer be visible to Cryptoki applications until hsmreset.exe is executed.</para>
		/// </summary>
		/// <param name="deviceNumber">device to tamper</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/30	Created
		/// </history>
		static void HaltAdapter(UInt32 deviceNumber, String^ adminPIN);

		/// <summary>
		/// Returns the real HSM id for the specified user Slot ID.
		/// </summary>
		/// <param name="slotID">the input slot ID</param>
		/// <param name="deviceID">the output device ID</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/30	Created
		/// </history>
		static void GetDeviceNumberFromSlotID(UInt32 slotID, UInt32% deviceID);

		/// <summary>
		/// This Function Encode elliptic curve domain parameters over Fp.
		/// <para>Do DER enc of ECC Domain Parameters Prime.</para>
		/// <para>All integer values are variable length big endian numbers with optional leading zeros. Integer lengths are all in bytes.</para>
		/// </summary>
		/// <param name="prime">the input Elliptic Curve Prime modulus</param>
		/// <param name="curveA">the input Elliptic Curve coefficient a</param>
		/// <param name="curveB">the input Elliptic Curve coefficient b</param>
		/// <param name="curveSeed">the input Seed (optional may be nullptr)</param>
		/// <param name="baseX">the input Elliptic Curve point X coord</param>
		/// <param name="baseY">the input Elliptic Curve point Y coord</param>
		/// <param name="bpOrder">the input Order n of the Base Point</param>
		/// <param name="cofactor">the input integer h = #E(Fq)/n (optional)</param>
		/// <param name="result">the output encoded Elliptic Curve Domain Parameter over Fp</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		static void EncodeECParamsP(array<Byte>^ prime, array<Byte>^ curveA, array<Byte>^ curveB, array<Byte>^ curveSeed, array<Byte>^ baseX, array<Byte>^ baseY, array<Byte>^ bpOrder, array<Byte>^ cofactor, array<Byte>^% result);

		/// <summary>
		/// This Function Encode elliptic curve domain parameters over F2^m.
		/// <para>Do DER enc of ECC Domain Parameters 2^M</para>
		/// <para>All long integer values are variable length big endian numbers with optional leading zeros, lengths are all in bytes.</para>
		/// </summary>
		/// <param name="m">the input degree of field (m = {113;131;163;193;233;239;283;409;571})</param>
		/// <param name="basis">Should be 'GnBasis' or 'TpBasis' or 'PpBasis'</param>
		/// <param name="parameters">Array of three integers - values depend on basis (ECBT_GnBasis - parameters = 0. 0. 0; ECBT_TpBasis - parameters = k. 0. 0; ECBT_PpBasis - parameters = k1.k2.k3)</param>
		/// <param name="curveA">the input Elliptic Curve coefficient a</param>
		/// <param name="curveB">the input Elliptic Curve coefficient b</param>
		/// <param name="curveSeed">the input Seed (optional may be nullptr)</param>
		/// <param name="baseX">the input Elliptic Curve point X coord</param>
		/// <param name="baseY">the input Elliptic Curve point Y coord</param>
		/// <param name="bpOrder">the input Order n of the Base Point</param>
		/// <param name="cofactor">The input integer h = #E(Fq)/n (optional)</param>
		/// <param name="result">the output encoded Elliptic Curve Domain Parameter over F2^m</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		static void EncodeECParams2M(UInt32 m, ECBasis basis, array<UInt32>^ parameters, array<Byte>^ curveA, array<Byte>^ curveB, array<Byte>^ curveSeed, array<Byte>^ baseX, array<Byte>^ baseY, array<Byte>^ bpOrder, array<Byte>^ cofactor, array<Byte>^% result);

		/// <summary>
		/// This function provides the Object Identifier (OID) of DER encoding of a supported named curve.
		/// <para>This function is typically used to populate the CKA_EC_PARAMS attribute of the template used during EC key pair generation.</para>
		/// </summary>
		/// <param name="curve">the input curve name to get the encoding for</param>
		/// <param name="dp">the output OID of DER encoded Elliptic Curve Domain Parameter</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		static void DerEncodeNamedCurve(CurveName curve, array<Byte>^% dp);

		/// <summary>
		/// This Function exports slot/token.
		/// </summary>
		/// <param name="session">Session that is openned on the token</param>
		/// <param name="tokenData">the output exported token data</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		static void ExportToken(SMSession^ session, array<Byte>^% tokenData);

		/// <summary>
		/// This Function import slot/token.
		/// </summary>
		/// <param name="session">Session that is openned on the destination token</param>
		/// <param name="tokenData">the input exported token data to restore</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		static void ImportToken(SMSession^ session, array<Byte>^ tokenData);

		/// <summary>
		/// Retrieve an event log instance.
		/// <para>Use GetDeviceInfo with EVENT_LOG_COUNT to determine valid values for zero based index.</para>
		/// </summary>
		/// <param name="deviceNumber">the device to retrieve the event log entry from</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <param name="index">index of the entry to retrieve. Valid values are from 0 to EVENT_LOG_COUNT-1.</param>
		/// <param name="entryLog">the output string result</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/07	Created
		/// </history>
		static void GetEventLogEntry(UInt32 deviceNumber, String^ adminPIN, UInt32 index, String^% entryLog);

		/// <summary>
		/// Purge the full event log of the device.
		/// <para>This function will only purge the event log if it is full. Use GetDeviceInfo with EVENT_LOG_FULL to check.</para>
		/// </summary>
		/// <param name="deviceNumber">the device to purge the event log from</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/07	Created
		/// </history>
		static void PurgeEventLog(UInt32 deviceNumber, String^ adminPIN);

		/// <summary>
		/// Upgrade the firmware of the device.
		/// <para>Note: If the firmware upgrade procedure is interrupted, the device may be left in an unusable state.Therefore, the caller must ensure that the operation cannot be terminated by the user, before this function returns.</para>
		/// <para>Note: This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
		/// </summary>
		/// <param name="deviceNumber">the device ID to download the FM to</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <param name="fileName">Name of the file containing the firmware</param>
		/// <param name="verifyOnly">upgrade the device using the specified file or do not upgrade the device, just validate the signature of the firmware file</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/07	Created
		/// </history>
		static void UpgradeFirmware(UInt32 deviceNumber, String^ adminPIN, String^ fileName, Boolean verifyOnly);

		/// <summary>
		/// Download a Functionality Module to a device.
		/// <para>Note: If the firmware upgrade procedure is interrupted, the device may be left in an unusable state.Therefore, the caller must ensure that the operation cannot be terminated by the user, before this function returns.</para>
		/// <para>Note: This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
		/// </summary>
		/// <param name="deviceNumber">the device ID to download the FM to</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <param name="fileName">Name of the certificate kept inside the AdminToken, which will be used to validate the FM image signature</param>
		/// <param name="certName">Name of the file containing the firmware</param>
		/// <param name="verifyOnly">Download the FM using the specified FM image or do not download the FM image, just validate the signature</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/07	Created
		/// </history>
		static void UpgradeFirmware(UInt32 deviceNumber, String^ adminPIN, String^ fileName, String^ certName, Boolean verifyOnly);

		/// <summary>
		/// Disable the downloaded FM in the device.
		/// <para>Note: This function does not check whether the FM is already disabled or not.If a FM that is already disabled is disabled again, the function will report success.</para>
		/// </summary>
		/// <param name="deviceNumber">the device ID to disable FM</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/07	Created
		/// </history>
		static void DisableFm(UInt32 deviceNumber, String^ adminPIN);

		/// <summary>
		/// Force a detection of the peripheral devices.
		/// <para>Note: This operation can only be performed if there are no current Cryptoki sessions open, and the client is the only application using Cryptoki.</para>
		/// </summary>
		/// <param name="deviceNumber">the device ID to perform the rescan.</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/07	Created
		/// </history>
		static void RescanPeripherals(UInt32 deviceNumber, String^ adminPIN);

		/// <summary>
		/// Set a value within the secure configuration of a device for the specified domain. A domain is a collection of configuration items belonging, generally, to a specific application.
		/// </summary>
		/// <param name="deviceNumber">device on which to update configuration</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <param name="configDomain">Configuration domain to set item on</param>
		/// <param name="item">name of item to set</param>
		/// <param name="value">value to set the item to</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/08	Created
		/// </history>
		static void SetHSMConfigItem(UInt32 deviceNumber, String^ adminPIN, String^ configDomain, String^ item, String^ value);

		/// <summary>
		/// Get a value from the secure configuration of a device for the specified domain. A domain is a collection of configuration items belonging, generally, to a specific application.
		/// </summary>
		/// <param name="deviceNumber">device on which to read configuration</param>
		/// <param name="configDomain">Configuration domain to read item from</param>
		/// <param name="item">name of item to get</param>
		/// <param name="value">the output to read value into</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/08	Created
		/// </history>
		static void Cryptoki::GetConfigItem(UInt32 deviceNumber, String^ configDomain, String^ item, String^% value);

		/// <summary>
		/// Set new parameters for the RTC Adjustment Access Control (AAC) for the specified device.
		/// <para>These parameters control how much of an adjustment can be made to the RTC within a specified duration using the unauthenticated HSMADM_AdjustTime() function.</para>
		/// </summary>
		/// <param name="deviceNumber">device to update the RTC AAC parameters.</param>
		/// <param name="aacEnabled">true:Enable RTC Adjustment Access Control. false: Allow unlimited unauthenticated adjustments to the RTC.</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/08	Created
		/// </history>
		static void SetRtcAacEnabled(UInt32 deviceNumber, Boolean aacEnabled, String^ adminPIN);

		/// <summary>
		/// Set new parameters for the RTC Adjustment Access Control (AAC) for the specified device.
		/// <para>These parameters control how much of an adjustment can be made to the RTC within a specified duration using the unauthenticated HSMADM_AdjustTime() function.</para>
		/// </summary>
		/// <param name="deviceNumber">device to update the RTC AAC parameters.</param>
		/// <param name="guardSeconds">Total amount of deviation, in number of seconds, allowed as an adjustment to the RTC within the Guard Duration.</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static void SetRtcAacSeconds(UInt32 deviceNumber, UInt32 guardSeconds, String^ adminPIN);

		/// <summary>
		/// Set new parameters for the RTC Adjustment Access Control (AAC) for the specified device.
		/// <para>These parameters control how much of an adjustment can be made to the RTC within a specified duration using the unauthenticated HSMADM_AdjustTime() function.</para>
		/// </summary>
		/// <param name="deviceNumber">device to update the RTC AAC parameters.</param>
		/// <param name="guardCount">Total number of adjustments that can be made to the RTC within the Guard Duration.</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static void SetRtcAacCount(UInt32 deviceNumber, UInt32 guardCount, String^ adminPIN);

		/// <summary>
		/// Set new parameters for the RTC Adjustment Access Control (AAC) for the specified device.
		/// <para>These parameters control how much of an adjustment can be made to the RTC within a specified duration using the unauthenticated HSMADM_AdjustTime() function.</para>
		/// </summary>
		/// <param name="deviceNumber">device to update the RTC AAC parameters.</param>
		/// <param name="durationDays">The guard duration, in number of days, used to enforce the Guard Seconds and Guard Count limits.</param>
		/// <param name="adminPIN">current Admin Token USER PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static void SetRtcAacDuration(UInt32 deviceNumber, UInt32 durationDays, String^ adminPIN);

		/// <summary>
		/// Obtain the current time of day from the HSM RTC.
		/// </summary>
		/// <param name="deviceNumber">the zero-based index of the HSM number to be used.</param>
		/// <param name="adminTime">the output reference variable which will be initialized with the current time of day.</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static void HSMAdmin_GetTimeOfDay(UInt32 deviceNumber, HSMAdminTime^% adminTime);

		/// <summary>
		/// Adjust the time, or obtain the current adjustment value.
		/// <para>The parameter, delta, indicates the adjustment factor to be applied to the HSM RTC.</para>
		/// <para>If there is an adjustment being performed when this function is called, the remaining adjustment factor is discarded, and the new adjustment value is used instead.</para>
		/// <para>This function can also be used to obtain the remaining adjustment amount.</para>
		/// <para>If the parameter delta is NULL, and oldDelta is a valid pointer, it will return the current delta value.</para>
		/// </summary>
		/// <param name="deviceNumber">the zero-based index of the HSM number to be used.</param>
		/// <param name="delta">The amount of adjustment to be made to the RTC. This parameter must be nullptr, if oldDelta is not nullptr.</param>
		/// <param name="oldDelta">the output variable that will receive the remaining amount of adjustment from a previous call. This parameter must be nullptr if delta is not nullptr.</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static void HSMAdmin_AdjustTime(UInt32 deviceNumber, HSMAdminTime^ delta, HSMAdminTime^% oldDelta);

		/// <summary>
		/// Change the HSM RTC status. An external manager may use this function to change the status of the RTC.
		/// </summary>
		/// <param name="deviceNumber">the zero-based index of the HSM number to be used.</param>
		/// <param name="status">The new status of the RTC.</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static void HSMAdmin_SetRtcStatus(UInt32 deviceNumber, RTCStatus status);

		/// <summary>
		/// Obtain the HSM RTC status. An application may use this function to determine the availability or reliability of the RTC.
		/// </summary>
		/// <param name="deviceNumber">the zero-based index of the HSM number to be used.</param>
		/// <returns>the status of RTC</returns>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static RTCStatus HSMAdmin_GetRtcStatus(UInt32 deviceNumber);

		/// <summary>
		/// Get the effective total amount, in milliseconds, of adjustments made to the RTC using the HSMADM_AdjustTime() function.
		/// </summary>
		/// <param name="deviceNumber">the zero-based index of the HSM number to be used.</param>
		/// <returns>the value of RTC adjustments. The return value is only valid if RTC Access Control is enabled.</returns>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static UInt32 HSMAdmin_GetRtcAdjustAmount(UInt32 deviceNumber);

		/// <summary>
		/// Get the effective count of adjustments made to the RTC using the HSMADM_AdjustTime() function.
		/// </summary>
		/// <param name="deviceNumber">the zero-based index of the HSM number to be used.</param>
		/// <returns>the value of RTC effective count of adjustments. The return value is only valid if RTC Access Control is enabled.</returns>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/20	Created
		/// </history>
		static UInt32 HSMAdmin_GetRtcAdjustCount(UInt32 deviceNumber);
	};
}
