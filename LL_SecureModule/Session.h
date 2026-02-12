#pragma once

#include "SecureModuleException.h"

#include "Mechanisms.h"

using namespace System;

namespace LL_SecureModule
{
	/// <summary>
	/// provides information about a session.
	/// </summary>
	public ref class SessionInfo
	{
	public:
		/// <summary>
		/// Default Class constructor.
		/// </summary>
		SessionInfo(void) { };
	};

	/// <summary>
	/// Type of session.
	/// </summary>
	public enum class SessionType
	{
		/// <summary>
		/// ...
		/// </summary>
		EXCLUSIVE_SESSION = CKF_EXCLUSIVE_SESSION,

		/// <summary>
		/// 'True' if the session is read/write; 'False' if the session is read-only.
		/// </summary>
		RW_SESSION = CKF_RW_SESSION,

		/// <summary>
		/// This flag is provided for backward compatibility, and should always be set to 'True'.
		/// </summary>
		SERIAL_SESSION = CKF_SERIAL_SESSION
	};

	/// <summary>
	/// Types of users.
	/// </summary>
	public enum class UserType
	{
		/// <summary>
		/// Normal user
		/// <para>The normal user, which manipulates objects and performs most operations, cannot log in until the security officer has set that user's PIN.</para>
		/// </summary>
		USER = CKU_USER,

		/// <summary>
		/// Security Officer.
		/// <para>The security officer's only role is to initialize a token and set the normal users access PIN.</para>
		/// </summary>
		SO = CKU_SO,

		/// <summary>
		/// Matiran-co. selfdefined user which is made by Functionality Module.
		/// </summary>
		FM_USER = (int)(CK_VENDOR_DEFINED | (0x40000000uL + 0xA001)),

		/// <summary>
		/// Unknown user.
		/// </summary>
		UNKNOWN = (int)CK_VENDOR_DEFINED
	};

#ifndef _PTKC_V400_
	/// <summary>
	/// Remote Activation feature flags.
	/// </summary>
	public enum class AuthenticationFlag
	{
		AUTH_RESPONSE = CKF_AUTH_RESPONSE,
		AUTH_TEMP_PIN = CKF_AUTH_TEMP_PIN,
	};
#endif

	/// <summary>
	/// State of the session.
	/// </summary>
	public enum class SessionState
	{
		RO_PUBLIC_SESSION = CKS_RO_PUBLIC_SESSION,
		RO_USER_FUNCTIONS = CKS_RO_USER_FUNCTIONS,
		RW_PUBLIC_SESSION = CKS_RW_PUBLIC_SESSION,
		RW_USER_FUNCTIONS = CKS_RW_USER_FUNCTIONS,
		RW_SO_FUNCTIONS = CKS_RW_SO_FUNCTIONS,
	};

	/// <summary>
	/// SMSession Class representing a logical connection between an application and a token.
	/// </summary>
	public ref class SMSession
	{
	private:

		/// <summary>
		/// PKCS#11 handle of session
		/// </summary>
		CK_SESSION_HANDLE hSession;

		/// <summary>
		/// ID of the token's slot
		/// </summary>
		CK_SLOT_ID slotID;

		/// <summary>
		/// Indicates that if a user logs into the token or not.
		/// </summary>
		Boolean isLoggedIn;

		/// <summary>
		/// represents the current user that logged into the token.
		/// </summary>
		UserType currentUser;

	public:

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		SMSession(void) { this->slotID = (CK_SLOT_ID)UINT_MAX; this->hSession = CK_INVALID_HANDLE; this->isLoggedIn = false; this->currentUser = UserType::UNKNOWN; };

		/// <summary>
		/// Initializes new instance of SMSession class.
		/// </summary>
		/// <param name="slotID">the ID of the token's slot</param>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		SMSession(UInt32 slotID) { this->slotID = (CK_SLOT_ID)slotID; this->hSession = CK_INVALID_HANDLE; this->isLoggedIn = false; this->currentUser = UserType::UNKNOWN; };

		/// <summary>
		/// Initializes a new instance of the <see cref="SMSession"/> class and open a new session on the HSM.
		/// </summary>
		/// <param name="slotID">the ID of the token's slot</param>
		/// <param name="sessionType">type of the session to open.</param>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/08/20	Created
		/// </history>
		SMSession(UInt32 slotID, SessionType sessionType);

		/// <summary>
		/// Initializes a new instance of the <see cref="SMSession" /> class and then open a new session on the HSM and try to logs user into the new session.
		/// <para>If the specific user already logged into the session, this function can ignore it without throwing an Exception error.</para>
		/// </summary>
		/// <param name="slotID">the ID of the token's slot</param>
		/// <param name="sessionType">type of the session to open.</param>
		/// <param name="userType">Type of the user.</param>
		/// <param name="pin">The user pin.</param>
		/// <param name="ignoreIfAlreadyLoggedIn">Should ignore if user already logged-in.</param>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/08/20	Created
		/// </history>
		SMSession(UInt32 slotID, SessionType sessionType, UserType userType, String^ pin, bool ignoreIfAlreadyLoggedIn);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/28	Created
		/// </history>
		SMSession(SMSession^ session);

		/// <summary>The 'SessionID' property represents the handle of session.</summary>
		/// <value>The 'SessionID' property gets the value of the CK_SESSION_HANDLE field, 'hSession'.</value>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		property UInt32 SessionID
		{
			UInt32 get() { return (UInt32)this->hSession; }
		}

		/// <summary>The 'SlotID' property represents the ID of the token's slot.</summary>
		/// <value>The 'SlotID' property gets the value of the CK_SLOT_ID field, 'slotID'.</value>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		property UInt32 SlotID
		{
			UInt32 get() { return (UInt32)this->slotID; }
		}

		/// <summary>The 'IsLoggedIn' property represents the login status of login.</summary>
		/// <value>The 'IsLoggedIn' property gets the value of the boolean field, 'isLoggedIn'.</value>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		property Boolean IsLoggedIn
		{
			Boolean get() { return this->isLoggedIn; }
		}

		/// <summary>The 'CurrentUser' property represents the current user type that logged into the token.</summary>
		/// <value>The 'CurrentUser' property gets the value of the UserType field, 'currentUser'.</value>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		property UserType CurrentUser
		{
			UserType get() { return this->currentUser; }
		}

		/// <summary>
		/// Determines whether [The session handle is a valid identifier].
		/// <para>The session handle should be non-zero</para>
		/// </summary>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/08/21	Created
		/// </history>
		Boolean IsValidSessionHandle()
		{
			if (this->hSession == CK_INVALID_HANDLE)
				return false;
			return true;
		}

		/// <summary>
		/// Initializes the normal user's PIN.
		/// <para>This function can only be called in the "R/W SO Functions" state. An attempt to call it from a session in any other state fails with error.</para>
		/// </summary>
		/// <param name="userPin">normal user's PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		void InitPIN(String^ userPin);

		/// <summary>
		/// Modifies the PIN of the user that is currently logged in.
		/// </summary>
		/// <param name="oldPin">the old PIN</param>
		/// <param name="newPin">the new PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		void SetPIN(String^ oldPin, String^ newPin);

		/// <summary>
		/// Modifies the PIN of the user that is currently logged in.
		/// <para>This function is not supported in the current version of 'LL_SecureModule'.</para>
		/// </summary>
		/// <param name="sessionInfo">the output session's information</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		void GetSessionInfo(SessionInfo^% sessionInfo);

		/// <summary>
		/// Opens a session between an application and a token in a particular slot.
		/// <para>When opening a session with 'OpenSession', the flags parameter consists of the logical OR of zero or more bit flags defined in the CK_SESSION_INFO data type.</para>
		/// <para>For legacy reasons, the CKF_SERIAL_SESSION bit must always be set; if a call to 'OpenSession' does not have this bit set, the call should return unsuccessfully with the error code CKR_PARALLEL_NOT_SUPPORTED.</para>
		/// </summary>
		/// <param name="slotID">the slot's ID</param>
		/// <param name="sessionType">indicates the type of session</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		void OpenSession(UInt32 slotID, SessionType sessionType);

		/// <summary>
		/// Opens a session between an application and a token in a particular slot.
		/// <para>When opening a session with 'OpenSession', the flags parameter consists of the logical OR of zero or more bit flags defined in the CK_SESSION_INFO data type.</para>
		/// <para>For legacy reasons, the CKF_SERIAL_SESSION bit must always be set; if a call to 'OpenSession' does not have this bit set, the call should return unsuccessfully with the error code CKR_PARALLEL_NOT_SUPPORTED.</para>
		/// </summary>
		/// <param name="sessionType">indicates the type of session</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		void OpenSession(SessionType sessionType);

		/// <summary>
		/// Closes a session between an application and a token.
		/// <para>When a session is closed, all session objects created by the session are destroyed automatically, even if the application has other sessions using the objects.</para>
		/// <para>If this function is successful and it closes the last session between the application and the token, the login state of the token for the application returns to public sessions.</para>
		/// </summary>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		void CloseSession();

#ifndef _PTKC_V400_
		/// <summary>
		/// This function can be used to identify the HSM that a particular WLD or HA session has been assigned to.
		/// </summary>
		/// <param name="deviceID">the output device ID</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/30	Created
		/// </history>
		void GetDeviceID(UInt32% deviceID);
#endif

		/// <summary>
		/// This function returns the HSM session handle for the specified user Session Handle.
		/// </summary>
		/// <param name="HSMSession">the output HSM session</param>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/04	Created
		/// </history>
		void ToHSMSession(SMSession^% HSMSession);

		/// <summary>
		/// Logs a user into a token.
		/// <para>If the application calling 'Login' has a R/O session open with the token, then it will be unable to log the SO into a session.</para>
		/// </summary>
		/// <param name="userType">user's type</param>
		/// <param name="pin">user's PIN</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		void Login(UserType userType, String^ pin);

		/// <summary>
		/// Logs a user into a token.
		/// <para>If the specific user already logged into the session, this function can ignore it without throwing an Exception error.</para>
		/// <para>If the application calling 'Login' has a R/O session open with the token, then it will be unable to log the SO into a session.</para>
		/// </summary>
		/// <param name="userType">user's type</param>
		/// <param name="pin">user's PIN</param>
		/// <param name="ignoreIfAlreadyLoggedIn">should ignore if user already logged-in.</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/08/20	Created
		/// </history>
		void Login(UserType userType, String^ pin, bool ignoreIfAlreadyLoggedIn);

#ifndef _PTKC_V400_
		/// <summary>
		/// Challenge/Response operation login.
		/// <para>If the application calling 'Login' has a R/O session open with the token, then it will be unable to log the SO into a session.</para>
		/// </summary>
		/// <param name="userType">user's type</param>
		/// <param name="authFlag">authentication mode</param>
		/// <param name="response">response</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		void Login(UserType userType, AuthenticationFlag authFlag, array<Byte>^ response);
#endif

		/// <summary>
		/// Logs a user out from a token.
		/// <para>Depending on the current user type, if the call succeeds, each of the application's sessions will enter either the "R/W Public SMSession" state or the "R/O Public SMSession" state.</para>
		/// <para>When 'Logout' successfully executes, any of the application's handles to private objects become invalid (even if a user is later logged back into the token, those handles remain invalid).</para>
		/// <para>In addition, all private session objects from sessions belonging to the application are destroyed.</para>
		/// </summary>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/19	Created
		/// </history>
		void Logout();

#ifdef _WITH_AUTH_CHALLENGE_RESPONSE_
		/// <summary>
		/// This function is a PTK C extension to PKCS#11 provided with the PTK C SDK as a host side library function.
		/// <para>The function requests the HSM to generate a random 16 byte challenge value and to return the challenge to the calling application. The function uses the CKH_VD_USER object to fetch the Challenge.</para>
		/// <para>The Application can use authentication data (pin) to create a Response from the challenge. See description of Gen_AUTH_Response. for more details.</para>
		/// <para>The Response can be used with the C_Login function to authenticate the user to the Token. See description of C_Login for more details.</para>
		/// <para>Operator Authentication:</para>
		/// <para>Protect toolkit C provides several methods to authenticate the operator.</para>
		/// <para>- The conventional C_Login allows the user Pin to be presented directly to the Token.</para>
		/// <para>- The Pin Challenge feature provides the operator the ability to authenticate to a token by first requesting and then responding to a random challenge. This is a form of bi-directional authentication protocol. The main advantage of this authentication system over the normal PKCS#11 Login command is that the clear PIN value never leaves the proximity of the operator. It is particularly useful in the situation where the operator is physically remote from the HSM</para>
		/// <para>- Temporary Pins are an authentication technique that gives the ability to a process to pass user authentication to another process without having to hold a long term sensitive authentication data (such as the PIN) or repeatedly require the operator to authenticate.</para>
		/// <para>A new CKO_HW_FEATURE object called CKH_VD_USER is provided by the firmware to allow the application to obtain the random challenge for either the User Password or SO Password.</para>
		/// <para>The Object has an attribute that an application can read to generate and obtain a random challenge.</para>
		/// <para>A new challenge value will generated each time the attribute is read. A separate Challenge is held for each registered application.</para>
		/// <para>The same challenge can be used for User or SO authentication.</para>
		/// <para>The calling application converts the challenge into a Response by using the following algorithm:</para>
		/// <para>Response = SHA-256( challenge | PVC)</para>
		/// <para>Where PVC = LEFT64BIT( SHA1(password | userTypeByte)</para>
		/// <para>A host side static library function Gen_Auth_Response is provided in the SDK to assist developers in using this scheme.</para>
		/// <para>The CKH_VD_USER has an attribute that an application can read to generate and obtain a Temporary Pin. Only one SO and one User Temporary pin may exist at any one time in any single Token. Each read from this attribute will generate a new Temporary Pin.</para>
		/// <para>Any Temporary Pins in a Token are automatically destroyed when the generating process logs off or is terminated or the HSM has reset – whichever comes first.</para>
		/// <para>Under Cryptoki all authentication of users to the HSM is valid for the calling process only. Each application must authenticate separately. Once a process has authenticated is granted appropriate access to the services of the token.</para>
		/// <para>With PTK-C, if a process forks a new process then the new process must authenticate itself - it can not inherit the authentication of the parent.</para>
		/// <para>The Temporary Pin feature is a method where a parent process can pass on its authentication to a child process without having to pass the sensitive pin value.</para>
		/// <para>The Response and Temporary Pin are passed to the HSM using the Login function. The Function will be extended such that unused bits in the userType parameter will be set to indicate that a Response value or Temporary PIN is being used instead of the normal password.</para>
		/// <para>The following bits are added to the userType parameter of the C_Login Function to specify the type of authentication required:</para>
		/// <para>- AUTH_RESPONSE</para>
		/// <para>- AUTH_TEMP_PIN</para>
		/// <para>Programmatic Challenge Response Activation:</para>
		/// <para>1. Remote client initiates activation by sending a message to the server</para>
		/// <para>2. Server Process registers itself to HSMs using C_Initialise</para>
		/// <para>3. Server Process opens a session to a Token</para>
		/// <para>4. Server Process obtains a Random challenge by calling GetAuthChallenge</para>
		/// <para>5. Server Process sends challenge to Remote client</para>
		/// <para>6. Client computes the response value using Gen_Auth_Response and returns it to the Server</para>
		/// <para>7. Server Process supplies response as PIN value to the Login function using a special userType parameter value</para>
		/// <para>Pass Authentication to a New Process:</para>
		/// <para>1. Server Primary Process authenticates using Programmatic Challenge Response Activation</para>
		/// <para>2. Server Primary Process obtains a temporary pin by calling GetTmpPin</para>
		/// <para>3. For each spawned process, the Primary Process passes the temporary PIN to it using an appropriate inter process communication method (or by forking).</para>
		/// <para>4. New Process registers itself to HSMs using Initialize</para>
		/// <para>5. New Process opens a session to the Required Token</para>
		/// <para>6. New Process authenticates to Token with Login function and the temporary pin using a special userType parameter value</para>
		/// </summary>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		void GetAuthChallenge(array<Byte>^% challenge);

		/// <summary>
		/// This function is a PTK C extension to PKCS#11provided with the PTK C SDK as a host side library function.
		/// <para>The function requests the HSM to generate a random Temporary Pin value and to return the pin to the calling application. The function uses the CKH_VD_USER object to fetch the Pin.</para>
		/// <para>A User or SO must be already logged on or this function will fail with error USER_NOT_LOGGED_ON.</para>
		/// <para>The Application can pass this Temporary Pin to another process which can then use it to authenticate to the HSM (as the same user type only).</para>
		/// <para>The Temporary Pin can be passed to the C_Login function to authenticate the user to the Token.</para>
		/// <para>Protect toolkit C provides several methods to authenticate the operator.</para>
		/// <para>- The conventional C_Login allows the user Pin to be presented directly to the Token.</para>
		/// <para>- The Pin Challenge feature provides the operator the ability to authenticate to a token by first requesting and then responding to a random challenge. This is a form of bi-directional authentication protocol. The main advantage of this authentication system over the normal PKCS#11 Login command is that the clear PIN value never leaves the proximity of the operator. It is particularly useful in the situation where the operator is physically remote from the HSM</para>
		/// <para>- Temporary Pins are an authentication technique that gives the ability to a process to pass user authentication to another process without having to hold a long term sensitive authentication data (such as the PIN) or repeatedly require the operator to authenticate.</para>
		/// <para>A new CKO_HW_FEATURE object called CKH_VD_USER is provided by the firmware to allow the application to obtain the random challenge for either the User Password or SO Password.</para>
		/// <para>The Object has an attribute that an application can read to generate and obtain a random challenge.</para>
		/// <para>A new challenge value will generated each time the attribute is read. A separate Challenge is held for each registered application.</para>
		/// <para>The same challenge can be used for User or SO authentication.</para>
		/// <para>The calling application converts the challenge into a Response by using the following algorithm:</para>
		/// <para>Response = SHA-256( challenge | PVC)</para>
		/// <para>Where PVC = LEFT64BIT( SHA1(password | userTypeByte)</para>
		/// <para>A host side static library function Gen_Auth_Response is provided in the SDK to assist developers in using this scheme.</para>
		/// <para>The CKH_VD_USER has an attribute that an application can read to generate and obtain a Temporary Pin. Only one SO and one User Temporary pin may exist at any one time in any single Token. Each read from this attribute will generate a new Temporary Pin.</para>
		/// <para>Any Temporary Pins in a Token are automatically destroyed when the generating process logs off or is terminated or the HSM has reset – whichever comes first.</para>
		/// <para>Under Cryptoki all authentication of users to the HSM is valid for the calling process only. Each application must authenticate separately. Once a process has authenticated is granted appropriate access to the services of the token.</para>
		/// <para>With PTK-C, if a process forks a new process then the new process must authenticate itself - it can not inherit the authentication of the parent.</para>
		/// <para>The Temporary Pin feature is a method where a parent process can pass on its authentication to a child process without having to pass the sensitive pin value.</para>
		/// <para>The Response and Temporary Pin are passed to the HSM using the Login function. The Function will be extended such that unused bits in the userType parameter will be set to indicate that a Response value or Temporary PIN is being used instead of the normal password.</para>
		/// <para>The following bits are added to the userType parameter of the C_Login Function to specify the type of authentication required:</para>
		/// <para>- AUTH_RESPONSE</para>
		/// <para>- AUTH_TEMP_PIN</para>
		/// <para>Programmatic Challenge Response Activation:</para>
		/// <para>1. Remote client initiates activation by sending a message to the server</para>
		/// <para>2. Server Process registers itself to HSMs using C_Initialise</para>
		/// <para>3. Server Process opens a session to a Token</para>
		/// <para>4. Server Process obtains a Random challenge by calling GetAuthChallenge</para>
		/// <para>5. Server Process sends challenge to Remote client</para>
		/// <para>6. Client computes the response value using Gen_Auth_Response and returns it to the Server</para>
		/// <para>7. Server Process supplies response as PIN value to the Login function using a special userType parameter value</para>
		/// <para>Pass Authentication to a New Process:</para>
		/// <para>1. Server Primary Process authenticates using Programmatic Challenge Response Activation</para>
		/// <para>2. Server Primary Process obtains a temporary pin by calling GetTmpPin</para>
		/// <para>3. For each spawned process, the Primary Process passes the temporary PIN to it using an appropriate inter process communication method (or by forking).</para>
		/// <para>4. New Process registers itself to HSMs using Initialize</para>
		/// <para>5. New Process opens a session to the Required Token</para>
		/// <para>6. New Process authenticates to Token with Login function and the temporary pin using a special userType parameter value</para>
		/// </summary>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		void GetTmpPin(array<Byte>^% temp_pin);

		/// <summary>
		/// Creates the response to a challenge.
		/// <para>The library provides a single function used by a remote agent attempting to authenticate to the HSM using the challenge Response system.</para>
		/// <para>Tis function converts the challenge into a Response by using the following algorithm:</para>
		/// <para>Response = SHA-256( challenge | PVC)</para>
		/// <para>Where PVC = LEFT64BIT( SHA1(password | userTypeByte)</para>
		/// <para>Programmatic Challenge Response Activation:</para>
		/// <para>1. Remote client initiates activation by sending a message to the server</para>
		/// <para>2. Server Process registers itself to HSMs using C_Initialise</para>
		/// <para>3. Server Process opens a session to a Token</para>
		/// <para>4. Server Process obtains a Random challenge by calling GetAuthChallenge</para>
		/// <para>5. Server Process sends challenge to Remote client</para>
		/// <para>6. Client computes the response value using Gen_Auth_Response and returns it to the Server</para>
		/// <para>7. Server Process supplies response as PIN value to the Login function using a special userType parameter value</para>
		/// </summary>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/20	Created
		/// </history>
		static void GenAuthResponse(UserType userType, String^ pin, array<Byte>^ challenge, array<Byte>^% response);
#endif
		/// <summary>
		/// Generates random or pseudo-random data.
		/// <para>This function can mix additional seed material into the token's random number generator.</para>
		/// </summary>
		/// <param name="seed">the seed material</param>
		/// <param name="randomLength">the length in bytes of the random or pseudo-random data to be generated</param>
		/// <param name="randomData">the output location that receives the random data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/29	Created
		/// </history>
		void GenerateRandom(array<Byte>^ seed, UInt32 randomLength, array<Byte>^% randomData);

		/// <summary>
		/// Digest data in a single part.
		/// </summary>
		/// <param name="mechanism">mechanism for message digesting</param>
		/// <param name="plainData">the input plain data</param>
		/// <param name="digestData">the output location that receives the random data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/29	Created
		/// </history>
		void Digest(DigestMechanism mechanism, array<Byte>^ plainData, array<Byte>^% digestData);

		/// <summary>
		/// This function is a SafeNet extension to PKCS#11, it allows the Administrator to initialize a new Token.
		/// <para>When this flag is enabled the normal InitToken function will fail with the error result ACCESS_DENIED. In order to initialize tokens it is necessary to use the SafeNet extension function InitToken.</para>
		/// <para>The SafeNet tools ctconf and gctadmin are aware of this restriction and will automatically use the appropriate function.</para>
		/// <para>It initializes the token indicated by slotId with the SO pin and Label.</para>
		/// <para>The session, must be a session to the Admin Token of the adapter and be in RW User Mode for this function to succeed otherwise SESSION_HANDLE_INVALID is returned.</para>
		/// <para>The slotId value must refer to a valid slot where the token in the slot must be in an un-initialized state, otherwise SLOT_ID_INVALID is returned.</para>
		/// <para>If the slotID is valid but the token is not present then TOKEN_NOT_PRESENT is returned.</para>
		/// <para>When ProtectToolkit is configured to operate in WLD mode, this function is not supported and will return the error FUNCTION_NOT_SUPPORTED.</para>
		/// </summary>
		/// <param name="slotID">slot id which contains the new token</param>
		/// <param name="SOPin">the new Token SO pin</param>
		/// <param name="tokenLabel">the new Token label</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/21	Created
		/// </history>
		void InitToken(UInt32 slotID, String^ SOPin, String^ tokenLabel);

		/// <summary>
		/// This function is a SafeNet extension to PKCS#11, it will erase (reset) the token which the session is connected to.
		/// <para>The session must be in RW SO Mode for this function to succeed otherwise USER_NOT_LOGGED_IN is returned.</para>
		/// <para>This function allows Token Security Officers to reset a Token. The module will detect if other sessions are active on the token and, if so, return SESSION_EXISTS.</para>
		/// <para>This function will erase all objects it can from the token (depending on the token type some objects will no be erased). The token is left in an initialized state where the SO pin and label are set as specified by the SOPin and tokenLabel parameters.</para>
		/// <para>NOTE: SOPin becomes the new SO pin and need not match the old SO pin value.</para>
		/// <para>The session is automatically terminated by this call.</para>
		/// <para>When ProtectToolkit is configured to operate in WLD mode, this function is not supported and returns the error FUNCTION_NOT_SUPPORTED.</para>
		/// </summary>
		/// <param name="newSOPin">the Token new SO pin</param>
		/// <param name="tokenLabel">the Token new label</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/21	Created
		/// </history>
		void ResetToken(String^ newSOPin, String^ tokenLabel);
	};
}
