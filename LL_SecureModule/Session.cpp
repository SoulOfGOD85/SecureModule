#include "stdafx.h"

#include "Session.h"
#include "Utils.h"

#include <ctfext.h>
#include <ctutil.h>
#ifndef _PTKC_V400_
#include <ctauth.h>
#endif

namespace LL_SecureModule
{
	/// <summary>
	/// Copy constructor.
	/// </summary>
	SMSession::SMSession(SMSession^ session)
	{
		this->hSession = session->hSession;
		this->slotID = session->slotID;
		this->isLoggedIn = session->isLoggedIn;
		this->currentUser = session->currentUser;
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="SMSession"/> class and open a new session on the HSM.
	/// </summary>
	SMSession::SMSession(UInt32 slotID, SessionType sessionType)
	{
		this->hSession = CK_INVALID_HANDLE;
		this->slotID = slotID;
		this->isLoggedIn = false;
		this->currentUser = UserType::UNKNOWN;

		try
		{
			this->OpenSession(sessionType);
		}
		catch (...)
		{
			throw;
		}
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="SMSession" /> class and then open a new session on the HSM and try to logs user into the new session.
	/// <para>If the specific user already logged into the session, this function can ignore it without throwing an Exception error.</para>
	/// </summary>
	SMSession::SMSession(UInt32 slotID, SessionType sessionType, UserType userType, String^ pin, bool ignoreIfAlreadyLoggedIn)
	{
		this->hSession = CK_INVALID_HANDLE;
		this->slotID = slotID;
		this->isLoggedIn = false;
		this->currentUser = UserType::UNKNOWN;

		try
		{
			this->OpenSession(sessionType);
			this->Login(userType, pin, ignoreIfAlreadyLoggedIn);
		}
		catch (...)
		{
			throw;
		}
	}

	/// <summary>
	/// Initializes the normal user's PIN.
	/// <para>This function can only be called in the "R/W SO Functions" state. An attempt to call it from a session in any other state fails with error.</para>
	/// </summary>
	void SMSession::InitPIN(String^ userPin)
	{
		CK_RV rv = CKR_OK;

		CK_CHAR_PTR user_pin = NULL;
		CK_ULONG user_pin_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(userPin)) throw gcnew SecureModuleException("User PIN is nullptr or an Empty string.");
		if (userPin->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of User PIN is more than maximum pin length.");

		try
		{
			// Convert User PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(userPin, &user_pin, &user_pin_len);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'user_pin'.
			if (user_pin != NULL)
			{
				delete[] user_pin;
				user_pin = NULL;
			}

			throw;
		}

		// Initializes the normal user's PIN.
		rv = C_InitPIN(this->hSession, user_pin, user_pin_len);

		// Deallocate memory for 'user_pin'.
		delete[] user_pin;
		user_pin = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Modifies the PIN of the user that is currently logged in.
	/// </summary>
	void SMSession::SetPIN(String^ oldPin, String^ newPin)
	{
		CK_RV rv = CKR_OK;

		CK_CHAR_PTR old_pin = NULL;
		CK_CHAR_PTR new_pin = NULL;
		CK_ULONG old_pin_len = 0;
		CK_ULONG new_pin_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(oldPin)) throw gcnew SecureModuleException("Old PIN is nullptr or an Empty string.");
		if (String::IsNullOrEmpty(newPin)) throw gcnew SecureModuleException("New PIN is nullptr or an Empty string.");
		if (oldPin->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of Old PIN is more than maximum pin length.");
		if (newPin->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of New PIN is more than maximum pin length.");

		try
		{
			// Convert old PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(oldPin, &old_pin, &old_pin_len);

			// Convert new PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(newPin, &new_pin, &new_pin_len);
		}
		catch (Exception^)
		{
			// Deallocate memory for 'old_pin' and 'new_pin'.
			if (old_pin != NULL)
			{
				delete[] old_pin;
				old_pin = NULL;
			}

			if (new_pin != NULL)
			{
				delete[] new_pin;
				new_pin = NULL;
			}

			throw;
		}

		// Set the new PIN
		rv = C_SetPIN(this->hSession, old_pin, old_pin_len, new_pin, new_pin_len);

		// Deallocate memory for 'old_pin' and 'new_pin'.
		delete[] old_pin;
		old_pin = NULL;
		delete[] new_pin;
		new_pin = NULL;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Modifies the PIN of the user that is currently logged in.
	/// <para>This function is not supported in the current version of 'LL_SecureModule'.</para>
	/// </summary>
	void SMSession::GetSessionInfo(SessionInfo^% sessionInfo)
	{
		CK_RV rv = CKR_OK;

		rv = CKR_FUNCTION_NOT_SUPPORTED;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Opens a session between an application and a token in a particular slot.
	/// <para>When opening a session with C_OpenSession, the flags parameter consists of the logical OR of zero or more bit flags defined in the CK_SESSION_INFO data type.</para>
	/// <para>For legacy reasons, the CKF_SERIAL_SESSION bit must always be set; if a call to C_OpenSession does not have this bit set, the call should return unsuccessfully with the error code CKR_PARALLEL_NOT_SUPPORTED.</para>
	/// </summary>
	void SMSession::OpenSession(UInt32 slotID, SessionType sessionType)
	{
		CK_RV rv = CKR_OK;
		CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

		// Check current status of this SMSession. this->hSession must be CK_INVALID_HANDLE.
		if (this->hSession != CK_INVALID_HANDLE) throw gcnew SecureModuleException("SMSession must be uninitialized or closed.");;

		// Opens a session
		rv = C_OpenSession((CK_SLOT_ID)slotID, (CK_ULONG)sessionType, NULL, NULL, &hSession);

		// Sets hSession & slotID
		if (rv == CKR_OK)
		{
			this->slotID = slotID;
			this->hSession = hSession;
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Opens a session between an application and a token in a particular slot.
	/// <para>When opening a session with C_OpenSession, the flags parameter consists of the logical OR of zero or more bit flags defined in the CK_SESSION_INFO data type.</para>
	/// <para>For legacy reasons, the CKF_SERIAL_SESSION bit must always be set; if a call to C_OpenSession does not have this bit set, the call should return unsuccessfully with the error code CKR_PARALLEL_NOT_SUPPORTED.</para>
	/// </summary>
	void SMSession::OpenSession(SessionType sessionType)
	{
		CK_RV rv = CKR_OK;
		CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

		// Check current status of this SMSession. this->hSession must be CK_INVALID_HANDLE.
		if (this->hSession != CK_INVALID_HANDLE) throw gcnew SecureModuleException("It seems that this SMSession has a session's handle. Close it and then try again.");;

		// Open a session
		rv = C_OpenSession(this->slotID, (CK_ULONG)sessionType, NULL, NULL, &hSession);

		// Set this.hSession to the opened session's handle.
		if (rv == CKR_OK)
		{
			this->hSession = hSession;
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Closes a session between an application and a token.
	/// <para>When a session is closed, all session objects created by the session are destroyed automatically, even if the application has other sessions using the objects.</para>
	/// <para>If this function is successful and it closes the last session between the application and the token, the login state of the token for the application returns to public sessions.</para>
	/// </summary>
	void SMSession::CloseSession()
	{
		CK_RV rv = CKR_OK;

		// Close this SMSession
		C_CloseSession(this->hSession);

		// Set 'hSession' to default value.
		if (rv == CKR_OK) this->hSession = CK_INVALID_HANDLE;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

#ifndef _PTKC_V400_
	/// <summary>
	/// This function can be used to identify the HSM that a particular WLD or HA session has been assigned to.
	/// </summary>
	void SMSession::GetDeviceID(UInt32% deviceID)
	{
		CK_RV rv = CKR_OK;
		CK_ULONG hsm_id = 0;

		rv = CT_GetHSMId(this->hSession, &hsm_id);
		if (rv != CKR_OK)
			deviceID = (UInt32)hsm_id;

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}
#endif

	/// <summary>
	/// This function returns the HSM session handle for the specified user Session Handle.
	/// </summary>
	void SMSession::ToHSMSession(SMSession^% HSMSession)
	{
		CK_RV rv = CKR_OK;
		CK_SESSION_HANDLE hHsmSession = CK_INVALID_HANDLE;

		rv = CT_ToHsmSession(this->hSession, &hHsmSession);
		if (rv != CKR_OK)
		{
			HSMSession = gcnew SMSession();
			HSMSession->hSession = hHsmSession;
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Logs a user into a token.
	/// <para>If the application calling 'Login' has a R/O session open with the token, then it will be unable to log the SO into a session.</para>
	/// </summary>
	void SMSession::Login(UserType userType, String^ pin)
	{
		CK_RV rv = CKR_OK;

		CK_CHAR_PTR user_pin = NULL;
		CK_ULONG user_pin_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(pin)) throw gcnew SecureModuleException("PIN is nullptr or an Empty string.");
		if (pin->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of PIN is more than maximum pin length.");
		if (userType == UserType::UNKNOWN) throw gcnew SecureModuleException("Unknown user type.");

		try
		{
			// Convert PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(pin, &user_pin, &user_pin_len);
		}
		catch (Exception^)
		{
			throw;
		}

		// Login to session
		rv = C_Login(this->hSession, (CK_ULONG)userType, user_pin, user_pin_len);

		// Set 'isLoggedIn' and 'currentUser'.
		if (rv == CKR_OK)
		{
			this->isLoggedIn = true;
			this->currentUser = userType;
		}

		// Deallocate memory for 'old_pin' and 'new_pin'.
		if (user_pin != NULL)
		{
			delete[] user_pin;
			user_pin = NULL;
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

	/// <summary>
	/// Logs a user into a token.
	/// <para>If the specific user already logged into the session, this function can ignore it and doesn't throw an Exception error.</para>
	/// <para>If the application calling 'Login' has a R/O session open with the token, then it will be unable to log the SO into a session.</para>
	/// </summary>
	void SMSession::Login(UserType userType, String^ pin, bool ignoreIfAlreadyLoggedIn)
	{
		CK_RV rv = CKR_OK;

		CK_CHAR_PTR user_pin = NULL;
		CK_ULONG user_pin_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(pin)) throw gcnew SecureModuleException("PIN is nullptr or an Empty string.");
		if (pin->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of PIN is more than maximum pin length.");
		if (userType == UserType::UNKNOWN) throw gcnew SecureModuleException("Unknown user type.");

		try
		{
			// Convert PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(pin, &user_pin, &user_pin_len);
		}
		catch (Exception^)
		{
			throw;
		}

		// Login to session
		rv = C_Login(this->hSession, (CK_ULONG)userType, user_pin, user_pin_len);

		// Set 'isLoggedIn' and 'currentUser'.
		if (rv == CKR_OK)
		{
			this->isLoggedIn = true;
			this->currentUser = userType;
		}

		// Deallocate memory for 'old_pin' and 'new_pin'.
		if (user_pin != NULL)
		{
			delete[] user_pin;
			user_pin = NULL;
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
		{
			if (rv == CKR_USER_ALREADY_LOGGED_IN && ignoreIfAlreadyLoggedIn)
			{
				this->isLoggedIn = true;
				this->currentUser = userType;
				return;
			}
			else
				throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
		}
	}

#ifndef _PTKC_V400_
	/// <summary>
	/// Challenge/Response operation login.
	/// <para>If the application calling 'Login' has a R/O session open with the token, then it will be unable to log the SO into a session.</para>
	/// </summary>
	void SMSession::Login(UserType userType, AuthenticationFlag authFlag, array<Byte>^ response)
	{
		CK_RV rv = CKR_OK;

		CK_BYTE_PTR response_pin = NULL;
		CK_ULONG response_pin_len = 0;

		// Input data validation check.
		if (response->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of PIN is more than maximum pin length.");
		if (userType == UserType::UNKNOWN) throw gcnew SecureModuleException("Unknown user type.");

		try
		{
			// Convert PIN from System::Byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(response, &response_pin, &response_pin_len);
		}
		catch (Exception^)
		{
			throw;
		}

		// Login to session
		rv = C_Login(this->hSession, (CK_ULONG)(userType) | (CK_ULONG)(authFlag), response_pin, response_pin_len);

		// Set 'isLoggedIn' and 'currentUser'.
		if (rv == CKR_OK)
		{
			isLoggedIn = true;
			currentUser = userType;
		}

		// Deallocate memory for 'old_pin' and 'new_pin'.
		if (response_pin != NULL)
		{
			delete[] response_pin;
			response_pin = NULL;
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}
#endif

	/// <summary>
	/// Logs a user out from a token.
	/// <para>Depending on the current user type, if the call succeeds, each of the application's sessions will enter either the "R/W Public SMSession" state or the "R/O Public SMSession" state.</para>
	/// <para>When 'Logout' successfully executes, any of the application's handles to private objects become invalid (even if a user is later logged back into the token, those handles remain invalid).</para>
	/// <para>In addition, all private session objects from sessions belonging to the application are destroyed.</para>
	/// </summary>
	void SMSession::Logout()
	{
		CK_RV rv = CKR_OK;

		// Logout from session
		rv = C_Logout(this->hSession);

		// Set 'isLoggedIn' and 'currentUser' to default value.
		if (rv == CKR_OK)
		{
			isLoggedIn = false;
			currentUser = UserType::UNKNOWN;
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

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
	void SMSession::GetAuthChallenge(array<Byte>^% challenge)
	{
		CK_RV rv = CKR_OK;

		const int ChallengeLength = 16;

		CK_BYTE challenge_data[ChallengeLength] = { 0 };
		CK_ULONG challenge_data_len = ChallengeLength;

		// Get Authentication Challenge
		rv = CT_GetAuthChallenge(this->hSession, challenge_data, &challenge_data_len);

		if (rv == CKR_OK)
		{
			// Convert challenge_data from CK_BYTE_PTR to array of byte.
			Utils::ConvertCKBytePtrToByteArray(challenge_data, challenge_data_len, challenge);
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

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
	void SMSession::GenAuthResponse(UserType userType, String^ pin, array<Byte>^ challenge, array<Byte>^% response)
	{
		CK_RV rv = CKR_OK;

		const int ResponseLength = 32;

		CK_BYTE response_data[ResponseLength] = { 0 };
		CK_ULONG response_data_len = ResponseLength;

		CK_BYTE_PTR challenge_data = NULL;
		CK_ULONG challenge_data_len = 0;

		CK_CHAR_PTR user_pin = NULL;
		CK_ULONG user_pin_len = 0;

		// Input data validation check.
		if (String::IsNullOrEmpty(pin)) throw gcnew SecureModuleException("PIN is nullptr or an Empty string.");
		if (pin->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of PIN is more than maximum pin length.");
		if (userType == UserType::UNKNOWN) throw gcnew SecureModuleException("Unknown user type.");

		try
		{
			// Convert PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(pin, &user_pin, &user_pin_len);

			// Convert PIN from System::Byte to CK_BYTE_PTR.
			Utils::ConvertByteArrayToCKBytePtr(challenge, &challenge_data, &challenge_data_len);
		}
		catch (Exception^)
		{
			throw;
		}

		// Get Response
		rv = CT_Gen_AUTH_Response(user_pin, user_pin_len, challenge_data, challenge_data_len, (CK_ULONG)userType, response_data, &response_data_len);

		// Deallocate memory for 'user_pin'
		if (user_pin != NULL)
		{
			delete[] user_pin;
			user_pin = NULL;
		}

		// Deallocate memory for 'challenge_data'
		if (challenge_data != NULL)
		{
			delete[] challenge_data;
			challenge_data = NULL;
		}

		if (rv == CKR_OK)
		{
			// Convert response_data from CK_BYTE_PTR to array of byte.
			Utils::ConvertCKBytePtrToByteArray(response_data, response_data_len, response);
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}

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
	void SMSession::GetTmpPin(array<Byte>^% temp_pin)
	{
		CK_RV rv = CKR_OK;

		const int TempPINLength = 32;

		CK_BYTE temp_pin_data[TempPINLength] = { 0 };
		CK_ULONG temp_pin_data_len = TempPINLength;

		// Get Temporary PIN
		rv = CT_GetTmpPin(this->hSession, temp_pin_data, &temp_pin_data_len);

		if (rv == CKR_OK)
		{
			// Convert temp_pin_data from CK_BYTE_PTR to array of byte.
			Utils::ConvertCKBytePtrToByteArray(temp_pin_data, temp_pin_data_len, temp_pin);
		}

		// Check if resulting an exception.
		if (rv != CKR_OK)
			throw gcnew SecureModuleException(rv, "Error: " + Utils::GetCKRString(rv) + "\tDescription message: " + Utils::GetErrorDescription(rv));
	}
#endif

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
	void SMSession::InitToken(UInt32 slotID, String^ SOPin, String^ tokenLabel)
	{
		CK_RV rv = CKR_OK;

		CK_CHAR_PTR so_pin = NULL;
		CK_ULONG so_pin_len = 0;

		CK_CHAR_PTR label = NULL;
		CK_ULONG label_len = 0;

		try
		{
			// Input data validation check.
			if (String::IsNullOrEmpty(SOPin)) throw gcnew SecureModuleException("SO PIN is nullptr or an Empty string.");
			if (SOPin->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of User PIN is more than maximum pin length.");

			if (String::IsNullOrEmpty(tokenLabel)) throw gcnew SecureModuleException("Token label is nullptr or an Empty string.");

			// Convert SO PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(SOPin, &so_pin, &so_pin_len);

			// Convert tokenLabel from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(tokenLabel, &label, &label_len);

			// Initializes the token.
			rv = CT_InitToken(this->hSession, (CK_SLOT_ID)slotID, so_pin, so_pin_len, label);

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
			// Deallocate memory of 'so_pin' and 'label'.
			if (so_pin != NULL) delete[] so_pin;
			so_pin = NULL;
			so_pin_len = 0;

			if (label != NULL) delete[] label;
			label = NULL;
			label_len = 0;
		}
	}

	/// <summary>
	/// This function is a SafeNet extension to PKCS#11, it will erase (reset) the token which the session is connected to.
	/// <para>The session must be in RW SO Mode for this function to succeed otherwise USER_NOT_LOGGED_IN is returned.</para>
	/// <para>This function allows Token Security Officers to reset a Token. The module will detect if other sessions are active on the token and, if so, return SESSION_EXISTS.</para>
	/// <para>This function will erase all objects it can from the token (depending on the token type some objects will no be erased). The token is left in an initialized state where the SO pin and label are set as specified by the SOPin and tokenLabel parameters.</para>
	/// <para>NOTE: SOPin becomes the new SO pin and need not match the old SO pin value.</para>
	/// <para>The session is automatically terminated by this call.</para>
	/// <para>When ProtectToolkit is configured to operate in WLD mode, this function is not supported and returns the error FUNCTION_NOT_SUPPORTED.</para>
	/// </summary>
	void SMSession::ResetToken(String^ newSOPin, String^ tokenLabel)
	{
		CK_RV rv = CKR_OK;

		CK_CHAR_PTR new_so_pin = NULL;
		CK_ULONG new_so_pin_len = 0;

		CK_CHAR_PTR label = NULL;
		CK_ULONG label_len = 0;

		try
		{
			// Input data validation check.
			if (String::IsNullOrEmpty(newSOPin)) throw gcnew SecureModuleException("SO PIN is nullptr or an Empty string.");
			if (newSOPin->Length > CK_MAX_PIN_LEN) throw gcnew SecureModuleException("Length of User PIN is more than maximum pin length.");

			if (String::IsNullOrEmpty(tokenLabel)) throw gcnew SecureModuleException("Token label is nullptr or an Empty string.");

			// Convert SO PIN from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(newSOPin, &new_so_pin, &new_so_pin_len);

			// Convert tokenLabel from System::String to CK_CHAR_PTR.
			Utils::ConvertStringToCKCharPtr(tokenLabel, &label, &label_len);

			// Reset the token.
			rv = CT_ResetToken(this->hSession, new_so_pin, new_so_pin_len, label);

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
			// Deallocate memory of 'so_pin' and 'label'.
			if (new_so_pin != NULL) delete[] new_so_pin;
			new_so_pin = NULL;
			new_so_pin_len = 0;

			if (label != NULL) delete[] label;
			label = NULL;
			label_len = 0;
		}
	}
}