#pragma once

using namespace System;

namespace LL_SecureModule
{
	/// <summary>
	/// Security flags control particular security settings. One or more of these flags can be set to create custom security policies or to implement the typical security policies.
	/// </summary>
	public enum class SecurityFlag
	{
		/// <summary>
		/// By default (after initial HSM installation or following a tamper event) the ProtectToolkit C security policy applying is SafeNet Default Mode.
		/// <para>This mode offers a greater level of security than is afforded when operating in PKCS #11 Compatibility Mode while at the same time affording a greater level of compliance with the PKCS #11 standard over other possible security policy implementations.</para>
		/// </summary>
		DEFAULT_MODE = 0x00000000,

		/// <summary>
		/// The Entrust Ready (Entrust Compliant) flag, when set, indicates that:
		/// <para>- When a mechanism is queried that does not exist an empty mechanism structure is returned.</para>
		/// <para>- When a token is initialized with the C_InitToken command the SO PIN is not required.</para>
		/// <para>- A user that is already logged in is permitted to log in again.</para>
		/// <para>- When using the C_SignFinal command the size of the message authentication code (MAC) returned can be controlled, even if the mechanism is not one of the general length MAC mechanisms specified in the PKCS #11 standard.</para>
		/// <para>- When using the C_WrapKey function, if the extractable attribute is not specified then it defaults to 'True' so wrapping is allowed.</para>
		/// </summary>
		ENTRUST_READY = CKF_ENTRUST_READY,

		/// <summary>
		/// The No Clear PINs (No Clear PINs Allowed) flag, when set, indicates that:
		/// <para>- User PINs or other sensitive information cannot be passed across the host interface in an unencrypted form.</para>
		/// <para>- Secure messaging encryption is enabled for requests to the HSM that are critical or for those requests that might otherwise contain sensitive information.</para>
		/// <para>- Certain functions that would otherwise result in the clear transmission of sensitive data are disabled.</para>
		/// <para>- The creation of any keys with the SENSITIVE attribute set to 'False', is not permitted.</para>
		/// </summary>
		NO_CLEAR_PINS = CKF_NO_CLEAR_PINS,

		/// <summary>
		/// The Auth Protection (Authentication/SMSession Protection) flag, when set, indicates that secure messaging authentication between applications and the HSM is being enforced for certain messages sent from applications to the HSM.
		/// <para>Effected messages are those that are critical or messages that might otherwise contain sensitive information. These messages must be digitally signed so that they can be verified by the HSM.</para>
		/// <para>By enabling this setting applications will operate in a more secure manner, however this will also have the effect of decreasing HSM performance. This is due to the increased operations required to sign and verify each request message.</para>
		/// </summary>
		AUTH_PROTECTION = CKF_AUTH_PROTECTION,

		/// <summary>
		/// The No Public Crypto flag, when set, indicates that no user can perform a cryptographic operation without having first authenticated themselves.
		/// <para>When this flag is set, each token in the system will have the PKCS #11 CKF_LOGIN_REQUIRED flag set to indicate that applications must authenticate before operations are allowed. Note that this security flag does not affect the Admin token which always requires authentication for access.</para>
		/// </summary>
		NO_PUBLIC_CRYPTO = CKF_NO_PUBLIC_CRYPTO,

		/// <summary>
		/// The Tamper Before Upgrade flag, when set, indicates that a soft tamper (erasure of all HSM internal secure memory) will occur when any of the following operations are undertaken.
		/// <para>- Firmware upgrade.</para>
		/// <para>- FM download.</para>
		/// <para>- FM disable operation.</para>
		/// </summary>
		TAMPER_BEFORE_UPGRADE = CKF_TAMPER_BEFORE_UPGRADE,

		/// <summary>
		/// The Increased Security Level flag, when set, indicates that:
		/// <para>- The mechanism CKM_EXTRACT_KEY_FROM_KEY is disabled.</para>
		/// <para>- Changing the MODIFIABLE attribute from False to True while using the C_CopyObject command is not permitted.</para>
		/// </summary>
		INCREASED_SECURITY = CKF_INCREASED_SECURITY,

		/// <summary>
		/// The FIPS Mode (FIPS 140-1 Mode or FIPS 140-2 Mode) flag, when set, indicates that the following composite flags are set.
		/// <para>- FIPS Algorithms Only.</para>
		/// <para>- No Public Crypto.</para>
		/// <para>- Mode Locked.</para>
		/// <para>- No Clear PINs.</para>
		/// <para>- Tamper Before Upgrade.</para>
		/// <para>- Auth Protection.</para>
		/// <para>Instead of specifying each of these flags individually when using the ctconf utility to put a HSM into FIPS Mode, the FIPS Mode flag can be specified as a shortcut.</para>
		/// </summary>
		FIPS_ALGORITHMS = CKF_FIPS_ALGORITHMS,

		/// <summary>
		/// The Full Secure Messaging Encryption flag, when set, indicates that:
		/// <para>- User PINs or other sensitive information cannot be passed across the host interface in an unencrypted form.</para>
		/// <para>- Secure messaging encryption is enabled so that every message is encrypted in both directions between the application and the HSM.</para>
		/// <para>- Certain functions that would otherwise result in the clear transmission of sensitive data are disabled.</para>
		/// <para>- The creation of any keys with the SENSITIVE attribute set to 'False' is not permitted.</para>
		/// <para>Note that the Full Secure Messaging Encryption flag is similar to the No Clear PINs Allowed flag except that every message is encrypted in both directions between the application and the HSM.</para>
		/// <para>The key used for the message encryption is generated using the PKCS #3 Diffie-Hellman Key Agreement Standard.</para>
		/// <para>This flag is not applicable if the SMS mode is set to HIMK for further information.</para>
		/// <para>By enabling this setting the applications will operate in a more secure manner, however this will also have the effect of decreasing HSM performance. This is due to the increased operations required to encrypt and decrypt each request and response message.</para>
		/// </summary>
		FULL_SMS_ENC = CKF_FULL_SMS_ENC,

		/// <summary>
		/// <para>The Full Secure Messaging Signing flag, when set, indicates that secure messaging authentication between applications and the HSM is being enforced for every message, in both directions, between the application and the HSM.</para>
		/// <para>All messages must be digitally signed so that they can be verified by the HSM.</para>
		/// <para>Note that the Full Secure Messaging Signing flag is similar to the Auth Protection flag except that every message, in both directions, between the application and the HSM is digitally signed and verified.</para>
		/// <para>The key used for the message signing is generated using the PKCS #3 Diffie-Hellman Key Agreement Standard.</para>
		/// <para>This setting is not applicable if the SMS mode is set to HIMK.</para>
		/// <para>By enabling this setting applications will operate in a more secure manner, however this will also have the effect of decreasing HSM performance. This is due to the increased operations required to sign and verify each request and response message.</para>
		/// </summary>
		FULL_SMS_SIGN = CKF_FULL_SMS_SIGN,

		/// <summary>
		/// The Pure PKCS11 flag, when set, indicates that the following mechanisms will behave as the PKCS #11 v2.20 standard requires.
		/// <para>- CKM_CONCATENATE_BASE_AND_KEY.</para>
		/// <para>- CKM_CONCATENATE_BASE_AND_DATA.</para>
		/// <para>- CKM_CONCATENATE_DATA_AND_BASE.</para>
		/// <para>- CKM_EXTRACT_KEY_FROM_KEY.</para>
		/// </summary>
		PURE_P11 = CKF_PURE_P11,

		/// <summary>
		/// The Des Keys Even Parity Allowed permits creation of DES, DES2 and DES3 keys that have even parity. Creation of a DES key and DES key components with even parity is permitted if this flag is set.
		/// </summary>
		DES_EVEN_PARITY_ALLOWED = CKF_DES_EVEN_PARITY_ALLOWED,

		/// <summary>
		/// The User Specified ECC DomainParameters Allowed, when set, indicates that ECC Public and Private keys may be generated and stored within the HSM which have Domain Parameters other then the set of named curves built into the HSM.
		/// </summary>
		USER_ECC_DP_ALLOWED = CKF_USER_ECC_DP_ALLOWED,

		/// <summary>
		/// The Mode Locked (Lock Security Mode) flag, when set, indicates that this flag (or any other security flag) cannot be modified. A new security policy can only be implemented after a tamper operation has been performed.
		/// </summary>
		MODE_LOCKED = CKF_MODE_LOCKED,
	};
}
