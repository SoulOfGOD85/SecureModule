#pragma once

using namespace System;

namespace LL_SecureModule
{
	/// <summary>
	/// This enumeration identifies an attribute type
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public enum class AttributeType
	{
		///
		/// BOOLEAN ATTRIBUTES
		///

		/// <summary>
		/// 'True' if object is a token object; 'False' if object is a session object.
		/// <para>Default is 'False'.</para>
		/// </summary>
		TOKEN = CKA_TOKEN,

		/// <summary>
		/// 'True' if object is a private object; 'False' if object is a public object.
		/// <para>Default value is token-specific, and may depend on the values of other attributes of the object.</para>
		/// </summary>
		PRIVATE = CKA_PRIVATE,

		/// <summary>
		/// This attribute may be included in a template for the creation of a Certificate object. It is used to indicate whether or not the certificate is trusted by the application. Once set the value of this attribute may not be modified.
		/// <para>'True' if the certificate is trusted; 'False' if the certificate is not trusted and must be verified.</para>
		/// </summary>
		TRUSTED = CKA_TRUSTED,

		/// <summary>
		/// 'True' if key is sensitive.
		/// </summary>
		SENSITIVE = CKA_SENSITIVE,

		/// <summary>
		/// 'True' if key supports encryption.
		/// </summary>
		ENCRYPT = CKA_ENCRYPT,

		/// <summary>
		/// 'True' if key supports decryption.
		/// </summary>
		DECRYPT = CKA_DECRYPT,

		/// <summary>
		/// 'True' if key supports wrapping (i.e., can be used to wrap other keys).
		/// </summary>
		WRAP = CKA_WRAP,

		/// <summary>
		/// 'True' if key supports unwrapping (i.e., can be used to unwrap other keys).
		/// </summary>
		UNWRAP = CKA_UNWRAP,

		/// <summary>
		/// 'True' if key supports signatures (i.e., authentication codes) where the signature is an appendix to the data.
		/// </summary>
		SIGN = CKA_SIGN,

		/// <summary>
		/// 'True' if key supports signatures where the data can be recovered from the signature.
		/// </summary>
		SIGN_RECOVER = CKA_SIGN_RECOVER,

		/// <summary>
		/// 'True' if key supports verification (i.e., of authentication codes) where the signature is an appendix to the data.
		/// </summary>
		VERIFY = CKA_VERIFY,

		/// <summary>
		/// 'True' if key supports verification where the data is recovered from the signature.
		/// </summary>
		VERIFY_RECOVER = CKA_VERIFY_RECOVER,

		/// <summary>
		/// 'True' if key supports key derivation (i.e., if other keys can be derived from this one).
		/// <para>Default is 'False'.</para>
		/// </summary>
		DERIVE = CKA_DERIVE,

		/// <summary>
		/// 'True' if key is extractable and can be wrapped.
		/// </summary>
		EXTRACTABLE = CKA_EXTRACTABLE,

		/// <summary>
		/// 'True' only if key was either generated locally (i.e., on the token) or created as a copy of a key which had its LOCAL attribute set to 'True'.
		/// </summary>
		LOCAL = CKA_LOCAL,

		/// <summary>
		/// 'True' if key has never had the EXTRACTABLE attribute set to 'True'.
		/// </summary>
		NEVER_EXTRACTABLE = CKA_NEVER_EXTRACTABLE,

		/// <summary>
		/// 'True' if key has always had the SENSITIVE attribute set to 'True'.
		/// </summary>
		ALWAYS_SENSITIVE = CKA_ALWAYS_SENSITIVE,

		/// <summary>
		/// 'True' if object can be modified.
		/// <para>Default is 'True'.</para>
		/// </summary>
		MODIFIABLE = CKA_MODIFIABLE,

		/// <summary>
		/// 'True' if the key requires a secondary authentication to take place before its use it allowed.
		/// </summary>
		SECONDARY_AUTH = CKA_SECONDARY_AUTH,

		/// <summary>
		/// The value of the counter will reset to a previously returned value if the token is initialized.
		/// </summary>
		RESET_ON_INIT = CKA_RESET_ON_INIT,

		/// <summary>
		/// The value of the counter has been reset at least once at some point in time.
		/// </summary>
		HAS_RESET = CKA_HAS_RESET,

		///
		/// There are a number of additional SafeNet PSE vendor defined attribute types.
		///

		/// <summary>
		/// This attribute is similar to the standard WRAP attribute as it determines if a given key can wrap others keys from the token in an encrypted form.
		/// <para>The important difference between this attribute and it's standard counterpart is that there are special controls on who can set the EXPORT flag.</para>
		/// <para>This flag may be set to 'True' by the token's Security Officer or by the User if certain conditions are met. Thus the normal user can specify that a key may be exported in an encrypted form (by specifying that the EXPORTABLE attribute is 'True') but only by keys as determined by the SO (for example, a key that has the EXPORT attribute set to 'True').</para>
		/// <para>All other key usage attributes that might allow such a key, or any key exported by it, to be known outside the adapter must be set to FALSE. Specifically the template must specify FALSE for EXTRACTABLE, DECRYPT, SIGN and MODIFIABLE as well as TRUE for SENSITIVE, the template may also not specify TRUE for the DERIVE attribute.</para>
		/// </summary>
		EXPORT = (int)CKA_EXPORT,

		/// <summary>
		/// This attribute is similar to the standard EXTRACTABLE attribute as it determines if a given key can be extracted from the token in an encrypted form.
		/// <para>The normal user can specify that a key may be exported in an encrypted form by specifying that the EXPORTABLE attribute is 'True'; but only by keys as determined by the SO (for example, a key that has the EXPORT attribute set to 'True').</para>
		/// </summary>
		EXPORTABLE = (int)CKA_EXPORTABLE,

		/// <summary>
		/// This attribute may be set on any token object (that is, where the TOKEN attribute is 'True') to specify that the object is permanent and may not be deleted.
		/// <para>Once created, an object with the DELETABLE attribute set to 'False' may be deleting only by re-initialization of the token (or during a hardware tamper process).</para>
		/// </summary>
		DELETABLE = (int)CKA_DELETABLE,

		/// <summary>
		/// This attribute must be set to 'True' on any private key that is used with the Proof of origin mechanism (CKM_ENOCDE_X_509_LOCAL_CERT). Signing keys that do not have this attribute may not be used with this mechanism.
		/// <para>Keys with this attribute should have the SIGN and ENCRYPT attributes set to 'False' to ensure that the key cannot be used to sign arbitrary data.</para>
		/// <para>Further special precautions should be taken to ensure that the key cannot leave the adapter – generally EXTRACTABLE and EXPORTABLE should be 'False' and SENSITIVE should be 'True'.</para>
		/// </summary>
		SIGN_LOCAL_CERT = (int)CKA_SIGN_LOCAL_CERT,

		/// <summary>
		/// This attribute is similar to the standard UNWRAP attribute to determine if a given key can be used to unwrap encrypted key material.
		/// <para>The important difference between these attributes and their standard counterparts is that if this attribute is set to True and UNWRAP attribute is set to False, then the only unwrap mechanism that can be used is WRAPKEY_DES3_CBC. With this combination, the error code CKR_MECHANISM_INVALID is returned for all other mechanisms.</para>
		/// <para>The default of IMPORT is set to 'False'.</para>
		/// </summary>
		IMPORT = (int)CKA_IMPORT,

		///
		/// UINT ATTRIBUTES
		///

		/// <summary>
		/// Object class (type) [CKO].
		/// </summary>
		CLASS = CKA_CLASS,

		/// <summary>
		/// Type of certificate [CKC].
		/// </summary>
		CERTIFICATE_TYPE = CKA_CERTIFICATE_TYPE,

		/// <summary>
		/// Type of key [CKK].
		/// </summary>
		KEY_TYPE = CKA_KEY_TYPE,

		/// <summary>
		/// Length in bits of modulus n.
		/// </summary>
		MODULUS_BITS = CKA_MODULUS_BITS,

		/// <summary>
		/// Length of the prime value.
		/// </summary>
		PRIME_BITS = CKA_PRIME_BITS,

		/// <summary>
		/// Length in bits of private value x.
		/// </summary>
		VALUE_BITS = CKA_VALUE_BITS,

		/// <summary>
		/// Length in bytes of key value.
		/// </summary>
		VALUE_LEN = CKA_VALUE_LEN,

		/// <summary>
		/// Identifier of the mechanism used to generate the key material [CKM].
		/// </summary>
		KEY_GEN_MECHANISM = CKA_KEY_GEN_MECHANISM,

		/// <summary>
		/// Mask indicating the current state of the secondary authentication PIN.
		/// </summary>
		AUTH_PIN_FLAGS = CKA_AUTH_PIN_FLAGS,

		/// <summary>
		/// Hardware feature (type) [CKH].
		/// </summary>
		HW_FEATURE_TYPE = CKA_HW_FEATURE_TYPE,

		///
		/// There are a number of additional SafeNet vendor defined attribute types.
		///

		/// <summary>
		/// The key size for key type EC can be any arbitrary bit length. That is, not within the byte boundary (for example, the key size for a P-521 curve).
		/// <para>- The KEY_SIZE attribute has the following additional properties:</para>
		/// <para>- Size is in bits</para>
		/// <para>- Read-only attribute</para>
		/// <para>- Assigned at object creation time</para>
		/// <para>- Applicable to both private and public keys</para>
		/// <para>NOTE: This attribute is applicable only to EC.</para>
		/// </summary>
		KEY_SIZE = (int)CKA_KEY_SIZE,

		/// <summary>
		/// The value of this attribute maintains a count of the number of times a key object is used for a cryptographic operation.
		/// <para>It is possible to set the value of this attribute for a key.</para>
		/// <para>Afterwards it is automatically incremented each time the key is used in a Cryptoki initialization routine (that is, C_SignInit).</para>
		/// <para>When generating Certificate objects with the CKM_ENCODE_X_509 mechanism the SERIAL_NUMBER attribute for the new certificate object is taken from the certificate signing key's USAGE_COUNT attribute.</para>
		/// <para>The usage count from the private key is used only if the serial number is not already included in the template for the new certificate.</para>
		/// <para>In order to stop abuse of the USAGE_COUNT/USAGE_LIMIT controls any Object with a non-empty CKA_USAGE_LIMIT attribute will be automatically deleted after a successful Copy operation. Without this rule a key and its attributes may be copied and therefore the number of operation remaining is automatically doubled.</para>
		/// </summary>
		USAGE_COUNT = (int)CKA_USAGE_COUNT,

#ifndef _PTKC_V400_
		/// <summary>
		/// This attribute represents the maximum number of times the object can be used.
		/// <para>Simply - it is the highest possible USAGE_COUNT value allowed on this object.</para>
		/// <para>This attribute may be specified when the object is created or added to an object when MODIFIABLE is 'True'.</para>
		/// <para>Once the attribute is added it cannot be changed by the C_SetAttributeValue function.</para>
		/// <para>Only the CKM_SET_ATTRIBUTES ticket mechanism can change this attribute. The Ticket can modify the attribute even if MODIFABLE is 'False'.</para>
		/// <para>In order to stop abuse of the USAGE_COUNT/USAGE_LIMIT controls any Object with a non-empty CKA_USAGE_LIMIT attribute will be automatically deleted after a successful Copy operation. Without this rule a key and its attributes may be copied and therefore the number of operation remaining is automatically doubled.</para>
		/// </summary>
		USAGE_LIMIT = (int)CKA_USAGE_LIMIT,
#endif

		///
		/// BYTE-ARRAY ATTRIBUTES
		///

		/// <summary>
		/// Value of the object.
		/// <para>Default is empty.</para>
		/// </summary>
		VALUE = CKA_VALUE,

		/// <summary>
		/// DER-encoding of the object identifier indicating the data object type.
		/// <para>Default is empty.</para>
		/// </summary>
		OBJECT_ID = CKA_OBJECT_ID,

		/// <summary>
		/// DER-encoding of the certificate issuer name.
		/// <para>Default is empty.</para>
		/// </summary>
		ISSUER = CKA_ISSUER,

		/// <summary>
		/// DER-encoding of the certificate serial number.
		/// <para>Default is empty.</para>
		/// </summary>
		SERIAL_NUMBER = CKA_SERIAL_NUMBER,

		/// <summary>
		/// DER-encoding of the attribute certificate's issuer field.
		/// </summary>
		AC_ISSUER = CKA_AC_ISSUER,

		/// <summary>
		/// DER-encoding of the attribute certificate's subject field..
		/// </summary>
		OWNER = CKA_OWNER,

		/// <summary>
		/// BER-encoding of a sequence of object identifier values corresponding to the attribute types contained in the certificate..
		/// </summary>
		ATTR_TYPES = CKA_ATTR_TYPES,

		/// <summary>
		/// DER-encoding of the key subject name.
		/// <para>Default is empty.</para>
		/// </summary>
		SUBJECT = CKA_SUBJECT,

		/// <summary>
		/// Key identifier for public/private key pair.
		/// <para>Default is empty.</para>
		/// </summary>
		ID = CKA_ID,

		/// <summary>
		/// Modulus n.
		/// </summary>
		MODULUS = CKA_MODULUS,

		/// <summary>
		/// Public exponent e.
		/// </summary>
		PUBLIC_EXPONENT = CKA_PUBLIC_EXPONENT,

		/// <summary>
		/// Private exponent d.
		/// </summary>
		PRIVATE_EXPONENT = CKA_PRIVATE_EXPONENT,

		/// <summary>
		/// Prime p.
		/// </summary>
		PRIME_1 = CKA_PRIME_1,

		/// <summary>
		/// Prime q.
		/// </summary>
		PRIME_2 = CKA_PRIME_2,

		/// <summary>
		/// Private exponent d modulo p-1.
		/// </summary>
		EXPONENT_1 = CKA_EXPONENT_1,

		/// <summary>
		/// Private exponent d modulo q-1.
		/// </summary>
		EXPONENT_2 = CKA_EXPONENT_2,

		/// <summary>
		/// CRT coefficient q^-1 mod p.
		/// </summary>
		COEFFICIENT = CKA_COEFFICIENT,

		/// <summary>
		/// Prime p (512 to 1024 bits, in steps of 64 bits).
		/// </summary>
		PRIME = CKA_PRIME,

		/// <summary>
		/// Subprime q (160 bits).
		/// </summary>
		SUBPRIME = CKA_SUBPRIME,

		/// <summary>
		/// Base g.
		/// </summary>
		BASE = CKA_BASE,

		/// <summary>
		/// DER-encoding of an ANSI X9.62 Parameters value.
		/// </summary>
		ECDSA_PARAMS = CKA_ECDSA_PARAMS,

		/// <summary>
		/// DER-encoding of an ANSI X9.62 Parameters value.
		/// </summary>
		EC_PARAMS = CKA_EC_PARAMS,

		/// <summary>
		/// DER-encoding of ANSI X9.62 ECPoint value Q.
		/// </summary>
		EC_POINT = CKA_EC_POINT,

		///
		/// There are a number of additional SafeNet vendor defined attribute types.
		///

		/// <summary>
		/// This attribute is a key check value that is calculated as follows:
		/// <para>- Take a buffer of the cipher block size of binary zeros (0x00).</para>
		/// <para>- Encrypt this block in ECB mode.</para>
		/// <para>- Take the first three bytes of cipher text as the check value.</para>
		/// <para>This attribute is calculated on all keys of class CKO_SECRET, which means all symmetric key types when they are created or generated.</para>
		/// <para>The attribute is generated by default if it is not supplied in the key template.</para>
		/// <para>If it is supplied in the template, then the template value is used, even if its value would conflict with the one calculated as shown above. This is applicable when a customer wants to use an alternative method to validate a key.</para>
		/// <para>NOTE: The ENCRYPT attribute is not required to be set to TRUE on the key object, in order for the check value attribute to be generated. This attribute cannot be changed once it has been set.</para>
		/// </summary>
		CHECK_VALUE = (int)CKA_CHECK_VALUE,

#ifndef _PTKC_V400_
		/// <summary>
		/// This attribute is used to hold the certificate of an entity that can perform certain Management operations on that Object.
		/// <para>The ADMIN_CERT is a new Vendor defined Attribute.</para>
		/// <para>The value of the attribute is the DER encoding of a X509 v3 Public Key Certificate.</para>
		/// <para>Rules for validation of the Certificate are: if it is self signed then it is implicitly trusted, if it signed by another entity then that Entities PKC must be present on the Token and be part of a chain terminating in a Cert marked TRUSTED = 'True'.</para>
		/// <para>It may be specified in the template when the Object is created, generated or imported. It may be added to an object with the C_SetAttributeValue command only if the MODIFIABLE is 'True' and the attribute does not already exist i.e. once an object is created and made non-modifiable then the ADMIN_CERT cannot be later added.</para>
		/// <para>The ADMIN_CERT is used with the CKM_SET_ATTRIBUTES Ticket Mechanism.</para>
		/// <para>So if an object is not Modifiable and has no ADMIN_CERT then the CKM_SET_ATTRIBUTES Ticket Mechanism can never be applied to that object and its attributes are forever locked.</para>
		/// </summary>
		ADMIN_CERT = (int)CKA_ADMIN_CERT,
#endif

		/// <summary>
		/// This attribute may be used to supply X.509 certificate extensions or PKCS#10 attribute values when creating these objects using the CKM_ENCODE_X509 or CKM_ENCODE_PKCS10 mechanisms respectively.
		/// <para>The value of the PKI_ATTRIBUTE_BER_ENCODED is the BER encoded attribute.</para>
		/// </summary>
		PKI_ATTRIBUTE_BER_ENCODED = (int)CKA_PKI_ATTRIBUTE_BER_ENCODED,

		/// <summary>
		/// Certificate serial number as an integer.
		/// <para>If this attribute is not included the serial number is set to the value of the USAGE_COUNT attribute of the signing key.</para>
		/// <para>SERIAL_NUMBER is the encoded version of this attribute.</para>
		/// <para>NOTE: SERIAL_NUMBER_INT is a Cryptoki Big Integer and not an intrinsic integer type. Therefore, its size is not constrained to 4 bytes.</para>
		/// <para>Default is empty.</para>
		/// </summary>
		SERIAL_NUMBER_INT = (int)CKA_SERIAL_NUMBER_INT,

		///
		/// STRING ATTRIBUTES
		///

		/// <summary>
		/// Description of the object.
		/// <para>Default is empty.</para>
		/// </summary>
		LABEL = CKA_LABEL,

		/// <summary>
		/// Description of the application that manages the object.
		/// <para>Default is empty.</para>
		/// </summary>
		APPLICATION = CKA_APPLICATION,

		///
		/// There are a number of additional SafeNet vendor defined attribute types.
		///

		/// <summary>
		/// This attribute mirror the standard attribute (without the _STR suffix) but present that attribute as a printable value rather than as a DER encoding.
		/// <para>For the distinguished name attributes the string is encoded in the form:</para>
		/// <para>C=Country code, O=Organization, CN=Common Name, OU=Organizational Unit, L=Locality name, ST=State name</para>
		/// </summary>
		ISSUER_STR = (int)CKA_ISSUER_STR,

		/// <summary>
		/// This attribute mirror the standard attribute (without the _STR suffix) but present that attribute as a printable value rather than as a DER encoding.
		/// <para>For the distinguished name attributes the string is encoded in the form:</para>
		/// <para>C=Country code, O=Organization, CN=Common Name, OU=Organizational Unit, L=Locality name, ST=State name</para>
		/// </summary>
		SUBJECT_STR = (int)CKA_SUBJECT_STR,

		///
		/// DATE/TIME ATTRIBUTES
		///

		/// <summary>
		/// This attribute and END_DATE control the period in which the object can be used.
		/// <para>These attributes may be specified when the object is created or added to an object when MODIFIABLE is 'True'.</para>
		/// <para>Once the attribute is added it cannot be changed by the C_SetAttributeValue function.</para>
		/// <para>Only the CKM_SET_ATTRIBUTES ticket mechanism can change these attributes. The Ticket can modify the attributes even if MODIFABLE is 'False'.</para>
		/// <para>Attribute validation is performed if these attributes are supplied during a C_CreateObject or C_UnWrapkey or C_DeriveKey operation.</para>
		/// <para>One or both of these attributes may be missing or be present but with an empty value. In this case the attribute is interpreted as "No restriction applies". For example if START_DATE is specified but END_DATE is not then the object will be usable from the start date onwards.</para>
		/// <para>If the attribute is specified then it must be valid data structure - i.e. year is between 1900 and 9999, month from 01 to 12 and day from 01 to 31.</para>
		/// </summary>
		START_DATE = CKA_START_DATE,

		/// <summary>
		/// This attribute and START_DATE control the period in which the object can be used.
		/// <para>These attributes may be specified when the object is created or added to an object when MODIFIABLE is 'True'.</para>
		/// <para>Once the attribute is added it cannot be changed by the C_SetAttributeValue function.</para>
		/// <para>Only the CKM_SET_ATTRIBUTES ticket mechanism can change these attributes. The Ticket can modify the attributes even if MODIFABLE is 'False'.</para>
		/// <para>Attribute validation is performed if these attributes are supplied during a C_CreateObject or C_UnWrapkey or C_DeriveKey operation.</para>
		/// <para>One or both of these attributes may be missing or be present but with an empty value. In this case the attribute is interpreted as "No restriction applies". For example if START_DATE is specified but END_DATE is not then the object will be usable from the start date onwards.</para>
		/// <para>If the attribute is specified then it must be valid data structure - i.e. year is between 1900 and 9999, month from 01 to 12 and day from 01 to 31.</para>
		/// </summary>
		END_DATE = CKA_END_DATE,

		///
		/// There are a number of additional SafeNet vendor defined attribute types.
		///

		/// <summary>
		/// Every object created is assigned a value for the TIME_STAMP attribute.
		/// <para>This value is always read-only and may not be included in a template for a new object.</para>
		/// <para>However when an object is duplicated using the C_CopyObject function or the object is a key derived using the C_DeriveKey the new object will inherit the same creation time as the original object.</para>
		/// </summary>
		TIME_STAMP = (int)CKA_TIME_STAMP,

		/// <summary>
		/// This attribute and CERTIFICATE_END_TIME are used to specify a user defined validity period for X.509 certificates.
		/// <para>Without these, the certificate validity period is 1 year from the date and time of creation.</para>
		/// </summary>
		CERTIFICATE_START_TIME = (int)CKA_CERTIFICATE_START_TIME,

		/// <summary>
		/// This attribute and CERTIFICATE_START_TIME are used to specify a user defined validity period for X.509 certificates.
		/// <para>Without these, the certificate validity period is 1 year from the date and time of creation.</para>
		/// </summary>
		CERTIFICATE_END_TIME = (int)CKA_CERTIFICATE_END_TIME,

		unknown = (int)CKA_VENDOR_DEFINED,
	};

	/// <summary>
	///  This Class includes the type and value of an attribute
	/// </summary>
	/// <author> Roohollah Yeylaghi Ashrafi </author>
	/// <version> $Revision: 1.0.0.1 $ $Date : 2014-10-01 00:00:00 $ </version>
	public ref class SMAttribute
	{
	private:

		/// <summary>
		/// Attribute type
		/// </summary>
		AttributeType CKA;

		/// <summary>
		/// Value of the Attribute
		/// </summary>
		Object^ value;

	public:

		/// <summary>
		/// Initializes a new instance of the <see cref="SMAttribute"/> class.
		/// </summary>
		SMAttribute(void) { this->CKA = AttributeType::unknown; this->value = nullptr; };

		SMAttribute(AttributeType attributeType);

		SMAttribute(AttributeType attributeType, Object^ value);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		SMAttribute(SMAttribute^ attribute);

		/// <summary>The 'Attribute_Type' property represents the type of attribute.</summary>
		/// <value>The 'Attribute_Type' property gets the value of the CK_ATTRIBUTE_TYPE, 'CKA'.</value>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/28	Created
		/// </history>
		property AttributeType Attribute_Type
		{
			AttributeType get() { return this->CKA; }
		}

		/// <summary>The 'Value' property represents the type of attribute.</summary>
		/// <value>The 'Value' property gets the value of the CK_VOID_PTR, 'value'.</value>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/28	Created
		/// </history>
		property Object^ Value
		{
			Object^ get() { return this->value; }
			void set(Object^ x) { this->value = x; }
		}

		/// <summary>
		/// Get the attribute System::Type.
		/// </summary>
		System::TypeCode GetAttributeSystemTypeCode();
	};
}
