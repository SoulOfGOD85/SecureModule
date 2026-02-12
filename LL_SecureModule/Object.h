#pragma once

#include "SecureModuleException.h"
#include "Session.h"
#include "Attribute.h"
#include "Parameter.h"

using namespace System;

namespace LL_SecureModule
{
	/// Pre-definition of object class.
	ref class SMObject;

	/// <summary>
	/// Object classes are defined with the objects that use them. The type is specified on an object through the CLASS attribute of the object.
	/// </summary>
	public enum class ObjectClass
	{
		DATA = CKO_DATA,
		CERTIFICATE = CKO_CERTIFICATE,
		PUBLIC_KEY = CKO_PUBLIC_KEY,
		PRIVATE_KEY = CKO_PRIVATE_KEY,
		SECRET_KEY = CKO_SECRET_KEY,
		HW_FEATURE = CKO_HW_FEATURE,
		DOMAIN_PARAMETERS = CKO_DOMAIN_PARAMETERS,

		///
		/// There are a number of additional SafeNet vendor defined class types.
		///

		CERTIFICATE_REQUEST = CKO_CERTIFICATE_REQUEST,
		CRL = CKO_CRL,
		ADAPTER = CKO_ADAPTER,
		SLOT = CKO_SLOT,
		FM = CKO_FM,
	};

	/// <summary>
	/// This Class provides a structure that contains the resulting key handles and initialization vectors after performing a DeriveKey function with the SSL3_KEY_AND_MAC_DERIVE mechanism.
	/// </summary>
	public ref class SSL3_KEY_MAT_OUT
	{
	public:
		/// <summary>
		/// Key object for the resulting Client MAC Secret key.
		/// </summary>
		SMObject^ clientMacSecret;

		/// <summary>
		/// Key object for the resulting Server MAC Secret key.
		/// </summary>
		SMObject^ serverMacSecret;

		/// <summary>
		/// Key object for the resulting Client Secret key.
		/// </summary>
		SMObject^ clientKey;

		/// <summary>
		/// Key object for the resulting Server Secret key.
		/// </summary>
		SMObject^ serverKey;

		/// <summary>
		/// Initialization vector(IV) created for the client(if any).
		/// </summary>
		array<Byte>^ IVClient;

		/// <summary>
		/// Initialization vector(IV) created for the server(if any)
		/// </summary>
		array<Byte>^ IVServer;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		SSL3_KEY_MAT_OUT() { this->clientMacSecret = this->serverMacSecret = this->clientKey = this->serverKey = nullptr; this->IVClient = this->IVServer = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		SSL3_KEY_MAT_OUT(SMObject^ clientMacSecret, SMObject^ serverMacSecret, SMObject^ clientKey, SMObject^ serverKey, array<Byte>^ IVClient, array<Byte>^ IVServer);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		SSL3_KEY_MAT_OUT(SSL3_KEY_MAT_OUT^ ssl3_key_mat_out);
	};

	/// <summary>
	/// This Class provides the parameters to the SSL3_KEY_AND_MAC_DERIVE mechanism.
	/// </summary>
	public ref class SSL3_KEY_MAT_PARAMS
	{
	public:
		/// <summary>
		/// The length (in bits) of the MACing keys agreed upon during the protocol handshake phase.
		/// </summary>
		UInt32 macSizeInBits;

		/// <summary>
		/// The length (in bits) of the secret keys agreed upon during the protocol handshake phase.
		/// </summary>
		UInt32 keySizeInBits;

		/// <summary>
		/// The length (in bits) of the IV agreed upon during the protocol handshake phase.If no IV is required, the length should be set to 0.
		/// </summary>
		UInt32 IVSizeInBits;

		/// <summary>
		/// A Boolean value which indicates whether the keys have to be derived for an export version of the protocol.
		/// </summary>
		Boolean isExport;

		/// <summary>
		/// Client's and server's random data information
		/// </summary>
		SSL3_RANDOM_DATA^ randomInfo;

		/// <summary>
		/// The structures which receives the handles for the keys generated and the IVs.
		/// </summary>
		SSL3_KEY_MAT_OUT^ key_mat_out;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		SSL3_KEY_MAT_PARAMS() { this->macSizeInBits = this->keySizeInBits = this->IVSizeInBits = 0; this->isExport = false; this->randomInfo = nullptr; this->key_mat_out = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		SSL3_KEY_MAT_PARAMS(UInt32 macSizeInBits, UInt32 keySizeInBits, UInt32 IVSizeInBits, Boolean isExport, SSL3_RANDOM_DATA^ randomInfo, SSL3_KEY_MAT_OUT^ key_mat_out);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		SSL3_KEY_MAT_PARAMS(SSL3_KEY_MAT_PARAMS^ ssl3_key_mat_params);
	};

	/// <summary>
	/// This Class provides the parameters to the ENCODE_X_509_LOCAL_CERT mechanism.
	/// </summary>
	public ref class MECH_TYPE_AND_OBJECT
	{
	public:
		/// <summary>
		/// Specifies the actual signature mechanism to use in generation of the certificate signature. This must be one of the multipart digest RSA or DSA algorithms.
		/// </summary>
		SignMechanism mechanism;

		/// <summary>
		/// Specifies the signature generation key. That is, it should specify a RSA or DSA private key as appropriate for the chosen signature mechanism.
		/// </summary>
		SMObject^ obj;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		MECH_TYPE_AND_OBJECT() { this->obj = nullptr; this->mechanism = SignMechanism::RSA_PKCS; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		MECH_TYPE_AND_OBJECT(SignMechanism mechanism, SMObject^ obj);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		MECH_TYPE_AND_OBJECT(MECH_TYPE_AND_OBJECT^ mech_type_and_object);
	};

	/// <summary>
	/// This Class provides the parameters to the PKCS12_PBE_EXPORT mechanisms.
	/// </summary>
	public ref class PKCS12_PBE_EXPORT_PARAMS
	{
	public:
		/// <summary>
		/// This is the key generation mechanism for SafeBag encryption. It is only applicable to pkcs8ShroudedKeyBag.
		/// </summary>
		enum class SafeBagEncryption
		{
			PBE_SHA1_RC4_128 = CKM_PBE_SHA1_RC4_128,
			PBE_SHA1_RC4_40 = CKM_PBE_SHA1_RC4_40,
			PBE_SHA1_DES3_EDE_CBC = CKM_PBE_SHA1_DES3_EDE_CBC,
			PBE_SHA1_DES2_EDE_CBC = CKM_PBE_SHA1_DES2_EDE_CBC,
			PBE_SHA1_RC2_128_CBC = CKM_PBE_SHA1_RC2_128_CBC,
			PBE_SHA1_RC2_40_CBC = CKM_PBE_SHA1_RC2_40_CBC,
		};

		/// <summary>
		/// This is the key generation mechanism for SafeContent encryption. It is only applicable to EncryptedData.
		/// </summary>
		enum class SafeContentEncryption
		{
			PBE_SHA1_RC4_128 = CKM_PBE_SHA1_RC4_128,
			PBE_SHA1_RC4_40 = CKM_PBE_SHA1_RC4_40,
			PBE_SHA1_DES3_EDE_CBC = CKM_PBE_SHA1_DES3_EDE_CBC,
			PBE_SHA1_DES2_EDE_CBC = CKM_PBE_SHA1_DES2_EDE_CBC,
			PBE_SHA1_RC2_128_CBC = CKM_PBE_SHA1_RC2_128_CBC,
			PBE_SHA1_RC2_40_CBC = CKM_PBE_SHA1_RC2_40_CBC,
		};

		/// <summary>
		/// Key generation mechanism for generating PFX MAC.
		/// </summary>
		enum class KeGenerationMechanism
		{
			PBA_SHA1_WITH_SHA1_HMAC = CKM_PBA_SHA1_WITH_SHA1_HMAC,
		};

		/// <summary>
		/// This is certificate associated to the private key.
		/// </summary>
		SMObject^ keyCert;

		/// <summary>
		/// AuthenticatedSafe password.
		/// </summary>
		String^ passwordAuthSafe;

		/// <summary>
		/// HMAC password.
		/// </summary>
		String^ passwordHMAC;

		/// <summary>
		/// Key generation mechanism.
		/// </summary>
		SafeBagEncryption safeBagKgMech;

		/// <summary>
		/// Key generation mechanism.
		/// </summary>
		SafeContentEncryption safeContentKgMech;

		/// <summary>
		///  The valid option is: PBA_SHA1_WITH_SHA1_HMAC
		/// </summary>
		static const KeGenerationMechanism hmacKgMech = KeGenerationMechanism::PBA_SHA1_WITH_SHA1_HMAC;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		PKCS12_PBE_EXPORT_PARAMS() { this->keyCert = nullptr; this->passwordAuthSafe = this->passwordHMAC = String::Empty; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		PKCS12_PBE_EXPORT_PARAMS(SMObject^ keyCert, String^ passwordAuthSafe, String^ passwordHMAC, SafeBagEncryption safeBagKgMech, SafeContentEncryption safeContentKgMech);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		PKCS12_PBE_EXPORT_PARAMS(PKCS12_PBE_EXPORT_PARAMS^ pkcs12_pbe_export_params);
	};

	/// <summary>
	/// This Class provides the parameters to the PKCS12_PBE_IMPORT mechanisms.
	/// </summary>
	public ref class PKCS12_PBE_IMPORT_PARAMS
	{
	public:
		/// <summary>
		/// AuthenticatedSafe password.
		/// </summary>
		String^ passwordAuthSafe;

		/// <summary>
		/// HMAC password.
		/// </summary>
		String^ passwordHMAC;

		/// <summary>
		/// Certificate attributes
		/// </summary>
		array<SMAttribute^>^ certAttr;

		/// <summary>
		/// Returned certificate(s)
		/// </summary>
		array<SMObject^>^ cert;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		PKCS12_PBE_IMPORT_PARAMS() { this->passwordAuthSafe = this->passwordHMAC = String::Empty; this->certAttr = nullptr; this->cert = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		PKCS12_PBE_IMPORT_PARAMS(String^ passwordAuthSafe, String^ passwordHMAC, array<SMAttribute^>^ certAttr, array<SMObject^>^ cert);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		PKCS12_PBE_IMPORT_PARAMS(PKCS12_PBE_IMPORT_PARAMS^ pkcs12_pbe_import_params);
	};

	/// <summary>
	/// Token-specific identifier for an object
	/// </summary>
	public ref class SMObject
	{
	private:
		/// <summary>
		/// PKCS#11 handle of object.
		/// <para>It is a token-specific identifier for an object.</para>
		/// <para>When an object is created or found on a token by an application, Cryptoki assigns it an object handle for that application's sessions to use to access it.</para>
		/// <para>A particular object on a token does not necessarily have a handle which is fixed for the lifetime of the object; however, if a particular session can use a particular handle to access a particular object, then that session will continue to be able to use that handle to access that object as long as the session continues to exist, the object continues to exist, and the object continues to be accessible to the session.</para>
		/// <para>Valid object handles in Cryptoki always have nonzero values.</para>
		/// </summary>
		CK_OBJECT_HANDLE hObject;

		/// <summary>
		/// SMSession
		/// </summary>
		SMSession^ object_session;

	public:
		/// <summary>
		/// Default Class constructor.
		/// </summary>
		SMObject(void) { object_session = gcnew SMSession(); this->hObject = CK_INVALID_HANDLE; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		/// <param name="session">the new SMObject's session</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		SMObject(SMSession^ session) : object_session(session) { this->hObject = CK_INVALID_HANDLE; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		/// <param name="session">the new SMObject's session</param>
		/// <param name="hObject">the object's handle of new SMObject.</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		SMObject(SMSession^ session, UInt32 hObject) : object_session(session) { this->hObject = (CK_OBJECT_HANDLE)hObject; };

		/// <summary>
		/// Copy constructor.
		/// </summary>
		/// <param name="ck_object">the source SMObject to be copying</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		SMObject(SMObject^ ck_object) : object_session(ck_object->object_session) { this->hObject = ck_object->hObject; };

		/// <summary>returns the SMObject's session.</summary>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/17	Created
		/// </history>
		SMSession^ getSession()
		{
			return this->object_session;
		}

		/// <summary>returns the cryptoki object handle.</summary>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/17	Created
		/// </history>
		UInt32^ getObjectHandle()
		{
			return this->hObject;
		}

		/// <summary>
		/// Creates a new object.
		/// <para>Only session objects can be created during a read-only session. Only public objects can be created unless the normal user is logged in.</para>
		/// <para>If CreateObject cannot support the precise attribute(s) template supplied to it, it will fail and return without creating any object.</para>
		/// <para>If CreateObject is used to create a key object, the key object will have its LOCAL attribute set to 'False'.</para>
		/// <para>If that key object is a secret or private key then the new key will have the ALWAYS_SENSITIVE attribute set to 'False', and the NEVER_EXTRACTABLE attribute set to 'False'.</para>
		/// </summary>
		/// <param name="attribute">Attribute(s) template that specifies the attribute values of the new object</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		void CreateObject(array<SMAttribute^>^ attribute);

		/// <summary>
		/// Destroys object.
		/// <para>Only session objects can be destroyed during a read-only session. Only public objects can be destroyed unless the normal user is logged in.</para>
		/// <para>In addition to standard object deletion rules there is support for the DELETABLE attribute. This is an optional attribute that may be specified for token objects.</para>
		/// <para>For token objects with DELETABLE attribute set to 'False' the DestroyObject function will not delete the object and will instead return the error OBJECT_READ_ONLY.</para>
		/// <para>Unmodifiable objects can be deleted. Objects may however specify DELETABLE to 'False', for token objects only, in which case the object may not be deleted using the DestroyObject function. Only by re-initializing the token can the object be destroyed.</para>
		/// </summary>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		void DestroyObject();

		/// <summary>
		/// Gets the size of the object in bytes.
		/// <para>This function interprets the object size to be the amount of memory guaranteed to be sufficient to encode the object‘s attributes.</para>
		/// </summary>
		/// <param name="objectSize">the output object size</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		void GetObjectSize(UInt32% objectSize);

		/// <summary>
		/// Obtains the value of one or more attributes of the object.
		/// <para>Sensitive attributes are returned with the type and length information but an empty value, and also return an error result value of ATTRIBUTE_SENSITIVE.</para>
		/// </summary>
		/// <param name="attribute">Attribute(s) template that specifies which attribute values are to be obtained.</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		void GetAttributeValue(array<SMAttribute^>^ attribute);

		/// <summary>
		/// Modifies the value of one or more attributes of the object.
		/// <para>Only session objects can be modified during a read-only session.</para>
		/// <para>The input attribute(s) may specify new values for any attributes of the object that can be modified.</para>
		/// <para>If the attribute(s) specify a value of an attribute which is incompatible with other existing attributes of the object, the call fails with the return code TEMPLATE_INCONSISTENT.</para>
		/// <para>Not all attributes can be modified.</para>
		/// </summary>
		/// <param name="attribute">the input attribute(s) template that specifies which attribute values are to be modified and their new values</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		void SetAttributeValue(array<SMAttribute^>^ attribute);

		/// <summary>
		/// Copies an object, creating a new object for the copy.
		/// <para>The template may specify new values for any attributes of the object that can ordinarily be modified (e.g., in the course of copying a secret key, a key's EXTRACTABLE attribute may be changed from CK_TRUE to CK_FALSE, but not the other way around. If this change is made, the new key's NEVER_EXTRACTABLE attribute will have the value CK_FALSE. Similarly, the template may specify that the new key's SENSITIVE attribute be CK_TRUE; the new key will have the same value for its ALWAYS_SENSITIVE attribute as the original key).</para>
		/// <para>It may also specify new values of the TOKEN and PRIVATE attributes (e.g., to copy a session object to a token object). If the template specifies a value of an attribute which is incompatible with other existing attributes of the object, the call fails with the return code TEMPLATE_INCONSISTENT.</para>
		/// <para>If a call to C_CopyObject cannot support the precise template supplied to it, it will fail and return without creating any object.</para>
		/// <para>Only session objects can be created during a read-only session. Only public objects can be created unless the normal user is logged in.</para>
		/// </summary>
		/// <param name="newObject">the output reference to the new object</param>
		/// <param name="attribute">the input attribute(s) template that specifies attribute values of new object</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		void CopyObject(SMObject^% newObject, array<SMAttribute^>^ attribute);

		/// <summary>
		/// This function is a SafeNet extension to PKCS #11. It is identical to the PKCS#11 CopyObject function with the exception that it is capable of copying objects from one token to another token where the two tokens belong to the same adapter.
		/// <para>This function copies an object from one session to another session, creating a new object for the copy.</para>
		/// <para>If the base object has a valid USAGE_LIMIT attribute then the base object is deleted after a successful copy.</para>
		/// <para>The template may specify new values for any attributes of the object that can ordinarily be modified (e.g., in the course of copying a secret key, a key's EXTRACTABLE attribute may be changed from TRUE to FALSE, but not the other way around. If this change is made, the new key's NEVER_EXTRACTABLE attribute will have the value FALSE.</para>
		/// <para>Similarly, the template may specify that the new key's SENSITIVE attribute be TRUE; the new key will have the same value for its ALWAYS_SENSITIVE attribute as the original key). It may also specify new values of the TOKEN and PRIVATE attributes (e.g., to copy a session object to a token object).</para>
		/// <para>If the template specifies a value of an attribute which is incompatible with other existing attributes of the object, the call fails with the return code TEMPLATE_INCONSISTENT.</para>
		/// <para>If a call to CopyObject cannot support the precise template supplied to it, it will fail and return without creating any object.</para>
		/// <para>Only session objects can be created during a read-only session. Only public objects can be created unless the normal user is logged in.</para>
		/// <para>NOTE: If the Increased Security flag is set as part of the security policy, then CopyObject does not allow changing the MODIFIABLE flag from FALSE to TRUE.</para>
		/// </summary>
		/// <param name="destinationSession">the destination session for new object</param>
		/// <param name="newObject">the output reference to the new object</param>
		/// <param name="attribute">the input attribute(s) template that specifies attribute values of new object</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/21	Created
		/// </history>
		void CopyObject(SMSession^ destinationSession, SMObject^% newObject, array<SMAttribute^>^ attribute);

		/// <summary>
		/// This function copies an object from one Token to another.
		/// <para>This function tries the following methods to copy the object, in order:</para>
		/// <para>- Using the CKM_ENCODE_ATTRIBUTES vendor defined key wrapping mechanism to transfer keys.</para>
		/// <para>- Reading all the attributes of the existing object and creating a new object with them.</para>
		/// </summary>
		/// <param name="destinationSession">the destination session for new object</param>
		/// <param name="newObject">the output reference to the new object</param>
		/// <param name="attribute">the input attribute(s) template that specifies attribute values of new object</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/04/04	Created
		/// </history>
		void Transfer(SMSession^ destinationSession, SMObject^% newObject, array<SMAttribute^>^ attribute);

		/// <summary>
		/// The single-object search operation will only find objects that the session can view.
		/// <para>For example, an object search in an "R/W Public Session" will not find any private objects (even if one of the attributes in the search template specifies that the search is for private objects).</para>
		/// </summary>
		/// <param name="attribute">the input attribute(s) template that specifies attribute values of an object to find</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		void SelectObject(array<SMAttribute^>^ attribute);

		/// <summary>
		/// The multi-object search operation will only find objects that the session can view.
		/// <para>For example, an object search in an "R/W Public Session" will not find any private objects (even if one of the attributes in the search template specifies that the search is for private objects).</para>
		/// </summary>
		/// <param name="objects">the output list of founded objects</param>
		/// <param name="attribute">the input attribute(s) template that specifies attribute values of objects to find</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		static void FindObjects(SMSession^ session, System::Collections::Generic::List<SMObject^>^% objects, array<SMAttribute^>^ attribute);

		/// <summary>
		/// Calculate and return an AS2805 KCV (Key Check Value) for a key.
		/// <para>The key must be capable of doing an encryption operation using the supplied mechanism for this to succeed.</para>
		/// <para>Note that The CKA_CHECK_VALUE attribute can be used to get the KVC of a key that does not support the encryption operation.</para>
		/// </summary>
		/// <param name="kcv">the output encryption (KCV) result</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/05/30	Created
		/// </history>
		void CalculateKCV(array<Byte>^% kcv);

		/// <summary>
		/// Generates a secret key or set of domain parameters, creating a new object.
		/// <para>Since the type of key or domain parameters to be generated is implicit in the generation mechanism, the template does not need to supply a key type.</para>
		/// <para>If it does supply a key type which is inconsistent with the generation mechanism, GenerateKey fails and returns the error code TEMPLATE_INCONSISTENT.The CLASS attribute is treated similarly.</para>
		/// <para>The object created by a successful call to GenerateKey will have its LOCAL attribute set to TRUE</para>
		/// </summary>
		/// <param name="mechanism">The generation mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="attribute">The input attribute(s) template for the new key or set of domain parameters</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/02/29	Created
		/// </history>
		void GenerateKey(KeyGenerationMechanism mechanism, Object^ parameter, array<SMAttribute^>^ attribute);

		/// <summary>
		/// Generates a public/private key pair, creating new key objects.
		/// <para>Since the types of keys to be generated are implicit in the key pair generation mechanism, the templates do not need to supply key types.</para>
		/// <para>The key objects created by a successful call to GenerateKeyPair will have their LOCAL attributes set to TRUE.</para>
		/// </summary>
		/// <param name="mechanism">The generation mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="publicKey_attribute">The input attribute(s) template for the public key</param>
		/// <param name="privateKey_attribute">The input attribute(s) template for the private key</param>
		/// <param name="privateKey">the output reference to the private key; The public key reference to 'this' object</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/02/30	Created
		/// </history>
		void GenerateKeyPair(KeyGenerationMechanism mechanism, Object^ parameter, array<SMAttribute^>^ publicKey_attribute, array<SMAttribute^>^ privateKey_attribute, SMObject^% privateKey);

		/// <summary>
		/// Encrypts single-part data.
		/// </summary>
		/// <param name="mechanism">The encryption mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="plainData">the input plain data</param>
		/// <param name="cipherData">the output cipher (or encrypted) data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/02/29	Created
		/// </history>
		void Encrypt(EncryptionMechanism mechanism, Object^ parameter, array<Byte>^ plainData, array<Byte>^% cipherData);

		/// <summary>
		/// Decrypts single-part data.
		/// </summary>
		/// <param name="mechanism">The decryption mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="cipherData">the input cipher data</param>
		/// <param name="plainData">the output plain (or decrypted) data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/02/29	Created
		/// </history>
		void Decrypt(EncryptionMechanism mechanism, Object^ parameter, array<Byte>^ cipherData, array<Byte>^% plainData);

		/// <summary>
		/// Signs data in a single part, where the signature is an appendix to the data.
		/// </summary>
		/// <param name="mechanism">The signing mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="data">the input data to sign</param>
		/// <param name="signature">the output signature of data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/02/31	Created
		/// </history>
		void Sign(SignMechanism mechanism, Object^ parameter, array<Byte>^ data, array<Byte>^% signature);

		/// <summary>
		/// Signs data in a single part, where the signature is an appendix to the data.
		/// <para>This method is designed to be high performance</para>
		/// </summary>
		/// <param name="mechanism">The signing mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="data">the input data to sign</param>
		/// <param name="signature">the output signature of data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1397/09/18	Created
		/// </history>
		void SMObject::HighPerformanceSign(SignMechanism mechanism, Object^ parameter, array<Byte>^ data, array<Byte>^% signature);

		/// <summary>
		/// Signs data in a single operation, where the data can be recovered from the signature.
		/// </summary>
		/// <param name="mechanism">The signing mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="data">the input data to sign</param>
		/// <param name="signature">the output signature of data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/02/31	Created
		/// </history>
		void SignRecover(SignRecoverMechanism mechanism, Object^ parameter, array<Byte>^ data, array<Byte>^% signature);

		/// <summary>
		/// Verifies a signature in a single-part operation, where the signature is an appendix to the data.
		/// </summary>
		/// <returns>A successful call to Verify should return either the value TRUE (indicating that the supplied signature is valid) or FALSE (indicating that the supplied signature is invalid).</returns>
		/// <param name="mechanism">The verification mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="data">the input data to sign</param>
		/// <param name="signature">the input signature of data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/02/31	Created
		/// </history>
		Boolean Verify(SignMechanism mechanism, Object^ parameter, array<Byte>^ data, array<Byte>^ signature);

		/// <summary>
		/// Verifies a signature in a single-part operation, where the data is recovered from the signature.
		/// </summary>
		/// <returns>A successful call to VerifyRecover should return TRUE (indicating that the supplied signature is valid) or FALSE (indicating that the supplied signature is invalid).</returns>
		/// <param name="mechanism">The verification mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="signature">the input signature of data</param>
		/// <param name="data">the output recovered data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/02/31	Created
		/// </history>
		void VerifyRecover(SignRecoverMechanism mechanism, Object^ parameter, array<Byte>^ signature, array<Byte>^% data);

		/// <summary>
		/// Wraps (i.e., encrypts) a private or secret key.
		/// </summary>
		/// <param name="mechanism">The wrapping mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="key">Key object to be wrapped</param>
		/// <param name="wrappedKey">the output the wrapped key</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/03	Created
		/// </history>
		void WrapKey(WrappingMechanism mechanism, Object^ parameter, SMObject^ key, array<Byte>^% wrappedKey);

		/// <summary>
		/// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object.
		/// </summary>
		/// <param name="mechanism">The unwrapping mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="wrappedKey">The input the wrapped key</param>
		/// <param name="attribute">The input attribute(s) template for the unwrapped key</param>
		/// <param name="key">The output unwrapped key object</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/03	Created
		/// </history>
		void UnwrapKey(WrappingMechanism mechanism, Object^ parameter, array<Byte>^ wrappedKey, array<SMAttribute^>^ attribute, SMObject^% key);

		/// <summary>
		/// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object.
		/// </summary>
		/// <param name="mechanism">The unwrapping mechanism</param>
		/// <param name="parameter">Parameters for PKCS12_PBE_IMPORT mechanism</param>
		/// <param name="wrappedKey">The input the wrapped key</param>
		/// <param name="attribute">The input attribute(s) template for the unwrapped key</param>
		/// <param name="key">The output unwrapped key object</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/17	Created
		/// </history>
		void UnwrapKey(WrappingMechanism mechanism, PKCS12_PBE_IMPORT_PARAMS^% parameter, array<Byte>^ wrappedKey, array<SMAttribute^>^ attribute, SMObject^% key);

		/// <summary>
		/// Export(Wrap) object(s) to a file using wrap key with SafeNet format.
		/// <para>Note that actual objects that get exported may be less than the number indicated in the list.The HSM will only export objects which are marked EXPORTABLE or EXTRACTABLE.</para>
		/// </summary>
		/// <param name="objects">Key object(s) to be export</param>
		/// <param name="fileName">the output file location/name that receives the exported data</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/21	Created
		/// </history>
		void ExportToFile(array<SMObject^>^ objects, String^ fileName);

		/// <summary>
		/// import(Unwrap) objects from a file using wrap key with SafeNet format.
		/// </summary>
		/// <param name="fileName">the input file location/name that contains the exported data</param>
		/// <param name="importVersion">The import version (example: 300)</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/21	Created
		/// </history>
		void ImportFromFile(String^ fileName, UInt32 importVersion);

		/// <summary>
		/// Derives a key from a base key, creating a new key object
		/// </summary>
		/// <param name="mechanism">The derivation mechanism</param>
		/// <param name="parameter">Parameters for mechanism (if it requires)</param>
		/// <param name="attribute">The input attribute(s) template for the derived key</param>
		/// <param name="key">The output derived key object</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/04	Created
		/// </history>
		void DeriveKey(DeriveMechanism mechanism, Object^ parameter, array<SMAttribute^>^ attribute, SMObject^% key);

		/// <summary>
		/// Derives a key from a base key, creating a new key object
		/// </summary>
		/// <param name="mechanism">The derivation mechanism</param>
		/// <param name="parameter">The input/output Parameters for mechanism</param>
		/// <param name="attribute">The input attribute(s) template for the derived key</param>
		/// <exception cref="System::Exception">Thrown when... .</exception>
		/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1393/03/11	Created
		/// </history>
		void DeriveKey(DeriveMechanism mechanism, SSL3_KEY_MAT_PARAMS^% parameter, array<SMAttribute^>^ attribute);
	};
}
