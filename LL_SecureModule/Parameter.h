#pragma once

#include "Mechanisms.h"
#include "LL_SecureModule.h"

using namespace System;

namespace LL_SecureModule
{
	/// <summary>
	/// This Class provides the parameters to the CKM_RSA_PKCS_OAEP mechanism.
	/// </summary>
	public ref class RSA_PKCS_OAEP_PARAMS
	{
	public:
		/// <summary>
		/// Mechanism ID of the message digest algorithm used to calculate the digest of the encoding parameter.
		/// </summary>
		DigestMechanism hashAlg;

		/// <summary>
		/// Mask generation function to use on the encoded block.
		/// <para>It's used to indicate the Message Generation Function (MGF) applied to a message block when formatting a message block for the PKCS #1 OAEP encryption scheme or the PKCS #1 PSS signature scheme.</para>
		/// </summary>
		static const CK_ULONG MGF = CKG_MGF1_SHA1;

		/// <summary>
		/// Source of the encoding parameter.
		/// <para>It's used to indicate the source of the encoding parameter when formatting a message block for the PKCS #1 OAEP encryption scheme.</para>
		/// <para>Array of Byte containing the value of the encoding parameter. If the parameter is empty, 'SourceData' must be NULL</para>
		/// </summary>
		Boolean sourceType;

		/// <summary>
		/// Data used as the input for the encoding parameter source.
		/// </summary>
		array<Byte>^ sourceData;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		RSA_PKCS_OAEP_PARAMS() { this->sourceType = false; this->sourceData = nullptr; this->hashAlg = DigestMechanism::SHA_1; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		RSA_PKCS_OAEP_PARAMS(DigestMechanism hashAlg, Boolean sourceType, array<Byte>^ sourceData);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		RSA_PKCS_OAEP_PARAMS(RSA_PKCS_OAEP_PARAMS^ rsa_pkcs_oaep_params);
	};

	/// <summary>
	/// This Class provides the parameters to the RC2_ECB and CKM_RC2_MAC mechanisms.
	/// </summary>
	public ref class RC2_PARAMS
	{
	public:
		/// <summary>
		/// It holds the effective number of bits in the RC2 search.
		/// </summary>
		UInt32 effectiveBits;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		RC2_PARAMS() { this->effectiveBits = 0; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		RC2_PARAMS(UInt32 effectiveBits);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		RC2_PARAMS(RC2_PARAMS^ rc2_params);
	};

	/// <summary>
	/// This Class provides the parameters to the RC2_CBC and RC2_CBC_PAD mechanisms.
	/// </summary>
	public ref class RC2_CBC_PARAMS
	{
	public:
		/// <summary>
		/// The effective number of bits in the RC2 search space.
		/// </summary>
		UInt32 effectiveBits;

		/// <summary>
		/// The initialization vector (IV) for cipher block chaining mode.
		/// </summary>
		array<Byte>^ iv;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		RC2_CBC_PARAMS() { this->effectiveBits = 0; iv = gcnew array<Byte>(8); };

		/// <summary>
		/// Class constructor.
		/// </summary>
		RC2_CBC_PARAMS(UInt32 effectiveBits);

		/// <summary>
		/// Class constructor.
		/// </summary>
		RC2_CBC_PARAMS(UInt32 effectiveBits, array<Byte>^ iv);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		RC2_CBC_PARAMS(RC2_CBC_PARAMS^ rc2_cbc_params);
	};

	/// <summary>
	/// This Class provides the parameters to the ECIES mechanism.
	/// </summary>
	public ref class ECIES_PARAMS
	{
	public:
		/// <summary>
		/// This enum class identifies a MAC scheme type
		/// <para>The 'sharedData1' and 'sharedData2' parameters are optional, and if not supplied then they must be NULL and the 'ulSharedDataLen1' and 'ulSharedDataLen2' parameters must be zero. With the MAC scheme SHA1, any supplied shared data is ignored.</para>
		/// <para>With the encryption scheme CKES_XOR, the 'ulEncKeyLenInBits' parameter MUST be zero. With any other encryption scheme, the 'ulEncKeyLenInBits' parameter must be set to the applicable key length in bits.</para>
		/// <para>With the MAC scheme SHA1, the 'macKeyLenInBits' parameter must be 0. With any other MAC scheme, the 'macKeyLenInBits' parameter must be a minimum of 80 bits, and a multiple of 8 bits.</para>
		/// <para>The 'macLenInBits' parameter must be a minimum of 80 bits, a multiple of 8 bits, and not greater than the maximum output length for the specified Hash.</para>
		/// </summary>
		enum class ECIES_PARAMS_MACScheme
		{
			HMAC_SHA1 = CKMS_HMAC_SHA1,
			SHA1 = CKMS_SHA1,
		};

		/// <summary>
		/// This is the Diffie-Hellman primitive used to derive the shared secret value. Valid value: CKDHP_STANDARD
		/// </summary>
		static const CK_EC_DH_PRIMITIVE dhPrimitive = CKDHP_STANDARD;

		/// <summary>
		/// This is the key derivation function used on the shared secret value. Valid value: CKD_SHA1_KDF
		/// </summary>
		static const CK_EC_KDF_TYPE kdf = CKD_SHA1_KDF;

		/// <summary>
		/// This is the key derivation padding data shared between the two parties.
		/// </summary>
		array<Byte>^ sharedData1;

		/// <summary>
		/// This is the encryption scheme used to transform the input data. Valid value: CKES_XOR
		/// </summary>
		static const CK_EC_ENC_SCHEME encScheme = CKES_XOR;

		/// <summary>
		/// This is the bit length of the key to use for the encryption scheme.
		/// </summary>
		UInt32 encKeyLenInBits;

		/// <summary>
		/// This is the MAC scheme used for MAC generation or validation. Valid values: CKMS_HMAC_SHA1, CKMS_SHA1
		/// <para>The MAC scheme CKMS_SHA1, should only be used for compatibility with RSA BSAFE® Crypto-C, which uses a NON-STANDARD MAC scheme, which was defined in the 10/97 X9.63 Draft, but was removed from the released ANSI X9.63-2001 specification.</para>
		/// </summary>
		ECIES_PARAMS_MACScheme macScheme;

		/// <summary>
		/// This is the bit length of the key to use for the MAC scheme.
		/// </summary>
		UInt32 macKeyLenInBits;

		/// <summary>
		/// This is the bit length of the MAC scheme output.
		/// </summary>
		UInt32 macLenInBits;

		/// <summary>
		/// This is the MAC padding data shared between the two parties.
		/// </summary>
		array<Byte>^ sharedData2;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		ECIES_PARAMS() {
			this->sharedData1 = this->sharedData2 = nullptr;
			this->encKeyLenInBits = this->macKeyLenInBits = this->macLenInBits = 0;
			this->macScheme = ECIES_PARAMS::ECIES_PARAMS_MACScheme::SHA1;
		};

		/// <summary>
		/// Class constructor.
		/// </summary>
		ECIES_PARAMS(array<Byte>^ sharedData1, UInt32 ulEncKeyLenInBits, ECIES_PARAMS_MACScheme macScheme, UInt32 macKeyLenInBits, UInt32 macLenInBits, array<Byte>^ sharedData2);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		ECIES_PARAMS(ECIES_PARAMS^ ecies_params);
	};

	/// <summary>
	/// This Class provides the parameters to the general-length MACing mechanisms of the DES, DES3(triple - DES), CAST, CAST3, CAST128 (CAST5), IDEA, CDMF and AES ciphers.
	/// <para>It also provides the parameters to the general length HMACing mechanisms(i.e. MD2, MD5, SHA-1, SHA-256, SHA-384, SHA-512, RIPEMD-128 and RIPEMD-160) and the two SSL 3.0 MACing mechanisms(i.e. MD5 and SHA-1).</para>
	/// </summary>
	public ref class MAC_GENERAL_PARAMS
	{
	public:
		/// <summary>
		/// The length of the MAC that this mechanism will produce.
		/// </summary>
		UInt32 lengthOfMAC;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		MAC_GENERAL_PARAMS() { this->lengthOfMAC = 0; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		MAC_GENERAL_PARAMS(UInt32 lengthOfMAC);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		MAC_GENERAL_PARAMS(MAC_GENERAL_PARAMS^ mac_general_params);
	};

	/// <summary>
	/// This Class provides the parameters to the the RC2_MAC_GENERAL mechanism.
	/// </summary>
	public ref class RC2_MAC_GENERAL_PARAMS
	{
	public:
		/// <summary>
		/// The effective number of bits in the RC2 search space.
		/// </summary>
		UInt32 effectiveBits;

		/// <summary>
		/// The length of the MAC produced, in bytes.
		/// </summary>
		UInt32 macLength;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		RC2_MAC_GENERAL_PARAMS() { this->macLength = this->effectiveBits = 0; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		RC2_MAC_GENERAL_PARAMS(UInt32 effectiveBits, UInt32 macLength);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		RC2_MAC_GENERAL_PARAMS(RC2_MAC_GENERAL_PARAMS^ rc2_mac_general_params);
	};

	/// <summary>
	/// This Class provides the parameters to the the RSA_PKCS_PSS mechanism.
	/// </summary>
	public ref class RSA_PKCS_PSS_PARAMS
	{
	public:
		/// <summary>
		/// RSA_PKCS_MGF_TYPE is used to indicate the Message Generation Function (MGF) applied to a message block when formatting a message block for the PKCS #1 OAEP encryption scheme or the PKCS #1 PSS signature scheme.
		/// </summary>
		enum class RSA_PKCS_MGF_TYPE
		{
			MGF1_SHA1 = CKG_MGF1_SHA1,
			//MGF1_SHA256 = CKG_MGF1_SHA256,
			//MGF1_SHA384 = CKG_MGF1_SHA384,
			//MGF1_SHA512 = CKG_MGF1_SHA512,
		};

		/// <summary>
		/// Hash algorithm used in the PSS encoding;
		/// <para>If the signature mechanism does not include message hashing, then this value must be the mechanism used by the application to generate the message hash;</para>
		/// <para>If the signature mechanism includes hashing, then this value must match the hash algorithm indicated by the signature mechanism.</para>
		/// </summary>
		DigestMechanism hashAlg;

		/// <summary>
		/// Mask generation function to use on the encoded block.
		/// </summary>
		RSA_PKCS_MGF_TYPE mgf;

		/// <summary>
		/// Length, in bytes, of the salt value used in the PSS encoding; typical values are the length of the message hash and zero.
		/// </summary>
		UInt32 sLen;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		RSA_PKCS_PSS_PARAMS() { this->hashAlg = DigestMechanism::SHA_1; this->mgf = RSA_PKCS_MGF_TYPE::MGF1_SHA1; this->sLen = 0; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		RSA_PKCS_PSS_PARAMS(DigestMechanism hashAlg, UInt32 sLen);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		RSA_PKCS_PSS_PARAMS(RSA_PKCS_PSS_PARAMS^ rsa_pkcs_pss_params);
	};

	/// <summary>
	/// This Class provides all of the necessary information required by the CKM_PBE mechanisms (see PKCS #5 and PKCS #12 for information on the PBE generation mechanisms).
	/// </summary>
	public ref class PBE_PARAMS
	{
	public:
		/// <summary>
		/// 8-byte initialization vector(IV), if an IV is required.
		/// </summary>
		array<Byte>^ initVector;

		/// <summary>
		/// The password to be used in the PBE key generation.
		/// </summary>
		String^ password;

		/// <summary>
		/// The salt to be used in the PBE key generation.
		/// </summary>
		array<Byte>^ salt;

		/// <summary>
		/// Number of iterations required for the generation
		/// </summary>
		UInt32 iteration;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		PBE_PARAMS() { this->initVector = gcnew array<Byte>(8); this->password = String::Empty; this->salt = nullptr; this->iteration = 0; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		PBE_PARAMS(array<Byte>^ initVector, String^ password, array<Byte>^ salt, UInt32 iteration);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		PBE_PARAMS(PBE_PARAMS^ pbe_params);
	};

	/// <summary>
	/// This Class provides all of the necessary information required by the PP_LOAD_SECRET mechanism.
	/// </summary>
	public ref class PP_LOAD_SECRET_PARAMS
	{
	public:
		/// <summary>
		/// Entered characters should be masked with '*' or similar to hide the value being entered. An error is returned if this is TRUE and the device does not support this feature.
		/// </summary>
		Boolean maskInput;

		/// <summary>
		/// Entered characters should be converted from the ASCII representation to binary before being stored, according to the conversion type supplied.
		/// <para>If the device does not support the specified type of input (e.g. hex input on a decimal keyboard), an error is returned.</para>
		/// <para>The octal and decimal representations will expect 3 digits per byte, whereas the hexadecimal representations will expect 2 digits per byte.</para>
		/// <para>An error is returned if the data contains invalid encoding (such as 351 for decimal conversion).</para>
		/// </summary>
		Char convert;

		/// <summary>
		/// The time to wait for operator response - in seconds. An error is returned if the operation does not complete in the specified time.
		/// <para>This field may be ignored if the device does not support a configurable timeout.</para>
		/// </summary>
		UInt16 timeout;

		/// <summary>
		/// Reserved for future extensions. Must be set to zero.
		/// </summary>
		static const UInt16 reserved = 0;

		/// <summary>
		/// The prompt to be displayed on the device. If the prompt cannot fit on the device display, the output is clipped.
		/// <para>If the device does not have any display, the operation will continue without any prompt, or error.</para>
		/// <para>The following special characters are recognized on the display: * - Newline (0x0a): Continue the display on the next line.</para>
		/// </summary>
		String^ prompt;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		PP_LOAD_SECRET_PARAMS() { this->maskInput = false; this->convert = (Char)0; this->timeout = 0; this->prompt = String::Empty; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		PP_LOAD_SECRET_PARAMS(Boolean maskInput, Char convert, UInt16 timeout, String^ prompt);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		PP_LOAD_SECRET_PARAMS(PP_LOAD_SECRET_PARAMS^ pp_load_secret_params);
	};

	/// <summary>
	/// This Class provides the parameters to the KEY_WRAP_SET_OAEP mechanism.
	/// </summary>
	public ref class KEY_WRAP_SET_OAEP_PARAMS
	{
	public:
		/// <summary>
		/// Block contents byte.
		/// </summary>
		Byte BC;

		/// <summary>
		/// Concatenation of hash of plain-text data (if present) and extra data(if present). 'nullptr' if neither is present
		/// </summary>
		array<Byte>^ X;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		KEY_WRAP_SET_OAEP_PARAMS() { this->BC = (Byte)0; this->X = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		KEY_WRAP_SET_OAEP_PARAMS(Byte BC, array<Byte>^ X);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		KEY_WRAP_SET_OAEP_PARAMS(KEY_WRAP_SET_OAEP_PARAMS^ key_wrap_set_oaep_params);
	};

	/// <summary>
	/// This Class provides the parameters to the RC2_CBC and RC2_CBC_PAD mechanisms.
	/// </summary>
	public ref class KEY_DERIVATION_STRING_DATA
	{
	public:
		/// <summary>
		/// The byte string.
		/// </summary>
		array<Byte>^ data;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		KEY_DERIVATION_STRING_DATA() { this->data = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		KEY_DERIVATION_STRING_DATA(array<Byte>^ data);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		KEY_DERIVATION_STRING_DATA(KEY_DERIVATION_STRING_DATA^ key_derivation_string_data);
	};

	/// <summary>
	/// This Class provides the parameter to the EXTRACT_KEY_FROM_KEY mechanism.
	/// </summary>
	public ref class EXTRACT_PARAMS
	{
	public:
		/// <summary>
		/// It specifies which bit of the base key should be used as the first bit of the derived key.
		/// </summary>
		UInt32 bits;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		EXTRACT_PARAMS() { this->bits = 0; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		EXTRACT_PARAMS(UInt32 bits);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		EXTRACT_PARAMS(EXTRACT_PARAMS^ extract_params);
	};

	/// <summary>
	/// This Class provides information about the random data of a client and a server in an SSL context.
	/// <para>This structure is used by both the SSL3_MASTER_KEY_DERIVE and the SSL3_KEY_AND_MAC_DERIVE mechanisms.</para>
	/// </summary>
	public ref class SSL3_RANDOM_DATA
	{
	public:
		/// <summary>
		/// Client's random data
		/// </summary>
		array<Byte>^ clientRandom;

		/// <summary>
		/// Server's random data
		/// </summary>
		array<Byte>^ serverRandom;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		SSL3_RANDOM_DATA() { this->clientRandom = this->serverRandom = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		SSL3_RANDOM_DATA(array<Byte>^ clientRandom, array<Byte>^ serverRandom);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		SSL3_RANDOM_DATA(SSL3_RANDOM_DATA^ ssl3_random_data);
	};

	/// <summary>
	/// This Class provides the parameters to the SSL3_MASTER_KEY_DERIVE mechanism.
	/// </summary>
	public ref class SSL3_MASTER_KEY_DERIVE_PARAMS
	{
	public:
		/// <summary>
		/// Client's and Server's random data information.
		/// </summary>
		SSL3_RANDOM_DATA^ randomInfo;

		/// <summary>
		/// CVersion structure which receives the SSL protocol version information.
		/// </summary>
		CVersion^ version;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		SSL3_MASTER_KEY_DERIVE_PARAMS() { this->randomInfo = nullptr; this->version = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		SSL3_MASTER_KEY_DERIVE_PARAMS(SSL3_RANDOM_DATA^ randomInfo, CVersion^ version);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		SSL3_MASTER_KEY_DERIVE_PARAMS(SSL3_MASTER_KEY_DERIVE_PARAMS^ ssl3_master_key_derive_params);
	};

	/// <summary>
	/// This Class provides the parameters to the ECDH1_DERIVE mechanism.
	/// <para>The mechanism calculates an agreed value using the EC Private key referenced by the base object handle and the EC Public key passed to the mechanism through the pPublicData field of the mechanism parameter.</para>
	/// <para>The length of the agreed value is equal to the 'q' value of the underlying EC curve.</para>
	/// <para>The agreed value is then processed by the Key Derive Function (kdf) to produce the VALUE of the new Secret Key object.</para>
	/// </summary>
	public ref class ECDH1_DERIVE_PARAMS
	{
	public:
		/// <summary>
		/// The Key Derivation Function.
		/// </summary>
		enum class SES_CTR
		{
			/// <summary>
			/// Default encryption Key
			/// </summary>
			SES_ENC_CTR = CKD_SES_ENC_CTR,

			/// <summary>
			/// Default authentication Key
			/// </summary>
			SES_AUTH_CTR = CKD_SES_AUTH_CTR,

			/// <summary>
			/// Alternate encryption Key
			/// </summary>
			SES_ALT_ENC_CTR = CKD_SES_ALT_ENC_CTR,

			/// <summary>
			/// Alternate Authentication Key
			/// </summary>
			SES_ALT_AUTH_CTR = CKD_SES_ALT_AUTH_CTR,

			/// <summary>
			/// Maximum counter value
			/// </summary>
			SES_MAX_CTR = CKD_SES_MAX_CTR,
		};

		/// <summary>
		/// The Key Derivation Function.
		/// </summary>
		enum class EC_KDF_TYPE
		{
			/// <summary>
			/// The null transformation.The derived key value is produced by taking bytes from the left of the agreed value.The new key size is limited to the size of the agreed value.
			/// <para>The Shared Data is not used by this KDF and sharedData should be nullptr.</para>
			/// </summary>
			NULL_KDF = CKD_NULL,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in X9.63 with the SHA-1 hash algorithm.
			/// <para>Shared data may be provided.</para>
			/// </summary>
			SHA1_KDF = CKD_SHA1_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in X9.63 with the SHA-224 hash algorithm.
			/// <para>Shared data may be provided.</para>
			/// </summary>
			SHA224_KDF = CKD_SHA224_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in X9.63 with the SHA-256 hash algorithm.
			/// <para>Shared data may be provided.</para>
			/// </summary>
			SHA256_KDF = CKD_SHA256_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in X9.63 with the SHA-384 hash algorithm.
			/// <para>Shared data may be provided.</para>
			/// </summary>
			SHA384_KDF = CKD_SHA384_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in X9.63 with the SHA-512 hash algorithm.
			/// <para>Shared data may be provided.</para>
			/// </summary>
			SHA512_KDF = CKD_SHA512_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in X9.63 with the RIPE MD 160 hash algorithm.
			/// <para>Shared data may be provided.</para>
			/// <para>This KDF is not available if the HSM is configured for "Only allow Fips Approved Algorithms".</para>
			/// </summary>
			RIPEMD160_KDF = CKD_RIPEMD160_KDF,

			/// <summary>
			/// This KDF generates session keys. It uses the algorithm described in TR-03111 with the SHA-1 hash algorithm.
			/// <para>Shared data may be provided but typically it is not used.</para>
			/// <para>The counter value that is a parameter to this KDF must be added to this constant.</para>
			/// </summary>
			SHA1_SES_KDF = CKD_SHA1_SES_KDF,

			/// <summary>
			/// This KDF generates single, double and triple length DES keys that are intended for Encryption operations. It uses the algorithm described in TR-03111 with the SHA-224 hash algorithm.
			/// <para>Shared data may be provided but typically it is not used.</para>
			/// <para>The counter value that is a parameter to this KDF must be added to this constant.</para>
			/// </summary>
			SHA224_SES_KDF = CKD_SHA224_SES_KDF,

			/// <summary>
			/// This KDF generates single, double and triple length DES keys that are intended for Encryption operations. It uses the algorithm described in TR-03111 with the SHA-256 hash algorithm.
			/// <para>Shared data may be provided but typically it is not used.</para>
			/// <para>The counter value that is a parameter to this KDF must be added to this constant.</para>
			/// </summary>
			SHA256_SES_KDF = CKD_SHA256_SES_KDF,

			/// <summary>
			/// This KDF generates single, double and triple length DES keys that are intended for Encryption operations. It uses the algorithm described in TR-03111 with the SHA-384 hash algorithm.
			/// <para>Shared data may be provided but typically it is not used.</para>
			/// <para>The counter value that is a parameter to this KDF must be added to this constant.</para>
			/// </summary>
			SHA384_SES_KDF = CKD_SHA384_SES_KDF,

			/// <summary>
			/// This KDF generates single, double and triple length DES keys that are intended for Encryption operations. It uses the algorithm described in TR-03111 with the SHA-512 hash algorithm.
			/// <para>Shared data may be provided but typically it is not used.</para>
			/// <para>The counter value that is a parameter to this KDF must be added to this constant.</para>
			/// </summary>
			SHA512_SES_KDF = CKD_SHA512_SES_KDF,

			/// <summary>
			/// This KDF generates single, double and triple length DES keys that are intended for Encryption operations. It uses the algorithm described in TR-03111 with the Ripe MD 160 hash algorithm.
			/// <para>Shared data may be provided but typically it is not used.</para>
			/// <para>The counter value that is a parameter to this KDF must be added to this constant.</para>
			/// <para>This KDF is not available if the HSM is configured for "Only allow Fips Approved Algorithms".</para>
			/// </summary>
			RIPEMD160_SES_KDF = CKD_RIPEMD160_SES_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in NIST 800-56A with the SHA-1 hash algorithm.
			/// <para>Shared data should be formatted according to the standard.</para>
			/// </summary>
			SHA1_NIST_KDF = CKD_SHA1_NIST_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in NIST 800-56A with the SHA-224 hash algorithm.
			/// <para>Shared data should be formatted according to the standard.</para>
			/// </summary>
			SHA224_NIST_KDF = CKD_SHA224_NIST_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in NIST 800-56A with the SHA-256 hash algorithm.
			/// <para>Shared data should be formatted according to the standard.</para>
			/// </summary>
			SHA256_NIST_KDF = CKD_SHA256_NIST_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in NIST 800-56A with the SHA-384 hash algorithm.
			/// <para>Shared data should be formatted according to the standard.</para>
			/// </summary>
			SHA384_NIST_KDF = CKD_SHA384_NIST_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in NIST 800-56A with the SHA-512 hash algorithm.
			/// <para>Shared data should be formatted according to the standard.</para>
			/// </summary>
			SHA512_NIST_KDF = CKD_SHA512_NIST_KDF,

			/// <summary>
			/// This KDF generates secret keys of virtually any length using the algorithm described in NIST 800-56A with the RIPE MD 160 hash algorithm.
			/// <para>Shared data should be formatted according to the standard.</para>
			/// <para>This KDF is not available if the HSM is configured for "Only allow Fips Approved Algorithms".</para>
			/// </summary>
			RIPEMD160_NIST_KDF = CKD_RIPEMD160_NIST_KDF,
		};

		/// <summary>
		/// The Key Derivation Function.
		/// <para>To derive a session key to be used as an Alternate key for Encryption the counter must equal 0x00000003.</para>
		/// <para>If the SHA-1 hash algorithm is required then the kdf value would be set like this: Params.kdf = SHA1_SES_KDF + SES_ALT_ENC_CTR</para>
		/// <para>Four main types of KDFs are supported:</para>
		/// <para>- The NULL KDF performs no additional processing and can be used to obtain the raw agreed value. Basically: Key = Z</para>
		/// <para>- The 'hash'_KDF algorithms are based on the algorithm described in section 5.6.3 of ANSI X9.63 2001. Basically: Key = H(Z || counter || OtherInfo)</para>
		/// <para>- The 'hash'_SES_KDF algorithms are based on the variant of the x9.63 algorithm specified in Technical Guideline TR-03111 - Elliptic Curve Cryptography (ECC) based on ISO 15946 Version 1.0, Bundesamt Fur Sicherheit in der Informationstechnik (BSI). Basically: Key = H(Z || counter) where counter is a user specified parameter</para>
		/// <para>- The 'hash'_NIST_KDF algorithms are based on the algorithm described in NIST 800-56A Concatenisation Algorithm. Basically: Key = H(counter || Z || OtherInfo)</para>
		/// <para>The SES_'hash'_KDF algorithms require the value of the counter to be specified. This is done by arithmetically adding the counter value to the CKF value.</para>
		/// </summary>
		UInt32 kdf;

		/// <summary>
		/// Optional extra shared data. It's NULL if there is no shared data.
		/// <para>- With the key derivation function CKD_NULL, 'haredData' must be NULL.</para>
		/// <para>- With the key derivation function CKD_SHA1_KDF, an optional 'haredData' may be supplied, which consists of some data shared by the two parties intending to share the shared secret.</para>
		/// <para>- Otherwise, 'sharedData' must be NULL.</para>
		/// </summary>
		array<Byte>^ sharedData;

		/// <summary>
		/// Other party public key value. Only uncompressed format is accepted.
		/// <para>The encoding in V2.20 was not specified and resulted in different implementations choosing different encodings.</para>
		/// <para>Applications relying only on a V2.20 encoding (e.g. the DER variant) other than the one specified now (raw) may not work with all V2.30 compliant tokens.</para>
		/// <para>A token MUST be able to accept this value encoded as a raw octet string (as per section A.5.2 of [ANSI X9.62]).</para>
		/// <para>A token MAY, in addition, support accepting this value as a DER-encoded ECPoint (as per section E.6 of [ANSI X9.62]) i.e. the same as a CKA_EC_POINT encoding.</para>
		/// <para>The calling application is responsible for converting the offered public key to the compressed or uncompressed forms of these encodings if the token does not support the offered form.</para>
		/// </summary>
		array<Byte>^ publicData;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		ECDH1_DERIVE_PARAMS() { this->sharedData = this->publicData = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		ECDH1_DERIVE_PARAMS(UInt32 kdf, array<Byte>^ sharedData, array<Byte>^ publicData);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		ECDH1_DERIVE_PARAMS(ECDH1_DERIVE_PARAMS^ ecdh1_derive_params);
	};

	/// <summary>
	/// This Class provides the parameters to the DES_DERIVE_CBC mechanisms.
	/// </summary>
	public ref class DES_DERIVE_CBC_PARAMS
	{
	public:
		/// <summary>
		/// The initialization verctor.
		/// </summary>
		array<Byte>^ iv;

		/// <summary>
		/// The data to be encrypted.
		/// </summary>
		array<Byte>^ data;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		DES_DERIVE_CBC_PARAMS() { this->iv = this->data = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		DES_DERIVE_CBC_PARAMS(array<Byte>^ iv, array<Byte>^ data);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		DES_DERIVE_CBC_PARAMS(DES_DERIVE_CBC_PARAMS^ des_derive_cbc_params);
	};

	/// <summary>
	/// This Class provides the parameters to the DES3_DERIVE_CBC mechanisms.
	/// </summary>
	public ref class DES3_DERIVE_CBC_PARAMS
	{
	public:
		/// <summary>
		/// The initialization verctor.
		/// </summary>
		array<Byte>^ iv;

		/// <summary>
		/// The data to be encrypted.
		/// </summary>
		array<Byte>^ data;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		DES3_DERIVE_CBC_PARAMS() { this->iv = this->data = nullptr; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		DES3_DERIVE_CBC_PARAMS(array<Byte>^ iv, array<Byte>^ data);

		/// <summary>
		/// Copy constructor.
		/// </summary>
		DES3_DERIVE_CBC_PARAMS(DES3_DERIVE_CBC_PARAMS^ des3_derive_cbc_params);
	};

	/// <summary>
	/// This Class provides the parameters to the DES3_DERIVE_CBC mechanisms.
	/// </summary>
	public ref class SECRET_SHARE_PARAMS
	{
	public:
		/// <summary>
		/// Total number of shares. Must be at least two and not greater than sixty four.
		/// </summary>
		UInt32 m;

		/// <summary>
		/// Number of shares required to recover the secret. Must be at least two and not greater than the number of shares m.
		/// </summary>
		UInt32 n;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		SECRET_SHARE_PARAMS() { this->m = this->n = 0; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		SECRET_SHARE_PARAMS(UInt32 m, UInt32 n) { this->m = m; this->n = n; };

		/// <summary>
		/// Copy constructor.
		/// </summary>
		SECRET_SHARE_PARAMS(SECRET_SHARE_PARAMS^ secret_share_params) { this->m = secret_share_params->m; this->n = secret_share_params->n; };
	};

	/// <summary>
	/// This Class provides the parameters to the SHA1_RSA_PKCS_TIMESTAMP mechanisms.
	/// </summary>
	public ref class TIMESTAMP_PARAMS
	{
	public:
		/// <summary>
		/// This parameter specifies whether the timestamp should include millisecond granularity.
		/// <para> The default value for this parameter is FALSE. If the mechanism parameters are specified then the useMilliseconds parameter must be set to FALSE as only one-second granularity is provided in the first release of the mechanism‘s implementation.</para>
		/// </summary>
		Boolean useMilliseconds;

		/// <summary>
		/// This parameter specifies the input/output format of the data to be timestamped.
		/// <para>This provides the ability to introduce future support for time-stamping protocols such as those defined in RFC3161. The default value for this parameter is TIMESTAMP_FORMAT_PTKC.</para>
		/// </summary>
		static const UInt32 timestampFormat = CK_TIMESTAMP_FORMAT_PTKC;

		/// <summary>
		/// Default Class constructor.
		/// </summary>
		TIMESTAMP_PARAMS() { this->useMilliseconds = false; };

		/// <summary>
		/// Class constructor.
		/// </summary>
		TIMESTAMP_PARAMS(Boolean useMilliseconds) { this->useMilliseconds = useMilliseconds; };

		/// <summary>
		/// Copy constructor.
		/// </summary>
		TIMESTAMP_PARAMS(TIMESTAMP_PARAMS^ timestamp_params) { this->useMilliseconds = timestamp_params->useMilliseconds; };
	};
}
