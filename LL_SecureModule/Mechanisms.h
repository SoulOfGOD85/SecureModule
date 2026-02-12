#pragma once

using namespace System;

namespace LL_SecureModule
{
	/// <summary>
	/// Type of digesting mechanism.
	/// </summary>
	public enum class DigestMechanism
	{
		/// <summary>
		/// The MD2 mechanism, is a mechanism for message digesting, following the MD2 message-digest algorithm defined in RFC 1319.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 16 byte.</para>
		/// </summary>
		MD2 = CKM_MD2,

		/// <summary>
		/// The MD5 mechanism, is a mechanism for message digesting, following the MD5 message-digest algorithm defined in RFC 1321.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 16 byte.</para>
		/// </summary>
		MD5 = CKM_MD5,

		/// <summary>
		/// The SHA-1 mechanism (denoted SHA_1), is a mechanism for message digesting, following the Secure Hash Algorithm with a 160-bit message digest defined in FIPS PUB 180-2.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 20 byte.</para>
		/// </summary>
		SHA_1 = CKM_SHA_1,

		/// <summary>
		/// The SHA-224 mechanism (denoted SHA224), is a mechanism for message digesting, following the Secure Hash Algorithm with a 224-bit message digest defined in FIPS PUB 180-2.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 28 byte.</para>
		/// </summary>
		SHA224 = CKM_SHA224,

		/// <summary>
		/// The SHA-256 mechanism (denoted SHA256), is a mechanism for message digesting, following the Secure Hash Algorithm with a 256-bit message digest defined in FIPS PUB 180-2.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 32 byte.</para>
		/// </summary>
		SHA256 = CKM_SHA256,

		/// <summary>
		/// The SHA-384 mechanism (denoted SHA384), is a mechanism for message digesting, following the Secure Hash Algorithm with a 384-bit message digest defined in FIPS PUB 180-2.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 48 byte.</para>
		/// </summary>
		SHA384 = CKM_SHA384,

		/// <summary>
		/// The SHA-512 mechanism (denoted SHA512), is a mechanism for message digesting, following the Secure Hash Algorithm with a 512-bit message digest defined in FIPS PUB 180-2.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 64 byte.</para>
		/// </summary>
		SHA512 = CKM_SHA512,

		/// <summary>
		/// The RIPE-MD 128 mechanism (denoted RIPEMD128), is a mechanism for message digesting, following the RIPE-MD 128 message-digest algorithm.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 16 byte.</para>
		/// </summary>
		RIPEMD128 = CKM_RIPEMD128,

		/// <summary>
		/// The RIPE-MD 160 mechanism (denoted RIPEMD160), is a mechanism for message digesting, following the RIPE-MD 160 message-digest algorithm defined in ISO-10118.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 20 byte.</para>
		/// </summary>
		RIPEMD160 = CKM_RIPEMD160,

		/// <summary>
		/// The FASTHASH mechanism, is a mechanism for message digesting, following the U.S. government's algorithm.
		/// <para>It does not have a parameter.</para>
		/// <para>Digest length = 40 byte.</para>
		/// </summary>
		FASTHASH = CKM_FASTHASH,

		///
		/// There are a number of additional SafeNet vendor defined digest mechanism types.
		///

		/// <summary>
		/// This mechanism is a SafeNet vendor defined hash function as defined in ISO/IEC DIS 10118-2 using DES as block algorithm.
		/// <para>This mechanism implements padding in accordance with ISO 10118-1 Method 1.</para>
		/// <para>Basically, zeros are used to pad the input data to a multiple of eight if required. If the input data is already a multiple of eight, then no padding is added.</para>
		/// <para>This mechanism is SafeNet proprietary.</para>
		/// </summary>
		DES_MDC_2_PAD1 = (int)CKM_DES_MDC_2_PAD1,
	};

	/// <summary>
	/// Type of encrypt/decrypt mechanism.
	/// <para>If the mechanism in use is a multi-part mechanism and the data supplied exceeds a single block, that portion of the data is processed regardless of the result returned by the call. For example if 12 bytes are passed to a DES ECB operation, 8 bytes are processed even though an error result (due to the padding requirements not being met) is returned.</para>
	/// </summary>
	public enum class EncryptionMechanism
	{
		/// <summary>
		/// ...
		/// <para>...</para>
		/// </summary>
		ARIA_ECB = CKM_ARIA_ECB,

		/// <summary>
		/// ...
		/// <para>...</para>
		/// </summary>
		ARIA_CBC = CKM_ARIA_CBC,

		/// <summary>
		/// ...
		/// <para>...</para>
		/// </summary>
		ARIA_CBC_PAD = CKM_ARIA_CBC_PAD,

		/// <summary>
		/// AES-ECB (denoted AES_ECB), is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on NIST Advanced Encryption Standard and electronic codebook mode.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the 'VALUE' attribute of the key that is wrapped, padded on the trailing end with up to block size minus one null bytes so that the resulting length is a multiple of the block size.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the 'KEY_TYPE' attribute of the template and, if it has one, and the key type supports it, the 'VALUE_LEN' attribute of the template.</para>
		/// <para>The mechanism contributes the result as the 'VALUE' attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: AES] - [Input length: multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: AES] - [Input length: Any] - [Output length: input length rounded up to multiple of block size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_ECB = CKM_AES_ECB,

		/// <summary>
		/// AES-CBC (denoted AES_CBC), is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on NIST's Advanced Encryption Standard and cipher-block chaining mode.
		/// <para>It has a parameter, a 16 - byte initialization vector.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the 'VALUE' attribute of the key that is wrapped, padded on the trailing end with up to block size minus one null bytes so that the resulting length is a multiple of the block size.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the 'KEY_TYPE' attribute of the template and, if it has one, and the key type supports it, the 'VALUE_LEN' attribute of the template.</para>
		/// <para>The mechanism contributes the result as the 'VALUE' attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: AES] - [Input length: multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: AES] - [Input length: Any] - [Output length: input length rounded up to multiple of block size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_CBC = CKM_AES_CBC,

		/// <summary>
		/// AES-CBC with PKCS padding (denoted AES_CBC_PAD), is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on NIST's Advanced Encryption Standard; cipher-block chaining mode; and the block cipher padding method detailed in PKCS #7.
		/// <para>It has a parameter, a 16-byte initialization vector.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the 'VALUE_LEN' attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: AES] - [Input length: Any] - [Output length: input length rounded up to multiple of the block size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: between 1 and block size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: AES] - [Input length: Any] - [Output length: input length rounded up to multiple of the block size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: between 1 and block size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_CBC_PAD = CKM_AES_CBC_PAD,

		/// <summary>
		/// Cipher CAST128 has an electronic codebook mechanism, CAST128-ECB, denoted CAST128_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST128.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of CAST128's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST128_ECB = CKM_CAST128_ECB,

		/// <summary>
		/// Cipher CAST5 has an electronic codebook mechanism, CAST5-ECB, denoted CAST5_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST5.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of CAST5's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST5_ECB = CKM_CAST5_ECB,

		/// <summary>
		/// Cipher CAST128 has a cipher-block chaining mode, CAST128-CBC, denoted CAST128_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST128.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as CAST128's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes. For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST128_CBC = CKM_CAST128_CBC,

		/// <summary>
		/// Cipher CAST5 has a cipher-block chaining mode, CAST5-CBC, denoted CAST5_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST5.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as CAST5's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes. For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST5_CBC = CKM_CAST5_CBC,

		/// <summary>
		/// Cipher CAST128 has a cipher-block chaining mode with PKCS padding, CAST128-CBC with PKCS padding, denoted CAST128_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST128.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as CAST128's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST128_CBC_PAD = CKM_CAST128_CBC_PAD,

		/// <summary>
		/// Cipher CAST5 has a cipher-block chaining mode with PKCS padding, CAST5-CBC with PKCS padding, denoted CAST5_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST5.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as CAST5's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST5_CBC_PAD = CKM_CAST5_CBC_PAD,

		/// <summary>
		/// Cipher DES has an electronic codebook mechanism, DES-ECB, denoted DES_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of DES's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES_ECB = CKM_DES_ECB,

		/// <summary>
		/// Cipher DES has a cipher-block chaining mode, DES-CBC, denoted DES_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes. For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES_CBC = CKM_DES_CBC,

		/// <summary>
		/// Cipher DES has a cipher-block chaining mode with PKCS padding, DES-CBC with PKCS padding, denoted DES_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES_CBC_PAD = CKM_DES_CBC_PAD,

		/// <summary>
		/// Cipher DES3 has an electronic codebook mechanism, DES3-ECB, denoted DES3_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES3.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of DES3's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES3_ECB = CKM_DES3_ECB,

		/// <summary>
		/// Cipher DES3 has a cipher-block chaining mode, DES3-CBC, denoted DES3_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES3.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES3's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes. For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES3_CBC = CKM_DES3_CBC,

		/// <summary>
		/// Cipher DES3 has a cipher-block chaining mode with PKCS padding, DES3-CBC with PKCS padding, denoted DES3_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES3.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES3's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES3] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES3_CBC_PAD = CKM_DES3_CBC_PAD,

		/// <summary>
		/// Cipher IDEA has an electronic codebook mechanism, IDEA-ECB, denoted IDEA_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with IDEA.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of IDEA's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		IDEA_ECB = CKM_IDEA_ECB,

		/// <summary>
		/// Cipher IDEA has a cipher-block chaining mode, IDEA-CBC, denoted IDEA_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with IDEA.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as IDEA's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		IDEA_CBC = CKM_IDEA_CBC,

		/// <summary>
		/// Cipher IDEA has a cipher-block chaining mode with PKCS padding, IDEA-CBC with PKCS padding, denoted IDEA_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with IDEA.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as IDEA's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		IDEA_CBC_PAD = CKM_IDEA_CBC_PAD,

		/// <summary>
		/// RC2-ECB, denoted RC2_ECB, is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on RSA Security's block cipher RC2 and electronic codebook mode as defined in FIPS PUB 81.
		/// <para>It has a parameter, a RC2_PARAMS, which indicates the effective number of bits in the RC2 search space.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with up to seven null bytes so that the resulting length is a multiple of eight.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RC2] - [Input length: Any] - [Output length: input length rounded up to multiple of 8] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 effective number of bits.</para>
		/// </summary>
		RC2_ECB = CKM_RC2_ECB,

		/// <summary>
		/// RC2-CBC, denoted RC2_CBC, is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on RSA Security's block cipher RC2 and cipher-block chaining mode as defined in FIPS PUB 81.
		/// <para>It has a parameter, a RC2_CBC_PARAMS structure, where the first field indicates the effective number of bits in the RC2 search space, and the next field is the initialization vector for cipher block chaining mode.</para>
		/// <para>This mechanism can wrap and unwrap any secret key.</para>
		/// <para>Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with up to seven null bytes so that the resulting length is a multiple of eight.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RC2] - [Input length: Any] - [Output length: input length rounded up to multiple of 8] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 effective number of bits.</para>
		/// </summary>
		RC2_CBC = CKM_RC2_CBC,

		/// <summary>
		/// RC2-CBC with PKCS padding, denoted RC2_CBC_PAD, is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on RSA Security's block cipher RC2; cipher-block chaining mode as defined in FIPS PUB 81; and the block cipher padding method detailed in PKCS #7.
		/// <para>It has a parameter, a RC2_CBC_PARAMS structure, where the first field indicates the effective number of bits in the RC2 search space, and the next field is the initialization vector.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys. The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RC2] - [Input length: Any] - [Output length: input length rounded up to multiple of 8]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: between 1 and 8 bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RC2] - [Input length: Any] - [Output length: input length rounded up to multiple of 8]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: between 1 and 8 bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 effective number of bits.</para>
		/// </summary>
		RC2_CBC_PAD = CKM_RC2_CBC_PAD,

		/// <summary>
		/// RC4, denoted RC4, is a mechanism for single- and multiple-part encryption and decryption based on RSA Security's proprietary stream cipher RC4.
		/// <para>It does not have a parameter.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RC4] - [Input length: Any] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RC4] - [Input length: Any] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC4 key sizes, in bits.</para>
		/// </summary>
		RC4 = CKM_RC4,

		/// <summary>
		/// The PKCS #1 v1.5 RSA mechanism (denoted RSA_PKCS), is a multi-purpose mechanism based on the RSA public-key crypto-system and the block formats initially defined in PKCS #1 v1.5.
		/// <para>It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping.</para>
		/// <para>This mechanism corresponds only to the part of PKCS #1 v1.5 that involves RSA; it does not compute a message digest or a DigestInfo encoding as specified for the 'md2withRSAEncryption' and 'md5withRSAEncryption' algorithms in PKCS #1 v1.5.</para>
		/// <para>This mechanism can wrap and unwrap any secret key of appropriate length.</para>
		/// <para>Of course, a particular token may not be able to wrap/unwrap every appropriate-length secret key that it supports.</para>
		/// <para>For wrapping, the "input" to the encryption operation is the value of the 'VALUE' attribute of the key that is wrapped; similarly for unwrapping.</para>
		/// <para>The mechanism does not wrap the key type or any other information about the key, except the key length; the application must convey these separately.</para>
		/// <para>In particular, the mechanism contributes only the 'CLASS' and 'VALUE' (and 'VALUE_LEN', if the key has it) attributes to the recovered key during unwrapping; other attributes must be specified in the template.</para>
		/// <para>Constraints on key types and the length of the data are summarized in the following table.</para>
		/// <para>For encryption, decryption, signatures and signature verification, the input and output data may begin at the same location in memory. In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RSA public key] - [Data Length: ≤k-11] - [Signature Length: k] - [Comments: block type 02]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RSA private key] - [Data Length: k] - [Signature Length: ≤k-11] - [Comments: block type 02]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RSA public key] - [Data Length: ≤k-11] - [Signature Length: k] - [Comments: block type 02]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RSA private key] - [Data Length: k] - [Signature Length: ≤k-11] - [Comments: block type 02]</para>
		/// </summary>
		RSA_PKCS = CKM_RSA_PKCS,

		/// <summary>
		/// The PKCS #1 RSA OAEP mechanism (denoted RSA_PKCS_OAEP), is a multi-purpose mechanism based on the RSA public-key crypto-system and the OAEP block format defined in PKCS #1. It supports single-part encryption and decryption; key wrapping; and key unwrapping.
		/// <para>It has a parameter, a RSA_PKCS_OAEP_PARAMS structure.</para>
		/// <para>It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping. This mechanism corresponds only to the part of PKCS #1 v1.5 that involves RSA; it does not compute a message digest or a DigestInfo encoding as specified for the md2withRSAEncryption and md5withRSAEncryption algorithms in PKCS #1 v1.5.</para>
		/// <para>This mechanism can wrap and unwrap any secret key of appropriate length.</para>
		/// <para>Of course, a particular token may not be able to wrap/unwrap every appropriate-length secret key that it supports.</para>
		/// <para>For wrapping, the "input" to the encryption operation is the value of the 'VALUE' attribute of the key that is wrapped; similarly for unwrapping. The mechanism does not wrap the key type or any other information about the key, except the key length; the application must convey these separately.</para>
		/// <para>In particular, the mechanism contributes only the 'CLASS' and 'VALUE' (and 'VALUE_LEN', if the key has it) attributes to the recovered key during unwrapping; other attributes must be specified in the template.</para>
		/// </summary>
		RSA_PKCS_OAEP = CKM_RSA_PKCS_OAEP,

		/// <summary>
		/// The X.509 (raw) RSA mechanism (denoted RSA_X_509), is a multi-purpose mechanism based on the RSA public-key crypto-system. It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping. All these operations are based on so-called "raw" RSA, as assumed in X.509.
		/// <para>"Raw" RSA as defined here encrypts a byte string by converting it to an integer, most-significant byte first, applying "raw" RSA exponentiation, and converting the result to a byte string, most-significant byte first. The input string, considered as an integer, must be less than the modulus; the output string is also less than the modulus.</para>
		/// <para>This mechanism can wrap and unwrap any secret key of appropriate length. Of course, a particular token may not be able to wrap/unwrap every appropriate-length secret key that it supports.</para>
		/// <para>For wrapping, the "input" to the encryption operation is the value of the 'VALUE' attribute of the key that is wrapped; similarly for unwrapping.</para>
		/// <para>The mechanism does not wrap the key type, key length, or any other information about the key; the application must convey these separately, and supply them when unwrapping the key.</para>
		/// <para>NOTE: Executing cryptographic operations using this mechanism can result in the error returns CKR_DATA_INVALID (if plain-text is supplied which has the same length as the RSA modulus and is numerically at least as large as the modulus) and CKR_ENCRYPTED_DATA_INVALID (if cipher-text is supplied which has the same length as the RSA modulus and is numerically at least as large as the modulus).</para>
		/// </summary>
		RSA_X_509 = CKM_RSA_X_509,

		///
		/// There are a number of additional SafeNet vendor defined encryption mechanism types.
		///

		/// <summary>
		/// ...
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES's block-size.</para>
		/// </summary>
		DES_BCF = CKM_DES_BCF,

		/// <summary>
		/// ...
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES3's block-size.</para>
		/// </summary>
		DES3_BCF = CKM_DES3_BCF,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		CAST128_ECB_PAD = CKM_CAST128_ECB_PAD,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		DES_ECB_PAD = CKM_DES_ECB_PAD,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		DES3_ECB_PAD = CKM_DES3_ECB_PAD,

		/// <summary>
		/// Single DES-OFB64 denoted DES_OFB64 is a SafeNet vendor defined mechanism for single and multiple part encryption and decryption; based on DES Output Feedback Mode.
		/// <para>It has a parameter, an initialization vector for this mode. The initialization vector has the same length as the block-size, which is 8 bytes.</para>
		/// <para>This mechanism does not require either clear text or cipher text to be presented in multiple block lengths.</para>
		/// <para>There is no padding required.</para>
		/// <para>The mechanism will always return a reply equal in length to the request.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES, DES2, DES3] - [Input length: Any] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES, DES2, DES3] - [Input length: Any] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>For this mechanism the MECHANISM_INFO structure is as specified for CBC mode.</para>
		/// </summary>
		DES_OFB64 = CKM_DES_OFB64,

		/// <summary>
		/// DES3_DDD_CBC is a SafeNet vendor defined mechanism for single- and multiple-part encryption and decryption, key wrapping and key unwrapping, based on the DES block cipher and cipher-block chaining mode as defined in FIPS PUB 81.
		/// <para>The DES3-DDD cipher encrypts an 8 byte block by D(KL, D(KR, D(KL, data)))and decrypts with E(KL, E(KR, E(KL, cipher))); where Key = KL || KR, and E(KL, data) is a single DES encryption using key KL and D(KL, cipher)is a single DES decryption.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as the block size, which is 8 bytes.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES2] - [Input length: Any] - [Output length: input length rounded up to multiple of block size] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES2] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES2] - [Input length: Any] - [Output length: input length rounded up to multiple of block size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES2] - [Input length: Any] - [Output length: Determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For the encrypt and wrap operations, the mechanism performs zero-padding when the input data or wrapped key's length is not a multiple of 8. That is, the value 0x00 is appended to the last block until its length is 8 (for example, plain-text 0x01 would be padded to become 0x010x000x000x000x000x000x000x00).</para>
		/// <para>With the exception of the algorithm, the use of this mechanism is identical to the use of other secret key mechanisms.</para>
		/// <para>Therefore, for further details on aspects not covered here (for example, access control, or error codes) refer to the PKCS#11 standard.</para>
		/// </summary>
		DES3_DDD_CBC = CKM_DES3_DDD_CBC,

		/// <summary>
		/// Single DES3-OFB64 denoted DES3_OFB64 is a SafeNet vendor defined mechanism for single and multiple part encryption and decryption; based on DES3 Output Feedback Mode.
		/// <para>It has a parameter, an initialization vector for this mode. The initialization vector has the same length as the block-size, which is 8 bytes.</para>
		/// <para>This mechanism does not require either clear text or cipher text to be presented in multiple block lengths.</para>
		/// <para>There is no padding required.</para>
		/// <para>The mechanism will always return a reply equal in length to the request.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES, DES2, DES3] - [Input length: Any] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES, DES2, DES3] - [Input length: Any] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>For this mechanism the MECHANISM_INFO structure is as specified for CBC mode.</para>
		/// </summary>
		DES3_OFB64 = CKM_DES3_OFB64,

		/// <summary>
		/// The SafeNet vendor defined Elliptic Curve Integrated Encryption Scheme (ECIES) mechanism, denoted ECIES, performs single-part encryption and decryption operations.
		/// <para>The operations performed are as described in ANSI X9.63-2001.</para>
		/// <para>This mechanism has a parameter, a ECIES_PARAMS structure.</para>
		/// <para>Constraints on key types and the length of the data are summarized in the following table:</para>
		/// <para>Where 'modLen' is the curve modulus length, and 'macLen' is the length of the produced MAC</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: EC public key] - [Input length: Any] - [Output length: 1 + 2modLen + any + macLen]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: EC private key] - [Input length: 1 + 2modLen + any + macLen] - [Output length: Any]</para>
		/// <para>The encrypted data is in the format QE||EncData||MAC, where:</para>
		/// <para>- QE is the uncompressed bit string of the ephemeral EC public key</para>
		/// <para>- EncData is the encrypted data</para>
		/// <para>- MAC is the generated MAC</para>
		/// </summary>
		ECIES = CKM_ECIES,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		IDEA_ECB_PAD = CKM_IDEA_ECB_PAD,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		RC2_ECB_PAD = CKM_RC2_ECB_PAD,

		/// <summary>
		/// SEED-ECB (denoted SEED_ECB), is a SafeNet vendor defined mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on the KISA (Korean Information Security Agency) SEED specification and electronic codebook mode.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the 'VALUE' attribute of the key that is wrapped, padded on the trailing end with up to block size, minus one null bytes so that the resulting length is a multiple of the block size.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the 'KEY_TYPE' attribute of the template and, if it has one and the key type supports it, the 'VALUE_LEN' attribute of the template.</para>
		/// <para>The mechanism contributes the result as the 'VALUE' attribute of the new key. Other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: SEED] - [Input length: Any] - [Output length: Input length rounded up to multiple of block size] - [Comments: -]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Determined by type of key being unwrapped or VALUE_LEN] - [Comments: -]</para>
		/// </summary>
		SEED_ECB = CKM_SEED_ECB,

		/// <summary>
		/// SEED-ECB with PKCS padding (denoted SEED_ECB_PAD) is a SafeNet vendor defined mechanism for single- and multiple-part encryption and decryption, key wrapping and key unwrapping, based on the KISA (Korean Information Security Agency) SEED specification, electronic code book mode and the block cipher padding method detailed in PKCS #7.
		/// <para>It does not have a parameter.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the 'VALUE_LEN' attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, and DSA private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: SEED] - [Input length: Any] - [Output length: This is the input length plus one, rounded up to a multiple of the block size.]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Between 1 and block size bytes shorter than input length.]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: SEED] - [Input length: Any] - [Output length: This is the input length plus one, rounded up to a multiple of the block size.]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Between 1 and block length bytes shorter than input length.]</para>
		/// </summary>
		SEED_ECB_PAD = CKM_SEED_ECB_PAD,

		/// <summary>
		/// <para>SEED-CBC (denoted SEED_CBC), is a SafeNet vendor defined mechanism for single and multiple part encryption and decryption, key wrapping and key unwrapping, based on the KISA (Korean Information Security Agency) SEED specification and cipher-block chaining mode.</para>
		/// <para>It has a single parameter; a 16-byte initialization vector.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the 'VALUE' attribute of the key that is wrapped, padded on the trailing end with up to block size minus one null bytes so that the resulting length is a multiple of the block size.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the 'KEY_TYPE' attribute of the template and, if it has one and the key type supports it, the 'VALUE_LEN' attribute of the template.</para>
		/// <para>The mechanism contributes the result as the 'VALUE' attribute of the new key. Other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: SEED] - [Input length: Any] - [Output length: Input length rounded up to multiple of the block size] - [Comments: -]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Determined by type of key being unwrapped or VALUE_LEN] - [Comments: -]</para>
		/// </summary>
		SEED_CBC = CKM_SEED_CBC,

		/// <summary>
		/// SEED-CBC with PKCS padding (denoted SEED_CBC_PAD), is a SafeNet vendor defined mechanism for single and multiple part encryption and decryption; key wrapping; and key unwrapping, based on the KISA (Korean Information Security Agency) SEED specification, cipher-block chaining mode and the block cipher padding method detailed in PKCS #7.
		/// <para>It has a single parameter; a 16-byte initialization vector.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the 'VALUE_LEN' attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, and DSA private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table. The data length constraints do not apply to the wrapping and unwrapping of private keys.</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: SEED] - [Input length: Any] - [Output length: This is the input length plus one, rounded up to a multiple of the block size.]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Between 1 and block size bytes shorter than input length.]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: SEED] - [Input length: Any] - [Output length: This is the input length plus one, rounded up to a multiple of the block size.]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Between 1 and block length bytes shorter than input length.]</para>
		/// </summary>
		SEED_CBC_PAD = CKM_SEED_CBC_PAD,
	};

	/// <summary>
	/// Type of wrap/unwrap mechanism.
	/// </summary>
	public enum class WrappingMechanism
	{
		/// <summary>
		/// ...
		/// <para>...</para>
		/// </summary>
		ARIA_ECB = CKM_ARIA_ECB,

		/// <summary>
		/// ...
		/// <para>...</para>
		/// </summary>
		ARIA_CBC = CKM_ARIA_CBC,

		/// <summary>
		/// ...
		/// <para>...</para>
		/// </summary>
		ARIA_CBC_PAD = CKM_ARIA_CBC_PAD,

		/// <summary>
		/// AES-ECB (denoted AES_ECB), is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on NIST Advanced Encryption Standard and electronic codebook mode.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the 'VALUE' attribute of the key that is wrapped, padded on the trailing end with up to block size minus one null bytes so that the resulting length is a multiple of the block size.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the 'KEY_TYPE' attribute of the template and, if it has one, and the key type supports it, the 'VALUE_LEN' attribute of the template.</para>
		/// <para>The mechanism contributes the result as the 'VALUE' attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: AES] - [Input length: multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: AES] - [Input length: Any] - [Output length: input length rounded up to multiple of block size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_ECB = CKM_AES_ECB,

		/// <summary>
		/// AES-CBC (denoted AES_CBC), is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on NIST's Advanced Encryption Standard and cipher-block chaining mode.
		/// <para>It has a parameter, a 16 - byte initialization vector.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the 'VALUE' attribute of the key that is wrapped, padded on the trailing end with up to block size minus one null bytes so that the resulting length is a multiple of the block size.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the 'KEY_TYPE' attribute of the template and, if it has one, and the key type supports it, the 'VALUE_LEN' attribute of the template.</para>
		/// <para>The mechanism contributes the result as the 'VALUE' attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: AES] - [Input length: multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: AES] - [Input length: Any] - [Output length: input length rounded up to multiple of block size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_CBC = CKM_AES_CBC,

		/// <summary>
		/// AES-CBC with PKCS padding (denoted AES_CBC_PAD), is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on NIST's Advanced Encryption Standard; cipher-block chaining mode; and the block cipher padding method detailed in PKCS #7.
		/// <para>It has a parameter, a 16-byte initialization vector.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the 'VALUE_LEN' attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: AES] - [Input length: Any] - [Output length: input length rounded up to multiple of the block size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: between 1 and block size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: AES] - [Input length: Any] - [Output length: input length rounded up to multiple of the block size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: AES] - [Input length: multiple of block-size] - [Output length: between 1 and block size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_CBC_PAD = CKM_AES_CBC_PAD,

		/// <summary>
		/// Cipher CAST128 has an electronic codebook mechanism, CAST128-ECB, denoted CAST128_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST128.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of CAST128's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST128_ECB = CKM_CAST128_ECB,

		/// <summary>
		/// Cipher CAST5 has an electronic codebook mechanism, CAST5-ECB, denoted CAST5_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST5.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of CAST5's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST5_ECB = CKM_CAST5_ECB,

		/// <summary>
		/// Cipher CAST128 has a cipher-block chaining mode, CAST128-CBC, denoted CAST128_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST128.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as CAST128's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes. For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST128_CBC = CKM_CAST128_CBC,

		/// <summary>
		/// Cipher CAST5 has a cipher-block chaining mode, CAST5-CBC, denoted CAST5_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST5.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as CAST5's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes. For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST5_CBC = CKM_CAST5_CBC,

		/// <summary>
		/// Cipher CAST128 has a cipher-block chaining mode with PKCS padding, CAST128-CBC with PKCS padding, denoted CAST128_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST128.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as CAST128's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST128] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST128] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST128_CBC_PAD = CKM_CAST128_CBC_PAD,

		/// <summary>
		/// Cipher CAST5 has a cipher-block chaining mode with PKCS padding, CAST5-CBC with PKCS padding, denoted CAST5_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with CAST5.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as CAST5's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: CAST5] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: CAST5] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST5_CBC_PAD = CKM_CAST5_CBC_PAD,

		/// <summary>
		/// Cipher DES has an electronic codebook mechanism, DES-ECB, denoted DES_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of DES's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES_ECB = CKM_DES_ECB,

		/// <summary>
		/// Cipher DES has a cipher-block chaining mode, DES-CBC, denoted DES_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes. For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES_CBC = CKM_DES_CBC,

		/// <summary>
		/// Cipher DES has a cipher-block chaining mode with PKCS padding, DES-CBC with PKCS padding, denoted DES_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES_CBC_PAD = CKM_DES_CBC_PAD,

		/// <summary>
		/// Cipher DES3 has an electronic codebook mechanism, DES3-ECB, denoted DES3_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES3.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of DES3's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES3_ECB = CKM_DES3_ECB,

		/// <summary>
		/// Cipher DES3 has a cipher-block chaining mode, DES3-CBC, denoted DES3_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES3.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES3's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes. For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES3_CBC = CKM_DES3_CBC,

		/// <summary>
		/// Cipher DES3 has a cipher-block chaining mode with PKCS padding, DES3-CBC with PKCS padding, denoted DES3_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with DES3.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES3's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES3] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES3] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES3] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES3_CBC_PAD = CKM_DES3_CBC_PAD,

		/// <summary>
		/// Cipher IDEA has an electronic codebook mechanism, IDEA-ECB, denoted IDEA_ECB. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with IDEA.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with null bytes so that the resulting length is a multiple of IDEA's block-size.</para>
		/// <para>The output data is the same length as the padded input data.</para>
		/// <para>It does not wrap the key type, key length or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments:]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments:]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		IDEA_ECB = CKM_IDEA_ECB,

		/// <summary>
		/// Cipher IDEA has a cipher-block chaining mode, IDEA-CBC, denoted IDEA_CBC. It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with IDEA.
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as IDEA's block-size.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		IDEA_CBC = CKM_IDEA_CBC,

		/// <summary>
		/// Cipher IDEA has a cipher-block chaining mode with PKCS padding, IDEA-CBC with PKCS padding, denoted IDEA_CBC_PAD.
		/// <para>It is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping with IDEA.</para>
		/// <para>All cipher-text is padded with PKCS padding.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as IDEA's block-size.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys.</para>
		/// <para>The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: IDEA] - [Input Length: Any] - [Output Length: input length rounded up to multiple of block-size]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: IDEA] - [Input Length: multiple of block-size] - [Output Length: between 1 and block-size bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		IDEA_CBC_PAD = CKM_IDEA_CBC_PAD,

		/// <summary>
		/// RC2-ECB, denoted RC2_ECB, is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on RSA Security's block cipher RC2 and electronic codebook mode as defined in FIPS PUB 81.
		/// <para>It has a parameter, a RC2_PARAMS, which indicates the effective number of bits in the RC2 search space.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with up to seven null bytes so that the resulting length is a multiple of eight.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RC2] - [Input length: Any] - [Output length: input length rounded up to multiple of 8] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 effective number of bits.</para>
		/// </summary>
		RC2_ECB = CKM_RC2_ECB,

		/// <summary>
		/// RC2-CBC, denoted RC2_CBC, is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on RSA Security's block cipher RC2 and cipher-block chaining mode as defined in FIPS PUB 81.
		/// <para>It has a parameter, a RC2_CBC_PARAMS structure, where the first field indicates the effective number of bits in the RC2 search space, and the next field is the initialization vector for cipher block chaining mode.</para>
		/// <para>This mechanism can wrap and unwrap any secret key.</para>
		/// <para>Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the VALUE attribute of the key that is wrapped, padded on the trailing end with up to seven null bytes so that the resulting length is a multiple of eight.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one, and the key type supports it, the VALUE_LEN attribute of the template.</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RC2] - [Input length: Any] - [Output length: input length rounded up to multiple of 8] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 effective number of bits.</para>
		/// </summary>
		RC2_CBC = CKM_RC2_CBC,

		/// <summary>
		/// RC2-CBC with PKCS padding, denoted RC2_CBC_PAD, is a mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on RSA Security's block cipher RC2; cipher-block chaining mode as defined in FIPS PUB 81; and the block cipher padding method detailed in PKCS #7.
		/// <para>It has a parameter, a RC2_CBC_PARAMS structure, where the first field indicates the effective number of bits in the RC2 search space, and the next field is the initialization vector.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the VALUE_LEN attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, EC (also related to ECDSA) and DSA private keys. The entries in the table below for data length constraints when wrapping and unwrapping keys do not apply to wrapping and unwrapping private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RC2] - [Input length: Any] - [Output length: input length rounded up to multiple of 8]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: between 1 and 8 bytes shorter than input length]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RC2] - [Input length: Any] - [Output length: input length rounded up to multiple of 8]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RC2] - [Input length: multiple of 8] - [Output length: between 1 and 8 bytes shorter than input length]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 effective number of bits.</para>
		/// </summary>
		RC2_CBC_PAD = CKM_RC2_CBC_PAD,

		/// <summary>
		/// The PKCS #1 v1.5 RSA mechanism (denoted RSA_PKCS), is a multi-purpose mechanism based on the RSA public-key crypto-system and the block formats initially defined in PKCS #1 v1.5.
		/// <para>It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping.</para>
		/// <para>This mechanism corresponds only to the part of PKCS #1 v1.5 that involves RSA; it does not compute a message digest or a DigestInfo encoding as specified for the 'md2withRSAEncryption' and 'md5withRSAEncryption' algorithms in PKCS #1 v1.5.</para>
		/// <para>This mechanism can wrap and unwrap any secret key of appropriate length.</para>
		/// <para>Of course, a particular token may not be able to wrap/unwrap every appropriate-length secret key that it supports.</para>
		/// <para>For wrapping, the "input" to the encryption operation is the value of the 'VALUE' attribute of the key that is wrapped; similarly for unwrapping.</para>
		/// <para>The mechanism does not wrap the key type or any other information about the key, except the key length; the application must convey these separately.</para>
		/// <para>In particular, the mechanism contributes only the 'CLASS' and 'VALUE' (and 'VALUE_LEN', if the key has it) attributes to the recovered key during unwrapping; other attributes must be specified in the template.</para>
		/// <para>Constraints on key types and the length of the data are summarized in the following table.</para>
		/// <para>For encryption, decryption, signatures and signature verification, the input and output data may begin at the same location in memory. In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RSA public key] - [Data Length: ≤k-11] - [Signature Length: k] - [Comments: block type 02]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RSA private key] - [Data Length: k] - [Signature Length: ≤k-11] - [Comments: block type 02]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RSA public key] - [Data Length: ≤k-11] - [Signature Length: k] - [Comments: block type 02]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RSA private key] - [Data Length: k] - [Signature Length: ≤k-11] - [Comments: block type 02]</para>
		/// </summary>
		RSA_PKCS = CKM_RSA_PKCS,

		/// <summary>
		/// The PKCS #1 RSA OAEP mechanism (denoted RSA_PKCS_OAEP), is a multi-purpose mechanism based on the RSA public-key crypto-system and the OAEP block format defined in PKCS #1. It supports single-part encryption and decryption; key wrapping; and key unwrapping.
		/// <para>It has a parameter, a RSA_PKCS_OAEP_PARAMS structure.</para>
		/// <para>It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping. This mechanism corresponds only to the part of PKCS #1 v1.5 that involves RSA; it does not compute a message digest or a DigestInfo encoding as specified for the md2withRSAEncryption and md5withRSAEncryption algorithms in PKCS #1 v1.5.</para>
		/// <para>This mechanism can wrap and unwrap any secret key of appropriate length.</para>
		/// <para>Of course, a particular token may not be able to wrap/unwrap every appropriate-length secret key that it supports.</para>
		/// <para>For wrapping, the "input" to the encryption operation is the value of the 'VALUE' attribute of the key that is wrapped; similarly for unwrapping. The mechanism does not wrap the key type or any other information about the key, except the key length; the application must convey these separately.</para>
		/// <para>In particular, the mechanism contributes only the 'CLASS' and 'VALUE' (and 'VALUE_LEN', if the key has it) attributes to the recovered key during unwrapping; other attributes must be specified in the template.</para>
		/// </summary>
		RSA_PKCS_OAEP = CKM_RSA_PKCS_OAEP,

		/// <summary>
		/// The X.509 (raw) RSA mechanism (denoted RSA_X_509), is a multi-purpose mechanism based on the RSA public-key crypto-system. It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping. All these operations are based on so-called "raw" RSA, as assumed in X.509.
		/// <para>"Raw" RSA as defined here encrypts a byte string by converting it to an integer, most-significant byte first, applying "raw" RSA exponentiation, and converting the result to a byte string, most-significant byte first. The input string, considered as an integer, must be less than the modulus; the output string is also less than the modulus.</para>
		/// <para>This mechanism can wrap and unwrap any secret key of appropriate length. Of course, a particular token may not be able to wrap/unwrap every appropriate-length secret key that it supports.</para>
		/// <para>For wrapping, the "input" to the encryption operation is the value of the 'VALUE' attribute of the key that is wrapped; similarly for unwrapping.</para>
		/// <para>The mechanism does not wrap the key type, key length, or any other information about the key; the application must convey these separately, and supply them when unwrapping the key.</para>
		/// <para>NOTE: Executing cryptographic operations using this mechanism can result in the error returns CKR_DATA_INVALID (if plain-text is supplied which has the same length as the RSA modulus and is numerically at least as large as the modulus) and CKR_ENCRYPTED_DATA_INVALID (if cipher-text is supplied which has the same length as the RSA modulus and is numerically at least as large as the modulus).</para>
		/// </summary>
		RSA_X_509 = CKM_RSA_X_509,

		/// <summary>
		/// The OAEP key wrapping for SET mechanism, denoted KEY_WRAP_SET_OAEP, is a mechanism for wrapping and unwrapping a DES key with an RSA key.
		/// <para>The hash of some plain-text data and/or some extra data may optionally be wrapped together with the DES key.</para>
		/// <para>This mechanism is defined in the SET protocol specifications.</para>
		/// <para>It takes a parameter, a KEY_WRAP_SET_OAEP_PARAMS structure.</para>
		/// <para>This structure holds the "Block Contents" byte of the data and the concatenation of the hash of plain-text data (if present) and the extra data to be wrapped (if present).</para>
		/// <para>If neither the hash nor the extra data is present, this is indicated by the ulXLen field having the value 0.</para>
		/// <para>When this mechanism is used to unwrap a key, the concatenation of the hash of plain-text data (if present) and the extra data (if present) is returned on producing output.</para>
		/// <para>Note that if the inputs to UnwrapKey are such that the extra data is not returned (e.g., the buffer supplied in the KEY_WRAP_SET_OAEP_PARAMS structure is NULL), then the unwrapped key object will not be created, either.</para>
		/// <para>Be aware that when this mechanism is used to unwrap a key, the bBC and pX fields of the parameter supplied to the mechanism may be modified.</para>
		/// <para>If an application uses UnwrapKey with KEY_WRAP_SET_OAEP, it may be preferable for it simply to allocate a 128-byte buffer for the concatenation of the hash of plaintext data and the extra data (this concatenation is never larger than 128 bytes), rather than calling UnwrapKey twice.</para>
		/// <para>Each call of UnwrapKey with KEY_WRAP_SET_OAEP requires an RSA decryption operation to be performed, and this computational overhead can be avoided by this means.</para>
		/// </summary>
		KEY_WRAP_SET_OAEP = CKM_KEY_WRAP_SET_OAEP,

		///
		/// There are a number of additional SafeNet vendor defined encryption mechanism types.
		///

		/// <summary>
		/// ...
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES's block-size.</para>
		/// </summary>
		DES_BCF = CKM_DES_BCF,

		/// <summary>
		/// ...
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as DES3's block-size.</para>
		/// </summary>
		DES3_BCF = CKM_DES3_BCF,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		CAST128_ECB_PAD = CKM_CAST128_ECB_PAD,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		DES_ECB_PAD = CKM_DES_ECB_PAD,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		DES3_ECB_PAD = CKM_DES3_ECB_PAD,

		/// <summary>
		/// DES3_DDD_CBC is a SafeNet vendor defined mechanism for single- and multiple-part encryption and decryption, key wrapping and key unwrapping, based on the DES block cipher and cipher-block chaining mode as defined in FIPS PUB 81.
		/// <para>The DES3-DDD cipher encrypts an 8 byte block by D(KL, D(KR, D(KL, data)))and decrypts with E(KL, E(KR, E(KL, cipher))); where Key = KL || KR, and E(KL, data) is a single DES encryption using key KL and D(KL, cipher)is a single DES decryption.</para>
		/// <para>It has a parameter, an initialization vector for cipher block chaining mode. The initialization vector has the same length as the block size, which is 8 bytes.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: DES2] - [Input length: Any] - [Output length: input length rounded up to multiple of block size] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: DES2] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: DES2] - [Input length: Any] - [Output length: input length rounded up to multiple of block size] - [Comments: ]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: DES2] - [Input length: Any] - [Output length: Determined by type of key being unwrapped or VALUE_LEN] - [Comments: ]</para>
		/// <para>For the encrypt and wrap operations, the mechanism performs zero-padding when the input data or wrapped key's length is not a multiple of 8. That is, the value 0x00 is appended to the last block until its length is 8 (for example, plain-text 0x01 would be padded to become 0x010x000x000x000x000x000x000x00).</para>
		/// <para>With the exception of the algorithm, the use of this mechanism is identical to the use of other secret key mechanisms.</para>
		/// <para>Therefore, for further details on aspects not covered here (for example, access control, or error codes) refer to the PKCS#11 standard.</para>
		/// </summary>
		DES3_DDD_CBC = CKM_DES3_DDD_CBC,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		IDEA_ECB_PAD = CKM_IDEA_ECB_PAD,

		/// <summary>
		/// This is a SafeNet vendor defined padding mechanism.
		/// <para>This block cipher mechanism is based on the corresponding Electronic Code Book (ECB) algorithm, implied by it's name, but with the addition of the block-cipher padding method detailed in PKCS#7.</para>
		/// <para>This mechanism is supplied for compatibility only and its use in new applications is not recommended.</para>
		/// <para>PKCS#11 Version 2.1 specifies mechanisms for Chain Block Cipher algorithms with and without padding and ECB algorithms without padding, but not ECB with padding.</para>
		/// <para>This mechanism fill this gap. The mechanism may be used for general data encryption and decryption and also for key wrapping and unwrapping (provided all the access conditions of the relevant key are satisfied).</para>
		/// </summary>
		RC2_ECB_PAD = CKM_RC2_ECB_PAD,

		/// <summary>
		/// SEED-ECB (denoted SEED_ECB), is a SafeNet vendor defined mechanism for single- and multiple-part encryption and decryption; key wrapping; and key unwrapping, based on the KISA (Korean Information Security Agency) SEED specification and electronic codebook mode.
		/// <para>It does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the 'VALUE' attribute of the key that is wrapped, padded on the trailing end with up to block size, minus one null bytes so that the resulting length is a multiple of the block size.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the 'KEY_TYPE' attribute of the template and, if it has one and the key type supports it, the 'VALUE_LEN' attribute of the template.</para>
		/// <para>The mechanism contributes the result as the 'VALUE' attribute of the new key. Other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: SEED] - [Input length: Any] - [Output length: Input length rounded up to multiple of block size] - [Comments: -]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Determined by type of key being unwrapped or VALUE_LEN] - [Comments: -]</para>
		/// </summary>
		SEED_ECB = CKM_SEED_ECB,

		/// <summary>
		/// SEED-ECB with PKCS padding (denoted SEED_ECB_PAD) is a SafeNet vendor defined mechanism for single- and multiple-part encryption and decryption, key wrapping and key unwrapping, based on the KISA (Korean Information Security Agency) SEED specification, electronic code book mode and the block cipher padding method detailed in PKCS #7.
		/// <para>It does not have a parameter.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the 'VALUE_LEN' attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, and DSA private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: SEED] - [Input length: Any] - [Output length: This is the input length plus one, rounded up to a multiple of the block size.]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Between 1 and block size bytes shorter than input length.]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: SEED] - [Input length: Any] - [Output length: This is the input length plus one, rounded up to a multiple of the block size.]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Between 1 and block length bytes shorter than input length.]</para>
		/// </summary>
		SEED_ECB_PAD = CKM_SEED_ECB_PAD,

		/// <summary>
		/// <para>SEED-CBC (denoted SEED_CBC), is a SafeNet vendor defined mechanism for single and multiple part encryption and decryption, key wrapping and key unwrapping, based on the KISA (Korean Information Security Agency) SEED specification and cipher-block chaining mode.</para>
		/// <para>It has a single parameter; a 16-byte initialization vector.</para>
		/// <para>This mechanism can wrap and unwrap any secret key. Of course, a particular token may not be able to wrap/unwrap every secret key that it supports.</para>
		/// <para>For wrapping, the mechanism encrypts the value of the 'VALUE' attribute of the key that is wrapped, padded on the trailing end with up to block size minus one null bytes so that the resulting length is a multiple of the block size.</para>
		/// <para>The output data is the same length as the padded input data. It does not wrap the key type, key length, or any other information about the key; the application must convey these separately.</para>
		/// <para>For unwrapping, the mechanism decrypts the wrapped key, and truncates the result according to the 'KEY_TYPE' attribute of the template and, if it has one and the key type supports it, the 'VALUE_LEN' attribute of the template.</para>
		/// <para>The mechanism contributes the result as the 'VALUE' attribute of the new key. Other attributes required by the key type must be specified in the template.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: same as input length] - [Comments: no final part]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: SEED] - [Input length: Any] - [Output length: Input length rounded up to multiple of the block size] - [Comments: -]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Determined by type of key being unwrapped or VALUE_LEN] - [Comments: -]</para>
		/// </summary>
		SEED_CBC = CKM_SEED_CBC,

		/// <summary>
		/// SEED-CBC with PKCS padding (denoted SEED_CBC_PAD), is a SafeNet vendor defined mechanism for single and multiple part encryption and decryption; key wrapping; and key unwrapping, based on the KISA (Korean Information Security Agency) SEED specification, cipher-block chaining mode and the block cipher padding method detailed in PKCS #7.
		/// <para>It has a single parameter; a 16-byte initialization vector.</para>
		/// <para>The PKCS padding in this mechanism allows the length of the plain-text value to be recovered from the cipher-text value. Therefore, when unwrapping keys with this mechanism, no value should be specified for the 'VALUE_LEN' attribute.</para>
		/// <para>In addition to being able to wrap and unwrap secret keys, this mechanism can wrap and unwrap RSA, Diffie-Hellman, X9.42 Diffie-Hellman, and DSA private keys.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table. The data length constraints do not apply to the wrapping and unwrapping of private keys.</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: SEED] - [Input length: Any] - [Output length: This is the input length plus one, rounded up to a multiple of the block size.]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Between 1 and block size bytes shorter than input length.]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: SEED] - [Input length: Any] - [Output length: This is the input length plus one, rounded up to a multiple of the block size.]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: SEED] - [Input length: Multiple of block size] - [Output length: Between 1 and block length bytes shorter than input length.]</para>
		/// </summary>
		SEED_CBC_PAD = CKM_SEED_CBC_PAD,

		/// <summary>
		/// This wrapping mechanism takes the attributes of an object and encodes them.
		/// <para>The encoding is not encrypted therefore the wrapping key object handle parameter is ignored.</para>
		/// <para>If the object is sensitive then only non-sensitive attributes of the object are encoded.</para>
		/// <para>The encoding format is a simple proprietary encoding with the attribute type, length, a value presence indicator (Boolean) and the attribute value.</para>
		/// <para>This simple encoding format is used wherever BER or DER is not required.</para>
		/// <para>This mechanism has no parameter.</para>
		/// </summary>
		ENCODE_ATTRIBUTES = CKM_ENCODE_ATTRIBUTES,

		/// <summary>
		/// This wrapping mechanism performs a DER encoding of a Public Key object.
		/// <para>The encoding is not encrypted therefore the wrapping key object handle parameter is ignored.</para>
		/// <para>Public keys of type CKK_RSA, CKK_DSA and CKK_DH may be encoded with this mechanism.</para>
		/// <para>The encoding format is defined in PKCS#1</para>
		/// <para>This mechanism has no parameter.</para>
		/// </summary>
		ENCODE_PUBLIC_KEY = CKM_ENCODE_PUBLIC_KEY,

		/// <summary>
		/// This is a key wrapping mechanisms as used by Entrust compliant applications.
		/// <para>This mechanism is only visible when the ENTRUST_READY flag is set in the SecurityMode attribute of the Adapter Configuration object in the Admin Token of the adapter.</para>
		/// <para>This mechanism has no parameter.</para>
		/// </summary>
		KEY_TRANSLATION = CKM_KEY_TRANSLATION,

		/// <summary>
		/// The WRAPKEY_DES3_CBC and WRAPKEY_DES3_ECB mechanisms are used to wrap a key value plus all of its attributes so that the entire key can be reconstructed without a template at the destination.
		/// <para>The key value is encoded and encrypted using DES3_CBC_PAD and then combined with all other object attributes.</para>
		/// <para>The result are then MACed. The wrapping key is supplied as normal to the Wrap and Unwrap Cryptoki functions.</para>
		/// <para>The Unwrap operation will fail with SIGNATURE_INVALID if any of the key's attributes have been tampered with while the key was in transit.</para>
		/// <para>Encoding Format:</para>
		/// <para>The encoding is a proprietary encoding where fields are identified by their position (no tags).</para>
		/// <para>All fields are preceded by an encoding of the length of the content. The length may be zero indicating an empty field but must always be present.</para>
		/// <para>Where the length is zero the content is not present (zero bytes). Where the length is non zero the content has the number of bytes equal to the value of the encoded length.</para>
		/// <para>The length is encoded as a 32-bit big-endian binary value and can thus take values from 0 to ((2^32) - 1) i.e. around 4 gigabytes.</para>
		/// <para>Definitions:</para>
		/// <para>[wK] - This is the wrapping key under which the subject key is to be wrapped. This key must be valid for the operation Ex.</para>
		/// <para>[mK] - This is a randomly generated MAC key using CKM_DES2_KEY_GEN. This key is used with Mx.</para>
		/// <para>[wK] - This is clear encoding of the subject key. For single part symmetric keys, this is just the key value. For compound (e.g., RSA) keys, it is a BER encoding as per PKCS#1.</para>
		/// <para>[cK] - This is the wrapping key under which the subject key is to be wrapped. This key must be valid for the operation Ex.</para>
		/// <para>[a] - This is the encoded non-sensitive subject key attributes. The attributes are encoded with an attribute header, which is the number of attributes (4 byte), followed by a list of sub encodings which contain the attribute type (4 byte), content length (4 byte), a content presence indicator (1 byte), and the content bytes. The presence indicator allows the content length value to be non-zero, but, where presence indicator = 0, no content bytes are included. If the presence indicator is 1 then the content length must be the number of bytes indicated by the content length field. All numeric values are encoded as big-endian. Note that the sensitive attributes are contained in cK.</para>
		/// <para>[eX] - This is encryption using DES3_(ECB/CBC)_PAD with key 'x'.</para>
		/// <para>[mX] - This is MAC generation using DES3_MAC_GENERAL (8 byte MAC result) with key 'x'.</para>
		/// <para>A wrapped key using WRAPKEY_DES3_ECB or WRAPKEY_DES3_CBC is made up of the following fields:</para>
		/// <para>- ecK the encrypted key value, ecK = EwK(cK).</para>
		/// <para>- a the encoded non-sensitive subject key attributes.</para>
		/// <para>- m a MAC of the key value and attributes, m = MmK(cK + a).</para>
		/// <para>- emK the encrypted MAC key value, emK = EwK(mK).</para>
		/// <para>These fields are then encoded as described above.</para>
		/// </summary>
		WRAPKEY_DES3_CBC = CKM_WRAPKEY_DES3_CBC,

		/// <summary>
		/// The WRAPKEY_DES3_CBC and WRAPKEY_DES3_ECB mechanisms are used to wrap a key value plus all of its attributes so that the entire key can be reconstructed without a template at the destination.
		/// <para>The key value is encoded and encrypted using DES3_CBC_PAD and then combined with all other object attributes.</para>
		/// <para>The result are then MACed. The wrapping key is supplied as normal to the Wrap and Unwrap Cryptoki functions.</para>
		/// <para>The Unwrap operation will fail with SIGNATURE_INVALID if any of the key's attributes have been tampered with while the key was in transit.</para>
		/// <para>Encoding Format:</para>
		/// <para>The encoding is a proprietary encoding where fields are identified by their position (no tags).</para>
		/// <para>All fields are preceded by an encoding of the length of the content. The length may be zero indicating an empty field but must always be present.</para>
		/// <para>Where the length is zero the content is not present (zero bytes). Where the length is non zero the content has the number of bytes equal to the value of the encoded length.</para>
		/// <para>The length is encoded as a 32-bit big-endian binary value and can thus take values from 0 to ((2^32) - 1) i.e. around 4 gigabytes.</para>
		/// <para>Definitions:</para>
		/// <para>[wK] - This is the wrapping key under which the subject key is to be wrapped. This key must be valid for the operation Ex.</para>
		/// <para>[mK] - This is a randomly generated MAC key using CKM_DES2_KEY_GEN. This key is used with Mx.</para>
		/// <para>[wK] - This is clear encoding of the subject key. For single part symmetric keys, this is just the key value. For compound (e.g., RSA) keys, it is a BER encoding as per PKCS#1.</para>
		/// <para>[cK] - This is the wrapping key under which the subject key is to be wrapped. This key must be valid for the operation Ex.</para>
		/// <para>[a] - This is the encoded non-sensitive subject key attributes. The attributes are encoded with an attribute header, which is the number of attributes (4 byte), followed by a list of sub encodings which contain the attribute type (4 byte), content length (4 byte), a content presence indicator (1 byte), and the content bytes. The presence indicator allows the content length value to be non-zero, but, where presence indicator = 0, no content bytes are included. If the presence indicator is 1 then the content length must be the number of bytes indicated by the content length field. All numeric values are encoded as big-endian. Note that the sensitive attributes are contained in cK.</para>
		/// <para>[eX] - This is encryption using DES3_(ECB/CBC)_PAD with key 'x'.</para>
		/// <para>[mX] - This is MAC generation using DES3_MAC_GENERAL (8 byte MAC result) with key 'x'.</para>
		/// <para>A wrapped key using WRAPKEY_DES3_ECB or WRAPKEY_DES3_CBC is made up of the following fields:</para>
		/// <para>- ecK the encrypted key value, ecK = EwK(cK).</para>
		/// <para>- a the encoded non-sensitive subject key attributes.</para>
		/// <para>- m a MAC of the key value and attributes, m = MmK(cK + a).</para>
		/// <para>- emK the encrypted MAC key value, emK = EwK(mK).</para>
		/// <para>These fields are then encoded as described above.</para>
		/// </summary>
		WRAPKEY_DES3_ECB = CKM_WRAPKEY_DES3_ECB,

#ifndef _PTKC_V400_
		/// <summary>
		/// The WRAPKEY_AES_CBC mechanism is used to wrap a key value plus all of its attributes so that the entire key can be reconstructed without a template at the destination.
		/// <para>This mechanism is the same as the WRAPKEY_DES3_CBC mechanism but uses only NIST approved cryptographic algorithms and key sizes.</para>
		/// <para>The following fields in the encoding are computed differently to those in WRAPKEY_DES3_CBC mechanism described above.</para>
		/// <para>[mK] - This is a randomly generated 256-bit MAC key using GENERIC_SECRET_KEY_GEN. This key is used with Mx.</para>
		/// <para>[eX] - This is encryption using CKM_AES_CBC_PAD with key 'x'.</para>
		/// <para>[mX] - This is MAC generation using SHA512_HMAC_GENERAL (16 byte MAC result) with key 'x'.</para>
		/// </summary>
		WRAPKEY_AES_CBC = CKM_WRAPKEY_AES_CBC,

		/// <summary>
		/// The WRAPKEYBLOB_AES_CBC and WRAPKEYBLOB_DES3_CBC mechanism is used to wrap a private key value using the Microsoft PRIVATEKEYBLOB format.
		/// <para>http://msdn.microsoft.com/en-us/library/cc250013(PROT.13).aspx</para>
		/// <para>The RSA private key is formatted as shown below and then the result is encrypted by AES_CBC_PAD or DES3_CBC_PAD:</para>
		/// <para>- Header 12 bytes long = 07 02 00 00 00 A4 00 00 52 53 41 32</para>
		/// <para>- Bit Length (32 bit LE)</para>
		/// <para>- PubExp (32 bit LE)</para>
		/// <para>- Modulus (BitLength/8 bytes long LE)</para>
		/// <para>- P (BitLength/8 bytes long LE)</para>
		/// <para>- Q (BitLength/8 bytes long LE)</para>
		/// <para>- Dp (BitLength/8 bytes long LE)</para>
		/// <para>- Dq (BitLength/8 bytes long LE)</para>
		/// <para>- Iq (BitLength/8 bytes long LE)</para>
		/// <para>- D (BitLength/8 bytes long LE)</para>
		/// </summary>
		WRAPKEYBLOB_AES_CBC = CKM_WRAPKEYBLOB_AES_CBC,

		/// <summary>
		/// The WRAPKEYBLOB_AES_CBC and WRAPKEYBLOB_DES3_CBC mechanism is used to wrap a private key value using the Microsoft PRIVATEKEYBLOB format.
		/// <para>http://msdn.microsoft.com/en-us/library/cc250013(PROT.13).aspx</para>
		/// <para>The RSA private key is formatted as shown below and then the result is encrypted by AES_CBC_PAD or DES3_CBC_PAD:</para>
		/// <para>- Header 12 bytes long = 07 02 00 00 00 A4 00 00 52 53 41 32</para>
		/// <para>- Bit Length (32 bit LE)</para>
		/// <para>- PubExp (32 bit LE)</para>
		/// <para>- Modulus (BitLength/8 bytes long LE)</para>
		/// <para>- P (BitLength/8 bytes long LE)</para>
		/// <para>- Q (BitLength/8 bytes long LE)</para>
		/// <para>- Dp (BitLength/8 bytes long LE)</para>
		/// <para>- Dq (BitLength/8 bytes long LE)</para>
		/// <para>- Iq (BitLength/8 bytes long LE)</para>
		/// <para>- D (BitLength/8 bytes long LE)</para>
		/// </summary>
		WRAPKEYBLOB_DES3_CBC = CKM_WRAPKEYBLOB_DES3_CBC,
#endif

		/// <summary>
		/// The PKCS#12 export mechanism, denoted PKCS12_PBE_EXPORT is a mechanism for wrapping a private key and a certificate. The outcome of the wrapping operation is a PKCS#12 byte buffer.
		/// <para>This mechanism has a parameter, a PKCS12_PBE_EXPORT_PARAMS structure.</para>
		/// <para>This mechanism will enforce a password length based on the token. If the PIN is too short, then PIN_LEN_RANGE error is returned.</para>
		/// <para>This mechanism does not require a wrapping key and it only support RSA, ECDSA and DSA private keys and certificates.</para>
		/// <para>During the wrapping operation, this mechanism performs a sign and verify test on the supplied key/certificate pair. Should this test fail, the wrapping operation will abort.</para>
		/// <para>If the exported key is marked EXPORTABLE=TRUE and EXTRACTABLE=FALSE this mechanism forces the export to be performed under the Security Officer session.</para>
		/// <para>In this case, the user must ensure that the private key is either visible to the Security Officer or made available to the Security Officer by performing a copy.</para>
		/// <para>Note that the user performing the private key export is asked to supply two (2) passwords. These passwords must be identical if MS Windows is to be used to later extract the created PKCS#12 file. For other 3rd party tools such as OpenSSL these two passwords do not have to be the same.</para>
		/// </summary>
		PKCS12_PBE_EXPORT = CKM_PKCS12_PBE_EXPORT,

		/// <summary>
		/// The PKCS#12 import mechanism, denoted PKCS12_PBE_IMPORT is a mechanism for unwrapping a private key and certificate(s). This mechanism shall return the user a handle to a private key and handle(s) to certificate(s).
		/// <para>Note that multiple certificate handles could be returned depending on the contents of the PKCS#12 file.</para>
		/// <para>NOTE: This mechanism does not import optional PKCS#12 bag attributes and PKCS#8 private-key attributes. These components are discarded during import.</para>
		/// <para>The mechanism has a parameter, a PKCS12_PBE_IMPORT_PARAMS structure. This mechanism does not require an unwrapping key and supports RSA, DH, DSA and EC Private Keys and certificates.</para>
		/// </summary>
		PKCS12_PBE_IMPORT = CKM_PKCS12_PBE_IMPORT,
	};

	/// <summary>
	/// Type of sign/verify mechanism.
	/// </summary>
	public enum class SignMechanism
	{
		/// <summary>
		/// CKM_ARIA_MAC
		/// </summary>
		ARIA_MAC = CKM_ARIA_MAC,

		/// <summary>
		/// CKM_ARIA_MAC_GENERAL
		/// </summary>
		ARIA_MAC_GENERAL = CKM_ARIA_MAC_GENERAL,

		/// <summary>
		/// CKM_AES_MAC, denoted by AES_MAC, is a special case of the general-length AES-MAC mechanism.
		/// <para>AES_MAC always produces and verifies MACs that are half the block size in length. It does not have a parameter.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: AES] - [Data Length: Any] - [Signature Length: 1/2 block size (8 bytes)]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: AES] - [Data Length: ‍Any] - [Signature Length: 1/2 block size (8 bytes)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_MAC = CKM_AES_MAC,

		/// <summary>
		/// General-length AES_MAC, denoted AES_MAC_GENERAL, is a mechanism for single- and multiple-part signatures and verification, based on NIST Advanced Encryption Standard.
		/// <para>It has a parameter, a 'MAC_GENERAL_PARAMS' structure, which specifies the output length desired from the mechanism.</para>
		/// <para>The output bytes from this mechanism are taken from the start of the final AES cipher block produced in the MACing process.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: AES] - [Data Length: Any] - [Signature Length: 0-block size, as specified in parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: AES] - [Data Length: ‍Any] - [Signature Length: 0-block size, as specified in parameters]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_MAC_GENERAL = CKM_AES_MAC_GENERAL,

		/// <summary>
		/// Cipher CAST128 has a MACing mechanism, CAST128-MAC, denoted CAST128_MAC. This mechanism is a special case of the CAST128_MAC_GENERAL mechanism. It always produces an output of size half as large as CAST128's block-size.
		/// <para>This mechanism has no parameters.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: CAST128] - [Data Length: Any] - [Signature Length: floor(block-size/2)]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: CAST128] - [Data Length: Any] - [Signature Length: floor(block-size/2)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST128_MAC = CKM_CAST128_MAC,

		/// <summary>
		/// Cipher CAST128 has a general-length MACing mode, General-length CAST128-MAC, denoted CAST128_MAC_GENERAL.
		/// <para>It is a mechanism for single- and multiple-part signatures and verification, based on the CAST128 encryption algorithm and data authentication as defined in FIPS PUB 113.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which specifies the size of the output.</para>
		/// <para>The output bytes from this mechanism are taken from the start of the final cipher block produced in the MACing process.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: CAST128] - [Data Length: Any] - [Signature Length: 0-block-size, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: CAST128] - [Data Length: Any] - [Signature Length: 0-block-size, depending on parameters]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used. The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		CAST128_MAC_GENERAL = CKM_CAST128_MAC_GENERAL,

		/// <summary>
		/// Cipher DES has a MACing mechanism, DES-MAC, denoted DES_MAC. This mechanism is a special case of the DES_MAC_GENERAL mechanism. It always produces an output of size half as large as DES's block-size.
		/// <para>This mechanism has no parameters.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: DES] - [Data Length: Any] - [Signature Length: floor(block-size/2)]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: DES] - [Data Length: Any] - [Signature Length: floor(block-size/2)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES_MAC = CKM_DES_MAC,

		/// <summary>
		/// Cipher DES has a general-length MACing mode, General-length DES-MAC, denoted DES_MAC_GENERAL.
		/// <para>It is a mechanism for single- and multiple-part signatures and verification, based on the DES encryption algorithm and data authentication as defined in FIPS PUB 113.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which specifies the size of the output.</para>
		/// <para>The output bytes from this mechanism are taken from the start of the final cipher block produced in the MACing process.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: DES] - [Data Length: Any] - [Signature Length: 0-block-size, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: DES] - [Data Length: Any] - [Signature Length: 0-block-size, depending on parameters]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used. The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES_MAC_GENERAL = CKM_DES_MAC_GENERAL,

		/// <summary>
		/// Cipher DES3 has a MACing mechanism, DES3-MAC, denoted DES3_MAC. This mechanism is a special case of the DES3_MAC_GENERAL mechanism. It always produces an output of size half as large as DES3's block-size.
		/// <para>This mechanism has no parameters.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: DES3] - [Data Length: Any] - [Signature Length: floor(block-size/2)]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: DES3] - [Data Length: Any] - [Signature Length: floor(block-size/2)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES3_MAC = CKM_DES3_MAC,

		/// <summary>
		/// Cipher DES3 has a general-length MACing mode, General-length DES3-MAC, denoted DES3_MAC_GENERAL.
		/// <para>It is a mechanism for single- and multiple-part signatures and verification, based on the DES3 encryption algorithm and data authentication as defined in FIPS PUB 113.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which specifies the size of the output.</para>
		/// <para>The output bytes from this mechanism are taken from the start of the final cipher block produced in the MACing process.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: DES3] - [Data Length: Any] - [Signature Length: 0-block-size, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: DES3] - [Data Length: Any] - [Signature Length: 0-block-size, depending on parameters]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used. The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		DES3_MAC_GENERAL = CKM_DES3_MAC_GENERAL,

		/// <summary>
		/// The DSA without hashing mechanism, denoted DSA, is a mechanism for single-part signatures
		/// <para>and verification based on the Digital Signature Algorithm defined in FIPS PUB 186-2.</para>
		/// <para>This mechanism corresponds only to the part of DSA that processes the 20-byte hash value; it does not compute the hash value.</para>
		/// <para>For the purposes of this mechanism, a DSA signature is a 40-byte string, corresponding to the concatenation of the DSA values r and s, each represented most-significant byte first.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: DSA private key] - [Data Length: 20] - [Signature Length: 40]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: DSA public key] - [Data Length: ‍‍20, 40] - [Signature Length: N/A]</para>
		/// <para>For this mechanism, the ulMinKeySize and ulMaxKeySize fields of the MECHANISM_INFO structure specify the supported range of DSA prime sizes, in bits.</para>
		/// </summary>
		DSA = CKM_DSA,

		/// <summary>
		/// The DSA with SHA-1 mechanism, denoted DSA_SHA1, is a mechanism for single- and multiple-part signatures and verification based on the Digital Signature Algorithm defined in FIPS PUB 186-2.
		/// <para>This mechanism computes the entire DSA specification, including the hashing with SHA-1.</para>
		/// <para>For the purposes of this mechanism, a DSA signature is a 40-byte string, corresponding to the concatenation of the DSA values r and s, each represented most-significant byte first.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: DSA private key] - [Data Length: Any] - [Signature Length: 40]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: DSA public key] - [Data Length: Any, 40] - [Signature Length: N/A]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of DSA prime sizes, in bits.</para>
		/// </summary>
		DSA_SHA1 = CKM_DSA_SHA1,

		/// <summary>
		/// The ECDSA without hashing mechanism, denoted ECDSA, is a mechanism for single-part signatures and verification for ECDSA.
		/// <para>This mechanism corresponds only to the part of ECDSA that processes the hash value, which should not be longer than 1024 bits; it does not compute the hash value.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: ECDSA private key] - [Data Length: Any] - [Signature Length: 2nLen]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: ECDSA public key] - [Data Length: ‍Any, ≤2nLen] - [Signature Length: N/A]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the minimum and maximum supported number of bits in the field sizes, respectively.</para>
		/// <para>For example, if a Cryptoki library supports only ECDSA using a field of characteristic 2 which has between 2^200 and 2^300 elements(inclusive),</para>
		/// <para>then ulMinKeySize = 201 and ulMaxKeySize = 301 (when written in binary notation, the number 2^200 consists of a 1 bit followed by 200 0 bits. It is therefore a 201-bit number. Similarly, 2^300 is a 301-bit number).</para>
		/// </summary>
		ECDSA = CKM_ECDSA,

		/// <summary>
		/// The ECDSA with SHA-1 mechanism, denoted ECDSA_SHA1, is a mechanism for single- and multiple-part signatures and verification for ECDSA.
		/// <para>This mechanism computes the entire ECDSA specification, including the hashing with SHA-1.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: ECDSA private key] - [Data Length: Any] - [Signature Length: 2nLen]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: ECDSA public key] - [Data Length: Any, ≤2nLen] - [Signature Length: N/A]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the minimum and maximum supported number of bits in the field sizes, respectively.</para>
		/// <para>For example, if a Cryptoki library supports only ECDSA using a field of characteristic 2 which has between 2^200 and 2^300 elements,</para>
		/// <para>then ulMinKeySize = 201 and ulMaxKeySize = 301 (when written in binary notation, the number 2^200 consists of a 1 bit followed by 200 0 bits. It is therefore a 201-bit number. Similarly, 2^300 is a 301-bit number).</para>
		/// </summary>
		ECDSA_SHA1 = CKM_ECDSA_SHA1,

		/// <summary>
		/// Cipher IDEA has a MACing mechanism, IDEA-MAC, denoted IDEA_MAC. This mechanism is a special case of the IDEA_MAC_GENERAL mechanism. It always produces an output of size half as large as IDEA's block-size.
		/// <para>This mechanism has no parameters.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: IDEA] - [Data Length: Any] - [Signature Length: floor(block-size/2)]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: IDEA] - [Data Length: Any] - [Signature Length: floor(block-size/2)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used.</para>
		/// <para>The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		IDEA_MAC = CKM_IDEA_MAC,

		/// <summary>
		/// Cipher IDEA has a general-length MACing mode, General-length IDEA-MAC, denoted IDEA_MAC_GENERAL.
		/// <para>It is a mechanism for single- and multiple-part signatures and verification, based on the IDEA encryption algorithm and data authentication as defined in FIPS PUB 113.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which specifies the size of the output.</para>
		/// <para>The output bytes from this mechanism are taken from the start of the final cipher block produced in the MACing process.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: IDEA] - [Data Length: Any] - [Signature Length: 0-block-size, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: IDEA] - [Data Length: Any] - [Signature Length: 0-block-size, depending on parameters]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure may or may not be used. The CAST, CAST3, and CAST128 (CAST5) ciphers have variable key sizes, and so for these ciphers, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of key sizes, in bytes.</para>
		/// <para>For the DES, DES3 (triple-DES), IDEA, and CDMF ciphers, these fields are not used.</para>
		/// </summary>
		IDEA_MAC_GENERAL = CKM_IDEA_MAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA mechanism, denoted RSA_PKCS, is a multi-purpose mechanism based on the RSA public-key crypto-system and the block formats initially defined in PKCS #1 v1.5.
		/// <para>It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping.</para>
		/// <para>This mechanism corresponds only to the part of PKCS #1 v1.5 that involves RSA; it does not compute a message digest or a DigestInfo encoding as specified for the md2withRSAEncryption and md5withRSAEncryption algorithms in PKCS #1 v1.5 .</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data are summarized in the following table.</para>
		/// <para>For encryption, decryption, signatures and signature verification, the input and output data may begin at the same location in memory.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: ≤k-11] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_SignRecover] - [Key Type: RSA private key] - [Data Length: ≤k-11] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: ≤k-11, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_VerifyRecover] - [Key Type: RSA public key] - [Data Length: k] - [Signature Length: ≤k-11] - [Comments: block type 01]</para>
		/// </summary>
		RSA_PKCS = CKM_RSA_PKCS,

		/// <summary>
		/// The ISO/IEC 9796 RSA mechanism, denoted RSA_9796, is a mechanism for single-part signatures and verification with and without message recovery based on the RSA public-key crypto-system and the block formats defined in ISO/IEC 9796 and its annex A.
		/// <para>This mechanism processes only byte strings, whereas ISO/IEC 9796 operates on bit strings.</para>
		/// <para>Accordingly, the following transformations are performed:</para>
		/// <para>- Data is converted between byte and bit string formats by interpreting the most significant bit of the leading byte of the byte string as the leftmost bit of the bit string, and the least-significant bit of the trailing byte of the byte string as the rightmost bit of the bit string (this assumes the length in bits of the data is a multiple of 8).</para>
		/// <para>- A signature is converted from a bit string to a byte string by padding the bit string on the left with 0 to 7 zero bits so that the resulting length in bits is a multiple of 8, and converting the resulting bit string as above; it is converted from a byte string to a bit string by converting the byte string as above, and removing bits from the left so that the resulting length in bits is the same as that of the RSA modulus.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: ≤floor(k/2)] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_SignRecover] - [Key Type: RSA private key] - [Data Length: floor(≤k/2)] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: floor(≤k/2), k^2] - [Signature Length: N/A]</para>
		/// <para>[Function:‍ C_VerifyRecover] - [Key Type: RSA public key] - [Data Length: k] - [Signature Length: floor(≤k/2)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		RSA_9796 = CKM_RSA_9796,

		/// <summary>
		/// The X.509 (raw) RSA mechanism, denoted RSA_X_509, is a multi-purpose mechanism based on the RSA public-key crypto-system.
		/// <para>It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping.</para>
		/// <para>All these operations are based on so called "raw" RSA, as assumed in X.509.</para>
		/// <para>"Raw" RSA as defined here encrypts a byte string by converting it to an integer, most significant byte first, applying "raw" RSA exponentiation, and converting the result to a byte string, most-significant byte first.</para>
		/// <para>The input string, considered as an integer, must be less than the modulus; the output string is also less than the modulus.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key of appropriate length. Of course, a particular token may not be able to wrap/unwrap every appropriate-length secret key that it supports.</para>
		/// <para>For wrapping, the "input" to the encryption operation is the value of the 'VALUE' attribute of the key that is wrapped; similarly for unwrapping.</para>
		/// <para>The mechanism does not wrap the key type, key length, or any other information about the key; the application must convey these separately, and supply them when unwrapping the key.</para>
		/// <para>Unfortunately, X.509 does not specify how to perform padding for RSA encryption.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RSA public key] - [Data Length: ≤k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RSA private key] - [Data Length: k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: ≤k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_SignRecover] - [Key Type: RSA private key] - [Data Length: ≤k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: ≤k, k^2] - [Signature Length: N/A]</para>
		/// <para>[Function:‍ C_VerifyRecover] - [Key Type: RSA public key] - [Data Length: k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RSA public key] - [Data Length: ≤k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RSA private key] - [Data Length: k] - [Signature Length: ≤k (specified in template)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// <para>This mechanism is intended for compatibility with applications that do not follow the PKCS #1 or ISO/IEC 9796 block formats.</para>
		/// </summary>
		RSA_X_509 = CKM_RSA_X_509,

		/// <summary>
		/// RC2-MAC, denoted by RC2_MAC, is a special case of the general-length RC2-MAC mechanism.
		/// <para>This mechanism does not have a parameter. Instead of taking a RC2_MAC_GENERAL_PARAMS parameter, it takes a RC2_PARAMS parameter, which only contains the effective number of bits in the RC2 search space.</para>
		/// <para>RC2-MAC always produces and verifies 4-byte MACs.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RC2] - [Data Length: Any] - [Signature Length: 4]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RC2] - [Data Length: Any] - [Signature Length: 4]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 effective number of bits.</para>
		/// </summary>
		RC2_MAC = CKM_RC2_MAC,

		/// <summary>
		/// General-length RC2-MAC, denoted RC2_MAC_GENERAL, is a mechanism for single- and multiple-part signatures and verification, based on RSA Security's block cipher RC2 and data authentication as defined in FIPS PUB 113.
		/// <para>It has a parameter, a RC2_MAC_GENERAL_PARAMS structure, which specifies the effective number of bits in the RC2 search space and the output length desired from the mechanism.</para>
		/// <para>The output bytes from this mechanism are taken from the start of the final RC2 cipher block produced in the MACing process.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RC2] - [Data Length: Any] - [Signature Length: 0-8, as specified in parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RC2] - [Data Length: Any] - [Signature Length: 0-8, as specified in parameters]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 effective number of bits.</para>
		/// </summary>
		RC2_MAC_GENERAL = CKM_RC2_MAC_GENERAL,

		/// <summary>
		/// The MD2-HMAC mechanism, denoted MD2_HMAC, is a special case of the general-length MD2-HMAC mechanism.
		/// <para>It has no parameter, and always produces an output of length 16.</para>
		/// </summary>
		MD2_HMAC = CKM_MD2_HMAC,

		/// <summary>
		/// The general-length MD2-HMAC mechanism, denoted MD2_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the MD2 hash function. The keys it uses are generic secret keys.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-16 (the output size of MD2 is 16 bytes).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 16-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-16, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-16, depending on parameters]</para>
		/// </summary>
		MD2_HMAC_GENERAL = CKM_MD2_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with MD2 mechanism, denoted MD2_RSA_PKCS, performs single- and multiple-part digital signatures and verification operations without message recovery.
		/// <para>The operations performed are as described initially in PKCS #1 v1.5 with the object identifier md2WithRSAEncryption, and as in the scheme RSASSA-PKCS1-v1_5 in the current version of PKCS #1, where the underlying hash function is MD2.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		MD2_RSA_PKCS = CKM_MD2_RSA_PKCS,

		/// <summary>
		/// The MD5-HMAC mechanism, denoted MD5_HMAC, is a special case of the general-length MD5-HMAC mechanism.
		/// <para>It has no parameter, and always produces an output of length 16.</para>
		/// </summary>
		MD5_HMAC = CKM_MD5_HMAC,

		/// <summary>
		/// The general-length MD5-HMAC mechanism, denoted MD5_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the MD5 hash function. The keys it uses are generic secret keys.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-16 (the output size of MD5 is 16 bytes).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 16-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-16, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-16, depending on parameters]</para>
		/// </summary>
		MD5_HMAC_GENERAL = CKM_MD5_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with MD5 mechanism, denoted MD5_RSA_PKCS, performs single- and multiple-part digital signatures and verification operations without message recovery in PKCS #1 with the object identifier md5WithRSAEncryption.
		/// <para>he PKCS #1 v1.5 RSA signature with SHA-1 mechanism, denoted SHA1_RSA_PKCS, performs the same operations, except that it uses the hash function SHA-1 with object identifier sha1WithRSAEncryption.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		MD5_RSA_PKCS = CKM_MD5_RSA_PKCS,

		/// <summary>
		/// MD5 MACing in SSL3.0, denoted SSL3_MD5_MAC, is a mechanism for single- and multiple-part signatures (data authentication) and verification using MD5, based on the SSL 3.0 protocol.
		/// <para>This technique is very similar to the HMAC technique.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which specifies the length in bytes of the signatures produced by this mechanism.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 4-8, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 4-8, depending on parameters]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of generic secret key sizes, in bits.</para>
		/// </summary>
		SSL3_MD5_MAC = CKM_SSL3_MD5_MAC,

		/// <summary>
		/// SHA-1 MACing in SSL3.0, denoted SSL3_SHA1_MAC, is a mechanism for single- and multiple-part signatures (data authentication) and verification using SHA-1, based on the SSL 3.0 protocol.
		/// <para>This technique is very similar to the HMAC technique.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which specifies the length in bytes of the signatures produced by this mechanism.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 4-8, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 4-8, depending on parameters]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of generic secret key sizes, in bits.</para>
		/// </summary>
		SSL3_SHA1_MAC = CKM_SSL3_SHA1_MAC,

		/// <summary>
		/// The SHA-1-HMAC mechanism, denoted SHA_1_HMAC, is a special case of the general-length SHA-1-HMAC mechanism
		/// <para>It has no parameter, and always produces an output of length 20.</para>
		/// </summary>
		SHA_1_HMAC = CKM_SHA_1_HMAC,

		/// <summary>
		/// The general-length SHA-1-HMAC mechanism, denoted SHA_1_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the SHA-1 hash function.</para>
		/// <para>The keys it uses are generic secret keys.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-20 (the output size of SHA-1 is 20 bytes).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 20-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-20, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-20, depending on parameters]</para>
		/// </summary>
		SHA_1_HMAC_GENERAL = CKM_SHA_1_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with SHA-1 mechanism, denoted SHA1_RSA_PKCS performs single- and multiple-part digital signatures and verification operations without message recovery using the SHA-1 hash function with the object identifier sha1WithRSAEncryption.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		SHA1_RSA_PKCS = CKM_SHA1_RSA_PKCS,

		/// <summary>
		/// The SHA-224-HMAC mechanism, denoted SHA224_HMAC, is a special case of the general-length SHA-224-HMAC mechanism
		/// <para>It has no parameter, and always produces an output of length 28.</para>
		/// </summary>
		SHA_224_HMAC = CKM_SHA224_HMAC,

		/// <summary>
		/// The general-length SHA-224-HMAC mechanism, denoted SHA224_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the SHA-224 hash function.</para>
		/// <para>The keys it uses are generic secret keys.</para>
		/// <para>FIPS-198 compliant tokens may require the key length to be at least 16 bytes; that is, half the size of the SHA-224 hash output.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-28 (the output size of SHA-224 is 28 bytes).</para>
		/// <para>FIPS-198 compliant tokens may constrain the output length to be at least 4 or 16 (half the maximum length).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 28-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-28, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-28, depending on parameters]</para>
		/// </summary>
		SHA_224_HMAC_GENERAL = CKM_SHA224_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with SHA-224, SHA-256, SHA-384, and SHA-512 mechanisms, denoted SHA224_RSA_PKCS, SHA256_RSA_PKCS, SHA384_RSA_PKCS, and SHA512_RSA_PKCS respectively, performs single- and multiple-part digital signatures and verification operations without message recovery using the SHA-224, SHA-256, SHA-384 and SHA-512 hash functions with the object identifiers sha256WithRSAEncryption, sha384WithRSAEncryption and sha384WithRSAEncryption respectively.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		SHA224_RSA_PKCS = CKM_SHA224_RSA_PKCS,

		/// <summary>
		/// The SHA-256-HMAC mechanism, denoted SHA256_HMAC, is a special case of the general-length SHA-256-HMAC mechanism
		/// <para>It has no parameter, and always produces an output of length 32.</para>
		/// </summary>
		SHA_256_HMAC = CKM_SHA256_HMAC,

		/// <summary>
		/// The general-length SHA-256-HMAC mechanism, denoted SHA256_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the SHA-256 hash function.</para>
		/// <para>The keys it uses are generic secret keys.</para>
		/// <para>FIPS-198 compliant tokens may require the key length to be at least 16 bytes; that is, half the size of the SHA-256 hash output.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-32 (the output size of SHA-256 is 32 bytes).</para>
		/// <para>FIPS-198 compliant tokens may constrain the output length to be at least 4 or 16 (half the maximum length).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 32-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-32, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-32, depending on parameters]</para>
		/// </summary>
		SHA_256_HMAC_GENERAL = CKM_SHA256_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with SHA-224, SHA-256, SHA-384, and SHA-512 mechanisms, denoted SHA224_RSA_PKCS, SHA256_RSA_PKCS, SHA384_RSA_PKCS, and SHA512_RSA_PKCS respectively, performs single- and multiple-part digital signatures and verification operations without message recovery using the SHA-224, SHA-256, SHA-384 and SHA-512 hash functions with the object identifiers sha256WithRSAEncryption, sha384WithRSAEncryption and sha384WithRSAEncryption respectively.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		SHA256_RSA_PKCS = CKM_SHA256_RSA_PKCS,

		/// <summary>
		/// The SHA-384-HMAC mechanism, denoted SHA384_HMAC, is a special case of the general-length SHA-384-HMAC mechanism.
		/// <para>It has no parameter, and always produces an output of length 48.</para>
		/// </summary>
		SHA384_HMAC = CKM_SHA384_HMAC,

		/// <summary>
		/// The general-length SHA-384-HMAC mechanism, denoted SHA384_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the SHA-384 hash function.</para>
		/// <para>The keys it uses are generic secret keys.</para>
		/// <para>FIPS-198 compliant tokens may require the key length to be at least 16 bytes; that is, half the size of the SHA-384 hash output.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-48 (the output size of SHA-384 is 48 bytes).</para>
		/// <para>FIPS-198 compliant tokens may constrain the output length to be at least 4 or 16 (half the maximum length).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 48-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-48, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-48, depending on parameters]</para>
		/// </summary>
		SHA384_HMAC_GENERAL = CKM_SHA384_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with SHA-224, SHA-256, SHA-384, and SHA-512 mechanisms, denoted SHA224_RSA_PKCS, SHA256_RSA_PKCS, SHA384_RSA_PKCS, and SHA512_RSA_PKCS respectively, performs single- and multiple-part digital signatures and verification operations without message recovery using the SHA-224, SHA-256, SHA-384 and SHA-512 hash functions with the object identifiers sha256WithRSAEncryption, sha384WithRSAEncryption and sha384WithRSAEncryption respectively.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		SHA384_RSA_PKCS = CKM_SHA384_RSA_PKCS,

		/// <summary>
		/// The SHA-512-HMAC mechanism, denoted SHA512_HMAC, is a special case of the general-length SHA-512-HMAC mechanism.
		/// <para>It has no parameter, and always produces an output of length 64.</para>
		/// </summary>
		SHA512_HMAC = CKM_SHA512_HMAC,

		/// <summary>
		/// The general-length SHA-512-HMAC mechanism, denoted SHA512_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the SHA-512 hash function.</para>
		/// <para>The keys it uses are generic secret keys.</para>
		/// <para>FIPS-198 compliant tokens may require the key length to be at least 16 bytes; that is, half the size of the SHA-512 hash output.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-64 (the output size of SHA-512 is 64 bytes).</para>
		/// <para>FIPS-198 compliant tokens may constrain the output length to be at least 4 or 16 (half the maximum length).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 64-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-64, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-64, depending on parameters]</para>
		/// </summary>
		SHA512_HMAC_GENERAL = CKM_SHA512_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with SHA-224, SHA-256, SHA-384, and SHA-512 mechanisms, denoted SHA224_RSA_PKCS, SHA256_RSA_PKCS, SHA384_RSA_PKCS, and SHA512_RSA_PKCS respectively, performs single- and multiple-part digital signatures and verification operations without message recovery using the SHA-224, SHA-256, SHA-384 and SHA-512 hash functions with the object identifiers sha256WithRSAEncryption, sha384WithRSAEncryption and sha384WithRSAEncryption respectively.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		SHA512_RSA_PKCS = CKM_SHA512_RSA_PKCS,

		/// <summary>
		/// The PKCS #1 RSA PSS signature with SHA-224 mechanism, denoted SHA224_RSA_PKCS_PSS, performs single- and multiple-part digital signatures and verification operations without message recovery.
		/// <para>The operations performed are as described in PKCS #1 with the object identifier id-RSASSA-PSS, i.e., as in the scheme RSASSA-PSS in PKCS #1 where the underlying hash function is SHA-224.</para>
		/// <para>The mechanisms have a parameter, a RSA_PKCS_PSS_PARAMS structure.</para>
		/// <para>The sLen field must be less than or equal to k*-2-hLen where hLen is the length in bytes of the hash value.</para>
		/// <para>k* is the length in bytes of the RSA modulus, except if the length in bits of the RSA modulus is one more than a multiple of 8, in which case k* is one less than the length in bytes of the RSA modulus.</para>
		/// <para>Constraints on key types and the length of the data are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA private key] - [Data Length: Any, k^2] - [Signature Length: N/A]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		SHA224_RSA_PKCS_PSS = CKM_SHA224_RSA_PKCS_PSS,

		/// <summary>
		/// The RIPE-MD 128-HMAC mechanism, denoted RIPEMD128_HMAC, is a special case of the general-length RIPE-MD 128-HMAC mechanism.
		/// <para>It has no parameter, and always produces an output of length 16.</para>
		/// </summary>
		RIPEMD128_HMAC = CKM_RIPEMD128_HMAC,

		/// <summary>
		/// The general-length RIPE-MD 128-HMAC mechanism, denoted RIPEMD128_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the RIPE-MD 128 hash function.</para>
		/// <para>The keys it uses are generic secret keys.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-16 (the output size of RIPEMD 128 is 16 bytes).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 16-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-16, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-16, depending on parameters]</para>
		/// </summary>
		RIPEMD128_HMAC_GENERAL = CKM_RIPEMD128_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with RIPEMD-128 or RIPEMD-160, denoted RIPEMD128_RSA_PKCS and RIPEMD160_RSA_PKCS respectively, performs single- and multiple-part digital signatures and verification operations without message recovery using the RIPE-MD 128 and RIPE-MD 160 hash functions.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		RIPEMD128_RSA_PKCS = CKM_RIPEMD128_RSA_PKCS,

		/// <summary>
		/// The RIPE-MD 160-HMAC mechanism, denoted RIPEMD160_HMAC, is a special case of the general-length RIPE-MD 160-HMAC mechanism
		/// <para>It has no parameter, and always produces an output of length 20.</para>
		/// </summary>
		RIPEMD160_HMAC = CKM_RIPEMD160_HMAC,

		/// <summary>
		/// The general-length RIPE-MD 160-HMAC mechanism, denoted RIPEMD160_HMAC_GENERAL, is a mechanism for signatures and verification.
		/// <para>It uses the HMAC construction, based on the RIPE-MD 160 hash function.</para>
		/// <para>The keys it uses are generic secret keys.</para>
		/// <para>It has a parameter, a MAC_GENERAL_PARAMS, which holds the length in bytes of the desired output.</para>
		/// <para>This length should be in the range 0-20 (the output size of RIPEMD 160 is 20 bytes).</para>
		/// <para>Signatures (MACs) produced by this mechanism will be taken from the start of the full 20-byte HMAC output.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-20, depending on parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: generic secret] - [Data Length: Any] - [Signature Length: 0-20, depending on parameters]</para>
		/// </summary>
		RIPEMD160_HMAC_GENERAL = CKM_RIPEMD160_HMAC_GENERAL,

		/// <summary>
		/// The PKCS #1 v1.5 RSA signature with RIPEMD-128 or RIPEMD-160, denoted RIPEMD128_RSA_PKCS and RIPEMD160_RSA_PKCS respectively, performs single- and multiple-part digital signatures and verification operations without message recovery using the RIPE-MD 128 and RIPE-MD 160 hash functions.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data for these mechanisms are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>For the PKCS #1 v1.5 RSA signature with MD2 and PKCS #1 v1.5 RSA signature with MD5 mechanisms, k must be at least 27; for the PKCS #1 v1.5 RSA signature with SHA-1 mechanism, k must be at least 31, and so on for other underlying hash functions, where the minimum is always 11 bytes more than the length of the hash value.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: Any] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: Any, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		RIPEMD160_RSA_PKCS = CKM_RIPEMD160_RSA_PKCS,

		///
		/// There are a number of additional SafeNet vendor defined sing/verify mechanisms.
		///

#ifndef _PTKC_V400_
		/// <summary>
		/// The ECDSA with SHA-224 mechanism, denoted ECDSA_SHA224, is a SafeNet vendor defined mechanism for single- and multiple-part signatures and verification for ECDSA.
		/// <para>This mechanism computes the entire ECDSA specification, including the hashing with SHA-224.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		ECDSA_SHA224 = CKM_ECDSA_SHA224,

		/// <summary>
		/// The ECDSA with SHA-256 mechanism, denoted ECDSA_SHA256, is a SafeNet vendor defined mechanism for single- and multiple-part signatures and verification for ECDSA.
		/// <para>This mechanism computes the entire ECDSA specification, including the hashing with SHA-256.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		ECDSA_SHA256 = CKM_ECDSA_SHA256,

		/// <summary>
		/// The ECDSA with SHA-384 mechanism, denoted ECDSA_SHA384, is a SafeNet vendor defined mechanism for single- and multiple-part signatures and verification for ECDSA.
		/// <para>This mechanism computes the entire ECDSA specification, including the hashing with SHA-384.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		ECDSA_SHA384 = CKM_ECDSA_SHA384,

		/// <summary>
		/// The ECDSA with SHA-512 mechanism, denoted ECDSA_SHA512, is a SafeNet vendor defined mechanism for single- and multiple-part signatures and verification for ECDSA.
		/// <para>This mechanism computes the entire ECDSA specification, including the hashing with SHA-512.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		ECDSA_SHA512 = CKM_ECDSA_SHA512,
#endif

		/// <summary>
		/// The SafeNet vendor defined PKCS #1 DSA signature with SHA-1 mechanism, denoted DSA_SHA1_PKCS, performs single and multiple - part digital signature and verification operations without message recovery.
		/// <para>The operations performed are as described in PKCS #1 with the object identifier sha1WithDSAEncryption.</para>
		/// <para>It is similar to the PKCS#11 mechanism RSA_SHA1_PKCS except DSA is used instead of RSA.This mechanism has no parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		DSA_SHA1_PKCS = CKM_DSA_SHA1_PKCS,

		/// <summary>
		/// This is a SafeNet vendor defined signature generation and verification mechanism. The produced MAC is 8 bytes in length. It is an extension of the single length key MAC mechanisms.
		/// <para>It takes an 8 byte IV as a parameter, which is encrypted (ECB mode) with the left most key value before the first data block is MAC'ed.</para>
		/// <para>The data, which must be a multiple of 8 bytes, is MAC'ed with the left most key value in the normal manner, but the final cipher block is then decrypted (ECB mode) with the middle key value and encrypted (ECB mode) with the Right most key part.</para>
		/// <para>For double length DES keys, the Right key component is the same as the Left key component.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		DES3_RETAIL_CFB_MAC = CKM_DES3_RETAIL_CFB_MAC,

		/// <summary>
		/// DES3_X919_MAC and DES3_X919_MAC_GENERAL are SafeNet vendor defined signature generation and verification mechanisms, as defined by ANSI X9.19. They are an extension of the single length key MAC mechanisms.
		/// <para>The data is MAC‘ed with the left most key value in the normal manner, but the final cipher block is then decrypted (ECB mode) with the middle key value and encrypted (ECB mode) with the Right most key part.</para>
		/// <para>For double length keys, the Right key component is the same as the Left key component.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		DES3_X919_MAC = CKM_DES3_X919_MAC,

		/// <summary>
		/// DES3_X919_MAC and DES3_X919_MAC_GENERAL are SafeNet vendor defined signature generation and verification mechanisms, as defined by ANSI X9.19. They are an extension of the single length key MAC mechanisms.
		/// <para>The data is MAC‘ed with the left most key value in the normal manner, but the final cipher block is then decrypted (ECB mode) with the middle key value and encrypted (ECB mode) with the Right most key part.</para>
		/// <para>For double length keys, the Right key component is the same as the Left key component.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		DES3_X919_MAC_GENERAL = CKM_DES3_X919_MAC_GENERAL,

		/// <summary>
		/// FW Upgrading mechanism. Used in C_VerifyInit/C_VerifyUpdate/C_VerifyFinal functions.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		FM_DOWNLOAD = CKM_FM_DOWNLOAD,

#ifndef _PTKC_V400_
		/// <summary>
		/// FW Upgrading mechanism. Used in C_VerifyInit/C_VerifyUpdate/C_VerifyFinal functions.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		FM_DOWNLOAD_2 = CKM_FM_DOWNLOAD_2,
#endif
		/// <summary>
		/// FW Upgrading mechanism. Used in C_VerifyInit/C_VerifyUpdate/C_VerifyFinal functions.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		OS_UPGRADE = CKM_OS_UPGRADE,

#ifndef _PTKC_V400_
		/// <summary>
		/// FW Upgrading mechanism. Used in C_VerifyInit/C_VerifyUpdate/C_VerifyFinal functions.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism is a vendor defined extension mechanism.</para>
		/// </summary>
		OS_UPGRADE_2 = CKM_OS_UPGRADE_2,
#endif

		/// <summary>
		/// SafeNet vendor defined SEED-MAC, denoted by SEED_MAC, is a special case of the general-length SEEDMAC mechanism.
		/// <para>SEED-MAC always produces and verifies MACs that are eight bytes in length.</para>
		/// <para>It does not have a parameter.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: SEED] - [Data Length: Any] - [Signature Length: 1/2 block size (8 bytes)]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: SEED] - [Data Length: Any] - [Signature Length: 1/2 block size (8 bytes)]</para>
		/// </summary>
		SEED_MAC = CKM_SEED_MAC,

		/// <summary>
		/// General-length SEED-MAC, denoted SEED_MAC_GENERAL, is a SafeNet vendor defined mechanism for single and multiple part signatures and verification, based on the KISA (Korean Information Security Agency) SEED specification.
		/// <para>It has a single parameter, a MAC_GENERAL_PARAMS structure, which specifies the output length desired from the mechanism.</para>
		/// <para>The output bytes from this mechanism are taken from the start of the final SEED cipher block produced in the MACing process.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: SEED] - [Data Length: Any] - [Signature Length: 0-block size, as specified in parameters]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: SEED] - [Data Length: Any] - [Signature Length: 0-block size, as specified in parameters]</para>
		/// </summary>
		SEED_MAC_GENERAL = CKM_SEED_MAC_GENERAL,

		/// <summary>
		/// This is a SafeNet vendor defined signature generation and verification method. The Card Verification Value signature is generated as specified by VISA.
		/// <para>The mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of data are summarized in the following table:</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: DES2] - [Data Length: 16] - [Signature Length: 2]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: DES2] - [Data Length: 16, 2] - [Signature Length: N/A]</para>
		/// </summary>
		VISA_CVV = CKM_VISA_CVV,

		/// <summary>
		/// The SafeNet vendor defined PKCS#11 mechanism SHA1_RSA_PKCS_TIMESTAMP provides time stamping functionality. The supported signing functions are C_Sign_Init and C_Sign.
		/// <para>This mechanism supports single and multiple-part digital signatures and verification with message recovery.</para>
		/// <para>The mechanism uses the SHA1 hash function to generate the message digest.</para>
		/// <para>It has a parameter, a TIMESTAMP_PARAMS structure.</para>
		/// <para>If the mechanism parameters are specified then the timeStampType parameter must be set to TIMESTAMP_FORMAT_PTKC as only this format is supported in the first release.</para>
		/// <para>The mechanism only supports one second granularity in the timestamp although the timestamp format will provide for future sub-second granularity.</para>
		/// <para>A monotonic counter object is used to generate the unique serial number that forms part of the timestamp.</para>
		/// <para>The monotonic counter object is automatically created when a token is initialized and exists by default in the Admin Token.</para>
		/// <para>The parameter formats are defined the following:</para>
		/// <para>Input format:</para>
		/// <para>- Data: Transaction data (variable length), maximum of 3k</para>
		/// <para>Output format:</para>
		/// <para>- serialnumber[20]: This is a unique number for each timestamp, padded with zeroes in a Big Endian 20 byte array. The number is read from the CKH_MONOTONIC_COUNTER hardware feature object on the same token as the signing key. By this read action the value contained by the object is automatically increased by 1.</para>
		/// <para>- timestamp[15]: This is the timestamp in the format of GeneralizedTime specified in RFC3161. The syntax is: YYYYMMDDhhmmss[.s...]Z The sub-second component is optional and not supported in the intial release but still defined to ensure backward compatibility in the future.</para>
		/// <para>- sign[128]: RSA Signature.</para>
		/// <para>NOTE 1: Please see the PKCS#11 v2.10: Cryptographic Token Interface Standard, RSA Laboratories December 1999 for a definition of types.</para>
		/// <para>NOTE 2: It is highly recommended that the RFC3161 format timestamp provided by the HSM be stored on the host to allow future independent third party timestamp verification.</para>
		/// <para>The mechanism will perform the following:</para>
		/// <para>- Input data that is provided by the calling host.</para>
		/// <para>- Obtain the time from within the ProtectHost.</para>
		/// <para>- Calculate a signature across the merged input data and time data using PKCS#1 type 01 padding as follows: Signature = Sign(SHA1(Data || serialnumber || timestamp)</para>
		/// <para>- Output part of the input data, the time data and the signature.</para>
		/// <para>Verification of the signature can be performed using the SHA1_RSA_PKCS_TIMESTAMP mechanism with Verify or VerifyRecover.</para>
		/// <para>The difference between the two functions is that C_Verify calculates the hash but does not return it to the caller where as C_VerifyRecover() returns the hash. The following is passed as input data: [data][serialnumber][timestamp]</para>
		/// </summary>
		SHA1_RSA_PKCS_TIMESTAMP = CKM_SHA1_RSA_PKCS_TIMESTAMP,
	};

	/// <summary>
	/// Type of sign/verify recover mechanism.
	/// </summary>
	public enum class SignRecoverMechanism
	{
		/// <summary>
		/// The PKCS #1 v1.5 RSA mechanism, denoted RSA_PKCS, is a multi-purpose mechanism based on the RSA public-key crypto-system and the block formats initially defined in PKCS #1 v1.5.
		/// <para>It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping.</para>
		/// <para>This mechanism corresponds only to the part of PKCS #1 v1.5 that involves RSA; it does not compute a message digest or a DigestInfo encoding as specified for the md2withRSAEncryption and md5withRSAEncryption algorithms in PKCS #1 v1.5 .</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of the data are summarized in the following table.</para>
		/// <para>For encryption, decryption, signatures and signature verification, the input and output data may begin at the same location in memory.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: ≤k-11] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_SignRecover] - [Key Type: RSA private key] - [Data Length: ≤k-11] - [Signature Length: k] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: ≤k-11, k^2] - [Signature Length: N/A] - [Comments: block type 01]</para>
		/// <para>[Function:‍ C_VerifyRecover] - [Key Type: RSA public key] - [Data Length: k] - [Signature Length: ≤k-11] - [Comments: block type 01]</para>
		/// </summary>
		RSA_PKCS = CKM_RSA_PKCS,

		/// <summary>
		/// The ISO/IEC 9796 RSA mechanism, denoted RSA_9796, is a mechanism for single-part signatures and verification with and without message recovery based on the RSA public-key crypto-system and the block formats defined in ISO/IEC 9796 and its annex A.
		/// <para>This mechanism processes only byte strings, whereas ISO/IEC 9796 operates on bit strings.</para>
		/// <para>Accordingly, the following transformations are performed:</para>
		/// <para>- Data is converted between byte and bit string formats by interpreting the most significant bit of the leading byte of the byte string as the leftmost bit of the bit string, and the least-significant bit of the trailing byte of the byte string as the rightmost bit of the bit string (this assumes the length in bits of the data is a multiple of 8).</para>
		/// <para>- A signature is converted from a bit string to a byte string by padding the bit string on the left with 0 to 7 zero bits so that the resulting length in bits is a multiple of 8, and converting the resulting bit string as above; it is converted from a byte string to a bit string by converting the byte string as above, and removing bits from the left so that the resulting length in bits is the same as that of the RSA modulus.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: ≤floor(k/2)] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_SignRecover] - [Key Type: RSA private key] - [Data Length: floor(≤k/2)] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: floor(≤k/2), k^2] - [Signature Length: N/A]</para>
		/// <para>[Function:‍ C_VerifyRecover] - [Key Type: RSA public key] - [Data Length: k] - [Signature Length: floor(≤k/2)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		RSA_9796 = CKM_RSA_9796,

		/// <summary>
		/// The X.509 (raw) RSA mechanism, denoted RSA_X_509, is a multi-purpose mechanism based on the RSA public-key crypto-system.
		/// <para>It supports single-part encryption and decryption; single-part signatures and verification with and without message recovery; key wrapping; and key unwrapping.</para>
		/// <para>All these operations are based on so called "raw" RSA, as assumed in X.509.</para>
		/// <para>"Raw" RSA as defined here encrypts a byte string by converting it to an integer, most significant byte first, applying "raw" RSA exponentiation, and converting the result to a byte string, most-significant byte first.</para>
		/// <para>The input string, considered as an integer, must be less than the modulus; the output string is also less than the modulus.</para>
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>This mechanism can wrap and unwrap any secret key of appropriate length. Of course, a particular token may not be able to wrap/unwrap every appropriate-length secret key that it supports.</para>
		/// <para>For wrapping, the "input" to the encryption operation is the value of the 'VALUE' attribute of the key that is wrapped; similarly for unwrapping.</para>
		/// <para>The mechanism does not wrap the key type, key length, or any other information about the key; the application must convey these separately, and supply them when unwrapping the key.</para>
		/// <para>Unfortunately, X.509 does not specify how to perform padding for RSA encryption.</para>
		/// <para>Constraints on key types and the length of input and output data are summarized in the following table.</para>
		/// <para>In the table, k is the length in bytes of the RSA modulus.</para>
		/// <para>[Function:‍ C_Encrypt] - [Key Type: RSA public key] - [Data Length: ≤k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Decrypt] - [Key Type: RSA private key] - [Data Length: k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Sign] - [Key Type: RSA private key] - [Data Length: ≤k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_SignRecover] - [Key Type: RSA private key] - [Data Length: ≤k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_Verify] - [Key Type: RSA public key] - [Data Length: ≤k, k^2] - [Signature Length: N/A]</para>
		/// <para>[Function:‍ C_VerifyRecover] - [Key Type: RSA public key] - [Data Length: k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_WrapKey] - [Key Type: RSA public key] - [Data Length: ≤k] - [Signature Length: k]</para>
		/// <para>[Function:‍ C_UnwrapKey] - [Key Type: RSA private key] - [Data Length: k] - [Signature Length: ≤k (specified in template)]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// <para>This mechanism is intended for compatibility with applications that do not follow the PKCS #1 or ISO/IEC 9796 block formats.</para>
		/// </summary>
		RSA_X_509 = CKM_RSA_X_509,

		/// <summary>
		/// The SafeNet vendor defined PKCS#11 mechanism SHA1_RSA_PKCS_TIMESTAMP provides time stamping functionality. The supported signing functions are C_Sign_Init and C_Sign.
		/// <para>This mechanism supports single and multiple-part digital signatures and verification with message recovery.</para>
		/// <para>The mechanism uses the SHA1 hash function to generate the message digest.</para>
		/// <para>It has a parameter, a TIMESTAMP_PARAMS structure.</para>
		/// <para>If the mechanism parameters are specified then the timeStampType parameter must be set to TIMESTAMP_FORMAT_PTKC as only this format is supported in the first release.</para>
		/// <para>The mechanism only supports one second granularity in the timestamp although the timestamp format will provide for future sub-second granularity.</para>
		/// <para>A monotonic counter object is used to generate the unique serial number that forms part of the timestamp.</para>
		/// <para>The monotonic counter object is automatically created when a token is initialized and exists by default in the Admin Token.</para>
		/// <para>The parameter formats are defined the following:</para>
		/// <para>Input format:</para>
		/// <para>- Data: Transaction data (variable length), maximum of 3k</para>
		/// <para>Output format:</para>
		/// <para>- serialnumber[20]: This is a unique number for each timestamp, padded with zeroes in a Big Endian 20 byte array. The number is read from the CKH_MONOTONIC_COUNTER hardware feature object on the same token as the signing key. By this read action the value contained by the object is automatically increased by 1.</para>
		/// <para>- timestamp[15]: This is the timestamp in the format of GeneralizedTime specified in RFC3161. The syntax is: YYYYMMDDhhmmss[.s...]Z The sub-second component is optional and not supported in the intial release but still defined to ensure backward compatibility in the future.</para>
		/// <para>- sign[128]: RSA Signature.</para>
		/// <para>NOTE 1: Please see the PKCS#11 v2.10: Cryptographic Token Interface Standard, RSA Laboratories December 1999 for a definition of types.</para>
		/// <para>NOTE 2: It is highly recommended that the RFC3161 format timestamp provided by the HSM be stored on the host to allow future independent third party timestamp verification.</para>
		/// <para>The mechanism will perform the following:</para>
		/// <para>- Input data that is provided by the calling host.</para>
		/// <para>- Obtain the time from within the ProtectHost.</para>
		/// <para>- Calculate a signature across the merged input data and time data using PKCS#1 type 01 padding as follows: Signature = Sign(SHA1(Data || serialnumber || timestamp)</para>
		/// <para>- Output part of the input data, the time data and the signature.</para>
		/// <para>Verification of the signature can be performed using the SHA1_RSA_PKCS_TIMESTAMP mechanism with Verify or VerifyRecover.</para>
		/// <para>The difference between the two functions is that C_Verify calculates the hash but does not return it to the caller where as C_VerifyRecover() returns the hash. The following is passed as input data: [data][serialnumber][timestamp]</para>
		/// </summary>
		SHA1_RSA_PKCS_TIMESTAMP = CKM_SHA1_RSA_PKCS_TIMESTAMP,
	};

	/// <summary>
	/// Type of Key/Key-Pair Generation mechanism.
	/// </summary>
	public enum class KeyGenerationMechanism
	{
		/// <summary>
		/// The AES key generation mechanism, denoted AES_KEY_GEN, is a key generation mechanism for NIST's Advanced Encryption Standard.
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism generates AES keys with a particular length in bytes, as specified in the VALUE_LEN attribute of the template for the key.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, and VALUE attributes to the new key.</para>
		/// <para>Other attributes supported by the AES key type (specifically, the flags indicating which functions the key supports) may be specified in the template for the key, or else are assigned default initial values.</para>
		/// <para>The following table defines the AES secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (16, 24, or 32 bytes)]</para>
		/// <para>[Attribute:‍ VALUE_LEN] - [Data type: ULong] - [Meaning: Length in bytes of key value]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of AES key sizes, in bytes.</para>
		/// </summary>
		AES_KEY_GEN = CKM_AES_KEY_GEN,

		/// <summary>
		/// CAST128 (also known as CAST5) secret key objects (object class SECRET_KEY, key type CAST128 or CAST5) hold CAST128 keys.
		/// <para>The following table defines the CAST128 secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (1 to 16 bytes)]</para>
		/// </summary>
		CAST128_KEY_GEN = CKM_CAST128_KEY_GEN,

		/// <summary>
		/// CAST128 (also known as CAST5) secret key objects (object class SECRET_KEY, key type CAST128 or CAST5) hold CAST128 keys.
		/// <para>The following table defines the CAST128 secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (1 to 16 bytes)]</para>
		/// </summary>
		CAST5_KEY_GEN = CKM_CAST5_KEY_GEN,

		/// <summary>
		/// DES secret key objects (object class SECRET_KEY, key type DES) hold single-length DES keys.
		/// <para>The following table defines the DES secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (always 8 bytes long)]</para>
		/// </summary>
		DES_KEY_GEN = CKM_DES_KEY_GEN,

		/// <summary>
		/// The double-length DES key generation mechanism, denoted DES2_KEY_GEN, is a key generation mechanism for double-length DES keys.
		/// <para>The DES keys making up a double-length DES key both have their parity bits set properly, as specified in FIPS PUB 46-3.</para>
		/// <para>Attempting to create or unwrap a DES2 key with incorrect parity will return an error.</para>
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, and VALUE attributes to the new key.</para>
		/// <para>Other attributes supported by the double-length DES key type (specifically, the flags indicating which functions the key supports) may be specified in the template for the key, or else are assigned default initial values.</para>
		/// <para>Double-length DES keys can be used with all the same mechanisms as triple-DES keys:</para>
		/// <para>CKM_DES3_ECB, CKM_DES3_CBC, CKM_DES3_CBC_PAD, CKM_DES3_MAC_GENERAL, and CKM_DES3_MAC</para>
		/// <para>The following table defines the DES2 secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (always 16 bytes long)]</para>
		/// <para>Triple-DES encryption with a double-length DES key is equivalent to encryption with a triple-length DES key with K1=K3 as specified in FIPS PUB 46-3.</para>
		/// </summary>
		DES2_KEY_GEN = CKM_DES2_KEY_GEN,

		/// <summary>
		/// DES3 secret key objects (object class SECRET_KEY, key type DES3) hold triple-length DES keys.
		/// <para>The following table defines the DES3 secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (always 24 bytes long)]</para>
		/// </summary>
		DES3_KEY_GEN = CKM_DES3_KEY_GEN,

		/// <summary>
		/// Diffie-Hellman public key objects (object class PUBLIC_KEY, key type DH) hold Diffie-Hellman public keys.
		/// <para>The following table defines the Diffie-Hellman public key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ PRIME] - [Data type: Big integer] - [Meaning: Prime p]</para>
		/// <para>[Attribute:‍ BASE] - [Data type: Big integer] - [Meaning: Base g]</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Big integer] - [Meaning: Public value y]</para>
		/// <para>Diffie-Hellman private key objects (object class PRIVATE_KEY, key type DH) hold Diffie-Hellman private keys.</para>
		/// <para>The following table defines the Diffie-Hellman private key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ PRIME] - [Data type: Big integer] - [Meaning: Prime p]</para>
		/// <para>[Attribute:‍ BASE] - [Data type: Big integer] - [Meaning: Base g]</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Big integer] - [Meaning: Private value x]</para>
		/// <para>[Attribute:‍ VALUE_BITS] - [Data type: ULong] - [Meaning: Length in bits of private value x]</para>
		/// <para>The PRIME and BASE attribute values are collectively the Diffie-Hellman domain parameters.</para>
		/// <para>Depending on the token, there may be limits on the length of the key components. See PKCS #3 for more information on Diffie-Hellman keys.</para>
		/// <para>Note that when generating an Diffie-Hellman private key, the Diffie-Hellman parameters are not specified in the key's template.</para>
		/// <para>This is because Diffie-Hellman private keys are only generated as part of a Diffie-Hellman key pair, and the Diffie-Hellman parameters for the pair are specified in the template for the Diffie-Hellman public key.</para>
		/// </summary>
		DH_PKCS_KEY_PAIR_GEN = CKM_DH_PKCS_KEY_PAIR_GEN,

		/// <summary>
		/// The PKCS #3 Diffie-Hellman domain parameter generation mechanism, denoted DH_PKCS_PARAMETER_GEN, is a domain parameter generation mechanism based on Diffie-Hellman key agreement, as defined in PKCS #3.
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism generates Diffie-Hellman domain parameters with a particular prime length in bits, as specified in the PRIME_BITS attribute of the template.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, PRIME, BASE, and PRIME_BITS attributes to the new object. Other attributes supported by the Diffie-Hellman domain parameter types may also be specified in the template, or else are assigned default initial values.</para>
		/// <para>DSA public key objects (object class PUBLIC_KEY, key type DSA) hold DSA public keys.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of Diffie-Hellman prime sizes, in bits.</para>
		/// </summary>
		DH_PKCS_PARAMETER_GEN = CKM_DH_PKCS_PARAMETER_GEN,

		/// <summary>
		/// The DSA key pair generation mechanism, denoted DSA_KEY_PAIR_GEN, is a key pair generation mechanism based on the Digital Signature Algorithm defined in FIPS PUB 186-2.
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism generates DSA public/private key pairs with a particular prime, sub-prime and base, as specified in the PRIME, SUBPRIME, and BASE attributes of the template for the public key.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, and VALUE attributes to the new public key and the CLASS, KEY_TYPE, PRIME, SUBPRIME, BASE, and VALUE attributes to the new private key.</para>
		/// <para>Other attributes supported by the DSA public and private key types (specifically, the flags indicating which functions the keys support) may also be specified in the templates for the keys, or else are assigned default initial values.</para>
		/// <para>The following table defines the DSA public key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ PRIME] - [Data type: Big integer] - [Meaning: Prime p (512 to 1024 bits, in steps of 64 bits)]</para>
		/// <para>[Attribute:‍ SUBPRIME] - [Data type: Big integer] - [Meaning: Sub-prime q (160 bits)]</para>
		/// <para>[Attribute:‍ BASE] - [Data type: Big integer] - [Meaning: Base g]</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Big integer] - [Meaning: Public value y]</para>
		/// <para>DSA private key objects (object class PRIVATE_KEY, key type DSA) hold DSA private keys.</para>
		/// <para>The following table defines the DSA private key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ PRIME] - [Data type: Big integer] - [Meaning: Prime p (512 to 1024 bits, in steps of 64 bits)]</para>
		/// <para>[Attribute:‍ SUBPRIME] - [Data type: Big integer] - [Meaning: Sub-prime q (160 bits)]</para>
		/// <para>[Attribute:‍ BASE] - [Data type: Big integer] - [Meaning: Base g]</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Big integer] - [Meaning: Private value x]</para>
		/// <para>The PRIME, SUBPRIME and BASE attribute values are collectively the "DSA domain parameters". See FIPS PUB 186-2 for more information on DSA keys.</para>
		/// <para>Note that when generating a DSA private key, the DSA domain parameters are not specified in the key’s template.</para>
		/// <para>This is because DSA private keys are only generated as part of a DSA key pair, and the DSA domain parameters for the pair are specified in the template for the DSA public key.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of DSA prime sizes, in bits.</para>
		/// </summary>
		DSA_KEY_PAIR_GEN = CKM_DSA_KEY_PAIR_GEN,

		/// <summary>
		/// The DSA domain parameter generation mechanism, denoted DSA_PARAMETER_GEN, is a domain parameter generation mechanism based on the Digital Signature Algorithm defined in FIPS PUB 186-2.
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism generates DSA domain parameters with a particular prime length in bits, as specified in the PRIME_BITS attribute of the template.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, PRIME, SUBPRIME, BASE and PRIME_BITS attributes to the new object. Other attributes supported by the DSA domain parameter types may also be specified in the template, or else are assigned default initial values.</para>
		/// <para>The following table defines the DSA domain parameter object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ PRIME] - [Data type: Big integer] - [Meaning: Prime p (512 to 1024 bits, in steps of 64 bits)]</para>
		/// <para>[Attribute:‍ SUBPRIME] - [Data type: Big integer] - [Meaning: Sub-prime q (160 bits)]</para>
		/// <para>[Attribute:‍ BASE] - [Data type: Big integer] - [Meaning: Base g]</para>
		/// <para>[Attribute:‍ PRIME_BITS] - [Data type: ULong] - [Meaning: Length of the prime value.]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of DSA prime sizes, in bits.</para>
		/// </summary>
		DSA_PARAMETER_GEN = CKM_DSA_PARAMETER_GEN,

		/// <summary>
		/// Generic secret key objects (object class SECRET_KEY, key type GENERIC_SECRET) hold generic secret keys.
		/// <para>It does not have a parameter.</para>
		/// <para>These keys do not support encryption, decryption, signatures or verification; however, other keys can be derived from them.</para>
		/// <para>The following table defines the generic secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>These key types are used in several of the mechanisms.</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (arbitrary length)]</para>
		/// <para>[Attribute:‍ VALUE_LEN] - [Data type: ULong] - [Meaning: Length in bytes of key value]</para>
		/// <para>CHECK_VALUE: The value of this attribute is derived from the key object by taking the first three bytes of the SHA-1 hash of the generic secret key object's VALUE attribute.</para>
		/// </summary>
		GENERIC_SECRET_KEY_GEN = CKM_GENERIC_SECRET_KEY_GEN,

		/// <summary>
		/// IDEA secret key objects (object class SECRET_KEY, key type IDEA) hold IDEA keys.
		/// <para>The following table defines the IDEA secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (always 16 bytes long)]</para>
		/// </summary>
		IDEA_KEY_GEN = CKM_IDEA_KEY_GEN,

		/// <summary>
		/// MD2-PBE for DES-CBC, denoted PBE_MD2_DES_CBC, is a mechanism used for generating a DES secret key and an IV from a password and a salt value by using the MD2 digest algorithm and an iteration count.
		/// <para>This functionality is defined in PKCS#5 as PBKDF1.</para>
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer which will receive the 8-byte IV generated by the mechanism.</para>
		/// </summary>
		PBE_MD2_DES_CBC = CKM_PBE_MD2_DES_CBC,

		/// <summary>
		/// MD5-PBE for DES-CBC, denoted PBE_MD5_DES_CBC, is a mechanism used for generating a DES secret key and an IV from a password and a salt value by using the MD5 digest algorithm and an iteration count.
		/// <para>This functionality is defined in PKCS#5 as PBKDF1.</para>
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer which will receive the 8-byte IV generated by the mechanism.</para>
		/// </summary>
		PBE_MD5_DES_CBC = CKM_PBE_MD5_DES_CBC,

		/// <summary>
		/// MD5-PBE for CAST128-CBC (CAST5-CBC), denoted PBE_MD5_CAST128_CBC or PBE_MD5_CAST5_CBC, is a mechanism used for generating a CAST128 (CAST5) secret key and an IV from a password and a salt value by using the MD5 digest algorithm and an iteration count.
		/// <para>This functionality is analogous to that defined in PKCS#5 PBKDF1 for MD5 and DES.</para>
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer which will receive the 8-byte IV generated by the mechanism.</para>
		/// <para>The length of the CAST128 (CAST5) key generated by this mechanism may be specified in the supplied template; if it is not present in the template, it defaults to 8 bytes.</para>
		/// </summary>
		PBE_MD5_CAST128_CBC = CKM_PBE_MD5_CAST128_CBC,

		/// <summary>
		/// MD5-PBE for CAST128-CBC (CAST5-CBC), denoted PBE_MD5_CAST128_CBC or PBE_MD5_CAST5_CBC, is a mechanism used for generating a CAST128 (CAST5) secret key and an IV from a password and a salt value by using the MD5 digest algorithm and an iteration count.
		/// <para>This functionality is analogous to that defined in PKCS#5 PBKDF1 for MD5 and DES.</para>
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer which will receive the 8-byte IV generated by the mechanism.</para>
		/// <para>The length of the CAST128 (CAST5) key generated by this mechanism may be specified in the supplied template; if it is not present in the template, it defaults to 8 bytes.</para>
		/// </summary>
		PBE_MD5_CAST5_CBC = CKM_PBE_MD5_CAST5_CBC,

		/// <summary>
		/// SHA-1-PBE for CAST128-CBC (CAST5-CBC), denoted PBE_SHA1_CAST128_CBC or PBE_SHA1_CAST5_CBC, is a mechanism used for generating a CAST128 (CAST5) secret key and an IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
		/// <para>This functionality is analogous to that defined in PKCS#5 PBKDF1 for MD5 and DES.</para>
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer which will receive the 8-byte IV generated by the mechanism.</para>
		/// <para>The length of the CAST128 (CAST5) key generated by this mechanism may be specified in the supplied template; if it is not present in the template, it defaults to 8 bytes.</para>
		/// </summary>
		PBE_SHA1_CAST128_CBC = CKM_PBE_SHA1_CAST128_CBC,

		/// <summary>
		/// SHA-1-PBE for CAST128-CBC (CAST5-CBC), denoted PBE_SHA1_CAST128_CBC or PBE_SHA1_CAST5_CBC, is a mechanism used for generating a CAST128 (CAST5) secret key and an IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
		/// <para>This functionality is analogous to that defined in PKCS#5 PBKDF1 for MD5 and DES.</para>
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer which will receive the 8-byte IV generated by the mechanism.</para>
		/// <para>The length of the CAST128 (CAST5) key generated by this mechanism may be specified in the supplied template; if it is not present in the template, it defaults to 8 bytes.</para>
		/// </summary>
		PBE_SHA1_CAST5_CBC = CKM_PBE_SHA1_CAST5_CBC,

		/// <summary>
		/// SHA-1-PBE for 2-key triple-DES-CBC, denoted PBE_SHA1_DES2_EDE_CBC, is a mechanism used for generating a 2-key triple-DES secret key and IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
		/// <para>Each byte of the key produced will have its low-order bit adjusted, if necessary, so that a valid 2-key triple-DES key with proper parity bits is obtained.</para>
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer which will receive the 8-byte IV generated by the mechanism.</para>
		/// <para>The key and IV produced by this mechanism will typically be used for performing password-based encryption.</para>
		/// </summary>
		PBE_SHA1_DES2_EDE_CBC = CKM_PBE_SHA1_DES2_EDE_CBC,

		/// <summary>
		/// SHA-1-PBE for 3-key triple-DES-CBC, denoted PBE_SHA1_DES3_EDE_CBC, is a mechanism used for generating a 3-key triple-DES secret key and IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
		/// <para>Each byte of the key produced will have its low-order bit adjusted, if necessary, so that a valid 3-key triple-DES key with proper parity bits is obtained.</para>
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer which will receive the 8-byte IV generated by the mechanism.</para>
		/// <para>The key and IV produced by this mechanism will typically be used for performing password-based encryption.</para>
		/// </summary>
		PBE_SHA1_DES3_EDE_CBC = CKM_PBE_SHA1_DES3_EDE_CBC,

		/// <summary>
		/// This is a mechanism used for generating a 128-bit RC2 secret key and IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer that will receive the 8-byte IV generated by the mechanism.</para>
		/// <para>When the key and IV generated by this mechanism are used to encrypt or decrypt, the effective number of bits in the RC2 search space should be set to 128. This ensures compatibility with the ASN.1 Object Identifier pbeWithSHA1And128BitRC2-CBC.</para>
		/// <para>The key and IV produced by this mechanism will typically be used for performing password-based encryption.</para>
		/// </summary>
		PBE_SHA1_RC2_128_CBC = CKM_PBE_SHA1_RC2_128_CBC,

		/// <summary>
		/// This is a mechanism used for generating a 40-bit RC2 secret key and IV from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
		/// <para>It has a parameter, a PBE_PARAMS structure.</para>
		/// <para>The parameter specifies the input information for the key generation process and the location of the application-supplied buffer that will receive the 8-byte IV generated by the mechanism.</para>
		/// <para>When the key and IV generated by this mechanism are used to encrypt or decrypt, the effective number of bits in the RC2 search space should be set to 40. This ensures compatibility with the ASN.1 Object Identifier pbeWithSHA1And40BitRC2-CBC.</para>
		/// <para>The key and IV produced by this mechanism will typically be used for performing password-based encryption.</para>
		/// </summary>
		PBE_SHA1_RC2_40_CBC = CKM_PBE_SHA1_RC2_40_CBC,

		/// <summary>
		/// This is a mechanism used for generating a 128-bit RC4 secret key from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
		/// <para>It has a parameter, a PBE_PARAMS structure. The parameter specifies the input information for the key generation process.</para>
		/// <para>The parameter also has a field to hold the location of an application-supplied buffer that will receive an IV; for this mechanism, the contents of this field are ignored, since RC4 does not require an IV.</para>
		/// <para>The key produced by this mechanism will typically be used for performing password-based encryption.</para>
		/// </summary>
		PBE_SHA1_RC4_128 = CKM_PBE_SHA1_RC4_128,

		/// <summary>
		/// This is a mechanism used for generating a 40-bit RC4 secret key from a password and a salt value by using the SHA-1 digest algorithm and an iteration count.
		/// <para>It has a parameter, a PBE_PARAMS structure. The parameter specifies the input information for the key generation process.</para>
		/// <para>The parameter also has a field to hold the location of an application-supplied buffer that will receive an IV; for this mechanism, the contents of this field are ignored, since RC4 does not require an IV.</para>
		/// <para>The key produced by this mechanism will typically be used for performing password-based encryption.</para>
		/// </summary>
		PBE_SHA1_RC4_40 = CKM_PBE_SHA1_RC4_40,

		/// <summary>
		/// The RC2 key generation mechanism, denoted RC2_KEY_GEN, is a key generation mechanism for RSA Security's block cipher RC2.
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism generates RC2 keys with a particular length in bytes, as specified in the VALUE_LEN attribute of the template for the key.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, and VALUE attributes to the new key. Other attributes supported by the RC2 key type (specifically, the flags indicating which functions the key supports) may be specified in the template for the key, or else are assigned default initial values.</para>
		/// <para>The following table defines the RC2 secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (1 to 128 bytes)]</para>
		/// <para>[Attribute:‍ VALUE_LEN] - [Data type: ULong] - [Meaning: Length in bytes of key value]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC2 key sizes, in bits.</para>
		/// </summary>
		RC2_KEY_GEN = CKM_RC2_KEY_GEN,

		/// <summary>
		/// The RC4 key generation mechanism, denoted RC4_KEY_GEN, is a key generation mechanism for RSA Security's proprietary stream cipher RC4.
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism generates RC4 keys with a particular length in bytes, as specified in the VALUE_LEN attribute of the template for the key.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, and VALUE attributes to the new key.</para>
		/// <para>Other attributes supported by the RC4 key type (specifically, the flags indicating which functions the key supports) may be specified in the template for the key, or else are assigned default initial values.</para>
		/// <para>The following table defines the RC4 secret key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ VALUE] - [Data type: Byte array] - [Meaning: Key value (1 to 256 bytes)]</para>
		/// <para>[Attribute:‍ VALUE_LEN] - [Data type: ULong] - [Meaning: Length in bytes of key value]</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RC4 key sizes, in bits</para>
		/// </summary>
		RC4_KEY_GEN = CKM_RC4_KEY_GEN,

		/// <summary>
		/// The PKCS #1 RSA key pair generation mechanism, denoted RSA_PKCS_KEY_PAIR_GEN, is a key pair generation mechanism based on the RSA public-key crypto-system, as defined in PKCS #1.
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism generates RSA public/private key pairs with a particular modulus length in bits and public exponent, as specified in the MODULUS_BITS and PUBLIC_EXPONENT attributes of the template for the public key.</para>
		/// <para>The PUBLIC_EXPONENT may be omitted in which case the mechanism shall supply the public exponent attribute using the default value of 0x10001 (65537).</para>
		/// <para>Specific implementations may use a random value or an alternative default if 0x10001 cannot be used by the token.</para>
		/// <para>Implementations strictly compliant with version 2.11 or prior versions may generate an error if this attribute is omitted from the template.</para>
		/// <para>Experience has shown that many implementations of 2.11 and prior did allow the PUBLIC_EXPONENT attribute to be omitted from the template, and behaved as described above.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, MODULUS, and PUBLIC_EXPONENT attributes to the new public key.</para>
		/// <para>PUBLIC_EXPONENT will be copied from the template if supplied. CKR_TEMPLATE_INCONSISTENT shall be returned if the implementation cannot use the supplied exponent value.</para>
		/// <para>It contributes the CLASS and KEY_TYPE attributes to the new private key; it may also contribute some of the following attributes to the new private key: MODULUS, PUBLIC_EXPONENT, PRIVATE_EXPONENT, PRIME_1, PRIME_2, EXPONENT_1, EXPONENT_2, COEFFICIENT.</para>
		/// <para>Other attributes supported by the RSA public and private key types (specifically, the flags indicating which functions the keys support) may also be specified in the templates for the keys, or else are assigned default initial values.</para>
		/// <para>RSA public key objects (object class PUBLIC_KEY, key type RSA) hold RSA public keys.</para>
		/// <para>The following table defines the RSA public key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ MODULUS] - [Data type: Big integer] - [Meaning: Modulus n]</para>
		/// <para>[Attribute:‍ MODULUS_BITS] - [Data type: ULong] - [Meaning: Length in bits of modulus n]</para>
		/// <para>[Attribute:‍ PUBLIC_EXPONENT] - [Data type: Big integer] - [Meaning: Public exponent e]</para>
		/// <para>RSA private key objects (object class PRIVATE_KEY, key type RSA) hold RSA private keys.</para>
		/// <para>The following table defines the RSA private key object attributes, in addition to the common attributes defined for this object class:</para>
		/// <para>[Attribute:‍ MODULUS] - [Data type: Big integer] - [Meaning: Modulus n]</para>
		/// <para>[Attribute:‍ PUBLIC_EXPONENT] - [Data type: ULong] - [Meaning: Public exponent e]</para>
		/// <para>[Attribute:‍ PRIVATE_EXPONENT] - [Data type: Big integer] - [Meaning: Private exponent d]</para>
		/// <para>[Attribute:‍ PRIME_1] - [Data type: Big integer] - [Meaning: Prime p]</para>
		/// <para>[Attribute:‍ PRIME_2] - [Data type: Big integer] - [Meaning: Prime q]</para>
		/// <para>[Attribute:‍ EXPONENT_1] - [Data type: Big integer] - [Meaning: Private exponent d modulo p-1]</para>
		/// <para>[Attribute:‍ EXPONENT_2] - [Data type: Big integer] - [Meaning: Private exponent d modulo q-1]</para>
		/// <para>[Attribute:‍ COEFFICIENT] - [Data type: Big integer] - [Meaning: CRT coefficient (q^-1) mod p]</para>
		/// <para>Depending on the token, there may be limits on the length of the key components. See PKCS #1 for more information on RSA keys.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		RSA_PKCS_KEY_PAIR_GEN = CKM_RSA_PKCS_KEY_PAIR_GEN,

		/// <summary>
		/// The X9.31 RSA key pair generation mechanism, denoted RSA_X9_31_KEY_PAIR_GEN, is a key pair generation mechanism based on the RSA public-key crypto-system, as defined in X9.31.
		/// <para>It does not have a parameter.</para>
		/// <para>The mechanism generates RSA public/private key pairs with a particular modulus length in bits and public exponent, as specified in the MODULUS_BITS and PUBLIC_EXPONENT attributes of the template for the public key.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, MODULUS, and PUBLIC_EXPONENT attributes to the new public key.</para>
		/// <para>It contributes the CLASS and KEY_TYPE attributes to the new private key; it may also contribute some of the following attributes to the new private key: MODULUS, PUBLIC_EXPONENT, PRIVATE_EXPONENT, PRIME_1, PRIME_2, EXPONENT_1, EXPONENT_2, COEFFICIENT.</para>
		/// <para>Other attributes supported by the RSA public and private key types (specifically, the flags indicating which functions the keys support) may also be specified in the templates for the keys, or else are assigned default initial values.</para>
		/// <para>Unlike the RSA_PKCS_KEY_PAIR_GEN mechanism, this mechanism is guaranteed to generate p and q values, PRIME_1 and PRIME_2 respectively, that meet the strong primes requirement of X9.31.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of RSA modulus sizes, in bits.</para>
		/// </summary>
		RSA_X9_31_KEY_PAIR_GEN = CKM_RSA_X9_31_KEY_PAIR_GEN,
		
		/// <summary>
		/// The EC (also related to ECDSA) key pair generation mechanism, denoted CKM_EC_KEY_PAIR_GEN or CKM_ECDSA_KEY_PAIR_GEN, is a key pair generation mechanism for EC.
		/// <para>This mechanism does not have a parameter.</para>
		/// <para>The mechanism generates EC public/private key pairs with particular EC domain parameters, as specified in the CKA_EC_PARAMS or CKA_ECDSA_PARAMS attribute of the template for the public key.</para>
		/// <para>Note that this version of Cryptoki does not include a mechanism for generating these EC domain parameters.</para>
		/// <para>The mechanism contributes the CKA_CLASS, CKA_KEY_TYPE, and CKA_EC_POINT attributes to the new public key and the CKA_CLASS, CKA_KEY_TYPE, CKA_EC_PARAMS or CKA_ECDSA_PARAMS and CKA_CKA_VALUE attributes to the new private key. Other attributes supported by the EC public and private key types (specifically, the flags indicating which functions the keys support) may also be specified in the templates for the keys, or else are assigned default initial values.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the CK_MECHANISM_INFO structure specify the minimum and maximum supported number of bits in the field sizes, respectively. For example, if a Cryptoki library supports only ECDSA using a field of characteristic 2 which has between 2200 and 2300 elements, then ulMinKeySize = 201 and ulMaxKeySize = 301 (when written in binary notation, the number 2200 consists of a 1 bit followed by 200 0 bits. It is therefore a 201-bit number. Similarly, 2300 is a 301-bit number).</para>
		/// </summary>
		EC_KEY_PAIR_GEN = CKM_EC_KEY_PAIR_GEN,

		/// <summary>
		/// Pre_master key generation in SSL 3.0, denoted SSL3_PRE_MASTER_KEY_GEN, is a mechanism which generates a 48-byte generic secret key.
		/// <para>It is used to produce the "pre_master" key used in SSL version 3.0 for RSA-like cipher suites.</para>
		/// <para>It has one parameter, a VERSION structure, which provides the client's SSL version number.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, and VALUE attributes to the new key (as well as the VALUE_LEN attribute, if it is not supplied in the template). Other attributes may be specified in the template, or else are assigned default values.</para>
		/// <para>The template sent along with this mechanism during a C_GenerateKey call may indicate that the object class is SECRET_KEY, the key type is GENERIC_SECRET, and the VALUE_LEN attribute has value 48.</para>
		/// <para>However, since these facts are all implicit in the mechanism, there is no need to specify any of them.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure both indicate 48 bytes.</para>
		/// </summary>
		SSL3_PRE_MASTER_KEY_GEN = CKM_SSL3_PRE_MASTER_KEY_GEN,

		///
		/// There are a number of additional SafeNet vendor defined key generation mechanisms.
		///

		/// <summary>
		/// This is a SafeNet vendor defined key generate mechanism to provide the capability to load a clear key component from a directly attached pin pad device.
		/// <para>It has a parameter, a PP_LOAD_SECRET_PARAMS, which holds the operational details for the mechanism.</para>
		/// <para>The template supplied with the call to the GenerateKey function determines the type of object generated by the operation.</para>
		/// <para>CLASS may be SECRET_KEY only, and the only key type supported is GENERIC_SECRET. (This restriction applies because only key components are to be entered by this mechanism).</para>
		/// <para>The normal rules for template consistencies apply. In particular the ALWAYS_SENSITIVE must be set FALSE and the NEVER_EXTRACTABLE must be FALSE.</para>
		/// <para>The expected size of the object value created by this operation is supplied in the VALUE_LEN parameter in the template.</para>
		/// </summary>
		PP_LOAD_SECRET = CKM_PP_LOAD_SECRET,

		/// <summary>
		/// The SafeNet vendor defined SEED key generation mechanism, denoted SEED_KEY_GEN, is a key generation mechanism for the Korean Information Security Agency's SEED algorithm.
		/// <para>The mechanism does not have a parameter, and it generates SEED keys 16 bytes in length.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, VALUE_LEN, and VALUE attributes to the new key.</para>
		/// <para>Other attributes supported by the SEED key type (specifically, the flags indicating which functions the key supports) may be specified in the template for the key, or they may be assigned default initial values.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySizefields' of the MECHANISM_INFO structure specify the supported range of SEED key sizes, in bytes, which is 16.</para>
		/// <para>The algorithm block size is 16 bytes.</para>
		/// </summary>
		SEED_KEY_GEN = CKM_SEED_KEY_GEN,
	};

	/// <summary>
	/// Type of digesting mechanism.
	/// </summary>
	public enum class DeriveMechanism
	{
		/// <summary>
		/// This mechanism, denoted CONCATENATE_BASE_AND_DATA, derives a secret key by concatenating data onto the end of a specified secret key.
		/// <para>This mechanism takes a parameter, a KEY_DERIVATION_STRING_DATA structure, which specifies the length and value of the data which will be appended to the base key to derive another key.</para>
		/// <para>For example, if the value of the base key is 0x01234567, and the value of the data is 0x89ABCDEF, then the value of the derived key will be taken from a buffer containing the string 0x0123456789ABCDEF.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be equal to the sum of the lengths of the value of the original key and the data.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn’t, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, DES3, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more bytes than are available by concatenating the original key’s value and the data, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- If the base key has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key's SENSITIVE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- Similarly, if the base key has its EXTRACTABLE attribute set to FALSE, so does the derived key. If not, then the derived key’s EXTRACTABLE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- The derived key’s ALWAYS_SENSITIVE attribute is set to TRUE if and only if the base key has its ALWAYS_SENSITIVE attribute set to TRUE.</para>
		/// <para>- Similarly, the derived key's NEVER_EXTRACTABLE attribute is set to TRUE if and only if the base key has its NEVER_EXTRACTABLE attribute set to TRUE.</para>
		/// </summary>
		CONCATENATE_BASE_AND_DATA = CKM_CONCATENATE_BASE_AND_DATA,

		/// <summary>
		/// This mechanism, denoted CONCATENATE_BASE_AND_KEY, derives a secret key from the concatenation of two existing secret keys.
		/// <para>The two keys are specified by handles; the values of the keys specified are concatenated together in a buffer.</para>
		/// <para>This mechanism takes a parameter, a SMObject. This parameter produces the key value information which is appended to the end of the base key's value information (the base key is the key whose handle is supplied as an argument to DeriveKey).</para>
		/// <para>For example, if the value of the base key is 0x01234567, and the value of the other key is 0x89ABCDEF, then the value of the derived key will be taken from a buffer containing the string 0x0123456789ABCDEF.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be equal to the sum of the lengths of the values of the two original keys.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn't, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, DES3, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more bytes than are available by concatenating the two original keys' values, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- If either of the two original keys has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key's SENSITIVE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- Similarly, if either of the two original keys has its EXTRACTABLE attribute set to FALSE, so does the derived key. If not, then the derived key's EXTRACTABLE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- The derived key's ALWAYS_SENSITIVE attribute is set to TRUE if and only if both of the original keys have their ALWAYS_SENSITIVE attributes set to TRUE.</para>
		/// <para>- Similarly, the derived key's NEVER_EXTRACTABLE attribute is set to TRUE if and only if both of the original keys have their NEVER_EXTRACTABLE attributes set to TRUE.</para>
		/// </summary>
		CONCATENATE_BASE_AND_KEY = CKM_CONCATENATE_BASE_AND_KEY,

		/// <summary>
		/// Extraction of one key from another key, denoted EXTRACT_KEY_FROM_KEY, is a mechanism which provides the capability of creating one secret key from the bits of another secret key.
		/// <para>This mechanism has a parameter, a EXTRACT_PARAMS, which specifies which bit of the original key should be used as the first bit of the newly-derived key.</para>
		/// <para>We give an example of how this mechanism works. Suppose a token has a secret key with the 4-byte value 0x329F84A9.</para>
		/// <para>We will derive a 2-byte secret key from this key, starting at bit position 21 (i.e., the value of the parameter to the EXTRACT_KEY_FROM_KEY mechanism is 21).</para>
		/// <para>- We write the key's value in binary: 0011 0010 1001 1111 1000 0100 1010 1001. We regard this binary string as holding the 32 bits of the key, labeled as b0, b1,..., b31.</para>
		/// <para>We then extract 16 consecutive bits (i.e., 2 bytes) from this binary string, starting at bit b21. We obtain the binary string 1001 0101 0010 0110.</para>
		/// <para>The value of the new key is thus 0x9526.</para>
		/// <para>Note that when constructing the value of the derived key, it is permissible to wrap around the end of the binary string representing the original key's value.</para>
		/// <para>If the original key used in this process is sensitive, then the derived key must also be sensitive for the derivation to succeed.</para>
		/// <para>- If no length or key type is provided in the template, then an error will be returned.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn't, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, DES3, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more bytes than the original key has, an error is generated.</para>
		/// <para>- If the base key has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key's SENSITIVE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- Similarly, if the base key has its EXTRACTABLE attribute set to FALSE, so does the derived key. If not, then the derived key's EXTRACTABLE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- The derived key's ALWAYS_SENSITIVE attribute is set to TRUE if and only if the base key has its ALWAYS_SENSITIVE attribute set to TRUE.</para>
		/// <para>- Similarly, the derived key's NEVER_EXTRACTABLE attribute is set to TRUE if and only if the base key has its NEVER_EXTRACTABLE attribute set to TRUE.</para>
		/// </summary>
		EXTRACT_KEY_FROM_KEY = CKM_EXTRACT_KEY_FROM_KEY,

		/// <summary>
		/// MD2 key derivation, denoted MD2_KEY_DERIVATION, is a mechanism which provides the capability of deriving a secret key by digesting the value of another secret key with MD2.
		/// <para>The value of the base key is digested once, and the result is used to make the value of derived secret key.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be 16 bytes (the output size of MD2).</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length was provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn’t, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more than 16 bytes, such as DES3, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// </summary>
		MD2_KEY_DERIVATION = CKM_MD2_KEY_DERIVATION,

		/// <summary>
		/// MD5 key derivation, denoted MD5_KEY_DERIVATION, is a mechanism which provides the capability of deriving a secret key by digesting the value of another secret key with MD5.
		/// <para>The value of the base key is digested once, and the result is used to make the value of derived secret key.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be 16 bytes (the output size of MD5).</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length was provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn't, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more than 16 bytes, such as DES3, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// </summary>
		MD5_KEY_DERIVATION = CKM_MD5_KEY_DERIVATION,

		/// <summary>
		/// SHA-1 key derivation, denoted SHA1_KEY_DERIVATION, is a mechanism which provides the capability of deriving a secret key by digesting the value of another secret key with SHA-1.
		/// <para>The value of the base key is digested once, and the result is used to make the value of derived secret key.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be 20 bytes (the output size of SHA-1).</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length was provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn’t, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more than 20 bytes, such as DES3, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// </summary>
		SHA1_KEY_DERIVATION = CKM_SHA1_KEY_DERIVATION,

		/// <summary>
		/// SHA-224 key derivation, denoted SHA224_KEY_DERIVATION, is a mechanism which provides the capability of deriving a secret key by digesting the value of another secret key with SHA-224.
		/// <para>The value of the base key is digested once, and the result is used to make the value of derived secret key.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be 28 bytes (the output size of SHA-224).</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length was provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn’t, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more than 28 bytes, such as DES3, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// </summary>
		SHA224_KEY_DERIVATION = CKM_SHA224_KEY_DERIVATION,

		/// <summary>
		/// SHA-256 key derivation, denoted SHA256_KEY_DERIVATION, is a mechanism which provides the capability of deriving a secret key by digesting the value of another secret key with SHA-256.
		/// <para>The value of the base key is digested once, and the result is used to make the value of derived secret key.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be 32 bytes (the output size of SHA-256).</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length was provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn’t, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more than 32 bytes, such as DES3, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// </summary>
		SHA256_KEY_DERIVATION = CKM_SHA256_KEY_DERIVATION,

		/// <summary>
		/// SHA-384 key derivation, denoted SHA384_KEY_DERIVATION, is a mechanism which provides the capability of deriving a secret key by digesting the value of another secret key with SHA-384.
		/// <para>The value of the base key is digested once, and the result is used to make the value of derived secret key.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be 48 bytes (the output size of SHA-384).</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length was provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn’t, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more than 48 bytes, such as DES3, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// </summary>
		SHA384_KEY_DERIVATION = CKM_SHA384_KEY_DERIVATION,

		/// <summary>
		/// SHA-512 key derivation, denoted SHA512_KEY_DERIVATION, is a mechanism which provides the capability of deriving a secret key by digesting the value of another secret key with SHA-512.
		/// <para>The value of the base key is digested once, and the result is used to make the value of derived secret key.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be 64 bytes (the output size of SHA-512).</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length was provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn’t, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more than 64 bytes, such as DES3, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// </summary>
		SHA512_KEY_DERIVATION = CKM_SHA512_KEY_DERIVATION,

		/// <summary>
		/// Key, MAC and IV derivation in SSL 3.0, denoted SSL3_KEY_AND_MAC_DERIVE, is a mechanism used to derive the appropriate cryptographic keying material used by a "CipherSuite" from the "master_secret" key and random data. This mechanism returns the key handles for the keys generated in the process, as well as the IVs created.
		/// <para>It has a parameter, a SSL3_KEY_MAT_PARAMS structure, which allows for the passing of random data as well as the characteristic of the cryptographic material for the given CipherSuite and a pointer to a structure which receives the handles and IVs which were generated.</para>
		/// <para>This mechanism contributes to the creation of four distinct keys on the token and returns two IVs (if IVs are requested by the caller) back to the caller. The keys are all given an object class of SECRET_KEY.</para>
		/// <para>The two MACing keys ("client_write_MAC_secret" and "server_write_MAC_secret") are always given a type of GENERIC_SECRET. They are flagged as valid for signing, verification, and derivation operations.</para>
		/// <para>The other two keys ("client_write_key" and "server_write_key") are typed according to information found in the template sent along with this mechanism during a C_DeriveKey function call. By default, they are flagged as valid for encryption, decryption, and derivation operations.</para>
		/// <para>IVs will be generated and returned if the ulIVSizeInBits field of the SSL_KEY_MAT_PARAMS field has a nonzero value. If they are generated, their length in bits will agree with the value in the ulIVSizeInBits field.</para>
		/// <para>All four keys inherit the values of the SENSITIVE, ALWAYS_SENSITIVE, EXTRACTABLE, and NEVER_EXTRACTABLE attributes from the base key. The template provided to C_DeriveKey may not specify values for any of these attributes which differ from those held by the base key.</para>
		/// <para>Note that the CK_SSL3_KEY_MAT_OUT structure pointed to by the SSL3_KEY_MAT_PARAMS structure's returnedKeyMaterial field will be modified by the DeriveKey call.</para>
		/// <para>In particular, the four key handle fields in the SSL3_KEY_MAT_OUT structure will be modified to hold handles to the newly created keys; in addition, the buffers pointed to by the SSL3_KEY_MAT_OUT structure's IVClient and IVServer fields will have IVs returned in them (if IVs are requested by the caller).</para>
		/// <para>Therefore, these two fields must point to buffers with sufficient space to hold any IVs that will be returned.</para>
		/// <para>This mechanism departs from the other key derivation mechanisms in Cryptoki in its returned information.</para>
		/// <para>For most key-derivation mechanisms, DeriveKey returns a single key handle as a result of a successful completion.</para>
		/// <para>However, since the SSL3_KEY_AND_MAC_DERIVE mechanism returns all of its key handles in the SSL3_KEY_MAT_OUT structure pointed to by the SSL3_KEY_MAT_PARAMS structure specified as the mechanism parameter, the parameter phKey passed to DeriveKey is unnecessary, and should be a NULL.</para>
		/// <para>If a call to DeriveKey with this mechanism fails, then none of the four keys will be created on the token.</para>
		/// </summary>
		SSL3_KEY_AND_MAC_DERIVE = CKM_SSL3_KEY_AND_MAC_DERIVE,

		/// <summary>
		/// Master key derivation in SSL 3.0, denoted SSL3_MASTER_KEY_DERIVE, is a mechanism used to derive one 48-byte generic secret key from another 48-byte generic secret key.
		/// <para>It is used to produce the "master_secret" key used in the SSL protocol from the "pre_master" key. This mechanism returns the value of the client version, which is built into the "pre_master" key as well as a handle to the derived "master_secret" key.</para>
		/// <para>It has a parameter, a SSL3_MASTER_KEY_DERIVE_PARAMS structure, which allows for the passing of random data to the token as well as the returning of the protocol version number which is part of the pre-master key.</para>
		/// <para>The mechanism contributes the CLASS, KEY_TYPE, and VALUE attributes to the new key (as well as the VALUE_LEN attribute, if it is not supplied in the template). Other attributes may be specified in the template; otherwise they are assigned default values.</para>
		/// <para>The template sent along with this mechanism during a DeriveKey call may indicate that the object class is CKO_SECRET_KEY, the key type is CKK_GENERISECRET, and the VALUE_LEN attribute has value 48. However, since these facts are all implicit in the mechanism, there is no need to specify any of them.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure both indicate 48 bytes.</para>
		/// <para>Note that the VERSION structure pointed to by the SSL3_MASTER_KEY_DERIVE_PARAMS structure’s pVersion field will be modified by the DeriveKey call. In particular, when the call returns, this structure will hold the SSL version associated with the supplied pre_master key.</para>
		/// <para>Note that this mechanism is only useable for cipher suites that use a 48-byte "pre_master" secret with an embedded version number. This includes the RSA cipher suites, but excludes the Diffie-Hellman cipher suites.</para>
		/// </summary>
		SSL3_MASTER_KEY_DERIVE = CKM_SSL3_MASTER_KEY_DERIVE,

		/// <summary>
		/// XORing key derivation, denoted XOR_BASE_AND_DATA, is a mechanism which provides the capability of deriving a secret key by performing a bit XORing of a key pointed to by a base key handle and some data.
		/// <para>This mechanism takes a parameter, a KEY_DERIVATION_STRING_DATA structure, which specifies the data with which to XOR the original key's value.</para>
		/// <para>For example, if the value of the base key is 0x01234567, and the value of the data is 0x89ABCDEF, then the value of the derived key will be taken from a buffer containing the string 0x88888888.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism will be a generic secret key. Its length will be equal to the minimum of the lengths of the data and the value of the original key.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism will be a generic secret key of the specified length.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism will be of the type specified in the template. If it doesn’t, an error will be returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism will be of the specified type and length.</para>
		/// <para>If a DES, DES2, DES3, or CDMF key is derived with this mechanism, the parity bits of the key will be set properly.</para>
		/// <para>If the requested type of key requires more bytes than are available by taking the shorter of the data and the original key’s value, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- If the base key has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key’s SENSITIVE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- Similarly, if the base key has its EXTRACTABLE attribute set to FALSE, so does the derived key. If not, then the derived key’s EXTRACTABLE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- The derived key’s ALWAYS_SENSITIVE attribute is set to TRUE if and only if the base key has its ALWAYS_SENSITIVE attribute set to TRUE.</para>
		/// <para>- Similarly, the derived key’s NEVER_EXTRACTABLE attribute is set to TRUE if and only if the base key has its NEVER_EXTRACTABLE attribute set to TRUE.</para>
		/// </summary>
		XOR_BASE_AND_DATA = CKM_XOR_BASE_AND_DATA,

		/// <summary>
		/// The PKCS#3 Diffie-Hellman key derivation mechanism, denoted DH_PKCS_DERIVE, is a mechanism for key derivation based on Diffie-Hellman key agreement, as defined in PKCS #3. This is what PKCS #3 calls "phase II".
		/// <para>It has a parameter, which is the public value of the other party in the key agreement protocol, represented as a Cryptoki "Big integer" (i.e., a sequence of bytes, mostsignificant byte first).</para>
		/// <para>This mechanism derives a secret key from a Diffie-Hellman private key and the public value of the other party.</para>
		/// <para>It computes a Diffie-Hellman secret value from the public value and private key according to PKCS #3, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one and the key type supports it, the VALUE_LEN attribute of the template. (The truncation removes bytes from the leading end of the secret value.)</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- The SENSITIVE and EXTRACTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes each take on some default value.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// <para>Note that the rules regarding the SENSITIVE, EXTRACTABLE, ALWAYS_SENSITIVE, and NEVER_EXTRACTABLE attributes have changed in PKCS#11 version 2.11 to match the policy used by other key derivation mechanisms such as SSL3_MASTER_KEY_DERIVE.</para>
		/// <para>For this mechanism, the 'ulMinKeySize' and 'ulMaxKeySize' fields of the MECHANISM_INFO structure specify the supported range of Diffie-Hellman prime sizes, in bits.</para>
		/// </summary>
		DH_PKCS_DERIVE = CKM_DH_PKCS_DERIVE,

		///
		/// There are a number of additional SafeNet vendor defined digest mechanism types.
		///

		/// <summary>
		/// This mechanism is used with the DeriveKey function to create a PKCS#10 certification request from a public key.
		/// <para>Either an RSA or DSA public key may be used with this function.</para>
		/// <para>The PKCS#10 certificate request could then be sent to a Certificate authority for signing.</para>
		/// <para>It takes a parameter that is a MECH_TYPE_AND_OBJECT structure.</para>
		/// <para>This mechanism field specifies the actual signature mechanism to use in generation of the certificate signature.</para>
		/// <para>A certification request consists of a distinguished name, a public key and optionally a set of attributes that are collectively signed by the entity requesting certification.</para>
		/// <para>Certification requests are sent to a certification authority, which will transform the request to an X.509 public-key certificate.</para>
		/// <para>Usage:</para>
		/// <para>- Use RSA_PKCS_KEY_PAIR_GEN to generate a key.</para>
		/// <para>- Add a SUBJECT attribute to the public key, containing the subject's distinguished name.</para>
		/// <para>- Initialize the signature mechanism to sign the request. Note that a digest/sign mechanism must be chosen. For example, SHA1_RSA_PKCS</para>
		/// <para>- Call DeriveKey with the ENCODE_PKCS_10 mechanism to perform the generation.</para>
		/// <para>- On success, an object handle for the certificate request is returned.</para>
		/// <para>- The object's VALUE attribute contains the PKCS#10 request.</para>
		/// </summary>
		ENCODE_PKCS_10 = CKM_ENCODE_PKCS_10,

		/// <summary>
		/// This mechanism is used with the DeriveKey function to derive a set of X.509 Certificate objects and X.509 CRL objects from a PKCS#7 object.
		/// <para>The base key object handle is a DATA object (the PKCS#7 encoding) which has a OBJECT_ID attribute indicating the type of the object as being a PKCS#7 encoding.</para>
		/// <para>This mechanism does not take any parameters.</para>
		/// <para>One of the functions of PKCS7 is a mechanism for distributing certificates and CRLs in a single encoded package. In this case the PKCS7 message content is usually empty.</para>
		/// <para>This mechanism is provided to split certificates and CRLs from such a PKCS7 encoding so that those certificates and CRLs may be further processed.</para>
		/// <para>This mechanism will decode a PKCS7 encoding and create PKCS#11 objects for all certificates (object class CERTIFICATE) and CRLs (object class CRL) that it finds in the encoding.</para>
		/// <para>The signature on the PKCS7 content is not verified. The parameter containing the newly derived key is the last Certificate or CRL that is extracted from the PKCS7 encoding. The attribute template is applied to all objects extracted from the encoding.</para>
		/// </summary>
		DECODE_PKCS_7 = CKM_DECODE_PKCS_7,

		/// <summary>
		/// This mechanism is used with the DeriveKey function to derive a public key object from an X.509 certificate or a PKCS#10 certification request.
		/// <para>This mechanism does not perform a certificate validation.</para>
		/// <para>The base key object handle should refer to the X.509 certificate or PKCS#10 certificate request.</para>
		/// <para>This mechanism has no parameter.</para>
		/// </summary>
		DECODE_X_509 = CKM_DECODE_X_509,

		/// <summary>
		/// The DES_DERIVE_CBC and DES3_DERIVE_CBC mechanisms are used with the DeriveKey function to derive a secret key by performing a CBC (no padding) encryption.
		/// <para>They create a new secret key whose value is generated by encrypting the provided data with the provided Single, Double or Triple length DES key.</para>
		/// <para>Three new mechanism Parameter structures are created, DES_CBC_PARAMS, DES2_CBC_PARAMS and DES3_CBC_PARAMS, for use by these mechanisms.</para>
		/// <para>These structures consists of 2-byte arrays, the first array contains the IV (must be 8 bytes) and the second array contains the data to be encrypted, being 8, 16 or 24 bytes in length, for each PARAMS structure respectively.</para>
		/// <para>These mechanisms require the pParameter in the MECHANISM structure to be a pointer to one of the above new Parameter structures and the parameterLen to be the size of the provided Parameter structure.</para>
		/// <para>If the length of data to be encrypted by the CBC mechanism does not fit into one of the above PARAMS structures, the developer must produce their own byte array with the following layout.</para>
		/// <para>The first 8 bytes must be the IV, then the data to be encrypted. To use this array, the pParameter in the MECHANISM structure must be a pointer to this array and the parameterLen is the length of the IV (must be 8 bytes) plus the length of the provided data, which must be a multiple of 8 bytes.</para>
		/// <para>The following rules apply to the provided attribute template:</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by these mechanisms is a generic secret key. Its length is equal to the length of the provided data.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by these mechanisms is a generic secret key of the specified length, extracted from the left bytes of the cipher text.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by these mechanisms is of the type specified in the template. If it doesn't, an error is returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by these mechanisms is of the specified type and length, extracted from the left bytes of the cipher text.</para>
		/// <para>If a DES key is derived with these mechanisms, the parity bits of the key are set properly. If the requested type of key requires more bytes than the length of the provided data, an error is generated.</para>
		/// <para>These mechanisms have the following rules about key sensitivity and extractability:</para>
		/// <para>- If the base key has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key's SENSITIVE attribute is set either from the supplied template or else it defaults to TRUE.</para>
		/// <para>- Similarly, the derived key's EXTRACTABLE attribute is set either from the supplied template or else it defaults to the value of the EXTRACTABLE of the base key.</para>
		/// <para>- The derived key's ALWAYS_SENSITIVE attribute is set to TRUE if and only if the base key has its ALWAYS_SENSITIVE attribute set to TRUE.</para>
		/// <para>- Similarly, the derived key's NEVER_EXTRACTABLE attribute is set to TRUE if and only if the base key has its NEVER_EXTRACTABLE attribute set to TRUE.</para>
		/// </summary>
		DES_DERIVE_CBC = CKM_DES_DERIVE_CBC,

		/// <summary>
		/// The DES_DERIVE_ECB and DES3_DERIVE_ECB mechanisms are used with the DeriveKey function to derive a secret key by performing an ECB (no padding) encryption.
		/// <para>They create a new secret key whose value is generated by encrypting the provided data with the provided single, double or triple length DES key.</para>
		/// <para>The DES_DERIVE_ECB and DES3_DERIVE_ECB mechanisms require the 'parameter' in the CK_MECHANISM structure to be the pointer to the data that is to be encrypted, which must be a multiple of 8 bytes.</para>
		/// <para>The following rules apply to the provided attribute template:</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by these mechanisms is a generic secret key. Its length is equal to the length of the provided data.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by these mechanisms is a generic secret key of the specified length, extracted from the left bytes of the cipher text.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by these mechanisms is of the type specified in the template. If it doesn't, an error is returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by these mechanisms is of the specified type and length, extracted from the left bytes of the cipher text.</para>
		/// <para>If a DES key is derived with these mechanisms, the parity bits of the key are set properly. If the requested type of key requires more bytes than the length of the provided data, an error is generated.</para>
		/// <para>The mechanisms have the following rules about key sensitivity and extractability:</para>
		/// <para>- If the base key has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key's SENSITIVE attribute is set either from the supplied template or else it defaults to TRUE.</para>
		/// <para>- Similarly, the derived key's EXTRACTABLE attribute is set either from the supplied template or else it defaults to the value of the EXTRACTABLE of the base key.</para>
		/// <para>- The derived key's ALWAYS_SENSITIVE attribute is set to TRUE if and only if the base key has its ALWAYS_SENSITIVE attribute set to TRUE.</para>
		/// <para>- Similarly, the derived key's NEVER_EXTRACTABLE attribute is set to TRUE if and only if the base key has its NEVER_EXTRACTABLE attribute set to TRUE.</para>
		/// </summary>
		DES_DERIVE_ECB = CKM_DES_DERIVE_ECB,

		/// <summary>
		/// The DES_DERIVE_CBC and DES3_DERIVE_CBC mechanisms are used with the DeriveKey function to derive a secret key by performing a CBC (no padding) encryption.
		/// <para>They create a new secret key whose value is generated by encrypting the provided data with the provided Single, Double or Triple length DES key.</para>
		/// <para>Three new mechanism Parameter structures are created, DES_CBC_PARAMS, DES2_CBC_PARAMS and DES3_CBC_PARAMS, for use by these mechanisms.</para>
		/// <para>These structures consists of 2-byte arrays, the first array contains the IV (must be 8 bytes) and the second array contains the data to be encrypted, being 8, 16 or 24 bytes in length, for each PARAMS structure respectively.</para>
		/// <para>These mechanisms require the pParameter in the MECHANISM structure to be a pointer to one of the above new Parameter structures and the parameterLen to be the size of the provided Parameter structure.</para>
		/// <para>If the length of data to be encrypted by the CBC mechanism does not fit into one of the above PARAMS structures, the developer must produce their own byte array with the following layout.</para>
		/// <para>The first 8 bytes must be the IV, then the data to be encrypted. To use this array, the pParameter in the MECHANISM structure must be a pointer to this array and the parameterLen is the length of the IV (must be 8 bytes) plus the length of the provided data, which must be a multiple of 8 bytes.</para>
		/// <para>The following rules apply to the provided attribute template:</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by these mechanisms is a generic secret key. Its length is equal to the length of the provided data.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by these mechanisms is a generic secret key of the specified length, extracted from the left bytes of the cipher text.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by these mechanisms is of the type specified in the template. If it doesn't, an error is returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by these mechanisms is of the specified type and length, extracted from the left bytes of the cipher text.</para>
		/// <para>If a DES key is derived with these mechanisms, the parity bits of the key are set properly. If the requested type of key requires more bytes than the length of the provided data, an error is generated.</para>
		/// <para>These mechanisms have the following rules about key sensitivity and extractability:</para>
		/// <para>- If the base key has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key's SENSITIVE attribute is set either from the supplied template or else it defaults to TRUE.</para>
		/// <para>- Similarly, the derived key's EXTRACTABLE attribute is set either from the supplied template or else it defaults to the value of the EXTRACTABLE of the base key.</para>
		/// <para>- The derived key's ALWAYS_SENSITIVE attribute is set to TRUE if and only if the base key has its ALWAYS_SENSITIVE attribute set to TRUE.</para>
		/// <para>- Similarly, the derived key's NEVER_EXTRACTABLE attribute is set to TRUE if and only if the base key has its NEVER_EXTRACTABLE attribute set to TRUE.</para>
		/// </summary>
		DES3_DERIVE_CBC = CKM_DES3_DERIVE_CBC,

		/// <summary>
		/// The DES_DERIVE_ECB and DES3_DERIVE_ECB mechanisms are used with the DeriveKey function to derive a secret key by performing an ECB (no padding) encryption.
		/// <para>They create a new secret key whose value is generated by encrypting the provided data with the provided single, double or triple length DES key.</para>
		/// <para>The DES_DERIVE_ECB and DES3_DERIVE_ECB mechanisms require the 'parameter' in the CK_MECHANISM structure to be the pointer to the data that is to be encrypted, which must be a multiple of 8 bytes.</para>
		/// <para>The following rules apply to the provided attribute template:</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by these mechanisms is a generic secret key. Its length is equal to the length of the provided data.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by these mechanisms is a generic secret key of the specified length, extracted from the left bytes of the cipher text.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by these mechanisms is of the type specified in the template. If it doesn't, an error is returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by these mechanisms is of the specified type and length, extracted from the left bytes of the cipher text.</para>
		/// <para>If a DES key is derived with these mechanisms, the parity bits of the key are set properly. If the requested type of key requires more bytes than the length of the provided data, an error is generated.</para>
		/// <para>The mechanisms have the following rules about key sensitivity and extractability:</para>
		/// <para>- If the base key has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key's SENSITIVE attribute is set either from the supplied template or else it defaults to TRUE.</para>
		/// <para>- Similarly, the derived key's EXTRACTABLE attribute is set either from the supplied template or else it defaults to the value of the EXTRACTABLE of the base key.</para>
		/// <para>- The derived key's ALWAYS_SENSITIVE attribute is set to TRUE if and only if the base key has its ALWAYS_SENSITIVE attribute set to TRUE.</para>
		/// <para>- Similarly, the derived key's NEVER_EXTRACTABLE attribute is set to TRUE if and only if the base key has its NEVER_EXTRACTABLE attribute set to TRUE.</para>
		/// </summary>
		DES3_DERIVE_ECB = CKM_DES3_DERIVE_ECB,

		/// <summary>
		/// The elliptic curve Diffie-Hellman (ECDH) key derivation mechanism, denoted ECDH1_DERIVE, is a mechanism for key derivation based on the Diffie-Hellman version of the elliptic curve key agreement scheme, as defined in ANSI X9.63, where each party contributes one key pair all using the same EC domain parameters.
		/// <para>This mechanism has a parameter, a ECDH1_DERIVE_PARAMS structure.</para>
		/// <para>This mechanism derives a secret value, and truncates the result according to the KEY_TYPE attribute of the template and, if it has one and the key type supports it, the VALUE_LEN attribute of the template. (The truncation removes bytes from the leading end of the secret value.)</para>
		/// <para>The mechanism contributes the result as the VALUE attribute of the new key; other attributes required by the key type must be specified in the template.</para>
		/// <para>The following rules apply to the provided attribute template:</para>
		/// <para>- A key type must be provided in the template or else a Template Error is returned.</para>
		/// <para>- If no length is provided in the template then that key type must have a well-defined length. If it doesn't, an error is returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type.</para>
		/// <para>- If a DES key is derived with these mechanisms, the parity bits of the key are set properly.</para>
		/// <para>- If the requested type of key requires more bytes than the Key Derive Function can provide, an error is generated.</para>
		/// <para>The mechanisms have the following rules about key sensitivity and extractability:</para>
		/// <para>The SENSITIVE, EXTRACTABLE and EXPORTABLE attributes in the template for the new key can both be specified to be either TRUE or FALSE. If omitted, these attributes all take on the default value TRUE.</para>
		/// <para>If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>Similarly, if the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will, too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to the opposite value from its EXTRACTABLE attribute.</para>
		/// </summary>
		ECDH1_DERIVE = CKM_ECDH1_DERIVE,

		/// <summary>
		/// This mechanism is similar to the ENCODE_X_509 mechanism in that it is used to create an X.509 public key certificate. The basic difference is that this mechanism has additional usage controls.
		/// <para>This mechanism will only create certificates for public keys locally generated on the adapter. That is, the base key must have a CLASS attribute of PUBLIC_KEY and have the LOCAL attribute set to TRUE.</para>
		/// <para>In addition, the signing key specified in the mechanism parameter must have the SIGN_LOCAL_CERT attribute set to TRUE. It is used with the KeyDerive function only, (that is, it is a derive mechanism).</para>
		/// <para>It takes a parameter that is a MECH_TYPE_AND_OBJECT structure.</para>
		/// <para>This mechanism field specifies the actual signature mechanism to use in generation of the certificate signature.</para>
		/// <para>This must be one of the multipart digest RSA or DSA algorithms. The obj field above specifies the signature generation key. That is, it should specify a RSA or DSA private key as appropriate for the chosen signature mechanism.</para>
		/// <para>To create a X.509 local certificate that uses EC keys, either provide a PKCS#10 certificate request that was created with EC keys, or provide an EC public key for the BaseKey to the function.</para>
		/// <para>To sign the certificate as a CA using EC keys, use the ECDSA_SHA1 mechanism to initialize the sign operation before calling DeriveKey(). The ECDSA_SHA1 mechanism and EC key must also be specified in the mechanism parameter.</para>
		/// </summary>
		ENCODE_X_509_LOCAL_CERT = CKM_ENCODE_X_509_LOCAL_CERT,

		/// <summary>
		/// This mechanism is used with the DeriveKey function to derive an X.509 certificate from a public key or a PKCS#10 certification request.
		/// <para>This mechanism creates a new X.509 certificate based on the provided public key or certification request signed with a CA key.</para>
		/// <para>This mechanism takes no parameter.</para>
		/// <para>The new certificate validity period is based on the START_DATE and END_DATE attributes on the base object.</para>
		/// <para>If the start date is missing the current time is used. If the end date is missing the certificate is valid for one year.</para>
		/// <para>These dates may be specified as relative values by adding the '+' character at the start of the date value. The start date is relative to 'now' and the end date is relative to the start date if relative times are specified.</para>
		/// <para>Negative relative times are not allowed. If the start or end date is invalid then the error TEMPLATE_INCONSISTENT is returned.</para>
		/// <para>The certificate's serial number is taken from the template's SERIAL_NUMBER, SERIAL_NUMBER_INT or the signing key's USAGE_COUNT in that order. If none of these values is available WRAPPING_KEY_HANDLE_INVALID error is returned.</para>
		/// <para>To determine the Subject distinguished name for the new certificate if the base object is a public key the algorithm will use the SUBJECT_STR, SUBJECT from the template or the base key (in that order). If none of these values is available KEY_HANDLE_INVALID is returned.</para>
		/// <para>It is also possible to include arbitrary X.509 extensions in the certificate.</para>
		/// <para>These are not verified for validity nor parsed for correctness. Rather they are included verbatim in the newly generated certificate.</para>
		/// <para>In order to specify an extension use the PKI_ATTRIBUTE_BER_ENCODED attribute with the value specified as a BER encoding of the attribute. If the base object is a Certification request or a self-signed certificate the subject is taken from the objects encoded subject name.</para>
		/// <para>Currently this mechanism supports generation of RSA or DSA certificates. On success, a handle to a new CKO_CERTIFICATE object is returned.</para>
		/// <para>The certificate will include the ISSUER, SERIAL_NUMBER and SUBJECT attributes as well as a VALUE attribute which will contain the DER encoded certificate.</para>
		/// <para>To create a X.509 certificate that uses EC keys, either provide a PKCS#10 certificate request that was created with EC keys, or provide an EC public key for the hBaseKey parameter to the function. To sign the certificate as a CA using EC keys, use the ECDSA_SHA1 mechanism to initialise the sign operation before calling DeriveKey().</para>
		/// <para>Usage:</para>
		/// <para>- Create a key-pair using the RSA_PKCS mechanism (this is the key-pair for the new certificate), or</para>
		/// <para>- Create a CKO_CERTIFICATE_REQUEST object (with the object's VALUE attribute set to the PKCS#10 data)</para>
		/// <para>- This object is the "base-key" used in the DeriveKey function</para>
		/// <para>- Initialize the signature mechanism to sign the request using SignInit. Note that a digest/sign mechanism must be chosen. For example, SHA1_RSA_PKCS</para>
		/// <para>- Call DeriveKey with ENCODE_X_509 to perform the generation</para>
		/// <para>The new certificate's template may contain:</para>
		/// <para>ISSUER_STR, ISSUER: The distinguished name of the issuer of the new certificate. If this attribute is not included the issuer is taken from the signing key's SUBJECT attribute. ISSUER is the encoded version of this attribute.</para>
		/// <para>SERIAL_NUMBER_INT, SERIAL_NUMBER: The serial number of the new certificate. If this attribute is not included the serial number is set to the value of the USAGE_COUNT attribute of the signing key. SERIAL_NUMBER is the encoded version of this attribute.</para>
		/// <para>SUBJECT_STR, SUBJECT: If the base key (i.e. the input object) is a public key then either the template must contain this attribute or the public key must have a SUBJECT attribute. This attribute contains the distinguished name of the subject. When the base key is a PKCS#10 certification request the SUBJECT information is taken from there. SUBJECT is the encoded version of this attribute.</para>
		/// <para>START_DATE, END_DATE: These attributes are used to determine the new certificate's validity period. If the start date is missing the current date is used. If the end date is missing the date is set to one year from the start date. Relative values may be specified.</para>
		/// <para>PKI_ATTRIBUTE_BER_ENCODED: These attributes are used to determine the new certificate's extended attributes.</para>
		/// </summary>
		ENCODE_X_509 = CKM_ENCODE_X_509,

		/// <summary>
		/// The Secret Recovery Mechanism denoted SECRET_RECOVER_WITH_ATTRIBUTES is a derive mechanism to create a new key object by combining two or more shares.
		/// <para>The mechanism has no parameter.</para>
		/// <para>The DeriveKey parameter BaseKey is the handle of one of the share objects. The mechanism will obtain the LABEL value from BaseKey and then treat all data objects with the same label as shares.</para>
		/// <para>A template is not required as all the attributes of the object are also recovered from the secret.</para>
		/// <para>Usage Note:</para>
		/// <para>To avoid shares getting mixed up between different uses of this mechanism the developer should ensure that data objects with the same label are all from the same secret share batch.</para>
		/// </summary>
		SECRET_RECOVER_WITH_ATTRIBUTES = CKM_SECRET_RECOVER_WITH_ATTRIBUTES,

		/// <summary>
		/// The Secret Share Mechanism denoted SECRET_SHARE_WITH_ATTRIBUTES is a derive mechanism to create M shares of a key such that N shares are required to recover the secret, where N is less than or equal to M.
		/// <para>The mechanism creates a secret value by combining all the attributes of the base key and then shares that secret into M shares.</para>
		/// <para>The algorithm used is according to A. Shamir - How to Share a Secret, Communications of the ACM vol. 22, no. 11, November 1979, pp. 612-613</para>
		/// <para>It has a parameter, a SECRET_SHARE_PARAMS, which specifies the number of shares M and the recovery threshold N</para>
		/// <para>The mechanism will create M data objects and return the object handle of one of them. It is expected that the data objects would be copied to a smart card token for storage.</para>
		/// <para>The template supplied is used to specify the LABEL attribute of each new data object. If the LABEL attribute is not provided in the template then a TEMPLATE_INCOMPLETE error is returned.</para>
		/// <para>The mechanism contributes the VALUE attribute of each data object. Any attempt to specify a VALUE attribute in the template will cause the mechanism to return the error: TEMPLATE_INCONSISTENT.</para>
		/// <para>The default value of the TOKEN, PRIVATE attribute of the new objects is false. The new data objects will have a SENSITIVE attribute. If the SENSITIVE attribute of the base key is true then the data objects is sensitive.</para>
		/// <para>If the base key is not sensitive then the data objects take the value of SENSITIVE from the template or it is defaulted to false.</para>
		/// <para>Usage Note:</para>
		/// <para>To avoid shares getting mixed up between different uses of this mechanism the developer should ensure that there are no data objects with the same label already on the token before attempting to use this mechanism.</para>
		/// <para>If objects are found then these objects should be deleted or a different label chosen.</para>
		/// <para>Security Note:</para>
		/// <para>The key to be exported with this mechanism requires the DERIVE attribute to be true.</para>
		/// <para>This has the effect of enabling other key derive mechanisms to be performed with the key. If this is not desired then the MECHANISM_LIST attribute may be used with the key to restrict its derive operations to this mechanism.</para>
		/// </summary>
		SECRET_SHARE_WITH_ATTRIBUTES = CKM_SECRET_SHARE_WITH_ATTRIBUTES,

		/// <summary>
		/// XORing key derivation, denoted XOR_BASE_AND_KEY, is a mechanism which provides the capability of deriving a secret key by performing a bit XORing of two existing secret keys. The two keys are specified by handles; the values of the keys specified are XORed together in a buffer to create the value of the new key.
		/// <para>This mechanism takes a parameter, an SMObject. This parameter produces the key value information that is XORed with the base key's value information (the base key is the key whose handle is supplied as an argument to DeriveKey).</para>
		/// <para>For example, if the value of the base key is 0x01234567,and the value of the other key is 0x89ABCDEF, then the value of the derived key is taken from a buffer containing the string 0x88888888.</para>
		/// <para>- If no length or key type is provided in the template, then the key produced by this mechanism is a generic secret key. Its length is equal to the minimum of the lengths of the data and the value of the original key.</para>
		/// <para>- If no key type is provided in the template, but a length is, then the key produced by this mechanism is a generic secret key of the specified length.</para>
		/// <para>- If no length is provided in the template, but a key type is, then that key type must have a well-defined length. If it does, then the key produced by this mechanism is of the type specified in the template. If it doesn't, an error is returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism is of the specified type and length.</para>
		/// <para>- If a key type is provided in the template the behavior depends on whether the type is identical to the type of the base key. If the base key is of type GENERISECRET then you can change the type of the new key. Otherwise you can change the type only if the "Pure PKCS11" configuration flag has been set.</para>
		/// <para>If a DES, DES2, DES3, or CDMF key is derived with this mechanism, the parity bits of the key are set properly.</para>
		/// <para>If the requested type of key requires more bytes than are available by taking the shorter of the two key's value, an error is generated.</para>
		/// <para>This mechanism has the following rules about key sensitivity and extractability:</para>
		/// <para>- If the base key has its SENSITIVE attribute set to TRUE, so does the derived key. If not, then the derived key's SENSITIVE attribute is set either from the supplied template or from a default value.</para>
		/// <para>- Similarly, the derived key's EXTRACTABLE attribute is set either from the supplied template or else it defaults to the value of the EXTRACTABLE of the base key.</para>
		/// <para>- The derived key's ALWAYS_SENSITIVE attribute is set to TRUE if and only if the base key has its ALWAYS_SENSITIVE attribute set to TRUE.</para>
		/// <para>- Similarly, the derived key's NEVER_EXTRACTABLE attribute is set to TRUE if and only if the base key has its NEVER_EXTRACTABLE attribute set to TRUE.</para>
		/// </summary>
		XOR_BASE_AND_KEY = CKM_XOR_BASE_AND_KEY,

		/// <summary>
		/// This is the ZKA MDC-2 and DES based key derivation mechanism.
		/// <para>The algorithm implemented by this mechanism is defined in the ZKA technical appendix, "Technischer Anhang zum Vertrag über die Zulassung als Netzbetreiber im electronic-cash-System der deutschen Kreditwirtschaft" V5.2, section 1.9.2.3, "Generierung kartenindividueller Schlüssel".</para>
		/// <para>It has a parameter, the derivation data, which is an arbitrary-length byte array.</para>
		/// <para>This mechanism only operates with the DeriveKey() function.</para>
		/// <para>The derivation data is digested using the DES_MD2_PAD1 mechanism, and the result is ECB decrypted with the base key.</para>
		/// <para>The result is used to make the value of a derived secret key. Only keys of type DES, DES2 and DES3 can be used as the base key for this mechanism.</para>
		/// <para>The derived key can have any key type with key length less than or equal to 16 bytes.</para>
		/// <para>- If no key type and no length is provided in the template, then the key produced by this mechanism is a generic secret key. Its length is 16 bytes (the output size of MDC2).</para>
		/// <para>- If no key type is provided in the template, but a length is provided, then the key produced by this mechanism is a generic secret key of the specified length – created by discarding one or more bytes from the right hand side of the decryption result.</para>
		/// <para>- If a key type is provided in the template, but no length is provided, then that key type must have a well-defined length. If it does, then the key produced by this mechanism is of the type specified in the template. If it doesn't, an error is returned.</para>
		/// <para>- If both a key type and a length are provided in the template, the length must be compatible with that key type. The key produced by this mechanism is of the specified type and length. If the length isn't compatible with the key type, an error is returned.</para>
		/// <para>- If the derived key type is DES, or DES2, the parity bits of the key are set properly.</para>
		/// <para>- If the derived key value length requested is more than 16 bytes, an error is returned.</para>
		/// <para>The following key sensitivity and extractability rules apply for this mechanism:</para>
		/// <para>- The SENSITIVE, EXTRACTABLE and EXPORTABLE attributes in the template for the new key can be specified to be either TRUE or FALSE. If omitted, these attributes each take on the value of the corresponding attribute of the base key. The default value for the EXTRACTABLE and EXPORTABLE attributes is TRUE. The default value of the SENSITIVE attribute depends on the security flags. If the No clear Pins security flag is set, the default value is TRUE; otherwise, it is false.</para>
		/// <para>- If the base key has its ALWAYS_SENSITIVE attribute set to FALSE, then the derived key will as well. If the base key has its ALWAYS_SENSITIVE attribute set to TRUE, then the derived key has its ALWAYS_SENSITIVE attribute set to the same value as its SENSITIVE attribute.</para>
		/// <para>- If the base key has its NEVER_EXTRACTABLE attribute set to FALSE, then the derived key will too. If the base key has its NEVER_EXTRACTABLE attribute set to TRUE, then the derived key has its NEVER_EXTRACTABLE attribute set to TRUE only if both EXTRACTABLE and EXPORTABLE attributes are FALSE. Otherwise, it is set to FALSE.</para>
		/// </summary>
		ZKA_MDC_2_KEY_DERIVATION = CKM_ZKA_MDC_2_KEY_DERIVATION,
	};
}
