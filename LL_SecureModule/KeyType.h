#pragma once

using namespace System;

namespace LL_SecureModule
{
	/// <summary>
	/// This enum class identifies the key type of objects that Cryptoki recognizes.
	/// <para>Key types are defined with the objects and mechanisms that use them. The key type is specified on an object through the KEY_TYPE attribute of the object.</para>
	/// </summary>
	public enum class KeyType
	{
		/// <summary>
		/// RSA key
		/// </summary>
		RSA = CKK_RSA,

		/// <summary>
		/// DSA key
		/// </summary>
		DSA = CKK_DSA,

		/// <summary>
		/// DH (Diffie-Hellman) key
		/// </summary>
		DH = CKK_DH,

		/// <summary>
		/// EC (Elliptic Curve) key
		/// </summary>
		ECDSA = CKK_ECDSA,

		/// <summary>
		/// EC (Elliptic Curve) key
		/// </summary>
		EC = CKK_EC,

		/// <summary>
		/// X9.42 Diffie-Hellman public keys
		/// </summary>
		X9_42_DH = CKK_X9_42_DH,

		/// <summary>
		/// KEA keys
		/// </summary>
		KEA = CKK_KEA,

		/// <summary>
		/// Generic secret key
		/// </summary>
		GENERIC_SECRET = CKK_GENERIC_SECRET,

		/// <summary>
		/// RC2 key
		/// </summary>
		RC2 = CKK_RC2,

		/// <summary>
		/// RC4 key
		/// </summary>
		RC4 = CKK_RC4,

		/// <summary>
		/// Single-length DES key
		/// </summary>
		DES = CKK_DES,

		/// <summary>
		/// Double-length DES key
		/// </summary>
		DES2 = CKK_DES2,

		/// <summary>
		/// Triple-length DES key
		/// </summary>
		DES3 = CKK_DES3,

		/// <summary>
		/// CAST key
		/// </summary>
		CAST = CKK_CAST,

		/// <summary>
		/// CAST3 key
		/// </summary>
		CAST3 = CKK_CAST3,

		/// <summary>
		/// CAST128 key
		/// </summary>
		CAST5 = CKK_CAST5,

		/// <summary>
		/// CAST128 key
		/// </summary>
		CAST128 = CKK_CAST128,

		/// <summary>
		/// RC5 key
		/// </summary>
		RC5 = CKK_RC5,

		/// <summary>
		/// IDEA key
		/// </summary>
		IDEA = CKK_IDEA,

		/// <summary>
		/// Single-length MEK or a TEK
		/// </summary>
		SKIPJACK = CKK_SKIPJACK,

		/// <summary>
		/// Single-length BATON key
		/// </summary>
		BATON = CKK_BATON,

		/// <summary>
		/// Single-length JUNIPER key
		/// </summary>
		JUNIPER = CKK_JUNIPER,

		/// <summary>
		/// Single-length CDMF key
		/// </summary>
		CDMF = CKK_CDMF,

		/// <summary>
		/// AES key
		/// </summary>
		AES = CKK_AES,

		/// <summary>
		/// Permanently reserved for token vendors
		/// </summary>
		VENDOR_DEFINED = CKK_VENDOR_DEFINED,

		///
		/// There are a number of additional SafeNet vendor defined attribute types.
		///

		/// <summary>
		/// Entrust translation key type object that holds Entrust translation of RSA keys.
		/// <para>This object class is a vendor defined extension class.</para>
		/// </summary>
		RSA_DISCRETE = CKK_RSA_DISCRETE,

		/// <summary>
		/// Entrust translation key type object that holds Entrust translation of DSA keys.
		/// <para>This object class is a vendor defined extension class.</para>
		/// </summary>
		DSA_DISCRETE = CKK_DSA_DISCRETE,

		/// <summary>
		/// Korean SEED algorithm key object that holds Korean SEED keys.
		/// <para>This object class is a vendor defined extension class.</para>
		/// </summary>
		SEED = CKK_SEED,
	};
}
