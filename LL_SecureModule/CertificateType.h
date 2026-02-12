#pragma once

using namespace System;

namespace LL_SecureModule
{
	/// <summary>
	/// This enum class identifies the certificate type of objects that Cryptoki recognizes.
	/// <para>Certificate types are defined with the objects and mechanisms that use them. The certificate type is specified on an object through the CERTIFICATE_TYPE attribute of the object.</para>
	/// </summary>
	public enum class CertificateType
	{
		/// <summary>
		/// X.509 public key certificate
		/// </summary>
		X_509 = CKC_X_509,

		/// <summary>
		/// X.509 attribute certificate
		/// </summary>
		X_509_ATTR_CERT = CKC_X_509_ATTR_CERT,

		/// <summary>
		/// Permanently reserved for token vendors
		/// </summary>
		VENDOR_DEFINED = (int)CKC_VENDOR_DEFINED,
	};
}
