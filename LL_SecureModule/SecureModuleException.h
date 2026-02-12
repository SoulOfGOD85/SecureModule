#pragma once

using namespace System;
using namespace System::Runtime::Serialization;

namespace LL_SecureModule
{
	/// <summary>
	/// This class represents errors that occur during execution of Cryptoki functions.
	/// </summary>
	[Serializable]
	public ref class SecureModuleException :
		public Exception, public ISerializable
	{
	private:
		/// <summary>Cryptoki PKCS#11 error code.</summary>
		CK_RV exceptionNo;
	public:

		/// <summary>The 'ExceptionNo' property represents the cryptoki error code.</summary>
		/// <value>The 'ExceptionNo' property gets the value of the CK_RV field, 'exceptionNo'.</value>
		/// <history>
		/// [R. Yeylaghi Ashrafi]	1392/04/26	Created
		/// </history>
		property UInt32 ExceptionNo
		{
			UInt32 get() { return (UInt32)(this->exceptionNo); }
		}

		/// <summary>
		/// Initializes a new instance of the SecureModuleException class.
		/// <para>This class library provides an exception-handling mechanism based on class Exception</para>
		/// </summary>
		SecureModuleException(void) : Exception() { this->exceptionNo = CKR_OK; }

		/// <summary>
		/// Initializes a new instance of the SecureModuleException class with a specified message.
		/// </summary>
		/// <param name="message">error description</param>
		SecureModuleException(String^ message) : Exception(message) { this->exceptionNo = CKR_OK; }

		/// <summary>
		/// Initializes a new instance of the SecureModuleException class with a specified error code and message.
		/// </summary>
		/// <param name="errorCode">cryptoki error code</param>
		/// <param name="message">error description</param>
		SecureModuleException(CK_RV errorCode, String^ message) : Exception(message) { this->exceptionNo = errorCode; }

		/// <summary>
		/// Initializes a new instance of the SecureModuleException class with a specified error code and message and a reference to the inner exception that is the cause of this exception.
		/// </summary>
		/// <param name="errorCode">cryptoki error code</param>
		/// <param name="message">error description</param>
		/// <param name="inner">the inner exception reference</param>
		SecureModuleException(CK_RV errorCode, String^ message, Exception^ inner) : Exception(message, inner) { this->exceptionNo = errorCode; }

		/// <summary>
		/// Get string format of SecureModule exception number.
		/// </summary>
		/// <param name="errorCode">cryptoki error code</param>
		String^ GetSecureModuleExceptionNoString(CK_RV errorCode);

	protected:

		/// <summary>
		/// Initializes a new instance of the SecureModuleException class with serialized data.
		/// <para>This constructor is called during deserialization to reconstitute the SecureModuleException object transmitted over a stream.</para>
		/// </summary>
		SecureModuleException(SerializationInfo^ info, StreamingContext context)
			: Exception(info, context) {
			this->exceptionNo = CKR_OK;
		}
	};
}
