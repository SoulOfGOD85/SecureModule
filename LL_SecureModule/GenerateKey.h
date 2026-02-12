#pragma once
ref class GenerateKey
{
public:
	/// <summary>
	/// ...
	/// </summary>
	/// <param name="...">...</param>
	/// <exception cref="System::Exception">Thrown when... .</exception>
	/// <exception cref="LL_SecureModule::SecureModuleException">Thrown when... .</exception>
	/// <history>
	/// [R. Yeylaghi Ashrafi]	1392/09/25	Created
	/// </history>
	void GenerateKey(EncryptionMechanism mechanism, Object^ parameter, array<Byte>^ plainData, array<Byte>^% cipherData);
};

