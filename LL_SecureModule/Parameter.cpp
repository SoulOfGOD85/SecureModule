#include "stdafx.h"
#include "Parameter.h"

namespace LL_SecureModule
{
	RSA_PKCS_OAEP_PARAMS::RSA_PKCS_OAEP_PARAMS(DigestMechanism hashAlg, Boolean sourceType, array<Byte>^ sourceData)
	{
		this->hashAlg = hashAlg;
		if (sourceType)
		{
			if (sourceData == nullptr)
			{
				this->sourceType = false;
				this->sourceData = nullptr;
			}
			else
			{
				this->sourceType = sourceType;
				this->sourceData = gcnew array<Byte>(sourceData->Length);
				for (int i = 0; i < sourceData->Length; i++)
					this->sourceData[i] = sourceData[i];
			}
		}
	}

	RSA_PKCS_OAEP_PARAMS::RSA_PKCS_OAEP_PARAMS(RSA_PKCS_OAEP_PARAMS^ rsa_pkcs_oaep_params)
	{
		this->hashAlg = rsa_pkcs_oaep_params->hashAlg;

		if (rsa_pkcs_oaep_params->sourceData == nullptr)
		{
			this->sourceType = false;
			this->sourceData = nullptr;
		}
		else
		{
			this->sourceType = rsa_pkcs_oaep_params->sourceType;
			this->sourceData = gcnew array<Byte>(rsa_pkcs_oaep_params->sourceData->Length);
			for (int i = 0; i < this->sourceData->Length; i++)
				this->sourceData[i] = rsa_pkcs_oaep_params->sourceData[i];
		}
	}

	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////

	RC2_PARAMS::RC2_PARAMS(UInt32 effectiveBits)
	{
		this->effectiveBits = effectiveBits;
	}

	RC2_PARAMS::RC2_PARAMS(RC2_PARAMS^ rc2_params)
	{
		this->effectiveBits = rc2_params->effectiveBits;
	}

	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////

	RC2_CBC_PARAMS::RC2_CBC_PARAMS(UInt32 effectiveBits)
	{
		this->effectiveBits = effectiveBits;

		this->iv = gcnew array<Byte>(8);
	}

	RC2_CBC_PARAMS::RC2_CBC_PARAMS(UInt32 effectiveBits, array<Byte>^ iv)
	{
		this->effectiveBits = effectiveBits;

		if (iv == nullptr)
		{
			this->iv = nullptr;
		}
		else
		{
			this->iv = gcnew array<Byte>(iv->Length);
			for (int i = 0; i < this->iv->Length; i++)
				this->iv[i] = iv[i];
		}
	}

	RC2_CBC_PARAMS::RC2_CBC_PARAMS(RC2_CBC_PARAMS^ rc2_cbc_params)
	{
		this->effectiveBits = rc2_cbc_params->effectiveBits;

		if (rc2_cbc_params->iv == nullptr)
		{
			this->iv = nullptr;
		}
		else
		{
			this->iv = gcnew array<Byte>(rc2_cbc_params->iv->Length);
			for (int i = 0; i < this->iv->Length; i++)
				this->iv[i] = rc2_cbc_params->iv[i];
		}
	}

	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////

	ECIES_PARAMS::ECIES_PARAMS(array<Byte>^ sharedData1, UInt32 ulEncKeyLenInBits, ECIES_PARAMS_MACScheme macScheme, UInt32 macKeyLenInBits, UInt32 macLenInBits, array<Byte>^ sharedData2)
	{
		this->encKeyLenInBits = ulEncKeyLenInBits;
		this->macKeyLenInBits = macKeyLenInBits;
		this->macLenInBits = macLenInBits;
		this->macScheme = macScheme;

		if (sharedData1 == nullptr)
		{
			this->sharedData1 = nullptr;
		}
		else
		{
			this->sharedData1 = gcnew array<Byte>(sharedData1->Length);
			for (int i = 0; i < this->sharedData1->Length; i++)
				this->sharedData1[i] = sharedData1[i];
		}

		if (sharedData2 == nullptr)
		{
			this->sharedData2 = nullptr;
		}
		else
		{
			this->sharedData2 = gcnew array<Byte>(sharedData2->Length);
			for (int i = 0; i < this->sharedData2->Length; i++)
				this->sharedData2[i] = sharedData2[i];
		}
	}

	ECIES_PARAMS::ECIES_PARAMS(ECIES_PARAMS^ ecies_params)
	{
		this->encKeyLenInBits = ecies_params->encKeyLenInBits;
		this->macKeyLenInBits = ecies_params->macKeyLenInBits;
		this->macLenInBits = ecies_params->macLenInBits;
		this->macScheme = ecies_params->macScheme;

		if (ecies_params->sharedData1 == nullptr)
		{
			this->sharedData1 = nullptr;
		}
		else
		{
			this->sharedData1 = gcnew array<Byte>(ecies_params->sharedData1->Length);
			for (int i = 0; i < this->sharedData1->Length; i++)
				this->sharedData1[i] = ecies_params->sharedData1[i];
		}

		if (ecies_params->sharedData2 == nullptr)
		{
			this->sharedData2 = nullptr;
		}
		else
		{
			this->sharedData2 = gcnew array<Byte>(ecies_params->sharedData2->Length);
			for (int i = 0; i < this->sharedData2->Length; i++)
				this->sharedData2[i] = ecies_params->sharedData2[i];
		}
	}

	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////

	MAC_GENERAL_PARAMS::MAC_GENERAL_PARAMS(UInt32 lengthOfMAC)
	{
		this->lengthOfMAC = lengthOfMAC;
	}

	MAC_GENERAL_PARAMS::MAC_GENERAL_PARAMS(MAC_GENERAL_PARAMS^ mac_general_params)
	{
		this->lengthOfMAC = mac_general_params->lengthOfMAC;
	}

	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////

	RC2_MAC_GENERAL_PARAMS::RC2_MAC_GENERAL_PARAMS(UInt32 effectiveBits, UInt32 macLength)
	{
		this->effectiveBits = effectiveBits;
		this->macLength = macLength;
	}

	RC2_MAC_GENERAL_PARAMS::RC2_MAC_GENERAL_PARAMS(RC2_MAC_GENERAL_PARAMS^ rc2_mac_general_params)
	{
		this->effectiveBits = rc2_mac_general_params->effectiveBits;
		this->macLength = rc2_mac_general_params->macLength;
	}

	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////

	RSA_PKCS_PSS_PARAMS::RSA_PKCS_PSS_PARAMS(DigestMechanism hashAlg, UInt32 sLen)
	{
		this->hashAlg = hashAlg;
		this->sLen = sLen;
		this->mgf = RSA_PKCS_MGF_TYPE::MGF1_SHA1;
	}

	RSA_PKCS_PSS_PARAMS::RSA_PKCS_PSS_PARAMS(RSA_PKCS_PSS_PARAMS^ rsa_pkcs_pss_params)
	{
		this->hashAlg = rsa_pkcs_pss_params->hashAlg;
		this->sLen = rsa_pkcs_pss_params->sLen;
		this->mgf = RSA_PKCS_MGF_TYPE::MGF1_SHA1;
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	PBE_PARAMS::PBE_PARAMS(array<Byte>^ initVector, String^ password, array<Byte>^ salt, UInt32 iteration)
	{
		this->initVector = initVector;
		this->password = password;
		this->iteration = iteration;

		if (initVector == nullptr)
		{
			this->initVector = gcnew array<Byte>(8);
		}
		else
		{
			this->initVector = gcnew array<Byte>(initVector->Length);
			for (int i = 0; i < this->initVector->Length; i++)
				this->initVector[i] = initVector[i];
		}

		if (salt == nullptr)
		{
			this->salt = nullptr;
		}
		else
		{
			this->salt = gcnew array<Byte>(salt->Length);
			for (int i = 0; i < this->salt->Length; i++)
				this->salt[i] = salt[i];
		}
	}

	PBE_PARAMS::PBE_PARAMS(PBE_PARAMS^ pbe_params)
	{
		this->initVector = pbe_params->initVector;
		this->password = pbe_params->password;
		this->iteration = pbe_params->iteration;

		if (pbe_params->initVector == nullptr)
		{
			this->initVector = gcnew array<Byte>(8);
		}
		else
		{
			this->initVector = gcnew array<Byte>(pbe_params->initVector->Length);
			for (int i = 0; i < this->initVector->Length; i++)
				this->initVector[i] = pbe_params->initVector[i];
		}

		if (pbe_params->salt == nullptr)
		{
			this->salt = nullptr;
		}
		else
		{
			this->salt = gcnew array<Byte>(pbe_params->salt->Length);
			for (int i = 0; i < this->salt->Length; i++)
				this->salt[i] = pbe_params->salt[i];
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	PP_LOAD_SECRET_PARAMS::PP_LOAD_SECRET_PARAMS(Boolean maskInput, Char convert, UInt16 timeout, String^ prompt)
	{
		this->maskInput = maskInput;
		this->convert = convert;
		this->timeout = timeout;
		this->prompt = prompt;
	}

	PP_LOAD_SECRET_PARAMS::PP_LOAD_SECRET_PARAMS(PP_LOAD_SECRET_PARAMS^ pp_load_secret_params)
	{
		this->maskInput = pp_load_secret_params->maskInput;
		this->convert = pp_load_secret_params->convert;
		this->timeout = pp_load_secret_params->timeout;
		this->prompt = pp_load_secret_params->prompt;
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	KEY_WRAP_SET_OAEP_PARAMS::KEY_WRAP_SET_OAEP_PARAMS(Byte BC, array<Byte>^ X)
	{
		this->BC = BC;
		if (X == nullptr)
		{
			this->X = nullptr;
		}
		else
		{
			this->X = gcnew array<Byte>(X->Length);
			for (int i = 0; i < this->X->Length; i++)
				this->X[i] = X[i];
		}
	}

	KEY_WRAP_SET_OAEP_PARAMS::KEY_WRAP_SET_OAEP_PARAMS(KEY_WRAP_SET_OAEP_PARAMS^ key_wrap_set_oaep_params)
	{
		this->BC = key_wrap_set_oaep_params->BC;
		if (key_wrap_set_oaep_params->X == nullptr)
		{
			this->X = nullptr;
		}
		else
		{
			this->X = gcnew array<Byte>(key_wrap_set_oaep_params->X->Length);
			for (int i = 0; i < this->X->Length; i++)
				this->X[i] = key_wrap_set_oaep_params->X[i];
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	KEY_DERIVATION_STRING_DATA::KEY_DERIVATION_STRING_DATA(array<Byte>^ data)
	{
		if (data == nullptr)
		{
			this->data = nullptr;
		}
		else
		{
			this->data = gcnew array<Byte>(data->Length);
			for (int i = 0; i < this->data->Length; i++)
				this->data[i] = data[i];
		}
	}

	KEY_DERIVATION_STRING_DATA::KEY_DERIVATION_STRING_DATA(KEY_DERIVATION_STRING_DATA^ key_derivation_string_data)
	{
		if (key_derivation_string_data->data == nullptr)
		{
			this->data = nullptr;
		}
		else
		{
			this->data = gcnew array<Byte>(key_derivation_string_data->data->Length);
			for (int i = 0; i < this->data->Length; i++)
				this->data[i] = key_derivation_string_data->data[i];
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	EXTRACT_PARAMS::EXTRACT_PARAMS(UInt32 bits)
	{
		this->bits = bits;
	}

	EXTRACT_PARAMS::EXTRACT_PARAMS(EXTRACT_PARAMS^ extract_params)
	{
		this->bits = extract_params->bits;
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	SSL3_RANDOM_DATA::SSL3_RANDOM_DATA(array<Byte>^ clientRandom, array<Byte>^ serverRandom)
	{
		if (clientRandom == nullptr)
		{
			this->clientRandom = nullptr;
		}
		else
		{
			this->clientRandom = gcnew array<Byte>(clientRandom->Length);
			for (int i = 0; i < this->clientRandom->Length; i++)
				this->clientRandom[i] = clientRandom[i];
		}

		if (serverRandom == nullptr)
		{
			this->serverRandom = nullptr;
		}
		else
		{
			this->serverRandom = gcnew array<Byte>(serverRandom->Length);
			for (int i = 0; i < this->serverRandom->Length; i++)
				this->serverRandom[i] = serverRandom[i];
		}
	}

	SSL3_RANDOM_DATA::SSL3_RANDOM_DATA(SSL3_RANDOM_DATA^ ssl3_random_data)
	{
		if (ssl3_random_data->clientRandom == nullptr)
		{
			this->clientRandom = nullptr;
		}
		else
		{
			this->clientRandom = gcnew array<Byte>(ssl3_random_data->clientRandom->Length);
			for (int i = 0; i < this->clientRandom->Length; i++)
				this->clientRandom[i] = ssl3_random_data->clientRandom[i];
		}

		if (ssl3_random_data->serverRandom == nullptr)
		{
			this->serverRandom = nullptr;
		}
		else
		{
			this->serverRandom = gcnew array<Byte>(ssl3_random_data->serverRandom->Length);
			for (int i = 0; i < this->serverRandom->Length; i++)
				this->serverRandom[i] = ssl3_random_data->serverRandom[i];
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	SSL3_MASTER_KEY_DERIVE_PARAMS::SSL3_MASTER_KEY_DERIVE_PARAMS(SSL3_RANDOM_DATA^ randomInfo, CVersion^ version)
	{
		this->randomInfo = gcnew SSL3_RANDOM_DATA(randomInfo);
		this->version = gcnew CVersion(version);
	}

	SSL3_MASTER_KEY_DERIVE_PARAMS::SSL3_MASTER_KEY_DERIVE_PARAMS(SSL3_MASTER_KEY_DERIVE_PARAMS^ ssl3_master_key_derive_params)
	{
		this->randomInfo = gcnew SSL3_RANDOM_DATA(ssl3_master_key_derive_params->randomInfo);
		this->version = gcnew CVersion(ssl3_master_key_derive_params->version);
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	/// <summary>
	/// Class constructor.
	/// </summary>
	ECDH1_DERIVE_PARAMS::ECDH1_DERIVE_PARAMS(UInt32 kdf, array<Byte>^ sharedData, array<Byte>^ publicData)
	{
		this->kdf = kdf;

		if (sharedData == nullptr)
		{
			this->sharedData = nullptr;
		}
		else
		{
			this->sharedData = gcnew array<Byte>(sharedData->Length);
			for (int i = 0; i < this->sharedData->Length; i++)
				this->sharedData[i] = sharedData[i];
		}

		if (publicData == nullptr)
		{
			this->publicData = nullptr;
		}
		else
		{
			this->publicData = gcnew array<Byte>(publicData->Length);
			for (int i = 0; i < this->publicData->Length; i++)
				this->publicData[i] = publicData[i];
		}
	}

	/// <summary>
	/// Copy constructor.
	/// </summary>
	ECDH1_DERIVE_PARAMS::ECDH1_DERIVE_PARAMS(ECDH1_DERIVE_PARAMS^ ecdh1_derive_params)
	{
		this->kdf = ecdh1_derive_params->kdf;

		if (ecdh1_derive_params->sharedData == nullptr)
		{
			this->sharedData = nullptr;
		}
		else
		{
			this->sharedData = gcnew array<Byte>(ecdh1_derive_params->sharedData->Length);
			for (int i = 0; i < this->sharedData->Length; i++)
				this->sharedData[i] = ecdh1_derive_params->sharedData[i];
		}

		if (ecdh1_derive_params->publicData == nullptr)
		{
			this->publicData = nullptr;
		}
		else
		{
			this->publicData = gcnew array<Byte>(ecdh1_derive_params->publicData->Length);
			for (int i = 0; i < this->publicData->Length; i++)
				this->publicData[i] = ecdh1_derive_params->publicData[i];
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	/// <summary>
	/// Class constructor.
	/// </summary>
	DES_DERIVE_CBC_PARAMS::DES_DERIVE_CBC_PARAMS(array<Byte>^ iv, array<Byte>^ data)
	{
		if (iv == nullptr)
		{
			this->iv = nullptr;
		}
		else
		{
			this->iv = gcnew array<Byte>(iv->Length);
			for (int i = 0; i < this->iv->Length; i++)
				this->iv[i] = iv[i];
		}

		if (data == nullptr)
		{
			this->data = nullptr;
		}
		else
		{
			this->data = gcnew array<Byte>(data->Length);
			for (int i = 0; i < this->data->Length; i++)
				this->data[i] = data[i];
		}
	}

	/// <summary>
	/// Copy constructor.
	/// </summary>
	DES_DERIVE_CBC_PARAMS::DES_DERIVE_CBC_PARAMS(DES_DERIVE_CBC_PARAMS^ des_derive_cbc_params)
	{
		if (des_derive_cbc_params->iv == nullptr)
		{
			this->iv = nullptr;
		}
		else
		{
			this->iv = gcnew array<Byte>(des_derive_cbc_params->iv->Length);
			for (int i = 0; i < this->iv->Length; i++)
				this->iv[i] = des_derive_cbc_params->iv[i];
		}

		if (des_derive_cbc_params->data == nullptr)
		{
			this->data = nullptr;
		}
		else
		{
			this->data = gcnew array<Byte>(des_derive_cbc_params->data->Length);
			for (int i = 0; i < this->data->Length; i++)
				this->data[i] = des_derive_cbc_params->data[i];
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////

	/// <summary>
	/// Class constructor.
	/// </summary>
	DES3_DERIVE_CBC_PARAMS::DES3_DERIVE_CBC_PARAMS(array<Byte>^ iv, array<Byte>^ data)
	{
		if (iv == nullptr)
		{
			this->iv = nullptr;
		}
		else
		{
			this->iv = gcnew array<Byte>(iv->Length);
			for (int i = 0; i < this->iv->Length; i++)
				this->iv[i] = iv[i];
		}

		if (data == nullptr)
		{
			this->data = nullptr;
		}
		else
		{
			this->data = gcnew array<Byte>(data->Length);
			for (int i = 0; i < this->data->Length; i++)
				this->data[i] = data[i];
		}
	}

	/// <summary>
	/// Copy constructor.
	/// </summary>
	DES3_DERIVE_CBC_PARAMS::DES3_DERIVE_CBC_PARAMS(DES3_DERIVE_CBC_PARAMS^ des3_derive_cbc_params)
	{
		if (des3_derive_cbc_params->iv == nullptr)
		{
			this->iv = nullptr;
		}
		else
		{
			this->iv = gcnew array<Byte>(des3_derive_cbc_params->iv->Length);
			for (int i = 0; i < this->iv->Length; i++)
				this->iv[i] = des3_derive_cbc_params->iv[i];
		}

		if (des3_derive_cbc_params->data == nullptr)
		{
			this->data = nullptr;
		}
		else
		{
			this->data = gcnew array<Byte>(des3_derive_cbc_params->data->Length);
			for (int i = 0; i < this->data->Length; i++)
				this->data[i] = des3_derive_cbc_params->data[i];
		}
	}
}