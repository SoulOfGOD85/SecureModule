#include "stdafx.h"
#include "Attribute.h"

namespace LL_SecureModule
{
	/// <summary>
	/// Initializes a new instance of the <see cref="SMAttribute" /> class.
	/// </summary>
	/// <param name="attributeType">Type of the attribute.</param>
	SMAttribute::SMAttribute(AttributeType attributeType)
	{
		this->CKA = attributeType;
		this->value = nullptr;
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="SMAttribute"/> class.
	/// </summary>
	/// <param name="attributeType">Type of the attribute.</param>
	/// <param name="value">The value.</param>
	SMAttribute::SMAttribute(AttributeType attributeType, Object^ value)
	{
		this->CKA = attributeType;
		this->value = value;
	}

	/// <summary>
	/// Copy constructor.
	/// </summary>
	/// <param name="attribute">The attribute.</param>
	SMAttribute::SMAttribute(SMAttribute^ attribute)
	{
		this->CKA = attribute->CKA;
		this->value = attribute->value;
	}

	/// <summary>
	/// Get the attribute System::Type.
	/// </summary>
	/// <returns></returns>
	System::TypeCode SMAttribute::GetAttributeSystemTypeCode()
	{
		switch (this->CKA)
		{
		case AttributeType::TOKEN:
		case AttributeType::PRIVATE:
		case AttributeType::TRUSTED:
		case AttributeType::SENSITIVE:
		case AttributeType::ENCRYPT:
		case AttributeType::DECRYPT:
		case AttributeType::WRAP:
		case AttributeType::UNWRAP:
		case AttributeType::SIGN:
		case AttributeType::SIGN_RECOVER:
		case AttributeType::VERIFY:
		case AttributeType::VERIFY_RECOVER:
		case AttributeType::DERIVE:
		case AttributeType::EXTRACTABLE:
		case AttributeType::LOCAL:
		case AttributeType::NEVER_EXTRACTABLE:
		case AttributeType::ALWAYS_SENSITIVE:
		case AttributeType::MODIFIABLE:
		case AttributeType::SECONDARY_AUTH:
		case AttributeType::RESET_ON_INIT:
		case AttributeType::HAS_RESET:
		case AttributeType::EXPORT:
		case AttributeType::EXPORTABLE:
		case AttributeType::DELETABLE:
		case AttributeType::SIGN_LOCAL_CERT:
		case AttributeType::IMPORT:
			return TypeCode::Boolean;

		case AttributeType::CLASS:
		case AttributeType::CERTIFICATE_TYPE:
		case AttributeType::KEY_TYPE:
		case AttributeType::MODULUS_BITS:
		case AttributeType::PRIME_BITS:
		case AttributeType::VALUE_BITS:
		case AttributeType::VALUE_LEN:
		case AttributeType::KEY_GEN_MECHANISM:
		case AttributeType::AUTH_PIN_FLAGS:
		case AttributeType::HW_FEATURE_TYPE:
		case AttributeType::KEY_SIZE:
		case AttributeType::USAGE_COUNT:
#ifndef _PTKC_V400_
		case AttributeType::USAGE_LIMIT:
			return TypeCode::UInt32;
#endif

		case AttributeType::VALUE:
		case AttributeType::OBJECT_ID:
		case AttributeType::ISSUER:
		case AttributeType::SERIAL_NUMBER:
		case AttributeType::AC_ISSUER:
		case AttributeType::OWNER:
		case AttributeType::ATTR_TYPES:
		case AttributeType::CHECK_VALUE:
		case AttributeType::SUBJECT:
		case AttributeType::ID:
		case AttributeType::MODULUS:
		case AttributeType::PUBLIC_EXPONENT:
		case AttributeType::PRIVATE_EXPONENT:
		case AttributeType::PRIME_1:
		case AttributeType::PRIME_2:
		case AttributeType::EXPONENT_1:
		case AttributeType::EXPONENT_2:
		case AttributeType::COEFFICIENT:
		case AttributeType::PRIME:
		case AttributeType::SUBPRIME:
		case AttributeType::BASE:
		case AttributeType::ECDSA_PARAMS:
		case AttributeType::EC_POINT:
#ifndef _PTKC_V400_
		case AttributeType::ADMIN_CERT:
#endif
		case AttributeType::PKI_ATTRIBUTE_BER_ENCODED:
		case AttributeType::SERIAL_NUMBER_INT:
			return TypeCode::Byte;

		case AttributeType::LABEL:
		case AttributeType::APPLICATION:
		case AttributeType::ISSUER_STR:
		case AttributeType::SUBJECT_STR:
			return TypeCode::String;

		case AttributeType::START_DATE:
		case AttributeType::END_DATE:
		case AttributeType::TIME_STAMP:
		case AttributeType::CERTIFICATE_START_TIME:
		case AttributeType::CERTIFICATE_END_TIME:
			return TypeCode::DateTime;

		default:
			break;
		}

		return TypeCode::Empty;
	}
}