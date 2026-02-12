#include "stdafx.h"
#include "SecureModuleException.h"
#include "Utils.h"

namespace LL_SecureModule
{
	String^ SecureModuleException::GetSecureModuleExceptionNoString(CK_RV errorCode)
	{
		return Utils::GetCKRString(errorCode);
	}
}