#pragma once

using namespace System;

#include <cmlib.h>

namespace LL_SecureModule
{
	/// <summary>
	/// The transport mode is a facility that allows the HSM hardware to be removed from the host system PCI bus without causing a board removal tamper condition.
	/// <para>A board removal tamper will remove all sensitive material from the HSM including the HSM configuration, all keys and certificates.</para>
	/// <para>It is the Administrator‘s responsibility to set the required transport mode on the HSM.</para>
	/// <para>NOTE: The transport mode does not disable the tamper response mechanism entirely. Any attempt to physically attack the HSM will still result in a tamper response.</para>
	/// <para>NOTE: On the ProtectServer Gold hardware, transport mode also disables the external tamper jumper. This is not the case for other hardware platforms such as the ProtectServer Internal Express product, and should not be relied on as a general behavior.</para>
	/// </summary>
	public enum class TransportMode
	{
		/// <summary>
		/// To be applied when HSM is installed and configured. This mode will tamper the HSM if removed from the PCI Bus.
		/// </summary>
		NO_TRANSPORT_MODE = CK_NO_TRANSPORT_MODE,

		/// <summary>
		/// HSM will not be tampered after removal from the PCI bus. HSM will automatically change to No Transport Mode the next time the HSM is reset or power is removed and restored.
		/// </summary>
		SINGLE_TRANSPORT_MODE = CK_SINGLE_TRANSPORT_MODE,

		/// <summary>
		/// HSM will not be tampered by being removed from the PCI bus.
		/// </summary>
		CONTINUOUS_TRANSPORT_MODE = CK_CONTINUOUS_TRANSPORT_MODE
	};

	/// <summary>
	/// Flags indicating capabilities and status of the slot as defined.
	/// </summary>
	public enum class FMStatus
	{
		/// <summary>
		/// Device contains a FM, and it is not active.
		/// </summary>
		FM_DISABLED = CM_FM_DISABLED,

		/// <summary>
		/// Device contains a FM, and it is active.
		/// </summary>
		FM_ENABLED = CM_FM_ENABLED,

		/// <summary>
		/// Device does not contain a FM.
		/// </summary>
		NO_FM_LOADED = CM_NO_FM_LOADED,

		/// <summary>
		/// Device does not allow FMs.
		/// </summary>
		NO_FM_SUPPORT = CM_NO_FM_SUPPORT
	};

	/// <summary>
	/// Flags indicating capabilities and status of the slot as defined.
	/// </summary>
	public enum class BatteryStatus
	{
		/// <summary>
		/// Battery is low.
		/// </summary>
		Low = 0,

		/// <summary>
		/// Battery is good.
		/// </summary>
		Good = 1,
	};

	/// <summary>
	/// Various retrievable HSM device information.
	/// </summary>
	public enum class DeviceInfoType
	{
		/// <summary>
		/// Adapter model.
		/// </summary>
		MODEL = CM_MODEL,

		/// <summary>
		/// Adapter batch.
		/// </summary>
		BATCH = CM_BATCH,

		/// <summary>
		/// Date of manufacture.
		/// </summary>
		DATE_OF_MANUFACTURE,

		/// <summary>
		/// Adapter serial number.
		/// </summary>
		SERIAL_NUMBER = CM_SERIAL_NUMBER,

		/// <summary>
		/// Current security mode.
		/// </summary>
		SECURITY_MODE = CM_SECURITY_MODE,

		/// <summary>
		/// Current transport mode.
		/// <para>One of the following: NO_TRANSPORT_MODE, SINGLE_TRANSPORT_MODE, CONTINUOUS_TRANSPORT_MODE</para>
		/// </summary>
		TRANSPORT_MODE = CM_TRANSPORT_MODE,

		/// <summary>
		/// Current time of adapter clock (LOCAL) in the
		/// format "hh:mm:ss DD/MM/YYYY (TimeZone)".If the clock has not been set, then "UNAVAILABLE" is returned and SyncClock or SetClock should be called.
		/// </summary>
		CLOCK_LOCAL = CM_CLOCK_LOCAL,

		/// <summary>
		/// Board revision.
		/// </summary>
		BOARD_REVISION = CM_BOARD_REVISION,

		/// <summary>
		/// Firmware revision.
		/// </summary>
		FIRMWARE_REVISION = CM_FIRMWARE_REVISION,

		/// <summary>
		/// Cprov revision.
		/// </summary>
		CPROV_REVISION = CM_CPROV_REVISION,

		/// <summary>
		/// Battery status.
		/// </summary>
		BATTERY_STATUS = CM_BATTERY_STATUS,

		/// <summary>
		/// PCB version.
		/// </summary>
		PCB_VERSION = CM_PCB_VERSION,

		/// <summary>
		/// FPGA version.
		/// </summary>
		FPGA_VERSION = CM_FPGA_VERSION,

		/// <summary>
		/// External input pin states.
		/// </summary>
		EXTERNAL_PINS = CM_EXTERNAL_PINS,

		/// <summary>
		/// Adapters heap space (RAM) available.
		/// </summary>
		FREE_MEMORY = CM_FREE_MEMORY,

		/// <summary>
		/// Total secure memory.
		/// </summary>
		TOTAL_PUBLIC_MEMORY = CM_TOTAL_PUBLIC_MEMORY,

		/// <summary>
		/// Available secure memory.
		/// </summary>
		FREE_PUBLIC_MEMORY = CM_FREE_PUBLIC_MEMORY,

		/// <summary>
		/// Number of sessions open on all devices.
		/// </summary>
		TOTAL_SESSION_COUNT = CM_TOTAL_SESSION_COUNT,

		/// <summary>
		/// Number of active devices.
		/// </summary>
		DEVICE_COUNT = CM_DEVICE_COUNT,

		/// <summary>
		/// Number of slots on a device.
		/// </summary>
		SLOT_COUNT = CM_SLOT_COUNT,

		/// <summary>
		/// Name (label) of a token, optionally prefixed with "removable" or "admin".
		/// <para>"uninitialised" if the token has not been initialised.</para>
		/// <para>'itemNumber' is the index of the slot within the device.</para>
		/// </summary>
		TOKEN_NAME = CM_TOKEN_NAME,

		/// <summary>
		/// Number of entries in device event log.
		/// </summary>
		EVENT_LOG_COUNT = CM_EVENT_LOG_COUNT,

		/// <summary>
		/// 'true' or 'false'.
		/// </summary>
		EVENT_LOG_FULL = CM_EVENT_LOG_FULL,

		/// <summary>
		/// 'true' or 'false'.
		/// </summary>
		DEVICE_INITIALISED = CM_DEVICE_INITIALISED,

		/// <summary>
		/// Number of applications currently using cryptoki.
		/// </summary>
		APPLICATION_COUNT = CM_APPLICATION_COUNT,

		/// <summary>
		/// The total number of sessions open on the specified token.
		/// <para>'itemNumber' is the index of the slot within the device.</para>
		/// </summary>
		TOKEN_SESSION_COUNT = CM_TOKEN_SESSION_COUNT,

		/// <summary>
		/// Label of the FM inside the device. Empty string if the device is not FM-enabled, or there are no FMs in the device(not when there is an FM, and it is disabled).
		/// </summary>
		FM_LABEL = CM_FM_LABEL,

		/// <summary>
		/// Version of the FM inside the device. Empty string if the device is not FM-enabled, or there are no FMs in the device(not when there is an FM, and it is disabled).
		/// </summary>
		FM_VERSION = CM_FM_VERSION,

		/// <summary>
		/// Manufacturer of the FM inside the device. Empty string if the device is not FM-enabled, or there are no FMs in the device(not when there is an FM, and it is disabled).
		/// </summary>
		FM_MANUFACTURER = CM_FM_MANUFACTURER,

		/// <summary>
		/// Build time of the FM inside the device. Empty if the device is not FM-enabled, or there are no FMs in the device(not when there is an FM, and it is disabled).
		/// </summary>
		FM_BUILD_TIME = CM_FM_BUILD_TIME,

		/// <summary>
		/// Fingerprint (a hexadecimal string identifying the FM image) of the FM inside the device.Empty string if the device is not FM-enabled, or there are no FMs in the device (not when there is an FM, and it is disabled).
		/// </summary>
		FM_FINGERPRINT = CM_FM_FINGERPRINT,

		/// <summary>
		/// Amount of ROM the FM is occupying inside the device.Returns "0" if the device is not FM-enabled, or there are no FMs in the device (not when there is an FM, and it is disabled).
		/// </summary>
		FM_ROM_SIZE = CM_FM_ROM_SIZE,

		/// <summary>
		/// Amount of static RAM the FM is using inside the device(the actual amount of RAM used may be higher, due to dynamic memory allocations).Returns "0" if the device is not FM-enabled, there are no FMs in the device, or when there is an FM, and it is disabled).
		/// </summary>
		FM_RAM_SIZE = CM_FM_RAM_SIZE,

		/// <summary>
		/// Current status of Functional Module.
		/// <para>One of the following: CM_FM_ENABLED, FM_DISABLED, NO_FM_LOADED, NO_FM_SUPPORT.</para>
		/// </summary>
		FM_STATUS = CM_FM_STATUS,

		/// <summary>
		/// 'true' or 'false'.
		/// </summary>
		DEVICE_ALLOWS_FM = CM_DEVICE_ALLOWS_FM,

		/// <summary>
		/// Current time of adapter clock (GMT) in the format "hh:mm:ss DD/MM/YYYY".If the clock has not been set, then "UNAVAILABLE" is returned and SyncClock or SetClock should be called.
		/// </summary>
		CLOCK_GMT = CM_CLOCK_GMT,

		/// <summary>
		/// The error code returned by the FM startup entry point. Returns "0" if the device is not FM-enabled, there are no FMs in the device, or when there is an FM, and it is disabled).
		/// </summary>
		FM_STARTUP_STATUS = CM_FM_STARTUP_STATUS,

		/// <summary>
		/// The current status of the RTC Adjustment access control.
		/// <para>'true' or 'false'.</para>
		/// </summary>
		RTC_AAC_ENABLED = CM_RTC_AAC_ENABLED,

		/// <summary>
		/// The current maximum amount of RTC adjustments(in number of seconds) setting. It is only in effect if RTC_AAC_ENABLED is 'true'. This is a numerical value.
		/// </summary>
		RTC_AAC_GUARD_SECONDS = CM_RTC_AAC_GUARD_SECONDS,

		/// <summary>
		/// The current maximum number of RTC adjustments setting.It is only in effect if RTC_AAC_ENABLED is 'true'. This is a numerical value.
		/// </summary>
		RTC_AAC_GUARD_COUNT = CM_RTC_AAC_GUARD_COUNT,

		/// <summary>
		/// The current gurad duration for the enforcement of RTC adjustment limits.It is only in effect if RTC_AAC_ENABLED is 'true'. This is a numerical value.
		/// </summary>
		RTC_AAC_GUARD_DURATION = CM_RTC_AAC_GUARD_DURATION,

		/// <summary>
		/// Extra h/w information string  comma separated list of [label]=[value] which are set at manufacturing time.
		/// </summary>
		HW_EXT_INFO_STR = CM_HW_EXT_INFO_STR,

		/// <summary>
		/// pinpad dscovery. Returns [port as 32bits] [name as a string].
		/// </summary>
		PINPAD_DESC = CM_PINPAD_DESC,

#if   CPROV_VER_MAJOR == 5
		/// <summary>
		/// ID of the FM inside the device (Just for ProtectServer2 [PL1500])
		/// <para>Empty string if the device is not FM-enabled, or there are no FMs in the device (not when there is an FM, and it is disabled).</para>
		/// </summary>
		FM_ID = CM_FM_ID,

		/// <summary>
		/// HSM Temperature. Returns deg C
		/// <para>Temperature reading does not function with legacy K5 cards. Therefore, the temperature displayed on PSE and PSI-E is 0 Celsius, which is the default value.</para>
		/// </summary>
		TEMPERATURE = CM_TEMP,

		/// <summary>
		/// Determine total session open to an HSM
		/// </summary>
		HSM_SESSION_COUNT = CM_HSM_SESSION_COUNT,
#endif

		/// <summary>
		/// ...
		/// </summary>
		MAX_INFO = CM_MAX_E_INFO,
	};
}
