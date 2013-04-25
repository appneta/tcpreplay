# - Find the Windows SDK aka Platform SDK
#
# Variables:
#  WINDOWSSDK_FOUND - if any version of the windows or platform SDK was found that is usable with the current version of visual studio
#  WINDOWSSDK_LATEST_DIR
#  WINDOWSSDK_LATEST_NAME
#  WINDOWSSDK_FOUND_PREFERENCE - if we found an entry indicating a "preferred" SDK listed for this visual studio version
#  WINDOWSSDK_PREFERRED_DIR
#  WINDOWSSDK_PREFERRED_NAME
#
#  WINDOWSSDK_DIRS - contains no duplicates, ordered most recent first.
#  WINDOWSSDK_PREFERRED_FIRST_DIRS - contains no duplicates, ordered with preferred first, followed by the rest in descending recency
#
# Functions:
#  windowssdk_name_lookup(<directory> <output variable>) - Find the name corresponding with the SDK directory you pass in, or
#     NOTFOUND if not recognized. Your directory must be one of WINDOWSSDK_DIRS for this to work.
#
# Requires these CMake modules:
#  FindPackageHandleStandardArgs (known included with CMake >=2.6.2)
#
# Original Author:
# 2012 Ryan Pavlik <rpavlik@iastate.edu> <abiryan@ryand.net>
# http://academic.cleardefinition.com
# Iowa State University HCI Graduate Program/VRAC
#
# Copyright Iowa State University 2012.
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

set(_preferred_sdk_dirs)
set(_win_sdk_dirs)
set(_win_sdk_versanddirs)
if(MSVC_VERSION GREATER 1310) # Newer than VS .NET/VS Toolkit 2003

	# Environment variable for SDK dir
	if(EXISTS "$ENV{WindowsSDKDir}" AND (NOT "$ENV{WindowsSDKDir}" STREQUAL ""))
		message(STATUS "Got $ENV{WindowsSDKDir} - Windows/Platform SDK directories: ${_win_sdk_dirs}")
		list(APPEND _preferred_sdk_dirs "$ENV{WindowsSDKDir}")
	endif()

	if(MSVC_VERSION LESS 1600)
		# Per-user current Windows SDK for VS2005/2008
		get_filename_component(_sdkdir
			"[HKEY_CURRENT_USER\\Software\\Microsoft\\Microsoft SDKs\\Windows;CurrentInstallFolder]"
			ABSOLUTE)
		if(EXISTS "${_sdkdir}")
			list(APPEND _preferred_sdk_dirs "${_sdkdir}")
		endif()

		# System-wide current Windows SDK for VS2005/2008
		get_filename_component(_sdkdir
			"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SDKs\\Windows;CurrentInstallFolder]"
			ABSOLUTE)
		if(EXISTS "${_sdkdir}")
			list(APPEND _preferred_sdk_dirs "${_sdkdir}")
		endif()
	endif()

	if(MSVC_VERSION LESS 1700)
		# VC 10 and older has broad target support
		set(_winsdk_vistaonly)
	else()
		# VC 11 by default targets Vista and later only, so we can add a few more SDKs that (might?) only work on vista+
		set(_winsdk_vistaonly
			v8.0
			v8.0A)
	endif()
	foreach(_winsdkver v7.1 v7.0A v6.1 v6.0A v6.0)
		get_filename_component(_sdkdir
			"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SDKs\\Windows\\${_winsdkver};InstallationFolder]"
			ABSOLUTE)
		if(EXISTS "${_sdkdir}")
			list(APPEND _win_sdk_dirs "${_sdkdir}")
			list(APPEND
				_win_sdk_versanddirs
				"Windows SDK ${_winsdkver}"
				"${_sdkdir}")
		endif()
	endforeach()
endif()
if(MSVC_VERSION GREATER 1200)
	foreach(_platformsdkinfo
		"D2FF9F89-8AA2-4373-8A31-C838BF4DBBE1_Microsoft Platform SDK for Windows Server 2003 R2"
		"8F9E5EF3-A9A5-491B-A889-C58EFFECE8B3_Microsoft Platform SDK for Windows Server 2003 SP1")
		string(SUBSTRING "${_platformsdkinfo}" 0 36 _platformsdkguid)
		string(SUBSTRING "${_platformsdkinfo}" 37 -1 _platformsdkname)
		get_filename_component(_sdkdir
			"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\MicrosoftSDK\\InstalledSDKs\\${_platformsdkguid};Install Dir]"
			ABSOLUTE)
		if(EXISTS "${_sdkdir}")
			list(APPEND _win_sdk_dirs "${_sdkdir}")
			list(APPEND _win_sdk_versanddirs "${_platformsdkname}" "${_sdkdir}")
		endif()

		get_filename_component(_sdkdir
			"[HKEY_CURRENT_USER\\Software\\Microsoft\\MicrosoftSDK\\InstalledSDKs\\${_platformsdkguid};Install Dir]"
			ABSOLUTE)
		if(EXISTS "${_sdkdir}")
			list(APPEND _win_sdk_dirs "${_sdkdir}")
			list(APPEND _win_sdk_versanddirs "${_platformsdkname}" "${_sdkdir}")
		endif()
	endforeach()
endif()

set(_win_sdk_versanddirs
	"${_win_sdk_versanddirs}"
	CACHE
	INTERNAL
	"mapping between windows sdk version locations and names"
	FORCE)

function(windowssdk_name_lookup _dir _outvar)
	list(FIND _win_sdk_versanddirs "${_dir}" _diridx)
	math(EXPR _nameidx "${_diridx} - 1")
	if(${_nameidx} GREATER -1)
		list(GET _win_sdk_versanddirs ${_nameidx} _sdkname)
	else()
		set(_sdkname "NOTFOUND")
	endif()
	set(${_outvar} "${_sdkname}" PARENT_SCOPE)
endfunction()

if(_win_sdk_dirs)
	# Remove duplicates
	list(REMOVE_DUPLICATES _win_sdk_dirs)
	list(GET _win_sdk_dirs 0 WINDOWSSDK_LATEST_DIR)
	windowssdk_name_lookup("${WINDOWSSDK_LATEST_DIR}"
		WINDOWSSDK_LATEST_NAME)
	set(WINDOWSSDK_DIRS ${_win_sdk_dirs})
endif()
if(_preferred_sdk_dirs)
	list(GET _preferred_sdk_dirs 0 WINDOWSSDK_PREFERRED_DIR)
	windowssdk_name_lookup("${WINDOWSSDK_LATEST_DIR}"
		WINDOWSSDK_PREFERRED_NAME)
	set(WINDOWSSDK_PREFERRED_FIRST_DIRS
		${_preferred_sdk_dirs}
		${_win_sdk_dirs})
	list(REMOVE_DUPLICATES WINDOWSSDK_PREFERRED_FIRST_DIRS)
	set(WINDOWSSDK_FOUND_PREFERENCE ON)

	# In case a preferred dir was found that isn't found otherwise
	#set(WINDOWSSDK_DIRS ${WINDOWSSDK_DIRS} ${WINDOWSSDK_PREFERRED_FIRST_DIRS})
	#list(REMOVE_DUPLICATES WINDOWSSDK_DIRS)
else()
	set(WINDOWSSDK_PREFERRED_DIR "${WINDOWSSDK_LATEST_DIR}")
	set(WINDOWSSDK_PREFERRED_NAME "${WINDOWSSDK_LATEST_NAME}")
	set(WINDOWSSDK_PREFERRED_FIRST_DIRS ${WINDOWSSDK_DIRS})
	set(WINDOWSSDK_FOUND_PREFERENCE OFF)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WindowsSDK
	"No compatible version of the Windows SDK or Platform SDK found."
	WINDOWSSDK_DIRS)

if(WINDOWSSDK_FOUND)
	if(NOT _winsdk_remembered_dirs STREQUAL WINDOWSSDK_DIRS)
		set(_winsdk_remembered_dirs
			"${WINDOWSSDK_DIRS}"
			CACHE
			INTERNAL
			""
			FORCE)
		if(NOT WindowsSDK_FIND_QUIETLY)
			foreach(_sdkdir ${WINDOWSSDK_DIRS})
				windowssdk_name_lookup("${_sdkdir}" _sdkname)
				message(STATUS " - Found ${_sdkname} at ${_sdkdir}")
			endforeach()
		endif()
	endif()
endif()
