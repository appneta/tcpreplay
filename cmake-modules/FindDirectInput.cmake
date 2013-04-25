# - try to find DirectInput library (part of DirectX SDK)
#
# Cache Variables: (probably not for direct use in your scripts)
#  DIRECTINPUT_DXGUID_LIBRARY
#  DIRECTINPUT_DXERR_LIBRARY
#  DIRECTINPUT_DINPUT_LIBRARY
#  DIRECTINPUT_INCLUDE_DIR
#
# Non-cache variables you should use in your CMakeLists.txt:
#  DIRECTINPUT_LIBRARIES
#  DIRECTINPUT_INCLUDE_DIRS
#  DIRECTINPUT_FOUND - if this is not true, do not attempt to use this library
#
# Requires these CMake modules:
#  FindPackageHandleStandardArgs (known included with CMake >=2.6.2)
#
# Original Author:
# 2011 Ryan Pavlik <rpavlik@iastate.edu> <abiryan@ryand.net>
# http://academic.cleardefinition.com
# Iowa State University HCI Graduate Program/VRAC
#
# Copyright Iowa State University 2011.
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)


set(DIRECTINPUT_ROOT_DIR
	"${DIRECTINPUT_ROOT_DIR}"
	CACHE
	PATH
	"Root directory to search for DirectX/DirectInput")

if(MSVC)
	file(TO_CMAKE_PATH "$ENV{ProgramFiles}" _PROG_FILES)
	file(TO_CMAKE_PATH "$ENV{ProgramFiles(x86)}" _PROG_FILES_X86)
	if(_PROG_FILES_X86)
		set(_PROG_FILES "${_PROG_FILES_X86}")
	endif()
	if(CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(_lib_suffixes lib/x64 lib)
	else()
		set(_lib_suffixes lib/x86 lib)
	endif()
	macro(_append_dxsdk_in_inclusive_range _low _high)
		if((NOT MSVC_VERSION LESS ${_low}) AND (NOT MSVC_VERSION GREATER ${_high}))
			list(APPEND DXSDK_DIRS ${ARGN})
		endif()
	endmacro()
	_append_dxsdk_in_inclusive_range(1500 1600 "${_PROG_FILES}/Microsoft DirectX SDK (June 2010)")
	_append_dxsdk_in_inclusive_range(1400 1600
		"${_PROG_FILES}/Microsoft DirectX SDK (February 2010)"
		"${_PROG_FILES}/Microsoft DirectX SDK (August 2009)"
		"${_PROG_FILES}/Microsoft DirectX SDK (March 2009)"
		"${_PROG_FILES}/Microsoft DirectX SDK (November 2008)"
		"${_PROG_FILES}/Microsoft DirectX SDK (August 2008)"
		"${_PROG_FILES}/Microsoft DirectX SDK (June 2008)"
		"${_PROG_FILES}/Microsoft DirectX SDK (March 2008)")
	_append_dxsdk_in_inclusive_range(1310 1500
		"${_PROG_FILES}/Microsoft DirectX SDK (November 2007)"
		"${_PROG_FILES}/Microsoft DirectX SDK (August 2007)"
		"${_PROG_FILES}/Microsoft DirectX SDK (June 2007)"
		"${_PROG_FILES}/Microsoft DirectX SDK (April 2007)"
		"${_PROG_FILES}/Microsoft DirectX SDK (February 2007)"
		"${_PROG_FILES}/Microsoft DirectX SDK (December 2006)"
		"${_PROG_FILES}/Microsoft DirectX SDK (October 2006)"
		"${_PROG_FILES}/Microsoft DirectX SDK (August 2006)"
		"${_PROG_FILES}/Microsoft DirectX SDK (June 2006)"
		"${_PROG_FILES}/Microsoft DirectX SDK (April 2006)"
		"${_PROG_FILES}/Microsoft DirectX SDK (February 2006)")

	file(TO_CMAKE_PATH "$ENV{DXSDK_DIR}" ENV_DXSDK_DIR)
	if(ENV_DXSDK_DIR)
		list(APPEND DXSDK_DIRS ${ENV_DXSDK_DIR})
	endif()
else()
	set(_lib_suffixes lib)
	set(DXSDK_DIRS /mingw)
endif()

find_path(DIRECTINPUT_INCLUDE_DIR
	NAMES
	dinput.h
	PATHS
	${DXSDK_DIRS}
	HINTS
	"${DIRECTINPUT_ROOT_DIR}"
	PATH_SUFFIXES
	include)

find_library(DIRECTINPUT_DXGUID_LIBRARY
	NAMES
	dxguid
	PATHS
	${DXSDK_DIRS}
	HINTS
	"${DIRECTINPUT_ROOT_DIR}"
	PATH_SUFFIXES
	${_lib_suffixes})

if(DIRECTINPUT_DXGUID_LIBRARY)
	get_filename_component(_dinput_lib_dir
		${DIRECTINPUT_DXGUID_LIBRARY}
		PATH)
endif()

find_library(DIRECTINPUT_DINPUT_LIBRARY
	NAMES
	dinput8
	dinput
	PATHS
	${DXSDK_DIRS}
	HINTS
	"${_dinput_lib_dir}"
	"${DIRECTINPUT_ROOT_DIR}"
	PATH_SUFFIXES
	${_lib_suffixes})

find_library(DIRECTINPUT_DXERR_LIBRARY
	NAMES
	dxerr
	dxerr9
	dxerr8
	PATHS
	${DXSDK_DIRS}
	HINTS
	"${_dinput_lib_dir}"
	"${DIRECTINPUT_ROOT_DIR}"
	PATH_SUFFIXES
	${_lib_suffixes})
set(DIRECTINPUT_EXTRA_CHECK)
if(DIRECTINPUT_INCLUDE_DIR)
	if(MSVC80)
		set(DXSDK_DEPRECATION_BUILD 1962)
	endif()

	if(DXSDK_DEPRECATION_BUILD)
		include(CheckCSourceCompiles)
		set(_dinput_old_includes ${CMAKE_REQUIRED_INCLUDES})
		set(CMAKE_REQUIRED_INCLUDES "${DIRECTINPUT_INCLUDE_DIR}")
		check_c_source_compiles(
			"
			#include <dxsdkver.h>
			#if _DXSDK_BUILD_MAJOR >= ${DXSDK_DEPRECATION_BUILD}
			#error
			#else
			int main(int argc, char * argv[]) {
				return 0;
			}
			"
			DIRECTINPUT_SDK_SUPPORTS_COMPILER)
		set(DIRECTINPUT_EXTRA_CHECK DIRECTINPUT_SDK_SUPPORTS_COMPILER)
		set(CMAKE_REQUIRED_INCLUDES "${_dinput_old_includes}")
	endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DirectInput
	DEFAULT_MSG
	DIRECTINPUT_DINPUT_LIBRARY
	DIRECTINPUT_DXGUID_LIBRARY
	DIRECTINPUT_DXERR_LIBRARY
	DIRECTINPUT_INCLUDE_DIR
	${DIRECTINPUT_EXTRA_CHECK})

if(DIRECTINPUT_FOUND)
	set(DIRECTINPUT_LIBRARIES
		"${DIRECTINPUT_DXGUID_LIBRARY}"
		"${DIRECTINPUT_DXERR_LIBRARY}"
		"${DIRECTINPUT_DINPUT_LIBRARY}")

	set(DIRECTINPUT_INCLUDE_DIRS "${DIRECTINPUT_INCLUDE_DIR}")

	mark_as_advanced(DIRECTINPUT_ROOT_DIR)
endif()

mark_as_advanced(DIRECTINPUT_DINPUT_LIBRARY
	DIRECTINPUT_DXGUID_LIBRARY
	DIRECTINPUT_DXERR_LIBRARY
	DIRECTINPUT_INCLUDE_DIR)
