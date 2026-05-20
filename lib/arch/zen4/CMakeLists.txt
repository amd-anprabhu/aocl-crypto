# Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 #    this list of conditions and the following disclaimer in the documentation
 #    and/or other materials provided with the distribution.
 # 3. Neither the name of the copyright holder nor the names of its contributors
 #    may be used to endorse or promote products derived from this software
 # without specific prior written permission.
 #
 # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 # AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 # IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 # ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 # LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 # CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.

 ADD_SUBDIRECTORY(gcm) # gcm ZEN4 specific

FILE(GLOB ZEN4_SRCS "*.cc")

alcp_get_arch_cflags_zen4()

#CMAKE_POLICY(SET CMP0079 NEW)

MESSAGE(STATUS "COMPILE_FLAGS:ZEN4:${ARCH_COMPILE_FLAGS}")


#Adding -funroll-loops only to sha2_512_avx512.cc file in this arch since it improves performance for digest.
# This flag may improve or decrease performance. But for current implementation in file, it improves performance.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
	set_source_files_properties(sha2_512_avx512.cc PROPERTIES COMPILE_FLAGS "-funroll-loops")
endif()

# FIXME: GCC 15 introduced a throughput regression in SHA256 multibuffer on Zen5.
#
# The regression is caused by GCC commit f0ab3de6ec0e3540f2e57f3f5628005f0a4e3fa5
# ("Zen5 tuning part 4: update reassociation width") which increased znver5
# reassociation widths from {4,4,3,6} to {6,6,4,6}. This causes register pressure
# and spills in the AVX512 integer-heavy SHA256 multibuffer kernel.
#
# Workaround: Override -mtune to znver4 to use pre-regression reassociation widths.
# This workaround is applied strictly for GCC 15. Future GCC versions must be
# tested and this condition must be adjusted accordingly.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "15" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "16")
	set_source_files_properties(sha256_mb_avx512.cc PROPERTIES COMPILE_FLAGS "-mtune=znver4")
	MESSAGE(WARNING "GCC 15 workaround: adding -mtune=znver4 to sha256_mb_avx512.cc due to reassociation width regression")
endif()

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/include)

ADD_LIBRARY(arch_zen4
	OBJECT
	${ZEN4_SRCS})

TARGET_COMPILE_OPTIONS(arch_zen4 PRIVATE ${ARCH_COMPILE_FLAGS})

# BUG in GCC-12
if(CMAKE_COMPILER_IS_GCC)
if(CMAKE_COMPILER_GCC_VERSION MATCHES "12")
 	MESSAGE(WARNING "GCC12 AVX512 Bug: Using -Wno-maybe-uninitialized -Wno-uninitialized for ZEN4")
	TARGET_COMPILE_OPTIONS(arch_zen4 PRIVATE "-Wno-maybe-uninitialized" "-Wno-uninitialized")
endif(CMAKE_COMPILER_GCC_VERSION MATCHES "12")
endif(CMAKE_COMPILER_IS_GCC)

IF(ALCP_ENABLE_CIPHER_MULTI_UPDATE)
	TARGET_COMPILE_DEFINITIONS(arch_zen4 PRIVATE "AES_MULTI_UPDATE")	
ENDIF(ALCP_ENABLE_CIPHER_MULTI_UPDATE)

TARGET_LINK_LIBRARIES(alcp PRIVATE arch_zen4)
TARGET_LINK_LIBRARIES(alcp_static PRIVATE arch_zen4)
