cmake_minimum_required(VERSION 3.28)

project(NekoIMS VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()


set(CMAKE_XCODE_ATTRIBUTE_RANLIBFLAGS "-c")

option(NEKOIMS_FULLY_STATIC "Link libc and libstdc++ statically too (-static)" ON)
if(APPLE)
  set(NEKOIMS_FULLY_STATIC OFF CACHE BOOL "Linking libc and libstdc++ statically is not supported on macOS" FORCE)
endif()
option(NEKOIMS_WITH_PCSC "Build pcsc-lite client library for simcard-server" OFF)

# MSVC has no -static; the equivalent is the static CRT (/MT), which has to
# be chosen before any dependency target is created.
if(MSVC AND NEKOIMS_FULLY_STATIC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(FetchContent)
include(ExternalProject)

# Everything below is built from source and linked statically.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(FETCHCONTENT_QUIET OFF)
set(FETCHCONTENT_TRY_FIND_PACKAGE_MODE NEVER)

# Never pick up system copies of optional deps; they'd pull in shared libs.
set(CMAKE_DISABLE_FIND_PACKAGE_OpenSSL ON)
set(CMAKE_DISABLE_FIND_PACKAGE_ZLIB ON)

##############################################################################
#
# Pinned dependencies
#

set(MBEDTLS_VERSION     3.6.7)
set(MBEDTLS_SHA256      a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6)
set(CURL_VERSION        8.22.0)
string(REPLACE "." "_" CURL_TAG ${CURL_VERSION})
set(CURL_SHA256         f7ef3ae8a22e521f289803fe93543eb64c329b58aa73a9e224dfd915a2a5f4f7)
set(JSON_VERSION        3.12.0)
set(JSON_SHA256         42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa)
set(RE_VERSION          4.12.0)
set(RE_SHA256           707b6194dd3b8d3fb1641ca08a0999aaac1d38d36b5c45514777a13ded311923)
set(BARESIP_VERSION     4.12.0)
set(BARESIP_SHA256      710d79d60c15c09f0aeb93e5d2f219e7f12ab93f62cab826e4280592a1ea155f)
set(OPENCORE_AMR_VERSION 0.1.6)
set(OPENCORE_AMR_SHA256 483eb4061088e2b34b358e47540b5d495a96cd468e361050fae615b1809dc4a1)
set(VO_AMRWBENC_VERSION 0.1.3)
set(VO_AMRWBENC_SHA256  5652b391e0f0e296417b841b02987d3fd33e6c0af342c69542cbb016a71d9d4e)
set(PCSCLITE_VERSION    2.5.2)
set(PCSCLITE_SHA256     60a08942d8c00a1d86a3bf4c64eddbf7a5569c7c54f6904e3f07801bb5316acd)
set(ALSA_LIB_VERSION    1.2.16.1)
set(ALSA_LIB_SHA256     f740db7f488255944ffd4428416ee3390a96742856916433df468c281436480e)
set(LIBG722_VERSION     1.2.8)
set(LIBG722_SHA256      953bf2ead9b0b0dde32fcbc022a2cf5029155405737eba203499e30b18610706)

##############################################################################
#
# mbedTLS (crypto for libre, TLS for libcurl)
#

set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)

FetchContent_Declare(mbedtls
  URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${MBEDTLS_VERSION}/mbedtls-${MBEDTLS_VERSION}.tar.bz2
  URL_HASH SHA256=${MBEDTLS_SHA256}
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(mbedtls)

# Consumed by the Find modules of both libre and libcurl. Values are target
# names, so find_path/find_library are skipped and linking resolves to targets.
set(MBEDTLS_INCLUDE_DIR "${mbedtls_SOURCE_DIR}/include" CACHE PATH "" FORCE)
set(MBEDTLS_LIBRARY    mbedtls    CACHE STRING "" FORCE)
set(MBEDX509_LIBRARY   mbedx509   CACHE STRING "" FORCE)
set(MBEDCRYPTO_LIBRARY mbedcrypto CACHE STRING "" FORCE)

##############################################################################
#
# libcurl
#

set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_LIBCURL_DOCS OFF CACHE BOOL "" FORCE)
set(BUILD_MISC_DOCS OFF CACHE BOOL "" FORCE)
set(ENABLE_CURL_MANUAL OFF CACHE BOOL "" FORCE)
set(CURL_USE_PKGCONFIG OFF CACHE BOOL "" FORCE)
set(CURL_USE_MBEDTLS ON CACHE BOOL "" FORCE)
set(CURL_USE_OPENSSL OFF CACHE BOOL "" FORCE)
set(CURL_ZLIB OFF CACHE STRING "" FORCE)
set(CURL_BROTLI OFF CACHE STRING "" FORCE)
set(CURL_ZSTD OFF CACHE STRING "" FORCE)
set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)
set(CURL_USE_LIBSSH OFF CACHE BOOL "" FORCE)
set(CURL_USE_GSSAPI OFF CACHE BOOL "" FORCE)
set(CURL_DISABLE_LDAP ON CACHE BOOL "" FORCE)
set(USE_NGHTTP2 OFF CACHE BOOL "" FORCE)
set(USE_LIBIDN2 OFF CACHE BOOL "" FORCE)
set(USE_LIBRTMP OFF CACHE BOOL "" FORCE)

FetchContent_Declare(curl
  URL https://github.com/curl/curl/releases/download/curl-${CURL_TAG}/curl-${CURL_VERSION}.tar.xz
  URL_HASH SHA256=${CURL_SHA256}
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(curl)

##############################################################################
#
# nlohmann/json
#

FetchContent_Declare(json
  URL https://github.com/nlohmann/json/releases/download/v${JSON_VERSION}/json.tar.xz
  URL_HASH SHA256=${JSON_SHA256}
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(json)

##############################################################################
#
# opencore-amr + vo-amrwbenc
#
# Autotools out of tree everywhere but Windows, where there's no shell to run
# configure; there they're compiled in tree from the same pinned tarballs.
#

if(WIN32)

FetchContent_Declare(opencore_amr
  URL https://downloads.sourceforge.net/project/opencore-amr/opencore-amr/opencore-amr-${OPENCORE_AMR_VERSION}.tar.gz
  URL_HASH SHA256=${OPENCORE_AMR_SHA256}
  SOURCE_SUBDIR no-cmake  # download only
)
FetchContent_Declare(vo_amrwbenc
  URL https://downloads.sourceforge.net/project/opencore-amr/vo-amrwbenc/vo-amrwbenc-${VO_AMRWBENC_VERSION}.tar.gz
  URL_HASH SHA256=${VO_AMRWBENC_SHA256}
  SOURCE_SUBDIR no-cmake
)
FetchContent_MakeAvailable(opencore_amr vo_amrwbenc)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AmrSources.cmake)
set(AMR_INCLUDE "${CMAKE_BINARY_DIR}/_deps/amr-include")
amr_add_libraries(${opencore_amr_SOURCE_DIR} ${vo_amrwbenc_SOURCE_DIR} ${AMR_INCLUDE})

# Pre-seed baresip's FindAMR; library values are the targets above.
set(NB_INCLUDE_DIR     "${AMR_INCLUDE}" CACHE PATH "" FORCE)
set(WB_ENC_INCLUDE_DIR "${AMR_INCLUDE}" CACHE PATH "" FORCE)
set(WB_DEC_INCLUDE_DIR "${AMR_INCLUDE}" CACHE PATH "" FORCE)
set(NB_LIBRARY        opencore-amrnb CACHE STRING "" FORCE)
set(WB_LIBRARY        opencore-amrwb CACHE STRING "" FORCE)
set(WB_VO_ENC_LIBRARY vo-amrwbenc    CACHE STRING "" FORCE)

else()

set(AMR_PREFIX "${CMAKE_BINARY_DIR}/_deps/amr-install")
set(AMR_CONFIGURE_ARGS
  --prefix=${AMR_PREFIX}
  --libdir=${AMR_PREFIX}/lib
  --enable-static
  --disable-shared
  --with-pic
  CC=${CMAKE_C_COMPILER}
  CXX=${CMAKE_CXX_COMPILER}
  AR=${CMAKE_AR}
  RANLIB=${CMAKE_RANLIB}
)

ExternalProject_Add(opencore_amr_ext
  URL https://downloads.sourceforge.net/project/opencore-amr/opencore-amr/opencore-amr-${OPENCORE_AMR_VERSION}.tar.gz
  URL_HASH SHA256=${OPENCORE_AMR_SHA256}
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  CONFIGURE_COMMAND <SOURCE_DIR>/configure ${AMR_CONFIGURE_ARGS} --disable-examples
  BUILD_COMMAND make
  INSTALL_COMMAND make install
  BUILD_BYPRODUCTS
    ${AMR_PREFIX}/lib/libopencore-amrnb.a
    ${AMR_PREFIX}/lib/libopencore-amrwb.a
)

ExternalProject_Add(vo_amrwbenc_ext
  URL https://downloads.sourceforge.net/project/opencore-amr/vo-amrwbenc/vo-amrwbenc-${VO_AMRWBENC_VERSION}.tar.gz
  URL_HASH SHA256=${VO_AMRWBENC_SHA256}
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  CONFIGURE_COMMAND <SOURCE_DIR>/configure ${AMR_CONFIGURE_ARGS}
  BUILD_COMMAND make
  INSTALL_COMMAND make install
  BUILD_BYPRODUCTS ${AMR_PREFIX}/lib/libvo-amrwbenc.a
)

# Pre-seed baresip's FindAMR so it resolves to the libraries built above.
set(NB_INCLUDE_DIR     "${AMR_PREFIX}/include" CACHE PATH "" FORCE)
set(WB_ENC_INCLUDE_DIR "${AMR_PREFIX}/include" CACHE PATH "" FORCE)
set(WB_DEC_INCLUDE_DIR "${AMR_PREFIX}/include" CACHE PATH "" FORCE)
set(NB_LIBRARY        "${AMR_PREFIX}/lib/libopencore-amrnb.a" CACHE FILEPATH "" FORCE)
set(WB_LIBRARY        "${AMR_PREFIX}/lib/libopencore-amrwb.a" CACHE FILEPATH "" FORCE)
set(WB_VO_ENC_LIBRARY "${AMR_PREFIX}/lib/libvo-amrwbenc.a"    CACHE FILEPATH "" FORCE)

endif()

##############################################################################
#
# alsa-lib (autotools, built out of tree; not used on Windows or macOS, see wasapi and coreaudio respectively)
#
# Config files are read from the host at runtime. Plugins that live in shared
# objects (pipewire, pulse) can't be loaded by a static binary, so use a
# hardware device such as plughw:0,0.
#

if(NOT WIN32 AND NOT APPLE)

set(ALSA_PREFIX "${CMAKE_BINARY_DIR}/_deps/alsa-install")

ExternalProject_Add(alsa_lib_ext
  URL https://www.alsa-project.org/files/pub/lib/alsa-lib-${ALSA_LIB_VERSION}.tar.bz2
  URL_HASH SHA256=${ALSA_LIB_SHA256}
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  CONFIGURE_COMMAND <SOURCE_DIR>/configure
    --prefix=${ALSA_PREFIX}
    --libdir=${ALSA_PREFIX}/lib
    --enable-static
    --disable-shared
    --disable-python
    --disable-topology
    --with-configdir=/usr/share/alsa
    --with-plugindir=/usr/lib/alsa-lib
    CC=${CMAKE_C_COMPILER}
    CFLAGS=-O2\ -fPIE
  BUILD_COMMAND make -C src
  # Library and headers only; config files stay the host's.
  INSTALL_COMMAND make -C src install-libLTLIBRARIES
  COMMAND make -C include install
  BUILD_BYPRODUCTS ${ALSA_PREFIX}/lib/libasound.a
)

# Pre-seed CMake's FindALSA (used by baresip's alsa module).
file(MAKE_DIRECTORY ${ALSA_PREFIX}/include)
set(ALSA_INCLUDE_DIR "${ALSA_PREFIX}/include" CACHE PATH "" FORCE)
set(ALSA_LIBRARY "${ALSA_PREFIX}/lib/libasound.a" CACHE FILEPATH "" FORCE)

endif()

##############################################################################
#
# libre
#

set(LIBRE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(LIBRE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(USE_MBEDTLS ON CACHE BOOL "" FORCE)
set(USE_OPENSSL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(re
  URL https://github.com/baresip/re/archive/refs/tags/v${RE_VERSION}.tar.gz
  URL_HASH SHA256=${RE_SHA256}
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(re)

# libre only uses mbedTLS for hashing and expects it on the system include
# path, so wire the headers and link dependency in explicitly.
target_link_libraries(re-objs PRIVATE mbedcrypto)
target_link_libraries(re PRIVATE $<BUILD_INTERFACE:mbedcrypto>)

# libre's APPLE branch skips src/tls/stub.c (it assumes OpenSSL), leaving
# tls_* undefined for baresip. We build without OpenSSL, so add the stub.
if(APPLE)
  target_sources(re-objs PRIVATE "${re_SOURCE_DIR}/src/tls/stub.c")
endif()

##############################################################################
#
# libg722 (G.722 for baresip's libg722 module; the spandsp one can't be
# linked statically on most distros). Two C files, built here rather than
# with its own CMakeLists, which wants a shared library and tests.
#

FetchContent_Declare(libg722
  URL https://github.com/sippy/libg722/archive/refs/tags/v${LIBG722_VERSION}.tar.gz
  URL_HASH SHA256=${LIBG722_SHA256}
  SOURCE_SUBDIR no-cmake  # download only
)
FetchContent_MakeAvailable(libg722)
add_library(sippy_g722 STATIC
  ${libg722_SOURCE_DIR}/g722_decode.c
  ${libg722_SOURCE_DIR}/g722_encode.c
)
target_include_directories(sippy_g722 PUBLIC ${libg722_SOURCE_DIR})
add_library(LIBG722::LIBG722 ALIAS sippy_g722)
# Found already, for baresip's FindLIBG722
set(LIBG722_INCLUDE_DIR ${libg722_SOURCE_DIR} CACHE PATH "" FORCE)
set(LIBG722_LIBRARY sippy_g722 CACHE STRING "" FORCE)

##############################################################################
#
# baresip (static, modules compiled into libbaresip)
#

set(STATIC ON CACHE BOOL "" FORCE)
# Audio driver and console UI are per platform; main.cpp picks the same ones.
if(WIN32)
  set(NEKOIMS_PLATFORM_MODULES wasapi wincons)
elseif(APPLE)
  set(NEKOIMS_PLATFORM_MODULES coreaudio stdio)
else()
  set(NEKOIMS_PLATFORM_MODULES alsa stdio)
endif()
set(MODULES
  ${NEKOIMS_PLATFORM_MODULES}
  amr
  aubridge
  auconv
  aufile
  auresamp
  ausine
  ctrl_tcp
  g711
  httpd
  libg722
  menu
  CACHE STRING "baresip modules linked into NekoIMS" FORCE
)

# Point baresip's FindRE / find_package(re CONFIG) at the libre built above.
set(RE_INCLUDE_DIR "${re_SOURCE_DIR}/include" CACHE PATH "" FORCE)
set(RE_LIBRARY re CACHE STRING "" FORCE)
set(re_DIR "${re_SOURCE_DIR}/cmake" CACHE PATH "" FORCE)
list(APPEND CMAKE_MODULE_PATH "${re_SOURCE_DIR}/cmake")

# Local patches on top of the pinned release (patches/baresip/*.patch).
# GIT_DIR points nowhere so git apply ignores any enclosing repository.
find_package(Git REQUIRED)
file(GLOB BARESIP_PATCHES "${CMAKE_CURRENT_SOURCE_DIR}/patches/baresip/*.patch")
list(SORT BARESIP_PATCHES)

FetchContent_Declare(baresip
  URL https://github.com/baresip/baresip/archive/refs/tags/v${BARESIP_VERSION}.tar.gz
  URL_HASH SHA256=${BARESIP_SHA256}
  PATCH_COMMAND ${CMAKE_COMMAND} -E env GIT_DIR=<SOURCE_DIR>/.nogit
                ${GIT_EXECUTABLE} apply --verbose ${BARESIP_PATCHES}
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(baresip)

if(NOT WIN32)
  # TODO: figure out how to use native core audio amr codec on macos
  # (opencore works fine but it just feels wrong when its in core audio)
  add_dependencies(amr opencore_amr_ext vo_amrwbenc_ext)
  if(NOT APPLE)
    add_dependencies(alsa alsa_lib_ext)
  endif()
endif()

##############################################################################
#
# pcsc-lite (optional, client library only)
#

if(NEKOIMS_WITH_PCSC)
  find_program(MESON_EXECUTABLE meson REQUIRED)
  find_program(NINJA_EXECUTABLE ninja REQUIRED)

  set(PCSCLITE_PREFIX "${CMAKE_BINARY_DIR}/_deps/pcsclite-install")

  ExternalProject_Add(pcsclite_ext
    URL https://pcsclite.apdu.fr/files/pcsc-lite-${PCSCLITE_VERSION}.tar.xz
    URL_HASH SHA256=${PCSCLITE_SHA256}
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env CC=${CMAKE_C_COMPILER}
      ${MESON_EXECUTABLE} setup <BINARY_DIR> <SOURCE_DIR>
        --prefix=${PCSCLITE_PREFIX}
        --libdir=lib
        --buildtype=release
        --default-library=static
        -Dlibsystemd=false
        -Dlibudev=false
        -Dpolkit=false
        -Dusb=false
        -Dserial=false
    BUILD_COMMAND ${NINJA_EXECUTABLE} -C <BINARY_DIR> libpcsclite.a
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy
      <BINARY_DIR>/libpcsclite.a ${PCSCLITE_PREFIX}/lib/libpcsclite.a
    COMMAND ${CMAKE_COMMAND} -E copy_directory
      <SOURCE_DIR>/src/PCSC ${PCSCLITE_PREFIX}/include/PCSC
    COMMAND ${CMAKE_COMMAND} -E copy
      <BINARY_DIR>/pcsclite.h ${PCSCLITE_PREFIX}/include/PCSC/pcsclite.h
    BUILD_BYPRODUCTS ${PCSCLITE_PREFIX}/lib/libpcsclite.a
  )

  file(MAKE_DIRECTORY ${PCSCLITE_PREFIX}/include/PCSC)
  add_library(pcsclite STATIC IMPORTED GLOBAL)
  set_target_properties(pcsclite PROPERTIES
    IMPORTED_LOCATION ${PCSCLITE_PREFIX}/lib/libpcsclite.a
    INTERFACE_INCLUDE_DIRECTORIES ${PCSCLITE_PREFIX}/include/PCSC
  )
  add_dependencies(pcsclite pcsclite_ext)
endif()

##############################################################################
#
# NekoIMS
#

add_executable(nekoims
  src/main.cpp
  src/netns.cpp
  src/b2bua.cpp
  src/ims_register.cpp
  src/ipsec.cpp
  src/simcard_client.cpp
  src/sms.cpp
  src/sms_codec.cpp
)

target_compile_definitions(nekoims PRIVATE
  NEKOIMS_VERSION="${PROJECT_VERSION}"
)

target_link_libraries(nekoims PRIVATE
  baresip
  re
  CURL::libcurl
  nlohmann_json::nlohmann_json
)

if(NEKOIMS_WITH_PCSC)
  target_compile_definitions(nekoims PRIVATE NEKOIMS_WITH_PCSC)
  target_link_libraries(nekoims PRIVATE pcsclite)
endif()

if(APPLE)
  target_link_libraries(nekoims PRIVATE "-framework CoreAudio" "-framework AudioToolbox")
elseif(MSVC)
  # Static CRT is selected by CMAKE_MSVC_RUNTIME_LIBRARY above.
elseif(NEKOIMS_FULLY_STATIC)
  target_link_options(nekoims PRIVATE -static)
else()
  target_link_options(nekoims PRIVATE -static-libgcc -static-libstdc++)
endif()

install(TARGETS nekoims RUNTIME DESTINATION bin)
