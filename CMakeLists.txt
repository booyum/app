############################ PRIMARY CMAKE FILE ################################

# This CMakeLists.txt file functions to set the needed environment for the 
# Project and GUI CMakeLists.txt files, then it calls those CMakeLists.txt 
# files and builds the project and GUI

# Possibly will work with lower versions, however certainly works with 2.6
cmake_minimum_required(VERSION 2.6)

# Let's use clang to compile everything
set(CMAKE_C_COMPILER_INIT clang)
set(CMAKE_CXX_COMPILER_INIT clang++)





# Compile flags TODO add march and variably set it
# -O2 sets optimization level, -pipe uses memory pipes instead of files during 
# compilation and makes it faster but uses more memory, -Wformat-security and
# -Werror=format-security will attempt to detect format string vulnerabilities
# and error during compile if any are found, -Warray-bounds and 
# -Werror=array-bounds will attempt to detect array bound violations and error
# during compile if any are found, -D_FORTIFY_SOURCE=2 can protect from a 
# limited set of buffer overflow vulnerabilities, -fPIE makes position 
# independent executable for ASLR, -fsanitize=safe-stack adds protection from
# some ROP attacks, -fstack-protector-all adds stack canaries to protect from
# linear stack buffer overflows, -Wall catches all warnings 
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -pipe -Wformat-security -Werror=format-security -Warray-bounds -Werror=array-bounds -D_FORTIFY_SOURCE=2  -fstack-protector-all -Wall -I.")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -pipe -Wformat-security -Werror=format-security -Warray-bounds -Werror=array-bounds -D_FORTIFY_SOURCE=2  -fstack-protector-all -Wall -I.")

#todo add safe stack, etc

########################## DETERMINE OPERATING SYSTEM ##########################

# These environment variables are set by cmake, though APPLE only approximates
# osx (see cmake documentation, TODO). 
if (APPLE)
endif(APPLE)

if (WIN32)
endif(WIN32)

# This can determine Unix more specifically than cmake natively has defined with
# UNIX, and were obtained from the following site;
# 
# github.com/substack/libssh/blob/master/cmake/Modules/DefinePlatformDefaults.cmake
if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    set(LINUX TRUE)
endif(CMAKE_SYSTEM_NAME MATCHES "Linux")

if (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
    set(FREEBSD TRUE)
endif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")

if (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
    set(OPENBSD TRUE)
endif (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")

################################################################################

include("gui/gui.cmake")
include("app/app.cmake")
