cmake_minimum_required(VERSION 3.13)

### Prerequisites ###
include(libraries/pico-sdk/pico_sdk_init.cmake)

### Project name and a few useful settings. Other commands can pick up the results ###
project(
  assignment_2
  DESCRIPTION "Cryptographic implementations of PRESENT algorithm for assessment 2 for the 'Secure Software & Hardware' module."
  LANGUAGES C CXX ASM
  VERSION 1.0
)

### Set where CMake will output files ###
#set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
#set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
#set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

### Configure relevant toolchains used to compile ###
pico_sdk_init() # initialize the Raspberry Pi Pico SDK

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(
	# Warnings
#	-Werror # it appears the SDK has a bunch of errors internally. Can't really enforce warnings->errors...
	-Wpedantic
	-Wall
	-Wextra
	-Wbad-function-cast
	-Wcast-align
	-Wcast-qual
	-Wfloat-equal
	-Wformat=2
	-Wlogical-op
	-Wnested-externs
	-Wpointer-arith
	-Wundef
	-Wno-pointer-compare
	-Wredundant-decls
	-Wsequence-point
	-Wshadow
	-Wstrict-prototypes
	-Wswitch
	-Wundef
	-Wunreachable-code
	-Wunused-but-set-parameter
	-Wwrite-strings

	# Optimisations
	-Ofast # super fast optimisation which is permitted to sacrifice space
)
include_directories(
	include/
)

### Configure any related projects commands (e.g. creating documentation) ###
#find_package(Doxygen)
#if(Doxygen_FOUND)
#  execute_process(COMMAND doxygen .config.txt)
#else()
#  message(STATUS "Doxygen tool not found, not building additional source code docs")
#endif()

### Now actually compile ###
add_library(present_ref src/present_ref/crypto.c)
add_library(present_bs src/present_bs/crypto.c)
add_library(present_bs_op src/present_bs/crypto_op.c)

add_executable(pico_present_ref src/present_ref/main.c)
pico_enable_stdio_usb(pico_present_ref 1)
pico_enable_stdio_uart(pico_present_ref 1)
pico_add_extra_outputs(pico_present_ref)
target_link_libraries(pico_present_ref present_ref pico_stdlib hardware_clocks pico_time)

add_executable(pico_present_bs src/present_bs/main.c)
pico_enable_stdio_usb(pico_present_bs 1)
pico_enable_stdio_uart(pico_present_bs 1)
pico_add_extra_outputs(pico_present_bs)
target_link_libraries(pico_present_bs present_bs_op pico_stdlib hardware_clocks pico_time)
