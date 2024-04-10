cmake_minimum_required(VERSION 3.16)
set(CMAKE_CXX_STANDARD 17 CACHE STRING "")

############ LLVM Install dir and version ###############
set(LT_LLVM_INSTALL_DIR "/usr/local/" CACHE PATH "LLVM installation directory")
set(LT_LLVM_CMAKE_CONFIG_DIR "${LT_LLVM_INSTALL_DIR}/lib/cmake/llvm/")
list(APPEND CMAKE_PREFIX_PATH "${LT_LLVM_CMAKE_CONFIG_DIR}")
find_package(LLVM 17 REQUIRED CONFIG)
#########################################################

include_directories(${LLVM_INCLUDE_DIRS})
if(NOT LLVM_ENABLE_RTTI)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti")
endif()

add_library(AtomicBPF SHARED atomic_BPF.cpp)
