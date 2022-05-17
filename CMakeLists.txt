# cmake version 
cmake_minimum_required(VERSION 3.15)

# project name
PROJECT(ipp_project)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE "Debug")

# head file path
INCLUDE_DIRECTORIES (${ipp_project_SOURCE_DIR}/include)

INCLUDE_DIRECTORIES ($ENV{IPPCRYPTOROOT}/include)

LINK_DIRECTORIES ($ENV{IPPCRYPTOROOT}/lib/intel64)

# source directory
AUX_SOURCE_DIRECTORY(src DIR_SRCS)

# set environment variable
SET(IPP_DEMO ${DIR_SRCS})

# add executable file
ADD_EXECUTABLE(${PROJECT_NAME} ${IPP_DEMO})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ippcp)

