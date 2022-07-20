
cmake_minimum_required(VERSION 3.16)
project(test1)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

set(OPENSSL_INC_PATH /usr/local/ssl/include)
INCLUDE_DIRECTORIES(. ${OPENSSL_INC_PATH})

set(OPENSSL_LIB_PATH /usr/local/ssl/lib64)
link_directories( ${OPENSSL_LIB_PATH})


AUX_SOURCE_DIRECTORY( ${PROJECT_SOURCE_DIR} DIR_SRCS)

FILE (GLOB ALL_SOURCES "*.cpp" "*.c")

# 5.set environment variable，设置环境变量，编译用到的源文件全部都要放到这里，否则编译能够通过，但是执行的时候会出现各种问题，比如"symbol lookup error xxxxx , undefined symbol"
SET(TEST_EVP ${ALL_SOURCES})

# 6.add executable file，添加要编译的可执行文件
ADD_EXECUTABLE(${PROJECT_NAME} ${TEST_EVP})

# 7.add link library，添加可执行文件所需要的库，比如我们用到了libm.so（命名规则：lib+name+.so），就添加该库的名称
TARGET_LINK_LIBRARIES(${PROJECT_NAME} crypto)

