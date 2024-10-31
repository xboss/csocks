cmake_minimum_required(VERSION 3.20.0)
project(socks5server VERSION 0.1.0)


#SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -std=c89 -O0 -DDEBUG -ggdb -fsanitize=address")
SET(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -DDEBUG -g -ggdb ")
SET(CMAKE_C_FLAGS_RELEASE "$ENV{CXXFLAGS} -std=c89 -O3 -Wall")

message("project dir: ${PROJECT_SOURCE_DIR} compiler: ${CMAKE_C_COMPILER_ID} platform: ${CMAKE_SYSTEM_NAME}")


include_directories(${PROJECT_SOURCE_DIR})

aux_source_directory(${PROJECT_SOURCE_DIR} DIR_SRCS)

############# socks5server #############
list(REMOVE_ITEM DIR_SRCS "${PROJECT_SOURCE_DIR}/socks.c")
add_executable(socks5server ${DIR_SRCS})
target_link_libraries(socks5server pthread)



#cmake -DCMAKE_BUILD_TYPE=Debug ..
