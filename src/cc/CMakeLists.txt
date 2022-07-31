cmake_minimum_required(VERSION 3.10)

project(eMPTCPd VERSION 1.0)

set(EXECUTABLE_OUTPUT_PATH "${BIN_TARGETS}")
#set(CONFIG_DIR "${PROJECT_SOURCE_DIR}/config")
#set(EXT_DIR "${PROJECT_SOURCE_DIR}/ext")

#add your libaries 
#libxdp   
find_library(LIBXDP NAMES xdp  HINTS "/usr/local/lib" REQUIRED)
find_library(LIBBPF NAMES bpf HINTS "/usr/lib64" REQUIRED)
include_directories("${PROJECT_SOURCE_DIR}"  "/usr/local/include/xdp" "/home/chonepieceyb/CODING/Src/xdp-tools/headers")

aux_source_directory(${PROJECT_SOURCE_DIR} SRC_LIST)

#get all target files
set(TARGET_LIST "${PROJECT_SOURCE_DIR}/test.cxx" "${PROJECT_SOURCE_DIR}/emptcpd.cxx")
list(REMOVE_ITEM SRC_LIST ${TARGET_LIST})

foreach(TF ${TARGET_LIST})
    get_filename_component(TN ${TF} NAME_WE)
    add_executable(${TN} ${SRC_LIST} ${TF})
    #configure_file("${CONFIG_DIR}/${CMAKE_PROJECT_NAME}_config.h.in" "${PROJECT_BINARY_DIR}/${CMAKE_PROJECT_NAME}_config.h")
    #target_include_directories(${TN} PUBLIC "${BOOST_DIR}/include")
    target_link_libraries(${TN} ${LIBXDP} ${LIBBPF})
endforeach()

set(CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror -O2"
)
