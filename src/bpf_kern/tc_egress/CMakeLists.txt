#add your libaries 
#bpf 
find_library(LIBBPF NAMES bpf libbpf HINTS "/usr/lib64" REQUIRED)
aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}" TC_SRC_LIST)


#compile all .o files 
add_library(tc_egress OBJECT ${TC_SRC_LIST})

target_include_directories(tc_egress PUBLIC ${BPF_KERN_SRC_FILES})

install(FILES $<TARGET_OBJECTS:tc_egress> DESTINATION "${BPF_KERN_TARGETS}/tc_egress") 

set(CMAKE_C_FLAGS
    "${CMAKE_CXX_FLAGS} -Werror -O2 -g -target bpf" 
)
