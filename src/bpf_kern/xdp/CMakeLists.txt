#add your libaries 
#bpf 
find_library(LIBBPF NAMES bpf libbpf HINTS "/usr/lib64" REQUIRED)
aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}" XDP_SRC_LIST)

#compile all .o files 
add_library(xdp OBJECT ${XDP_SRC_LIST})

target_include_directories(xdp PUBLIC ${BPF_KERN_SRC_FILES})

install(FILES $<TARGET_OBJECTS:xdp> DESTINATION "${BPF_KERN_TARGETS}/xdp") 

set(CMAKE_C_FLAGS
    "${CMAKE_CXX_FLAGS} -Werror -g -O2 -target bpf" 
)
