#add your libaries 
#bpf 
find_library(LIBBPF NAMES bpf libbpf REQUIRED)
aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}" TC_SRC_LIST)


#compile all .o files 
add_library(tc OBJECT ${TC_SRC_LIST})

target_include_directories(tc PUBLIC ${BPF_KERN_SRC_FILES})

install(FILES $<TARGET_OBJECTS:tc> DESTINATION "${BPF_KERN_TARGETS}/tc") 

set(CMAKE_C_FLAGS
    "${CMAKE_CXX_FLAGS} -Werror -O2  -target bpf" 
)
