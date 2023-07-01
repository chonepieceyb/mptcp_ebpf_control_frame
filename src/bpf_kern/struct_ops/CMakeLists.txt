aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}" ST_OPS_SRC_LIST)
add_library(struct_ops OBJECT ${ST_OPS_SRC_LIST})
target_include_directories(struct_ops PUBLIC "${LINUX_PATH}/tools/lib")
target_include_directories(struct_ops PUBLIC "${LINUX_PATH}/tools/include")
target_include_directories(struct_ops PUBLIC ${BPF_KERN_SRC_FILES})
install(FILES $<TARGET_OBJECTS:struct_ops> DESTINATION "${BPF_KERN_TARGETS}/struct_ops")
set(CMAKE_C_FLAGS
    "${CMAKE_CXX_FLAGS} -Werror -g -O2 -target bpf -mcpu=v3"
)