aux_source_directory("${CMAKE_CURRENT_SOURCE_DIR}" KPROBE_SRC_LIST)
add_library(kprobe OBJECT ${KPROBE_SRC_LIST})
target_include_directories(kprobe PUBLIC "${LINUX_PATH}/tools/lib")
target_include_directories(kprobe PUBLIC "${LINUX_PATH}/tools/include")
target_include_directories(kprobe PUBLIC ${BPF_KERN_SRC_FILES})
install(FILES $<TARGET_OBJECTS:kprobe> DESTINATION "${BPF_KERN_TARGETS}/kprobe")
set(CMAKE_C_FLAGS
    "${CMAKE_CXX_FLAGS} -Werror -g -O2 -target bpf"
)