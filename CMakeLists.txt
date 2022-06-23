cmake_minimum_required(VERSION 3.10)

project(mptcp_ebpf_control_frame VERSION 0.1)

set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/install")

#some custom vars 
set(BPF_KERN_SRC_FILES "${PROJECT_SOURCE_DIR}/src/bpf_kern")
set(BPF_KERN_TARGETS "${CMAKE_INSTALL_PREFIX}/bpf_kern_objs")

#add_definitions(-DNOBCC)

OPTION(DEBUG 
    "debug mode"
    OFF)

if (DEBUG)
add_definitions(-DDEBUG)
endif (DEBUG)

#sub dir 
#add_subdirectory("${BPF_KERN_SRC_FILES}/tc" "${BPF_KERN_TARGETS}/tc")
add_subdirectory("${BPF_KERN_SRC_FILES}/tc_egress")
#add_subdirectory("${BPF_KERN_SRC_FILES}/tc_btf")
add_subdirectory("${BPF_KERN_SRC_FILES}/xdp")

