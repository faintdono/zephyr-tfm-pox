#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#

add_library(tfm_app_rot_partition_pox STATIC)

target_include_directories(tfm_app_rot_partition_pox
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    PRIVATE
        ${CMAKE_BINARY_DIR}/pox
)
target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/pox
)

target_sources(tfm_app_rot_partition_pox
    PRIVATE
        pox.c
)

# The generated sources
target_sources(tfm_app_rot_partition_pox
PRIVATE
        ${CMAKE_BINARY_DIR}/pox/auto_generated/intermedia_tfm_pox.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/pox/auto_generated/load_info_tfm_pox.c
)

target_link_libraries(tfm_app_rot_partition_pox
    PRIVATE
        platform_s
        tfm_sprt
        psa_crypto_config
)

target_link_libraries(tfm_spm
    PRIVATE
        tfm_app_rot_partition_pox
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_pox
)

target_compile_definitions(tfm_config
    INTERFACE
        TFM_PARTITION_POX
)
