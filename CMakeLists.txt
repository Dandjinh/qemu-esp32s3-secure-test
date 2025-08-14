# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(secure_test)

set(COPY_PACK_DIR ${CMAKE_BINARY_DIR}/pack)
add_custom_command(
    TARGET app
    POST_BUILD
    # COMMAND ${CMAKE_COMMAND} -E copy_if_different
    #     ${CMAKE_BINARY_DIR}/bootloader/bootloader-unsigned.bin ${COPY_PACK_DIR}/bootloader-unsigned.bin
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/bootloader/bootloader.bin ${COPY_PACK_DIR}/bootloader.bin
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/partition_table/partition-table.bin ${COPY_PACK_DIR}/partition-table.bin
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/ota_data_initial.bin ${COPY_PACK_DIR}/ota_data_initial.bin
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_BINARY_DIR}/secure_test.bin ${COPY_PACK_DIR}/secure_test.bin
    # COMMAND ${CMAKE_COMMAND} -E copy_if_different
    #     ${CMAKE_BINARY_DIR}/secure_test-unsigned.bin ${COPY_PACK_DIR}/secure_test-unsigned.bin
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    DEPENDS ${PROJECT_NAME}.bin
    VERBATIM
)
