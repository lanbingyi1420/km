# 构建后副本：km_V<VERSION>_YYYYMMDDHHMM（Windows 追加 .exe）
# 由 CMakeLists.txt 中 km 目标的 POST_BUILD 调用；时间戳取构建时刻。
if(NOT DEFINED SRC OR NOT DEFINED DST_DIR OR NOT DEFINED VERSION)
    message(FATAL_ERROR "km_version_copy.cmake: SRC / DST_DIR / VERSION required")
endif()

string(TIMESTAMP _time "%Y%m%d%H%M")
set(_name "km_V${VERSION}_${_time}")
if(WIN32)
    string(APPEND _name ".exe")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E copy "${SRC}" "${DST_DIR}/${_name}"
    RESULT_VARIABLE _rc
)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "km_version_copy.cmake: copy to ${DST_DIR}/${_name} failed (${_rc})")
endif()
message(STATUS "versioned copy: ${DST_DIR}/${_name}")
