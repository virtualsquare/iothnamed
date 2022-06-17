cmake_minimum_required(VERSION 3.13)
project("iothnamed"
    DESCRIPTION "DNS server/forwarder/proxy for the ioth "
    HOMEPAGE_URL "https://github.com/virtualsquare/iothnamed"
    VERSION 0.1.0
    LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")

include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)

set(LIBS_REQUIRED ioth iothdns iothconf iothaddr stropt)
set(HEADERS_REQUIRED ioth.h iothaddr.h iothconf.h iothdns.h stropt.h strcase.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# configure_file(config.h.in config.h)

add_executable(iothnamed main.c mainloop.c dnsreqq.c now.c utils.c arpainetx.c
		tcpq.c auth.c process_dns_req.c cache.c fdtimeout.c)
target_link_libraries(iothnamed ioth iothdns iothconf iothaddr stropt)
install(TARGETS iothnamed
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")

