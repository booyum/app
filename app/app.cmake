############################### PROJECT CMAKE ##################################

project(App)

# The cross platform controller is always utilized
list  (APPEND primary_sources 
      "app/controller/main.c"
      )

# Cross platform modules are always utilized
list  (APPEND primary_sources 
      "app/modules/shared/dataContainer/dataContainer.c" 
      "app/modules/shared/logger/logger.c" 
      "app/modules/shared/router/router.c"
      "app/modules/shared/security/security.c"
      "app/modules/shared/tweetNacl/tweetNacl.c"
      )


# Some interfaces have no possible cross platform implementation, therefore these
# interfaces are implemented with OS specific modules, we will switch based on 
# the current OS to determine which OS specific modules to build and utilize for
# the interface

IF (LINUX)
    list (APPEND primary_sources
         "app/modules/os/linux/sandbox/isolFs.c"
         "app/modules/os/linux/sandbox/isolKern.c"
         "app/modules/os/linux/sandbox/isolIpc.c"
         "app/modules/os/linux/sandbox/isolName.c"
         "app/modules/os/linux/sandbox/isolNet.c"
         "app/modules/os/linux/sandbox/isolProc.c"
         "app/modules/os/linux/sandbox/isolGui.c"
         "app/modules/os/unixLike/prng/prng.c"
         )
ENDIF (LINUX)

IF (WIN32)
    #todo
ENDIF (WIN32)

IF (appLE)
    #todo
ENDIF (appLE)

IF (FREEBSD)
    #todo
ENDIF (FREEBSD)

IF (OPENBSD)
    #todo
ENDIF (OPENBSD)


#set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})
add_executable(App ${primary_sources})

# Program interface declarations, which are simply header files, are stored in
# the 'interfaces' directory, which is itself in the projects root directory. 
# Adding interface directory with include_directories() allows for us to use the 
# standard include quote syntax, even though the headers (which define interfaces) 
# are not being stored in the same directories as the source files (which modularly 
# define implementations). 
target_include_directories(App PUBLIC app/interfaces/sandbox)
target_include_directories(App PUBLIC app/interfaces) 

# We want to make the App executable in the parent directory 
set_target_properties( App
    PROPERTIES
#   ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
#   LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)




# Modules that are not cross platform require differing libraries to support 
# them, we will switch based on the current OS to determine which libraries 
# to link in. 
IF (LINUX)
  target_link_libraries(App "-lseccomp -lcap")
ENDIF (LINUX)

IF (WIN32)
    #todo
ENDIF (WIN32)

IF (appLE)
    #todo
ENDIF (appLE)

IF (FREEBSD)
    #todo
ENDIF (FREEBSD)

IF (OPENBSD)
    #todo
ENDIF (OPENBSD)