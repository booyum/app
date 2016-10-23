############################### PROJECT CMAKE ##################################

project(App)

# App specific libraries
list  (APPEND primary_sources 
      "app/bootstrap/main.c"
      "app/libs/controller.c"
      )

# Shared source
list  (APPEND primary_sources 
      "shared/source/logger.c" 
      "shared/source/torCon.c"
      "shared/source/security.c"
      "shared/source/tweetNacl.c"
      "shared/source/isolFs.c"
      "shared/source/isolIpc.c"
      "shared/source/isolName.c"
      "shared/source/isolNet.c"
      "shared/source/net.c"
      "shared/source/isolProc.c"
      "shared/source/isolGui.c"
      "shared/source/prng.c"
      )


#set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})
add_executable(App ${primary_sources})

# Header files can be found in these directories
target_include_directories(App PUBLIC app/libs/interfaces) 
target_include_directories(App PUBLIC shared/interfaces)


# We want to make the App executable in the parent directory 
set_target_properties( App
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# Dynamically linked libraries are required
target_link_libraries(App "-lseccomp -lcap")

