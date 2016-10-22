############################### PROJECT CMAKE ##################################

project(App)

# App specific libraries
list  (APPEND primary_sources 
      "app/bootstrap/main.c"
      "app/libs/controller.c"
      )

# Shared libraries
list  (APPEND primary_sources 
      "libs/logger.c" 
      "libs/torCon.c"
      "libs/security.c"
      "libs/tweetNacl.c"
      "libs/isolFs.c"
      "libs/isolIpc.c"
      "libs/isolName.c"
      "libs/isolNet.c"
      "libs/net.c"
      "libs/isolProc.c"
      "libs/isolGui.c"
      "libs/prng.c"
      )


#set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})
add_executable(App ${primary_sources})

# Header files can be found in these directories
target_include_directories(App PUBLIC app/interfaces) 
target_include_directories(App PUBLIC libs/interfaces)


# We want to make the App executable in the parent directory 
set_target_properties( App
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)

# Dynamically linked libraries are required
target_link_libraries(App "-lseccomp -lcap")

