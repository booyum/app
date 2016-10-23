############################### GUI CMAKE ######################################

project (guiBin)

# GUI specific libraries
  list  (APPEND gui_sources 
        "gui/bootstrap/main.cxx"
        "gui/source/contPortCon.cxx"
        "gui/source/initX11.cxx"
        "gui/source/isolX11Win.cxx"
        )

# The GUI views 
  list  (APPEND gui_sources 
        "gui/views/initGui.cxx"
        )


# Shared libraries
list  (APPEND gui_sources 
      "shared/source/logger.c" 
      "shared/source/security.c"
      "shared/source/isolNet.c"
      "shared/source/isolFs.c"
      "shared/source/isolName.c"
      "shared/source/isolProc.c"
      "shared/source/isolIpc.c"
      "shared/source/net.c"
      )


add_executable(guiBin ${gui_sources})

# Header files can be found here
target_include_directories(guiBin PUBLIC gui/interfaces)
target_include_directories(guiBin PUBLIC shared/interfaces)


# We want to make the gui executable in the bins directory 
set_target_properties( guiBin
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bins"
)

# Dynamically linked libraries are used
target_link_libraries(guiBin "-lseccomp -lcap -lfltk -lXext -lX11 -lm -lXrandr")

