############################### GUI CMAKE ######################################

project (guiBin)

# GUI specific libraries
  list  (APPEND gui_sources 
        "gui/bootstrap/main.cxx"
         "gui/libs/contPortCon.cxx"
        )

# The GUI views 
  list  (APPEND gui_sources 
        "gui/views/initGui.cxx"
        )

# Window manager support (currently only x11)
  list  (APPEND gui_sources 
        "gui/wms/x11/initWm.cxx"
        "gui/wms/x11/initIsolWin.cxx"
        )


# Shared libraries
list  (APPEND gui_sources 
      "libs/logger.c" 
      "libs/security.c"
      "libs/isolNet.c"
      "libs/isolFs.c"
      "libs/isolName.c"
      "libs/isolProc.c"
      "libs/isolIpc.c"
      "libs/net.c"
      )


add_executable(guiBin ${gui_sources})

# Header files can be found here
target_include_directories(guiBin PUBLIC gui/interfaces)
target_include_directories(guiBin PUBLIC libs/interfaces)


# We want to make the gui executable in the bins directory 
set_target_properties( guiBin
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bins"
)

# Dynamically linked libraries are used
target_link_libraries(guiBin "-lseccomp -lcap -lfltk -lXext -lX11 -lm -lXrandr")

