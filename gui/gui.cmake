############################### GUI CMAKE ######################################

project (guiBin)

# The cross platform controller is always utilized
  list  (APPEND gui_sources 
        "gui/controller/main.cxx"
        )

# The views are cross platform from FLTK 
  list  (APPEND gui_sources 
        "gui/views/initGui.cxx"
        )


# Different window managers are used on the different operating systems 
IF(LINUX)
  list  (APPEND gui_sources 
        "gui/wms/x11/initWm.cxx"
        "gui/wms/x11/initIsolWin.cxx"
        )
ENDIF(LINUX) 


# Different modules are used on different operating systems
IF(LINUX)
  list  (APPEND gui_sources 
        "gui/modules/os/linux/sandbox/isolKern.cxx"
        "gui/modules/os/linux/sandbox/isolNet.cxx"
        "gui/modules/os/linux/sandbox/isolFs.cxx"
        "gui/modules/os/linux/sandbox/isolName.cxx"
        "gui/modules/os/linux/sandbox/isolProc.cxx"
        "gui/modules/os/linux/sandbox/isolIpc.cxx"
        )
ENDIF(LINUX)


add_executable(guiBin ${gui_sources})


target_include_directories(guiBin PUBLIC gui/interfaces/)
target_include_directories(guiBin PUBLIC gui/interfaces/sandbox/)

# We want to make the gui executable in the bins directory 
set_target_properties( guiBin
    PROPERTIES
#   ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
#   LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bins"
)




# Depending on the OS different libraries are linked with the binary 
IF (LINUX)
  target_link_libraries(guiBin "-lseccomp -lcap -lfltk -lXext -lX11 -lm -lXrandr")
ENDIF (LINUX)
