cmake_minimum_required(VERSION 3.6)
project(gtk)
set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES src/main.cpp src/dae.cpp)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -Wall -D_REENTRANT -I/usr/local/Cellar/gtk+/2.24.31_1/include/gtk-2.0 -I/usr/local/Cellar/gtk+/2.24.31_1/lib/gtk-2.0/include -I/usr/local/Cellar/pango/1.40.5/include/pango-1.0 -I/usr/local/Cellar/harfbuzz/1.4.6/include/harfbuzz -I/usr/local/Cellar/pango/1.40.5/include/pango-1.0 -I/usr/local/Cellar/atk/2.24.0/include/atk-1.0 -I/usr/local/Cellar/cairo/1.14.8/include/cairo -I/usr/local/Cellar/pixman/0.34.0/include/pixman-1 -I/usr/local/Cellar/fontconfig/2.12.1_2/include -I/usr/local/opt/freetype/include/freetype2 -I/usr/local/Cellar/libpng/1.6.29/include/libpng16 -I/usr/local/Cellar/gdk-pixbuf/2.36.6/include/gdk-pixbuf-2.0 -I/usr/local/Cellar/libpng/1.6.29/include/libpng16 -I/usr/local/Cellar/glib/2.52.0/include/glib-2.0 -I/usr/local/Cellar/glib/2.52.0/lib/glib-2.0/include -I/usr/local/opt/gettext/include -I/usr/local/Cellar/pcre/8.40/include -L/usr/local/Cellar/gtk+/2.24.31_1/lib -L/usr/local/Cellar/pango/1.40.5/lib -L/usr/local/Cellar/atk/2.24.0/lib -L/usr/local/Cellar/cairo/1.14.8/lib -L/usr/local/Cellar/gdk-pixbuf/2.36.6/lib -L/usr/local/Cellar/glib/2.52.0/lib -L/usr/local/opt/gettext/lib -lgtk-quartz-2.0 -lgdk-quartz-2.0 -lpangocairo-1.0 -lpango-1.0 -latk-1.0 -lcairo -lgdk_pixbuf-2.0 -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lintl")
include_directories(include)

set(C_PARSER_HEAD include/)
add_executable(gtk ${SOURCE_FILES} ${C_PARSER_HEAD})
