END_OF_LIST =

BUILT_SOURCES = gdm-greeter-server.h gdm-display-glue.h
CLEANFILES = 			\
	$(BUILT_SOURCES)	\
	gdm-display-glue.c	\
	$(END_OF_LIST)

gdm-greeter-server.c gdm-greeter-server.h : $(top_srcdir)/daemon/gdm-greeter-server.xml Makefile.am
	$(AM_V_GEN)gdbus-codegen 					\
		--interface-prefix=org.gnome.DisplayManager		\
		--generate-c-code=gdm-greeter-server			\
		--annotate "org.gnome.DisplayManager.GreeterServer"	\
			   "org.gtk.GDBus.C.Name" GdmGreeterServer	\
		$(top_srcdir)/daemon/gdm-greeter-server.xml

gdm-display-glue.c gdm-display-glue.h : $(top_srcdir)/daemon/gdm-display.xml Makefile.am
	$(AM_V_GEN)gdbus-codegen 					\
		--c-namespace GdmDBus					\
		--interface-prefix=org.gnome.DisplayManager		\
		--generate-c-code=gdm-display-glue			\
		$(top_srcdir)/daemon/gdm-display.xml

AM_CPPFLAGS = \
        -I.                                                                   \
        -I..                                                                  \
	-I$(srcdir)                                                           \
        -DG_LOG_DOMAIN=\"GdmGreeter\"                                         \
        -DDMCONFDIR=\""$(dmconfdir)"\"                                        \
        -DDATADIR=\""$(datadir)"\"                                            \
        $(END_OF_LIST)

lib_LTLIBRARIES =                                                             \
        libgdmgreeter.la                                                      \
        $(END_OF_LIST)

libgdmgreeterdir = $(includedir)/gdm/greeter
libgdmgreeter_HEADERS =                                                       \
        gdm-greeter-util.h                                                    \
	gdm-greeter-server.h                                                  \
        gdm-greeter-sessions.h                                                \
        $(END_OF_LIST)

libgdmgreeter_la_CFLAGS =                                                     \
        $(LIBGDMGREETER_CFLAGS)                                               \
        $(END_OF_LIST)
libgdmgreeter_la_LDFLAGS =                                                    \
        -export-symbols-regex '^[^_].*'                                       \
        -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)                  \
        -no-undefined                                                         \
        $(END_OF_LIST)

libgdmgreeter_la_LIBADD =                                                     \
        $(LIBGDMGREETER_LIBS)                                                 \
        $(END_OF_LIST)

libgdmgreeter_la_SOURCES =                                                    \
        $(libgdmgreeter_HEADERS)                                              \
	gdm-greeter-server.c                                                  \
        gdm-greeter-util.c                                                    \
        gdm-greeter-sessions.c                                                \
        $(END_OF_LIST)

nodist_libgdmgreeter_la_SOURCES = 	\
	gdm-display-glue.c		\
	gdm-display-glue.h		\
	$(END_OF_LIST)

pkgconfigdir = $(libdir)/pkgconfig
dist_pkgconfig_DATA = gdmgreeter.pc

-include $(INTROSPECTION_MAKEFILE)

if HAVE_INTROSPECTION
girdir = $(datadir)/gir-1.0
gir_DATA = GdmGreeter-1.0.gir
typelibsdir = $(libdir)/girepository-1.0
typelibs_DATA = $(gir_DATA:.gir=.typelib)
INTROSPECTION_GIRS = $(gir_DATA)

GdmGreeter-1.0.gir:                                                      \
        $(INTROSPECTION_SCANNER)                                              \
        libgdmgreeter.la                                                      \
        Makefile                                                              \
        $(END_OF_LIST)

GdmGreeter_1_0_gir_SCANNERFLAGS =                                        \
        --warn-all                                                            \
        --namespace=GdmGreeter                                                \
        --identifier-prefix GdmGreeter                                        \
	$(AM_CPPFLAGS)                                                        \
        $(libgdmgreeter_la_CFLAGS)                                            \
        $(END_OF_LIST)

GdmGreeter_1_0_gir_INCLUDES = $(LIBGDMGREETER_GIR_INCLUDES)
GdmGreeter_1_0_gir_LIBS = libgdmgreeter.la
GdmGreeter_1_0_gir_FILES =                                                    \
        $(filter-out %-private.h, $(libgdmgreeter_la_SOURCES))                \
        $(END_OF_LIST)

CLEANFILES += $(gir_DATA) $(typelibs_DATA)
endif

MAINTAINERCLEANFILES = Makefile.in
