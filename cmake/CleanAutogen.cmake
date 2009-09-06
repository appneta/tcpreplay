# clean autogen created files
file(GLOB_RECURSE autogen_gen_files ${CMAKE_SOURCE_DIR}/src 
    *.1 *_opts.c *_opts.h *_stub.h)
file(REMOVE ${autogen_gen_files})
