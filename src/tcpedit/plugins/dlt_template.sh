#!/bin/bash
# $Id:$
# Script to use the dlt_template subdirectory to create a new DLT plugin

try() {
    eval $*
    if [ $? -ne 0 ]; then
        echo >&2 
        echo '!!! '"ERROR: the $1 command did not complete successfully." >&2
        echo '!!! '"(\"$*\")" >&2
        echo '!!! '"Since this is a critical task, I'm stopping." >&2
        echo >&2
        exit 1
    fi
}
                                                                                

if [ -z "$1" ]; then
    echo "Error: Please provide a name for your plugin";
    exit 1;
fi

PLUGIN=$1

PLUGINDIR="dlt_${PLUGIN}"

if [ ! -d $PLUGINDIR ]; then 
    try mkdir $PLUGINDIR
fi


# Files to not change their name
for i in Makefile.am ; do
    if [ -f ${PLUGINDIR}/$i ]; then
        echo "Skipping ${PLUGINDIR}/$i"
        continue;
    fi
    try sed -e "s/%{plugin}/$PLUGIN/g" dlt_template/$i >${PLUGINDIR}/$i
done

# Files to have their name changed
for i in plugin.c.tmpl plugin.h plugin_opts.def plugin_api.c.tmpl plugin_api.h plugin_types.h ; do
    OUTFILE=$(echo $i | sed -E "s/plugin/${PLUGIN}/")
    OUTFILE=$(echo $OUTFILE | sed -E "s/\.tmpl//")
    OUTFILE="${PLUGINDIR}/${OUTFILE}"
    if [ -f $OUTFILE ]; then
        echo "Skipping $OUTFILE"
        continue;
    fi

    try sed -e "s/%{plugin}/${PLUGIN}/g" dlt_template/$i >$OUTFILE
done

# tell the user what to do now
echo "Plugin template created in: $PLUGINDIR"
echo ""
echo "Pleased be sure to modify ./Makefile.am and add the line to the END OF THE FILE:"
echo "include \$(srcdir)/plugins/${PLUGINDIR}/Makefile.am"
echo ""
echo "You must also modify ./dlt_stub.def and add the line:"
echo "#include ${PLUGINDIR}/${PLUGIN}_opts.def"
echo ""
echo "You may also need to update dlt.c, get.c, tcpprep.c,
echo "flows.c, send_packets.c, dlt_opts.def and tcprewrite_opts.def
echo ""
echo "Next, you must make the appropriate modifications to ./dlt_plugin.c"
echo ""
echo "You'll want to use your configuration parsing functions from above in your"
echo "tcpedit_${PLUGIN}_parse_opts() function"
echo ""
echo "Lastly, re-run automake from the root source directory"
echo "and run ./configure to build your new plugin"
exit 0
