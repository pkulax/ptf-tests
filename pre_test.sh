#!/bin/bash

shopt -s expand_aliases

if [ -z "$1" ] || [ -z "$2" ]
then
    echo "- Missing mandatory argument:"
    echo " - Usage: source pre_test.sh <SDE_INSTALL_PATH> <IPDK_RECIPE>"
    return 0
fi

export SDE_INSTALL=$1
export IPDK_RECIPE=$2

echo "Killing qemu"
pkill -9 qemu

echo "killing infrap4d"
pkill -9 infrap4d

echo "Sleeping for 2 seconds"
sleep 2

echo "Killing ovs"
pkill -9 ovs
echo "sleeping for 2 seconds"
sleep 2

echo "Removing any vhost users from /tmp"
rm -rf /tmp/vhost-user-*
rm -rf /tmp/intf/vhost-user-*

echo "Setting PATH"
export PATH=$PATH:$IPDK_RECIPE/install/bin
export LD_LIBRARY_PATH=$IPDK_RECIPE/install/lib/:$SDE_INSTALL/lib:$SDE_INSTALL/lib64:$DEPEND_INSTALL/lib:$DEPEND_INSTALL/lib64
export PATH=$PATH:$IPDK_RECIPE/install/bin
export RUN_OVS=$IPDK_RECIPE/install

echo "starting ovs"
mkdir -p $IPDK_RECIPE/install/var/run/openvswitch
rm -rf $IPDK_RECIPE/install/etc/openvswitch/conf.db
$IPDK_RECIPE/install/bin/ovsdb-tool create $IPDK_RECIPE/install/etc/openvswitch/conf.db $IPDK_RECIPE/install/share/openvswitch/vswitch.ovsschema
$IPDK_RECIPE/install/sbin/ovsdb-server  --remote=punix:$RUN_OVS/var/run/openvswitch/db.sock   --remote=db:Open_vSwitch,Open_vSwitch,manager_options  --pidfile --detach
$IPDK_RECIPE/install/sbin/ovs-vswitchd --detach --no-chdir unix:$RUN_OVS/var/run/openvswitch/db.sock --mlockall --log-file=/tmp/ovs-vswitchd.log