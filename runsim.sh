
#!/bin/bash
set -eu

( mountpoint -q /build/toolchain && mountpoint -q /build/sptoolchain ) \
  || ( echo "Error: toolchain not mounted." && exit 1)

STORFS_BASEDIR=${STORFS_BASEDIR:-$(git rev-parse --show-toplevel)}
#source ${STORFS_BASEDIR}/setvars.sh ${STORFS_BUILDTYPE:-release} >/dev/null
export SCRIPTDIR=${STORFS_BASEDIR}/docker

sudo docker build -t="simulator" ${SCRIPTDIR}

# DOCKER_EXTRA_ARGS are for users to customize docker build with
# extra mount points etc.
EXTRA_ARGS=${DOCKER_EXTRA_ARGS-""}

# older docker versions does not seem to inherit dns/search domains
# This is needed if build needs to access spcentral maven repo
DNS_ARGS="--dns 10.64.1.8 --dns 10.64.1.9 --dns 10.90.0.53"

exec sudo docker run --rm -it --hostname="simulator" \
    -w ${SCRIPTDIR}/../ \
    -v ${STORFS_BASEDIR}:${STORFS_BASEDIR} \
    ${EXTRA_ARGS} \
    ${DNS_ARGS} \
    -e DHOME=${HOME} \
    -e DGROUPID=$(id -g) \
    -e DUSERID=$(id -u) \
    -e SRCDIR=${STORFS_BASEDIR} \
    -e http_proxy=http://proxy.esl.cisco.com \
    -e https_proxy=http://proxy.esl.cisco.com \
    -e no_proxy=cisco.com,storvisor.com \
    -v /build/sptoolchain:/build/sptoolchain \
    -v /build/sptoolchain:/build/sptoolchain \
    -v /opt/sysmgmt:/opt/sysmgmt \
    -v ${HOME}:${HOME} \
    -v /dev/log:/dev/log \
    -t simulator /bin/bash
