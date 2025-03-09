#!/bin/sh

set -e

images=$1
list=$2
REGISTRY_EP=$3
REGISTRY_USR=$4
REGISTRY_PWD=$5


#docker load -i  ${images}
docker login ${REGISTRY_EP} -u${REGISTRY_USR} -p ${REGISTRY_PWD}

while IFS= read -r i; do
    [ -z "${i}" ] && continue
    image_name="${REGISTRY_EP}/${i}"
    echo $image_name
    docker tag $i $image_name
    docker push $image_name
done < "${list}"

