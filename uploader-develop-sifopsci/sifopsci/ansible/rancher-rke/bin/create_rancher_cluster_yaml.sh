#!/bin/sh


ANSIBLE_DIR=$(pwd)/../
# create the rancher-cluster.yml file if it doesn't exist


touch rancher-cluster.yml

sudo docker run --rm \
		-v $(pwd)/rancher-cluster.yml:/crv-ansible/rancher-cluster.yml \
		-v ${ANSIBLE_DIR}:/crv-ansible \
		-w /crv-ansible \
		pad92/ansible-alpine:2.10 \
		ansible-playbook -i production.yml rke-rancher-cluster.yml


# clean up empty, unwanted left over dir that docker gives us 

rm -rf  ${ANSIBLE_DIR}/rancher-cluster.yml

