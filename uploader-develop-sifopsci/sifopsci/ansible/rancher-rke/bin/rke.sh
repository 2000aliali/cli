#!/bin/sh

KUBE_CONFIG=kube_config_rancher-cluster.yml

sudo touch ${KUBE_CONFIG}

sudo docker run --rm -it \
	-v /home/devops/.ssh/id_rsa:/root/.ssh/id_rsa \
	-v /home/devops/.ssh/id_rsa.pub:/root/.ssh/id_rsa.pub \
	-v $(pwd)/kube_config_rancher-cluster.yml:/app/kube_config_rancher-cluster.yml \
	-v $(pwd)/rancher-cluster.yml:/app/rancher-cluster.yml \
	rke:1.3.1 \
	/app/rke_linux-amd64 $1

