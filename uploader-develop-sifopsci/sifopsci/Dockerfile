FROM alpine:3.16.2

ENV RANCHER_REPOSITORY=rancher/rke

WORKDIR /app

RUN apk --no-cache add --update openrc busybox-initscripts python3 ansible py3-pip openssl

RUN echo "Installing Curl" && \
    apk --no-cache add curl > /dev/null && \
    apk --no-cache add openssh && \
    echo "Using Repository: $RANCHER_REPOSITORY" && \
    RANCHER_VERSION=v1.4.3	&& \
    echo "Using Rancher Version: $RANCHER_VERSION" && \
    curl --silent -L "https://github.com/$RANCHER_REPOSITORY/releases/download/$RANCHER_VERSION/rke_linux-amd64" --output rke_linux-amd64 && \
    chmod +x rke_linux-amd64 && \
    export PATH=$PATH:/app/ && \
    cp rke_linux-amd64 /usr/bin/ && \
    rke_linux-amd64 --version

# docker, helm and kubectl client

RUN curl -o /usr/local/bin/mc https://dl.min.io/client/mc/release/linux-amd64/mc && \
    chmod +x /usr/local/bin/mc

RUN curl -L  --output yq4 https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 && \
    chmod +x yq4 && \
    cp yq4 /usr/bin/

RUN apk --no-cache add docker 

RUN pip3 install pyyaml


RUN apk add --no-cache bash
RUN apk add --no-cache sshpass

COPY ansible ansible/

RUN chmod +x ansible/kubectl && \
    cp ansible/kubectl /usr/bin/ && \
    chmod +x ansible/linux-amd64/helm && \
    mv ansible/linux-amd64/helm /usr/bin


COPY importer.py .

RUN chmod +x importer.py


ENTRYPOINT ["python3", "importer.py"]
#CMD ["python3", "importer.py"]
