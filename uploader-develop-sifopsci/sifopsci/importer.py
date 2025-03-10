#!/usr/bin/env python
import yaml,subprocess
import tarfile
import sys
import logging
import argparse
import shutil
import base64
#import secrets
import os
import time


# Function 
def decodeToUtf(out,err):
    if type(out) != type(None) :
        out = out.decode('utf-8')
    if type(err) != type(None) :
        err = err.decode('utf-8')
    return (out,err)

def add_value(d, path, value):
    curr = d
    for key in path:
        if key not in curr:
            curr[key] = {}
        curr = curr[key]
    k, v = value
    curr[k] = v

    return d

main_parser = argparse.ArgumentParser(prog = 'sifops',description = 'SifOps (or Sif Operations) is a CLI based tool, built to deploy and operate Sif Platform either online (Hosted) or Offline. It is delivered as a Docker container that includes all required tools to help automate the installation process')
main_parser.add_argument('--skipHarbor', action='store_true', default=False, help='Will automatically skip harbor installation')
main_parser.add_argument('--deployRancherOnApp', action='store_true', default=False, help='Will automatically launch Rancher installation on App Cluster')
main_parser.add_argument('--skipCNS', action='store_true', default=False, help='Will automatically skip CSI INSTALLATION')
main_parser.add_argument('--skipAppPreRequisite', action='store_true', default=False, help='Will automatically skip app prerequisite')
main_parser.add_argument('--skipMinio', action='store_true', default=False, help='Will automatically skip minio')
main_parser.add_argument('--skipAdminPreRequisite', action='store_true', default=False, help='Will automatically skip admin prerequisite')
main_parser.add_argument('--skipAdministrationPlatform', action='store_true', default=False, help='Will automatically skip rancher Administration Platform installation')
main_parser.add_argument('--skipAppPlatform', action='store_true', default=False, help='Will automatically skip rancher Application Platform installation')
main_parser.add_argument('--skipLoad', action='store_true', default=False, help='Will automatically skip Artifacts loads')
main_parser.add_argument('--offline', action='store_true', default=False, help='Enable offline mode')
main_parser.add_argument('--nohooks', action='store_true', default=False, help='Disable profile hooks')
main_parser.add_argument('--dryrun', action='store_true', default=False, help='Enable Dry Run mode')
main_parser.add_argument('--skipCnsTaint', action='store_true', default=False, help='Skip Taint Of Cns Nodes')
main_parser.add_argument('create')
main_parser.add_argument('offlinepackage', nargs='?')
main_parser.add_argument(
    '--data', action='store', help='A YAML file containing configuration of the Platform')
main_parser.add_argument(
    '--verbose', action='store_true', help="Show more context")
main_parser.add_argument('--revision', action='store', help='The revision you want to rollback to ')

main_parser.add_argument('--restore', action='store_true', default=False, help='Restore rke etcd from minio ')
main_parser.add_argument('--snapshotname', action='store', type=str, help='The snapshot name in S3 Bucket')

main_parser.add_argument('--package', action='store', help='The package to be installed')



main_parser.add_argument('--skipKafkaUpgrade', action='store_true', default=False, help='Skip upgrade of kafka topic suffix')
args = main_parser.parse_args()

logger = logging.getLogger()
logger_handler = logging.StreamHandler()
logger.addHandler(logger_handler)
logger_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

logger.setLevel(logging.INFO)

if not args.data:
    logger.error("data.yml file is missing please specify it using --data option".format(args.data))
    sys.exit(1)
else:
    if args.create == "upgrade":
        if args.offlinepackage is None:
            logger.error("Failed to load sif-base package, sifops upgrade <sif-base-package> ....")
            sys.exit(1)
        else:
            if not os.path.exists("/app/artifacts/{}".format(args.offlinepackage)):
                logger.error("Offline package {} does not exist in artifacts folder".format(args.offlinepackage))
                sys.exit(1)
            logger.info("Extracting data yml patch from sifbase package ... {} in current directory".format(args.offlinepackage))
            file = tarfile.open("/app/artifacts/"+args.offlinepackage)
            for member in file.getnames():
                print(str(member))
                if member == "sifbase/data-patch.yml":
                    file.extract("sifbase/data-patch.yml","/tmp")
                    logger.info("PLATFORM UPGRADE - Patching data yml file ")
                    shutil.copyfile(args.data, "/tmp/old-data.yaml")
                    returncode = subprocess.call("yq4 eval-all '. as $item ireduce ({{}}; . * $item)' {} {} > {}".format(args.data,"/tmp/sifbase/data-patch.yml","/app/data-result.yaml"),shell=True,stderr=subprocess.STDOUT)
                    if returncode == 0:
                        shutil.copyfile("/app/data-result.yaml", args.data)
                        logger.info("PLATFORM UPGRADE - Patching was done successfully")
                    else:
                        logger.error("PLATFORM UPGRADE - Patching failed")
                        logger.info("PLATFORM UPGRADE - RECOVERING DATA YML FILE")
                        shutil.copyfile("/tmp/old-data.yaml", args.data)
                        file.close()
                        sys.exit(1)
            file.close() 

if args.data:
    with open(args.data, 'r') as dataFile:
        try:
            platformSpec = yaml.safe_load(dataFile)
        except:
            logger.error("Failed to load {}".format(args.data))
            sys.exit(1)

# Load the inventory file
with open("ansible/production.yml", 'r') as inventoryFile:
    try:
        inventory = yaml.safe_load(inventoryFile)
    except:
        logger.error("Failed to load {}".format("ansible/production.yml"))
        sys.exit(1)

# load the group all vars yml file
with open("ansible/group_vars/all.yml",'r') as allVarFile:
    try:
        allVar=yaml.safe_load(allVarFile)
    except:
        logger.error("Failed to load {}".format("ansible/group_vars/all.yml"))


# Check platform name and if already exists

if len(platformSpec["platform_name"]) == 0:
    logger.error("Platform Name is missing in {}".format(args.data))
    sys.exit(1)
if len(platformSpec["platform_fqdn"]) == 0:
    logger.error("Platform FQDN is missing in {}".format(args.data))
    sys.exit(1)
if len(platformSpec["platform_version"]) == 0:
    logger.error("Platform Version is missing in {}".format(args.data))
    sys.exit(1)

if platformSpec.get("rke_version") is not None:
    allVar["rke_version"] = platformSpec["rke_version"]
    rkeVersion = platformSpec["rke_version"]
else:
    rkeVersion = "1.21.5"
    allVar["rke_version"] = "1.21.5"

if platformSpec.get("rancher") is not None and platformSpec.get("rancher").get("version") is not None:
    rancherVersion = platformSpec["rancher"]["version"]
else:
    rancherVersion = "2.6.3"

if not args.skipAdministrationPlatform or args.deployRancherOnApp:
    if not os.path.exists("/app/ansible/rancher-rke/rancher-{}.tgz".format(rancherVersion)):
        logger.error("Rancher Version {} is Not Supported".format(rancherVersion))
        #sys.exit(1)

if args.restore:
    if not args.snapshotname:
        logger.error("You have to specify the Snapshot name with restore option!")
        sys.exit(1)


# PACKAGES
PLATFORM_DIRECTORY = "/app/opt/platform/"+platformSpec["platform_name"]
PLATFORM_PACKAGE = "/app/opt/platform/"+platformSpec["platform_name"]+"/sif-base-"+platformSpec["platform_version"]+"-offline.tar.gz"
HARBOR_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/harbor-offline-installer-v2.5.2.tgz"
RANCHER_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/rancher-"+rkeVersion+".tar.gz"
KEYCLOAK_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/keycloak.tar.gz"
KEYCLOAK_HA_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/keycloak-ha.tar.gz"
KEYCLOAK_EDP_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/keycloak-edp.tar.gz"
KAFKA_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/kafka.tar.gz"
POSTGRESQL_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/postgresql.tar.gz"


# KUBECONFIG FILES
KUBE_ADMIN = PLATFORM_DIRECTORY.removesuffix('/') + "/kube_config_rancher-cluster.yml"
KUBE_RKE = PLATFORM_DIRECTORY.removesuffix('/') + "/kube_config_rke_cluster.yml"

if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("kafka") is not None and platformSpec.get("middleware").get("kafka").get("namespace") is not None and platformSpec.get("middleware").get("kafka").get("namespace") != "":
    KAFKA_NS = platformSpec["middleware"]["kafka"]["namespace"]
else:
    KAFKA_NS = "kafka"

if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("vault") is not None and platformSpec.get("middleware").get("vault").get("namespace") is not None and platformSpec.get("middleware").get("vault").get("namespace") != "":
    VAULT_NS = platformSpec["middleware"]["vault"]["namespace"]
else:
    VAULT_NS = "vault"


if not os.path.exists(PLATFORM_DIRECTORY):
    logger.error("Directory {} does not exists".format(PLATFORM_DIRECTORY))
    sys.exit(1)    
    #os.makedirs(PLATFORM_DIRECTORY, exist_ok=True)


# Untar sifbase package if offline
if args.offline:
    if not os.path.exists(PLATFORM_PACKAGE) and not os.path.exists(PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase"):
        logger.info("Package {} does not exists, please copy the package to your $HOME/.paasrc/platform/{} directory".format(PLATFORM_PACKAGE,platformSpec["platform_name"]))
        sys.exit(1)
    if not os.path.exists(PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase"):
        logger.info("Extracting sifbase package ... {} in {}".format(PLATFORM_PACKAGE,PLATFORM_DIRECTORY))
        file = tarfile.open(PLATFORM_PACKAGE)
        print(file.getnames())
        file.extractall(PLATFORM_DIRECTORY.removesuffix('/'))
        file.close()

# authentication method
if platformSpec.get("system").get("authMethod") == "password":
    allVar["ansible_ssh_pass"] = platformSpec["system"]["password"]
    allVar["ansible_sudo_pass"] = platformSpec["system"]["password"]
    allVar["ansible_user"] = platformSpec["system"]["username"] 
    allVar["users"][0]["username"] = platformSpec["system"]["username"]
else:
    allVar["ansible_ssh_private_key_file"] = platformSpec["system"]["ssh_private_key"]
    allVar["users"][0]["username"] = platformSpec["system"]["username"]
    allVar["ansible_user"] = platformSpec["system"]["username"]

if platformSpec.get("system") is not None and platformSpec.get("system").get("docker_data_root") is not None and platformSpec.get("system").get("docker_data_root") != "":
    allVar["data_root"] = platformSpec["system"]["docker_data_root"]

if platformSpec.get("rancher-rke").get("all_in_one"):
   allVar["all_in_one"] = True
else:
   allVar["all_in_one"] = False

if args.skipAppPreRequisite:
   allVar["skip_app_prerequisite"] = True

if args.skipMinio:
   allVar["skip_minio"] = True

if args.skipAdminPreRequisite:
   allVar["skip_admin_prerequisite"] = True

# Files Directory for online and offline mode

allVar["platform_files_directory"] = PLATFORM_DIRECTORY.removesuffix('/')

# filling production and vars file
if args.offline:
    allVar["platform_directory"] = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase"
    if "harbor" not in platformSpec:
        logger.error("harbor is/are missing in {}".format(args.data))
        sys.exit(1)
    if platformSpec["harbor"]["external_url"] == "" or platformSpec["harbor"]["ip"] == "":
        logger.error("endpoint|ip of harbor is/are missing in {}".format(args.data))
        sys.exit(1)
    allVar["harbor_endpoint"] = platformSpec["harbor"]["external_url"]
    allVar["harbor_ip"] = platformSpec["harbor"]["ip"]
    allVar["users"][0]["username"] = platformSpec["system"]["username"]
    allVar["harbor_password"] = platformSpec["harbor"]["admin_password"]
    allVar["harbor_data_path"] = platformSpec["harbor"]["data_path"]
    allVar["offline"] = True
    inventory["all"]["hosts"]["rke-harbor"]["ansible_host"] = platformSpec["harbor"]["ip"]

allVar["harbor_endpoint"] = platformSpec["harbor"]["external_url"]
allVar["harbor_ep_ssl"] = "http://"+platformSpec["harbor"]["external_url"].replace("https://","").replace("http://","")

if platformSpec.get("harbor") is not None and platformSpec.get("harbor").get("ssl") is not None and platformSpec.get("harbor").get("ssl").get("enabled"):
    allVar["harbor_ssl"] = True
    allVar["harbor_ep_ssl"] = "https://"+platformSpec["harbor"]["external_url"].replace("https://","").replace("http://","")

if platformSpec.get("middleware") is not None and platformSpec["middleware"].get("keycloak") is not None and platformSpec["middleware"].get("keycloak").get("enabled"):
    allVar["keycloak_host"] = platformSpec["middleware"]["keycloak"]["host"]
    allVar["storageClassName"] = platformSpec["middleware"]["keycloak"]["storage_class"]
    allVar["storageSize"] = platformSpec["middleware"]["keycloak"]["storage_size"]
    allVar["admin_password"] = platformSpec["middleware"]["keycloak"]["admin_password"]
    if args.offline:
        allVar["keycloak_registry"] = platformSpec["harbor"]["external_url"]+"/middleware"
    else:
        allVar["keycloak_registry"] = "container-registry.dev.s2m.ma/infrastructure"

if platformSpec.get("middleware") is not None and platformSpec["middleware"].get("postgresql") is not None and platformSpec["middleware"].get("postgresql").get("enabled"):
    allVar["postgres_replicas"] = platformSpec["middleware"]["postgresql"]["count"] 
    allVar["postgres_size"] = platformSpec["middleware"]["postgresql"]["storage_size"]
    allVar["postgresql_password"] = platformSpec["middleware"]["postgresql"]["password"]
    allVar["postgres_registry"] = platformSpec["harbor"]["external_url"]+"/middleware"

# Filling EDP vars
if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("keycloak") is not None and platformSpec.get("middleware").get("keycloak").get("enabled"):
    if platformSpec["middleware"]["keycloak"].get("ha"):
        if args.offline:
            allVar["edp_registry"] =  platformSpec["harbor"]["external_url"]+"/middleware"
        else:
            allVar["edp_registry"] =  "quay.io/enterprisedb"


# Filling Minio vars
if platformSpec.get("minio") is not None and platformSpec["minio"].get("enabled"):
    allVar["minio_root_user"] = platformSpec["minio"]["accessId"]
    allVar["minio_root_password"] = platformSpec["minio"]["accessKey"]
    allVar["minio_data_path"] = platformSpec["minio"]["data_path"]
    inventory["all"]["hosts"]["rke-minio"]["ansible_host"] = platformSpec["minio"]["ip"]
    if platformSpec.get("minio") is not None and platformSpec["minio"].get("enabled"):
        if platformSpec.get("minio").get("ssl") is not None and platformSpec["minio"].get("ssl").get("enabled"):
            allVar["minio_ssl"] = True
            minioCertDir = PLATFORM_DIRECTORY.removesuffix('/') + "/minio-cert"
            if not os.path.exists(minioCertDir):
                logger.info("Create Directory for minio cert")
                os.makedirs(minioCertDir)
            msubjca = "/C=CN/ST=Maroc/L=Maroc/O=example/OU=Personal/CN="+ platformSpec["minio"]["host"]
            subserver = "/C=CN/ST=Maroc/L=Maroc/O=example/OU=Personal/CN="+ platformSpec["minio"]["host"]
            ca_certificate = minioCertDir + "/minio-ca.crt"
            if not args.dryrun:
                if not os.path.exists(ca_certificate):
                    logger.info("Generate a Certificate Authority Certificate")
                    retcode = subprocess.call("openssl genrsa -out {}/minio-ca.key 4096".format(minioCertDir),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("Minio CA certificate private key was generated successfully")
                    else:
                        logger.error("Minio CA certificate private key generation failed")
                        sys.exit(1)
                    retcode = subprocess.call("openssl req -x509 -new -nodes -sha512 -days 36500 -subj {} -key {}/minio-ca.key -out {}/minio-ca.crt".format(msubjca,minioCertDir,minioCertDir),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("Mini CA certificate  was generated successfully")
                    else:
                        logger.error("Minio CA certificate generation failed")
                        sys.exit(1)
                    logger.info("Generate Minio Server Certificate")
                    retcode = subprocess.call("openssl genrsa -out {}/{}.key 4096".format(minioCertDir,"private"),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("Minio Server certificate private key was generated successfully")
                    else:
                        logger.error(" Minio Server certificate private key generation failed")
                        sys.exit(1)
                    retcode = subprocess.call("openssl req -sha512 -new -subj {} -key {}/{}.key -out {}/{}.csr".format(msubjca,minioCertDir,"private",minioCertDir,"minio"),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("Minio CSR certificate  was generated successfully")
                    else:
                        logger.error("Minio CSR certificate generation failed")
                        sys.exit(1)
                    with open(minioCertDir+'/v3.ext','w') as out:
                        line1 = "authorityKeyIdentifier=keyid,issuer \n"
                        line2 = "basicConstraints=CA:FALSE \n"
                        line3 = "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment \n"
                        line4 = "extendedKeyUsage = serverAuth \n"
                        line5 = "subjectAltName = @alt_names \n"
                        line6 = "[alt_names] \n"
                        line7 = "DNS.1=" + platformSpec["minio"]["host"]+" \n"
                        line8 = "IP.1=" + platformSpec["minio"]["ip"]
                        out.writelines([line1, line2, line3, line4, line5, line6, line7, line8])
                    retcode = subprocess.call("openssl x509 -req -sha512 -days 36500 -extfile {}/v3.ext -CA {}/minio-ca.crt -CAkey {}/minio-ca.key -CAcreateserial -in {}/{}.csr -out {}/{}.crt".format(minioCertDir,minioCertDir,minioCertDir,minioCertDir,"minio",minioCertDir,"public"),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("Minio certificate  was generated successfully")
                    else:
                        logger.error("Minio certificate generation failed")
                        sys.exit(1)
                else:
                    logger.info("{} already exists skipping certificate generation for minio endpoint".format(ca_certificate))
                with open(ca_certificate, 'r') as file:
                    data = file.read().replace("\n", "\\n").removesuffix('\\n')
                allVar["minio_ca"] = data
                base64_minio_accessId = subprocess.check_output("echo -n {} | base64 ".format(platformSpec["minio"]["accessId"]), shell=True).decode('utf-8')
                allVar["minio_root_user_base64"] = base64_minio_accessId
                base64_minio_accessKey = subprocess.check_output("echo -n {} | base64 ".format(platformSpec["minio"]["accessKey"]), shell=True).decode('utf-8')
                allVar["minio_root_password_base64"] = base64_minio_accessKey
                base64_data = subprocess.check_output("cat {} | base64 -w 0  ".format(ca_certificate), shell=True).decode('utf-8')
                allVar["minio_aws_cert_base64"] = base64_data
                minio_url = "https://"+ platformSpec["minio"]["ip"].replace("https://","")
                base64_minio_url  = subprocess.check_output("echo -n {} | base64 ".format(minio_url), shell=True).decode('utf-8')
                allVar["minio_host_based64"] = base64_minio_url
            else:
                logger.info("Generate a Certificate Authority Certificate")
                logger.info("openssl genrsa -out {}/minio-ca.key 4096".format(minioCertDir))
                logger.info("openssl req -x509 -new -nodes -sha512 -days 36500 -subj {} -key {}/minio-ca.key -out {}/minio-ca.crt".format(msubjca,minioCertDir,minioCertDir))
                logger.info("Generate Minio Server Certificate")
                logger.info("openssl genrsa -out {}/{}.key 4096".format(minioCertDir,"private"))
                logger.info("openssl req -sha512 -new -subj {} -key {}/{}.key -out {}/{}.csr".format(msubjca,minioCertDir,"private",minioCertDir,"minio"))
                logger.info("openssl x509 -req -sha512 -days 36500 -extfile {}/v3.ext -CA {}/minio-ca.crt -CAkey {}/minio-ca.key -CAcreateserial -in {}/{}.csr -out {}/{}.crt".format(minioCertDir,minioCertDir,minioCertDir,minioCertDir,"minio",minioCertDir,"public"))
        
    

# Filling Minio vars

# Filling kafka vars
if platformSpec.get("middleware") is not None and platformSpec["middleware"].get("kafka") is not None and platformSpec["middleware"].get("kafka").get("enabled"):
    allVar["kafka_replication_factor"] = platformSpec["middleware"]["kafka"]["replication_factor"]
    allVar["kafka_topic_replication_factor"] = platformSpec["middleware"]["kafka"]["topic_replication_factor"]
    allVar["kafka_broker_Xms"] = platformSpec["middleware"]["kafka"]["brokerXms"]
    allVar["kafka_broker_Xmx"] = platformSpec["middleware"]["kafka"]["brokerXmx"]
    allVar["kafka_broker_count"] = platformSpec["middleware"]["kafka"]["broker_count"]
    allVar["kafka_memory_min"] = platformSpec["middleware"]["kafka"]["brokerMemory"]
    allVar["kafka_storage_size"] = platformSpec["middleware"]["kafka"]["brokerPvSize"]
    allVar["zookeeper_broker_Xms"] = platformSpec["middleware"]["kafka"]["zookeeperXms"]
    allVar["zookeeper_broker_Xmx"] = platformSpec["middleware"]["kafka"]["zookeeperXmx"]
    allVar["zookeeper_count"] = platformSpec["middleware"]["kafka"]["zookeeper_count"]
    allVar["zookeeper_memory_min"] = platformSpec["middleware"]["kafka"]["zookeeperMemory"]
    allVar["zookeeper_storage_size"] = platformSpec["middleware"]["kafka"]["zookeeperPvSize"]
    allVar["akhq_host"] = platformSpec["middleware"]["kafka"]["akhqHost"]
    allVar["kafka_namespace"] = KAFKA_NS
    if args.offline:
        allVar["registry"] = platformSpec["harbor"]["external_url"]+"/middleware"
        allVar["registry_schema"] = platformSpec["harbor"]["external_url"] + "/middleware"
        allVar["registry_akhq"] = platformSpec["harbor"]["external_url"] + "/middleware"
    else:
        allVar["registry"] = "quay.io/strimzi"
        allVar["registry_schema"] = "confluentinc"
        allVar["registry_akhq"] = "tchiotludo"

if platformSpec.get("middleware") is not None and platformSpec["middleware"].get("vault") is not None and platformSpec["middleware"].get("vault").get("enabled"):
    allVar["vault_host"] = platformSpec["middleware"]["vault"]["host"]
    allVar["vault_sc"] = platformSpec["middleware"]["vault"]["storage_class"]
    if args.offline:
        allVar["vault_registry"] = platformSpec["harbor"]["external_url"] + "/middleware"
    else:
        allVar["vault_registry"] = "hashicorp"


if not args.skipAdministrationPlatform or args.deployRancherOnApp:
    if args.offline:
        #allVar["certManager_registry"] = "quay.io"
        allVar["certManager_registry"] = platformSpec["harbor"]["external_url"] + "/rancher"
    else:
        allVar["certManager_registry"] = "quay.io/jetstack"

if not args.skipAdministrationPlatform:
    if platformSpec.get("rancher") is None:
        logger.error("rancher field is missing in {}".format(args.data))
        sys.exit(1)
    elif platformSpec.get("rancher").get("host") is None:
        logger.error("rancher host field is missing in {}".format(args.data))
        sys.exit(1)
    elif platformSpec.get("rancher").get("ips") is None:
        logger.error("rancher ips field is missing in {}".format(args.data))
        sys.exit(1)

if not args.skipAdministrationPlatform:
    if len(platformSpec["rancher"]["ips"]) == 0:
        logger.error("endpoints|ips of Administration nodes  is/are missing in {}".format(args.data))
        sys.exit(1)
    else:
        for idx, ip in enumerate(platformSpec["rancher"]["ips"]):
            host = "rke-rancher-" + str(idx)
            inventory = add_value(inventory,['all','hosts', host], ('ansible_host', ip))
            inventory = add_value(inventory,['all','children','rancher-2-kubernetes-nodes', 'hosts'], (host, None))

if not args.skipAppPlatform:
    if platformSpec.get("rancher-rke") is None:
        logger.error("rancher rke field is missing in {}".format(args.data))
        sys.exit(1)
    elif platformSpec.get("rancher-rke").get("control_plane_ips") is None: 
        logger.error("rancher rke control ips field is missing in {}".format(args.data))
        sys.exit(1)
    elif platformSpec.get("rancher-rke").get("worker_ips") is None:
        logger.error("rancher rke worker ips field is missing in {}".format(args.data))
        sys.exit(1)
    if platformSpec.get("rancher-rke") is not None and platformSpec.get("rancher-rke").get("s3Backups") is not None and platformSpec.get("rancher-rke").get("s3Backups").get("enabled"):
        allVar["clusterbackup"] = True
        allVar["minio_access_key"] = platformSpec["minio"]["accessId"]
        allVar["minio_secret_key"] = platformSpec["minio"]["accessKey"]
        allVar["minio_bucket_name"] = platformSpec["rancher-rke"]["s3Backups"]["bucket_name"]
        allVar["minio_host"] = platformSpec["minio"]["ip"].replace("https://","")
        allVar["etcd_retention"] = platformSpec["rancher-rke"]["s3Backups"]["retention"]
        allVar["interval_hours"] = platformSpec["rancher-rke"]["s3Backups"]["interval_hours"]


if not args.skipCNS:
    if platformSpec.get("rancher-rke") is None:
        logger.error("rancher rke field is missing in {}".format(args.data))
        sys.exit(1)
    elif platformSpec.get("rancher-rke").get("worker_cns") is None:
        logger.error("rancher rke worker cns ips field is missing in {}".format(args.data))
        sys.exit(1)

if not args.skipAppPlatform:
    if len(platformSpec["rancher-rke"]["control_plane_ips"]) == 0 or len(platformSpec["rancher-rke"]["worker_ips"]) == 0:
        logger.error("endpoints|ips of Application Platform nodes  is/are missing in {}".format(args.data))
    else:
        for idx, ip in enumerate(platformSpec["rancher-rke"]["control_plane_ips"]):
            host = "rke-cp-" + str(idx)
            inventory = add_value(inventory,['all','hosts', host], ('ansible_host', ip))
            inventory = add_value(inventory,['all','children','rancher-2-controlplane', 'hosts'], (host, None))
        if not platformSpec.get("rancher-rke").get("all_in_one"):
            for idx, ip in enumerate(platformSpec["rancher-rke"]["worker_ips"]):
                host = "rke-worker-" + str(idx)
                inventory = add_value(inventory,['all','hosts', host], ('ansible_host', ip))
                inventory = add_value(inventory,['all','children','rancher-2-workers', 'hosts'], (host, None))
            if platformSpec.get("rancher-rke").get("worker_cns") is not None:
                for idx, ip in enumerate(platformSpec["rancher-rke"]["worker_cns"]):
                    host = "rke-workercns-" + str(idx)
                    inventory = add_value(inventory,['all','hosts', host], ('ansible_host', ip))
                    inventory = add_value(inventory,['all','children','rancher-2-workers', 'hosts'], (host, None))
        else:
            del inventory["all"]["children"]["rancher-2-workers"]



    
with open("/tmp/all.yml",'w') as allVarOut:
    yaml.safe_dump(allVar, allVarOut, default_flow_style=False)
    shutil.copyfile("/tmp/all.yml", "ansible/group_vars/all.yml")
with open("/tmp/production.yml",'w') as inventoryOut:
    yaml.safe_dump(inventory, inventoryOut, default_flow_style=False)
    shutil.copyfile("/tmp/production.yml", "ansible/production.yml")


# PREPARE HELM CMD
# CSI 
cns_crd_cmd="helm --kubeconfig {}  upgrade -i  longhorn-crd /app/ansible/longhorn-crd-102.4.1+up1.6.2.tgz --namespace longhorn-system --create-namespace"
cns_cmd="helm --kubeconfig {} upgrade -i longhorn /app/ansible/longhorn-102.4.1+up1.6.2.tgz --namespace longhorn-system --create-namespace --wait --reuse-values --set defaultSettings.createDefaultDiskLabeledNodes=true --set ingress.enabled=true --set ingress.host=longhorn."+platformSpec["platform_fqdn"]+ " "
if args.offline:
    cns_cmd = cns_cmd + " --set global.cattle.systemDefaultRegistry="+ platformSpec["harbor"]["external_url"]

if platformSpec.get("cns") is not None and platformSpec["cns"].get("data_path"):
    cns_cmd = cns_cmd + " --set defaultSettings.defaultDataPath="+platformSpec["cns"]["data_path"]

if platformSpec.get("cns") is not None and platformSpec["cns"].get("default_replica_count"):
    cns_cmd = cns_cmd + " --set defaultSettings.defaultReplicaCount="+str(platformSpec["cns"]["default_replica_count"]) + " --set persistence.defaultClassReplicaCount="+str(platformSpec["cns"]["default_replica_count"])

if platformSpec.get("rancher-rke") is not None and platformSpec.get("rancher-rke").get("s3Backups") is not None and platformSpec.get("rancher-rke").get("s3Backups").get("enabled"):
    cns_cmd = cns_cmd + " --set defaultSettings.backupTarget=s3://rke-app@us-east-1/ --set defaultSettings.backupTargetCredentialSecret=minio-secret"

secret_cmd = "kubectl --kubeconfig {} apply -f {}/minio-secret.yaml "
# RANCHER CMD
if platformSpec.get("rancher") is not None and platformSpec["rancher"].get("host") is not None:
    rancherHost = platformSpec["rancher"]["host"]
else:
    rancherHost = "rancher.example.com"

rancher_cmd="helm --kubeconfig {} upgrade -i rancher /app/ansible/rancher-rke/rancher-{}.tgz -n cattle-system --create-namespace --set hostname="+rancherHost  + " "
if args.offline:
    rancher_cmd = rancher_cmd +" --set systemDefaultRegistry="+ platformSpec["harbor"]["external_url"] + " --set rancherImage="+platformSpec["harbor"]["external_url"]+"/rancher/rancher"
else:
    rancher_cmd = rancher_cmd +" --set systemDefaultRegistry= --set rancherImage=rancher/rancher"

if platformSpec.get("rancher") is not None and platformSpec["rancher"].get("rancher_count"):
    rancher_cmd = rancher_cmd +" --set replicas="+str(platformSpec["rancher"]["rancher_count"])

# POSTGRESQL CMD
postgres_ns="kubectl --kubeconfig {} create ns postgresql | true"
postgres_cmd="kubectl --kubeconfig {} -n postgresql apply -f {}"

# KAFKA CMD
kafka_ns="kubectl --kubeconfig {} create ns {} | true"
kafka_cmd="kubectl --kubeconfig {} -n {} apply -f {}"
akhq_cmd="helm --kubeconfig {} upgrade -i akhq {} -f {} -n {}"
cert_cmd="kubectl --kubeconfig {} apply -f {}"

# KEYCLOAK CMD 
keycloak_cmd="helm --kubeconfig {} upgrade -i ckey ansible/keycloak -f {} -n keycloak --create-namespace"
if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("keycloak") is not None and platformSpec.get("middleware").get("keycloak").get("enabled") and platformSpec.get("middleware").get("keycloak").get("ha"):
    keycloak_ha_cmd="helm --kubeconfig {} upgrade -i ckey ansible/ckey/keycloak -f {} -n keycloak --create-namespace --set auth.adminPassword="+platformSpec["middleware"]["keycloak"]["admin_password"] + " --set ingress.hostname="+platformSpec["middleware"]["keycloak"]["host"] + "  --set postgresql.persistence.size="+platformSpec["middleware"]["keycloak"]["storage_size"]
    if args.offline:
        keycloak_ha_cmd = keycloak_ha_cmd + " --set image.registry="+platformSpec["harbor"]["external_url"]+"/middleware"  + " --set image.repository=keycloak " + " --set postgresql.image.registry="+platformSpec["harbor"]["external_url"]+"/middleware" + " --set postgresql.image.repository=postgresql "
    else:
        keycloak_ha_cmd = keycloak_ha_cmd + " --set image.registry=docker.io --set image.repository=bitnami/keycloak --set postgresql.image.registry=docker.io --set postgresql.image.repository=bitnami/postgresql"

# EDP CMD
edp_ns_cmd="kubectl --kubeconfig {} create ns keycloak | true"
edp_operator_cmd="kubectl --kubeconfig {} apply -f {} "
edp_cluster_cmd="kubectl --kubeconfig {} -n keycloak apply -f {} "

# ELK CMD
elk_cmd="helm --kubeconfig {} upgrade -i elk ansible/elasticsearch -n elk --create-namespace"
if args.offline:
    elk_cmd = elk_cmd + "  --set image="+platformSpec["harbor"]["external_url"]+"/middleware/elasticsearch"
    
#Vault CMD
vault_cmd="helm --kubeconfig {} upgrade -i vault ansible/vault -f {} -n {} --create-namespace"

# PROFILE CMD
profile_cmd="helm --kubeconfig {} upgrade -i {} {} -f {} -n {} --create-namespace --reuse-values"
if args.offline:
    profile_cmd = profile_cmd + " --set global.registry={} --set global.registry1={} --set global.registry2={}"

if args.nohooks:
    profile_cmd = profile_cmd + "  --no-hooks"

# profile upgrade cmd
upgrade_cmd = "helm --kubeconfig {} upgrade -i {} {}  --set "

if args.create == "upgrade":
    if args.offlinepackage == "":
        logger.error("Failed to load sif-base package")
        sys.exit(1)
    else:
        if platformSpec.get("profiles") is not None:
            if not os.path.exists("/app/artifacts/{}".format(args.offlinepackage)):
                logger.error("Offline package {} does not exist in artifacts folder".format(args.offlinepackage))
                sys.exit(1)
            logger.info("Loading package : {}".format(args.offlinepackage))
            offlinefine = tarfile.open("/app/artifacts/"+args.offlinepackage)
            for item in platformSpec["profiles"]:
                if platformSpec.get("profiles").get(item) is not None and platformSpec.get("profiles").get(item).get("enabled"):
                    PROFILE_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/" + item + "-" + platformSpec["profiles"][item]["version"]+".tar.gz"
                    profile_file1 = "sifbase/"+ item + "-values.yaml"
                    profile_file2 = "sifbase/"+ item + "-" + platformSpec["profiles"][item]["version"]+".tgz"
                    profile_file3 = "sifbase/"+ item + "-images.txt"
                    profile_file4 = "sifbase/"+ item + "-" + platformSpec["profiles"][item]["version"]+".tar.gz"
                    PROFILE_REGISTRY = platformSpec["harbor"]["external_url"]+"/"+item
                    if profile_file1 not in offlinefine.getnames():
                        logger.error("File {} does not exist in package {}".format(profile_file1,args.offlinepackage))
                        sys.exit(1)
                    if profile_file2 not in offlinefine.getnames():
                        logger.error("File {} does not exist in package {}".format(profile_file2,args.offlinepackage))
                        sys.exit(1)
                    if profile_file3 not in offlinefine.getnames():
                        logger.error("File {} does not exist in package {}".format(profile_file3,args.offlinepackage))
                        sys.exit(1)
                    if profile_file4 not in offlinefine.getnames():
                        logger.error("File {} does not exist in package {}".format(profile_file4,args.offlinepackage))
                        sys.exit(1)
                    for member in offlinefine.getnames():
                        if member == profile_file1:
                            offlinefine.extract(profile_file1,PLATFORM_DIRECTORY.removesuffix('/'))
                        if member == profile_file2:
                            offlinefine.extract(profile_file2,PLATFORM_DIRECTORY.removesuffix('/'))
                        if member == profile_file3:
                            offlinefine.extract(profile_file3,PLATFORM_DIRECTORY.removesuffix('/'))
                        if member == profile_file4:
                            offlinefine.extract(profile_file4,PLATFORM_DIRECTORY.removesuffix('/'))

                    if not os.path.exists(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file4):
                        logger.error("Failed to load {}".format(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file4))
                        sys.exit(1)
                    logger.info("ansible/rancher-load-images.sh -i {} -l {} --registry {}".format(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file4,PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file3,PROFILE_REGISTRY))
                    if not args.dryrun:
                        returncodeoffline = subprocess.call("docker login -u admin -p {} {}".format(platformSpec["harbor"]["admin_password"],platformSpec["harbor"]["external_url"]),shell=True,stderr=subprocess.STDOUT)
                        if returncodeoffline == 0:
                            logger.info("Harbor Successfull login")
                        else:
                            logger.error("Harbor Login failed")
                            sys.exit(1)
                        returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {} -l {} --registry {}".format(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file4,PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file3,PROFILE_REGISTRY),shell=True,stderr=subprocess.STDOUT)
                        if returncodeoffline == 0:
                            logger.info("Profile {} Load  Job was run successfully".format(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file4))
                        else:
                            logger.error("Profile {} Load Job failed".format(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file4))
                            sys.exit(1)
        if not args.skipKafkaUpgrade:
            if platformSpec["profiles"].get("push-payment") is not None and platformSpec["profiles"]["push-payment"].get("enabled") and platformSpec["profiles"]["push-payment"].get("topicsuffix") is not None:
                allVar["topic_suffix"] = platformSpec["profiles"]["push-payment"]["topicsuffix"]
                with open("ansible/group_vars/all.yml",'w') as allVarOut:
                    yaml.safe_dump(allVar, allVarOut, default_flow_style=False)
                if args.dryrun:
                    logger.info(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/upgrade.yml ")
                    logger.info(" kubectl --kubeconfig {} apply -f /app/ansible/kafka/kafka-topics.yaml".format(KUBE_RKE))
                else:
                    returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/upgrade.yml ",shell=True,stderr=subprocess.STDOUT)
                    if returncode == 0:
                        logger.info("Playbook run successfully")
                        returncode = subprocess.call("kubectl --kubeconfig {} apply -f /app/ansible/kafka/kafka-topics.yaml || true".format(KUBE_RKE),shell=True,stderr=subprocess.STDOUT)
                        if returncode == 0:
                            logger.info("kafka topics file updated")
                        else:
                            logger.error(" kafka topics file update failed")
                    else:
                        logger.error("Playbook has failed ")
        if platformSpec["profiles"].get("itsp") is not None and platformSpec["profiles"]["itsp"].get("enabled") and platformSpec["profiles"]["itsp"].get("version") is not None:
            logger.info("Upgrade ITSP Solution in APP PLATFORM")     
            if args.offline:
                registry = platformSpec["harbor"]["external_url"]+"/itsp"
                profile_cmd = profile_cmd.format(KUBE_RKE,"itsp",PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file2,PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file1,"itsp",registry,registry,registry)
            else:
                profile_cmd = profile_cmd.format(KUBE_RKE,"itsp",PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file2,PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file1,"itsp")
            if not os.path.exists(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file1):
                logger.error("Failed to load {}".format(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file1))
                sys.exit(1)
            if not os.path.exists(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file2):
                logger.error("Failed to load {}".format(PLATFORM_DIRECTORY.removesuffix('/')+"/"+profile_file2))
                sys.exit(1)
            logger.info(profile_cmd)
            if not args.dryrun:
                returncode = subprocess.call(profile_cmd,shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Happy helming! itsp release was upgraded Successfully")
                else:
                    logger.error("itsp release upgrade failed")
                    sys.exit(1)
 
        if platformSpec["profiles"].get("push-payment") is not None and platformSpec["profiles"]["push-payment"].get("enabled") and platformSpec["profiles"]["push-payment"].get("version") is not None:
            logger.info("Upgrade Push Payment Solution in APP PLATFORM")
            package = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/push-payment-" + platformSpec["profiles"]["push-payment"]["version"]+".tgz"
            values = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/push-payment-values.yaml"
            if args.offline:
                registry = platformSpec["harbor"]["external_url"]+"/push-payment"
                profile_cmd = profile_cmd.format(KUBE_RKE,"pp",package,values,"push-payment",registry,registry,registry)
            else:
                profile_cmd = profile_cmd.format(KUBE_RKE,"pp",package,values,"push-payment")
            if not os.path.exists(values):
                logger.error("Failed to load {}".format(values))
                sys.exit(1)
            if not os.path.exists(package):
                logger.error("Failed to load {}".format(package))
                sys.exit(1)
            if not args.dryrun:
                returncode = subprocess.call(" helm --kubeconfig {} upgrade -i pp {} -f {}  -n {} --set interface-jms-service.enabled=false --set interface-canaux-service.enabled=false --reuse-values --set global.registry={} --set global.registry1={} --set global.registry2={} ".format(KUBE_RKE,package,values,"push-payment",registry,registry,registry),shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Push Payment Service was re-instaled Successfully without interface-cannaux and interface-jms services")
                    choice = input(" do you want to re-install all push-payment microservices ?( 'yes' to confirm )")
                    if choice == "yes":
                        returncode = subprocess.call(profile_cmd,shell=True,stderr=subprocess.STDOUT)
                        if returncode == 0:
                            logger.info("Push Payment was re-installed Successfully")
                        else:
                            logger.error("Push Payment release installation failed")
                            sys.exit(1)
            else:
                logger.info("Push-payment re-installation withput the interface-cannaux and interface-jms services")
                logger.info("helm --kubeconfig {} upgrade -i pp {} -f {} -n {} --set interface-jms-service.enabled=false --set interface-canaux-service.enabled=false --reuse-values --set global.registry={} --set global.registry1={} --set global.registry2={}".format(KUBE_RKE,package,values,"push-payment",registry,registry,registry))
                choice = input(" do you want to re-install all push-payment microservices ?( 'yes' to confirm )")
                if choice == "yes":
                    logger.info(profile_cmd)


if args.create == "rollback":
    logger.info("Rollback Option")
    if platformSpec["profiles"]["push-payment"]:
        release = "pp"
        ns ="push-payment"
    elif platformSpec["profiles"]["mobile-switch"]:
        release= "ms"
        ns ="mobile-switch"
    if args.revision is None:
        if args.dryrun:
            logger.info(" helm --kubeconfig {} rollback {} -n {} ".format(KUBE_RKE,release,ns))
        else:
            returncode = subprocess.call(" helm --kubeconfig {} rollback {} ".format(KUBE_RKE,release,ns),shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Rollback was successful")
            else:
                logger.error("Rollback has failed")
                sys.exit(1)
    else:
        if args.dryrun:
            logger.info(" helm --kubeconfig {} rollback {} {} -n {}".format(KUBE_RKE,release,args.revision,ns))
        else:
            returncode = subprocess.call(" helm --kubeconfig {} rollback {} {} -n {}".format(KUBE_RKE,release,args.revision,ns),shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Rollback was succeful")
            else:
                logger.error("Rollback has failed")
                sys.exit(1)




if args.create == "harbor-upgrade":
    logger.info(" Upgrading Harbor Option")
    if args.offline:
        logger.info("Offline Installation")
        if args.package is None:
            logger.error("Please specify the package path")
        else:
            #check if package os on current directory
            if not os.path.exists("packages/"+args.package):
                logger.error(" the package doesn't exist in this directory")
            else:
                allVar["harbor_package_name"] = args.package
                allVar["harbor_package_path"] ="packages/"+args.package
                allVar["harbor_version"]=args.package.removeprefix('harbor-offline-installer-').removesuffix(".tgz")
                with open("/tmp/all.yml",'w') as allVarOut:
                    yaml.safe_dump(allVar, allVarOut, default_flow_style=False)
                    shutil.copyfile("/tmp/all.yml", "ansible/group_vars/all.yml")
                logger.info("package name : {}".format(allVar["harbor_package_name"]))
                logger.info("package path : {}".format(allVar["harbor_package_path"]))
                logger.info(" harbor version : {} ".format(allVar["harbor_version"]))
                if args.dryrun:
                    logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/harbor-upgrade.yml")
                else:
                    logger.info(" Running harbor-upgrade playbook . . .")
                    retcode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/harbor-upgrade.yml",shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        time.sleep(60)
                        logger.info("Harbor Playbook was run successfully")
                    else:
                        logger.error("Harbor Playbook failed")
                        sys.exit(1)
    else:
        logger.info("online harbor upgrade unavailable for the moment , please enter the --offline option for the offline installation ")



if args.create == "create":
    logger.info(" Create Platfrom Option")
    if not args.skipHarbor and args.offline:
        if platformSpec.get("harbor") is not None and platformSpec.get("harbor").get("ssl") is not None and platformSpec.get("harbor").get("ssl").get("enabled"):
            subjca = "/C=CN/ST=Maroc/L=Maroc/O=example/OU=Personal/CN="+ platformSpec["harbor"]["external_url"]
            subserver = "/C=CN/ST=Maroc/L=Maroc/O=example/OU=Personal/CN="+ platformSpec["harbor"]["external_url"]
            ca_certificate = PLATFORM_DIRECTORY.removesuffix('/') + "/ca-harbor.crt"
            if not args.dryrun:
                if not os.path.exists(ca_certificate):
                    logger.info("Generate a Certificate Authority Certificate")
                    retcode = subprocess.call("openssl genrsa -out {}/ca-harbor.key 4096".format(PLATFORM_DIRECTORY.removesuffix('/')),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("CA certificate private key was generated successfully")
                    else:
                        logger.error("CA certificate private key generation failed")
                        sys.exit(1)
                    retcode = subprocess.call("openssl req -x509 -new -nodes -sha512 -days 36500 -subj {} -key {}/ca-harbor.key -out {}/ca-harbor.crt".format(subjca,PLATFORM_DIRECTORY.removesuffix('/'),PLATFORM_DIRECTORY.removesuffix('/')),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("CA certificate  was generated successfully")
                    else:
                        logger.error("CA certificate generation failed")
                        sys.exit(1)
                    logger.info("Generate a Server Certificate")
                    retcode = subprocess.call("openssl genrsa -out {}/{}.key 4096".format(PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"]),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("Server certificate private key was generated successfully")
                    else:
                        logger.error("Server certificate private key generation failed")
                        sys.exit(1)
                    
                    retcode = subprocess.call("openssl req -sha512 -new -subj {} -key {}/{}.key -out {}/{}.csr".format(subjca,PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"],PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"]),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("CSR certificate  was generated successfully")
                    else:
                        logger.error("CSR certificate generation failed")
                        sys.exit(1)
                    with open(PLATFORM_DIRECTORY.removesuffix('/')+'/v3.ext','w') as out:
                        line1 = "authorityKeyIdentifier=keyid,issuer \n"
                        line2 = "basicConstraints=CA:FALSE \n"
                        line3 = "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment \n"
                        line4 = "extendedKeyUsage = serverAuth \n"
                        line5 = "subjectAltName = @alt_names \n"
                        line6 = "[alt_names] \n"
                        line7 = "DNS.1=" + platformSpec["harbor"]["external_url"]
                        out.writelines([line1, line2, line3, line4, line5, line6, line7])
                    retcode = subprocess.call("openssl x509 -req -sha512 -days 36500 -extfile {}/v3.ext -CA {}/ca-harbor.crt -CAkey {}/ca-harbor.key -CAcreateserial -in {}/{}.csr -out {}/{}.crt".format(PLATFORM_DIRECTORY.removesuffix('/'),PLATFORM_DIRECTORY.removesuffix('/'),PLATFORM_DIRECTORY.removesuffix('/'),PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"],PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"]),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("Harbor certificate  was generated successfully")
                    else:
                        logger.error("Harbor certificate generation failed")
                        sys.exit(1)
                    retcode = subprocess.call("openssl x509 -inform PEM -in {}/{}.crt -out {}/{}.cert".format(PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"],PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"]),shell=True,stderr=subprocess.STDOUT)
                    if retcode == 0:
                        logger.info("Harbor certificate  was generated successfully : cert")
                    else:
                        logger.error("Harbor certificate generation failed : cert")
                        sys.exit(1)
                else:
                    logger.info("{} already exists skipping certificate generation for harbor endpoint".format(ca_certificate))
            else:
                logger.info("Generate a Certificate Authority Certificate")
                logger.info("openssl genrsa -out {}/ca-harbor.key 4096".format(PLATFORM_DIRECTORY.removesuffix('/')))
                logger.info("openssl req -x509 -new -nodes -sha512 -days 36500 -subj {} -key {}/ca-harbor.key -out {}/ca-harbor.crt".format(subjca,PLATFORM_DIRECTORY.removesuffix('/'),PLATFORM_DIRECTORY.removesuffix('/')))
                logger.info("Generate a Server Certificate")
                logger.info("openssl genrsa -out {}/{}.key 4096".format(PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"]))
                logger.info("openssl req -sha512 -new -subj {} -key {}/{}.key -out {}/{}.csr".format(subjca,PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"],PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"]))
                logger.info("openssl x509 -req -sha512 -days 36500 -extfile {}/v3.ext -CA {}/ca-harbor.crt -CAkey {}/ca-harbor.key -CAcreateserial -in {}/{}.csr -out {}/{}.crt".format(PLATFORM_DIRECTORY.removesuffix('/'),PLATFORM_DIRECTORY.removesuffix('/'),PLATFORM_DIRECTORY.removesuffix('/'),PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"],PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"]))
                logger.info("openssl x509 -inform PEM -in {}/{}.crt -out {}/{}.cert".format(PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"],PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["harbor"]["external_url"]))
    #####   
    if not args.skipHarbor and args.offline:
        #password_length = 13
        if not os.path.exists(HARBOR_PACKAGE):
            logger.error("Failed to load {}".format(HARBOR_PACKAGE))
            sys.exit(1)
            #harborVar["harbor_password"] = secrets.token_urlsafe(password_length)
        logger.info("Running Harbor Playbook")
        #s = subprocess.Popen("ansible-playbook -i ansible/production.yml ansible/rancher-2-harbor.yml -vvvv", stdout=subprocess.PIPE, shell=True)
        #retcode = subprocess.call(['tar','-xvf', 'allimages-'+allimages_version+'.tgz', '-C', '.'], stdout=FNULL, stderr=subprocess.STDOUT)
        if not args.dryrun:
            retcode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-harbor.yml",shell=True,stderr=subprocess.STDOUT)
            if retcode == 0:
                time.sleep(60)
                logger.info("Harbor Playbook was run successfully")
            else:
                logger.error("Harbor Playbook failed")
                sys.exit(1)
        else:
            logger.info(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-harbor.yml")
    # Offline load of packages in Harbor
    if args.offline and not args.skipLoad:
        logger.info("Harbor First login ")
        if not args.dryrun:
            returncodeoffline = subprocess.call("docker login -u admin -p {} {}".format(platformSpec["harbor"]["admin_password"],platformSpec["harbor"]["external_url"]),shell=True,stderr=subprocess.STDOUT)
            if returncodeoffline == 0:
                logger.info("Harbor Successfull login")
            else:
                logger.error("Harbor Login failed")
                sys.exit(1)
        else:
            logger.info("docker login -u admin -p {} {}".format(platformSpec["harbor"]["admin_password"],platformSpec["harbor"]["external_url"]))
        if platformSpec.get("minio") is not None and platformSpec["minio"].get("enabled"):
            logger.info("Loading minio artficats into Client Harbor")
            logging.info("ansible/rancher-load-images.sh -i {}/minio.tar.gz -l {}/minio-images.txt --registry {}".format(PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/minio"))
            if not args.dryrun:
                returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {}/minio.tar.gz -l {}/minio-images.txt --registry {}".format(PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/minio"),shell=True,stderr=subprocess.STDOUT)
                if returncodeoffline == 0:
                    logger.info("Minio Load Job was run successfully")
                else:
                    logger.error("Minio load JOB failed")
                    sys.exit(1)
        if not args.skipAdministrationPlatform or not args.skipAppPlatform:
            logger.info("Loading rancher artficats into Client Harbor")
            if not os.path.exists(RANCHER_PACKAGE):
                logger.error("Failed to load {}".format(RANCHER_PACKAGE))
                sys.exit(1)
            logging.info("ansible/rancher-load-images.sh -i {} -l {}/rancher-images-{}.txt --registry {}".format(RANCHER_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",rkeVersion,platformSpec["harbor"]["external_url"]+"/rancher"))
            if not args.dryrun:
                returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {} -l {}/rancher-images-{}.txt --registry {}".format(RANCHER_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",rkeVersion,platformSpec["harbor"]["external_url"]+"/rancher"),shell=True,stderr=subprocess.STDOUT)
                if returncodeoffline == 0:
                    logger.info("Rancher Load Job was run successfully")
                else:
                    logger.error("Rancher load JOB failed")
                    sys.exit(1)
        if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("keycloak") is not None and platformSpec.get("middleware").get("keycloak").get("enabled"):
            if not platformSpec["middleware"]["keycloak"].get("ha"):
                if not os.path.exists(KEYCLOAK_PACKAGE):
                    logger.error("Failed to load {}".format(KEYCLOAK_PACKAGE))
                    sys.exit(1)
                logger.info("ansible/rancher-load-images.sh -i {} -l {}/keycloak-images.txt --registry {}".format(KEYCLOAK_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"))
                if not args.dryrun:
                    returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {} -l {}/keycloak-images.txt --registry {}".format(KEYCLOAK_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"),shell=True,stderr=subprocess.STDOUT)
                    if returncodeoffline == 0:
                        logger.info("Keycloak Load Job was run successfully")
                    else:
                        logger.error("Keycloak Load Job failed")
                        sys.exit(1)
            else:
                if not os.path.exists(KEYCLOAK_HA_PACKAGE):
                    logger.error("Failed to load {}".format(KEYCLOAK_HA_PACKAGE))
                    sys.exit(1)
                if platformSpec["middleware"]["keycloak"].get("external_pg_db"):           
                    if not os.path.exists(KEYCLOAK_EDP_PACKAGE):
                        logger.error("Failed to load {}".format(KEYCLOAK_EDP_PACKAGE))
                        sys.exit(1)
                    logger.info("ansible/rancher-load-images.sh -i {} -l {}/keycloak-edp-images.txt --registry {}".format(KEYCLOAK_EDP_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"))
                    logger.info("ansible/rancher-load-images.sh -i {} -l {}/keycloak-ha-images.txt --registry {}".format(KEYCLOAK_HA_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"))
                logger.info("ansible/rancher-load-images.sh -i {} -l {}/keycloak-ha-images.txt --registry {}".format(KEYCLOAK_HA_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"))
                if not args.dryrun:
                    if platformSpec["middleware"]["keycloak"].get("external_pg_db"):               
                        returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {} -l {}/keycloak-edp-images.txt --registry {}".format(KEYCLOAK_EDP_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"),shell=True,stderr=subprocess.STDOUT)
                        if returncodeoffline == 0:
                            logger.info("Keycloak EDP LOAD Job was run successfully")
                        else:
                            logger.error("Keycloak EDP Job Playbook failed")
                            sys.exit(1)
                    returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {} -l {}/keycloak-ha-images.txt --registry {}".format(KEYCLOAK_HA_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"),shell=True,stderr=subprocess.STDOUT)
                    if returncodeoffline == 0:
                        logger.info("Keycloak HA LOAD Job was run successfully")
                    else:
                        logger.error("Keycloak HA Job Playbook failed")
                        sys.exit(1) 
        if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("kafka") is not None and platformSpec.get("middleware").get("kafka").get("enabled"):
            if not os.path.exists(KAFKA_PACKAGE):
                logger.error("Failed to load {}".format(KAFKA_PACKAGE))
                sys.exit(1)
            logger.info("ansible/rancher-load-images.sh -i {} -l {}/kafka-images.txt --registry {}".format(KAFKA_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"))
            if not args.dryrun:
                returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {} -l {}/kafka-images.txt --registry {}".format(KAFKA_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"),shell=True,stderr=subprocess.STDOUT)
                if returncodeoffline == 0:
                    logger.info("KAFKA Load Job was run successfully")
                else:
                    logger.error("KAFKA Load Job failed")
                    sys.exit(1)
        if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("postgresql") is not None and platformSpec.get("middleware").get("postgresql").get("enabled"):
            if not os.path.exists(POSTGRESQL_PACKAGE):
                logger.error("Failed to load {}".format(POSTGRESQL_PACKAGE))
                sys.exit(1)
            logger.info("ansible/rancher-load-images.sh -i {} -l {}/postgresql-images.txt --registry {}".format(POSTGRESQL_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"))
            if not args.dryrun:
                returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {} -l {}/postgresql-images.txt --registry {}".format(POSTGRESQL_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",platformSpec["harbor"]["external_url"]+"/middleware"),shell=True,stderr=subprocess.STDOUT)
                if returncodeoffline == 0:
                    logger.info("POSTGRESQL Load Job was run successfully")
                else:
                    logger.error("POSTGRESQL Load Job failed")
                    sys.exit(1)
        if platformSpec.get("profiles") is not None:
            for item in platformSpec["profiles"]:
                if platformSpec.get("profiles").get(item) is not None and platformSpec.get("profiles").get(item).get("enabled"):
                    PROFILE_PACKAGE = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/" + item + "-" + platformSpec["profiles"][item]["version"]+".tar.gz"
                    PROFILE_REGISTRY = platformSpec["harbor"]["external_url"]+"/"+item
                    if not os.path.exists(PROFILE_PACKAGE):
                        logger.error("Failed to load {}".format(PROFILE_PACKAGE))
                        sys.exit(1)
                    logger.info("ansible/rancher-load-images.sh -i {} -l {}/{}-images.txt --registry {}".format(PROFILE_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",item,PROFILE_REGISTRY))
                    if not args.dryrun:
                        returncodeoffline = subprocess.call("ansible/rancher-load-images.sh -i {} -l {}/{}-images.txt --registry {}".format(PROFILE_PACKAGE,PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase",item,PROFILE_REGISTRY),shell=True,stderr=subprocess.STDOUT)
                        if returncodeoffline == 0:
                            logger.info("Profile {} Load  Job was run successfully".format(PROFILE_PACKAGE))
                        else:
                            logger.error("Profile {} Load Job failed".format(PROFILE_PACKAGE))
                            sys.exit(1)
    # Install Minio
    
    if platformSpec.get("minio") is not None and platformSpec["minio"].get("enabled"):
        if not args.dryrun:
            if not args.skipMinio:
                retcode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-minio.yml",shell=True,stderr=subprocess.STDOUT)
                if retcode == 0:
                    logger.info("Minio Playbook was run successfully")
                else:
                    logger.error("Minio Playbook failed")
                    sys.exit(1)
                logging.info("Add Minio Server... ")
                retcode = subprocess.call("mc alias set myminio http://{}:443 {} {} --insecure".format(platformSpec["minio"]["ip"],platformSpec["minio"]["accessId"],platformSpec["minio"]["accessKey"]),shell=True,stderr=subprocess.STDOUT)
                if retcode == 0:
                    logger.info("Minio server  was added successfully")
                else:
                    logger.error("Minio server add failed")
                    sys.exit(1)
                logging.info("Add etcd Bucket... ")
                retcode = subprocess.call("mc mb myminio/rke-etcd --insecure",shell=True,stderr=subprocess.STDOUT)
                if retcode == 0:
                    logger.info("Minio etcd bucket  was created successfully")
                else:
                    logger.error("Minio etcd bucket creation failed")
                    #sys.exit(1)
                logging.info("Add rke app Bucket... ")
                retcode = subprocess.call("mc mb myminio/rke-app --insecure",shell=True,stderr=subprocess.STDOUT)
                if retcode == 0:
                    logger.info("Minio rke app Bucket  was created successfully")
                else:
                    logger.error("Minio rke app Bucket creation failed")
                    #sys.exit(1)
        else:
            logger.info(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-minio.yml")
            logger.info("Add Minio Server... ")
            logger.info("Create etcd Bucket... ")
            logger.info("Create rke app Bucket... ")

    logger.info(" minio installtion is completed now ")
    # Parsing data yml and generate production yml file 
    if not args.skipAdministrationPlatform:
        if not args.dryrun:
            logger.info("Running Administration Platform Playbook")
            returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-admin-platform.yml",shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Rancher Admnistration Playbook was run Successfully")
            else:
                logger.error("Rancher Admnistration Playbook failed")
                sys.exit(1)
            logger.info("Installing rke kubernetes distribution")
            returncode = subprocess.call("rke_linux-amd64 up --config {}/rancher-cluster.yml".format(PLATFORM_DIRECTORY.removesuffix('/')),cwd=PLATFORM_DIRECTORY.removesuffix('/'),shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("rancher admin platform installation was run successfully")
            else:
                logger.error("rancher installation failed")
                sys.exit(1)
            logger.info("Waiting for rke services to be up and running")
            time.sleep(120)
            logger.info("Installing RANCHER on ADMIN platform")
            returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-rancher.yml",shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Rancher Playbook was run successfully")
            else:
                logger.error("Rancher Playbook failed")
                sys.exit(1)
            returncode = subprocess.call(cert_cmd.format(KUBE_ADMIN,"/app/ansible/cert-manager.yaml") ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("CERTMANAGER  was installed successfully")
            else:
                logger.error("CERTMANAGER installation failed")
                sys.exit(1)
            time.sleep(180)
            logger.info(rancher_cmd.format(KUBE_ADMIN,rancherVersion))
            returncode = subprocess.call(rancher_cmd.format(KUBE_ADMIN,rancherVersion) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("HAPPY HELMING RANCHER  was installed successfully")
            else:
                logger.error("RANCHER installation failed")
        else:
            logger.info("Running Administration Platform Playbook")
            logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-admin-platform.yml")
            logger.info("Installing rke kubernetes distribution")
            logger.info("rke_linux-amd64 up --config {}/rancher-cluster.yml".format(PLATFORM_DIRECTORY.removesuffix('/')))
            logger.info("Waiting for rke services to be up and running 120s....")
            logger.info("Installing RANCHER on ADMIN platform")
            logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-rancher.yml")
            logger.info(cert_cmd.format(KUBE_ADMIN,"/app/ansible/cert-manager.yaml"))
            logger.info(rancher_cmd.format(KUBE_ADMIN,rancherVersion))
    if not args.skipAppPlatform:
        if not args.dryrun:
            logger.info("Installing RKE PRODUCTION Platform")
            returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-platform.yml",shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("RKE Playbook was run successfully")
            else:
                logger.error("RKE Playbook failed")
                sys.exit(1)
            logger.info("Installing rke kuberentes distribution")
            if args.restore:
                returncode = subprocess.call("rke_linux-amd64 etcd snapshot-restore --config {}/rke_cluster.yml --s3 --access-key {} --secret-key {} --bucket-name {}  --s3-endpoint {} --s3-endpoint-ca {} --name {} ".format(PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["minio"]["accessId"],platformSpec["minio"]["accessKey"],platformSpec["rancher-rke"]["s3Backups"]["bucket_name"],platformSpec["minio"]["host"],ca_certificate, args.snapshotname),cwd=PLATFORM_DIRECTORY.removesuffix('/'),shell=True,stderr=subprocess.STDOUT)
            else:
                returncode = subprocess.call("rke_linux-amd64 up --config {}/rke_cluster.yml".format(PLATFORM_DIRECTORY.removesuffix('/')),cwd=PLATFORM_DIRECTORY.removesuffix('/'),shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("rke instalation was run successfully")
                logger.info("Waiting for rke services to be up and running")
                time.sleep(180) 
            else:
                logger.error("rke installation failed")
                sys.exit(1)
        else:
            logger.info("Installing RKE PRODUCTION Platform")
            logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-platform.yml")
            if args.restore:
                logger.info("Restoring rke kuberentes distribution")
                logger.info("rke_linux-amd64 etcd snapshot-restore --config {}/rke_cluster.yml --s3 --access-key {} --secret-key {} --bucket-name {}  --s3-endpoint {} --s3-endpoint-ca {} --name {} ".format(PLATFORM_DIRECTORY.removesuffix('/'),platformSpec["minio"]["accessId"],platformSpec["minio"]["accessKey"],platformSpec["rancher-rke"]["s3Backups"]["bucket_name"],platformSpec["minio"]["host"],ca_certificate, args.snapshotname))
            else:
                logger.info("Installing rke kuberentes distribution")
                logger.info("rke_linux-amd64 up --config {}/rke_cluster.yml".format(PLATFORM_DIRECTORY.removesuffix('/')))
    if args.deployRancherOnApp:
        if not args.dryrun:
            logger.info("Installing RANCHER on APP platform")
            returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-rancher.yml",shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Playbook was run successfully")
            else:
                logger.error("Rancher Playbook failed")
                sys.exit(1)
            returncode = subprocess.call(cert_cmd.format(KUBE_RKE,"/app/ansible/cert-manager.yaml") ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("CERTMANAGER  was installed successfully")
            else:
                logger.error("CERTMANAGER installation failed")
                sys.exit(1)
            time.sleep(180)
            returncode = subprocess.call(rancher_cmd.format(KUBE_RKE,rancherVersion) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("HAPPY HELMING RANCHER  was installed successfully")
            else:
                logger.error("RANCHER installation failed")
                sys.exit(1)
        else:
            logger.info("Installing RANCHER on APP platform")
            logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-rancher.yml")
            logger.info(cert_cmd.format(KUBE_RKE,"/app/ansible/cert-manager.yaml"))
            logger.info("sleep 180s...")
            logger.info(rancher_cmd.format(KUBE_RKE,rancherVersion))
    if not args.skipCNS:
        logger.info("Deploy LONGHORN CSI for PERSISTENT STORAGE in APP PLATFORM")
        if not args.dryrun:
            if not os.path.exists(KUBE_RKE):
                logger.error("Failed to load {}".format(KUBE_RKE))
                sys.exit(1)
        for ip in platformSpec["rancher-rke"]["worker_cns"]:
            if not args.dryrun:
                returncode = subprocess.call(" kubectl --kubeconfig {} label nodes {} node.longhorn.io/create-default-disk=true storage=longhorn --overwrite".format(KUBE_RKE,ip),shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("NODE CNS LABELLING was run successfully")
                else: 
                    logger.error("NODE CNS LABELLNG failed")
                    sys.exit(1)
                if not args.skipCnsTaint:
                    returncode = subprocess.call(" kubectl --kubeconfig {} taint nodes {} worker=cns:NoSchedule --overwrite".format(KUBE_RKE,ip),shell=True,stderr=subprocess.STDOUT)
                    if returncode == 0:
                        logger.info("NODE CNS Tainting was run successfully")
                    else:
                        logger.error("NODE CNS Tainting failed")
                        sys.exit(1)
            else:
                logger.info(" kubectl --kubeconfig {} label nodes {} node.longhorn.io/create-default-disk=true storage=longhorn --overwrite".format(KUBE_RKE,ip))
                logger.info("kubectl --kubeconfig {} taint nodes {} worker=cns:NoSchedule --overwrite".format(KUBE_RKE,ip))
        if not args.dryrun:
            returncode = subprocess.call(cns_crd_cmd.format(KUBE_RKE) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("HAPPY HELMING LONGHORN CRD was installed successfully")
            else:
                logger.error("LONGHORN CRD installation failed")
                sys.exit(1)
            returncode = subprocess.call(cns_cmd.format(KUBE_RKE) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("HAPPY HELMING LONGHORN  was installed successfully")
            else:
                logger.error("LONGHORN installation failed")
                sys.exit(1)
            if platformSpec.get("rancher-rke") is not None and platformSpec.get("rancher-rke").get("s3Backups") is not None and platformSpec.get("rancher-rke").get("s3Backups").get("enabled"):
                returncode = subprocess.call(secret_cmd.format(KUBE_RKE,PLATFORM_DIRECTORY.removesuffix('/')) ,shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Minio secret  was installed successfully")
                else:
                    logger.error("Minio secret installation was failed")
                    sys.exit(1)
        else:
            logger.info(cns_crd_cmd.format(KUBE_RKE))
            logger.info(cns_cmd.format(KUBE_RKE))
            logger.info(secret_cmd.format(KUBE_RKE,PLATFORM_DIRECTORY.removesuffix('/')))
    if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("kafka") is not None and platformSpec.get("middleware").get("kafka").get("enabled"):
        if not args.dryrun:
            logger.info("Deploy Kafka in APP PLATFORM")
            returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-kafka.yml",shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Playbook was run successfully")
            else:
                logger.error("KAFKA Playbook failed")
                sys.exit(1)
            returncode = subprocess.call(kafka_ns.format(KUBE_RKE,KAFKA_NS) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Kafka namespace created Successfully")
            else:
                logger.error("Kafka namespace creation failed")
                sys.exit(1)
            returncode = subprocess.call(kafka_cmd.format(KUBE_RKE,KAFKA_NS,"/app/ansible/kafka/kafka/cluster-operator") ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Cluster Operator was created Successfully")
            else:
                logger.error("Cluster Operator creation failed")
                sys.exit(1)
            time.sleep(60)
            returncode = subprocess.call(kafka_cmd.format(KUBE_RKE,KAFKA_NS,"/app/ansible/kafka/kafka/kafka-cluster.yml") ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Kafka cluster was created Successfully")
            else:
                logger.error("kafka cluster creation failed")
                sys.exit(1)
            time.sleep(120)
            returncode = subprocess.call(kafka_cmd.format(KUBE_RKE,KAFKA_NS,"/app/ansible/kafka/schema-registry") ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Schema registry was created Successfully")
            else:
                logger.error("Schema registry creation failed")
                sys.exit(1)
            returncode = subprocess.call(akhq_cmd.format(KUBE_RKE,"/app/ansible/kafka/akhq/akhq-0.2.7.tgz","/app/ansible/kafka/akhq/values.yml",KAFKA_NS) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("akhq was created Successfully")
            else:
                logger.error("akhq release installation failed")
                sys.exit(1)
        else:
            logger.info("Deploy Kafka in APP PLATFORM")
            logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-kafka.yml")
            logger.info(kafka_ns.format(KUBE_RKE,KAFKA_NS))
            logger.info(kafka_cmd.format(KUBE_RKE,KAFKA_NS,"/app/ansible/kafka/kafka/cluster-operator"))
            logger.info(kafka_cmd.format(KUBE_RKE,KAFKA_NS,"/app/ansible/kafka/kafka/kafka-cluster.yml"))
            logger.info("sleep 60s.........")
            logger.info(kafka_cmd.format(KUBE_RKE,KAFKA_NS,"/app/ansible/kafka/schema-registry"))
            logger.info(akhq_cmd.format(KUBE_RKE,"/app/ansible/kafka/akhq/akhq-0.2.7.tgz","/app/ansible/kafka/akhq/values.yml",KAFKA_NS))
    if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("postgresql") is not None and platformSpec.get("middleware").get("postgresql").get("enabled"):
        if not args.dryrun:
            logger.info("Deploy Postgresql in APP PLATFORM")
            returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-postgres.yml",shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Postgresql Playbook was run successfully")
            else:
                logger.error("Postgresql Playbook failed")
                sys.exit(1)
            returncode = subprocess.call(postgres_ns.format(KUBE_RKE) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Postgresql namespace created Successfully")
            else:
                logger.error("Postgresql namespace creation failed")
                sys.exit(1)
            returncode = subprocess.call(postgres_cmd.format(KUBE_RKE,"/app/ansible/postgres/") ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Postgresql was created Successfully")
            else:
                logger.error("Postgresql Operator creation failed")
                sys.exit(1)
        else:
            logger.info("Deploy Postgresql in APP PLATFORM")
            logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-postgres.yml")
            logger.info(postgres_ns.format(KUBE_RKE))
            logger.info(postgres_cmd.format(KUBE_RKE,"/app/ansible/postgres/"))
    if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("keycloak") is not None and platformSpec.get("middleware").get("keycloak").get("enabled"):
        if not platformSpec["middleware"]["keycloak"].get("ha"):
            if not args.dryrun:
                logger.info("Deploy a standalone Keycloak in APP PLATFORM")
                returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-keycloak.yml",shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Playbook was run successfully")
                else:
                    logger.error("Keycloak Playbook failed")
                    sys.exit(1)
                logger.info(keycloak_cmd)
                returncode = subprocess.call(keycloak_cmd.format(KUBE_RKE,"/app/ansible/keycloak-values.yml") ,shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Keycloak was created Successfully")
                else:
                    logger.error("Keycloak release installation failed")
                    sys.exit(1)
            else:
                logger.info("Deploy a standalone Keycloak in APP PLATFORM")
                logger.info(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-keycloak.yml")
                logger.info(keycloak_cmd)
        else:
            if not args.dryrun:
                if platformSpec["middleware"]["keycloak"].get("external_pg_db"):           
                    logger.info("Deploy a Highly available EDP postgresql cluster")
                    returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-edp.yml",shell=True,stderr=subprocess.STDOUT)
                    if returncode == 0:
                        logger.info("EDP Rendering Playbook was run successfully")
                    else:
                        logger.error("EDP Rendering Playbook Failed")
                        sys.exit(1)
                    logger.info(edp_ns_cmd)
                    returncode = subprocess.call(edp_ns_cmd.format(KUBE_RKE) ,shell=True,stderr=subprocess.STDOUT)
                    if returncode == 0:
                        logger.info("EDP namespace was created Successfully")
                    else:
                        logger.error("EDP namespace release installation failed")
                        sys.exit(1)
                    logger.info(edp_operator_cmd)
                    returncode = subprocess.call(edp_operator_cmd.format(KUBE_RKE,"/app/ansible/edp/postgresql-operator-1.18.0.yaml") ,shell=True,stderr=subprocess.STDOUT)
                    if returncode == 0:
                        logger.info("EDP operator was created Successfully")
                    else:
                        logger.error("EDP operator release installation failed")
                        sys.exit(1)
                    logger.info(edp_cluster_cmd)
                    time.sleep(30)
                    returncode = subprocess.call(edp_cluster_cmd.format(KUBE_RKE,"/app/ansible/edp/cluster-edp.yaml") ,shell=True,stderr=subprocess.STDOUT)
                    if returncode == 0:
                        logger.info("EDP cluster was created Successfully")
                    else:
                        logger.error("EDP cluster release installation failed")
                        sys.exit(1)
                    time.sleep(120)
                logger.info("Deploy a Highly available Keycloak in APP PLATFORM")
                logger.info(keycloak_ha_cmd)
                returncode = subprocess.call(keycloak_ha_cmd.format(KUBE_RKE,"/app/ansible/ckey/keycloak/ci/values-ha.yaml") ,shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Keycloak HA was created Successfully")
                else:
                    logger.error("Keycloak HA release installation failed")
                    sys.exit(1)
            else:
                logger.info("Deploy a Highly available Keycloak in APP PLATFORM")
                if platformSpec["middleware"]["keycloak"].get("external_pg_db"):
                    logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-edp.yml")
                    logger.info(edp_ns_cmd.format(KUBE_RKE))
                    logger.info(edp_operator_cmd.format(KUBE_RKE,"/app/ansible/edp/postgresql-operator-1.18.0.yaml"))
                    logger.info(edp_cluster_cmd.format(KUBE_RKE,"/app/ansible/edp/cluster-edp.yaml"))
                logger.info(keycloak_ha_cmd)
    if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("elk") is not None and platformSpec.get("middleware").get("elk").get("enabled"):
        if not args.dryrun:
            logger.info("Deploy Elastic Search in APP PLATFORM")
            returncode = subprocess.call(elk_cmd.format(KUBE_RKE) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("ElasticSearch was created Successfully")
            else:
                logger.error("ElasticSearch release installation failed")
                sys.exit(1)
        else:
            logger.info("Deploy Elastic Search in APP PLATFORM")
            logger.info(elk_cmd.format(KUBE_RKE))
    if platformSpec.get("middleware") is not None and platformSpec.get("middleware").get("vault") is not None and platformSpec.get("middleware").get("vault").get("enabled"):
        if not args.dryrun:
            logger.info("Deploy Vault in APP PLATFORM")
            returncode = subprocess.call(" ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-vault.yml",shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Playbook was run successfully")
            else:
                logger.error("Vault Playbook failed")
                sys.exit(1)
            returncode = subprocess.call(vault_cmd.format(KUBE_RKE,"/app/ansible/vault-values.yml",VAULT_NS) ,shell=True,stderr=subprocess.STDOUT)
            if returncode == 0:
                logger.info("Vault Service was created Successfully")
            else:
                logger.error("Vault release installation failed")
                sys.exit(1)
        else:
            logger.info("Deploy Vault in APP PLATFORM")
            logger.info("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i ansible/production.yml ansible/rancher-2-rke-vault.yml")
            logger.info(vault_cmd.format(KUBE_RKE,"/app/ansible/vault-values.yml",VAULT_NS))
    if platformSpec.get("profiles") is not None and platformSpec.get("profiles").get("mobile-ptf") is not None and platformSpec.get("profiles").get("mobile-ptf").get("enabled"):
        if platformSpec["profiles"]["mobile-ptf"]["version"]:
            package = "/app/artifacts/mobile-ptf-"+platformSpec["profiles"]["mobile-ptf"]["version"]+".tgz"
            values = "/app/artifacts/mobile-ptf-values.yaml"
            if args.offline:
                registry = platformSpec["harbor"]["external_url"]+"/mobile-ptf"
                profile_cmd = profile_cmd.format("/app/files/kube_config_rke_cluster.yml","mptf",package,values,"mptf",registry,registry,registry)
            else:
                profile_cmd = profile_cmd.format("/app/files/kube_config_rke_cluster.yml","mptf",package,values,"mptf")
            if not os.path.exists(values):
                logger.error("Failed to load {}".format(values))
                sys.exit(1)
            if not os.path.exists(package):
                logger.error("Failed to load {}".format(package))
                sys.exit(1)
            logger.info("Deploy Mobile-ptf in APP PLATFORM")
            logger.info(profile_cmd)
            if not args.dryrun:
                returncode = subprocess.call(profile_cmd,shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Mobile-ptf Service was created Successfully")
                else:
                    logger.error("mptf release installation failed")
                    sys.exit(1)
        else:
            logger.error("Version of the profile not specified, please set mptf profile version")
            sys.exit(1)
    if platformSpec.get("profiles") is not None and platformSpec.get("profiles").get("mobile-switch") is not None and platformSpec.get("profiles").get("mobile-switch").get("enabled"):
        if platformSpec["profiles"]["mobile-switch"]["version"]:
            logger.info("Deploy mobile-switch in APP PLATFORM")
            package = "/app/artifacts/mobile-switch-"+platformSpec["profiles"]["mobile-switch"]["version"]+".tgz"
            values = "/app/artifacts/mobile-switch-values.yaml"
            if args.offline:
                registry = platformSpec["harbor"]["external_url"]+"/mobile-switch"
                profile_cmd = profile_cmd.format("/app/files/kube_config_rke_cluster.yml","ms",package,values,"mobile-switch",registry,registry,registry)
            else:
                profile_cmd = profile_cmd.format("/app/files/kube_config_rke_cluster.yml","ms",package,values,"mobile-switch")
            if not os.path.exists(values):
                logger.error("Failed to load {}".format(values))
                sys.exit(1)
            if not os.path.exists(package):
                logger.error("Failed to load {}".format(package))
                sys.exit(1)
            logger.info(profile_cmd)
            if not args.dryrun:
                returncode = subprocess.call(profile_cmd,shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Mobile-switch Service was created Successfully")
                else:
                    logger.error("mobile-switch release installation failed")
                    sys.exit(1)
        else:
            logger.error("Version of the profile not specified, please set mobile-switch profile version")
            sys.exit(1)
    if platformSpec.get("profiles") is not None and platformSpec.get("profiles").get("push-payment") is not None and platformSpec.get("profiles").get("push-payment").get("enabled"):
        if platformSpec["profiles"]["push-payment"]["version"]:
            logger.info("Deploy Push Payment Solution in APP PLATFORM")
            package = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/push-payment-" + platformSpec["profiles"]["push-payment"]["version"]+".tgz"
            values = PLATFORM_DIRECTORY.removesuffix('/') + "/sifbase/push-payment-values.yaml"
            if args.offline:
                registry = platformSpec["harbor"]["external_url"]+"/push-payment"
                profile_cmd = profile_cmd.format(KUBE_RKE,"pp",package,values,"push-payment",registry,registry,registry)
            else:
                profile_cmd = profile_cmd.format(KUBE_RKE,"pp",package,values,"push-payment")
            if not os.path.exists(values):
                logger.error("Failed to load {}".format(values))
                sys.exit(1)
            if not os.path.exists(package):
                logger.error("Failed to load {}".format(package))
                sys.exit(1)
            logger.info(profile_cmd)
            if not args.dryrun:
                returncode = subprocess.call(profile_cmd,shell=True,stderr=subprocess.STDOUT)
                if returncode == 0:
                    logger.info("Push Payment Service was created Successfully")
                else:
                    logger.error("Push Payment release installation failed")
                    sys.exit(1)
        else:
            logger.error("Version of the profile not specified, please set push-payment profile version")
            sys.exit(1)
