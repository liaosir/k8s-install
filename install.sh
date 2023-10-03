#!/bin/bash

# bin
# ├── etcd-v3.4.27
# │   ├── etcd
# │   └── etcdctl
# └── kubernetes-v1.26.9
#     ├── apiextensions-apiserver
#     ├── kubeadm
#     ├── kube-aggregator
#     ├── kube-apiserver
#     ├── kube-controller-manager
#     ├── kubectl
#     ├── kubectl-convert
#     ├── kubelet
#     ├── kube-log-runner
#     ├── kube-proxy
#     ├── kube-scheduler
#     └── mounter

CURRENT_DIR=$(cd `dirname $0`;pwd)
cd $CURRENT_DIR; pwd

TOOLS_DIR=${CURRENT_DIR}/tools
KUBE_DIR=${CURRENT_DIR}/bin/kubernetes-v1.26.9
ETCD_DIR=${CURRENT_DIR}/bin/etcd-v3.4.27
DATA_DIR=${CURRENT_DIR}/data
CONF_DIR=${CURRENT_DIR}/conf

# kubernetes 服务 IP (一般是 SERVICE_CIDR 中第一个IP)
SERVICE_CIDR="10.144.0.0/16"
CLUSTER_KUBERNETES_SVC_IP="10.144.0.1"
NODE_PORT_RANGE="30000-32767"

# echo "按加车开始安装 ... ";read

MASTERS=("10.206.16.14" "10.206.16.16" "10.206.16.15")
INSTALL_DIR="/data/kube"
MASTER_IP="${MASTERS[0]}"

if [ ! -f ~/.ssh/id_ed25519 ]; then
    echo "本机没有密钥，准备生成ed25519密钥"
    ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
else
    echo "密钥已存在，跳过生成密钥"
fi

for i in "${MASTERS[@]}"; do
    ssh-copy-id -i ~/.ssh/id_ed25519.pub root@${i} || { echo "在'${i}'安装免密登录密钥失败，即将退出安装..."; exit 1; }
    ssh root@$i "echo 在'${i}'安装免密登录密钥成功"
done

# echo;echo;echo "检测密钥是否复制成功，回车继续，CTRL+C 结束。 ... ";read

echo "准备安装..."

function do_ms() {
    local i 
    local ec
    for i in "${MASTERS[@]}"; do
        echo "准备在机器 $i 上执行 $1"
        ssh root@$i "$1"
        ec=$?
        if [ $ec -eq 0 ]; then
            echo '执行成功'
        else
            echo "执行失败, 退出码: $ec"
            exit 1;
        fi
    done;
}

function scp_ms() {
    local i 
    local ec
    for i in "${MASTERS[@]}"; do
        echo "准备复制 $1 到机器 $i 的 $2 目录"
        scp $1 root@${i}:/$2
        ec=$?
        if [ $ec -eq 0 ]; then
            echo '执行成功'
        else
            echo "执行失败, 退出码: $ec"
            exit 1;
        fi
    done;
}

echo "== 设置HOSTS"
i=0
len=${#MASTERS[@]}
while [ $i -lt $len ]; do
    hostname="master$i"
    hip4="127.0.0.1 $hostname"
    hip6="::1 $hostname"
    hip="${MASTERS[$i]} $hostname"
    ssh root@${MASTERS[$i]} hostnamectl set-hostname ${hostname}
    ssh root@${MASTERS[$i]} "bash -c \"grep '${hip4}' /etc/hosts || echo '${hip4}' >> /etc/hosts\""
    ssh root@${MASTERS[$i]} "bash -c \"grep '${hip6}' /etc/hosts || echo '${hip6}' >> /etc/hosts\""
    do_ms "bash -c \"grep '${hip}' /etc/hosts || echo '${hip}' >> /etc/hosts\""
    ((i++))
done

echo "== 设置时区"
do_ms "timedatectl set-timezone Asia/Shanghai"

do_ms "bash -c \"killall -9 etcd; killall -9 kube-apiserver || exit 0\""
sleep 1

echo "== 创建目录，复制BIN文件，设置PATH"
do_ms "mkdir -p $INSTALL_DIR"
do_ms "rm -rf $INSTALL_DIR/*"
do_ms "mkdir -p $INSTALL_DIR/{bin,conf,log,data};ls -al $INSTALL_DIR"

scp_ms "${ETCD_DIR}/*" "$INSTALL_DIR/bin"
scp_ms "${KUBE_DIR}/*" "$INSTALL_DIR/bin"

tmp="export PATH=$INSTALL_DIR/bin:\\\$PATH"
do_ms "bash -c \"grep '${tmp}' /etc/profile || echo '${tmp}' >> /etc/profile\""

echo "== 关闭防火墙，设置iptables，关闭交换分区，关闭SELinux"
do_ms "bash -c \"systemctl stop firewalld ; systemctl disable firewalld \""
# -F 清空所有规则，-X清空自定义链，-P设置默认策略FORWARD链
do_ms "bash -c \"iptables -F && iptables -X && iptables -F -t nat && iptables -X -t nat && iptables -P FORWARD ACCEPT \""
tmp='/ swap / s/^\(.*\)$/#\1/g'
do_ms "bash -c \"swapoff -a; sed -i '$tmp' /etc/fstab \""
tmp='s/^SELINUX=.*/SELINUX=disabled/'
do_ms "bash -c \"setenforce 0; sed -i '$tmp' /etc/selinux/config \""

echo "== 复制内核参数"
scp_ms conf/kubernetes.conf /etc/sysctl.d/
do_ms "sysctl -p /etc/sysctl.d/kubernetes.conf"

# 这里只是生成CA证书
echo "== 生成CA证书"

mkdir -p ${DATA_DIR}
cd ${DATA_DIR}
rm -rf ${DATA_DIR}/*

${TOOLS_DIR}/cfssl gencert -initca "${CONF_DIR}/ca-csr.json" | ${TOOLS_DIR}/cfssljson -bare ca ; ls ca*
scp_ms "${DATA_DIR}/ca*.pem" "${INSTALL_DIR}/conf/"
# 生成admin证书
echo "== 生成admin证书"

cd ${DATA_DIR}
${TOOLS_DIR}/cfssl gencert -ca="${DATA_DIR}/ca.pem" \
  -ca-key="${DATA_DIR}/ca-key.pem" \
  -config="${CONF_DIR}/ca-config.json" \
  -profile=kubernetes "${CONF_DIR}/admin-csr.json" | ${TOOLS_DIR}/cfssljson -bare admin ; ls admin*

# 生成kubeconfig
echo "== 生成kubeconfig"

cd ${DATA_DIR}

# 设置集群参数
${KUBE_DIR}/kubectl config set-cluster kubernetes \
  --certificate-authority=${DATA_DIR}/ca.pem \
  --embed-certs=true \
  --server=https://master0:6443 \
  --kubeconfig=${DATA_DIR}/kubectl.kubeconfig

# 设置客户端认证参数
${KUBE_DIR}/kubectl config set-credentials admin \
  --client-certificate=${DATA_DIR}/admin.pem \
  --client-key=${DATA_DIR}/admin-key.pem \
  --embed-certs=true \
  --kubeconfig=${DATA_DIR}/kubectl.kubeconfig

# 设置上下文参数
${KUBE_DIR}/kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin \
  --kubeconfig=${DATA_DIR}/kubectl.kubeconfig

# 设置默认上下文
${KUBE_DIR}/kubectl config use-context kubernetes \
  --kubeconfig=${DATA_DIR}/kubectl.kubeconfig

do_ms "mkdir -p /root/.kube"
scp_ms "${DATA_DIR}/kubectl.kubeconfig" "/root/.kube/config"

echo "== 生成ETCD证书"
cd ${DATA_DIR}
${TOOLS_DIR}/cfssl gencert -ca=${DATA_DIR}/ca.pem \
    -ca-key=${DATA_DIR}/ca-key.pem \
    -config=${CONF_DIR}/ca-config.json \
    -profile=kubernetes ${CONF_DIR}/etcd-csr.json | ${TOOLS_DIR}/cfssljson -bare etcd

scp_ms "${DATA_DIR}/etcd*.pem" "${INSTALL_DIR}/conf"

# 生成etcd启动脚本

echo "== 生成ETCD启动脚本"
i=0
len=${#MASTERS[@]}
ETCD_NODES=()
ETCD_ENDPOINTS=()

while [ $i -lt $len ]; do
    ETCD_NODES+=("etcd${i}=https://master${i}:2380")
    ETCD_ENDPOINTS+=("https://master${i}:2379")
    ((i++))
done

default_ifs="$IFS"
IFS=","
ETCD_NODES="${ETCD_NODES[*]}"
ETCD_ENDPOINTS="${ETCD_ENDPOINTS[*]}"
IFS="$default_ifs" 

i=0
len=${#MASTERS[@]}
while [ $i -lt $len ]; do
    cat > ${DATA_DIR}/etcd_start${i}.sh <<EOF
#!/bin/bash
CURRENT_DIR=\$(cd \`dirname \$0\`;pwd)
cd \$CURRENT_DIR; pwd
echo "start etcd${i} ..."
mkdir -p ${INSTALL_DIR}/data/{etcd-data,etcd-wal}
nohup ./etcd --data-dir=${INSTALL_DIR}/data/etcd-data \\
  --wal-dir=${INSTALL_DIR}/data/etcd-wal \\
  --name=etcd${i} \\
  --cert-file=${INSTALL_DIR}/conf/etcd.pem \\
  --key-file=${INSTALL_DIR}/conf/etcd-key.pem \\
  --trusted-ca-file=${INSTALL_DIR}/conf/ca.pem \\
  --peer-cert-file=${INSTALL_DIR}/conf/etcd.pem \\
  --peer-key-file=${INSTALL_DIR}/conf/etcd-key.pem \\
  --peer-trusted-ca-file=${INSTALL_DIR}/conf/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --listen-peer-urls=https://${MASTERS[$i]}:2380 \\
  --initial-advertise-peer-urls=https://master${i}:2380 \\
  --listen-client-urls=https://${MASTERS[$i]}:2379,https://127.0.0.1:2379 \\
  --advertise-client-urls=https://master${i}:2379 \\
  --initial-cluster-token=etcd-cluster-kubernetes \\
  --initial-cluster=${ETCD_NODES} \\
  --initial-cluster-state=new \\
  --auto-compaction-mode=periodic \\
  --auto-compaction-retention=1 \\
  --max-request-bytes=33554432 \\
  --quota-backend-bytes=6442450944 \\
  --heartbeat-interval=250 \\
  --election-timeout=2000 >${INSTALL_DIR}/log/etcd.log 2>&1 &

sleep 1
ps -ef|grep etcd |grep -v grep
EOF

    cat > ${DATA_DIR}/etcd_health${i}.sh <<EOF
#!/bin/bash
CURRENT_DIR=\$(cd \`dirname \$0\`;pwd)
cd \$CURRENT_DIR; pwd
echo "health check etcd${i} ..."
./etcdctl -w table --endpoints=https://master${i}:2379 --cacert=../conf/ca.pem --cert=../conf/etcd.pem --key=../conf/etcd-key.pem endpoint health
./etcdctl -w table --endpoints=https://master${i}:2379 --cacert=../conf/ca.pem --cert=../conf/etcd.pem --key=../conf/etcd-key.pem endpoint status
EOF

    chmod +x ${DATA_DIR}/etcd_*${i}.sh
    scp ${DATA_DIR}/etcd_start${i}.sh root@${MASTERS[$i]}:${INSTALL_DIR}/bin/etcd_start.sh
    scp ${DATA_DIR}/etcd_health${i}.sh root@${MASTERS[$i]}:${INSTALL_DIR}/bin/etcd_health.sh

    ((i++))

done

# 生成k8s master证书
echo "== 生成k8s master证书"
sed s/CLUSTER_KUBERNETES_SVC_IP/${CLUSTER_KUBERNETES_SVC_IP}/g ${CONF_DIR}/kubernetes-csr.json > ${DATA_DIR}/kubernetes-csr.json
cd ${DATA_DIR}
${TOOLS_DIR}/cfssl gencert -ca="${DATA_DIR}/ca.pem" \
  -ca-key="${DATA_DIR}/ca-key.pem" \
  -config="${CONF_DIR}/ca-config.json" \
  -profile=kubernetes "${DATA_DIR}/kubernetes-csr.json" | ${TOOLS_DIR}/cfssljson -bare kubernetes ; ls kubernetes*.pem

scp_ms "${DATA_DIR}/kubernetes*.pem" "${INSTALL_DIR}/conf"


# 生成k8s加密文件 https://kubernetes.io/zh-cn/docs/tasks/administer-cluster/encrypt-data/
echo "== 生成k8s加密文件"
ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)
sed s/ENCRYPTION_KEY/${ENCRYPTION_KEY}/g ${CONF_DIR}/encryption-config.yaml > ${DATA_DIR}/encryption-config.yaml
scp_ms "${DATA_DIR}/encryption-config.yaml" "${INSTALL_DIR}/conf"

# 生成审计配置文件 https://kubernetes.io/zh-cn/docs/tasks/debug/debug-cluster/audit/
echo "== 生成审计配置文件"
scp_ms "${CONF_DIR}/audit-policy.yaml" "${INSTALL_DIR}/conf"

# 生成访问 metrics-server 或 kube-prometheus 使用的证书

echo "== 生成访问 metrics-server 或 kube-prometheus 使用的证书"

${TOOLS_DIR}/cfssl gencert -ca="${DATA_DIR}/ca.pem" \
  -ca-key="${DATA_DIR}/ca-key.pem" \
  -config="${CONF_DIR}/ca-config.json" \
  -profile=kubernetes "${CONF_DIR}/proxy-client-csr.json" | ${TOOLS_DIR}/cfssljson -bare proxy-client ; ls proxy-client*

scp_ms "${DATA_DIR}/proxy-client*.pem" "${INSTALL_DIR}/conf/"

# apiserver的选项说明 https://v1-26.docs.kubernetes.io/zh-cn/docs/reference/command-line-tools-reference/kube-apiserver/
i=0
len=${#MASTERS[@]}
while [ $i -lt $len ]; do
    cat > ${DATA_DIR}/apiserver_start${i}.sh <<EOF
#!/bin/bash
CURRENT_DIR=\$(cd \`dirname \$0\`;pwd)
cd \$CURRENT_DIR; pwd
echo "start apiserver${i} ..."
mkdir -p ${INSTALL_DIR}/log/kube-apiserver

# --advertise-address向别的组件公示自己的地址
# --default-not-ready-toleration-seconds，--default-unreachable-toleration-seconds表示NODE异常时，最少要等多少秒才重新调度POD。默认是300，即5分种，主要为了防止脑裂
# --max-mutating-requests-inflight，--max-requests-inflight 变更类请求和总请求限制
# --delete-collection-workers 用多少个线程来删除集合类资源比如POD。默认1
# --encryption-provider-config 加密API对像的配置文件
# --audit-log-maxage 审计日志保留多少天
# --audit-log-maxbackup 审计日志保留多少个
# --audit-log-maxsize 日志总大小M
# --profiling 通过 Web 接口 host:port/debug/pprof/ 启用性能分析。
# --anonymous-auth 启用到 API 服务器的安全端口的匿名请求。 未被其他认证方法拒绝的请求被当做匿名请求。 匿名请求的用户名为 system:anonymous， 用户组名为 system:unauthenticated。
# --enable-bootstrap-token-auth 这个还没明白

nohup ./kube-apiserver \\
--advertise-address=${MASTERS[$i]} \\
--default-not-ready-toleration-seconds=300 \\
--default-unreachable-toleration-seconds=300 \\
--max-mutating-requests-inflight=2000 \\
--max-requests-inflight=4000 \\
--delete-collection-workers=2 \\
--encryption-provider-config=${INSTALL_DIR}/conf/encryption-config.yaml \\
--etcd-cafile=${INSTALL_DIR}/conf/ca.pem \\
--etcd-certfile=${INSTALL_DIR}/conf/kubernetes.pem \\
--etcd-keyfile=${INSTALL_DIR}/conf/kubernetes-key.pem \\
--etcd-servers=${ETCD_ENDPOINTS} \\
--bind-address=0.0.0.0 \\
--secure-port=6443 \\
--tls-cert-file=${INSTALL_DIR}/conf/kubernetes.pem \\
--tls-private-key-file=${INSTALL_DIR}/conf/kubernetes-key.pem \\
--audit-log-maxage=7 \\
--audit-log-maxbackup=100 \\
--audit-log-maxsize=100 \\
--audit-log-truncate-enabled \\
--audit-log-path=${INSTALL_DIR}/log/kube-apiserver/audit.log \\
--audit-policy-file=${INSTALL_DIR}/conf/audit-policy.yaml \\
--profiling \\
--anonymous-auth=false \\
--client-ca-file=/etc/kubernetes/cert/ca.pem \\
--enable-bootstrap-token-auth \\
--requestheader-allowed-names="aggregator" \\
--requestheader-client-ca-file=/etc/kubernetes/cert/ca.pem \\
--requestheader-extra-headers-prefix="X-Remote-Extra-" \\
--requestheader-group-headers=X-Remote-Group \\
--requestheader-username-headers=X-Remote-User \\
--service-account-key-file=${INSTALL_DIR}/conf/ca.pem \\
--authorization-mode=Node,RBAC \\
--runtime-config=api/all=true \\
--enable-admission-plugins=NodeRestriction \\
--allow-privileged=true \\
--event-ttl=168h \\
--kubelet-certificate-authority=${INSTALL_DIR}/conf/ca.pem \\
--kubelet-client-certificate=${INSTALL_DIR}/conf/kubernetes.pem \\
--kubelet-client-key=${INSTALL_DIR}/conf/kubernetes-key.pem \\
--kubelet-timeout=10s \\
--proxy-client-cert-file=${INSTALL_DIR}/conf/proxy-client.pem \\
--proxy-client-key-file=${INSTALL_DIR}/conf/proxy-client-key.pem \\
--service-cluster-ip-range=${SERVICE_CIDR} \\
--service-node-port-range=30000-32767 \\
--service-account-issuer=https://example.com \\
--service-account-key-file=${INSTALL_DIR}/conf/proxy-client.pem \\
--service-account-signing-key-file=${INSTALL_DIR}/conf/proxy-client-key.pem \\
--v=3 \\
>${INSTALL_DIR}/log/kube-apiserver.log 2>&1 &
EOF
    chmod +x ${DATA_DIR}/apiserver_start${i}.sh
    scp ${DATA_DIR}/apiserver_start${i}.sh root@${MASTERS[$i]}:${INSTALL_DIR}/bin/apiserver_start.sh
    
    ((i++))
done

do_ms "bash -c \"cd ${INSTALL_DIR}/bin;./etcd_start.sh;\""
do_ms "bash -c \"cd ${INSTALL_DIR}/bin;./etcd_health.sh;\""