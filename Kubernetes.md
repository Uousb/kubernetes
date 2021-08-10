# Docker && Kubernetes

### 容器基础

容器可以隔离UTS+NET+MOUNT+PID+USER

### Dockerfile

Docker 镜像制作的方法：

	- docker commit
	- Dockerfile

Dockerfile规则

- 格式

  - ‘#’  为注释
- 指令（大写）内容（小写）
- Docker 按顺序执行Dockerfile里面的指令
- 每一个Dockerfile的第一个非注释行指令，必须是”FROM“指令，用于为镜像文件构造过程中指定基础镜像，后续的指令运行于此基准镜像所提供的的运行环境中
  - 实践中，基准镜像可以是任何可用的镜像文件，默认情况下，docker build 会在本地查找指定的镜像文件，若不存在则会从docker registry（远端）上拉取。

常用Dockerfile指令

- USER/WORKDIR指令
- ADD/COPY指令
- EXPOSE指令
- RUN/ENV指令
- CMD/ENTRYPOINT指令

| USER   | 容器中PID=1的用户                                            | WOEKDIR    | 为后续的 `RUN`、`CMD`、`ENTRYPOINT` 指令配置工作目录         |
| ------ | :----------------------------------------------------------- | :--------- | ------------------------------------------------------------ |
| ADD    | 该命令将复制指定的 `<src>` 到容器中的 `<dest>`。 其中 `<src>` 可以是Dockerfile所在目录的一个相对路径；也可以是一个 URL；还可以是一个 tar 文件（自动解压为目录）。 | COPY       | 复制本地主机的 `<src>`（为 Dockerfile 所在目录的相对路径）到容器中的 `<dest>`，当使用本地目录为源目录时，推荐使用 `COPY` |
| EXPOSE | 容器暴露的端口号                                             |            |                                                              |
| RUN    | 每条 `RUN` 指令将在当前镜像基础上执行指定命令，并提交为新的镜像 | ENV        | 定义一个环境变量                                             |
| CMD    | 容器启动时运行的指令                                         | ENTRYPOINT |                                                              |



### docker 网络

##### Bridge(默认)

此模式会为每一个容器分配、设置IP等，并将容器连接到一个docker0虚拟网桥，通过docker0网桥以及Iptables nat表配置与宿主机通信。

##### None

该模式关闭了容器的网络功能。

##### Host

容器将不会虚拟出自己的网卡，配置自己的IP等，而是使用宿主机的IP和端口。





## K8S

### 1. 基本基础概念

- Pod/Pod控制器
- Name/Namespace
- Label/Label选择器
- Service/Ingress



- **Pod**
  - Pod是K8S里能够被运行的最小的逻辑单元（原子单元）
  - 1个Pod里面可以运行多个容器，他们共享UTS+NET+IPC名称空间
  - 可以吧Pod理解成豌豆荚，而同一个Pod内的每个容器是一颗颗豌豆
  - 一个Pod里可以运行多个容器，又叫：边车（SideCar）模式
- **Pod控制器**
  - Pod控制器是Pod启动的一种模板，用来保证在K8S里启动的Pod应四种按照人们的预期运行（副本数、生命周期、健康状态检查等）
  - K8S内提供了众多的Pod控制器，常用有以下
    - **Deployment**
    - **DaemonSet**
    - ReplicaSet
    - StatefulSet
    - Job
    - Cronjob
- **Name**
  - 由于K8S内部使用“资源”来定义每一种逻辑概念（功能）故每种”资源“，都应该有自己的”名称“
  - “资源”有api版本（apiversion）类别（kind）、元数据（metadata）、定义清单（spec）、状态（status）等配置信息
  - “名称”通常定义在“资源”的“元数据”信息里
- **Namespace**
  - 随着项目增多、人员增加、集群规模的扩大，需要一种能够隔离K8S内各种“资源”的方法，这就是命名空间
  - 命名空间可以理解为K8S内部的虚拟集群组
  - 不同命名空间内的“资源”，名称可以相同。相同命名空间内的同种“资源”，“名称不能相同”。
  - 合理的使用K8S的命名空间，使得集群管理员能够更好的对交付到K8S里的服务进行分类管理和浏览。
  - K8S里默认存在的命名空间有：default、kube-system、kube-public
  - 查询K8S里特定”资源“要带上相应的命名空间
- **Label标签**
  - 标签是K8S特色的管理方式，便于管理资源对象
  - 一个标签可以对应多个资源，一个资源也可以有多个标签，他们是多对多的关系。
  - 一个资源拥有多个标签，可以实现不同维度的管理。
  - 标签的组成：key=value
  - 与标签类似的，还有一种”注解（annotations）“ 
- **Label标签选择器**
  - 给资源打上标签后，可以使用标签选择器过滤指定的标签
  - 标签选择器目前有两个：基于等值关系（等于、不等于）和基于集合关系（属于、不属于、存在）
  - 许多资源支持内嵌标签选择器字段
    - matchLabels
    - matchExpressions
- **Service**
  - K8S世界里，虽然每个Pod都会被分配一个单独的IP地址，但这个IP地址会随着Pod的销毁而消失
  - Service（服务）就是用来解决这个问题的核心概念
  - 一个Service可以看做一组提供相同服务的Pod的对外访问接口
  - Service作用于哪些Pod是通过标签选择器来定义的
- **Ingress**
  - Ingress是K8S集群里工作在OSI网络参考模型下，第七层的应用，对外暴露的接口
  - Service只能进行L4流量调度，表现形式是ip+port
  - Ingress则可以调度不同业务域、不同URL访问路径的业务流量



### 2.核心组件

- 配置存储中心 etcd服务
- 主控（master）节点
  - Kube-apiserver服务
    - 提供了集群管理的REST API接口（包括鉴权、数据校验及集群状态变更）
    - 负责其他模块之间的数据交互，承担通信枢纽功能
    - 是资源配额控制的入口
    - 提供完备的集群安全机制
  - Kube-controller-manager服务
    - 有一系列控制器组成，通过apiserver监控整个集群的状态，并确保集群处于预期的工作状态
    - Node 、Deployment 、Service 、Volume 、Endpoint、Garbage、Namespace、Job、Resource quta。。。。。
  - kube-scheduler服务
    - 主要功能是接收调度pod到合适的运算节点上
    - 预算策略（predict）
    - 优选策略（priorities）
- 运算（node）节点
  - kube-kubelet服务
    - 主要功能是定时从某个地方获取节点上pod的期望状态（运行什么容器、运行的副本数量、网络或者存储如何配置等），并调用对应的容器平台接口达到这个状态
    - 定时汇报当前节点的状态给apiserver，以供调度的时候使用
    - 镜像和容器的清理工作，保证节点上镜像不会占满磁盘空间，退出的容器不会占用太多资源
  - kube-proxy服务
    - 是K8S在每个节点上运行网络代理，service资源的载体
    - 建立了pod网络和集群网络的关系（cluster_ip---> pod_ip）
    - 常用三种流量调度模式
      - Userspace（淘汰）
      - Iptables（即将淘汰）
      - Ipvs（推荐）
    - 负责建立和删除包括更新调度规则、同种apiserver自己的更新，或者从apiserver那里获取其他kube-proxy调度规则变化来更新自己的

### 3.CLI客户端

- kubectl

### 4.核心附件

- CNI网络插件 flannel/calico
- 服务发现用插件 coredns
- 服务暴露插件 traefik
- GUI管理插件 Dashboard





## 安装

### 准备工作

+ 安装DNS
+ 准备签发证书环境
+ docker 环境
+ harbor

---



#### 1.安装bind(DNS)

```shell
##主配置文件
vim /etc/named.conf
listen-on port 53 { 10.7.6.37; };
allow-query     { any; };
forwarders      { 114.114.114.114; };
dnssec-enable no;
dnssec-validation no;
```

```shell
##区域配置文件
vim /etc/named.rfc1912.zones
 
zone "host.com" IN {
        type master;
        file "host.com.zone";
        allow-update { 10.7.6.37; };
};

zone "s8k.com" IN {
        type master;
        file "s8k.com.zone";
        allow-update { 10.7.6.37; };
};
```

```shell
##区域解析文件配置
vim /var/named/host.com.zone
$ORIGIN host.com.
$TTL 600        ; 10 minutes
@       IN SOA  dns.host.com. dnsadmin.host.com. (
                2021082601      ; serial
                10800           ; refresh (3 hours)
                900             ; retry (15 minutes)
                604800          ; expire (1 week)
                86400           ; minimum (1 day)
                )
        NS      dns.host.com.
$TTL 60 ; 1 minute
dns     A 10.7.6.34
k8-34        A       10.7.6.34
k8-35        A       10.7.6.35
k8-36        A       10.7.6.36
k8-37        A       10.7.6.37
k8-38        A       10.7.6.38


##
vim s8k.com.zone
$ORIGIN s8k.com.
$TTL 600        ; 10 minutes
@       IN SOA  dns.s8k.com. dnsadmin.s8k.com. (
                2021082601      ; serial
                10800           ; refresh (3 hours)
                900             ; retry (15 minutes)
                604800          ; expire (1 week)
                86400           ; minimum (1 day)
                )
                NS      dns.s8k.com.
$TTL 60 ; 1 minute
dns     A       10.7.6.34
```

 主机配置dns

```shell
vim /etc/resolv.conf
search host.com
nameserver 10.7.6.34
```

验证解析

```shell
nslookup k8-34.host.com
```



#### 2.cfssl环境

```shell
##下载cfssl
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
chmod +x cfssl_linux-amd64 cfssljson_linux-amd64 cfssl-certinfo_linux-amd64
mv cfssl_linux-amd64 /usr/local/bin/cfssl
mv cfssljson_linux-amd64 /usr/local/bin/cfssljson
mv cfssl-certinfo_linux-amd64 /usr/bin/cfssl-certinfo
```

- 生成CA模板

```json
#打印csr模板文件从而进行修改
cfssl print-defaults csr > ca-csr.json
vim ca-csr.json
{
    "CN": "AuthCentEdu",
    "hosts": [
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST":"beijing",
            "L": "beijing",
            "O": "od",
            "OU": "ops"
        }
    ],
    "ca": {
            "expiry": "175200h" 
        }
}

## CN: Common Name，浏览器使用该字段验证网站是否合法，一般写的是域名。非常重要。浏览器使用该字段验证网站是否合法
## key：生成证书的算法
## hosts：表示哪些主机名(域名)或者IP可以使用此csr申请的证书，为空或者""表示所有的都可以使用(本例中没有hosts字段)
## names：一些其它的属性
## C: Country， 国家
## ST: State，州或者是省份
## L: Locality Name，地区，城市
## O: Organization Name，组织名称，公司名称(在k8s中常用于指定Group，进行RBAC绑定)
## OU: Organization Unit Name，组织单位名称，公司部门
```

- 生成CA

```shell
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
# ca-key.pem（私钥）
# ca.pem（证书）
# ca.csr（证书签名请求）
```



#### 3.docker环境安装

#### 4.安装harbor



### 部署Master节点服务

#### 部署etcd服务

| Ip        | 主机名         | 角色        |
| --------- | -------------- | ----------- |
| 10.7.6.35 | K8-35.host.com | etcd lead   |
| 10.7.6.36 | K8-36.host.com | etcd follow |
| 10.7.6.37 | K8-37.host.com | etcd follow |

- 创建证书

```json
cat << EOF >> /opt/certs/ca-config.json
{
	"signing": {
		"default": {
			"expiry": "175200h"
		},
		"profiles": {
			"server": {
				"expiry": "175200h",
				"usages": [
					"signing",
					"key encipherment",
					"server auth"
				]
			},
			"client": {
				"expiry": "175200h",
				"usages": [
					"signing",
					"key encipherment",
					"client auth"
				]
			},
			"peer": {
				"expiry": "175200h",
				"usages": [
					"signing",
					"key encipherment",
					"client auth"
				]
			}
		}
	}
}
EOF
## etcd
vim /opt/certs/etcd-peer-csr.json
cat << EOF >> /opt/certs/etcd-peer-csr.json
{
	"CN": "k8s-etcd",
	"hosts": [
	    "10.7.6.34",
	    "10.7.6.35",
	    "10.7.6.36",
	    "10.7.6.37",
	    "10.7.6.38"
	],
	"key": {
	    "algo": "rsa",
	    "size": 2048
	},
	"names": [
	    {
	        "C": "CN",
	        "ST": "beijing",
	        "L": "beijing",
	        "O": "od",
	        "OU": "ops"
	    }
	]
}
EOF
```

```shell
#生成etcd公钥于私钥
cfssl gencert -ca=ca.pem -ca.key=ca-key.pem -config=config.json -profile=peer etcd-peer-csr.json |cfssljson -bare etcd-peer
```

- etcd服务

```shell
###创建etcd程序目录
mkdir -p /opt/etcd/{bin,ssl,cfg}

###新建etcd配置文件,调整name于ip
cat << EOF >> /opt/etcd/cfg/etcd.cfg
#[Member]
ETCD_NAME="etcd-35"
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://10.7.6.35:2380"
ETCD_LISTEN_CLIENT_URLS="https://10.7.6.35:2379"

#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://10.7.6.35:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://10.7.6.35:2379"
ETCD_INITIAL_CLUSTER="etcd-35=https://10.7.6.35:2380,etcd-36=https://10.7.6.36:2380,etcd-37=https://10.7.6.37:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"
EOF

###拷贝证书
scp k8-37:/opt/certs/*.pem /opt/etcd/ssl/
```



- systemd托管etcd服务

> 待调整为使用配置文件

```shell
cat << EOF >> /usr/lib/systemd/system/etcd.service
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
#EnvironmentFile=/opt/etcd/cfg/etcd.cfg
ExecStart=/opt/etcd/bin/etcd \
--name=etcd-35 \
--data-dir=/data/etcd/etcd-server \
--listen-peer-urls=https://10.7.6.35:2380 \
--listen-client-urls=https://10.7.6.35:2379,http://127.0.0.1:2379 \
--quota-backend-bytes=8000000000 \
--initial-advertise-peer-urls=https://10.7.6.35:2380 \
--advertise-client-urls=https://10.7.6.35:2379,http://127.0.0.1:2379 \
--initial-cluster "etcd-35=https://10.7.6.35:2380,etcd-36=https://10.7.6.36:2380,etcd-37=https://10.7.6.37:2380" \
--ca-file=/opt/etcd/ssl/ca.pem \
--cert-file=/opt/etcd/ssl/etcd-peer.pem \
--key-file=/opt/etcd/ssl/etcd-peer-key.pem \
--client-cert-auth  \
--trusted-ca-file=/opt/etcd/ssl/ca.pem \
--peer-ca-file=/opt/etcd/ssl/ca.pem \
--peer-cert-file=/opt/etcd/ssl/etcd-peer.pem \
--peer-key-file=/opt/etcd/ssl/etcd-peer-key.pem \
--peer-client-cert-auth \
--peer-trusted-ca-file=/opt/etcd/ssl/ca.pem \
--initial-cluster-state=new\
--log-output stdout
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target

EOF
```



- 创建并启动其他节点etcd服务

```shell
##在其他节点创建程序目录
mkdir -p /opt/etcd/{bin,ssl,cfg}
tar zxvf etcd-v3.3.20-linux-amd64.tar.gz -C /opt/etcd/bin/
##复制etcd.service
scp k8-35:/usr/lib/systemd/system/etcd.service /usr/lib/systemd/system/etcd.service
##复制秘钥证书
scp k8-35:/opt/etcd/ssl/* /opt/etcd/ssl/
```



- 启动etcd服务

```shell
#所有节点启动etcd服务,并设置开机自启动
systemctl enable --now etcd.service
##集群至少启动两台才能显示启动成功
```



- 验证etcd集群状态

```shell
##查看端口状态
ss -tnlp|grep etcd
LISTEN     0      1024   10.7.6.35:2379                     *:*                   users:(("etcd",pid=42471,fd=8))
LISTEN     0      1024   127.0.0.1:2379                     *:*                   users:(("etcd",pid=42471,fd=7))
LISTEN     0      1024   10.7.6.35:2380                     *:*                   users:(("etcd",pid=42471,fd=6))

##查看集群状态,集群leader
./etcdctl member list
2b29c38ebc6a1ffb: name=etcd-36 peerURLs=https://10.7.6.36:2380 clientURLs=http://127.0.0.1:2379,https://10.7.6.36:2379 isLeader=true
a8b1da11a7f640dd: name=etcd-35 peerURLs=https://10.7.6.35:2380 clientURLs=http://127.0.0.1:2379,https://10.7.6.35:2379 isLeader=false
adbd015cebef0397: name=etcd-37 peerURLs=https://10.7.6.37:2380 clientURLs=http://127.0.0.1:2379,https://10.7.6.37:2379 isLeader=false


./etcdctl cluster-health
member 2b29c38ebc6a1ffb is healthy: got healthy result from http://127.0.0.1:2379
member a8b1da11a7f640dd is healthy: got healthy result from http://127.0.0.1:2379
member adbd015cebef0397 is healthy: got healthy result from http://127.0.0.1:2379
cluster is healthy
```



#### 部署apiserver

| IP        | 主机  | 角色      |
| --------- | ----- | --------- |
| 10.7.6.34 | K8-34 | apiserver |
| 10.7.6.38 | K8-38 | apiserver |

签发client证书

> apiserver 和 etcd 通信

```shell
##在k8-37
vim /opt/certs/client-csr.json
{
    "CN": "k8s-node",
    "hosts": [
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "beijing",
            "L": "beijing",
            "O": "od",
            "OU": "ops"
        }
    ]
}

##生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client client-csr.json |cfssljson -bare client


[root@k8-37 certs]# ll client*
-rw-r--r-- 1 root root  993 8月   8 20:11 client.csr
-rw-r--r-- 1 root root  280 8月   8 20:11 client-csr.json
-rw------- 1 root root 1679 8月   8 20:11 client-key.pem
-rw-r--r-- 1 root root 1363 8月   8 20:11 client.pem
```



签发server证书

```shell
#在k8-37
vim /opt/certs/apiserver-csr.json
##需要预留一个vip(虚拟ip)
{
    "CN": "k8s-apiserver",
    "hosts": [
        "127.0.0.1",
        "192.168.0.1",
        "kubernetes.default",
        "kubernetes.default.svc",
        "kubernetes.default.svc.cluster",
        "kubernetes.default.svc.cluster.local",
        "10.7.6.34",
        "10.7.6.35",
        "10.7.6.36",
        "10.7.6.37"，
        "10.7.6.38"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "beijing",
            "L": "beijing",
            "O": "od",
            "OU": "ops"
        }
    ]
}

##生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server apiserver-csr.json |cfssljson -bare apiserver

[root@k8-37 certs]# ll apiserver*
-rw-r--r-- 1 root root 1265 8月   8 20:19 apiserver.csr
-rw-r--r-- 1 root root  608 8月   8 20:19 apiserver-csr.json
-rw------- 1 root root 1679 8月   8 20:19 apiserver-key.pem
-rw-r--r-- 1 root root 1614 8月   8 20:19 apiserver.pem
```



将证书从k8-37拷贝至k8-34

```shell
scp k8-37:/opt/certs/ca.pem /opt/kubernets/certs
scp k8-37:/opt/certs/ca-key.pem /opt/kubernets/certs
scp k8-37:/opt/certs/client.pem /opt/kubernets/certs
scp k8-37:/opt/certs/client-key.pem /opt/kubernets/certs
scp k8-37:/opt/certs/apiserver-key.pem /opt/kubernets/certs
scp k8-37:/opt/certs/apiserver.pem /opt/kubernets/certs
```



创建apiserver的审计audit配置文件

```shell
mkdir /opt/kubernets/conf
vim /opt/kubernets/conf/audit.yaml
apiVersion: audit.k8s.io/v1beta1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  # Log pod changes at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      # Resource "pods" doesn't match requests to any subresource of pods,
      # which is consistent with the RBAC policy.
      resources: ["pods"]
  # Log "pods/log", "pods/status" at Metadata level
  - level: Metadata
    resources:
    - group: ""
      resources: ["pods/log", "pods/status"]

  # Don't log requests to a configmap called "controller-leader"
  - level: None
    resources:
    - group: ""
      resources: ["configmaps"]
      resourceNames: ["controller-leader"]

  # Don't log watch requests by the "system:kube-proxy" on endpoints or services
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
    - group: "" # core API group
      resources: ["endpoints", "services"]

  # Don't log authenticated requests to certain non-resource URL paths.
  - level: None
    userGroups: ["system:authenticated"]
    nonResourceURLs:
    - "/api*" # Wildcard matching.
    - "/version"

  # Log the request body of configmap changes in kube-system.
  - level: Request
    resources:
    - group: "" # core API group
      resources: ["configmaps"]
    # This rule only applies to resources in the "kube-system" namespace.
    # The empty string "" can be used to select non-namespaced resources.
    namespaces: ["kube-system"]

  # Log configmap and secret changes in all other namespaces at the Metadata level.
  - level: Metadata
    resources:
    - group: "" # core API group
      resources: ["secrets", "configmaps"]

  # Log all other resources in core and extensions at the Request level.
  - level: Request
    resources:
    - group: "" # core API group
    - group: "extensions" # Version of group should NOT be included.

  # A catch-all rule to log all other requests at the Metadata level.
  - level: Metadata
    # Long-running requests like watches that fall under this rule will not
    # generate an audit event in RequestReceived.
    omitStages:
      - "RequestReceived"
```



创建apiserver的启动脚本

```shell
mkdir -p /data/logs/kubernetes/kube-apiserver

vim /opt/kubernetes/server/bin/kube-apiserver-startup.sh

#!/bin/bash

WORK_DIR=$(dirname $(readlink -f $0))
[ $? -eq 0 ] && cd $WORK_DIR || exit

/opt/kubernetes/server/bin/kube-apiserver \
    --apiserver-count 2 \
    --audit-log-path /data/logs/kubernetes/kube-apiserver/audit-log \
    --audit-policy-file ../../conf/audit.yaml \
    --authorization-mode RBAC \
    --client-ca-file ./certs/ca.pem \
    --requestheader-client-ca-file ./certs/ca.pem \
    --enable-admission-plugins NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook,ResourceQuota \
    --etcd-cafile ./certs/ca.pem \
    --etcd-certfile ./certs/client.pem \
    --etcd-keyfile ./certs/client-key.pem \
    --etcd-servers https://10.7.6.35:2379,https://10.7.6.36:2379,https://10.7.6.37:2379 \
    --service-account-key-file ./certs/ca-key.pem \
    --service-cluster-ip-range 192.168.0.0/16 \
    --service-node-port-range 3000-29999 \
    --target-ram-mb=1024 \
    --kubelet-client-certificate ./certs/client.pem \
    --kubelet-client-key ./certs/client-key.pem \
    --log-dir  /data/logs/kubernetes/kube-apiserver \
    --tls-cert-file ./certs/apiserver.pem \
    --tls-private-key-file ./certs/apiserver-key.pem \
    --v 2
```



创建apiserver的启动配置文件

```shell
vim /etc/supervidor.d/kube-apiserver.ini
[program:kube-apiserver-7-21]
command=/opt/kubernetes/server/bin/kube-apiserver-startup.sh
numprocs=1
directory=/opt/kubernetes/server/bin
autostart=true
autorestart=true
startsecs=30
startretries=3
exitcodes=0,2
stopsignal=QUIT
stopwaitsecs=10
user=root
redirect_stderr=true
stdout_logfile=/data/logs/kubernetes/kube-apiserver/apiserver.stdout.log
stdout_logfile_maxbytes=64MB
stdout_logfile_backups=5
stdout_capture_maxbytes=1MB
stdout_events_enabled=false

```

