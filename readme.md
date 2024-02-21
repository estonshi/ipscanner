## **Ip-Scanner Agent**

###### Ip扫描发现服务，支持SNMP、SSH、ARP扫描

---

### **Compile**
libpcap & libpcap-devel packages are needed to be installed
```shell
# e.g for Centos7, 
rpm -ivh libpcap-1.5.3-13.el7_9.x86_64.rpm libpcap-devel-1.5.3-13.el7_9.x86_64.rpm
```
compile binary:
```bash
# golang version 1.20
go mod tidy
CGO_ENABLED=1 go build
```

### **Build images**
```bash
# on Linux
docker build -f Dockerfile -t agent/ipscan-agent:1.0.0 .
```

### **Run**
:bulb: `ARP scanner only works in local network, or same subnet`

1. run binary
```bash
# file 'manuf.txt' should be in the same folder with executable binary
./ipscanner {options}
```
2. run docker image
```bash
# run container (arp scanner doesn't work)
docker run -d --restart=always \
    -p 9921:9921 \
    --name ipscan-agent \
    agent/ipscan-agent:1.0.0 {options}

# run container (activate arp scanner)
docker run -d --restart=always \
    --network host \
    --name ipscan-agent \
    agent/ipscan-agent:1.0.0 {options}
```

3. options:
    - `--version` Print version information
    - `--web.listen-address` Address on which to expose metrics and web interface, default **9921**
    - `--log.level` Only log messages with the given severity or above. Valid levels: [debug, info, warn, error, fatal], default info
    - `--config` Path of config file, default 'config.yml'

### **Config**
`Note` ARP scanner only works in local network, or same subnet

```yaml
jobs:
  # 最大同时运行的任务数
  max_running: 50
  # 单任务并行数（不建议太大）
  parallel: 1
  # 已结束任务结果的缓存时间（分钟）
  result_cache_time: 10

aes:
  # 加密算法，不要更改
  algo: cbc_256
  # aes密钥
  key: r9qIJ7lxhwWofqYvac9XUU6xEGEUamOX
  # aes偏移量
  iv: ac9XUU6xEGEUamOX

server:
  # 是否向后端服务器发送注册请求
  register: true
  # 鉴权请求头
  authorization: Basic cHVibGljOjFnc2J6ODk3NTM0aHo=
  # 后端服务地址
  address: 192.168.163.15:8092
  # 注册名
  reg-name: ipscanner-01
  # 注册请求发送频率，分钟
  reg-freq: 60
```

### **API**
1. submit job
   - `POST /submit?type=&encrypt=`
   - query parameter
    ```yaml
      type: job type, "ssh"/"snmp"/"arp", not empty
      encrypt: whether to encrypt response body, give "encrypt=y" to enable encryption
    ```
   - body (type=ssh)
    ```json5
      // the following json string should be encrypted by AES-256/CBC/Pkcs7 algorithm and encoded in base64
      // the encryption key and iv are configured in 'config.yml'
      {
        "ports": [  // tcp ports, not empty
          22
        ],
        "iprange": [
          "192.168.163.73", // first ip, not empty
          "192.168.166.75"  // last ip, not empty
        ],
        "scrape_info": [  // retrieved info, not empty
          "hostname", // hostname
          "sysDesc", // system description, e.g os version
          "netAddr"  // mac address
        ],
        "auths": [ // ssh auth for example
          {
            "username": "user",    // ssh username, not empty
            "password": "password"  // ssh password, not empty
          }
        ],
        "other": {
          "mode": "valid-only",   // "all": return all valid ip even though failed to connect by ssh/snmp; "valid-only": only return successfully connected ip, default
          "source_encode": "utf-8"  // the encoding of raw ssh/snmp returns, choose from "utf-8"/"gbk"/"gb18030", default "utf-8"
        }
      }
      // after encryption, the real request body should be like:
      // ta3MdlnBYcVGKa6sb1cvmW/16y4t0+AKwl/1aYGJ7gMKG8nrde+f0Z5KktzWgv//IpjnSZlY0N0yNF3GtkBt8lms7AKt5ipgrtCpqlPHx/i0HBUBCqHPAP+4vpQA6zxFggaMttMWoKXEx5YGp2+XRqDbxsPlcUhbFRivC6xCBHQs9t1XcCtD/2cRsOq11REMbyzaglWramDn7URhWySJ8SqIwzMdO862YN17HOYlPWc=
    ```
   - body (type=snmp)
    ```json5
      // the following json string should be encrypted by AES-256/CBC/Pkcs7 algorithm and encoded in base64
      // the encryption key and iv are configured in 'config.yml'
      {
      "ports": [161],      // udp ports
      "iprange": ["192.168.163.14","192.168.163.17"],  // start ip, end ip
      "scrape_info": ["hostname","sysDesc","netAddr"],
      "auths": [
          {
              "version": "v3",               // v2c v3
              "security_level": "authPriv",  // authPriv noAuthNoPriv authNoPriv
              "username": "user",
              "password": "password",
              "auth_protocol": "MD5",        // MD5 SHA SHA256 SHA512
              "priv_protocol": "DES",        // DES AES AES256 AES256C
              "priv_password": "priv-password"
          }
        ]
      }
      // after encryption, the real request body should be like:
      // wxP6IKLHyMAWsHAs4qAGCeypsPmF4hWW2ydymTO+68GH80ybRtVmBnvkRrZxH30wOXkv+rf4S5pDuJnxZv03081BVPaGNiuUnz5Ans4IemyImGG9fJJa6e3U4+oTRSJPcUZOUVb3piI/OCUA3aft8UH9IcRHrWCoTV5LQt9V+QIEL7swFGjyynj0ltQ5z7ZEloy7KoWf+LGjXfRHaIuGZJZONC7fdp0ETdnZkUZq5d5tLu8goNWMjnxePvBGEk+YlubKdOwHLbiD7KZaFXlYkn/Fi5moG5z7pzu5XxnDGyBuIagAIx4hiwnl59okxGdz3I6nE+hvl6YkYcssGLFe5AIKv7O5eA6vVdtYzVV0kKwzSFLgDLxetwJFkb++87Sb
    ```
   - body (type=arp)
    ```json5
      // the following json string should be encrypted by AES-256/CBC/Pkcs7 algorithm and encoded in base64
      // the encryption key and iv are configured in 'config.yml'
      {
        "iprange": [
          "192.168.163.1",
          "192.168.163.20"
        ]
      }
      // after encryption, the real request body should be like:
      // ZiNnx5SgbkTE8B1X6fqPukTtEcRXU+3V/bU+W35HGCEQcvFvAXaJDgqJHRhIqz0avGzje6TxgFD0IuBna1OgCkdgnaBBOUZktPL//DWkm17Vok0Sq/XteUq2ySQ6sJh8
    ```
   - response body
    ```text
      // return job id, which should be like
      0dea82a9-a009-439d-a916-1c74b0f8ac6b
    ```

2. retrieve job results
   - `GET /result?id=&encrypt=`
   - query parameter
    ```yaml
      id: job id
      encrypt: whether to encrypt response body, give "encrypt=y" to enable encryption
    ```
   - response body
    ```json5
      {
      "id": "70db89e9-bcb0-4862-ac3b-1d313bb493ce",
      "type": "SSH",
      "startsAt": 1703238941,
      "endsAt": 1703238943,
      "status": "Finished",   // Created：job is still running; Finished：job is finished；Failed：job failed
      "message": "",          // error message when job is failed
      "result": [
          {
              "ip": "192.168.163.14",
              "hostname": "regester-1",
              "sysDesc": "Linux 6.6.7-1.el7.elrepo.x86_64",
              "netAddr": [
                  "fa:16:3e:1f:40:aa"
              ],
              "manufacture": []
          },
          {
              "ip": "192.168.163.15",
              "hostname": "application-1",
              "sysDesc": "Linux 3.10.0-1160.el7.x86_64",
              "netAddr": [
                  "fa:16:3e:85:4e:ce"
              ],
              "manufacture": []
          }
      ]
      }
    ```
3. prometheus metrics
   - `GET /metrics`

### **Metrics**
- URI: /metrics
- Metrics:
  - ipscan_task_executed_total : The total number of tasks this agent has ever started
  - ipscan_task_running : The number of tasks that are currently running on this agent
  - ipscan_task_finished_total : The total number of tasks that successfully finished on this agent
  - ipscan_task_failed_total : The total number of tasks that ran into error on this agent
