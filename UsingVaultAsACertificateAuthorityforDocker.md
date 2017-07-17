Merhaba;

Son günlerde, PKI - Public Key Infrastructure -  (Açık Anahtar Altyapısı) ve yönetimi konusunda birçok bilgi edindim. OpenSSL ve Vault tarafında araştırma ve denemeler yapma fırsatı buldum. Sonuç olarak Vault'un PKI yönetimini başka bir seviyeye taşığını gözlemledim. Açıkçası otomasyon tutkum ve Vault'un güçlü API desteğinin birleşimi beni ektisi altına aldı. 

Kaba bir özetle, Açık anahtar altyapısının merkezinde sertifika yetkilisi (certificate authority - CA) bulunuyor. Sertifika yetkilisi, sertifikaları imzalar ve iletişim kuran taraflar arasında kimlik doğrulaması yaparak, iletilerin güvenle taşınmasını sağlar. OpenSSL komut satırı araçlarını kullanarak kendi sertifika yetkilimi nasıl yapacağımı gösteren birçok örnek uygulama ve doküman buldum ancak ne yazık ki Vault PKI servisini kullanmak istediğimde yeteri kadar kaynak bulamadım.

Örneğin, Docker sunucusuna TCP üzerinden güvenli bir iletişim kurmak için TLS - Transport Layer Security (Taşıma Katmanı Güvenliği) - kriptolama protokolünü kullanıyoruz. TLS olası gizli dinlemeyi ve onaysız değişiklik yapmayı önleyerek, ağ üzerinden istemci-sunucu uygulamalarının güvenle haberleşmesine izin veriyor.

Docker; dokümantasyonlarında, Docker Daemon sokete TLS  kriptolama protokolü üzerinden erişmek istediğimizde, OpenSSL kullanarak sertifka yetkilisini nasıl yöneteceğimizi, X.509 sertifikalarını kullanarak taraflar arasındaki iletişimi asimetrik şifreleme ile nasıl güvence altına alacağımızı detaylarıyla anlatmış. Harika!

Peki aynı operasyonu Vault PKI servisi ile yapsam nasıl olurdu? Vault API'ın yeteneklerini düşününce bence süper olurdu diyerek kolları sıvadım. Farklı örnekleri inceledim, denemeler yaptım ve sonuçta bir yol haritası oluşturmayı başardım.

Bunun için aşağıdaki aşamalardan geçmem gekiyordu. 

* Ön hazılık
* Vault sunucusunun çalıştırılması
* Vault PKI servisi aracılığı ile kök sertfikanın oluşturulması
* Vault PKI servisi aracılığı ile Docker ara sertifika yetkilisinin oluşturulması
* Docker/Docker Swarm yöneticileri (sunucu) ve Docker istemcileri (api/cli) için TLS anahtar ve sertifikalarının oluşturulması
* Docker TLS'i Ektinleştirme
* Sertifika doğrulama ve istemcilerden bağlantı kabul etme
* Test

## Ön Hazırlık

Öncelikle gerek kurulum, gerek kurulum sonrası ihtiyacım olacak bazı programları kurmakla başlıyorum.

```
apt-get update  -y
apt-get install -y curl httpie unzip jq
```

Gerekli dizinleri oluşturuyorum

```
mkdir -p /certs/root && mkdir -p /certs/docker/{manager,client}
```

## Vault Sunucusunun Çalıştırılması

### Kurulum

```shell
wget https://releases.hashicorp.com/vault/0.7.3/vault_0.7.3_linux_amd64.zip
unzip vault_0.7.3_linux_amd64.zip && rm -f vault_0.7.3_linux_amd64.zip
mv /vault /usr/local/bin/vault
```

### Ayarlar

```shell
cat <<EOF >/home/ubuntu/vault.hcl
disable_mlock  = true

listener "tcp" {
	address = "0.0.0.0:8200"
	tls_disable = 1
}

backend "file" {
	path = "/home/ubuntu/vault/secrets"
}
EOF
```

### Sunucuyu Ayaklandırma

```shell
export VAULT_ADDR='http://127.0.0.1:8200'
vault server -config="/home/ubuntu/vault.hcl" &
sleep 6
vault init > /home/ubuntu/vault-keys.txt
export VAULT_TOKEN=$(grep 'Initial Root Token:' /home/ubuntu/vault-keys.txt | awk '{print substr($NF, 1, length($NF))}')
```

### Mühür Açma

```shell
key1=$(grep 'Unseal Key 1:' /home/ubuntu/vault-keys.txt | awk '{print substr($NF, 1, length($NF))}')
key2=$(grep 'Unseal Key 2:' /home/ubuntu/vault-keys.txt | awk '{print substr($NF, 1, length($NF))}')
key3=$(grep 'Unseal Key 3:' /home/ubuntu/vault-keys.txt | awk '{print substr($NF, 1, length($NF))}')

set -x
vault unseal $key1
vault unseal $key2
vault unseal $key3
set +x
```

### Yetkilendirme

```shell
vault auth ${VAULT_TOKEN}
```

## Kök Sertifika Yetkilisi

Vault kullanıma hazır olduğuna göre, Vault PKI servisini kullanmak için `monapi` adında **pki tipinde** bir yol tanımladım. Burada saklanacak gizli veriler için maksimum TTL'i yirmi yıl (175320 saat) olarak belirledim ve kök sertifikaya da yirmi yıl gibi uzun bir son kullanma tarihi verdim.

### PKI Servisinin Tanıtılması

```
vault mount -path=monapi -description="Monapi Root CA" -max-lease-ttl=175320h pki
```

### Anahtar Çiftinin Oluşturulması

Oluşturacağımız ilk şifreleme çifti, kök çiftidir. Bu, kök anahtardan (key.pem) ve kök sertifikadan (ca.pem) oluşur. Bu çift, CA'nızın kimliğini oluşturur.

> Not: `internal` tipinde bir istekte bulunduğumda private_key'in çıktısı dışarıya verilmeyecektir. Anahtara dışarıdan ulaşmanın bir yolu yoktur. Vault bizim için anahtarı saklayacak ve gerektiğinde kullanacaktır. Eğer bir şekilde `private_key`'i ayrıca depolamak isterseniz `exported` tipinde bir istekte bulunun. örn :  `monapi/root/generate/exported`

```
vault write -format=json monapi/root/generate/internal common_name="Monapi Root CA" ttl=175320h key_bits=4096 exclude_cn_from_sans=true > /certs/root/root.json

cat /certs/root/root.json | jq -r .data.certificate > /certs/root/ca.pem
cat /certs/root/root.json | jq -r .data.private_key > /certs/root/key.pem && rm -f /certs/root/root.json
```

> **Not:** Sadece çıktıları hızlıca gözlemlemek için sertifika ve anahtarı diske kaydettim. Vault zaten sizin için sertifikaları güvenle saklayacak, istediğinizde, yetkiniz dahilinde size verecektir. `internal` tipinde bir istekte bulunduğum için anahtar (private_key) Vault güvencesi altında.

Vault'un sertifika yetkilisine erişmek için kullanacağım CA adresini tanımladım:

```
vault write monapi/config/urls issuing_certificates=${VAULT_ADDR}/v1/monapi/ca
```

Genellikle kök CA, sunucu veya istemci sertifikalarını doğrudan imzalamaz. Kök CA yalnızca kök CA tarafından kendi adına sertifikalar imzalamaya güvendiği bir veya daha fazla ara (intermediate) CA oluşturmada kullanılır. Tam da bu amaca yönelik olarak `docker` adında bir **ara CA** oluşturabilirim. Bu ara sertifika yetkilisi sadece Docker hizmetleri için sertifika üretecektir. Daha açık bir ifade ile ad uzayı (namespace) görevi görerek daha fazla uygulama için yönetimi kolaylaştıracaktır.

## Docker Ara Sertifika Yetkilisi

### PKI Servisinin Tanıtılması

```
vault mount -path=docker -description="Monapi Docker Intermediate CA" -max-lease-ttl=26280h pki
```

### Anahtar Çiftinin Oluşturulması

İlk olarak ara sertifika imzalama isteği (CSR) ve ara anahtarı oluşturdum.

```
vault write -format=json docker/intermediate/generate/internal common_name="Monapi Docker Intermediate CA" ttl=26280h ip_sans="$(hostname --i),127.0.0.1" key_bits=4096 exclude_cn_from_sans=true > /certs/docker/docker.json
cat /certs/docker/docker.json | jq -r .data.csr            > /certs/docker/docker.csr
cat /certs/docker/docker.json | jq -r .data.private_key    > /certs/docker/ca-key.pem && rm -f /certs/docker/docker.json
```
> **Note:** `internal` tipinde bir istekte bulunduğum için anahtar (private_key) Vault güvencesi altında. Benim erişmem mümkün değil.

#### Anahtar Çiftinin İmzalanması

Bir ara sertifika oluşturmak için, kök sertifika yetkilisine ara sertifika imzalama isteği (CSR) gönderdim.

Örnek olması açısından bu işlemi Vault API desteği ile http üzerinden gerçekleştirdim. 

```shell
http --ignore-stdin POST "${VAULT_ADDR}/v1/monapi/root/sign-intermediate" X-Vault-Token:$VAULT_TOKEN common_name='Monapi Docker Intermediate CA' ttl="26280h" csr=@/certs/docker/docker.csr > /certs/docker/signed_docker.json
cat /certs/docker/signed_docker.json | jq -r .data.certificate > /certs/docker/ca.pem && rm -f /certs/docker/signed_docker.json
```

İmzalanan ara sertifikayı Vault'a teslim ettim.

```
vault write docker/intermediate/set-signed certificate=@/certs/docker/ca.pem
```

Son olarak Vault'un Docker ara sertifika yetkilisine erişmek için kullanacağım CA ve CRL (sertifika iptal listesi) adreslerini tanımladım:

```
vault write docker/config/urls issuing_certificates="http://$(hostname --i):8200/v1/docker/ca" crl_distribution_points="http://$(hostname --i):8200/v1/docker/crl"
```

## Sunucu ve İstemci Sertifikaları

Şimdi Ara Sertifika yöneticim ile sertifikalar imzalayacağım. Bu imzalı sertifikaları, Docker sunucusuna olan bağlantıları güvenli kılmak veya Docker sunucusuna bağlanan istemcileri doğrulamak gibi çeşitli durumlarda kullanacağım.

Buradaki işlemlerin tamamını HTTP üzerinden, Vault API'ın yeteneklerini kullanarak yapacağım. Otomasyon için API'ın katkısı daha da net ortaya çıkmış olacak. Bu işlemleri Vault sunusunun dışında başka bir makinada yapabilirsiniz (Bir Docker Sunucusu ile sunucuya ve istemci olarak da bilgisayarınız örnek verilebilir.) Aşağıdaki yönlendirmelerin çalışabilmesi için, bu makinalar üzerinde VAULT_ADDR (Vault sunucunun adresi) ve VAULT_TOKEN ortam değişkenlerinin tanımlı olmasına dikkat edin. Sonuçta Docker sunucunuzda veya istemcinizde Vault kurulu olmak zorunda değil. Büyük ihtimalle de kurulu olmayacaktır. Bu makinalar kendi işlerini gören ağ üzerine dağılmış öğelerdir.

### Sunucu Sertifikaları

Farklı bir makinada çalıştığımda dizin yapısının bu makinalarda da aynı olduğunundan emin olmalıyım.

```
mkdir -p /certs/docker/manager
```

#### Rol Oluştur
Docker sunucusu için bir `manager1` adında bir role oluşturuyorum. `manager1` rolünün `client_flag=false` parametresi ile istemci kullanımı için uygun olmadığını belirtiyorum. 

```
http --ignore-stdin POST ${VAULT_ADDR}/v1/docker/roles/manager1 X-Vault-Token:${VAULT_TOKEN} max_ttl=8760h allow_any_name=true allow_ip_sans=true client_flag=false
```

Evet bir `http` isteği ile Docker ara sertifika yetkilim üzerinde role tanımlaması yaptım. Bu işlemi doğrulamak için Vault API'ya başka bir istekte daha bulunuyorum. 

```
http --ignore-stdin GET http://${VAULT_SERVER_IP}:8200/v1/docker/roles/manager1 X-Vault-Token:${VAULT_TOKEN} | jq .
```

Çıktı buna benzer olmalıdır.

```json
{
  "request_id": "52f16cf7-0337-b251-1568-727f516b0091",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "allow_any_name": true,
    "allow_bare_domains": false,
    "allow_base_domain": false,
    "allow_glob_domains": false,
    "allow_ip_sans": true,
    "allow_localhost": true,
    "allow_subdomains": false,
    "allow_token_displayname": false,
    "allowed_domains": "",
    "client_flag": false,
    "code_signing_flag": false,
    "email_protection_flag": false,
    "enforce_hostnames": true,
    "generate_lease": false,
    "key_bits": 2048,
    "key_type": "rsa",
    "key_usage": "DigitalSignature,KeyAgreement,KeyEncipherment",
    "max_ttl": "8760h0m0s",
    "no_store": false,
    "organization": "",
    "ou": "",
    "server_flag": true,
    "ttl": "768h0m0s",
    "use_csr_common_name": true,
    "use_csr_sans": true
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

#### Sertifika Oluştur

```
http --ignore-stdin POST ${VAULT_ADDR}/v1/docker/issue/manager1 X-Vault-Token:${VAULT_TOKEN} common_name="manager1" ip_sans="$(hostname --i),127.0.0.1" ttl=720h > /certs/docker/manager/issue.json

cat /certs/docker/manager/issue.json | jq -r .data.ca_chain[]  > /certs/docker/manager/chain.pem
cat /certs/docker/manager/issue.json | jq -r .data.certificate > /certs/docker/manager/cert.pem
cat /certs/docker/manager/issue.json | jq -r .data.issuing_ca  > /certs/docker/manager/issuing.pem
cat /certs/docker/manager/issue.json | jq -r .data.private_key > /certs/docker/manager/key.pem && rm -f /docker/manager/issue.json
```

Ağ üzerinde başka bir makinada olabilceğim için, Docker ara sertifika yetkilisinin sertifikasını sunucuya indiriyorum.

```
curl ${VAULT_ADDR}/v1/docker/ca/pem > /certs/docker/manager/ca.pem
```

### İstemci Sertifikaları

Farklı bir makinada çalıştığımda dizin yapısının bu makinalarda da aynı olduğunundan emin olmalıyım.

```
mkdir -p /certs/docker/client
```

#### Rol Oluştur

Docker sunucusu için bir `client` adında bir role oluşturuyorum. `client` rolünün `server_flag=false` parametresi ile sunucu kullanımı için uygun olmadığını belirtiyorum. 

```
http --ignore-stdin POST ${VAULT_ADDR}/v1/docker/roles/client X-Vault-Token:${VAULT_TOKEN} max_ttl=8760h allow_any_name=true allow_ip_sans=true server_flag=false
```

#### Sertifika Oluştur

```  
http --ignore-stdin POST ${VAULT_ADDR}/v1/docker/issue/client X-Vault-Token:${VAULT_TOKEN} common_name="client" ttl=720h > /certs/docker/client/issue.json

cat /certs/docker/client/issue.json | jq -r .data.ca_chain[]  > /certs/docker/client/chain.pem
cat /certs/docker/client/issue.json | jq -r .data.certificate > /certs/docker/client/cert.pem
cat /certs/docker/client/issue.json | jq -r .data.issuing_ca  > /certs/docker/client/issuing.pem
cat /certs/docker/client/issue.json | jq -r .data.private_key > /certs/docker/client/key.pem && rm -f /docker/client/issue.json
```

Ağ üzerinde başka bir makinada olabileceğim, Docker ara sertifika yetkilisinin sertifikasını istemciye indiriyorum.

```
curl ${VAULT_ADDR}/v1/docker/ca/pem > /certs/docker/client/ca.pem
```

> **Not:** Bu, anahtarları olan herkesin, Docker daemon programına ev sahipliği yapan ana makineye root erişimi sağlayarak herhangi bir talimat verebileceği anlamına gelir. Bu anahtarları bir root parolası gibi korumak gerekir!

> **Not:** Sadece çıktıları hızlıca gözlemlemek için sertifika ve anahtarı diske kaydettim. Vault zaten sizin için sertifikaları güvenle saklayacak, istediğinizde, yetkiniz dahilinde size verecektir.

## TLS Etkinleştirme

Eğer docker kurulu değilse hızlıca kurmak için: 

```
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl software-properties-common nfs-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
apt-key fingerprint 0EBFCD88
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get update -y
apt-get install -y docker-ce
usermod -aG docker ubuntu
```
Kurulumun sorunsuz olduğunu doğruladım.

```
docker version

Client:
 Version:      17.06.0-ce
 API version:  1.30
 Go version:   go1.8.3
 Git commit:   02c1d87
 Built:        Fri Jun 23 21:23:31 2017
 OS/Arch:      linux/amd64

Server:
 Version:      17.06.0-ce
 API version:  1.30 (minimum version 1.12)
 Go version:   go1.8.3
 Git commit:   02c1d87
 Built:        Fri Jun 23 21:19:04 2017
 OS/Arch:      linux/amd64
 Experimental: false
```
 
Docker hizmetini durdurup, TLS'i etkinleştirdim.

```
systemctl stop docker
```

```
dockerd --tlsverify --tlscacert=/certs/docker/manager/ca.pem --tlscert=/certs/docker/manager/cert.pem --tlskey=/certs/docker/manager/key.pem -H=0.0.0.0:2376 &
```

Şimdi Docker istemcisi ile Docker sunucusu hakkında bilgi almak istiyorum ve gerekli bağlantı parametlerini ekliyorum. 

```
docker version

Client:
 Version:      17.06.0-ce
 API version:  1.30
 Go version:   go1.8.3
 Git commit:   02c1d87
 Built:        Fri Jun 23 21:23:31 2017
 OS/Arch:      linux/amd64
**Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?**
```

Yeni yapılandırma tcp üzerinden ve `tlsverify` olduğu için Unix soket üzerinden bağlantıya izin vermediği uyarısı aldım. 

İstemci için ürettiğim sertifika ve anahtar çiftini ve yetkili sertifikasını `/root/.docker` klasörüne kopyalalıyorum. Bu klasör Docker'ın ayarlarında varsayılan olarak tanımlıdır.

```
mkdir -p /root/.docker
cp /certs/docker/client/{ca,cert,key}.pem ~/.docker
```

Docker istemcisi üzerinden tls aktif edilmiş bir istekte bulunuyorum.

```
docker --tlsverify --tlscacert=/root/.docker/ca.pem --tlscert=/root/.docker/cert.pem --tlskey=/root/.docker/key.pem -H=$(hostname --i):2376 version

Client:
 Version:      17.06.0-ce
 API version:  1.30
 Go version:   go1.8.3
 Git commit:   02c1d87
 Built:        Fri Jun 23 21:23:31 2017
 OS/Arch:      linux/amd64

Server:
 Version:      17.06.0-ce
 API version:  1.30 (minimum version 1.12)
 Go version:   go1.8.3
 Git commit:   02c1d87
 Built:        Fri Jun 23 21:19:04 2017
 OS/Arch:      linux/amd64
 Experimental: false
```

Güzel! İstemci sunucuya başarı ile bağlandı ve sunucu bilgilerini döndü. Her seferinde uzun uzadıya parametre girmemek için Docker istemcisinin ortam değişkenlerini güncelliyorum. 
 
```
export DOCKER_HOST=tcp://$(hostname --i):2376 DOCKER_TLS_VERIFY=1
```

### Son Bir Test

```
docker version
Client:
 Version:      17.06.0-ce
 API version:  1.30
 Go version:   go1.8.3
 Git commit:   02c1d87
 Built:        Fri Jun 23 21:23:31 2017
 OS/Arch:      linux/amd64

Server:
 Version:      17.06.0-ce
 API version:  1.30 (minimum version 1.12)
 Go version:   go1.8.3
 Git commit:   02c1d87
 Built:        Fri Jun 23 21:19:04 2017
 OS/Arch:      linux/amd64
 Experimental: false
```

Harika!

## Sonuç

Vault ile bu yol haritasını baz alarak Docker sunucuları ve istemcilerim için TLS'i aktif hale getirebildim. İşin aslı geldiğim bu nokta daha yolun başı ve bir çok eksik içeriyor. 

Öncelikle Vault;
* istemcileri ile güvenli bir iletişim kurmuyor,
* yüksek erişilebilirlik standartlarını karşılamıyor ve 
* yeterli güvenlik rollerine sahip değil. 

Bu eksikliklerin tamamlanması bu aşama için bile çok önemli. Ayrıca PKI yönetiminden söz ediyorsam, sertifikları güncelleme ve iptal etme operasyonlarını da tam anlamıyla yerine getirebilmeliyim.

Günün sonunda sertifika yönetimini gözlemleyip, doğrulayabildiğim basit bir arayüze ihtiyaç duyabilirim. Şimdilik Ludwig Mies van der Rohe'e atıf yapıp, "Less is more" diyorum.

Sevgiler 
