--------------------------
**Disclaimer:** non-English version of the guide contain unofficial translations contributed by our users. They are not binding in any way, are not guaranteed to be accurate, and have no legal effect. The official text is the [English](https://docs.docker.com/engine/security/https/) version of the Docker website.

--------------------------

# Docker Daemon Soketin Korunması

Varsayılan olarak, Docker, ağa bağlı olmayan bir Unix soketi üzerinden çalışır. İsteğe bağlı olarak bir HTTP soketi kullanarak iletişim kurabilir.

Docker'a ağ üzerinden güvenli bir şekilde erişmesini istiyorsanız, tlsverify ayarını belirterek ve Docker'ın tlscacert ayarını güvenilir bir CA sertifikasına işaretleyerek TLS'yi etkinleştirebilirsiniz.

Daemon modunda (daemon mode), yalnızca o CA tarafından imzalanmış bir sertifika tarafından kimliği doğrulanan istemcilerin bağlantılarına izin verilir. İstemci modunda (client mode), yalnızca o CA tarafından imzalanmış bir sertifikaya sahip sunuculara bağlanır.

> Uyarı: TLS'yi kullanma ve CA yönetimi gelişmiş konulardır. Lütfen gerçek yayın ortamında kullanmadan önce OpenSSL, x509 ve TLS ile ilgili bilgi edinin.

> Uyarı: Bu TLS komutları yalnızca Linux'ta çalışan bir sertifika kümesi oluşturacaktır. MacOS, Docker'ın gerektirdiği sertifikalarla uyuşmayan bir OpenSSL sürümüyle birlikte gelir.

## OpenSSL ile CA Sunucu ve İstemci Anahtarı Oluşturma

> Not: Aşağıdaki örnekte `$HOST`'un tüm değerlerini Docker daemon ana bilgisayarının DNS adıyla değiştirin.

İlk olarak **Docker Daemon Sunucusu üzerinde** CA Özel ve Genel Anahtarlarını oluşturun.

```shell
$ openssl genrsa -aes256 -out ca-key.pem 4096
Generating RSA private key, 4096 bit long modulus
............................................................................................................................................................................................++
........++
e is 65537 (0x10001)
Enter pass phrase for ca-key.pem:
Verifying - Enter pass phrase for ca-key.pem:
```

```shell
$ openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem
Enter pass phrase for ca-key.pem:
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:Queensland
Locality Name (eg, city) []:Brisbane
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Docker Inc
Organizational Unit Name (eg, section) []:Sales
Common Name (e.g. server FQDN or YOUR name) []:$HOST
Email Address []:Sven@home.org.au
```

Artık bir CA sahibiyiz. Bir sunucu anahtarı ve sertifika imzamala isteği (CSR) oluşturabiliriz. 

`Common Name` (diğer bir deyişle, sucunu FQDN'si veya SİZİN adınız) Docker'a bağlanmak için kullanacağınız ana makine adıyla eşleştiğinden emin olun.

> Not: Aşağıdaki örnekte `$HOST`'un tüm değerlerini Docker daemon ana bilgisayarının DNS adıyla değiştirin.


```shell
$ openssl genrsa -out server-key.pem 4096
Generating RSA private key, 4096 bit long modulus
.....................................................................++
.................................................................................................++
e is 65537 (0x10001)
$ openssl req -subj "/CN=$HOST" -sha256 -new -key server-key.pem -out server.csr
```

Ardından, CA'yla ortak anahtarı imzalayacağız:

TLS bağlantıları DNS adının yanı sıra IP adresi üzerinden de yapılabildiğinden, sertifika oluşturulurken belirtilmeleri gerekir. Örneğin, 10.10.10.20 ve 127.0.0.1 kullanan bağlantılara izin vermek için:

```shell
$ echo subjectAltName = DNS:$HOST,IP:10.10.10.20,IP:127.0.0.1 > extfile.cnf

$ openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -extfile extfile.cnf
Signature ok
subject=/CN=your.host.com
Getting CA Private Key
Enter pass phrase for ca-key.pem:
```

İstemci kimlik doğrulaması için bir istemci anahtarı ve sertifika imzalama isteği oluşturun:

```shell
$ openssl genrsa -out key.pem 4096
Generating RSA private key, 4096 bit long modulus
.........................................................++
................++
e is 65537 (0x10001)
$ openssl req -subj '/CN=client' -new -key key.pem -out client.csr
```

Anahtarın istemci kimlik doğrulaması için uygun olmasını sağlamak için bir uzantı yapılandırma dosyası oluşturun:

```shell
$ echo extendedKeyUsage = clientAuth > extfile.cnf
```

Şimdi ortak anahtarı imzalayın:

```shell
$ openssl x509 -req -days 365 -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem \
  -CAcreateserial -out cert.pem -extfile extfile.cnf
Signature ok
subject=/CN=client
Getting CA Private Key
Enter pass phrase for ca-key.pem:
```

cert.pem ve server-cert.pem üretildikten sonra iki sertifika imzalama isteğini güvenle kaldırabilirsiniz:

```shell
$ rm -v client.csr server.csr
```
Sertifikalar herkes tarafından okunabilir olabilir. Yanlışlıkla hasar görmesini önlemek için yazma erişimini kaldırmak isteyebilirsiniz:

```shell
$ chmod -v 0444 ca.pem server-cert.pem cert.pem
```

Artık Docker daemon programını, yalnızca CA'dan güvenilir bir sertifika sağlayan istemcilerden gelen bağlantıları kabul edebileceksiniz:

```shell
$ dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376
```

Docker'a bağlanıp sertifikasını doğrulamak için şimdi istemci anahtarlarınızı, sertifikalarınızı ve güvenilen CA'yı sağlamalısınız:

> Not: Aşağıdaki örnekte `$HOST`'un tüm değerlerini Docker daemon ana bilgisayarının DNS adıyla değiştirin.

```shell
$ docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H=$HOST:2376 version
```

> Not: Docker TLS üzerinden 2376 TCP port'unda çalışır.

> Uyarı: Yukarıdaki örnekte gösterildiği gibi, sertifika kimlik doğrulamasını kullandığınızda docker istemcisini sudo veya docker grubuyla çalıştırmanız gerekmez. Bu, anahtarları olan herkesin, Docker daemon programına ev sahipliği yapan ana makineye root erişimi sağlayarak herhangi bir talimat verebileceği anlamına gelir. Bu anahtarları bir root parolası gibi koruyun!

## Varsayılan Güvenlik

Docker istemci bağlantılarınızı varsayılan olarak güvence altına almak istiyorsanız, dosyaları home dizininizdeki .docker dizinine taşıyabilirsiniz. Sonrasında DOCKER_HOST ve DOCKER_TLS_VERIFY değişkenlerini de ayarlayın.  (veya değişmek yerine her çağrıda --tlsverify ve -H = tcp: //$HOST:2376 parametlerini kullanın).

```shell
$ mkdir -pv ~/.docker
$ cp -v {ca,cert,key}.pem ~/.docker
$ export DOCKER_HOST=tcp://$HOST:2376 DOCKER_TLS_VERIFY=1
```

Docker şimdi varsayılan olarak güvenli bir şekilde bağlanacaktır:

```shell
docker ps
```

## Diğer modlar

Tam iki yönlü kimlik doğrulama yapmak istemiyorsanız, paremetrelerde uyguladığınız değişik kombinasyonlarla Docker'ı diğer modlarda çalıştırabilirsiniz.

### Daemon modu

* `tlsverify`, `tlscacert`, `tlscert`, `tlskey` : Authenticate clients
* `tls`, `tlscert`, `tlskey`: Do not authenticate clients

### İstemci Modu

* tls: Authenticate server based on public/default CA pool
* tlsverify, tlscacert: Authenticate server based on given CA
* tls, tlscert, tlskey: Authenticate with client certificate, do not authenticate server based on given CA
* tlsverify, tlscacert, tlscert, tlskey: Authenticate with client certificate and authenticate server based on given CA

If found, the client will send its client certificate, so you just need to drop your keys into ~/.docker/{ca,cert,key}.pem. Alternatively, if you want to store your keys in another location, you can specify that location using the environment variable DOCKER_CERT_PATH.

```shell
$ export DOCKER_CERT_PATH=~/.docker/zone1/
$ docker --tlsverify ps
```

### Curl ile Güvenli Port Üzerinden Bağlantı

```shell
$ curl https://$HOST:2376/images/json \
  --cert ~/.docker/cert.pem \
  --key ~/.docker/key.pem \
  --cacert ~/.docker/ca.pem
```

## İlgili İçerikler

* Using certificates for repository client verification  - https://docs.docker.com/engine/security/certificates/
* Use trusted images - https://docs.docker.com/engine/security/trust/
