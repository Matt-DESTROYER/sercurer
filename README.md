[![Version badge](https://img.shields.io/npm/v/sercurer.svg?style=flat)](https://www.npmjs.com/package/sercurer)
[![Install size](https://packagephobia.com/badge?p=sercurer)](https://www.npmjs.com/package/sercurer)
[![Install size](https://img.shields.io/bundlephobia/minzip/sercurer?style=flat)](https://www.npmjs.com/package/sercurer)
[![Install size](https://img.shields.io/npm/dm/sercurer.svg?style=flat)](https://www.npmjs.com/package/sercurer)

# Sercurer
Sercurer is a quick and easy way to make your servers more secure. Secure your server's headers and easily add ratelimiting to your server.

---

## Using Sercurer
```js
// require Sercurer and store it in a variable
const sercurer = require("sercurer");
```

Add security headers to your server:
```js
app.use(sercurer.headers());
```

Add ratelimiting to your server:
```js
// limit each IP address to 10 requests every second (1000 milliseconds)
app.use(sercurer.ratelimit(/* requests */ 10, /* milliseconds */ 1000));
```
> Note: Ratelimiting feature may temporarily be partially broken.