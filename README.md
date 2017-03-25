# api documentation for  [helmet (v3.5.0)](https://helmetjs.github.io/)  [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-helmet.svg)](https://travis-ci.org/npmdoc/node-npmdoc-helmet)
#### help secure Express/Connect apps with various HTTP headers

[![NPM](https://nodei.co/npm/helmet.png?downloads=true)](https://www.npmjs.com/package/helmet)

[![apidoc](https://npmdoc.github.io/node-npmdoc-helmet/build/screen-capture.buildNpmdoc.browser._2Fhome_2Ftravis_2Fbuild_2Fnpmdoc_2Fnode-npmdoc-helmet_2Ftmp_2Fbuild_2Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-helmet/build..beta..travis-ci.org/apidoc.html)

![package-listing](https://npmdoc.github.io/node-npmdoc-helmet/build/screen-capture.npmPackageListing.svg)



# package.json

```json

{
    "author": {
        "name": "Adam Baldwin",
        "email": "baldwin@andyet.net",
        "url": "http://andyet.net/team/baldwin"
    },
    "bugs": {
        "url": "https://github.com/helmetjs/helmet/issues"
    },
    "contributors": [
        {
            "name": "Evan Hahn",
            "email": "me@evanhahn.com",
            "url": "http://evanhahn.com"
        }
    ],
    "dependencies": {
        "connect": "3.6.0",
        "dns-prefetch-control": "0.1.0",
        "dont-sniff-mimetype": "1.0.0",
        "frameguard": "3.0.0",
        "helmet-csp": "2.4.0",
        "hide-powered-by": "1.0.0",
        "hpkp": "2.0.0",
        "hsts": "2.0.0",
        "ienoopen": "1.0.0",
        "nocache": "2.0.0",
        "referrer-policy": "1.1.0",
        "x-xss-protection": "1.0.0"
    },
    "description": "help secure Express/Connect apps with various HTTP headers",
    "devDependencies": {
        "mocha": "^3.2.0",
        "sinon": "^1.17.7",
        "standard": "^9.0.1"
    },
    "directories": {},
    "dist": {
        "shasum": "e1d6de27d2e3317d3182e00d672df3d0e1e12539",
        "tarball": "https://registry.npmjs.org/helmet/-/helmet-3.5.0.tgz"
    },
    "engines": {
        "node": ">= 0.10.0"
    },
    "gitHead": "ebd0d35495470708be42750204060a7f96bbd01d",
    "homepage": "https://helmetjs.github.io/",
    "keywords": [
        "security",
        "headers",
        "express",
        "connect",
        "x-frame-options",
        "x-powered-by",
        "csp",
        "hsts",
        "clickjack"
    ],
    "license": "MIT",
    "main": "index",
    "maintainers": [
        {
            "name": "adam_baldwin",
            "email": "baldwin@andyet.net"
        },
        {
            "name": "evanhahn",
            "email": "me@evanhahn.com"
        }
    ],
    "name": "helmet",
    "optionalDependencies": {},
    "readme": "ERROR: No README data found!",
    "repository": {
        "type": "git",
        "url": "git://github.com/helmetjs/helmet.git"
    },
    "scripts": {
        "pretest": "standard",
        "test": "mocha"
    },
    "standard": {
        "globals": [
            "describe",
            "it",
            "beforeEach",
            "afterEach"
        ]
    },
    "version": "3.5.0"
}
```



# <a name="apidoc.tableOfContents"></a>[table of contents](#apidoc.tableOfContents)

#### [module helmet](#apidoc.module.helmet)
1.  [function <span class="apidocSignatureSpan">helmet.</span>contentSecurityPolicy (options)](#apidoc.element.helmet.contentSecurityPolicy)
1.  [function <span class="apidocSignatureSpan">helmet.</span>dnsPrefetchControl (options)](#apidoc.element.helmet.dnsPrefetchControl)
1.  [function <span class="apidocSignatureSpan">helmet.</span>frameguard (options)](#apidoc.element.helmet.frameguard)
1.  [function <span class="apidocSignatureSpan">helmet.</span>hidePoweredBy (options)](#apidoc.element.helmet.hidePoweredBy)
1.  [function <span class="apidocSignatureSpan">helmet.</span>hpkp (passedOptions)](#apidoc.element.helmet.hpkp)
1.  [function <span class="apidocSignatureSpan">helmet.</span>hsts (options)](#apidoc.element.helmet.hsts)
1.  [function <span class="apidocSignatureSpan">helmet.</span>ieNoOpen ()](#apidoc.element.helmet.ieNoOpen)
1.  [function <span class="apidocSignatureSpan">helmet.</span>noCache ()](#apidoc.element.helmet.noCache)
1.  [function <span class="apidocSignatureSpan">helmet.</span>noSniff ()](#apidoc.element.helmet.noSniff)
1.  [function <span class="apidocSignatureSpan">helmet.</span>referrerPolicy (options)](#apidoc.element.helmet.referrerPolicy)
1.  [function <span class="apidocSignatureSpan">helmet.</span>xssFilter (options)](#apidoc.element.helmet.xssFilter)



# <a name="apidoc.module.helmet"></a>[module helmet](#apidoc.module.helmet)

#### <a name="apidoc.element.helmet.contentSecurityPolicy"></a>[function <span class="apidocSignatureSpan">helmet.</span>contentSecurityPolicy (options)](#apidoc.element.helmet.contentSecurityPolicy)
- description and source-code
```javascript
function csp(options) {
  checkOptions(options)

  var originalDirectives = camelize(options.directives || {})
  var directivesAreDynamic = containsFunction(originalDirectives)
  var shouldBrowserSniff = options.browserSniff !== false
  var reportOnlyIsFunction = isFunction(options.reportOnly)

  if (shouldBrowserSniff) {
    return function csp (req, res, next) {
      var userAgent = req.headers['user-agent']

      var browser
      if (userAgent) {
        browser = platform.parse(userAgent)
      } else {
        browser = {}
      }

      var headerKeys
      if (options.setAllHeaders || !userAgent) {
        headerKeys = config.allHeaders
      } else {
        headerKeys = getHeaderKeysForBrowser(browser, options)
      }

      if (headerKeys.length === 0) {
        next()
        return
      }

      var directives = transformDirectivesForBrowser(browser, originalDirectives)

      if (directivesAreDynamic) {
        directives = parseDynamicDirectives(directives, [req, res])
      }

      var policyString = cspBuilder({ directives: directives })

      headerKeys.forEach(function (headerKey) {
        if ((reportOnlyIsFunction && options.reportOnly(req, res)) ||
            (!reportOnlyIsFunction && options.reportOnly)) {
          headerKey += '-Report-Only'
        }
        res.setHeader(headerKey, policyString)
      })

      next()
    }
  } else {
    var headerKeys
    if (options.setAllHeaders) {
      headerKeys = config.allHeaders
    } else {
      headerKeys = ['Content-Security-Policy']
    }

    return function csp (req, res, next) {
      var directives = parseDynamicDirectives(originalDirectives, [req, res])
      var policyString = cspBuilder({ directives: directives })

      if ((reportOnlyIsFunction && options.reportOnly(req, res)) ||
          (!reportOnlyIsFunction && options.reportOnly)) {
        headerKeys.forEach(function (headerKey) {
          res.setHeader(headerKey + '-Report-Only', policyString)
        })
      } else {
        headerKeys.forEach(function (headerKey) {
          res.setHeader(headerKey, policyString)
        })
      }

      next()
    }
  }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.helmet.dnsPrefetchControl"></a>[function <span class="apidocSignatureSpan">helmet.</span>dnsPrefetchControl (options)](#apidoc.element.helmet.dnsPrefetchControl)
- description and source-code
```javascript
function dnsPrefetchControl(options) {
  if (options && options.allow) {
    return function dnsPrefetchControl (req, res, next) {
      res.setHeader('X-DNS-Prefetch-Control', 'on')
      next()
    }
  } else {
    return function dnsPrefetchControl (req, res, next) {
      res.setHeader('X-DNS-Prefetch-Control', 'off')
      next()
    }
  }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.helmet.frameguard"></a>[function <span class="apidocSignatureSpan">helmet.</span>frameguard (options)](#apidoc.element.helmet.frameguard)
- description and source-code
```javascript
function frameguard(options) {
  options = options || {}

  var domain = options.domain
  var action = options.action

  var directive
  if (action === undefined) {
    directive = 'SAMEORIGIN'
  } else if (isString(action)) {
    directive = action.toUpperCase()
  }

  if (directive === 'ALLOWFROM') {
    directive = 'ALLOW-FROM'
  } else if (directive === 'SAME-ORIGIN') {
    directive = 'SAMEORIGIN'
  }

  if (['DENY', 'ALLOW-FROM', 'SAMEORIGIN'].indexOf(directive) === -1) {
    throw new Error('action must be undefined, "DENY", "ALLOW-FROM", or "SAMEORIGIN".')
  }

  if (directive === 'ALLOW-FROM') {
    if (!isString(domain)) {
      throw new Error('ALLOW-FROM action requires a domain parameter.')
    }
    if (!domain.length) {
      throw new Error('domain parameter must not be empty.')
    }
    directive = 'ALLOW-FROM ' + domain
  }

  return function frameguard (req, res, next) {
    res.setHeader('X-Frame-Options', directive)
    next()
  }
}
```
- example usage
```shell
...

It's best to 'use' Helmet early in your middleware stack so that its headers are sure to be set.

You can also use its pieces individually:

'''js
app.use(helmet.noCache())
app.use(helmet.frameguard())
'''

You can disable a middleware that's normally enabled by default. This will disable 'frameguard' but include the other defaults.

'''js
app.use(helmet({
frameguard: false
...
```

#### <a name="apidoc.element.helmet.hidePoweredBy"></a>[function <span class="apidocSignatureSpan">helmet.</span>hidePoweredBy (options)](#apidoc.element.helmet.hidePoweredBy)
- description and source-code
```javascript
function hidePoweredBy(options) {
  var setTo = (options || {}).setTo

  if (setTo) {
    return function hidePoweredBy (req, res, next) {
      res.setHeader('X-Powered-By', setTo)
      next()
    }
  } else {
    return function hidePoweredBy (req, res, next) {
      res.removeHeader('X-Powered-By')
      next()
    }
  }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.helmet.hpkp"></a>[function <span class="apidocSignatureSpan">helmet.</span>hpkp (passedOptions)](#apidoc.element.helmet.hpkp)
- description and source-code
```javascript
function hpkp(passedOptions) {
  var options = parseOptions(passedOptions)
  var headerKey = getHeaderKey(options)
  var headerValue = getHeaderValue(options)

  return function hpkp (req, res, next) {
    var setHeader = true
    var setIf = options.setIf

    if (setIf) {
      setHeader = setIf(req, res)
    }

    if (setHeader) {
      res.setHeader(headerKey, headerValue)
    }

    next()
  }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.helmet.hsts"></a>[function <span class="apidocSignatureSpan">helmet.</span>hsts (options)](#apidoc.element.helmet.hsts)
- description and source-code
```javascript
function hsts(options) {
  options = options || {}

  var maxAge = options.maxAge != null ? options.maxAge : defaultMaxAge
  var includeSubDomains = (options.includeSubDomains !== false) && (options.includeSubdomains !== false)
  var force = options.force
  var setIf = options.setIf

  if (options.hasOwnProperty('maxage')) {
    throw new Error('maxage is not a supported property. Did you mean to pass "maxAge" instead of "maxage"?')
  }
  if (arguments.length > 1) {
    throw new Error('HSTS passed the wrong number of arguments.')
  }
  if (!util.isNumber(maxAge)) {
    throw new TypeError('HSTS must be passed a numeric maxAge parameter.')
  }
  if (maxAge < 0) {
    throw new RangeError('HSTS maxAge must be nonnegative.')
  }
  if (options.hasOwnProperty('setIf')) {
    if (!util.isFunction(setIf)) {
      throw new TypeError('setIf must be a function.')
    }
    if (options.hasOwnProperty('force')) {
      throw new Error('setIf and force cannot both be specified.')
    }
  }
  if (options.hasOwnProperty('includeSubDomains') && options.hasOwnProperty('includeSubdomains')) {
    throw new Error('includeSubDomains and includeSubdomains cannot both be specified.')
  }

  var header = 'max-age=' + Math.round(maxAge)
  if (includeSubDomains) {
    header += '; includeSubDomains'
  }
  if (options.preload) {
    header += '; preload'
  }

  return function hsts (req, res, next) {
    var setHeader
    if (setIf) {
      setHeader = setIf(req, res)
    } else {
      setHeader = force || req.secure
    }

    if (setHeader) {
      res.setHeader('Strict-Transport-Security', header)
    }

    next()
  }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.helmet.ieNoOpen"></a>[function <span class="apidocSignatureSpan">helmet.</span>ieNoOpen ()](#apidoc.element.helmet.ieNoOpen)
- description and source-code
```javascript
function ienoopen() {
  return function ienoopen (req, res, next) {
    res.setHeader('X-Download-Options', 'noopen')
    next()
  }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.helmet.noCache"></a>[function <span class="apidocSignatureSpan">helmet.</span>noCache ()](#apidoc.element.helmet.noCache)
- description and source-code
```javascript
function nocache() {
  return function nocache (req, res, next) {
    res.setHeader('Surrogate-Control', 'no-store')
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
    res.setHeader('Pragma', 'no-cache')
    res.setHeader('Expires', '0')

    next()
  }
}
```
- example usage
```shell
...
'''

It's best to 'use' Helmet early in your middleware stack so that its headers are sure to be set.

You can also use its pieces individually:

'''js
app.use(helmet.noCache())
app.use(helmet.frameguard())
'''

You can disable a middleware that's normally enabled by default. This will disable 'frameguard' but include the other defaults.

'''js
app.use(helmet({
...
```

#### <a name="apidoc.element.helmet.noSniff"></a>[function <span class="apidocSignatureSpan">helmet.</span>noSniff ()](#apidoc.element.helmet.noSniff)
- description and source-code
```javascript
function nosniff() {
  return function nosniff (req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff')
    next()
  }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.helmet.referrerPolicy"></a>[function <span class="apidocSignatureSpan">helmet.</span>referrerPolicy (options)](#apidoc.element.helmet.referrerPolicy)
- description and source-code
```javascript
function referrerPolicy(options) {
  options = options || {}

  var policy
  if ('policy' in options) {
    policy = options.policy
  } else {
    policy = DEFAULT_POLICY
  }

  if (ALLOWED_POLICIES.indexOf(policy) === -1) {
    throw new Error('"' + policy + '" is not a valid policy. Allowed policies: ' + ALLOWED_POLICIES_ERROR_LIST + '.')
  }

  return function referrerPolicy (req, res, next) {
    res.setHeader('Referrer-Policy', policy)
    next()
  }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.helmet.xssFilter"></a>[function <span class="apidocSignatureSpan">helmet.</span>xssFilter (options)](#apidoc.element.helmet.xssFilter)
- description and source-code
```javascript
function xXssProtection(options) {
  if (options && options.setOnOldIE) {
    return function xXssProtection (req, res, next) {
      res.setHeader('X-XSS-Protection', '1; mode=block')
      next()
    }
  } else {
    return function xXssProtection (req, res, next) {
      var matches = /msie\s*(\d+)/i.exec(req.headers['user-agent'])

      var value
      if (!matches || (parseFloat(matches[1]) >= 9)) {
        value = '1; mode=block'
      } else {
        value = '0'
      }

      res.setHeader('X-XSS-Protection', value)
      next()
    }
  }
}
```
- example usage
```shell
n/a
```



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
