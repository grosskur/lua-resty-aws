# lua-resty-aws

AWS signature V4 library for OpenResty + Lua.

## Overview

This library implements request signing using the [AWS Signature
Version 4][aws4] specification. This signature scheme is used by
nearly all AWS services.

## Example

```nginx
location / {
    set $s3_host s3.amazonaws.com;
    set $s3_uri $request_uri;
    access_by_lua "local aws = require 'resty.aws'; aws.s3_set_headers(ngx.var.s3_host, ngx.var.s3_uri)";
    proxy_pass https://$s3_host$s3_uri;
}
```

[aws4]: http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
