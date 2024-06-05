# Traefik Forward Auth

A minimal forward authentication service that provides OAuth/SSO login and authentication for the [traefik](https://github.com/containous/traefik) reverse proxy/load balancer.

## @traPtitech fork notes

This is a further fork of [jordemort/traefik-forward-auth](https://github.com/jordemort/traefik-forward-auth).
This is to build upon the `jordemort/traefik-forward-auth` work of merging several upstream PRs,
especially the custom user key support in pull/159.

This fork is **NOT** backwards-compatible with upstream releases.
Read below to see major (breaking) changes from upstream.

Further customization notes:

- Allows "soft-auth" mode instead of the usual "auth" mode which forces authentication.
    - Requests with our header will be passed with the user header, while other requests will also be passed through with empty user header value.
- Now builds against traefik v3.
    - Rule syntax now follows those of traefik v3.
- Configuration revamp to use github.com/spf13/viper.
    - Allows ease parsing and configuration from env, yaml, json, or toml files.
    - Instead, no longer accepts configurations from CLI args.
    - Several field names have been changed alongside to be more consistent overall.
- Use JWT (Json Web Token) instead of re-inventing the original token format.
- Dynamic mapping of userinfo values to header values.
- More expressive traefik-like language to replace the 'whitelist' and email 'domain' user filtering.

Despite quite a few breaking changes from upstream, it still supports the same basic usage,
and even more advanced dynamic usages.

### Releases

Releases of this fork are published to the [GitHub Container Registry](https://github.com/traPtitech/traefik-forward-auth/pkgs/container/traefik-forward-auth).

## Fork notes

This is yet another fork of [thomseddon/traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth).
I have merged several pull requests that have not (yet?) been merged upstream:

- https://github.com/thomseddon/traefik-forward-auth/pull/77
- https://github.com/thomseddon/traefik-forward-auth/pull/159
- https://github.com/thomseddon/traefik-forward-auth/pull/281
- https://github.com/thomseddon/traefik-forward-auth/pull/295
- https://github.com/thomseddon/traefik-forward-auth/pull/327

I have also updated all the dependencies, and switched to building with Go 1.19.
The Dockerfile has been switched from Alpine to using the official Go container for building the binary and a [distroless](https://github.com/GoogleContainerTools/distroless) image for runtime.

I wrote [a blog post](https://jordemort.dev/blog/single-sign-on-with-mastodon/) about how I use this.
Note that I only use the Generic OAuth provider.
I haven't tried using the other providers, but all the tests still pass.

This version now builds against Traefik 2.9, so you should be able to use all of the latest matchers, but `ClientIP` does not appear to be working as you might expect.
It seems to be a better bet to match against the `X-Forwarded-For` header.

## Why?

- Seamlessly overlays any http service with a single endpoint (see: `url-path` in [Configuration](#configuration))
- Supports multiple providers including Google and OpenID Connect (supported by Azure, Github, Salesforce etc.)
- Supports multiple domains/subdomains by dynamically generating redirect_uri's
- Allows authentication to be selectively applied/bypassed based on request parameters (see `rules` in [Configuration](#configuration))
- Supports use of centralised authentication host/redirect_uri (see `auth-host` in [Configuration](#configuration))
- Allows authentication to persist across multiple domains (see [Cookie Domains](#cookie-domains))
- Supports extended authentication beyond Google token lifetime (see: `lifetime` in [Configuration](#configuration))

# Contents

- [Releases](#releases)
- [Usage](#usage)
  - [Simple](#simple)
  - [Advanced](#advanced)
  - [Provider Setup](#provider-setup)
- [Configuration](#configuration)
  - [Option Details](#option-details)
- [Concepts](#concepts)
  - [Forwarded Headers](#forwarded-headers)
  - [Applying Authentication](#applying-authentication)
    - [Global Authentication](#global-authentication)
    - [Selective Ingress Authentication in Kubernetes](#selective-ingress-authentication-in-kubernetes)
    - [Selective Container Authentication in Swarm](#selective-container-authentication-in-swarm)
    - [Rules Based Authentication](#rules-based-authentication)
  - [Operation Modes](#operation-modes)
    - [Overlay Mode](#overlay-mode)
    - [Auth Host Mode](#auth-host-mode)
  - [Logging Out](#logging-out)
- [Copyright](#copyright)
- [License](#license)

## Usage

#### Simple:

See below for instructions on how to setup your [Provider Setup](#provider-setup).

docker-compose.yml:

```yaml
services:
  traefik:
    image: traefik:v3.0
    command: --providers.docker
    ports:
      - "8085:80"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  traefik-forward-auth:
    image: ghcr.io/jordemort/traefik-forward-auth:latest
    environment:
      - PROVIDERS_GOOGLE_CLIENT_ID=your-client-id
      - PROVIDERS_GOOGLE_CLIENT_SECRET=your-client-secret
      - SECRET=something-random
      - INSECURE_COOKIE=true # Example assumes no https, do not use in production
    labels:
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User"
      - "traefik.http.services.traefik-forward-auth.loadbalancer.server.port=4181"

  whoami:
    image: containous/whoami
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.mycompany.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
```

#### Advanced:

Please see the examples directory for a more complete [docker-compose.yml](examples/traefik-v2/swarm/docker-compose.yml) or [kubernetes/simple-separate-pod](examples/traefik-v2/kubernetes/simple-separate-pod/).

Also in the examples directory is [docker-compose-auth-host.yml](examples/traefik-v2/swarm/docker-compose-auth-host.yml) and [kubernetes/advanced-separate-pod](examples/traefik-v2/kubernetes/advanced-separate-pod/) which shows how to configure a central auth host, along with some other options.

#### Provider Setup

Below are some general notes on provider setup, specific instructions and examples for a number of providers can be found on the [Provider Setup](https://github.com/thomseddon/traefik-forward-auth/wiki/Provider-Setup) wiki page.

##### Google

Head to https://console.developers.google.com and make sure you've switched to the correct email account.

Create a new project then search for and select "Credentials" in the search bar. Fill out the "OAuth Consent Screen" tab.

Click "Create Credentials" > "OAuth client ID". Select "Web Application", fill in the name of your app, skip "Authorized JavaScript origins" and fill "Authorized redirect URIs" with all the domains you will allow authentication from, appended with the `url-path` (e.g. https://app.test.com/_oauth)

You must set the `providers.google.client-id` and `providers.google.client-secret` config options.

##### OpenID Connect

Any provider that supports OpenID Connect 1.0 can be configured via the OIDC config options below.

You must set the `providers.oidc.issuer-url`, `providers.oidc.client-id` and `providers.oidc.client-secret` config options.

Please see the [Provider Setup](https://github.com/thomseddon/traefik-forward-auth/wiki/Provider-Setup) wiki page for examples.

##### Generic OAuth2

For providers that don't support OpenID Connect, we also have the Generic OAuth2 provider where you can statically configure the OAuth2 and "user" endpoints.

You must set:
- `providers.generic-oauth.auth-url` - URL the client should be sent to authenticate the authenticate
- `providers.generic-oauth.token-url` - URL the service should call to exchange an auth code for an access token
- `providers.generic-oauth.user-url` - URL used to retrieve user info (service makes a GET request)
- `providers.generic-oauth.client-id` - Client ID
- `providers.generic-oauth.client-secret` - Client Secret

You can also set:
- `providers.generic-oauth.scope`- Any scopes that should be included in the request (default: profile, email)
- `providers.generic-oauth.token-style` - How token is presented when querying the User URL. Can be `header` or `query`, defaults to `header`. With `header` the token is provided in an Authorization header, with query the token is provided in the `access_token` query string value.

Please see the [Provider Setup](https://github.com/thomseddon/traefik-forward-auth/wiki/Provider-Setup) wiki page for examples.

## Configuration

### Command-line Args

Supply path to config file as CLI args.

```
Usage of traefik-foward-auth:
  -config string
        Path to config file
```

### File / Env Configuration

Configuration options and documentations are available in [config.go](./internal/config.go).

This library uses github.com/spf13/viper to parse configurations.
They are parsed in the following precedence order.

1. **Environment Variables** - Make all letters uppercase, and replace "-" and "." with "_" to get corresponding env key name
   - For example, `providers.google.client-secret` config key corresponds to `PROVIDERS_GOOGLE_CLIENT_SECRET` environment variable.
2. **Configuration Files** - Can be written in JSON, TOML, or YAML
3. **Default** - See config.go for default values

### Option Details

- `auth-host`

  When set, when a user returns from authentication with a 3rd party provider they will always be forwarded to this host. By using one central host, this means you only need to add this `auth-host` as a valid redirect uri to your 3rd party provider.

  The host should be specified without protocol or path, for example:

   ```yaml
   auth-host: "auth.example.com"
   ```

   For more details, please also read the [Auth Host Mode](#auth-host-mode), operation mode in the concepts section.

   Please Note - this should be considered advanced usage, if you are having problems please try disabling this option and then re-read the [Auth Host Mode](#auth-host-mode) section.

- `config`

   Used to specify the path to a configuration file, can be set multiple times, each file will be read in the order they are passed. Options should be set in an INI format, for example:

   ```yaml
   url-path: _oauthpath
   ```

- `cookie-domains`

  When set, if a user successfully completes authentication, then if the host of the original request requiring authentication is a subdomain of a given cookie domain, then the authentication cookie will be set for the higher level cookie domain. This means that a cookie can allow access to multiple subdomains without re-authentication. Can be specified multiple times.

   For example:
   ```yaml
   cookie-domains:
     - "example.com"
     - "test.org"
   ```

   For example, if the cookie domain `test.com` has been set, and a request comes in on `app1.test.com`, following authentication the auth cookie will be set for the whole `test.com` domain. As such, if another request is forwarded for authentication from `app2.test.com`, the original cookie will be sent and so the request will be allowed without further authentication.

   Beware however, if using cookie domains whilst running multiple instances of traefik/traefik-forward-auth for the same domain, the cookies will clash. You can fix this by using a different `cookie-name` in each host/cluster or by using the same `cookie-secret` in both instances.

- `insecure-cookie`

   If you are not using HTTPS between the client and traefik, you will need to pass the `insecure-cookie` option which will mean the `Secure` attribute on the cookie will not be set.

- `cookie-name`

   Set the name of the cookie set following successful authentication.

   Default: `_forward_auth`

- `csrf-cookie-name`

   Set the name of the temporary CSRF cookie set during authentication.

   Default: `_forward_auth_csrf`

- `provider`

   Set the provider to use for authentication. Valid options are currently `google`, `oidc`, or `generic-oauth`.

   Default: `google`

- `lifetime`

   How long a successful authentication session should last, in seconds.

   Default: `43200` (12 hours)

- `callback-path`

   Customise the path that this service uses to handle the callback following authentication.

   Default: `/_oauth`

   Please note that when using the default [Overlay Mode](#overlay-mode) requests to this exact path will be intercepted by this service and not forwarded to your application. Use this option (or [Auth Host Mode](#auth-host-mode)) if the default `/_oauth` path will collide with an existing route in your application.

- `secret`

   Used to sign cookies authentication, should be a random (e.g. `openssl rand -hex 16`)

- `rules`

   Specify selective authentication rules. Rules are specified in the following format: `rules.<name>.<param>: <value>`

   - `<name>` can be any string and is only used to group rules together
   - `<param>` can be:
       - `action` - supported values:
           - `auth` (default)
           - `soft-auth`
           - `allow`
           - `login`
           - `logout`
           - `callback`
           - `health`
       - `route-rule` - a rule to match a request, this uses traefik's v3 rule parser for which you can find the documentation here: https://docs.traefik.io/v3.0/routing/routers/#rule, supported values are summarised here:
           - ``Header(`key`, `value`)``
           - ``HeaderRegexp(`key`, `regexp`)``
           - ``Host(`example.com`)``
           - ``HostRegexp(`^[a-z]+.example.com`)``
           - ``Method(`OPTIONS`)``
           - ``Path(`path`)``
           - ``PathRegexp(`^/articles/{category}/[0-9]+$`)``
           - ``PathPrefix(`/products/`)``
           - ``Query(`foo=bar`)``
       - `priority` - route-rule's priority, working similarly to traefik v3 router rules. Higher number means the rule is checked earlier. Defaults to string length of the route-rule.
       - `auth-rule` - traefik router-like language to express whether a user is allowed to pass *after* authenticating the user. Headers will be set *only when* this AuthRule passes. Defaults to `True()` which passes all users. Allowed functions are:
         - ``True()`` - Always passes.
         - ``In(`path`, `value1`, `value2`, ...)`` - Passes when the userinfo is one of the values.
         - ``Regexp(`path`, `pattern`)`` - Passes when the userinfo matches the pattern.

   For example:
   ```
   # Allow requests that being with `/api/public` and contain the `Content-Type` header with a value of `application/json`
   rules.1.action = allow
   rules.1.route-rule = PathPrefix(`/api/public`) && Header(`Content-Type`, `application/json`)

   # Allow requests that have the exact path `/public`
   rules.two.action = allow
   rules.two.route-rule = Path(`/public`)

   # Allow jane@example.com to `/janes-eyes-only`
   rules.two.action = allow
   rules.two.route-rule = Path(`/janes-eyes-only`)
   rules.two.auth-rule = In(`email`, `jane@example.com`)
   ```

   Note: It is possible to break your redirect flow with rules, please be careful not to create an `allow` rule that matches your redirect_uri unless you know what you're doing. This limitation is being tracked in #101 and the behaviour will change in future releases.

   Default: `rules.default.action: auth`, `rules.default.priority: -10000`

- `rules.default.action`

  Specifies the behavior when a request does not match any additionally defined `rules`. 
  
  Valid options: `auth`, `soft-auth`, `allow`, `login`, `logout`, `callback`, `health`

  Default: `auth` (i.e. all requests require authentication)

- `headers`

   Dynamically specify which userinfo values to map into passed headers. Has a similar syntax to `rules`: `headers.<name>.<param>: <value>`.

   - `<name>` can be any string and is only used to group config together.
   - `<param>` can be:
      - `name` - Name of the header to pass on.
      - `source` - Dot notation path of userinfo values to source the header value from.

   Default: `headers.default.name: X-Forwarded-User`, `headers.default.source: email`

- `info-fields`

   List of dot notation of userinfo fields to save to the token.
   Note that fields not specified here will NOT be saved to the token to avoid bloating token size.
   Since traefik-forward-auth is a stateless application, fields not specified here cannot be referenced from `rules.<name>.auth-rule` or `headers.<name>.source`.

   Default: `email`

- `trusted-ip-address`

  This option adds an IP address or an IP network given in CIDR notation to the list of trusted networks. Requests originating
  from a trusted network are considered authenticated and are never redirected to an OAuth IDP. The option can be used
  multiple times to add many trusted address ranges.

  * `trusted-ip-address: 2.3.4.5` adds a single IP (`2.3.4.5`) as a trusted IP.
  * `trusted-ip-address: 30.1.0.0/16` adds the address range from `30.1.0.1` to `30.1.255.254` as a trusted range

  The list of trusted networks is initially empty.

## Concepts

### Forwarded Headers

The authenticated user is set in the `X-Forwarded-User` header, to pass this on add this to the `authResponseHeaders` config option in traefik, as shown below in the [Applying Authentication](#applying-authentication) section.

### Applying Authentication

Authentication can be applied in a variety of ways, either globally across all requests, or selectively to specific containers/ingresses.

#### Global Authentication

This can be achieved by enabling forward authentication for an entire entrypoint, for example, with http only:

```ini
--entryPoints.http.address=:80
--entrypoints.http.http.middlewares=traefik-forward-auth # "default-traefik-forward-auth" on kubernetes
```

Or https:

```ini
--entryPoints.http.address=:80
--entryPoints.http.http.redirections.entryPoint.to=https
--entryPoints.http.http.redirections.entryPoint.scheme=https
--entryPoints.https.address=:443
--entrypoints.https.http.middlewares=traefik-forward-auth # "default-traefik-forward-auth" on kubernetes
```

Note: Traefik prepends the namespace to the name of middleware defined via a kubernetes resource. This is handled automatically when referencing the middleware from another resource in the same namespace (so the namespace does not need to be prepended when referenced). However the full name, including the namespace, must be used when referenced from static configuration (e.g. command arguments or config file), hence you must prepend the namespace to your traefik-forward-auth middleware reference, as shown in the comments above (e.g. `default-traefik-forward-auth` if your middleware is named `traefik-forward-auth` and is defined in the `default` namespace).

#### Selective Ingress Authentication in Kubernetes

If you choose not to enable forward authentication for a specific entrypoint, you can apply the middleware to selected ingressroutes:

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: IngressRoute
metadata:
  name: whoami
  labels:
    app: whoami
spec:
  entryPoints:
    - http
  routes:
  - match: Host(`whoami.example.com`)
    kind: Rule
    services:
      - name: whoami
        port: 80
    middlewares:
      - name: traefik-forward-auth
```

See the examples directory for more examples.

#### Selective Container Authentication in Swarm

You can apply labels to selected containers:

```yaml
whoami:
  image: containous/whoami
  labels:
    - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
    - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
```

See the examples directory for more examples.

#### Rules Based Authentication

You can also leverage the `rules` config to selectively apply authentication via traefik-forward-auth. For example if you enabled global authentication by enabling forward authentication for an entire entrypoint, you can still exclude some patterns from requiring authentication:

```yaml
rule:
  # Allow requests to 'dash.example.com'
  "1":
    action: allow
    rule: Host(`dash.example.com`)
  # Allow requests to `app.example.com/public`
  two:
    action: allow
    rule: Host(`app.example.com`) && Path(`/public`)
```

### Operation Modes

#### Overlay Mode

Overlay is the default operation mode, in this mode the authorisation endpoint is overlaid onto any domain. By default the `/_oauth` path is used, this can be customised using the `callback-path` option.

The user flow will be:

1. Request to `www.myapp.com/home`
2. User redirected to Google login
3. After Google login, user is redirected to `www.myapp.com/_oauth`
4. Token, user and CSRF cookie is validated (this request in intercepted and is never passed to your application)
5. User is redirected to `www.myapp.com/home`
6. Request is allowed

As the hostname in the `redirect_uri` is dynamically generated based on the original request, every hostname must be permitted in the Google OAuth console (e.g. `www.myappp.com` would need to be added in the above example)

#### Auth Host Mode

This is an optional mode of operation that is useful when dealing with a large number of subdomains, it is activated by using the `auth-host` config option (see [this example docker-compose.yml](examples/traefik-v2/swarm/docker-compose-auth-host.yml) or [this kubernetes example](https://github.com/thomseddon/traefik-forward-auth/tree/master/examples/traefik-v2/kubernetes/advanced-separate-pod)).

For example, if you have a few applications: `app1.test.com`, `app2.test.com`, `appN.test.com`, adding every domain to Google's console can become laborious.
To utilise an auth host, permit domain level cookies by setting the cookie domain to `test.com` then set the `auth-host` to: `auth.test.com`.

The user flow will then be:

1. Request to `app10.test.com/home/page`
2. User redirected to Google login
3. After Google login, user is redirected to `auth.test.com/_oauth`
4. Token, user and CSRF cookie is validated, auth cookie is set to `test.com`
5. User is redirected to `app10.test.com/home/page`
6. Request is allowed

With this setup, only `auth.test.com` must be permitted in the Google console.

Two criteria must be met for an `auth-host` to be used:

1. Request matches given `cookie-domain`
2. `auth-host` is also subdomain of same `cookie-domain`

Please note: For Auth Host mode to work, you must ensure that requests to your auth-host are routed to the traefik-forward-auth container, as demonstrated with the service labels in the [docker-compose-auth.yml](examples/traefik-v2/swarm/docker-compose-auth-host.yml) example and the [ingressroute resource](examples/traefik-v2/kubernetes/advanced-separate-pod/traefik-forward-auth/ingress.yaml) in a kubernetes example.

### Logging in

The service provides an endpoint to allow users to explicitly login.
This behavior is achieved by setting "rules.<name>.action" option to `login`.

This action only makes sense for the `soft-auth` mode.

You can set `redirect` query parameter to redirect on login (defaults to `/`).

### Logging Out

The service provides additional "mode" to clear a users session and "log them out".
This behavior is achieved by setting "rules.<name>.action" option to `logout`.

You can set `redirect` query parameter to redirect on logout (defaults to `/`).
Note that the user will not have a valid auth cookie after being logged out.

Note: This only clears the auth cookie from the users browser and as this service is stateless, it does not invalidate the cookie against future use. So if the cookie was recorded, for example, it could continue to be used for the duration of the cookie lifetime.

## Copyright

2018 Thom Seddon

## License

[MIT](LICENSE.md)
