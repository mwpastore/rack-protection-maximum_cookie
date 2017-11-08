# Rack::Protection::MaximumCookie

[![Gem Version](https://badge.fury.io/rb/rack-protection-maximum_cookie.svg)](https://badge.fury.io/rb/rack-protection-maximum_cookie)
[![Build Status](https://travis-ci.org/mwpastore/rack-protection-maximum_cookie.svg?branch=master)](https://travis-ci.org/mwpastore/rack-protection-maximum_cookie)

Some bugs in Rack may cause cookies to be silently dropped&mdash;or worse,
truncated, leading to token leakage (i.e. transmission of a private session
over a insecure connection), cross-site scripting vulnerabilities, and/or
cross-site request forgery vulnerabilities. This gem provides a middleware that
tries to prevent these scenarios from occurring.

### Caveats

1.  Most modern browsers no longer have a [per-domain cookie size limit][1],
    so if you only care about modern browsers, go ahead and set `:per_domain?`
    to false. You'll benefit from the per-domain cookie limit and per-cookie
    bytesize limit (since most browsers still have some form of these limits,
    and Rack's built-in check for them is nonexistent in the former case and
    not implemented correctly in the latter).

2.  Browsers that do have per-domain cookie limits enforce these limits
    client-side, cumulatively over time. If you were to set a new cookie, every
    few minutes, one at a time, eventually you'd hit a limit. Or another
    service could be setting cookies for the domain your service listens on. If
    this is a concern for your app, see the `:stateful?` option below.

    In practice, your service is most likely setting the same cookies, for the
    same domains, every response, all in the same response, and it knows about
    all the cookies being set, so the default behavior of this gem should be
    appropriate in those cases.

## Installation

Add this line to your app's Gemfile:

```ruby
gem 'rack-protection-maximum_cookie'
```

And then execute:

```console
$ bundle
```

Or install it yourself as:

```console
$ gem install rack-protection-maximum_cookie
```

## Usage

Add this statement to your Rackup script or middleware-capable Rack app such as
Sinatra:

```ruby
use Rack::Protection::MaximumCookie
```

Or Rails:

> TODO: Somebody please tell me how to insert this and before or after what in
> Rails' middleware stack.

This middleware raises exceptions, so you'll want to use an error-reporting
service like Sentry, Rollbar, or Airbrake, and insert this middleware after it.

### Advanced

Rack::Protection::MaximumCookie accepts the following `use`-time options:

* `:limit` *Integer*

  Maximum number of cookies per domain. **50 cookies by default.** Set to a
  negative number to disable.

* `:bytesize_limit` *Integer*

  Maximum size&mdash;in bytes&mdash;of cookies per domain (if `:per_domain?` is
  set to true), or the maximum size of each cookie (if `:per_domain?` is set to
  false). **4,096 bytes by default.** Set to a negative number to disable.

* `:overhead` *Integer*

  Overhead&mdash;in bytes&mdash;per cookie. **Three (3) bytes by default.** Set to
  zero to disable.

* `:per_domain?` *Boolean*

  If true, apply the bytesize limit (e.g. 4,096 bytes&mdash;minus any
  per-cookie overhead) per domain. **This is the default behavior.**

  If false, apply the bytesize limit (e.g. 4,096 bytes&mdash;minus any
  overhead) per cookie.

* `:strict?` *Boolean*

  If false, each sub-domain gets its own quota, separate from its second-level
  domain. **This is the default behavior.**

  If true, `:per_domain?` is forced to true, and each second-level domain's
  cookies count towards its sub-domains' quotas. For example, if you have
  cookies for example<i></i>.org totaling 4,000 bytes, you wouldn't be able to
  set an additional 100-byte cookie on foo.example<i></i>.org in the same
  request.

* `:stateful?` *Boolean*

  If false, the cookies are evaluated for each response in isolation, i.e.
  statelessly. **This is the default behavior.**

  If true, `:strict?` is forced to true, and Rack::Protection::MaximumCookie
  will attempt to compensate for cookies that were set for the domain in
  previous responses (by this or other web services) but are not present in the
  current response.

  > This mechanism has its limits. First of all, browsers don't send cookie
  > directives in request headers&mdash;only key=value pairs&mdash;so in order
  > to compute the actual size of these cookies,
  > Rack::Protection::MaximumCookie must estimate the upper bound of the
  > bytesize of the directives in the original Set-Cookie headers. This
  > *should* work reasonably well as long as your app doesn't rely on any
  > non-standard directives or other quirky browser behavior.
  >
  > Secondly, browsers won't send cookies if their paths don't match the
  > request path. This means that if you're setting two cookies, one for
  > example<i></i>.org/foo and one for example<i></i>.org/bar, requests to
  > either path won't include the other's cookie. That defeats this mechanism,
  > as both cookies count toward example<i></i>.org's quota, but they aren't
  > able to be properly accounted for in the request. The only "workaround" is
  > to architect your app such that all cookies are set under a path common to
  > all routes. Unfortunately, this may lead to other security issues.
  >
  > This is an ugly wart on HTTP and the reason why modern browsers don't have
  > per-domain cookie size limits and drop cookies instead of truncating them.

#### Block Argument

If you don't want to raise exceptions, only want to raise exceptions under
certain conditions, or want to customize the exception, you can modify the
behavior by passing a block to the middleware initializer:

```ruby
use Rack::Protection::MaximumCookie do |env|
  raise MyCustomError, 'Someone broke the cookie jar!' if env['foo.bar']
end
```

If the block returns a truthy value, the default exception will be raised:

```ruby
use(Rack::Protection::MaximumCookie) { |env| env['foo.bar'] }
```

Keep in mind that the block receives the mutated *response* `env`.

I'm interested in hearing use-cases for this feature and I'm open to passing
additional arguments to the block. Open a new issue to document and discuss.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run
`rake spec` to run the tests. You can also run `bin/console` for an interactive
prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then run
`bundle exec rake release`, which will create a git tag for the version, push
git commits and tags, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/mwpastore/rack-protection-maximum_cookie.

Please let me know if I've made any invalid assumptions or conclusions about
the HTTP specification or older browser behavior.

## License

The gem is available as open source under the terms of the [MIT
License](http://opensource.org/licenses/MIT).

[1]: http://browsercookielimits.squawky.net
