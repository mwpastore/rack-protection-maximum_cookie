require_relative '../../test_helper'

require 'rack/test'
require 'securerandom'

MyApp = proc do
  response = Rack::MockResponse.new 200, {
    'Set-Cookie'=><<-EOF
foo.bar=12345; Secure; HttpOnly; SameSite=strict
bar.qux=67890; Secure; HttpOnly; SameSite=strict
qux.foo=09876; Secure; HttpOnly; SameSite=strict
foo.bar=12345; Domain=eXample.com
bar.qux=67890; domain=exAmple.com
qux.foo=09876; Domain=foo.example.com
foo.bar=12345; Path=/; Domain=example.net; Expires=Sun, 26 Nov 2017 22:38:06 -0000
    EOF
  }, '<div>Hello, world!</div>'
  response.finish
end

module MyAppTest
  def app(*args, &block)
    Rack::Builder.new do
      use Rack::Protection::MaximumCookie, *args, &block
      run MyApp
    end
  end
end

class DefaultBehaviorTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def test_simple_response
    get '/'

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
    assert_match %r{^foo.bar=12345}, last_response.headers['Set-Cookie']
    assert_match %r{^qux.foo=09876; Domain=foo.example.com}, last_response.headers['Set-Cookie']
  end
end

class LimitTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :limit=>2
  end

  def test_limit_with_default_domain
    error = assert_raises { get '/' }

    assert_equal 'Too many cookies for domain(s): example.org', error.message
  end
end

class BytesizeLimitTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :bytesize_limit=>80
  end

  def test_bytesize_limit_with_default_domain
    error = assert_raises { get '/' }

    assert_equal 'Too much cookie data for domain(s): example.org, example.net', error.message
  end
end

class StrictBehaviorTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :strict=>true
  end

  def test_simple_response
    get '/'

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
    assert_match %r{^foo.bar=12345}, last_response.headers['Set-Cookie']
    assert_match %r{^qux.foo=09876; Domain=foo.example.com}, last_response.headers['Set-Cookie']
  end
end

class StrictLimitTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :strict=>true, :limit=>2
  end

  def test_limit_with_subdomain
    error = assert_raises { get '/' }

    assert_equal 'Too many cookies for domain(s): example.org, foo.example.com', error.message
  end
end

class StrictBytesizeLimitTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :strict=>true, :bytesize_limit=>80
  end

  def test_bytesize_limit_with_subdomain
    error = assert_raises { get '/' }

    assert_equal 'Too much cookie data for domain(s): example.org, foo.example.com, example.net', error.message
  end
end

class PerCookieBehaviorTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :per_domain=>false
  end

  def test_simple_response
    get '/'

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
    assert_match %r{^foo.bar=12345}, last_response.headers['Set-Cookie']
    assert_match %r{^qux.foo=09876; Domain=foo.example.com}, last_response.headers['Set-Cookie']
  end
end

class PerCookieBytesizeLimitTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :per_domain=>false, :bytesize_limit=>80
  end

  def test_bytesize_limit_per_cookie
    error = assert_raises { get '/' }

    assert_equal 'Too much data for cookie(s): foo.bar', error.message
  end
end

class PerCookieOverheadTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :per_domain=>false, :bytesize_limit=>80, :overhead=>40
  end

  def test_bytesize_limit_per_cookie
    error = assert_raises { get '/' }

    assert_equal 'Too much data for cookie(s): foo.bar, bar.qux, qux.foo', error.message
  end
end

class TrueHandlerTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :limit=>2 do |env|
      @handler_did_fire = true
    end
  end

  def test_handler_returns_true
    @handler_did_fire = false

    error = assert_raises { get '/' }

    assert @handler_did_fire

    assert_equal 'Too many cookies for domain(s): example.org', error.message
  end
end

class FalseHandlerTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :per_domain=>false, :limit=>2 do |env|
      @handler_did_fire = true

      false
    end
  end

  def test_handler_returns_false
    @handler_did_fire = false

    get '/'

    assert @handler_did_fire

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
    assert_match %r{^foo.bar=12345}, last_response.headers['Set-Cookie']
    assert_match %r{^qux.foo=09876; Domain=foo.example.com}, last_response.headers['Set-Cookie']
  end
end

class NoLimitTest < Minitest::Test
  include Rack::Test::Methods

  def app
    Rack::Builder.new do
      app = proc do
        response = Rack::MockResponse.new 200, {
          'Set-Cookie'=>Array.new(1_000, 'a=b').join("\n")
        }, '<div>Hello, world!</div>'
        response.finish
      end

      use Rack::Protection::MaximumCookie,
        :per_domain=>false,
        :limit=>-1

      run app
    end
  end

  def test_no_limit
    get '/'

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
  end
end

class NoBytesizeLimitTest < Minitest::Test
  include Rack::Test::Methods

  def app
    Rack::Builder.new do
      app = proc do
        random_string = Rack::Utils.escape SecureRandom.base64(10_000)
        response = Rack::MockResponse.new 200, {
          'Set-Cookie'=>"foo.bar=#{random_string}"
        }, '<div>Hello, world!</div>'
        response.finish
      end

      use Rack::Protection::MaximumCookie,
        :per_domain=>false,
        :bytesize_limit=>-1

      run app
    end
  end

  def test_no_bytesize_limit
    get '/'

    assert last_response.ok?
    assert_equal '<div>Hello, world!</div>', last_response.body
  end
end

class DefaultDomainTest < Minitest::Test
  include MyAppTest
  include Rack::Test::Methods

  def app
    super :limit=>2
  end

  def test_it_handles_ports
    error = assert_raises { get 'http://example.org:23' }

    assert_equal 'Too many cookies for domain(s): example.org', error.message
  end

  def test_it_handles_localhost
    error = assert_raises { get 'http://localhost' }

    assert_equal 'Too many cookies for domain(s): localhost', error.message
  end

  def test_it_handles_ipv4_addresses
    error = assert_raises { get 'http://127.0.0.1' }

    assert_equal 'Too many cookies for domain(s): 127.0.0.1', error.message
  end

  def test_it_handles_ipv6_addresses_forwarded_host
    error = assert_raises do
      get '/', {}, { 'HTTP_X_FORWARDED_HOST'=>'foo, bar, [::1]' }
    end

    assert_equal 'Too many cookies for domain(s): ::1', error.message
  end
end
