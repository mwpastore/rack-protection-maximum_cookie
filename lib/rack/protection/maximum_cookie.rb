# frozen_string_literal: true
require 'rack/protection/maximum_cookie/version'

require 'public_suffix'
require 'rack'
require 'rack/request'
require 'resolv'

module Rack
  HTTP_HOST = 'HTTP_HOST'.freeze unless defined?(HTTP_HOST)
  SERVER_ADDR = 'SERVER_ADDR'.freeze unless defined?(SERVER_ADDR)
  SERVER_NAME = 'SERVER_NAME'.freeze unless defined?(SERVER_NAME)
  SERVER_PORT = 'SERVER_PORT'.freeze unless defined?(SERVER_PORT)
  SET_COOKIE = 'Set-Cookie'.freeze unless defined?(SET_COOKIE)

  class Request
    HTTP_X_FORWARDED_HOST = 'HTTP_X_FORWARDED_HOST'.freeze unless defined?(HTTP_X_FORWARDED_HOST)
  end

  module Protection
    class MaximumCookie
      HEADER_SEP_RE = %r{\r?\n|\0}.freeze
      DOMAIN_RE = %r{;\s*[Dd][Oo][Mm][Aa][Ii][Nn]=([^;]+)}.freeze

      attr_reader :app
      attr_reader :handler
      attr_reader :options
      attr_reader :public_suffix_list

      def initialize(app, options={}, &block)
        @app = app
        @handler = block

        @options = {}.tap do |h|
          h[:limit] = Integer(options.fetch(:limit, 50))
          h[:bytesize_limit] = Integer(options.fetch(:bytesize_limit, 4_096))
          h[:overhead] = Integer(options.fetch(:overhead, 3))
          h[:strict?] = !!options.fetch(:strict?, options.fetch(:strict, false))
          h[:per_domain?] = h[:strict?] || !!options.fetch(:per_domain?, options.fetch(:per_domain, true))

          h.freeze
        end

        # Allow non-ICANN domains to be handled the same as ICANN domains.
        @public_suffix_list = PublicSuffix::List.parse(::File.read(PublicSuffix::List::DEFAULT_LIST_PATH), :private_domains=>false)

        if @options[:limit] < 0 && @options[:bytesize_limit] < 0
          abort 'No limits, nothing to do!'
        end
      end

      def call(env)
        status, headers, body = app.call(env)
        if headers.key?(SET_COOKIE)
          check_cookies(env, normalize_header(headers[SET_COOKIE]))
        end
        [status, headers, body]
      end

      private

      def check_cookies(env, cookies)
        default_subdomain = domain(hostname(env).downcase)

        overhead, per_domain = options.values_at(:overhead, :per_domain?)

        count = Hash.new { |h, k| h[k] = 0 }
        bytesize = Hash.new { |h, k| h[k] = 0 } if per_domain

        cookies.each do |cookie|
          if (subdomain = cookie[DOMAIN_RE, 1])
            subdomain.downcase!
          else
            subdomain = default_subdomain
          end

          count[subdomain] += 1
          bytesize[subdomain] += cookie.bytesize + overhead if per_domain
        end

        if options[:strict?]
          propogate_values(count)
          propogate_values(bytesize) if per_domain
        end

        limit, bytesize_limit = options.values_at(:limit, :bytesize_limit)

        check_limit_per_domain(env, count, limit) unless limit < 0

        unless bytesize_limit < 0
          if per_domain
            check_bytesize_limit_per_domain(env, bytesize, bytesize_limit)
          else
            check_bytesize_limit_per_cookie(env, cookies, bytesize_limit - overhead)
          end
        end
      end

      def check_limit_per_domain(env, acc, limit)
        bad_domains = acc
          .keep_if { |_, value| value > limit }
          .keys

        if bad_domains.any? && handle(env)
          raise_error "Too many cookies for domain(s): #{bad_domains.join(', ')}"
        end
      end

      def check_bytesize_limit_per_domain(env, acc, limit)
        bad_domains = acc
          .keep_if { |_, value| value > limit }
          .keys

        if bad_domains.any? && handle(env)
          raise_error "Too much cookie data for domain(s): #{bad_domains.join(', ')}"
        end
      end

      def check_bytesize_limit_per_cookie(env, cookies, limit)
        bad_cookies = cookies
          .keep_if { |cookie| cookie.bytesize > limit }
          .map! { |cookie| cookie[/\A[^=]+/] }
          .tap(&:uniq!)

        if bad_cookies.any? && handle(env)
          raise_error "Too much data for cookie(s): #{bad_cookies.join(', ')}"
        end
      end

      def domain(host)
        return host if host =~ Resolv::IPv4::Regex || host =~ Resolv::IPv6::Regex

        PublicSuffix.domain(host, :list=>public_suffix_list) || host
      end

      def handle(env)
        handler.nil? || handler.call(env)
      end

      # TODO: Submit a PR to add this to Rack::Request a la URI#host vs. URI#hostname.
      def hostname(env)
        host = host(env)
        return $1 if host =~ /\A\[([^\]]+)\]\z/
        host
      end

      # Borrowed from Rack::Request
      def host(env)
        host_with_port(env).sub(/:\d+\z/, '')
      end

      # Borrowed from Rack::Request (with changes)
      def host_with_port(env)
        if (forwarded_host = env[Request::HTTP_X_FORWARDED_HOST])
          # TODO: I don't think X-Forwarded-Host ever contains more than a
          # single value (unlike X-Forwarded-For), so I'm not sure why
          # Rack::Request has this test, but we'll do it too, just in case.
          host = forwarded_host.to_s[/[^,\s]+\z/]

          # If the reverse proxy sends an IPv6 address without brackets,
          # prevent the last hextet from being stripped off by host() by
          # enclosing the address in brackets.
          # https://github.com/rack/rack/pull/1213
          host =~ Resolv::IPv6::Regex ? "[#{host}]" : host
        elsif (host = env[HTTP_HOST])
          host.to_s
        else
          "#{env[SERVER_NAME] || env[SERVER_ADDR]}:#{env[SERVER_PORT]}"
        end
      end

      def normalize_header(value)
        Array(value)
          .flat_map { |h| h.to_s.split(HEADER_SEP_RE) }
          .tap(&:compact!)
      end

      # Add the values for each second-level domain (e.g. example.com) to the
      # values for its subdomains (e.g. foo. and bar.example.com).
      def propogate_values(hash)
        hash.each_key do |subdomain|
          sld = domain(subdomain)
          next if sld == subdomain
          next unless hash.key?(sld)
          hash[subdomain] += hash[sld]
        end
      end

      def raise_error(message)
        fail message
      end
    end
  end
end
