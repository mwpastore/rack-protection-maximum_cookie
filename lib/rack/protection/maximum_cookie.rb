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
      attr_reader :check_cookies_meth
      attr_reader :public_suffix_list

      def initialize(app, options={}, &block)
        @app = app
        @handler = block

        @options = {}.tap do |h|
          h[:limit] = Integer(options.fetch(:limit, 50))
          h[:bytesize_limit] = Integer(options.fetch(:bytesize_limit, 4_096))
          h[:overhead] = Integer(options.fetch(:overhead, 3))
          h[:strict?] = !!options.fetch(:strict?, options.fetch(:strict, false))

          h.freeze
        end

        @check_cookies_meth =
          if @options[:strict?] || !!options.fetch(:per_domain?, options.fetch(:per_domain, true))
            # Allow non-ICANN domains to be handled the same as ICANN domains.
            @public_suffix_list = PublicSuffix::List.parse(::File.read(PublicSuffix::List::DEFAULT_LIST_PATH), :private_domains=>false)

            :check_per_domain
          else
            :check_simple
          end

        if @options[:limit] < 0 && @options[:bytesize_limit] < 0
          abort 'No limits, nothing to do!'
        end
      end

      def call(env)
        status, headers, body = app.call(env)
        send(check_cookies_meth, env, headers[SET_COOKIE]) if headers.key?(SET_COOKIE)
        [status, headers, body]
      end

      private

      def check_simple(env, set_cookie)
        cookies = normalize_header(set_cookie)

        unless options[:limit] < 0
          if cookies.size > options[:limit] && handle(env)
            raise_error 'Too many cookies'
          end
        end

        unless options[:bytesize_limit] < 0
          overhead, bytesize_limit = options.values_at(:overhead, :bytesize_limit)
          bad_keys = cookies
            .keep_if { |cookie| cookie.bytesize + overhead > bytesize_limit }
            .map! { |cookie| cookie[/\A[^=]+/] }
            .tap(&:uniq!)

          if bad_keys.any? && handle(env)
            raise_error "Too much data for cookie(s): #{bad_keys.join(', ')}"
          end
        end
      end

      def check_per_domain(env, set_cookie)
        default_subdomain = domain(hostname(env).downcase)

        count = Hash.new { |h, k| h[k] = 0 }
        bytesize = Hash.new { |h, k| h[k] = 0 }

        overhead = options[:overhead]

        normalize_header(set_cookie).each do |cookie|
          if (subdomain = cookie[DOMAIN_RE, 1])
            subdomain.downcase!
          else
            subdomain = default_subdomain
          end

          count[subdomain] += 1
          bytesize[subdomain] += cookie.bytesize + overhead
        end

        if options[:strict?]
          propogate_values(count)
          propogate_values(bytesize)
        end

        unless options[:limit] < 0
          limit = options[:limit]
          bad_domains = count
            .keep_if { |_, value| value > limit }
            .keys

          if bad_domains.any? && handle(env)
            raise_error "Too many cookies for domain(s): #{bad_domains.join(', ')}"
          end
        end

        unless options[:bytesize_limit] < 0
          bytesize_limit = options[:bytesize_limit]
          bad_domains = bytesize
            .keep_if { |_, value| value > bytesize_limit }
            .keys

          if bad_domains.any? && handle(env)
            raise_error "Too much cookie data for domain(s): #{bad_domains.join(', ')}"
          end
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
          # TODO: Submit a PR to add this test to Rack::Request.
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
