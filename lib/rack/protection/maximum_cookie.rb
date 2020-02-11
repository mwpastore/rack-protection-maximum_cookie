# frozen_string_literal: true
require 'rack/protection/maximum_cookie/version'

require 'date'
require 'public_suffix'
require 'rack'
require 'rack/request'
require 'resolv'
require 'set'

module Rack
  SET_COOKIE = 'Set-Cookie'.freeze unless defined?(SET_COOKIE)

  module Protection
    class MaximumCookie
      HEADER_SEP_RE = %r{\r?\n|\0}.freeze
      COOKIE_DOMAIN_RE = %r{;\s*[Dd][Oo][Mm][Aa][Ii][Nn]=([^;]+)}.freeze
      COOKIE_KEY_RE = %r{\A[^=]+}.freeze

      attr_reader :app
      attr_reader :handler
      attr_reader :public_suffix_list

      def limit
        @options[:limit]
      end

      def limit?
        @options[:limit] >= 0
      end

      def bytesize_limit
        @options[:bytesize_limit]
      end

      def bytesize_limit?
        @options[:bytesize_limit] >= 0
      end

      def overhead
        @options[:overhead]
      end

      def per_domain?
        @options[:per_domain?]
      end

      def strict?
        @options[:strict?]
      end

      def stateful?
        @options[:stateful?]
      end

      def initialize(app, options={}, &block)
        @app = app
        @handler = block

        @options = {}.tap do |h|
          h[:limit] = Integer(options.fetch(:limit, 50))
          h[:bytesize_limit] = Integer(options.fetch(:bytesize_limit, 4_096))
          h[:overhead] = Integer(options.fetch(:overhead, 3))
          h[:stateful?] = !!options.fetch(:stateful?, options.fetch(:stateful, false))
          h[:strict?] = h[:stateful?] || !!options.fetch(:strict?, options.fetch(:strict, false))
          h[:per_domain?] = h[:strict?] || !!options.fetch(:per_domain?, options.fetch(:per_domain, true))

          h.freeze
        end

        if strict?
          # Allow non-ICANN domains to be handled the same as ICANN domains.
          @public_suffix_list = PublicSuffix::List.parse(::File.read(PublicSuffix::List::DEFAULT_LIST_PATH), :private_domains=>false)
        end

        unless limit? || bytesize_limit?
          abort 'No limits, nothing to do!'
        end
      end

      def call(env)
        status, headers, body = app.call(env)
        if headers.key?(SET_COOKIE)
          check_cookies env, Rack::Request.new(env),
            normalize_cookie_header(headers[SET_COOKIE])
        end
        [status, headers, body]
      end

      private

      def check_cookies(env, request, cookies)
        default_subdomain = foldcase(request.hostname)

        keys = Hash.new { |h, k| h[k] = Set.new } if stateful?
        count = Hash.new { |h, k| h[k] = 0 }
        bytesize = Hash.new { |h, k| h[k] = 0 } if per_domain?

        cookies.each do |cookie|
          # TODO: Skip "delete" cookies?

          if (subdomain = cookie[COOKIE_DOMAIN_RE, 1])
            foldcase!(subdomain)
          else
            subdomain = default_subdomain
          end

          keys[subdomain] << cookie[COOKIE_KEY_RE] if stateful?
          count[subdomain] += 1
          bytesize[subdomain] += cookie.bytesize + overhead if per_domain?
        end

        if stateful?
          # Fold the request cookies (that aren't also present in the response)
          # into our totals.
          fold(request, keys) do |domain, cookie_bytesize|
            count[domain] += 1
            bytesize[domain] += cookie_bytesize + overhead
          end
        end

        if strict?
          # Add the values for each second-level domain (e.g. example.com) to
          # the values for its subdomains (e.g. foo. and bar.example.com).
          propogate_values(count)
          propogate_values(bytesize)
        end

        check_limit_per_domain(env, count, limit) if limit?

        if bytesize_limit?
          if per_domain?
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
          .map! { |cookie| cookie[COOKIE_KEY_RE] }
          .tap(&:uniq!)

        if bad_cookies.any? && handle(env)
          raise_error "Too much data for cookie(s): #{bad_cookies.join(', ')}"
        end
      end

      def domain(hostname)
        return hostname if hostname =~ Resolv::IPv4::Regex || hostname =~ Resolv::IPv6::Regex

        PublicSuffix.domain(hostname, :list=>public_suffix_list) || hostname
      end

      def handle(env)
        handler.nil? || handler.call(env)
      end

      def normalize_cookie_header(value)
        Array(value)
          .flat_map { |h| h.to_s.split(HEADER_SEP_RE) }
          .tap(&:compact!)
      end

      if String.instance_method(:downcase).arity.abs > 0
        def foldcase(str)
          str.downcase(:fold)
        end

        def foldcase!(str)
          str.downcase!(:fold)
        end
      else
        def foldcase(str)
          str.downcase
        end

        def foldcase!(str)
          str.downcase!
        end
      end

      def fold(request, response_cookie_keys)
        # Assume that all request cookies have a domain of the default
        # subdomain (e.g. foo.example.com) or its second-level domain (e.g.
        # example.com).
        domains = [foldcase(request.hostname)].tap do |a|
          a.unshift(domain(a.first))
          a.uniq!
        end

        request.cookies.each_pair do |key, value|
          # *Try* to prevent double-counting cookies (i.e. on the response
          # and the request).
          next if domains.any? { |domain| response_cookie_keys[domain].include?(key) }

          # *Try* to estimate the upper bound of the size of the cookie and its
          # directives in the original Set-Cookie header.
          # TODO: Replace this with a simpler byte count for efficiency?
          mock_cookie = String.new("#{key}=#{value}").tap do |s|
            s << "; Expires=#{Date.today.httpdate}"
            s << '; Max-Age=123456'
            s << "; Domain=#{domains.last}"
            s << "; Path=#{request.script_name}"
            s << '; Secure' if request.ssl?
            s << '; HttpOnly; SameSite=strict'
          end

          yield domains.first, mock_cookie.bytesize
        end
      end

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
