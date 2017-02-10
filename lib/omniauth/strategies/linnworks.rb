require 'omniauth'
require 'faraday'

module OmniAuth
  module Strategies
    class Linnworks
      include OmniAuth::Strategy

      args [:application_id, :application_secret]
      option :name, 'linnworks'
      option :application_id, nil
      option :application_secret, nil

      option :client_options, {
        :tracking => nil,
        :authorize_url => '/Authorization/Authorize',
        :site => 'http://apps.linnworks.net'
      }

      def request_phase # rubocop:disable MethodLength
        authorize_url = "#{options.client_options.site}#{options.client_options.authorize_url}/#{options.application_id}"
        authorize_url += "?tracking=#{options.client_options.tracking}" if options.client_options.tracking

        redirect authorize_url
      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      end

      def callback_phase # rubocop:disable MethodLength
        fail(OmniAuth::NoSessionError, "Session Expired") if session["oauth"].nil?

        params = @env['omniauth.params']

        @response = Faraday.post('https://api.linnworks.net//api/Auth/AuthorizeByApplication', {"applicationId" => options.application_id, 
                                                                                      "applicationSecret" => options.application_secret,
                                                                                      "token" => params['token']})

        fail!(:error, Exception.new(JSON.parse(@response.body))) unless @response.success?
      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      rescue ::OAuth::Unauthorized => e
        fail!(:invalid_credentials, e)
      rescue ::OmniAuth::NoSessionError => e
        fail!(:session_expired, e)
      end

      def raw_info
        @raw_info ||= JSON.parse(response.body)
      end

      uid { raw_info['Id'].to_s }

      credentials do
        {"token" => raw_info['Token'] }
      end        
      
      private 

      attr_reader :response

    end
  end
end
