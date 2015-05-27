# encoding: utf-8
module SamlIdp
  class IdpController < ActionController::Base
    include SamlIdp::Controller

    unloadable  unless Rails::VERSION::MAJOR >= 4

    protect_from_forgery

    before_filter :validate_saml_request
    skip_before_filter :validate_saml_request, :only => [:logout]
    before_filter :validate_saml_slo_request, :only => [:logout]

    def new
      user = User.where(:email => params[:email]).first
      #binding.pry
      render :template => "saml_idp/idp/new"
    end

    def create
      unless params[:email].blank? && params[:password].blank?
        person = idp_authenticate(params[:email], params[:password])
        if person.nil?
          @saml_idp_fail_msg = "Incorrect email or password."
        else
          @saml_response = idp_make_saml_response(person)
          session[:user_id] = person.email
          render :template => "saml_idp/idp/saml_post", :layout => false
          return
        end
      end
      render :template => "saml_idp/idp/new"
    end

    def logout
      #session[:user_id] = nil
      saml_request = params[:SAMLRequest]

      decode_SAMLRequest(saml_request)
      sid = @saml_request_id
      req = @saml_request
      issue_instant = @saml_request[/IssueInstant=['"](.+?)['"]/, 1]
      dest = @saml_request[/Destination=['"](.+?)['"]/, 1]
      binding.pry
      #@response = OneLogin::RubySaml::Logoutresponse.new(params[:SAMLRequest])
      #redirect_to root_url, :notice => "Logged out!"

      _person, _logout = idp_slo_authenticate(params[:name_id])
      if _person && _logout
        @saml_slo_response = idp_make_saml_slo_response(_person)
      else
        @saml_idp_fail_msg = 'User not found'
        logger.error "User with email #{params[:name_id]} not found"
        @saml_slo_response = encode_SAML_SLO_Response(params[:name_id])
      end
      render :template => "saml_idp/idp/saml_slo_post", :layout => false
    end

    protected

      def idp_authenticate(email, password)
        raise "Not implemented"
      end

      def idp_make_saml_response(person)
        raise "Not implemented"
      end

      def idp_slo_authenticate(email)
        raise "Not implemented"
      end

      def idp_make_saml_slo_response(person)
        raise "Not implemented"
      end

    def validate_saml_slo_request(saml_request = params[:SAMLRequest])
      decode_SAML_SLO_Request(saml_request)
    end

    def decode_SAML_SLO_Request(saml_request)
      zstream = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      @saml_slo_request = zstream.inflate(Base64.decode64(saml_request))
      zstream.finish
      zstream.close
      @saml_slo_request_id = @saml_slo_request[/ID=['"](.+?)['"]/, 1]
      #binding.pry
      #@saml_slo_acs_url = @saml_slo_request[/AssertionConsumerLogoutServiceURL=['"](.+?)['"]/, 1]
      @single_logout_service_url = "http://localhost:3001/saml/logout"
    end

    def encode_SAML_SLO_Response(nameID, opts = {})
      now = Time.now.utc
      response_id, reference_id = UUID.generate, UUID.generate
      audience_uri = opts[:audience_uri] #|| @saml_slo_acs_url[/^(.*?\/\/.*?\/)/, 1]
      issuer_uri = opts[:issuer_uri] || (defined?(request) && request.url.split("?")[0]) || "http://example.com"

      assertion = %[<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{reference_id}" IssueInstant="#{now.iso8601}" Version="2.0"><Issuer>#{issuer_uri}</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{nameID}</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="#{@saml_slo_request_id}" NotOnOrAfter="#{(now+3*60).iso8601}" Recipient="#{@single_logout_service_url}"></SubjectConfirmationData></SubjectConfirmation></Subject><Conditions NotBefore="#{(now-5).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}"><AudienceRestriction><Audience>#{audience_uri}</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>#{nameID}</AttributeValue></Attribute></AttributeStatement><AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{reference_id}"><AuthnContext><AuthnContextClassRef>urn:federation:authentication:windows</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>]

      digest_value = Base64.encode64(algorithm.digest(assertion)).gsub(/\n/, '')

      signed_info = %[<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"></ds:SignatureMethod><ds:Reference URI="#_#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"></ds:DigestMethod><ds:DigestValue>#{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>]

      signature_value = sign(signed_info).gsub(/\n/, '')

      signature = %[<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{signed_info}<ds:SignatureValue>#{signature_value}</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>#{self.x509_certificate}</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature>]

      assertion_and_signature = assertion.sub(/Issuer\>\<Subject/, "Issuer>#{signature}<Subject")

      xml = %[<samlp:LogoutResponse ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{@single_logout_service_url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="#{@saml_slo_request_id}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:LogoutResponse>]
binding.pry
      Base64.encode64(xml)
    end

    def encode_SAMLResponse(nameID, opts = {})
      now = Time.now.utc
      response_id, reference_id = UUID.generate, UUID.generate
      audience_uri = opts[:audience_uri] || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
      #binding.pry
      issuer_uri = opts[:issuer_uri] || (defined?(request) && request.url)
      attributes_statement = attributes(opts[:attributes_provider], nameID)

      assertion = %[<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{reference_id}" IssueInstant="#{now.iso8601}" Version="2.0"><saml:Issuer Format="urn:oasis:names:SAML:2.0:nameid-format:entity">#{issuer_uri}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{nameID}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="#{@saml_request_id}" NotOnOrAfter="#{(now+3*60).iso8601}" Recipient="#{@saml_acs_url}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="#{(now-5).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}"><saml:AudienceRestriction><saml:Audience>#{audience_uri}</saml:Audience></saml:AudienceRestriction></saml:Conditions>#{attributes_statement}<saml:AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{reference_id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:federation:authentication:windows</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>]

      digest_value = Base64.encode64(algorithm.digest(assertion)).gsub(/\n/, '')

      signed_info = %[<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"></ds:SignatureMethod><ds:Reference URI="#_#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"></ds:DigestMethod><ds:DigestValue>#{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>]

      signature_value = sign(signed_info).gsub(/\n/, '')

      signature = %[<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{signed_info}<ds:SignatureValue>#{signature_value}</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>#{self.x509_certificate}</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature>]

      assertion_and_signature = assertion.sub(/Issuer\>\<saml:Subject/, "Issuer>#{signature}<saml:Subject")

      xml = %[<samlp:Response ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{@saml_acs_url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="#{@saml_request_id}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:Response>]

      Base64.encode64(xml)
    end

  end
end
