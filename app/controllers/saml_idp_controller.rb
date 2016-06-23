
class SamlIdpController < SamlIdp::IdpController
  #before_filter :find_account
  # layout 'saml_idp'

  def idp_authenticate(email, password)
    user = User.where(:email => params[:email]).first
    user && user.authenticate(params[:password]) ? user : nil
    if user
      session[:user_id] = user.email
      user.logged_in = true
      user.current_logged_in_at = Time.now
      user.save
    end
    user
  end

  def idp_make_saml_response(user)

    provider = %[<saml:AttributeStatement><saml:Attribute Name="uid"><saml:AttributeValue>#{user.uid}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="firstName"><saml:AttributeValue>#{user.first_name}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="lastName"><saml:AttributeValue>#{user.last_name}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>#{user.email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>]
    issuer_uri = @saml_request[/<saml:Issuer>(.+?)<\/saml:Issuer>/, 1]
    encode_SAMLResponse(user.email, { attributes_provider: provider, issuer_uri: issuer_uri })
    #encode_response(user.email)
  end

  def idp_slo_authenticate(email)
    user = User.where(:email => email).first
    if user.logged_in?
      session[:user_id] = nil
      user.logged_in = false
      user.current_logged_in_at = nil
      user.save
    end
    [user, !user.logged_in]
  end

  def idp_make_saml_slo_response(user)
    issuer_uri = @saml_request[/<saml:Issuer>(.+?)<\/saml:Issuer>/, 1]
    encode_SAML_SLO_Response(user.email, issuer_uri: issuer_uri )
  end

  private

end
