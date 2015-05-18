
class SamlIdpController < SamlIdp::IdpController
  #before_filter :find_account
  # layout 'saml_idp'

  def idp_authenticate(email, password)
    user = User.where(:email => params[:email]).first
    user && user.authenticate(params[:password]) ? user : nil
    session[:user_id] = user.email
    user
  end

  def idp_make_saml_response(user)

    provider = %[<saml:AttributeStatement><saml:Attribute Name="uid"><saml:AttributeValue>#{user.uid}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="First Name"><saml:AttributeValue>#{user.first_name}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="Last Name"><saml:AttributeValue>#{user.last_name}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>#{user.email}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>]
    encode_SAMLResponse(user.email, { attributes_provider: provider })
    #encode_response(user.email)
  end

  private

  #def find_account
    #@subdomain = saml_acs_url[/https?:\/\/(.+?)\.example.com/, 1]
    #@account = Account.find_by_subdomain(@subdomain)
    #render :status => :forbidden unless @account.saml_enabled?
  #end

end
