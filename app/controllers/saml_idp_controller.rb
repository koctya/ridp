class SamlIdpController < SamlIdp::IdpController
  before_filter :find_account
  # layout 'saml_idp'

  #def idp_authenticate(email, password)
  #  true
  #end

  def idp_authenticate(email, password)
    #binding.pry
    user = User.where(:email => params[:email]).first
    #user && user.valid_password?(params[:password]) ? user : nil
  end

#  def idp_make_saml_response(user)
#    encode_SAMLResponse("you@example.com")
#  end
  def idp_make_saml_response(user)
    encode_SAMLResponse(user.email)
  end

  private

  def find_account
    @subdomain = saml_acs_url[/https?:\/\/(.+?)\.example.com/, 1]
    @account = Account.find_by_subdomain(@subdomain)
    render :status => :forbidden unless @account.saml_enabled?
  end

end
