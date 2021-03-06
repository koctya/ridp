class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

    private

  def current_user
    @current_user ||= user = User.where(:email => session[:user_id]).first() if session[:user_id]
  end

  def user_signed_in?
    current_user.signed_in?
  end

  helper_method :current_user, :user_signed_in?
end
