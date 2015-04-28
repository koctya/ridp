class UsersController < ApplicationController

  def new
    @user = User.new
  end

  def create
    #binding.pry
    @user = User.new(user_profile_parameters)
    if @user.save
      redirect_to root_url, :notice => "Signed up!"
    else
      render "new"
    end
  end

  private
  def user_profile_parameters
    params.require(:user).permit(:email, :password, :password_confirmation)
  end

end
