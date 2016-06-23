require 'uuid'

class UsersController < ApplicationController
  before_filter :find_user, :only => [:show, :edit, :update, :destroy]

  def new
    @user = User.new
    session[:forwarding_url] = params[:login_url]
  end

  def edit
  end

  def sign_in
    @user = User.new
    #@email = params[:email]
    session[:forwarding_url] = params[:login_url]
  end

  def create_session
    user = User.where(:email => params[:email]).first
    user && user.authenticate(params[:password]) ? user : nil
    session[:user_id] = user.email
    user.logged_in = true
    user.current_logged_in_at = Time.now
    user.save
    redirect_to root_path
  end

  def sign_out
    user = User.where(email: params[:email]).first
    #session[:user_id] = user.email
    user.logged_in = false
    user.current_logged_in_at = nil
    user.save
    redirect_to root_path, notice: 'User logged out'
  end

  def sp_edit
    @user = User.where(email: params[:user_id]).first
    render :edit
  end

  def show
  end

  def create
    @user = User.new(user_profile_parameters)
    @user.uid = UUID.generate
    if @user.save
      flash[:notice] = "#{@user.email} signed in."
      redirect_to(session[:forwarding_url] || root_path)
      session.delete(:forwarding_url)
    else
      render "new"
    end
  end

  def update
    @user.update_attributes(user_profile_parameters)

    respond_to do |format|
      if @user.save
        format.html do
          if params[:sp_profile_url]
            redirect_to params[:sp_profile_url] + "?first_name=#{params[:user][:first_name]}&last_name=#{params[:user][:last_name]}"
          else
            redirect_to user_path(@user), notice: 'Profile was successfully updated.'
          end
        end
        format.json { head :no_content }
      else
        format.html { render action: "edit" }
        format.json { render json: @user.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /users/1
  # DELETE /users/1.json
  def destroy
    @user.destroy

    respond_to do |format|
      format.html { redirect_to root_url }
      format.json { head :no_content }
    end
  end

  private

  def find_user
    @user = User.find(params[:id])
  end

  def user_profile_parameters
    params.require(:user).permit(:email, :password, :password_confirmation, :first_name, :last_name, :login_url)
  end

end
