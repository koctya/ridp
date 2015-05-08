require 'uuid'

class UsersController < ApplicationController
  before_filter :find_user, :only => [:show, :edit, :update, :destroy]

  def new
    @user = User.new
  end

  def edit
  end

  def show
  end

  def create
    @user = User.new(user_profile_parameters)
    @user.uid = UUID.generate
    #binding.pry
    if @user.save
      redirect_to root_url, :notice => "Signed up!"
    else
      render "new"
    end
  end

  def update
    #binding.pry
    @user.update_attributes(user_profile_parameters)

    respond_to do |format|
      if @user.save
        format.html { redirect_to user_path(@user), notice: 'Profile was successfully updated.' }
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
    params.require(:user).permit(:email, :password, :password_confirmation, :first_name, :last_name)
  end

end
