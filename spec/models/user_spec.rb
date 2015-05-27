require 'rails_helper'

describe User do

  before { @user = User.new(name: "Example User", email: "user@example.com", password: "foobar", password_confirmation: "foobar") }

  subject { @user }

  it { should respond_to(:name) }
  it { should respond_to(:email) }
  it { should respond_to(:password_digest) }
  it { should respond_to(:password) }
  it { should respond_to(:password_confirmation) }
  it { should respond_to(:authenticate) }

  it { should be_valid }

  describe "return value of authenticate method" do
    before(:all) { @user.save! }
    let(:found_user) { User.find_by(email: @user.email) }

    describe "with a valid password" do
      it { should eq found_user.authenticate(@user.password) }
    end

    describe "with an invalid password" do
      let(:user_for_invalid_password) { found_user.authenticate('invalid') }

      it { should_not eq user_for_invalid_password }
      specify { expect(user_for_invalid_password).to be_false }
    end
  end
end
