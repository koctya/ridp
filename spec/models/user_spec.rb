require 'rails_helper'

describe User do

  let(:user) { User.create(first_name: "John", last_name: "Smith", email: "user@example.com", password: "foobar", password_confirmation: "foobar") }

  subject { user }

  it { should respond_to(:first_name) }
  it { should respond_to(:last_name) }
  it { should respond_to(:email) }
  it { should respond_to(:password_digest) }
  it { should respond_to(:password) }
  it { should respond_to(:password_confirmation) }
  it { should respond_to(:authenticate) }

  it { should be_valid }

  describe "return value of authenticate method" do
    #before(:all) { user.save! }
    let(:found_user) { User.find_by(email: user.email) }

    describe "with a valid password" do
      it { should eq found_user.authenticate(user.password) }
    end

  end
end
