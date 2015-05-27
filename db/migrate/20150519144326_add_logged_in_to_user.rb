class AddLoggedInToUser < ActiveRecord::Migration
  def change
    add_column :users, :logged_in, :boolean
    add_column :users, :current_logged_in_at, :datetime
  end
end
