class AddUidToUser < ActiveRecord::Migration
  def change
    add_column :users, :uid, :string
    add_index :users, :uid
  end
end
