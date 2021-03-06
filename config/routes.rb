Rails.application.routes.draw do

  #post '/saml/consume' => 'saml#consume'

  get 'home/index'

  get '/saml/auth' => 'saml_idp#new'
  post '/saml/auth' => 'saml_idp#create'
  get '/saml/logout' => 'saml_idp#logout'

  resources :users
  get '/sp_edit' => 'users#sp_edit'
  get '/signin' => 'users#sign_in', as: :signin
  post '/signin' => 'users#create_session'
  get '/signout' => 'users#sign_out', as: :signout


  get '/signup' => 'users#new'
  #post '/users' => 'users#create', as: :users

  #get 'saml_idp/idp_authenticate'
  #get 'saml_idp/idp_make_saml_response'

  # The priority is based upon order of creation: first created -> highest priority.
  # See how all your routes lay out with "rake routes".

  # You can have the root of your site routed with "root"
  root 'home#index'

  # Example of regular route:
  #   get 'products/:id' => 'catalog#view'

  # Example of named route that can be invoked with purchase_url(id: product.id)
  #   get 'products/:id/purchase' => 'catalog#purchase', as: :purchase

  # Example resource route (maps HTTP verbs to controller actions automatically):
  #   resources :products

  # Example resource route with options:
  #   resources :products do
  #     member do
  #       get 'short'
  #       post 'toggle'
  #     end
  #
  #     collection do
  #       get 'sold'
  #     end
  #   end

  # Example resource route with sub-resources:
  #   resources :products do
  #     resources :comments, :sales
  #     resource :seller
  #   end

  # Example resource route with more complex sub-resources:
  #   resources :products do
  #     resources :comments
  #     resources :sales do
  #       get 'recent', on: :collection
  #     end
  #   end

  # Example resource route with concerns:
  #   concern :toggleable do
  #     post 'toggle'
  #   end
  #   resources :posts, concerns: :toggleable
  #   resources :photos, concerns: :toggleable

  # Example resource route within a namespace:
  #   namespace :admin do
  #     # Directs /admin/products/* to Admin::ProductsController
  #     # (app/controllers/admin/products_controller.rb)
  #     resources :products
  #   end
end
