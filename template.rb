unless File.read("config/application.rb").include?("config.api_only = true")
  say "❌ This template is intended for API-only Rails apps. Please use the `--api` flag.", :red
  exit
end

gem 'devise'
gem 'devise-jwt'

rails_command("generate devise:install")
rails_command("generate devise User")
rails_command("db:migrate")

registrations_controller = <<~RUBY
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json

  private

  def respond_with(resource, _opts = {})
    if resource.persisted?
      render json: { message: "Signed up successfully.", user: resource }, status: :ok
    else
      render json: { errors: resource.errors.full_messages }, status: :unprocessable_entity
    end
  end
end
RUBY

create_file "app/controllers/users/registrations_controller.rb", registrations_controller

sessions_controller = <<~RUBY
class Users::SessionsController < Devise::SessionsController
  respond_to :json

  private

  def respond_with(resource, _opts = {})
    render json: { message: "Logged in.", user: resource }, status: :ok
  end

  def respond_to_on_destroy
    render json: { message: "Logged out." }, status: :ok
  end
end
RUBY

create_file "app/controllers/users/sessions_controller.rb", sessions_controller

confidential_controller = '
class ConfidentialController < ApplicationController
  def secret
    render json: { message: "#{current_user.email}: I am not a fan of Hotwire!" }
  end
end
'

create_file "app/controllers/confidential_controller.rb", confidential_controller


remove_file "app/models/user.rb"

user_model = <<~RUBY
class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  # devise :database_authenticatable, :registerable,
  #        :recoverable, :rememberable, :validatable,
  #        :jwt_authenticatable,
  #        jwt_revocation_strategy: Devise::JWT::RevocationStrategies::Null

  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :jwt_authenticatable,
         jwt_revocation_strategy: Devise::JWT::RevocationStrategies::Null
end
RUBY
create_file "app/models/user.rb", user_model

environment %(config.session_store :disabled)


insert_into_file "app/controllers/application_controller.rb", """
  include ActionController::MimeResponds
  respond_to :json

  before_action :authenticate_user!
""", after: "class ApplicationController < ActionController::API"

gsub_file "config/routes.rb", "devise_for :users", <<~RUBY
  devise_for :users,
    path: "",
    path_names: {
      sign_in: "login",
      sign_out: "logout",
      registration: "signup"
    },
    controllers: {
      sessions: "users/sessions",
      registrations: "users/registrations"
    }, defaults: { format: :json }

  get "/secret", to: "confidential#secret", defaults: { format: :json }
RUBY

gem "rack-cors"

remove_file "config/initializers/cors.rb"

CORS_FILE = <<~RUBY
# Be sure to restart your server when you modify this file.

# Avoid CORS issues when API is called from the frontend app.
# Handle Cross-Origin Resource Sharing (CORS) in order to accept cross-origin Ajax requests.

# Read more: https://github.com/cyu/rack-cors

# Rails.application.config.middleware.insert_before 0, Rack::Cors do
#   allow do
#     origins "example.com"
#
#     resource "*",
#       headers: :any,
#       methods: [:get, :post, :put, :patch, :delete, :options, :head]
#   end
# end

if Rails.env.production?
  Rails.application.config.middleware.insert_before 0, Rack::Cors do
    allow do
      origins [ENV['FRONTEND_URL'], ENV['BACKEND_URL']]

      resource '*',
        headers: :any,
        expose: ['Authorization'],
        methods: [:get, :post, :put, :patch, :delete, :options, :head],
        credentials: false
    end
  end
else
  Rails.application.config.middleware.insert_before 0, Rack::Cors do
    allow do
      origins '*'

      resource '*',
        headers: :any,
        expose: ['Authorization'],
        methods: [:get, :post, :put, :patch, :delete, :options, :head],
        credentials: false
    end
  end
end
RUBY

create_file  "config/initializers/cors.rb", CORS_FILE

gsub_file "config/initializers/cors.rb", "devise_for :users", <<~RUBY
  devise_for :users,
    path: "",
    path_names: {
      sign_in: "login",
      sign_out: "logout",
      registration: "signup"
    },
    controllers: {
      sessions: "users/sessions",
      registrations: "users/registrations"
    }, defaults: { format: :json }

  get "/secret", to: "confidential#secret", defaults: { format: :json }
RUBY

after_bundle do
  master_key_path = "config/master.key"

  if File.exist?(master_key_path)
    say "🔐 master.key already exists, using existing key."
  else
    say "🔐 Creating new master.key..."
    key = run("rails secret", capture: true).strip
    create_file master_key_path, key + "\n"
    chmod master_key_path, 0600
    say "✅ Created config/master.key"
  end

  secret_key_base = run("rails secret", capture: true).strip
  jwt_secret = run("rails secret", capture: true).strip

  # Write plain content to temp file
  plain_content = <<~YML
  secret_key_base: #{secret_key_base}
  devise:
    jwt_secret_key: #{jwt_secret}
  YML

  create_file "tmp/plain_credentials.yml", plain_content

  # Ruby code to encrypt the credentials file
  encrypt_code = <<~RUBY
    require "rails"
    require "active_support"
    require "active_support/encrypted_file"

    root = Dir.pwd
    credentials_path = File.join(root, "config", "credentials.yml.enc")
    key_path = File.join(root, "config", "master.key")
    plain_path = File.join(root, "tmp", "plain_credentials.yml")

    ActiveSupport::EncryptedFile.new(
      content_path: credentials_path,
      key_path: key_path,
      env_key: "RAILS_MASTER_KEY",
      raise_if_missing_key: true
    ).write(File.read(plain_path))
  RUBY

  # Save and run the Ruby script
  create_file "tmp/encrypt.rb", encrypt_code
  run "bin/rails runner tmp/encrypt.rb"

  # Clean up
  remove_file "tmp/plain_credentials.yml"
  remove_file "tmp/encrypt.rb"

  say "🔐 Credentials encrypted and saved successfully!"

  gsub_file "config/initializers/devise.rb", "  # config.navigational_formats = ['*/*', :html, :turbo_stream]",  <<~RUBY
    # config.navigational_formats = ['*/*', :html, :turbo_stream]

    config.jwt do |jwt|
      jwt.secret = Rails.application.credentials.devise[:jwt_secret_key]
      jwt.dispatch_requests = [
        [ "POST", %r{^/login$} ]
      ]
      jwt.revocation_requests = [
        [ "DELETE", %r{^/logout$} ]
      ]
      jwt.expiration_time = 2.days.to_i
    end

    config.navigational_formats = []

    config.warden do |warden|
      warden.scope_defaults :user, store: false
    end
  RUBY
end

