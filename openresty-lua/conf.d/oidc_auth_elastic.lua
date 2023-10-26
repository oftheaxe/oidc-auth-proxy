-- oidc_auth_elastic.lua
local http = require("resty.http")

local session = require("resty.session")
local s = session.start()

-- define options for oidc authentication
local opts = {
    redirect_uri = ngx.var.redirect_uri,
    discovery = ngx.var.discovery,
    client_id = ngx.var.client_id,
    client_secret = ngx.var.client_secret,
    redirect_uri_scheme = ngx.var.redirect_uri_scheme,
    logout_path = "/logout",
    redirect_after_logout_uri = ngx.var.redirect_after_logout_uri,
    redirect_after_logout_with_id_token_hint = false,
    accept_none_alg = false,
    accept_unsupported_alg = false,
    renew_access_token_on_expiry = true,
    access_token_expires_in = 3600,
    revoke_tokens_on_logout = true,
    session_contents = {id_token=true, access_token=true}
}

local function set_authorization_header(username, password)
    -- Combine the credentials as username:password
    local credentials = username .. ":" .. password

    -- Encode the credentials in base64
    local base64_credentials = ngx.encode_base64(credentials)

    -- Set the "Authorization" header
    ngx.req.set_header("Authorization", "Basic " .. base64_credentials)
end

-- Helper function to determine if realm_role exists in id_token groups
local function has_value(tab, val)
  for index, value in ipairs(tab) do
    if value == val then
      return true
    end
  end
  return false
end

-- Helper function to store session state
local function save_session(username, roles)
  s.data.user_exists = true
  s:save()
end

local function ensure_user_exists(username, default_password, roles)
  -- Check if the user exists
  local httpc = http.new()
  local es_api_user = ngx.var.es_api_user
  local es_api_password = ngx.var.es_api_password
  local api_credentials = es_api_user .. ":" .. es_api_password
  local base64_api_credentials = ngx.encode_base64(api_credentials)
  local request_headers = {
      ["Authorization"] = "Basic " .. base64_api_credentials,
      ["Content-Type"] = "application/json"
  }
  local request_body = '{"roles": [ ' .. roles .. ' ], "password":"' .. default_password .. '"}'
  local user_api_uri = ngx.var.elastic_uri .. "/_security/user/" .. username

  -- Create/update user and roles
  local create_res, create_err = httpc:request_uri(user_api_uri, {
      method = "POST",
      headers = request_headers,
      body = request_body
  })

  if not create_res then
    ngx.log(ngx.ERR, "Request failed: ", create_err)
    return
  end

  if create_res.status == 200 then
    ngx.log(ngx.INFO, "User created/updated successfully")
    save_session(username, roles)
  else
    ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
    ngx.log(ngx.ERR, "Error creating user: ", create_err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
end

local function login_allowed(groups)
  local has_admin = has_value(groups, ngx.var.admin_group)
  local has_user = has_value(groups, ngx.var.user_group)

  if has_admin or has_user then
    return true
  else
    return false
  end  
end

local function get_roles_from_groups(groups)
  -- Define the group-to-role mapping
  local group_role_mapping_json = ngx.var.group_role_mapping_json
  
  -- Decode the JSON string to a Lua table
  local json = require("cjson")
  local group_role_mapping = json.decode(group_role_mapping_json)
  local roles = {}

  for _, group in ipairs(groups) do
      local role = group_role_mapping[group]
      if role then
          table.insert(roles, '"' .. role .. '"')
      end
  end

  return table.concat(roles, ', ')
end

local function main()

  -- Call introspect for OAuth 2.0 Bearer Access Token validation
  local res, err = require("resty.openidc").authenticate(opts)

  -- Do not proceed if error
  if err then
    ngx.status = 403
    ngx.log(ngx.ERR, "Error while processing ", err)
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  ngx.log(ngx.INFO, "OIDC login succeeded")

  -- If user is allowed to login, rewrite header to authenticate, otherwise forbid access
  if login_allowed(res.id_token.groups) then
    -- Credentials for user
    local remote_user = res.id_token.preferred_username
    local users_password = ngx.var.default_user_password
    
    -- Get session data
    local user_exists = s.data.user_exists
    
    -- If already a user session exists
    if user_exists then    
      set_authorization_header(remote_user, users_password)
    else            
      -- Map keycloak realm role names to elasticsearch role names
      local roles = get_roles_from_groups(res.id_token.groups)
      
      ngx.log(ngx.INFO, "User session does not exist yet, ensuring user exists, then setting header")
      ensure_user_exists(remote_user, users_password, roles)
      set_authorization_header(remote_user, users_password)
    end
    
  else
    ngx.status = 403
    ngx.log(ngx.ERR, "User is not allowed to login")
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end

end

main()