# Configure Self hosted Gitlab instance

### Create an OAuth Application in Gitlab

Create an OAuth application in your Gitlab instance that allows opkssh access.

1. Go to the Gitlab Admin page
2. Go to Applications, add a new application
3. Give it a descriptive name (Users will see this name when they authorize opkssh)
4. For the redirect URI's enter:
    ```
    http://localhost:3000/login-callback
    http://localhost:10001/login-callback
    http://localhost:11110/login-callback 
    ```
5. Deselect Trusted and Confidential.
6. Select the scopes: `openid`, `profile` and `email`

Create the application and note the Application ID.

### Configure the client

Add the configuration in the [config file](../README.md#client-config-file)

```
providers:
  - alias: my-gitlab
    issuer: https://my-gitlab-url.com
    client_id: <Application ID>
    scopes: openid email
    access_type: offline
    prompt: consent
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback
```

You can then log in using your Gitlab instance via

```
opkssh login my-gitlab
```

### Configure the server

Add the Gitlab URL and Application ID to the [providers file](../README.md#etcopkproviders) on the server:

```
https://my-gitlab-url.com <Application ID> 24h
```

Then add identities to the policy to allow those identities to SSH to the server:

```
opkssh add root alice@example.com https://my-gitlab-url.com
```
