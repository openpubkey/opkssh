# Configuring Google for OPKSSH

OPKSSH ships with a default Google client ID so that you can try it out without any setup.
That client ID is shared by everyone using OPKSSH's defaults and can stop working at any time, as it did in [#617](https://github.com/openpubkey/opkssh/issues/617).
To use Google with OPKSSH in production, register your own client ID as described here. It takes about 10 minutes.

**Something not working?** Open a new issue on <https://github.com/openpubkey/opkssh>

## Setup

You will create an OAuth client in a Google Cloud project and configure it with OPKSSH's three redirect URIs:

```
http://localhost:3000/login-callback
http://localhost:10001/login-callback
http://localhost:11110/login-callback
```

### 1. Configure the Google Auth Platform

Sign into the [Google Cloud console](https://console.cloud.google.com/) and select or create the project that will own the OAuth client.
Use a project dedicated to OPKSSH, or one where the client will not be deleted by accident.

Open the [Google Auth Platform](https://console.developers.google.com/auth/overview).
If it says that the Google Auth Platform is not configured yet, click **Get started** and fill in:

1. **App Information**: an app name users will recognize on the consent screen, such as `OPKSSH`, and a support email.
2. **Audience**:
   - **Internal** if everyone who will SSH is in your Google Workspace organization. Only members of the organization can then log in.
   - **External** otherwise. Any Google account can then log in, and the `/etc/opk/auth_id` policy on your servers decides who gets access.
3. **Contact Information**: an email address for notifications about the project.
4. Agree to the Google API Services User Data Policy, then click **Create**.

OPKSSH only requests the `openid`, `email` and `profile` scopes.
For an app that only requests these, Google does not require app verification, and an External app works while in the **Testing** publishing status, without listing test users.
See [Google's documentation on publishing status](https://support.google.com/cloud/answer/15549945).

### 2. Create the OAuth client

In the Google Auth Platform, open **Clients** and click **Create client**.

- **Application type**: Web application
- **Name**: `opkssh`, or any name you like
- **Authorized redirect URIs**: add the three redirect URIs, exactly as written above. Do not add a `/` at the end.

Leave **Authorized JavaScript origins** empty and click **Create**.

Google now shows the **client ID** and the **client secret**.
Copy both: Google shows the full client secret only once.
If you lose it, add a new secret to the client on the [Clients page](https://console.developers.google.com/auth/clients).

Google requires the client secret even though OPKSSH runs on your users' computers, where it cannot be kept secret.
OPKSSH treats it as a public value, like the client ID.

Changes to a client's redirect URIs can take from 5 minutes to a few hours to take effect.

### 3. Update the client ID on the servers and clients

On each server with OPKSSH installed, edit `/etc/opk/providers` (`%ProgramData%\opk\providers` on Windows) so that the Google line uses your client ID.
If the file has a line for `https://accounts.google.com` with another client ID, replace that line.

```
https://accounts.google.com <CLIENT-ID> 24h
```

To test, run `opkssh login --provider="https://accounts.google.com,<CLIENT-ID>,<CLIENT-SECRET>"` on a client, then SSH to the server.

To make `opkssh login google` use your client ID, check whether you have a client config at `~/.opk/config.yml`.
If not, create one by running `opkssh login --create-config`.
Then edit `~/.opk/config.yml` and change the entry for Google to use your client ID and client secret:

```yaml
  - alias: google
    issuer: https://accounts.google.com
    client_id: <CLIENT-ID>
    client_secret: <CLIENT-SECRET>
    scopes: openid email profile
    access_type: offline
    prompt: consent
    redirect_uris:
      - http://localhost:3000/login-callback
      - http://localhost:10001/login-callback
      - http://localhost:11110/login-callback
```

For more information see: [opkssh configuration files](../config.md).

### 4. Test

Run `opkssh login google` on the client and sign in with your Google account.
It should finish without error. Then SSH to the server.

## Troubleshooting (Common Issues)

### Error 401: disabled_client or deleted_client

```
Access blocked: Authorization Error
The OAuth client was disabled.
Error 401: disabled_client
```

The OAuth client that `opkssh login` used is disabled or deleted.
If it is OPKSSH's default client ID, register your own as described above.

If it is your own client, check it on the [Clients page](https://console.developers.google.com/auth/clients) of the Google Auth Platform.
Google deletes OAuth clients that have not been used for six months, and sends an email 30 days before.
Deleted clients can usually be restored for 30 days.
See [Google's documentation on managing OAuth clients](https://support.google.com/cloud/answer/15549257#unused-client-deletion).

### Error 400: redirect_uri_mismatch

The client does not have the redirect URI that OPKSSH used.
Check that the client is of type "Web application" and has all three redirect URIs, with `http`, `localhost`, the port and `/login-callback` exactly as written above, and no `/` at the end.
Changes to redirect URIs can take a few hours to take effect.

### Error 403: org_internal

The client's audience is **Internal**, and the Google account you logged in with is not in the organization that owns the project.
Log in with an account from the organization, or change the audience to **External** in the Google Auth Platform.

### Server rejects the login

If `opkssh login` works but SSH does not, check the server log: `/var/log/opkssh.log` on Linux, `%ProgramData%\opk\logs\opkssh.log` on Windows.
The client ID in the server's `/etc/opk/providers` must be the same as the one the client logged in with.
