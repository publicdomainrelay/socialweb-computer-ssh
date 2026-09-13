# socialweb-computer-ssh

SSH front door for the social web computer. Connect with an SSH key that has
been associated with an AT Protocol account, and the connection provisions a
fresh compute VM through the [compute market](../atproto-market) — the command
you typed runs inside that VM, and the VM is torn down when it exits.

```
ssh client
  -> socialweb-computer-ssh        (this repo: SSH server + OAuth HTTP server)
       -> badgeBlueKeys lookup     (requester_associate association for the key)
       -> deno run request-vm-ssh  (RFP -> bid -> accept -> cloud-init -> guest)
            -> command runs in the guest, output streams back over SSH
```

## What it does

- **SSH server** accepts public-key authentication and resolves the presented
  key against `com.publicdomainrelay.temp.badgeBlueKeys` records of service
  type `requester_associate` — the association a primary AT Protocol account
  writes when it acknowledges a requester.
- **OAuth HTTP server** runs the AT Protocol OAuth flow so an account can sign
  in, register SSH public keys, and review its associations.
- **Provisioning** shells out through Deno to `request-vm-ssh`, passing the
  OAuth session through a temporary directory.
- **Client options** travel as `LC_` environment variables:

  ```sh
  LC_MY_VAR="secret_value" ssh user@remote_host "echo \$LC_MY_VAR"
  ```

  These carry policy selection and policy arguments as well as plain values
  for the invoked command. Policy mode defaults to `tangled-vouch`; policy
  arguments such as `firstFree` default to `true`.

## Status

In development.
