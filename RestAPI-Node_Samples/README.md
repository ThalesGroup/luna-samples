# RestAPI Node Samples for Luna Network HSM

Node.js ports of `RestAPI-Python_Samples` from [ThalesGroup/luna-samples](https://github.com/ThalesGroup/luna-samples).

> These samples are for appliance **management** tasks only (not crypto).
> Some operations are destructive. Failed SO logins can zeroize the HSM.

## Environment

```powershell
$env:LUNA_APPLIANCE_PASSWORD = "<appliance-user-password>"
$env:LUNA_SO_PASSWORD = "<so-password>"   # only for SO-required samples
# Lab appliances with self-signed certs (opt-in; TLS verify is ON by default):
$env:LUNA_REST_INSECURE_TLS = "1"
```

## Examples

```powershell
node client_list.js <hsm-host> admin
node partition_list.js <hsm-host> admin
node user_list.js <hsm-host> admin
```

## Notes

- Password prompts mask input (or use env vars above).
- TLS certificate verification is enabled by default. Set `LUNA_REST_INSECURE_TLS=1` only for lab/self-signed appliances (same idea as Python `verify=False`).
- Some operations are destructive. Failed SO logins can zeroize the HSM.
