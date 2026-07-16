# RestAPI Node Samples for Luna Network HSM

Node.js ports of `RestAPI-Python_Samples` from [ThalesGroup/luna-samples](https://github.com/ThalesGroup/luna-samples).

> These samples are for appliance **management** tasks only (not crypto).
> Some operations are destructive. Failed SO logins can zeroize the HSM.

## Environment

```powershell
$env:LUNA_APPLIANCE_PASSWORD = "<appliance-user-password>"
$env:LUNA_SO_PASSWORD = "<so-password>"   # only for SO-required samples
```

## Examples

```powershell
node client_list.js <hsm-host> admin
node partition_list.js <hsm-host> admin
node user_list.js <hsm-host> admin
```
