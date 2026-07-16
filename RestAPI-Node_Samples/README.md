# RestAPI Node Samples for Luna Network HSM

Node.js ports of `RestAPI-Python_Samples` from [ThalesGroup/luna-samples](https://github.com/ThalesGroup/luna-samples), plus read-only monitoring samples.

> These samples are for appliance **management** tasks only (not crypto).
> Some operations are destructive. Failed SO logins can zeroize the HSM.
>
> Pass hostnames and credentials on the command line / via environment variables only.
> Do not commit real hostnames, usernames, or passwords.

## Environment

```powershell
$env:LUNA_APPLIANCE_PASSWORD = "<appliance-user-password>"
$env:LUNA_SO_PASSWORD = "<so-password>"   # only for SO-required samples
# Lab appliances with self-signed certs (opt-in; TLS verify is ON by default):
$env:LUNA_REST_INSECURE_TLS = "1"
```

## Python-parity samples

```powershell
node client_list.js <hsm-host> <appliance-user>
node client_show.js <hsm-host> <appliance-user>
node client_delete.js <hsm-host> <appliance-user>
node partition_list.js <hsm-host> <appliance-user>
node partition_create.js <hsm-host> <appliance-user>
node partition_delete.js <hsm-host> <appliance-user>
node user_list.js <hsm-host> <appliance-user>
node user_create.js <hsm-host> <appliance-user>
node user_delete.js <hsm-host> <appliance-user>
node user_set_certificate.js <hsm-host> <appliance-user>
node change_role_password.js <hsm-host> <appliance-user>
node certificate_based_authentication.js <hsm-host>
```

## Monitoring samples (read-only)

```powershell
node monitor_overview.js <hsm-host> <appliance-user>
node appliance_info.js <hsm-host> <appliance-user>
node monitor_cpu.js <hsm-host> <appliance-user>
node monitor_memory.js <hsm-host> <appliance-user>
node monitor_disk.js <hsm-host> <appliance-user>
node monitor_sensors.js <hsm-host> <appliance-user>
node monitor_services.js <hsm-host> <appliance-user>
node monitor_network.js <hsm-host> <appliance-user>
node monitor_ntp.js <hsm-host> <appliance-user>
node monitor_syslog.js <hsm-host> <appliance-user>
node monitor_webserver.js <hsm-host> <appliance-user>
node hsm_info.js <hsm-host> <appliance-user>
node hsm_metrics.js <hsm-host> <appliance-user>
```

## Notes

- Password prompts mask input (or use env vars above).
- TLS certificate verification is enabled by default. Set `LUNA_REST_INSECURE_TLS=1` only for lab/self-signed appliances.
- Monitoring samples are GET-only. Mutating samples (`*_create`, `*_delete`, etc.) can change appliance state — use with care.
- Failed SO logins can zeroize the HSM.
