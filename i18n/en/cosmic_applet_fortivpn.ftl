vpn = VPN

status-disconnected = Disconnected
status-connecting = Connecting…
status-waiting-for-login = Waiting for login in the browser…
status-connected = Connected
status-disconnecting = Disconnecting…
status-cert-untrusted = Certificate not trusted
status-failed = Connection failed

connect = Connect
disconnect = Disconnect
cancel = Cancel
save = Save

gateway = Gateway
gateway-placeholder = vpn.example.com:443
gateway-missing = Enter the address of the VPN gateway. Saving it needs an administrator password.
gateway-invalid = Enter host and port, e.g. vpn.example.com:443
gateway-unreadable = The gateway settings could not be read: { $reason }

cert-untrusted-title = Unverified certificate
cert-untrusted-body = The certificate of { $host } could not be verified. Only trust it if the fingerprint matches the one your IT department gives you. Trusting it needs an administrator password.
cert-subject = Issued to
cert-issuer = Issued by
cert-fingerprint = SHA-256 fingerprint
trust-and-connect = Trust and connect

error-not-configured = No VPN gateway is configured.
error-busy = Another VPN connection is already running.
error-auth-failed = The gateway rejected the login.
error-not-authorized = Not allowed to start the VPN: { $reason }
error-stopped = The VPN connection stopped unexpectedly.
error-other = The VPN could not be started: { $reason }
