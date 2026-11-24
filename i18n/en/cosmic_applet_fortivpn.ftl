vpn = OpenFortiVPN

status-disconnected = Disconnected
status-connecting = Connecting…
status-connected = Connected
status-disconnecting = Disconnecting…
status-cert-untrusted = Certificate not trusted
status-failed = Connection failed
status-interrupted = Connection interrupted
status-unavailable = Unavailable

connect = Connect
disconnect = Disconnect
cancel = Cancel
save = Save

gateway = Gateway
gateway-placeholder = vpn.example.com:443
gateway-missing = Add your VPN account: a name and the address of the VPN gateway. Saving it needs an administrator password.
gateway-invalid = Enter host and port, e.g. vpn.example.com:443
gateway-unreadable = The gateway settings could not be read: { $reason }

cert-untrusted-title = Unverified certificate
cert-untrusted-body = The certificate of { $host } could not be verified. Only trust it if the fingerprint matches the one your IT department gives you. Trusting it needs an administrator password.
cert-subject = Issued to
cert-issuer = Issued by
cert-fingerprint = SHA-256 fingerprint

error-not-configured = No VPN gateway is configured.
error-busy = Another VPN connection is already running.
error-auth-failed = The gateway rejected the login.
error-not-authorized = Not allowed to start the VPN: { $reason }
error-lost = The VPN connection stopped responding, probably because the network changed.
error-unreachable = The VPN gateway cannot be reached: { $reason }
error-stopped = The VPN connection stopped unexpectedly.
error-other = The VPN could not be started: { $reason }

agent-unavailable = The VPN service is not running.
cert-untrusted-hint = Decide about the gateway's certificate in the dialog.
always-trust = Always trust this certificate
trust = Trust

login-dialog-title = Log in to the VPN
login-dialog-body = Log in to { $host } in your browser. This window closes once you have logged in.
open-login-page = Open login page

notify-disconnected = The VPN connection was lost
notify-failed = The VPN connection could not be established

settings = Settings
change = Change
forget = Forget
gateway-change = Change the VPN account. Saving it needs an administrator password.
certificate = Certificate
certificate-system = Verified by the system
certificate-trusted = Trusted certificate (SHA-256)
address = Address
uptime = Connected for
received = Received
sent = Sent
# Decimal separator in amounts such as 1.5 MB.
decimal-separator = .

status-reconnecting = Reconnecting…
auto-reconnect = Reconnect automatically
notify-reconnect-failed = The VPN could not reconnect

password-dialog-title = Log in to the VPN
password-dialog-body = Log in to { $name }.
username = Username
password = Password
otp = One-time code
otp-placeholder = Only if your VPN asks for one
remember-password = Remember password
password-invalid = Enter username and password without line breaks or leading and trailing spaces (username up to 64 bytes, password up to 256); a one-time code has only letters and digits.

add-profile = Add account
remove = Remove
profile-name = Name
profile-name-placeholder = Customer or company
profile-name-invalid = Enter a name of at most 64 characters with a letter or digit.
profile-add-intro = Add a VPN account. Saving it needs an administrator password.
password-login = Log in with username and password (instead of single sign-on)
method-saml = single sign-on
method-password = password
