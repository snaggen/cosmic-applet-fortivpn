vpn = OpenFortiVPN

status-disconnected = Frånkopplad
status-connecting = Ansluter…
status-connected = Ansluten
status-disconnecting = Kopplar från…
status-cert-untrusted = Certifikatet är inte betrott
status-failed = Anslutningen misslyckades
status-interrupted = Anslutningen avbröts
status-unavailable = Inte tillgänglig

connect = Anslut
disconnect = Koppla från
cancel = Avbryt
save = Spara

gateway = Gateway
gateway-placeholder = vpn.example.com:443
gateway-missing = Ange adressen till VPN-gatewayen. För att spara den krävs ett administratörslösenord.
gateway-invalid = Ange värd och port, t.ex. vpn.example.com:443
gateway-unreadable = Inställningarna för gatewayen kunde inte läsas: { $reason }

cert-untrusted-title = Overifierat certifikat
cert-untrusted-body = Certifikatet för { $host } kunde inte verifieras. Lita bara på det om fingeravtrycket stämmer med det som din IT-avdelning anger. För att lita på det krävs ett administratörslösenord.
cert-subject = Utfärdat till
cert-issuer = Utfärdat av
cert-fingerprint = SHA-256-fingeravtryck

error-not-configured = Ingen VPN-gateway är inställd.
error-busy = En annan VPN-anslutning körs redan.
error-auth-failed = Gatewayen avvisade inloggningen.
error-not-authorized = Saknar behörighet att starta VPN:et: { $reason }
error-lost = VPN-anslutningen slutade svara, troligen för att nätverket ändrades.
error-unreachable = VPN-gatewayen går inte att nå: { $reason }
error-stopped = VPN-anslutningen avbröts oväntat.
error-other = VPN:et kunde inte startas: { $reason }

agent-unavailable = VPN-tjänsten körs inte.
cert-untrusted-hint = Ta ställning till gatewayens certifikat i dialogrutan.
always-trust = Lita alltid på det här certifikatet
trust = Lita på

login-dialog-title = Logga in på VPN:et
login-dialog-body = Logga in på { $host } i webbläsaren. Fönstret stängs när du har loggat in.
open-login-page = Öppna inloggningssidan

notify-disconnected = VPN-anslutningen bröts
notify-failed = VPN-anslutningen kunde inte upprättas

settings = Inställningar
change = Ändra
forget = Glöm
gateway-change = Ange den nya adressen till VPN-gatewayen. För att spara den krävs ett administratörslösenord.
certificate = Certifikat
certificate-system = Verifieras av systemet
certificate-trusted = Betrott certifikat (SHA-256)
address = Adress
uptime = Ansluten i
received = Mottaget
sent = Skickat
# Decimaltecken i mängder som 1,5 MB.
decimal-separator = ,

status-reconnecting = Återansluter…
auto-reconnect = Återanslut automatiskt
notify-reconnect-failed = VPN:et kunde inte återansluta
