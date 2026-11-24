vpn = VPN

status-disconnected = Frånkopplad
status-connecting = Ansluter…
status-waiting-for-login = Väntar på inloggning i webbläsaren…
status-connected = Ansluten
status-disconnecting = Kopplar från…
status-cert-untrusted = Certifikatet är inte betrott
status-failed = Anslutningen misslyckades

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
trust-and-connect = Lita på och anslut

error-not-configured = Ingen VPN-gateway är inställd.
error-busy = En annan VPN-anslutning körs redan.
error-auth-failed = Gatewayen avvisade inloggningen.
error-not-authorized = Saknar behörighet att starta VPN:et: { $reason }
error-stopped = VPN-anslutningen avbröts oväntat.
error-other = VPN:et kunde inte startas: { $reason }
