# 🔥 Graylog Netflow Firewall Analyzer

Ett Python-skript som hämtar Netflow-trafik från Graylog och använder Claude AI för att rekommendera brandväggsregler — anpassat för Meraki-brandväggar med NetFlow v9.

---

## 📋 Innehåll

- [Vad gör skriptet?](#vad-gör-skriptet)
- [Hur koden fungerar](#hur-koden-fungerar)
- [Installation](#installation)
- [Konfiguration (.env)](#konfiguration-env)
- [Kommandon](#kommandon)
- [Förstå utskriften](#förstå-utskriften)
- [Vanliga fel](#vanliga-fel)

---

## Vad gör skriptet?

```
Meraki Brandvägg
      │
      │  NetFlow v9 (UDP 2055)
      ▼
   Graylog                   ← Tar emot och lagrar all nätverkstrafik
      │
      │  REST API (HTTP)
      ▼
graylog_analyzer.py          ← Hämtar och aggregerar trafiken
      │
      │  Sammanfattning av trafikmönster
      ▼
  Claude AI                  ← Analyserar och genererar brandväggsregler
      │
      ▼
firewall_analysis_DATUM.md   ← Rapport sparas lokalt
```

Skriptet gör tre saker:

1. **Hämtar** tusentals Netflow-meddelanden från Graylog via REST API
2. **Aggregerar** rå trafik till meningsfulla mönster (vilka subnät pratar med vilka, på vilka portar)
3. **Skickar** en sammanfattning till Claude AI som returnerar konkreta brandväggsrekommendationer

---

## Hur koden fungerar

### Steg 1 — Anslutning till Graylog (`test_graylog_connection`)
Skriptet ansluter till Graylog REST API med Basic Auth (användarnamn + lösenord).
Verifierar att Graylog svarar och att inloggningen fungerar.

### Steg 2 — Hämta Netflow-meddelanden (`fetch_netflow`)
Anropar Graylogs sök-API:
```
GET /api/search/universal/relative?query=*&range=86400&limit=5000
```
- `range` = hur många sekunder bakåt i tid att söka
- `limit` = max antal meddelanden att hämta
- Returnerar råa Netflow-poster med fält som `nf_src_address`, `nf_dst_address`, `nf_l4_dst_port` etc.

### Steg 3 — Aggregera flöden (`aggregate_flows`)
Istället för att skicka tusentals enskilda rader till AI:n grupperas trafiken:

```
Rå data (10 000 rader):
  10.0.1.5 → 10.0.2.10:443/TCP  (162 bytes)
  10.0.1.7 → 10.0.2.10:443/TCP  (891 bytes)
  10.0.1.5 → 10.0.2.10:443/TCP  (234 bytes)
  ...

Aggregerat (1 rad):
  10.0.1.0/24 → 10.0.2.0/24  443/TCP  1287 bytes  3 flows  2 src IPs
```

IP-adresser konverteras till /24-subnät för att se mönster på nätverksnivå.

### Steg 4 — Klassificera trafik (`split_flows`)
Varje flöde kategoriseras som antingen:
- **Internt** — destination är ett privat IP (10.x, 172.16-31.x, 192.168.x)
- **Internet-bound** — destination är ett publikt IP

### Steg 5 — Bygg sammanfattning (`build_prompt_summary`)
Skapar en läsbar textsammanfattning med:
- Top 60 interna flöden (sorterat på volym)
- Top 60 internet-flöden
- Mest använda portar/protokoll
- Mest aktiva källsubnät

### Steg 6 — Claude AI-analys (`analyze_with_claude`)
Sammanfattningen skickas till Anthropic API med ett detaljerat systemprompt.
Claude returnerar:
- Zonindelning av ditt nätverk
- Konkreta brandväggsregler i tabellformat
- Säkerhetsproblem och anomalier
- Top 5 Quick Wins att implementera direkt

### Steg 7 — Spara rapport (`save_report`)
Resultatet sparas som en Markdown-fil:
```
firewall_analysis_20260423_110124.md
```

---

## Installation

### Krav
- Python 3.8 eller senare
- Graylog nåbart över nätverket
- Anthropic API-konto med credits

### 1. Installera Python-paket
```powershell
cd C:\graylog-analyzer
python -m pip install -r requirements.txt
```

### 2. Konfigurera .env
```powershell
copy .env.example .env
notepad .env
```

---

## Konfiguration (.env)

```env
# ── Graylog ─────────────────────────────────
GRAYLOG_URL=http://192.168.8.2:9000      # IP till din Graylog-server
GRAYLOG_USER=admin                        # Graylog-användarnamn
GRAYLOG_PASS=ditt-lösenord               # Graylog-lösenord

# ── Claude AI ───────────────────────────────
ANTHROPIC_API_KEY=sk-ant-...             # Från console.anthropic.com

# ── Netflow-fältnamn (Meraki/NetFlow v9) ────
FIELD_SRC_IP=nf_src_address
FIELD_DST_IP=nf_dst_address
FIELD_DST_PORT=nf_l4_dst_port
FIELD_PROTOCOL=nf_proto_name
FIELD_BYTES=nf_in_bytes
FIELD_PACKETS=nf_in_pkts
```

---

## Kommandon

### Testa anslutning och hitta fältnamn
```powershell
python graylog_analyzer.py --list-fields
```
**Vad det gör:** Ansluter till Graylog och skriver ut fältnamnen från de 5 senaste meddelandena.
Använd detta för att verifiera att anslutningen fungerar och för att se exakt vad dina Netflow-fält heter.

---

### Kör analys med AI (standard)
```powershell
python graylog_analyzer.py
```
**Vad det gör:** Hämtar 5 000 meddelanden från de senaste 24 timmarna, aggregerar trafiken och skickar till Claude AI. Sparar rapporten som `.md`-fil.

---

### Ändra tidsperiod
```powershell
python graylog_analyzer.py --hours 48
python graylog_analyzer.py --hours 168    # 7 dagar
```
**Vad det gör:** Styr hur långt bakåt i tid skriptet söker.
Rekommenderas att köra minst 48 timmar för en representativ bild av trafiken.

> 💡 Om du får "0 messages" — prova `--hours 48`. Datan kan vara några timmar gammal.

---

### Hämta fler meddelanden
```powershell
python graylog_analyzer.py --hours 48 --max 10000
python graylog_analyzer.py --hours 168 --max 10000
```
**Vad det gör:** Ökar antalet Netflow-poster som hämtas. Fler meddelanden = mer representativ analys, men tar längre tid. Ni har 6+ miljoner meddelanden per dag, så 10 000-25 000 ger en bra bild.

---

### Kör utan AI (bara trafiksammanfattning)
```powershell
python graylog_analyzer.py --hours 48 --no-ai
```
**Vad det gör:** Hämtar och aggregerar trafiken men skickar **inte** till Claude AI. Bra för att:
- Verifiera att fältmappningen fungerar
- Se trafikmönstren utan att använda API-credits
- Felsöka problem med datan

---

### Filtrera på specifik trafik
```powershell
python graylog_analyzer.py --query "nf_src_address:192.168.11.*"
python graylog_analyzer.py --query "nf_l4_dst_port:3389"
python graylog_analyzer.py --query "nf_proto_name:TCP AND nf_l4_dst_port:445"
```
**Vad det gör:** Filtrerar Graylog-sökningen så att bara matchande trafik hämtas. Använder Graylogs söksyntax (Lucene). Bra för att analysera specifik trafik — t.ex. bara RDP eller bara ett subnät.

---

### Kombinera flaggor
```powershell
# Hämta 7 dagars data, max 20 000 meddelanden, med AI-analys
python graylog_analyzer.py --hours 168 --max 10000

# Analysera bara RDP-trafik utan AI
python graylog_analyzer.py --query "nf_l4_dst_port:3389" --hours 168 --no-ai

# Snabbtest — hämta lite data och se trafikmönster
python graylog_analyzer.py --hours 48 --max 1000 --no-ai
```

---

## Förstå utskriften

### Trafiksammanfattningen

```
Source Subnet        Dest Subnet          Port/Proto   Volume    Flows  Src IPs
192.168.11.0/24      192.168.202.0/24     65525/TCP    22.5 KB       2        1
```

| Kolumn | Förklaring |
|---|---|
| Source Subnet | Varifrån trafiken kommer (/24-subnät) |
| Dest Subnet | Vart trafiken går |
| Port/Proto | Destinationsport och protokoll |
| Volume | Total datamängd i detta flödesmönster |
| Flows | Antal enskilda anslutningar |
| Src IPs | Antal unika käll-IP:n i subnätet |

### Portguide — vanliga portar i er trafik

| Port | Protokoll | Tjänst | Kommentar |
|---|---|---|---|
| 443/TCP | HTTPS | Säker webb | Normal — tillåt |
| 443/UDP | QUIC | HTTP/3 | Normal — tillåt |
| 53/UDP | DNS | Namnuppslag | Tillåt till kända DNS-servrar |
| 3478-3481/UDP | STUN | Microsoft Teams | Tillåt ut mot Microsoft |
| 7680/TCP | WUDO | Windows Update P2P | Överväg att begränsa |
| 3389/TCP | RDP | Fjärrskrivbord | Begränsa hårt! |
| 445/TCP | SMB | Fildelning | Begränsa mellan zoner |
| 389/TCP+UDP | LDAP | Active Directory | Byt till LDAPS (636) |
| 80/TCP | HTTP | Okrypterad webb | Blockera ut mot internet |
| 8883/TCP | MQTT | IoT-protokoll | Undersök källan |
| 4840/TCP | OPC-UA | Industriprotokoll | Undersök källan |

---

## Vanliga fel

| Felmeddelande | Orsak | Lösning |
|---|---|---|
| `Cannot reach Graylog` | Fel IP eller Graylog är nere | Kontrollera `GRAYLOG_URL` i .env |
| `authentication failed` | Fel lösenord | Kontrollera `GRAYLOG_PASS` i .env |
| `Got 0 messages` | Söker utanför tidsperiod | Prova `--hours 48` eller `--hours 168` |
| `Skipped 5000 messages` | Fel fältnamn i .env | Kör `--list-fields` och kontrollera fältnamnen |
| `credit balance is too low` | API-kontot saknar pengar | Gå till console.anthropic.com/settings/billing |
| `python is not recognized` | Python inte installerat/PATH | Installera Python, kryssa i "Add to PATH" |

---

## Säkerhet

- `.env`-filen innehåller lösenord och API-nycklar — **dela den aldrig**
- Lägg till `.env` i `.gitignore` om du använder Git
- Rotera API-nyckeln omedelbart om den råkar exponeras
- Granska alltid AI-rekommendationerna manuellt innan implementation
- Testa regler i stagingmiljö eller med "monitor-only" i Meraki innan du aktiverar

---

## Rapportfiler

Varje körning med AI-analys sparar en rapport:
```
C:\graylog-analyzer\firewall_analysis_20260423_110124.md
```

Öppna den i:
- **Notepad:** `notepad firewall_analysis_20260423_110124.md`
- **VS Code:** `code firewall_analysis_20260423_110124.md`
- **Browser:** Dra filen till Chrome/Edge för formaterad visning

---

*Skapat för NNG — Meraki NetFlow v9 + Graylog 5.2 + Claude AI*
