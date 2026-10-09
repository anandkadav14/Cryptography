# CS6530 Assignment 3 - Site-to-Site IPsec/IKEv2

Complete project setup for site-to-site IPsec/IKEv2 tunnel configuration, testing, and failure analysis.

## Project Structure

```
Assignment-3/
├── README.md                      # This file
├── REQUIREMENTS.md                # Configuration requirements & checklist
├── site-a-ipsec.conf              # IPsec config for Site A
├── site-b-ipsec.conf              # IPsec config for Site B
├── ipsec.secrets.template         # PSK secrets template
├── COMMANDS.md                    # All required commands for each test
├── TEST_PROCEDURES.md             # Detailed test procedures (TR-1 to TR-8)
├── DIAGNOSIS_FORMAT.md            # How to diagnose failures (TR-4 to TR-7)
├── EVIDENCE_CHECKLIST.md          # What evidence to collect (E1-A to E8-C)
├── setup-site-a.sh                # Optional: automated setup for Site A
├── setup-site-b.sh                # Optional: automated setup for Site B
└── evidence/                       # Directory for screenshots, PCAPs, logs
    ├── screenshots/               # Terminal screenshots
    ├── pcaps/                     # PCAP files
    └── logs/                      # Command output logs
```

## Quick Start (5 Steps)

### 1. Gather Information
Collect before starting:
- **Site A WAN IP**: `<GW-A-WAN>` (mutual reachability address)
- **Site B WAN IP**: `<GW-B-WAN>` (mutual reachability address)
- **Site A Roll Number**: `ROLLNO1` (UPPERCASE)
- **Site B Roll Number**: `ROLLNO2` (UPPERCASE)

Test gateway connectivity:
```bash
# On Site A gateway
ping <GW-B-WAN>

# On Site B gateway
ping <GW-A-WAN>
```

### 2. Update Configuration Files

**site-a-ipsec.conf**: Replace placeholders
```bash
<GW-A-WAN-IP> → Site A actual WAN IP
<GW-B-WAN-IP> → Site B actual WAN IP
```

**site-b-ipsec.conf**: Replace placeholders
```bash
<GW-A-WAN-IP> → Site A actual WAN IP
<GW-B-WAN-IP> → Site B actual WAN IP
```

### 3. Create PSK File

Using `ipsec.secrets.template`:

Replace:
```
ROLLNO1 → Your Site A roll number (UPPERCASE)
ROLLNO2 → Your Site B roll number (UPPERCASE)
```

Example: If roll numbers are CS24B001 and CS24B002:
```
<GW-A-WAN> <GW-B-WAN> : PSK "CS24B001CS24B002CS6530-IPsec-Assignment-2026"
```

On **both Site A and Site B**:
```bash
# Create /etc/ipsec.secrets with the PSK line above
sudo vim /etc/ipsec.secrets

# Set permissions
sudo chmod 600 /etc/ipsec.secrets
```

### 4. Deploy & Start Tunnel

On **both** Site A and Site B:
```bash
# Copy configuration
sudo cp site-a-ipsec.conf /etc/ipsec.conf        # On Site A
sudo cp site-b-ipsec.conf /etc/ipsec.conf        # On Site B

# Reload strongSwan
sudo ipsec reload

# Start tunnel
sudo ipsec up cs6530-site-to-site

# Verify establishment
sudo ipsec statusall
```

**Expected output** should show:
```
Security Associations (1 up, 0 connecting):
  cs6530-site-to-site[1]: ESTABLISHED
  cs6530-site-to-site{1}: INSTALLED, TUNNEL
```

### 5. Run Tests (TR-1 to TR-8)

Follow procedures in order:
1. **TR-1**: Baseline plaintext test
2. **TR-2**: Normal protected session
3. **TR-3**: IKEv2 exchange capture
4. **TR-4**: IKE proposal mismatch
5. **TR-5**: PSK authentication failure
6. **TR-6**: ESP proposal mismatch
7. **TR-7**: Traffic-selector mismatch
8. **TR-8**: Security-boundary observation

See **TEST_PROCEDURES.md** for detailed steps for each.

## Key Files Explained

### Configuration Files

**site-a-ipsec.conf** / **site-b-ipsec.conf**
- Connection name: `cs6530-site-to-site`
- Key exchange: IKEv2
- Type: tunnel (not transport)
- IKE proposal: aes256-sha256-modp2048!
- ESP proposal: aes256-sha256!
- Auto: start (tunnel comes up automatically)

**ipsec.secrets.template**
- Contains pre-shared key (PSK) for authentication
- Format: `left right : PSK "key"`
- Must have 600 permissions

### Documentation Files

- **REQUIREMENTS.md** - FR-1 to FR-8 checklist
- **COMMANDS.md** - Copy-paste commands for each test
- **TEST_PROCEDURES.md** - Full procedure for TR-1 to TR-8
- **DIAGNOSIS_FORMAT.md** - How to diagnose failures
- **EVIDENCE_CHECKLIST.md** - What to capture (E1-A to E8-C)

## Testing Workflow

### Phase 1: Baseline (Before IPsec)

**TR-1: Plaintext communication**
```bash
# On Site B (capture):
sudo tcpdump -l -n -i <WAN> -XX icmp

# On Site A hostA (ping):
sudo ip netns exec hostA ping 10.2.0.10
```
→ Expected: Plaintext ICMP visible on WAN

### Phase 2: Normal Operation (After IPsec)

**TR-2: Protected communication**
```bash
sudo ipsec up cs6530-site-to-site
sudo ipsec statusall
sudo ip xfrm state
sudo ip xfrm policy

# Same ping as TR-1:
sudo ip netns exec hostA ping 10.2.0.10

# Capture:
sudo tcpdump -l -n -i <WAN> -XX esp
```
→ Expected: ESP packets on WAN, ICMP not plaintext

### Phase 3: Packet Analysis

**TR-3: IKEv2 capture**
```bash
sudo tcpdump -i <WAN> -s 0 -w team-ikev2.pcap 'udp port 500 or udp port 4500 or esp'
# Then: sudo ipsec down; sudo ipsec up cs6530-site-to-site
# Open team-ikev2.pcap in Wireshark
```
→ Identify: IKE_SA_INIT → IKE_AUTH → ESP

### Phase 4-7: Failure Injection

For each test (TR-4 to TR-7):
1. **Introduce failure** (change one config line)
2. **Observe symptoms** (tunnel fails to establish)
3. **Collect evidence** (screenshots, captures, logs)
4. **Diagnose** (identify failure layer and root cause)
5. **Restore** (fix config, reload)
6. **Verify** (tunnel re-establishes)

### Phase 8: Boundary Analysis

**TR-8: Plaintext vs encrypted**
```bash
# Capture on protected side (plaintext):
sudo tcpdump -l -n -i ns-hostA-eth0 -XX icmp

# Capture on WAN (encrypted):
sudo tcpdump -l -n -i <WAN> -XX esp

# Generate traffic:
sudo ip netns exec hostA ping 10.2.0.10
```
→ Explain: why plaintext on one side, ESP on other?

## Common Commands

### Status & Inspection
```bash
# Check tunnel status
sudo ipsec statusall

# View installed policies (SPD)
sudo ip xfrm policy

# View installed SAs (SAD)
sudo ip xfrm state

# Check logs
sudo journalctl -xe | grep charon
sudo journalctl -u ipsec
```

### Troubleshooting
```bash
# Reload config after changes
sudo ipsec reload

# Down and up tunnel
sudo ipsec down cs6530-site-to-site
sudo ipsec up cs6530-site-to-site

# List pre-shared keys
sudo ipsec listpsk

# View config
sudo ipsec statusall | grep -A 20 cs6530
```

### Packet Capture
```bash
# Plain ICMP (baseline)
sudo tcpdump -l -n -i <WAN> -XX icmp

# ESP traffic
sudo tcpdump -l -n -i <WAN> -XX esp

# Both IKE and ESP (for PCAP)
sudo tcpdump -i <WAN> -s 0 -w team-ikev2.pcap 'udp port 500 or udp port 4500 or esp'

# Protected-side capture
sudo tcpdump -l -n -i ns-hostA-eth0 -XX
```

## Understanding the Evidence Chain

```
Application Traffic (ping)
    ↓
XFRM Policy (ip xfrm policy)
    ↓ matches
XFRM State / SA (ip xfrm state)
    ↓ uses SPI
ESP Packet on WAN (tcpdump)
```

**Example**:
- Ping from 10.1.0.10 → 10.2.0.10
- Matches policy: src 10.1.0.0/24 dst 10.2.0.0/24
- Uses SA with SPI 0xc0bfa0e3
- Packet shows: ESP spi=0xc0bfa0e3 on WAN

## Test Phases & Marks Breakdown

| Phase | Tests | Component | Marks | Status |
|-------|-------|-----------|-------|--------|
| Setup | FR | Topology + Configuration | 20 | [ ] |
| Baseline | TR-1, TR-2 | Before/After Evidence | 15 | [ ] |
| Analysis | TR-3 | IKEv2 PCAP | 10 | [ ] |
| Failures | TR-4 | IKE Mismatch | 10 | [ ] |
| | TR-5 | PSK Mismatch | 10 | [ ] |
| | TR-6 | ESP Mismatch | 10 | [ ] |
| | TR-7, TR-8 | Selectors & Boundary | 10 | [ ] |
| Report | D1-D5 | Report + Evidence | 5 | [ ] |
| Viva | D6 | Individual Assessment | 10 | [ ] |
| **TOTAL** | | | **100** | |

## Deliverables Checklist

- [ ] **D1** - Assignment Report (structured with TR-1 to TR-8)
- [ ] **D2** - Final configs (site-a-ipsec.conf, site-b-ipsec.conf, PSK used)
- [ ] **D3** - Team PCAP (team-ikev2.pcap with IKEv2 + ESP)
- [ ] **D4** - Evidence set (E1-A through E8-C)
- [ ] **D5** - AI-use disclosure
- [ ] **D6** - Individual viva (scheduled in-class)

## Failure Diagnosis Format (TR-4 to TR-7)

For each failure test, document:

**Symptom**: What went wrong?
- Tunnel didn't establish?
- Only IKE_SA established?
- CHILD_SA failed?

**Evidence**: What did you observe?
- ipsec statusall output
- Packet capture showing failure
- Error messages in logs

**Failure Layer**: Where in the protocol stack?
- IKE_SA_INIT (algorithm negotiation)
- IKE_AUTH (authentication)
- CHILD_SA (data-plane setup)

**Root Cause**: Why did it fail?
- Proposal mismatch
- Authentication rejection
- Traffic selector conflict

**Correction**: How to fix?
- Change config parameter
- Restore original value

**Verification**: Did restoration work?
- Tunnel re-established
- Traffic flows through tunnel

## Key Concepts Reminder

| Concept | Meaning | Evidence |
|---------|---------|----------|
| **IKE_SA** | Control-plane authentication | ipsec statusall |
| **CHILD_SA** | Data-plane protection | ipsec statusall + ip xfrm state |
| **SPI** | Packet identifier for each direction | ip xfrm state (two SPIs per CHILD_SA) |
| **Proposal** | Algorithms (aes256-sha256-modp2048) | ipsec statusall |
| **Traffic Selector** | Which packets to protect | ip xfrm policy |
| **XFRM Policy (SPD)** | Rules: which traffic needs protection | ip xfrm policy |
| **XFRM State (SAD)** | Active protections: SPIs, algorithms, keys | ip xfrm state |
| **ESP** | Encapsulating Security Payload | tcpdump -XX esp |

## Next Steps

1. ✅ Update configuration files with your WAN IPs
2. ✅ Create PSK file with your roll numbers
3. ✅ Read **COMMANDS.md** for copy-paste command reference
4. ✅ Read **TEST_PROCEDURES.md** for detailed test steps
5. ✅ Read **DIAGNOSIS_FORMAT.md** for failure analysis format
6. ✅ Follow **EVIDENCE_CHECKLIST.md** to collect required evidence
7. ✅ Create evidence/ directory structure
8. ✅ Run tests in order (TR-1 → TR-8)
9. ✅ Document results in report
10. ✅ Submit deliverables

---

**Questions?** Check the relevant .md file or revisit Assignment 3 PDF section 12 (Background / Reference Material).


