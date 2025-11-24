# Post-Quantum Readiness Assessment Plugin

## Overview

The Post-Quantum Readiness Assessment Plugin analyzes cryptographic components in a CBOM (Cryptography Bill of Materials) to assess their vulnerability to quantum computing attacks. It categorizes algorithms and provides actionable guidance for migrating to post-quantum cryptography.

## Features

- **Quantum Vulnerability Assessment**: Categorizes algorithms as:
  - `vulnerable`: Algorithms broken by quantum computers (e.g., RSA, ECC via Shor's algorithm)
  - `resistant`: Algorithms that maintain security with increased key sizes (e.g., AES-256, SHA-3)
  - `post-quantum`: Algorithms designed to resist quantum attacks (e.g., CRYSTALS-Kyber, CRYSTALS-Dilithium)

- **Threat Timeline Analysis**: Estimates when quantum computers might break each algorithm:
  - `near-term` (0-5 years): Already broken or critically weak
  - `medium-term` (5-15 years): Vulnerable to near-future quantum computers
  - `long-term` (15+ years): Secure for the foreseeable future

- **Migration Priority Guidance**: Assigns urgency levels:
  - `critical`: Immediate action required
  - `high`: Plan migration soon
  - `medium`: Monitor and plan
  - `low`: Not urgent
  - `none`: No action needed

- **Post-Quantum Alternatives**: Recommends specific PQ algorithms for each vulnerable algorithm

- **Hybrid Mode Detection**: Identifies whether hybrid classical+PQ modes are available

- **Readiness Scoring**: Calculates overall PQ-readiness score for the entire CBOM

## Supported Algorithms

### Quantum-Vulnerable Algorithms
- **Asymmetric Cryptography**: RSA, ECC/ECDSA/ECDH, DSA, Diffie-Hellman
- **Weak Symmetric**: DES, 3DES, RC4
- **Weak Hash Functions**: MD5, SHA-1
- **Legacy Algorithms**: Blowfish

### Quantum-Resistant Algorithms
- **Symmetric Encryption**: AES-128, AES-256, ChaCha20
- **Hash Functions**: SHA-256, SHA-384, SHA-512, SHA-3

### Post-Quantum Algorithms
- **Key Encapsulation**: CRYSTALS-Kyber (ML-KEM), FrodoKEM
- **Digital Signatures**: CRYSTALS-Dilithium (ML-DSA), Falcon, SPHINCS+

## CBOM Properties Added

For each cryptographic component, the plugin adds the following properties:

| Property Name | Description | Example Values |
|---------------|-------------|----------------|
| `cbomkit:cryptography:quantum:vulnerability` | Quantum vulnerability status | `vulnerable`, `resistant`, `post-quantum` |
| `cbomkit:cryptography:quantum:threat-timeline` | When quantum threat becomes real | `near-term`, `medium-term`, `long-term` |
| `cbomkit:cryptography:quantum:migration-priority` | Urgency of migration | `critical`, `high`, `medium`, `low`, `none` |
| `cbomkit:cryptography:quantum:pq-alternative` | Recommended PQ algorithm | `CRYSTALS-Kyber (ML-KEM)` |
| `cbomkit:cryptography:quantum:hybrid-available` | Whether hybrid mode exists | `true`, `false` |
| `cbomkit:cryptography:quantum:explanation` | Brief explanation | Description of the quantum threat |

## Usage

### Basic Usage

The plugin is enabled by default. To run CBOMkit-theia with PQ readiness assessment:

```bash
# Scan a directory
./cbomkit-theia dir /path/to/directory

# Scan a container image
./cbomkit-theia image nginx

# Scan with only specific plugins (including pqreadiness)
./cbomkit-theia image nginx -p certificates -p pqreadiness
```

### Custom Algorithm Profiles

You can extend or override the built-in algorithm database by creating a custom configuration file:

**Location**: `~/.cbomkit-theia/pq_profiles.json`

**Format**:
```json
[
  {
    "Name": "Custom Algorithm",
    "Patterns": ["custom-algo", "customalg"],
    "Vulnerability": "vulnerable",
    "ThreatTimeline": "medium-term",
    "MigrationPriority": "high",
    "PQAlternative": "CRYSTALS-Kyber",
    "HybridAvailable": true,
    "Explanation": "Custom algorithm vulnerable to quantum attacks"
  }
]
```

**Fields**:
- `Name`: Human-readable name for the algorithm
- `Patterns`: Array of strings to match against algorithm names (case-insensitive)
- `Vulnerability`: One of: `vulnerable`, `resistant`, `post-quantum`, `unknown`
- `ThreatTimeline`: One of: `near-term`, `medium-term`, `long-term`, `unknown`
- `MigrationPriority`: One of: `critical`, `high`, `medium`, `low`, `none`
- `PQAlternative`: Recommended post-quantum alternative (can be empty string)
- `HybridAvailable`: Boolean indicating if hybrid classical+PQ mode exists
- `Explanation`: Brief description of the quantum security implications

## Example Output

When analyzing a CBOM with RSA certificates, the plugin adds properties like:

```json
{
  "name": "RSA",
  "type": "cryptographic-asset",
  "properties": [
    {
      "name": "cbomkit:cryptography:quantum:vulnerability",
      "value": "vulnerable"
    },
    {
      "name": "cbomkit:cryptography:quantum:threat-timeline",
      "value": "medium-term"
    },
    {
      "name": "cbomkit:cryptography:quantum:migration-priority",
      "value": "high"
    },
    {
      "name": "cbomkit:cryptography:quantum:pq-alternative",
      "value": "CRYSTALS-Kyber (ML-KEM)"
    },
    {
      "name": "cbomkit:cryptography:quantum:hybrid-available",
      "value": "true"
    },
    {
      "name": "cbomkit:cryptography:quantum:explanation",
      "value": "RSA is vulnerable to Shor's algorithm; quantum computers can factor large numbers efficiently"
    }
  ]
}
```

## Log Output

The plugin provides summary statistics:

```
INFO[0002] Post-quantum readiness assessment completed
  analyzed=42
  vulnerable=15
  resistant=20
  post-quantum=7
  readiness-score=42.9%
```

## Integration with PQCA Mission

This plugin directly supports the Post-Quantum Cryptography Alliance (PQCA) mission by:

1. **Raising Awareness**: Identifying quantum-vulnerable cryptographic assets in production systems
2. **Risk Assessment**: Quantifying the scope of quantum cryptography migration challenges
3. **Migration Planning**: Providing concrete recommendations and priorities for PQ transitions
4. **Standards Adoption**: Promoting NIST-standardized PQ algorithms (ML-KEM, ML-DSA, etc.)
5. **Hybrid Approaches**: Highlighting when hybrid classical+PQ solutions are available

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Kyber (ML-KEM)](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium (ML-DSA)](https://pq-crystals.org/dilithium/)
- [PQCA - Post-Quantum Cryptography Alliance](https://pqca.org/)
- [Quantum Threat Timeline](https://globalriskinstitute.org/publications/quantum-threat-timeline-report-2023/)

## Contributing

To add support for additional algorithms or update vulnerability assessments, please submit a pull request with:

1. Updated algorithm profiles in `getBuiltinAlgorithmProfiles()`
2. Test cases demonstrating the new functionality
3. Documentation updates

## License

Apache License 2.0
