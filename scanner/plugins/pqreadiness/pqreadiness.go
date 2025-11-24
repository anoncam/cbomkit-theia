// Copyright 2024 PQCA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pqreadiness

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/cbomkit/cbomkit-theia/provider/filesystem"
	"github.com/cbomkit/cbomkit-theia/scanner/plugins"
	log "github.com/sirupsen/logrus"
)

// QuantumVulnerability represents the quantum threat level for an algorithm
type QuantumVulnerability string

const (
	// Vulnerable algorithms are broken by quantum computers (e.g., Shor's algorithm)
	QuantumVulnerable QuantumVulnerability = "vulnerable"
	// Resistant algorithms maintain security against known quantum attacks with increased key sizes
	QuantumResistant QuantumVulnerability = "resistant"
	// PostQuantum algorithms are designed to be secure against quantum computers
	QuantumPostQuantum QuantumVulnerability = "post-quantum"
	// Unknown vulnerability status
	QuantumUnknown QuantumVulnerability = "unknown"
)

// ThreatTimeline represents when quantum computers might break the algorithm
type ThreatTimeline string

const (
	ThreatNearTerm   ThreatTimeline = "near-term"   // 0-5 years
	ThreatMediumTerm ThreatTimeline = "medium-term" // 5-15 years
	ThreatLongTerm   ThreatTimeline = "long-term"   // 15+ years
	ThreatUnknown    ThreatTimeline = "unknown"
)

// MigrationPriority indicates urgency of migrating to PQ alternatives
type MigrationPriority string

const (
	PriorityCritical MigrationPriority = "critical" // Immediate action required
	PriorityHigh     MigrationPriority = "high"     // Plan migration soon
	PriorityMedium   MigrationPriority = "medium"   // Monitor and plan
	PriorityLow      MigrationPriority = "low"      // Not urgent
	PriorityNone     MigrationPriority = "none"     // No action needed
)

// AlgorithmPQProfile defines the post-quantum security profile of an algorithm
type AlgorithmPQProfile struct {
	Name              string               // Algorithm name or pattern
	Patterns          []string             // Patterns to match (e.g., "RSA", "ECDSA")
	Vulnerability     QuantumVulnerability // Quantum vulnerability status
	ThreatTimeline    ThreatTimeline       // When quantum threat becomes real
	MigrationPriority MigrationPriority    // How urgently to migrate
	PQAlternative     string               // Recommended PQ algorithm
	HybridAvailable   bool                 // Whether hybrid classical+PQ mode exists
	Explanation       string               // Brief explanation of the quantum threat
}

// Plugin to assess post-quantum cryptography readiness
type Plugin struct {
	algorithmProfiles []AlgorithmPQProfile
}

// GetName returns the name of the plugin
func (*Plugin) GetName() string {
	return "Post-Quantum Readiness Assessment Plugin"
}

// GetExplanation returns the explanation of the plugin's functionality
func (*Plugin) GetExplanation() string {
	return "Assess cryptographic algorithms for post-quantum security and identify quantum-vulnerable components"
}

// GetType returns the type of the plugin
func (*Plugin) GetType() plugins.PluginType {
	return plugins.PluginTypeVerify
}

// NewPQReadinessPlugin creates a new instance of the Post-Quantum Readiness Plugin
func NewPQReadinessPlugin() (plugins.Plugin, error) {
	// Start with built-in algorithm profiles
	profiles := getBuiltinAlgorithmProfiles()

	// Try to load custom profiles from user config directory
	customProfiles, err := loadCustomPQProfiles()
	if err != nil {
		log.WithError(err).Debug("Could not load custom PQ profiles (this is optional)")
	} else if len(customProfiles) > 0 {
		log.WithField("count", len(customProfiles)).Info("Loaded custom PQ algorithm profiles")
		profiles = append(profiles, customProfiles...)
	}

	return &Plugin{
		algorithmProfiles: profiles,
	}, nil
}

// loadCustomPQProfiles loads custom algorithm profiles from the user's config directory
func loadCustomPQProfiles() ([]AlgorithmPQProfile, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	customProfilePath := filepath.Join(homeDir, ".cbomkit-theia", "pq_profiles.json")

	// Check if the file exists
	if _, err := os.Stat(customProfilePath); os.IsNotExist(err) {
		return nil, nil
	}

	// Read the file
	data, err := os.ReadFile(customProfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom PQ profile file: %w", err)
	}

	// Parse JSON
	var customProfiles []AlgorithmPQProfile
	if err := json.Unmarshal(data, &customProfiles); err != nil {
		return nil, fmt.Errorf("failed to parse custom PQ profile file: %w", err)
	}

	return customProfiles, nil
}

// UpdateBOM analyzes cryptographic components for post-quantum readiness
func (plugin *Plugin) UpdateBOM(fs filesystem.Filesystem, bom *cdx.BOM) error {
	if bom.Components == nil || len(*bom.Components) == 0 {
		log.Debug("No components found in BOM to analyze")
		return nil
	}

	analyzedCount := 0
	vulnerableCount := 0
	resistantCount := 0
	pqCount := 0

	for i := range *bom.Components {
		component := &(*bom.Components)[i]

		// Only process cryptographic asset components
		if !isCryptographicComponent(component) {
			continue
		}

		analyzedCount++
		algorithmName := extractAlgorithmName(component)
		if algorithmName == "" {
			log.WithField("component", component.Name).Debug("Could not extract algorithm name from component")
			continue
		}

		// Match against PQ profiles
		if profile := plugin.matchAlgorithmProfile(algorithmName); profile != nil {
			plugin.enrichComponentWithPQAssessment(component, profile)

			switch profile.Vulnerability {
			case QuantumVulnerable:
				vulnerableCount++
			case QuantumResistant:
				resistantCount++
			case QuantumPostQuantum:
				pqCount++
			}

			log.WithFields(log.Fields{
				"component":     component.Name,
				"algorithm":     algorithmName,
				"vulnerability": profile.Vulnerability,
				"priority":      profile.MigrationPriority,
			}).Info("Post-quantum assessment completed for component")
		}
	}

	// Calculate overall PQ readiness score
	totalRelevant := vulnerableCount + resistantCount + pqCount
	if totalRelevant > 0 {
		readinessScore := calculatePQReadinessScore(vulnerableCount, resistantCount, pqCount)
		log.WithFields(log.Fields{
			"analyzed":        analyzedCount,
			"vulnerable":      vulnerableCount,
			"resistant":       resistantCount,
			"post-quantum":    pqCount,
			"readiness-score": fmt.Sprintf("%.1f%%", readinessScore),
		}).Info("Post-quantum readiness assessment completed")
	} else {
		log.WithField("analyzed", analyzedCount).Info("Post-quantum readiness assessment completed")
	}

	return nil
}

// isCryptographicComponent checks if a component represents a cryptographic asset
func isCryptographicComponent(component *cdx.Component) bool {
	return component.Type == cdx.ComponentTypeCryptographicAsset
}

// extractAlgorithmName extracts the algorithm name from a component
func extractAlgorithmName(component *cdx.Component) string {
	// First try to get the component name itself
	if component.Name != "" {
		return component.Name
	}

	// Check properties for algorithm identifiers
	if component.Properties != nil {
		for _, prop := range *component.Properties {
			// Look for various algorithm property names
			if strings.Contains(strings.ToLower(prop.Name), "algorithm") ||
				strings.Contains(strings.ToLower(prop.Name), "cipher") {
				return prop.Value
			}
		}
	}

	return ""
}

// matchAlgorithmProfile matches an algorithm name against the profile database
func (plugin *Plugin) matchAlgorithmProfile(algorithmName string) *AlgorithmPQProfile {
	algorithmLower := strings.ToLower(algorithmName)

	for i := range plugin.algorithmProfiles {
		profile := &plugin.algorithmProfiles[i]
		for _, pattern := range profile.Patterns {
			if strings.Contains(algorithmLower, strings.ToLower(pattern)) {
				return profile
			}
		}
	}

	return nil
}

// enrichComponentWithPQAssessment adds PQ assessment properties to the component
func (plugin *Plugin) enrichComponentWithPQAssessment(component *cdx.Component, profile *AlgorithmPQProfile) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}

	assessmentProps := []cdx.Property{
		{
			Name:  "cbomkit:cryptography:quantum:vulnerability",
			Value: string(profile.Vulnerability),
		},
		{
			Name:  "cbomkit:cryptography:quantum:threat-timeline",
			Value: string(profile.ThreatTimeline),
		},
		{
			Name:  "cbomkit:cryptography:quantum:migration-priority",
			Value: string(profile.MigrationPriority),
		},
	}

	// Add PQ alternative if available
	if profile.PQAlternative != "" {
		assessmentProps = append(assessmentProps, cdx.Property{
			Name:  "cbomkit:cryptography:quantum:pq-alternative",
			Value: profile.PQAlternative,
		})
	}

	// Add hybrid availability flag
	assessmentProps = append(assessmentProps, cdx.Property{
		Name:  "cbomkit:cryptography:quantum:hybrid-available",
		Value: fmt.Sprintf("%t", profile.HybridAvailable),
	})

	// Add explanation if available
	if profile.Explanation != "" {
		assessmentProps = append(assessmentProps, cdx.Property{
			Name:  "cbomkit:cryptography:quantum:explanation",
			Value: profile.Explanation,
		})
	}

	*component.Properties = append(*component.Properties, assessmentProps...)
}

// calculatePQReadinessScore computes an overall readiness score (0-100)
func calculatePQReadinessScore(vulnerable, resistant, postQuantum int) float64 {
	total := vulnerable + resistant + postQuantum
	if total == 0 {
		return 0.0
	}

	// Scoring: PQ algorithms = 100%, resistant = 50%, vulnerable = 0%
	score := (float64(postQuantum)*100.0 + float64(resistant)*50.0) / float64(total)
	return score
}

// getBuiltinAlgorithmProfiles returns the built-in database of algorithm PQ profiles
func getBuiltinAlgorithmProfiles() []AlgorithmPQProfile {
	return []AlgorithmPQProfile{
		// Asymmetric Encryption - Quantum Vulnerable (Shor's Algorithm)
		{
			Name:              "RSA",
			Patterns:          []string{"rsa", "rsaencryption"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatMediumTerm,
			MigrationPriority: PriorityHigh,
			PQAlternative:     "CRYSTALS-Kyber (ML-KEM)",
			HybridAvailable:   true,
			Explanation:       "RSA is vulnerable to Shor's algorithm; quantum computers can factor large numbers efficiently",
		},
		{
			Name:              "Elliptic Curve Cryptography",
			Patterns:          []string{"ecc", "ecdsa", "ecdh", "ec-", "secp", "prime256v1", "p-256", "p-384", "p-521"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatMediumTerm,
			MigrationPriority: PriorityHigh,
			PQAlternative:     "CRYSTALS-Dilithium (ML-DSA) for signatures, CRYSTALS-Kyber (ML-KEM) for key exchange",
			HybridAvailable:   true,
			Explanation:       "ECC is vulnerable to Shor's algorithm; quantum computers can solve discrete logarithm problem efficiently",
		},
		{
			Name:              "Diffie-Hellman",
			Patterns:          []string{"dh", "dhe", "diffie-hellman"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatMediumTerm,
			MigrationPriority: PriorityHigh,
			PQAlternative:     "CRYSTALS-Kyber (ML-KEM)",
			HybridAvailable:   true,
			Explanation:       "DH key exchange is vulnerable to Shor's algorithm via discrete logarithm problem",
		},
		{
			Name:              "DSA",
			Patterns:          []string{"dsa", "dss"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatMediumTerm,
			MigrationPriority: PriorityHigh,
			PQAlternative:     "CRYSTALS-Dilithium (ML-DSA)",
			HybridAvailable:   false,
			Explanation:       "DSA signatures are vulnerable to Shor's algorithm; also deprecated for other reasons",
		},

		// Hash Functions - Quantum Resistant with caveats
		{
			Name:              "SHA-256",
			Patterns:          []string{"sha-256", "sha256", "sha2-256"},
			Vulnerability:     QuantumResistant,
			ThreatTimeline:    ThreatLongTerm,
			MigrationPriority: PriorityLow,
			PQAlternative:     "SHA-384 or SHA-512 for increased security margin",
			HybridAvailable:   false,
			Explanation:       "Grover's algorithm reduces effective security to 128 bits; still considered secure for most uses",
		},
		{
			Name:              "SHA-384",
			Patterns:          []string{"sha-384", "sha384", "sha2-384"},
			Vulnerability:     QuantumResistant,
			ThreatTimeline:    ThreatLongTerm,
			MigrationPriority: PriorityLow,
			PQAlternative:     "SHA-512 for maximum security",
			HybridAvailable:   false,
			Explanation:       "Grover's algorithm reduces effective security to 192 bits; provides good quantum resistance",
		},
		{
			Name:              "SHA-512",
			Patterns:          []string{"sha-512", "sha512", "sha2-512"},
			Vulnerability:     QuantumResistant,
			ThreatTimeline:    ThreatLongTerm,
			MigrationPriority: PriorityNone,
			PQAlternative:     "",
			HybridAvailable:   false,
			Explanation:       "Grover's algorithm reduces effective security to 256 bits; excellent quantum resistance",
		},
		{
			Name:              "SHA-3",
			Patterns:          []string{"sha3", "sha-3"},
			Vulnerability:     QuantumResistant,
			ThreatTimeline:    ThreatLongTerm,
			MigrationPriority: PriorityNone,
			PQAlternative:     "",
			HybridAvailable:   false,
			Explanation:       "SHA-3 provides quantum resistance similar to SHA-2; based on different construction (Keccak)",
		},
		{
			Name:              "SHA-1",
			Patterns:          []string{"sha-1", "sha1"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatNearTerm,
			MigrationPriority: PriorityCritical,
			PQAlternative:     "SHA-256 or SHA-3-256 minimum",
			HybridAvailable:   false,
			Explanation:       "SHA-1 is already broken classically; quantum attacks make it completely insecure",
		},
		{
			Name:              "MD5",
			Patterns:          []string{"md5"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatNearTerm,
			MigrationPriority: PriorityCritical,
			PQAlternative:     "SHA-256 or SHA-3-256 minimum",
			HybridAvailable:   false,
			Explanation:       "MD5 is already broken classically; should not be used for any security purpose",
		},

		// Symmetric Encryption - Quantum Resistant with increased key sizes
		{
			Name:              "AES-256",
			Patterns:          []string{"aes-256", "aes256"},
			Vulnerability:     QuantumResistant,
			ThreatTimeline:    ThreatLongTerm,
			MigrationPriority: PriorityNone,
			PQAlternative:     "",
			HybridAvailable:   false,
			Explanation:       "AES-256 provides 128-bit quantum security via Grover's algorithm; considered secure",
		},
		{
			Name:              "AES-128",
			Patterns:          []string{"aes-128", "aes128"},
			Vulnerability:     QuantumResistant,
			ThreatTimeline:    ThreatMediumTerm,
			MigrationPriority: PriorityMedium,
			PQAlternative:     "AES-256",
			HybridAvailable:   false,
			Explanation:       "AES-128 provides 64-bit quantum security via Grover's algorithm; upgrade to AES-256 recommended",
		},
		{
			Name:              "ChaCha20",
			Patterns:          []string{"chacha20", "chacha"},
			Vulnerability:     QuantumResistant,
			ThreatTimeline:    ThreatLongTerm,
			MigrationPriority: PriorityLow,
			PQAlternative:     "",
			HybridAvailable:   false,
			Explanation:       "ChaCha20-Poly1305 maintains reasonable quantum resistance; 256-bit key provides 128-bit quantum security",
		},
		{
			Name:              "3DES",
			Patterns:          []string{"3des", "tripledes", "des-ede3"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatNearTerm,
			MigrationPriority: PriorityCritical,
			PQAlternative:     "AES-256",
			HybridAvailable:   false,
			Explanation:       "3DES provides only 112-bit classical security and ~56-bit quantum security; deprecated",
		},
		{
			Name:              "DES",
			Patterns:          []string{"des"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatNearTerm,
			MigrationPriority: PriorityCritical,
			PQAlternative:     "AES-256",
			HybridAvailable:   false,
			Explanation:       "DES is completely insecure; broken classically and trivially broken by quantum computers",
		},
		{
			Name:              "RC4",
			Patterns:          []string{"rc4", "arcfour"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatNearTerm,
			MigrationPriority: PriorityCritical,
			PQAlternative:     "AES-256 or ChaCha20",
			HybridAvailable:   false,
			Explanation:       "RC4 is broken classically; should not be used",
		},

		// Post-Quantum Algorithms (NIST Standards)
		{
			Name:              "CRYSTALS-Kyber (ML-KEM)",
			Patterns:          []string{"kyber", "ml-kem", "crystals-kyber"},
			Vulnerability:     QuantumPostQuantum,
			ThreatTimeline:    ThreatUnknown,
			MigrationPriority: PriorityNone,
			PQAlternative:     "",
			HybridAvailable:   true,
			Explanation:       "NIST-standardized post-quantum key encapsulation mechanism based on lattice cryptography",
		},
		{
			Name:              "CRYSTALS-Dilithium (ML-DSA)",
			Patterns:          []string{"dilithium", "ml-dsa", "crystals-dilithium"},
			Vulnerability:     QuantumPostQuantum,
			ThreatTimeline:    ThreatUnknown,
			MigrationPriority: PriorityNone,
			PQAlternative:     "",
			HybridAvailable:   true,
			Explanation:       "NIST-standardized post-quantum digital signature algorithm based on lattice cryptography",
		},
		{
			Name:              "SPHINCS+",
			Patterns:          []string{"sphincs", "sphincs+", "sphincsplus"},
			Vulnerability:     QuantumPostQuantum,
			ThreatTimeline:    ThreatUnknown,
			MigrationPriority: PriorityNone,
			PQAlternative:     "",
			HybridAvailable:   false,
			Explanation:       "NIST-standardized stateless hash-based signature scheme; conservative post-quantum option",
		},
		{
			Name:              "Falcon",
			Patterns:          []string{"falcon"},
			Vulnerability:     QuantumPostQuantum,
			ThreatTimeline:    ThreatUnknown,
			MigrationPriority: PriorityNone,
			PQAlternative:     "",
			HybridAvailable:   false,
			Explanation:       "NIST-standardized post-quantum signature scheme based on NTRU lattices; compact signatures",
		},
		{
			Name:              "FrodoKEM",
			Patterns:          []string{"frodo", "frodokem"},
			Vulnerability:     QuantumPostQuantum,
			ThreatTimeline:    ThreatUnknown,
			MigrationPriority: PriorityNone,
			PQAlternative:     "",
			HybridAvailable:   true,
			Explanation:       "Conservative lattice-based KEM; larger keys but based on well-studied hard problems",
		},

		// Legacy/Weak Algorithms
		{
			Name:              "Blowfish",
			Patterns:          []string{"blowfish"},
			Vulnerability:     QuantumVulnerable,
			ThreatTimeline:    ThreatNearTerm,
			MigrationPriority: PriorityHigh,
			PQAlternative:     "AES-256",
			HybridAvailable:   false,
			Explanation:       "Blowfish has 64-bit blocks (vulnerable to birthday attacks) and limited quantum resistance",
		},
	}
}
