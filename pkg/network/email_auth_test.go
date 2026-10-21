package network

import "testing"

func TestAnalyzeEmailAuth(t *testing.T) {
	orig := dmarcLookup
	defer func() { dmarcLookup = orig }()

	tests := []struct {
		name          string
		apexTXT       []string
		dmarc         []string
		wantSpoofable bool
		wantDMARC     string
		wantSPF       bool
	}{
		{
			name:          "no spf, no dmarc -> spoofable",
			apexTXT:       []string{"some-unrelated=verification"},
			dmarc:         nil,
			wantSpoofable: true,
			wantDMARC:     "",
			wantSPF:       false,
		},
		{
			name:          "spf hardfail but no dmarc -> still spoofable",
			apexTXT:       []string{"v=spf1 include:_spf.google.com -all"},
			dmarc:         nil,
			wantSpoofable: true,
			wantSPF:       true,
		},
		{
			name:          "dmarc p=none -> spoofable",
			apexTXT:       []string{"v=spf1 -all"},
			dmarc:         []string{"v=DMARC1; p=none; rua=mailto:x@y.com"},
			wantSpoofable: true,
			wantDMARC:     "none",
			wantSPF:       true,
		},
		{
			name:          "dmarc p=reject -> not spoofable",
			apexTXT:       []string{"v=spf1 -all"},
			dmarc:         []string{"v=DMARC1; p=reject; pct=100"},
			wantSpoofable: false,
			wantDMARC:     "reject",
			wantSPF:       true,
		},
		{
			name:          "dmarc p=quarantine -> not spoofable",
			apexTXT:       []string{"v=spf1 ~all"},
			dmarc:         []string{"v=DMARC1; p=quarantine"},
			wantSpoofable: false,
			wantDMARC:     "quarantine",
			wantSPF:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dmarcLookup = func(string) ([]string, error) { return tt.dmarc, nil }
			ea := AnalyzeEmailAuth("example.com", tt.apexTXT)
			if ea.Spoofable != tt.wantSpoofable {
				t.Errorf("Spoofable = %v, want %v", ea.Spoofable, tt.wantSpoofable)
			}
			if ea.DMARC.Policy != tt.wantDMARC {
				t.Errorf("DMARC.Policy = %q, want %q", ea.DMARC.Policy, tt.wantDMARC)
			}
			if ea.SPF.Present != tt.wantSPF {
				t.Errorf("SPF.Present = %v, want %v", ea.SPF.Present, tt.wantSPF)
			}
		})
	}
}

func TestSPFAllQualifier(t *testing.T) {
	cases := map[string]string{
		"v=spf1 -all":               "-",
		"v=spf1 include:x.com ~all": "~",
		"v=spf1 ?all":               "?",
		"v=spf1 +all":               "+",
		"v=spf1 all":                "+",
		"v=spf1 include:x.com":      "",
	}
	for record, want := range cases {
		if got := spfAllQualifier(record); got != want {
			t.Errorf("spfAllQualifier(%q) = %q, want %q", record, got, want)
		}
	}
}
