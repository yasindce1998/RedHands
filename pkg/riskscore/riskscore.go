package riskscore

import "math"

// Score holds a calculated risk score with component breakdown.
type Score struct {
	Total          float64 `json:"total"`
	Exploitability float64 `json:"exploitability"`
	Impact         float64 `json:"impact"`
	Exposure       float64 `json:"exposure"`
	Rating         string  `json:"rating"`
}

// Params are inputs to the risk calculation.
type Params struct {
	Exploitability float64 `json:"exploitability"`
	Impact         float64 `json:"impact"`
	Exposure       float64 `json:"exposure"`
}

// Calculate computes a risk score using the formula:
// Total = Exploitability*0.4 + Impact*0.4 + Exposure*0.2
// All inputs should be in [0, 10] range.
func Calculate(p Params) Score {
	e := clamp(p.Exploitability, 0, 10)
	i := clamp(p.Impact, 0, 10)
	x := clamp(p.Exposure, 0, 10)

	total := e*0.4 + i*0.4 + x*0.2
	total = math.Round(total*10) / 10

	return Score{
		Total:          total,
		Exploitability: e,
		Impact:         i,
		Exposure:       x,
		Rating:         rating(total),
	}
}

// FromSeverity derives risk params from a severity string with optional context.
func FromSeverity(severity string, hasExploit bool, isExposed bool) Score {
	var e, i, x float64

	switch severity {
	case "critical":
		e, i = 9.0, 9.5
	case "high":
		e, i = 7.0, 7.5
	case "medium":
		e, i = 5.0, 5.0
	case "low":
		e, i = 3.0, 3.0
	case "info":
		e, i = 1.0, 1.0
	default:
		e, i = 5.0, 5.0
	}

	if hasExploit {
		e = math.Min(e+2.0, 10.0)
	}

	if isExposed {
		x = 8.0
	} else {
		x = 4.0
	}

	return Calculate(Params{Exploitability: e, Impact: i, Exposure: x})
}

func rating(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 2.0:
		return "low"
	default:
		return "info"
	}
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
