package spamcheck

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

// MultiChecker runs multiple spam checkers and aggregates results.
type MultiChecker struct {
	checkers []Checker
	config   MultiConfig
}

// MultiConfig holds configuration for the multi-checker.
type MultiConfig struct {
	// Mode determines how results are aggregated.
	// "first_reject" - reject if any checker says reject (default)
	// "all_reject" - reject only if all checkers say reject
	// "highest_score" - use the result with the highest score
	Mode string

	// FailMode determines behavior when a checker errors.
	FailMode FailMode

	// RejectThreshold is the score threshold for rejection.
	RejectThreshold float64

	// TempFailThreshold is the score threshold for temp failure.
	TempFailThreshold float64

	// AddHeaders indicates whether to add headers from all checkers.
	AddHeaders bool
}

// NewMultiChecker creates a new multi-checker with the given checkers.
func NewMultiChecker(checkers []Checker, config MultiConfig) *MultiChecker {
	if config.Mode == "" {
		config.Mode = "first_reject"
	}
	return &MultiChecker{
		checkers: checkers,
		config:   config,
	}
}

// Name returns the name of this checker.
func (m *MultiChecker) Name() string {
	return "multi"
}

// Check runs all checkers and aggregates results.
func (m *MultiChecker) Check(ctx context.Context, message io.Reader, opts CheckOptions) (*CheckResult, error) {
	if len(m.checkers) == 0 {
		return &CheckResult{
			CheckerName: "multi",
			Action:      ActionAccept,
		}, nil
	}

	// Read message into buffer so we can pass it to multiple checkers
	msgData, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}

	var results []*CheckResult
	var errors []error
	aggregatedHeaders := make(map[string]string)

	for _, checker := range m.checkers {
		result, err := checker.Check(ctx, bytes.NewReader(msgData), opts)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", checker.Name(), err))
			continue
		}
		results = append(results, result)

		// Collect headers from all checkers
		if m.config.AddHeaders && result.Headers != nil {
			for k, v := range result.Headers {
				aggregatedHeaders[k] = v
			}
		}
	}

	// If all checkers errored, handle according to fail mode
	if len(results) == 0 && len(errors) > 0 {
		return nil, fmt.Errorf("all checkers failed: %v", errors)
	}

	// Aggregate results based on mode
	finalResult := m.aggregateResults(results)
	finalResult.Headers = aggregatedHeaders

	return finalResult, nil
}

func (m *MultiChecker) aggregateResults(results []*CheckResult) *CheckResult {
	if len(results) == 0 {
		return &CheckResult{
			CheckerName: "multi",
			Action:      ActionAccept,
		}
	}

	if len(results) == 1 {
		return results[0]
	}

	switch m.config.Mode {
	case "all_reject":
		return m.aggregateAllReject(results)
	case "highest_score":
		return m.aggregateHighestScore(results)
	default: // "first_reject"
		return m.aggregateFirstReject(results)
	}
}

// aggregateFirstReject returns reject if any checker says reject.
func (m *MultiChecker) aggregateFirstReject(results []*CheckResult) *CheckResult {
	var highestScore float64
	var highestScoreResult *CheckResult

	for _, r := range results {
		// Return immediately if any checker says reject
		if r.Action == ActionReject || r.ShouldReject(m.config.RejectThreshold) {
			return &CheckResult{
				CheckerName:   "multi",
				Score:         r.Score,
				Action:        ActionReject,
				IsSpam:        true,
				RejectMessage: r.RejectMessage,
				Details: map[string]interface{}{
					"rejected_by": r.CheckerName,
					"score":       r.Score,
				},
			}
		}

		// Track highest score for final result
		if r.Score > highestScore {
			highestScore = r.Score
			highestScoreResult = r
		}
	}

	// Check for temp fail
	for _, r := range results {
		if r.Action == ActionTempFail || r.ShouldTempFail(m.config.TempFailThreshold) {
			return &CheckResult{
				CheckerName:   "multi",
				Score:         r.Score,
				Action:        ActionTempFail,
				IsSpam:        false,
				RejectMessage: r.RejectMessage,
				Details: map[string]interface{}{
					"tempfail_by": r.CheckerName,
					"score":       r.Score,
				},
			}
		}
	}

	// No rejection, return result with highest score
	if highestScoreResult != nil {
		return &CheckResult{
			CheckerName: "multi",
			Score:       highestScoreResult.Score,
			Action:      ActionAccept,
			IsSpam:      highestScoreResult.IsSpam,
			Details: map[string]interface{}{
				"highest_score_from": highestScoreResult.CheckerName,
			},
		}
	}

	return &CheckResult{
		CheckerName: "multi",
		Action:      ActionAccept,
	}
}

// aggregateAllReject returns reject only if all checkers say reject.
func (m *MultiChecker) aggregateAllReject(results []*CheckResult) *CheckResult {
	allReject := true
	var totalScore float64
	var rejectMessage string

	for _, r := range results {
		totalScore += r.Score
		if r.Action != ActionReject && !r.ShouldReject(m.config.RejectThreshold) {
			allReject = false
		}
		if r.RejectMessage != "" {
			rejectMessage = r.RejectMessage
		}
	}

	avgScore := totalScore / float64(len(results))

	if allReject {
		return &CheckResult{
			CheckerName:   "multi",
			Score:         avgScore,
			Action:        ActionReject,
			IsSpam:        true,
			RejectMessage: rejectMessage,
		}
	}

	return &CheckResult{
		CheckerName: "multi",
		Score:       avgScore,
		Action:      ActionAccept,
		IsSpam:      false,
	}
}

// aggregateHighestScore returns the result with the highest score.
func (m *MultiChecker) aggregateHighestScore(results []*CheckResult) *CheckResult {
	var highest *CheckResult

	for _, r := range results {
		if highest == nil || r.Score > highest.Score {
			highest = r
		}
	}

	if highest == nil {
		return &CheckResult{
			CheckerName: "multi",
			Action:      ActionAccept,
		}
	}

	action := ActionAccept
	if highest.ShouldReject(m.config.RejectThreshold) {
		action = ActionReject
	} else if highest.ShouldTempFail(m.config.TempFailThreshold) {
		action = ActionTempFail
	}

	return &CheckResult{
		CheckerName:   "multi",
		Score:         highest.Score,
		Action:        action,
		IsSpam:        highest.IsSpam,
		RejectMessage: highest.RejectMessage,
		Details: map[string]interface{}{
			"highest_score_from": highest.CheckerName,
		},
	}
}

// Close closes all checkers.
func (m *MultiChecker) Close() error {
	var errs []error
	for _, checker := range m.checkers {
		if err := checker.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing checkers: %v", errs)
	}
	return nil
}
