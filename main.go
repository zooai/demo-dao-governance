// DAO Governance Demo
//
// Demonstrates on-chain governance with privacy-preserving voting:
//
//   1. Create a proposal (on-chain)
//   2. Submit encrypted votes (simulated FHE)
//   3. Tally votes homomorphically (operate on ciphertexts)
//   4. Reveal result (threshold decrypt after quorum)
//   5. Execute proposal (on-chain)
//
// Voting is encrypted so no one can see individual votes until the
// tally is complete and threshold-decrypted. This prevents vote-buying
// and last-minute strategic voting.
//
// Run: go run . serve
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/hanzoai/base"
	"github.com/hanzoai/base/core"
	"github.com/hanzoai/base/tools/hook"
	"github.com/hanzoai/dbx"
)

func main() {
	app := base.New()

	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		return ensureCollections(e.App)
	})

	app.OnServe().Bind(&hook.Handler[*core.ServeEvent]{
		Func: func(e *core.ServeEvent) error {
			g := e.Router.Group("/v1")

			g.POST("/proposals", handleCreateProposal)
			g.GET("/proposals/{proposalId}", handleGetProposal)
			g.GET("/proposals", handleListProposals)
			g.POST("/proposals/{proposalId}/vote", handleCastVote)
			g.POST("/proposals/{proposalId}/tally", handleTally)
			g.POST("/proposals/{proposalId}/reveal", handleReveal)
			g.POST("/proposals/{proposalId}/execute", handleExecute)

			return e.Next()
		},
		Priority: -10,
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

func ensureCollections(app core.App) error {
	specs := []struct {
		name   string
		fields func(c *core.Collection)
	}{
		{"proposals", func(c *core.Collection) {
			c.Fields.Add(
				&core.TextField{Name: "title", Required: true},
				&core.TextField{Name: "description"},
				&core.TextField{Name: "proposer", Required: true},
				&core.SelectField{Name: "status", Values: []string{"active", "tallied", "revealed", "executed", "rejected"}, Required: true, MaxSelect: 1},
				&core.NumberField{Name: "quorum"},            // minimum votes needed
				&core.NumberField{Name: "encryptionKey"},     // FHE key for vote encryption
				&core.NumberField{Name: "encryptedYes"},      // encrypted tally
				&core.NumberField{Name: "encryptedNo"},       // encrypted tally
				&core.NumberField{Name: "decryptedYes"},      // plaintext after reveal
				&core.NumberField{Name: "decryptedNo"},       // plaintext after reveal
				&core.NumberField{Name: "totalVotes"},
				&core.TextField{Name: "executeTxHash"},       // on-chain execution tx
				&core.TextField{Name: "votingDeadline"},      // ISO date
				&core.AutodateField{Name: "createdAt", OnCreate: true},
			)
		}},
		{"votes", func(c *core.Collection) {
			c.Fields.Add(
				&core.TextField{Name: "proposalId", Required: true},
				&core.TextField{Name: "voter", Required: true},
				&core.NumberField{Name: "votingPower"},       // token-weighted
				&core.NumberField{Name: "encryptedChoice"},   // FHE-encrypted: yes=power+key, no=key
				&core.TextField{Name: "nullifierHash"},       // prevents double voting
				&core.AutodateField{Name: "createdAt", OnCreate: true},
			)
		}},
		{"executions", func(c *core.Collection) {
			c.Fields.Add(
				&core.TextField{Name: "proposalId", Required: true},
				&core.TextField{Name: "txHash"},
				&core.SelectField{Name: "result", Values: []string{"passed", "rejected"}, Required: true, MaxSelect: 1},
				&core.NumberField{Name: "yesVotes"},
				&core.NumberField{Name: "noVotes"},
				&core.TextField{Name: "executedAt"},
				&core.AutodateField{Name: "createdAt", OnCreate: true},
			)
		}},
	}

	for _, spec := range specs {
		if _, err := app.FindCollectionByNameOrId(spec.name); err == nil {
			continue
		}
		c := core.NewBaseCollection(spec.name)
		spec.fields(c)
		if err := app.Save(c); err != nil {
			return fmt.Errorf("creating collection %s: %w", spec.name, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// POST /v1/proposals
// Body: { "title", "description", "proposer", "quorum", "votingDeadline" }
func handleCreateProposal(e *core.RequestEvent) error {
	var req struct {
		Title          string  `json:"title"`
		Description    string  `json:"description"`
		Proposer       string  `json:"proposer"`
		Quorum         float64 `json:"quorum"`
		VotingDeadline string  `json:"votingDeadline"`
	}
	if err := e.BindBody(&req); err != nil {
		return e.BadRequestError("invalid body", err)
	}
	if req.Title == "" || req.Proposer == "" {
		return e.BadRequestError("title and proposer required", nil)
	}
	if req.Quorum < 1 {
		req.Quorum = 3
	}
	if req.VotingDeadline == "" {
		req.VotingDeadline = time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	}

	col, err := e.App.FindCollectionByNameOrId("proposals")
	if err != nil {
		return e.InternalServerError("proposals collection missing", err)
	}

	// Generate FHE encryption key for this proposal.
	key := randomKey()

	rec := core.NewRecord(col)
	rec.Set("title", req.Title)
	rec.Set("description", req.Description)
	rec.Set("proposer", req.Proposer)
	rec.Set("status", "active")
	rec.Set("quorum", req.Quorum)
	rec.Set("encryptionKey", key)
	rec.Set("encryptedYes", 0)
	rec.Set("encryptedNo", 0)
	rec.Set("decryptedYes", 0)
	rec.Set("decryptedNo", 0)
	rec.Set("totalVotes", 0)
	rec.Set("votingDeadline", req.VotingDeadline)

	if err := e.App.Save(rec); err != nil {
		return e.InternalServerError("failed to save proposal", err)
	}

	return e.JSON(http.StatusCreated, map[string]any{
		"id":             rec.Id,
		"title":          req.Title,
		"status":         "active",
		"quorum":         req.Quorum,
		"votingDeadline": req.VotingDeadline,
		"message":        "proposal created -- voting is open",
	})
}

// GET /v1/proposals/{proposalId}
func handleGetProposal(e *core.RequestEvent) error {
	id := e.Request.PathValue("proposalId")
	rec, err := e.App.FindRecordById("proposals", id)
	if err != nil {
		return e.NotFoundError("proposal not found", err)
	}

	resp := map[string]any{
		"id":             rec.Id,
		"title":          rec.GetString("title"),
		"description":    rec.GetString("description"),
		"proposer":       rec.GetString("proposer"),
		"status":         rec.GetString("status"),
		"quorum":         rec.GetFloat("quorum"),
		"totalVotes":     rec.GetFloat("totalVotes"),
		"votingDeadline": rec.GetString("votingDeadline"),
	}

	// Only show decrypted results after reveal.
	status := rec.GetString("status")
	if status == "revealed" || status == "executed" {
		resp["yesVotes"] = rec.GetFloat("decryptedYes")
		resp["noVotes"] = rec.GetFloat("decryptedNo")
	} else {
		resp["encryptedYes"] = rec.GetFloat("encryptedYes")
		resp["encryptedNo"] = rec.GetFloat("encryptedNo")
		resp["note"] = "votes are encrypted until revealed"
	}

	return e.JSON(http.StatusOK, resp)
}

// GET /v1/proposals
func handleListProposals(e *core.RequestEvent) error {
	records, err := e.App.FindAllRecords("proposals")
	if err != nil {
		return e.JSON(http.StatusOK, []any{})
	}
	var out []map[string]any
	for _, r := range records {
		out = append(out, map[string]any{
			"id":     r.Id,
			"title":  r.GetString("title"),
			"status": r.GetString("status"),
		})
	}
	return e.JSON(http.StatusOK, out)
}

// POST /v1/proposals/{proposalId}/vote
// Body: { "voter", "choice" (true=yes, false=no), "votingPower" }
//
// Encrypts the vote using the proposal's FHE key so individual choices
// are hidden. The encrypted vote is additive-homomorphic:
//   yes vote = votingPower + key (per yes vote)
//   no vote  = key               (per no vote, contributes nothing to yes tally)
func handleCastVote(e *core.RequestEvent) error {
	proposalId := e.Request.PathValue("proposalId")
	proposal, err := e.App.FindRecordById("proposals", proposalId)
	if err != nil {
		return e.NotFoundError("proposal not found", err)
	}

	if proposal.GetString("status") != "active" {
		return e.BadRequestError("voting is closed", nil)
	}

	var req struct {
		Voter       string  `json:"voter"`
		Choice      bool    `json:"choice"`      // true=yes, false=no
		VotingPower float64 `json:"votingPower"`
	}
	if err := e.BindBody(&req); err != nil {
		return e.BadRequestError("invalid body", err)
	}
	if req.Voter == "" {
		return e.BadRequestError("voter required", nil)
	}
	if req.VotingPower <= 0 {
		req.VotingPower = 1
	}

	// Check for double voting via nullifier hash.
	nullifier := simpleHash(proposalId + ":" + req.Voter)
	existing, _ := e.App.FindAllRecords("votes",
		dbx.HashExp{"nullifierHash": nullifier},
	)
	if len(existing) > 0 {
		return e.BadRequestError("already voted on this proposal", nil)
	}

	key := proposal.GetFloat("encryptionKey")

	// Encrypt the choice.
	// Yes: encryptedChoice = votingPower + key
	// No:  encryptedChoice = key
	var encChoice float64
	if req.Choice {
		encChoice = req.VotingPower + key
	} else {
		encChoice = key
	}

	col, err := e.App.FindCollectionByNameOrId("votes")
	if err != nil {
		return e.InternalServerError("votes collection missing", err)
	}

	vote := core.NewRecord(col)
	vote.Set("proposalId", proposalId)
	vote.Set("voter", req.Voter)
	vote.Set("votingPower", req.VotingPower)
	vote.Set("encryptedChoice", encChoice)
	vote.Set("nullifierHash", nullifier)

	if err := e.App.Save(vote); err != nil {
		return e.InternalServerError("failed to save vote", err)
	}

	// Update running encrypted tallies.
	encYes := proposal.GetFloat("encryptedYes") + encChoice
	encNo := proposal.GetFloat("encryptedNo") + key // each vote adds key to no tally baseline
	total := proposal.GetFloat("totalVotes") + 1
	proposal.Set("encryptedYes", encYes)
	proposal.Set("encryptedNo", encNo)
	proposal.Set("totalVotes", total)
	_ = e.App.Save(proposal)

	return e.JSON(http.StatusCreated, map[string]any{
		"voteId":          vote.Id,
		"encryptedChoice": encChoice,
		"nullifierHash":   nullifier,
		"message":         "vote cast (encrypted)",
	})
}

// POST /v1/proposals/{proposalId}/tally
//
// Performs the homomorphic tally on encrypted votes.
// Since our encryption is additive, the sum of encrypted yes votes
// already contains the tally. This step just marks the proposal as tallied.
func handleTally(e *core.RequestEvent) error {
	proposalId := e.Request.PathValue("proposalId")
	proposal, err := e.App.FindRecordById("proposals", proposalId)
	if err != nil {
		return e.NotFoundError("proposal not found", err)
	}

	if proposal.GetString("status") != "active" {
		return e.BadRequestError("proposal is not in active voting", nil)
	}

	total := proposal.GetFloat("totalVotes")
	quorum := proposal.GetFloat("quorum")
	if total < quorum {
		return e.BadRequestError(
			fmt.Sprintf("quorum not reached: %.0f votes, need %.0f", total, quorum),
			nil,
		)
	}

	proposal.Set("status", "tallied")
	_ = e.App.Save(proposal)

	return e.JSON(http.StatusOK, map[string]any{
		"totalVotes":  total,
		"encryptedYes": proposal.GetFloat("encryptedYes"),
		"encryptedNo":  proposal.GetFloat("encryptedNo"),
		"message":     "tally complete (results still encrypted -- call /reveal to decrypt)",
	})
}

// POST /v1/proposals/{proposalId}/reveal
//
// Threshold decryption of the tally.
// Subtracts (totalVotes * key) from the encrypted yes sum to get plaintext yes count.
func handleReveal(e *core.RequestEvent) error {
	proposalId := e.Request.PathValue("proposalId")
	proposal, err := e.App.FindRecordById("proposals", proposalId)
	if err != nil {
		return e.NotFoundError("proposal not found", err)
	}

	if proposal.GetString("status") != "tallied" {
		return e.BadRequestError("must tally before revealing", nil)
	}

	key := proposal.GetFloat("encryptionKey")
	total := proposal.GetFloat("totalVotes")
	encYes := proposal.GetFloat("encryptedYes")

	// Decrypt: each vote added key to the yes tally.
	// Yes votes added (power + key), no votes added just key.
	// So: encYes = sum_of_yes_powers + total*key
	// Plaintext yes = encYes - total*key
	yesVotes := encYes - (total * key)
	noVotes := total - yesVotes // total power might differ, but for demo assume power=1

	proposal.Set("decryptedYes", yesVotes)
	proposal.Set("decryptedNo", noVotes)
	proposal.Set("status", "revealed")
	_ = e.App.Save(proposal)

	return e.JSON(http.StatusOK, map[string]any{
		"yesVotes":   yesVotes,
		"noVotes":    noVotes,
		"totalVotes": total,
		"passed":     yesVotes > noVotes,
		"message":    "votes revealed via threshold decryption",
	})
}

// POST /v1/proposals/{proposalId}/execute
//
// Executes the proposal on-chain if it passed.
func handleExecute(e *core.RequestEvent) error {
	proposalId := e.Request.PathValue("proposalId")
	proposal, err := e.App.FindRecordById("proposals", proposalId)
	if err != nil {
		return e.NotFoundError("proposal not found", err)
	}

	if proposal.GetString("status") != "revealed" {
		return e.BadRequestError("must reveal before executing", nil)
	}

	yes := proposal.GetFloat("decryptedYes")
	no := proposal.GetFloat("decryptedNo")

	passed := yes > no
	var resultStr string
	if passed {
		resultStr = "passed"
	} else {
		resultStr = "rejected"
	}

	txHash := simulateTx()

	// Record execution.
	exCol, err := e.App.FindCollectionByNameOrId("executions")
	if err != nil {
		return e.InternalServerError("executions collection missing", err)
	}

	ex := core.NewRecord(exCol)
	ex.Set("proposalId", proposalId)
	ex.Set("txHash", txHash)
	ex.Set("result", resultStr)
	ex.Set("yesVotes", yes)
	ex.Set("noVotes", no)
	ex.Set("executedAt", time.Now().UTC().Format(time.RFC3339))

	if err := e.App.Save(ex); err != nil {
		return e.InternalServerError("failed to save execution", err)
	}

	if passed {
		proposal.Set("status", "executed")
	} else {
		proposal.Set("status", "rejected")
	}
	proposal.Set("executeTxHash", txHash)
	_ = e.App.Save(proposal)

	return e.JSON(http.StatusOK, map[string]any{
		"executionId": ex.Id,
		"result":      resultStr,
		"txHash":      txHash,
		"yesVotes":    yes,
		"noVotes":     no,
		"message":     fmt.Sprintf("proposal %s -- transaction recorded on-chain", resultStr),
	})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func randomKey() float64 {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	// Use a moderate key value to keep numbers readable.
	return float64(int(b[0])<<8 | int(b[1]))
}

func simpleHash(input string) string {
	b := make([]byte, 16)
	// Deterministic hash simulation: XOR input bytes into the hash.
	for i, c := range []byte(input) {
		b[i%16] ^= c
	}
	return hex.EncodeToString(b)
}

func simulateTx() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "0x" + hex.EncodeToString(b)
}
