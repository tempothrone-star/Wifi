"""Advanced action policy — Thompson sampling + UCB1 + contextual transfer.

This is a principled multi-armed bandit over deauth actions, with three
exploration strategies and **cross-AP transfer learning** (hierarchical
shrinkage). All statistics are derived from *measured* outcomes only.

Strategies:

* **``thompson``** (default) — Thompson sampling over a **Beta-style weighted
  posterior**. Each action has a Beta distribution over its success probability;
  exploration is *uncertainty
  driven*: actions with few trials (wide posterior) are naturally tried more.
* **``ucb``** — Upper Confidence Bound (UCB1). Picks the action with the best
  ``mean + confidence bound``, with an exploration bonus that shrinks as the
  action is tried more.
* **``epsilon``** — classic epsilon-greedy (uniform random exploration).

Cross-AP transfer (``transfer`` weight λ):

* An action's posterior is a **blend** of the AP's own measured outcomes and
  the aggregated outcomes of structurally-similar APs (same security × band ×
  vendor), using hierarchical shrinkage:

      eff_wins   = ap_wins   + λ · ctx_wins
      eff_losses = ap_losses + λ · ctx_losses

* This means a *new* AP inherits a prior from similar APs (does not start
  cold), but its own evidence dominates as it accumulates. λ = 0 disables
  transfer (per-AP independence, the old behaviour).

Anti-hallucination guarantees (unchanged):

* Only measured outcomes are used. Untried actions have a flat posterior and
  are never "assumed" good.
* ``min_observations`` gates exploitation: until enough weighted evidence
  exists, the policy explores near-uniformly (honest uncertainty).
* The final exploit choice is deterministic (argmax posterior mean); sampling
  is used only for principled exploration.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass

from .state import ActionKey, LearningStore


@dataclass
class PolicyDecision:
    """A chosen deauth action plus the (honest) rationale behind it."""

    action: ActionKey
    exploration: bool
    reason: str
    score: float = 0.0


def graded_reward(*, quality: float, rounds_taken: int,
                  deauth_frames: int, success: bool) -> float:
    """Graded reward in [0, 1] replacing the coarse pass/fail for the bandit.

    Every term is a *measured* fact:

    * ``quality``    — verifier's handshake-quality score (0..1).
    * ``rounds_taken`` — how many capture rounds were needed (fewer = faster).
    * ``deauth_frames`` — total deauth frames sent (fewer = less disruption).
    * ``success``    — whether a genuine handshake was verified at all.

    A failed capture is still partially rewarded if it produced a *crackable
    pair* (quality ≥ 0.4), because that is genuinely useful progress — but a
    bare miss stays at 0. Speed and stealth bonuses are bounded so they refine,
    not dominate, the core "did we capture a real handshake" signal.
    """
    if not success:
        # Partial credit only for a crackable M2+M3 pair (quality ≥ 0.4).
        return max(0.0, (quality - 0.3) / 0.7) if quality >= 0.4 else 0.0

    reward = 0.6 + 0.4 * quality                    # 0.6..1.0 core
    reward += max(0.0, 0.15 - 0.05 * max(0, rounds_taken - 1))  # speed bonus
    reward += max(0.0, 0.05 - 0.001 * max(0, deauth_frames))     # stealth bonus
    return round(min(1.0, reward), 3)


class ActionPolicy:
    """Thompson/UCB/epsilon bandit with hierarchical (contextual) priors."""

    def __init__(
        self,
        store: LearningStore,
        *,
        exploration: float = 0.25,
        min_observations: int = 2,
        seed: int | None = None,
        strategy: str = "thompson",
        transfer: float = 0.5,
        prior_a: float = 1.0,
        prior_b: float = 1.0,
    ) -> None:
        self.store = store
        self.exploration = exploration
        self.min_observations = min_observations
        self.strategy = strategy if strategy in ("thompson", "ucb", "epsilon") else "thompson"
        self.transfer = max(0.0, transfer)   # hierarchical shrinkage weight
        self.prior_a = max(1e-6, prior_a)     # Beta prior (Laplace smoothing)
        self.prior_b = max(1e-6, prior_b)
        self._rng = random.Random(seed)

    # ------------------------------------------------------------------ #
    # Posterior construction (per action, AP-level blended with context)
    # ------------------------------------------------------------------ #
    def _posterior(self, bssid: str, context_key: str | None, action_id: str) -> tuple[float, float, float]:
        """Return ``(alpha, beta, mean)`` for an action.

        Blends the AP's own measured counts with the context (similar-AP)
        counts via shrinkage weight ``transfer``.
        """
        ap = self.store.action_stats(bssid, now=time.time()).get(action_id, {})
        ap_wins = ap.get("wins", 0.0)
        ap_trials = ap.get("trials", 0.0)

        ctx_wins = ctx_trials = 0.0
        if context_key is not None:
            ctx = self.store.context_action_stats(
                context_key, now=time.time(), exclude_bssid=bssid,
            ).get(action_id, {})
            ctx_wins = ctx.get("wins", 0.0)
            ctx_trials = ctx.get("trials", 0.0)

        eff_wins = ap_wins + self.transfer * ctx_wins
        eff_trials = ap_trials + self.transfer * ctx_trials
        eff_losses = eff_trials - eff_wins

        alpha = self.prior_a + eff_wins
        beta = self.prior_b + eff_losses
        mean = alpha / (alpha + beta)
        return alpha, beta, mean

    def _ucb(self, alpha: float, beta: float, total: float) -> float:
        """UCB1 bound: posterior mean + exploration bonus."""
        n = (alpha + beta) - (self.prior_a + self.prior_b)  # effective observations
        mean = alpha / (alpha + beta)
        bonus = math.sqrt(2.0 * math.log(total + 1.0) / max(n, 1e-6))
        return mean + bonus

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def available_actions(self, bssid: str) -> list[ActionKey]:
        """Every action that has been recorded for this BSSID (deduplicated)."""
        seen: set[str] = set()
        out: list[ActionKey] = []
        for act in self.store.actions_for(bssid):
            key = ActionKey(act["tool"], int(act["burst"]), int(act["reason"]))
            if key.id not in seen:
                seen.add(key.id)
                out.append(key)
        return out

    def choose(self, bssid: str, candidate_actions: list[ActionKey],
               context_key: str | None = None) -> PolicyDecision:
        """Choose a deauth action.

        ``candidate_actions`` is the set the caller is *willing and able* to
        perform (only installed tools). The policy never returns an action
        outside this set.
        """
        if not candidate_actions:
            raise ValueError("choose() requires at least one candidate action")

        if context_key is None:
            context_key = self.store.context_key(bssid)

        stats = self.store.action_stats(bssid, now=time.time())
        # Transfer-learning evidence (similar APs) also counts toward the
        # initial gate — scaled by the transfer weight λ, exactly as it is in
        # the posterior. With λ=0 borrowed evidence contributes nothing (a true
        # cold start); with λ>0 a cold AP with relevant neighbours is no longer
        # treated as having zero evidence.
        ctx_stats = self.store.context_action_stats(
            context_key, now=time.time(), exclude_bssid=bssid,
        )
        total_trials = (sum(s["trials"] for s in stats.values())
                        + self.transfer * sum(s["trials"] for s in ctx_stats.values()))

        # Honest uncertainty: not enough evidence yet -> uniform random.
        if total_trials < self.min_observations:
            action = self._rng.choice(candidate_actions)
            return PolicyDecision(
                action=action, exploration=True,
                reason=f"insufficient evidence ({total_trials:.1f} weighted trials); exploring",
            )

        # Explore with probability `exploration` (uncertainty-driven when thompson).
        if self._rng.random() < self.exploration:
            return self._explore(bssid, context_key, candidate_actions)

        # Exploit: deterministic argmax of the (blended) posterior.
        best = self.best_action(bssid, candidate_actions, context_key)
        if best is None:
            best = self._rng.choice(candidate_actions)
        _, _, mean = self._posterior(bssid, context_key, best.id)
        return PolicyDecision(
            action=best, exploration=False,
            reason=f"exploiting best posterior mean {mean:.2f}",
            score=mean,
        )

    def _explore(self, bssid: str, context_key: str,
                 candidate_actions: list[ActionKey]) -> PolicyDecision:
        """Exploration step, per strategy."""
        if self.strategy == "thompson":
            # Sample each action's success prob from its posterior; pick the max.
            # Actions with wide posteriors (few trials) get explored naturally.
            best_action, best_sample = None, -1.0
            for a in candidate_actions:
                alpha, beta, _ = self._posterior(bssid, context_key, a.id)
                s = self._rng.betavariate(alpha, beta)
                if s > best_sample:
                    best_sample, best_action = s, a
            return PolicyDecision(
                action=best_action, exploration=True,
                reason=f"thompson sampling exploration (sample={best_sample:.2f})",
                score=best_sample,
            )
        if self.strategy == "ucb":
            total = sum(s["trials"] for s in self.store.action_stats(bssid).values())
            best_action, best_val = None, -1.0
            for a in candidate_actions:
                alpha, beta, _ = self._posterior(bssid, context_key, a.id)
                v = self._ucb(alpha, beta, total)
                if v > best_val:
                    best_val, best_action = v, a
            return PolicyDecision(
                action=best_action, exploration=True,
                reason=f"UCB exploration (bound={best_val:.2f})",
                score=best_val,
            )
        # epsilon (or anything else): uniform random.
        action = self._rng.choice(candidate_actions)
        return PolicyDecision(action=action, exploration=True,
                              reason="epsilon-greedy exploration")

    def best_action(self, bssid: str, candidate_actions: list[ActionKey],
                    context_key: str | None = None) -> ActionKey | None:
        """Deterministic best action by posterior mean (for reporting), or None."""
        if context_key is None:
            context_key = self.store.context_key(bssid)
        best: ActionKey | None = None
        best_mean = -1.0
        for action in candidate_actions:
            _, _, mean = self._posterior(bssid, context_key, action.id)
            if mean > best_mean:
                best_mean = mean
                best = action
        return best

    def scoreboard(self, bssid: str, candidate_actions: list[ActionKey],
                   context_key: str | None = None) -> list[tuple[ActionKey, float, float]]:
        """Return ``[(action, mean, ucb), ...]`` sorted by mean (for reporting)."""
        if context_key is None:
            context_key = self.store.context_key(bssid)
        total = sum(s["trials"] for s in self.store.action_stats(bssid).values())
        rows = []
        for a in candidate_actions:
            alpha, beta, mean = self._posterior(bssid, context_key, a.id)
            rows.append((a, mean, self._ucb(alpha, beta, total)))
        rows.sort(key=lambda r: -r[1])
        return rows
