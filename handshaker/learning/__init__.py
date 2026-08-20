"""Adaptive learning layer.

The learner is **deterministic and outcome-grounded**: it only records measured
success/failure of a *verified* handshake capture, and only ever selects from
actions it has actually tried (bounded exploration). It never extrapolates,
never invents statistics, and never overrides the verifier.
"""
