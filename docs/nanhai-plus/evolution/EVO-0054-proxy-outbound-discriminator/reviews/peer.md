# Peer review

Observed: v6 code peer GO, actual root accepted only a local `/32` PROXY line and SSH child rc255; no node outbound, banner, key, auth or UID. The alternate-node selector peer GO is code/selection only. The offline pilot rc0 classified v6 as `LOCAL_RULE_ONLY` and four synthetic outbound/banner cases differently without upgrading unknown fields.

Inference: another node choice plus another rc255 would not isolate whether the selected node attempted the endpoint dial. A bounded endpoint/time/private-instance outbound outcome is the smallest *new* observation with causal value at the current boundary. It must not be described as gz02 authentication. This is a proposed future observer, not a measured proxy capability.

Unknown: whether a safe node-outbound outcome can be acquired from the private instance without logging credentials or changing the global proxy; whether an alternate node would reach gz02; whether SSH host key/auth then succeed. Do not infer from historical delay or local rule selection.

No promotion: the pilot is synthetic plus existing receipts. It did not run a live observer or improve real SSH. Existing runner, nonce and release remain unchanged.
