# Example fixtures (intentionally insecure)

These files exist **only** to demonstrate Warden's detections. They are
deliberately misconfigured and must **never** be deployed.

Any credential-looking values here are **fake, defanged placeholders**. Provider
tokens (e.g. Stripe/AWS keys) are broken on purpose — real, valid-format
credentials are never committed, even as test data, because that would trip
secret scanners and set a bad example. This mirrors how mature scanners ship
their fixtures, using vendor-documented "EXAMPLE" placeholder credentials
instead of real ones.

Run Warden against them with:

```bash
warden scan ./examples
```
