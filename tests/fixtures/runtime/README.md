# Runtime process fixture

crash_during_send.py runs only from the owned runtime regression. It opens disposable owner-only local data, uses an injected fake channel, and exits at the simulated provider call. It never sends externally, changes native host trust or opens a browser. The restart test verifies durable started-attempt recovery as outcome_unknown. This supplies local process/crash evidence only; native host, real Telegram, browser and clean-install qualification remain separate.
